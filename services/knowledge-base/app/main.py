"""Knowledge Base — 위협 지식 검색 서비스 (Qdrant + Neo4j GraphRAG)."""

import logging
import time
from contextlib import asynccontextmanager
from uuid import uuid4

import neo4j
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.config import redact_url_for_log, settings
from app.context import get_request_id, set_request_id
from app.cve.nvd_client import NvdClient
from app.graphrag.code_graph_assembler import CodeGraphAssembler
from app.graphrag.code_graph_service import CodeGraphService
from app.graphrag.code_vector_search import CodeVectorSearch
from app.graphrag.knowledge_assembler import KnowledgeAssembler
from app.graphrag.neo4j_graph import Neo4jGraph
from app.graphrag.vector_search import VectorSearch
from app.ledger.repository import SQLiteLedgerRepository
from app.observability import setup_logging
from app.rag.threat_search import COLLECTION as THREAT_COLLECTION, ThreatSearch
from app.graphrag.project_memory_service import ProjectMemoryService
from app.routers import (
    analyst_api,
    api,
    code_graph_api,
    contracts_api,
    cve_api,
    judge_api,
    paper_context_api,
    project_memory_api,
    source_kg_api,
    target_context_api,
)
from app.target_context_service import TargetContextService

setup_logging("s5-kb", log_file_name="aegis-knowledge-base")
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    threat_search = None
    vector_search = None
    assembler = None
    driver = None
    nvd_client = None
    target_context_svc = None
    ledger_repository = None

    # Qdrant 벡터 검색 초기화
    try:
        threat_search = ThreatSearch(
            qdrant_path=settings.qdrant_path if not settings.qdrant_url else None,
            qdrant_url=settings.qdrant_url,
            qdrant_api_key=settings.qdrant_api_key,
            require_collection=False,
        )
        collections = {c.name for c in threat_search.client.get_collections().collections}
        if THREAT_COLLECTION in collections:
            vector_search = VectorSearch(threat_search)
        logger.info("Qdrant 초기화 완료: mode=%s, target=%s",
                     threat_search.mode,
                     redact_url_for_log(settings.qdrant_url) if settings.qdrant_url else settings.qdrant_path)
        if THREAT_COLLECTION not in collections:
            logger.warning("Qdrant 연결은 성공했지만 threat_knowledge 컬렉션이 없어 threat search 비활성")
    except Exception as e:
        logger.warning("Qdrant 초기화 실패 (데이터 미적재 시 정상): %s", e)

    # Neo4j 그래프 초기화
    neo4j_graph = None
    code_graph_svc = None
    memory_svc = None

    try:
        driver = neo4j.GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        driver.verify_connectivity()

        neo4j_graph = Neo4jGraph(driver)
        code_graph_svc = CodeGraphService(driver)
        memory_svc = ProjectMemoryService(driver, memory_limit=settings.memory_limit_per_project)

        logger.info(
            "Neo4j 연결 완료: %d nodes, %d edges",
            neo4j_graph.node_count, neo4j_graph.edge_count,
        )
    except Exception as e:
        logger.warning("Neo4j 연결 실패 (미설치 시 정상): %s", e)

    # KnowledgeAssembler 조립 (벡터 + 그래프)
    if vector_search and neo4j_graph:
        assembler = KnowledgeAssembler(vector_search, neo4j_graph, rrf_k=settings.rrf_k)
    elif vector_search and not neo4j_graph:
        logger.warning("Neo4j 미연결 — threat search 비활성 (ready/search 모두 미준비)")

    # NVD 실시간 CVE 조회 클라이언트
    try:
        kb_lookup = threat_search.get_by_id if vector_search else None
        nvd_client = NvdClient(
            api_key=settings.nvd_api_key,
            api_base=settings.nvd_api_base,
            rate_delay=settings.nvd_rate_delay,
            cache_ttl=settings.nvd_cache_ttl,
            cache_file=settings.nvd_cache_file,
            neo4j_graph=neo4j_graph,
            kb_lookup=kb_lookup,
            nvd_concurrency=settings.nvd_batch_concurrency,
            epss_enabled=settings.epss_enabled,
            kev_ttl=settings.kev_ttl,
        )
        logger.info("NVD 클라이언트 초기화 완료 (API 키: %s, KB 보강: %s)",
                     "있음" if settings.nvd_api_key else "없음",
                     "활성" if kb_lookup else "비활성")
    except Exception as e:
        logger.warning("NVD 클라이언트 초기화 실패: %s", e)

    # 소스코드 GraphRAG 초기화 (공유 Qdrant client + Neo4j 필요)
    code_vector_search = None
    code_assembler = None
    if threat_search and code_graph_svc:
        try:
            code_vector_search = CodeVectorSearch(threat_search.client)
            code_assembler = CodeGraphAssembler(
                code_graph_svc, code_vector_search, rrf_k=settings.rrf_k,
            )
            logger.info("소스코드 GraphRAG 초기화 완료")
        except Exception as e:
            logger.warning("소스코드 GraphRAG 초기화 실패: %s", e)

    # S3 target-aware acquisition context ledger
    try:
        ledger_repository = SQLiteLedgerRepository(settings.ledger_url)
        target_context_svc = TargetContextService(
            settings.target_context_store_file,
            ledger_repository=ledger_repository,
        )
        logger.info(
            "Target context SQLite ledger 초기화 완료: ledger=%s mirror=%s",
            redact_url_for_log(settings.ledger_url),
            settings.target_context_store_file,
        )
    except Exception as e:
        logger.warning("Target context ledger 초기화 실패: %s", e)

    api.set_assembler(assembler)
    api.set_neo4j_graph(neo4j_graph)
    api.set_qdrant_ready(bool(vector_search))
    code_graph_api.set_service(code_graph_svc)
    code_graph_api.set_code_vector_search(code_vector_search)
    code_graph_api.set_code_assembler(code_assembler)
    cve_api.set_nvd_client(nvd_client)
    project_memory_api.set_service(memory_svc if neo4j_graph else None)
    target_context_api.set_target_context_service(target_context_svc)
    target_context_api.set_ledger_repository(ledger_repository)
    target_context_api.set_code_graph_service(code_graph_svc)
    target_context_api.set_code_vector_search(code_vector_search)
    target_context_api.set_code_assembler(code_assembler)
    target_context_api.set_knowledge_assembler(assembler)
    target_context_api.set_nvd_client(nvd_client)
    source_kg_api.set_ledger_repository(ledger_repository)
    judge_api.set_ledger_repository(ledger_repository)
    paper_context_api.set_ledger_repository(ledger_repository)

    logger.info("Knowledge Base 초기화 완료")

    yield

    if nvd_client:
        await nvd_client.close()
    if threat_search:
        threat_search.close()
    if driver:
        try:
            driver.close()
            logger.info("Neo4j 연결 종료")
        except Exception:
            logger.warning("Neo4j 연결 이미 종료됨 (외부 종료)")


app = FastAPI(
    title="AEGIS Knowledge Base",
    description="위협 지식 검색 서비스 — Qdrant 벡터 검색 + Neo4j 관계 그래프",
    version="0.2.0",
    lifespan=lifespan,
)

class _RequestIdMiddleware(BaseHTTPMiddleware):
    """Echo request ids, generating them for S5 paper-facing endpoints."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id")
        if request_id is None and _is_paper_facing_path(request.url.path):
            request_id = f"req-{uuid4()}"
        if request_id:
            request.state.aegis_request_id = request_id
        request.state.aegis_started_at = time.monotonic()
        set_request_id(request_id)
        response: Response = await call_next(request)
        response_request_id = response.headers.get("X-Request-Id") or get_request_id() or getattr(
            request.state,
            "aegis_request_id",
            request_id,
        )
        if response_request_id:
            response.headers["X-Request-Id"] = response_request_id
        return response


def _is_paper_facing_path(path: str) -> bool:
    return path.startswith("/v1/paper/") or path == "/v1/contracts/paper-context"


def _request_id_for_response(request: Request, *, generate_if_missing: bool = False) -> str | None:
    request_id = get_request_id() or getattr(request.state, "aegis_request_id", None) or request.headers.get("x-request-id")
    if request_id is None and generate_if_missing:
        request_id = f"req-{uuid4()}"
    if request_id:
        set_request_id(request_id)
        request.state.aegis_request_id = request_id
    return request_id


def _elapsed_ms(request: Request) -> int:
    started_at = getattr(request.state, "aegis_started_at", None)
    if started_at is None:
        return 0
    return int((time.monotonic() - started_at) * 1000)


def _paper_observability_extra(request: Request, *, status: int, error_code: str | None = None) -> dict:
    extra = {
        "service": "s5-kb",
        "requestId": _request_id_for_response(request, generate_if_missing=True),
        "method": request.method,
        "path": request.url.path,
        "status": status,
        "elapsedMs": _elapsed_ms(request),
    }
    if error_code:
        extra["errorCode"] = error_code
    return extra


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException):
    """HTTPException을 observability.md 공통 에러 포맷으로 변환."""
    _code_map = {
        400: "BAD_REQUEST",
        404: "NOT_FOUND",
        408: "TIMEOUT",
        409: "CONFLICT",
        422: "INVALID_INPUT",
        503: "KB_NOT_READY",
    }
    code = _code_map.get(exc.status_code, "INTERNAL_ERROR")
    reason = None
    paper_code = None
    if isinstance(exc.detail, dict):
        detail = str(exc.detail.get("message") or exc.detail.get("detail") or exc.detail)
        reason = exc.detail.get("reason")
        paper_code = exc.detail.get("code")
    else:
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    is_paper_facing = _is_paper_facing_path(request.url.path)
    request_id = _request_id_for_response(request, generate_if_missing=is_paper_facing)
    error_detail = {
        "code": paper_code or code,
        "message": detail,
        "requestId": request_id,
        "retryable": exc.status_code == 503,
    }
    if reason:
        error_detail["reason"] = reason
    response = JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": detail,
            "errorDetail": error_detail,
        },
    )
    if request_id:
        response.headers["X-Request-Id"] = request_id
    if is_paper_facing:
        logger.error(
            "S5 paper endpoint error",
            extra={"_extra": _paper_observability_extra(request, status=exc.status_code, error_code=str(paper_code or code))},
        )
    return response


@app.exception_handler(RequestValidationError)
async def _request_validation_exception_handler(request: Request, exc: RequestValidationError):
    """Pydantic/FastAPI validation errors in the S5 observability error envelope."""
    is_paper_facing = _is_paper_facing_path(request.url.path)
    request_id = _request_id_for_response(request, generate_if_missing=is_paper_facing)
    errors = exc.errors()
    sanitized_errors = [
        {key: value for key, value in error.items() if key not in {"input", "ctx"}}
        for error in errors
    ]
    detail = f"{len(errors)} validation error(s): " + "; ".join(
        f"{'.'.join(str(part) for part in (error.get('loc') or []))}: {error.get('msg')}"
        for error in sanitized_errors[:5]
    )
    reason = "request_schema_invalid"
    if request.url.path in {"/v1/source-code-kg/context", "/v1/judge/query"}:
        scalar_selector_fields = {"repositorySnapshotId", "buildContextId", "analysisArtifactSetId"}
        collection_selector_fields = {"graphNodeIds", "evidenceSnippetIds", "richIrArtifactIds"}
        selector_fields = scalar_selector_fields | collection_selector_fields
        control_list_fields = {"exclude", "prefer"}
        force_context_fields = {"forceContext", "force_context"}
        if request.url.path == "/v1/source-code-kg/context" and "at least one context identifier" in detail:
            reason = "no_context_selector"
        else:
            control_list_errors = [
                error
                for error in errors
                if control_list_fields.intersection({str(part) for part in (error.get("loc") or [])})
            ]
            selector_errors = [
                error
                for error in errors
                if selector_fields.intersection({str(part) for part in (error.get("loc") or [])})
            ]
            force_context_errors = [
                error
                for error in errors
                if force_context_fields.intersection({str(part) for part in (error.get("loc") or [])})
            ]
            if any(
                error.get("type") == "too_long" or "List should have at most" in str(error.get("msg") or "")
                for error in control_list_errors
            ):
                reason = "control_list_too_long"
            elif any(
                error.get("type") == "too_long"
                or "Dictionary should have at most" in str(error.get("msg") or "")
                or "control_object_too_large" in str(error.get("msg") or "")
                for error in force_context_errors
            ):
                reason = "control_object_too_large"
            elif any(
                error.get("type") == "string_too_long"
                or "String should have at most" in str(error.get("msg") or "")
                for error in selector_errors
            ):
                reason = "selector_value_too_long"
            elif any(
                collection_selector_fields.intersection({str(part) for part in (error.get("loc") or [])})
                and (error.get("type") == "too_long" or "List should have at most" in str(error.get("msg") or ""))
                for error in selector_errors
            ):
                reason = "explicit_selector_limit_exceeded"
    elif request.url.path == "/v1/source-code-kg/ingest":
        collection_fields = {"sourceArtifacts", "evidenceSnippets", "graphNodes", "graphEdges", "richIrArtifacts"}
        if any(
            collection_fields.intersection({str(part) for part in (error.get("loc") or [])})
            and (error.get("type") == "too_long" or "List should have at most" in str(error.get("msg") or ""))
            for error in errors
        ):
            reason = "ingest_collection_limit_exceeded"
        elif any(
            error.get("type") == "string_too_long"
            or "String should have at most" in str(error.get("msg") or "")
            or "payload byte length exceeds max bytes" in str(error.get("msg") or "")
            or "nested JSON object byte length exceeds max bytes" in str(error.get("msg") or "")
            for error in errors
        ):
            reason = "ingest_value_too_large"
    elif request.url.path.startswith("/v1/paper/"):
        reason = "S5_PAPER_SCHEMA_INVALID"
    error_code = "S5_PAPER_SCHEMA_INVALID" if request.url.path.startswith("/v1/paper/") else "INVALID_INPUT"
    response = JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": detail,
            "errorDetail": {
                "code": error_code,
                "message": detail,
                "requestId": request_id,
                "retryable": False,
                "reason": reason,
            },
        },
    )
    if request_id:
        response.headers["X-Request-Id"] = request_id
    if is_paper_facing:
        logger.error(
            "S5 paper endpoint validation error",
            extra={"_extra": _paper_observability_extra(request, status=422, error_code=error_code)},
        )
    return response


app.add_middleware(_RequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api.router)
app.include_router(analyst_api.router)
app.include_router(code_graph_api.router)
app.include_router(contracts_api.router)
app.include_router(cve_api.router)
app.include_router(judge_api.router)
app.include_router(paper_context_api.router)
app.include_router(project_memory_api.router)
app.include_router(source_kg_api.router)
app.include_router(target_context_api.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8002, reload=True)
