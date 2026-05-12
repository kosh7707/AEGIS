"""Code Graph API — 프로젝트별 코드 함수 호출 그래프 엔드포인트."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import APIRouter, Header, HTTPException, Query

from app.context import set_request_id
from app.timeout import parse_timeout, check_deadline, run_sync_with_deadline
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/code-graph", tags=["code-graph"])

_service = None
_code_vector_search = None
_code_assembler = None


def set_service(service) -> None:
    global _service
    _service = service


def set_code_vector_search(vs) -> None:
    global _code_vector_search
    _code_vector_search = vs


def set_code_assembler(asm) -> None:
    global _code_assembler
    _code_assembler = asm


class ProvenanceRequest(BaseModel):
    build_snapshot_id: str | None = Field(default=None, alias="buildSnapshotId")
    build_unit_id: str | None = Field(default=None, alias="buildUnitId")
    source_build_attempt_id: str | None = Field(default=None, alias="sourceBuildAttemptId")

    model_config = {"populate_by_name": True}


class IngestRequest(BaseModel):
    functions: list[dict] = Field(
        ...,
        description="함수 목록: [{name, file, line, calls: [str]}]",
    )
    provenance: ProvenanceRequest | None = Field(
        default=None,
        description="선택적 build snapshot provenance",
    )


class DangerousCallersRequest(BaseModel):
    dangerous_functions: list[str] = Field(
        ...,
        description="위험 함수 이름 목록",
    )
    build_snapshot_id: str | None = Field(default=None, alias="buildSnapshotId")

    model_config = {"populate_by_name": True}


def _require_service():
    if _service is None:
        raise HTTPException(503, "Code graph service not initialized")


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _ingest_readiness(
    node_count: int,
    vector_count: int,
    expected_vector_count: int,
) -> tuple[str, dict[str, bool], list[str]]:
    if node_count <= 0:
        return (
            "empty",
            {
                "neo4jGraph": False,
                "vectorIndex": False,
                "graphRag": False,
            },
            [],
        )

    vector_ready = vector_count >= expected_vector_count
    readiness = {
        "neo4jGraph": True,
        "vectorIndex": vector_ready,
        "graphRag": vector_ready,
    }
    if vector_ready:
        return "ready", readiness, []
    return "partial", readiness, ["VECTOR_INDEX_INCOMPLETE"]


def _rollback_ingest(project_id: str, previous_functions: list[dict] | None) -> None:
    logger.warning(
        "코드 그래프 ingest 롤백 시작: project=%s, previous_functions=%d",
        project_id,
        len(previous_functions or []),
    )
    if previous_functions:
        _service.ingest(project_id, previous_functions)
        if _code_vector_search is not None:
            _code_vector_search.ingest(project_id, previous_functions)
    else:
        _service.delete_project(project_id)
        if _code_vector_search is not None:
            _code_vector_search.delete_project(project_id)
    logger.warning("코드 그래프 ingest 롤백 완료: project=%s", project_id)


def _cleanup_staging(project_id: str, staging_project_id: str) -> None:
    logger.info(
        "코드 그래프 staging 정리: project=%s, staging=%s",
        project_id,
        staging_project_id,
    )
    _service.delete_project(staging_project_id)
    if _code_vector_search is not None:
        _code_vector_search.delete_project(staging_project_id)


class CodeSearchRequest(BaseModel):
    query: str = Field(..., description="검색 쿼리 (자연어 또는 함수명)")
    top_k: int = Field(default=10, ge=1, le=50)
    min_score: float = Field(default=0.3, ge=0.0, le=1.0)
    graph_depth: int = Field(default=2, ge=0, le=5)
    include_call_chain: bool = Field(default=True, description="호출 체인 포함 여부")
    build_snapshot_id: str | None = Field(default=None, alias="buildSnapshotId")
    query_intent: str | None = Field(default=None, alias="queryIntent")
    corpus_partitions: list[str] | None = Field(default=None, alias="corpusPartitions")
    profiles: list[str] = Field(default_factory=list)
    allow_global_embedding: bool | None = Field(default=None, alias="allowGlobalEmbedding")

    model_config = {"populate_by_name": True}


@router.post("/{project_id}/ingest")
async def ingest(
    project_id: str, req: IngestRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    start = time.monotonic()
    deadline, _ = parse_timeout(x_timeout_ms)
    _require_service()

    provenance = (
        req.provenance.model_dump(exclude_none=True)
        if req.provenance is not None else None
    )
    previous_functions = _service.export_project(project_id)
    replaced_existing_graph = len(previous_functions) > 0
    staging_project_id = f"__staging__::{project_id}::{uuid.uuid4().hex}"
    neo4j_stage_ms = 0
    vector_stage_ms = 0
    activation_ms = 0
    cleanup_ms = 0
    try:
        stage_start = time.monotonic()
        staged_result = _service.ingest(staging_project_id, req.functions, provenance=provenance)
        neo4j_stage_ms = _elapsed_ms(stage_start)
        check_deadline(deadline, "neo4j-stage-ingest")

        vector_count = 0
        if _code_vector_search is not None:
            try:
                stage_start = time.monotonic()
                vector_count = _code_vector_search.ingest(
                    staging_project_id,
                    req.functions,
                    provenance=provenance,
                )
                vector_stage_ms = _elapsed_ms(stage_start)
                check_deadline(deadline, "vector-stage-ingest")
            except HTTPException:
                raise
            except Exception as e:
                vector_stage_ms = _elapsed_ms(stage_start)
                logger.warning(
                    "코드 함수 벡터 stage 적재 실패 (Neo4j staging만 성공): %s",
                    e,
                    extra={"_extra": {
                        "projectId": project_id,
                        "stagingProjectId": staging_project_id,
                        "elapsedMs": _elapsed_ms(start),
                        "vectorStageMs": vector_stage_ms,
                    }},
                )
                vector_count = 0

        stage_start = time.monotonic()
        _service.activate_staging(staging_project_id, project_id)
        check_deadline(deadline, "neo4j-activate")
        result = {
            **staged_result,
            "project_id": project_id,
            "replaceMode": "replace_project_graph",
            "replacedExistingGraph": replaced_existing_graph,
        }
        result["vectorCount"] = 0
        if _code_vector_search is not None:
            _code_vector_search.activate_staging(staging_project_id, project_id)
            result["vectorCount"] = vector_count
            check_deadline(deadline, "vector-activate")
        activation_ms = _elapsed_ms(stage_start)
    except HTTPException as exc:
        try:
            cleanup_start = time.monotonic()
            _cleanup_staging(project_id, staging_project_id)
            cleanup_ms = _elapsed_ms(cleanup_start)
        except Exception as cleanup_error:
            logger.error(
                "코드 그래프 staging 정리 실패: project=%s staging=%s error=%s",
                project_id,
                staging_project_id,
                cleanup_error,
                extra={"_extra": {
                    "projectId": project_id,
                    "stagingProjectId": staging_project_id,
                    "elapsedMs": _elapsed_ms(start),
                }},
            )
        if exc.status_code == 408:
            try:
                _rollback_ingest(project_id, previous_functions)
            except Exception as rollback_error:
                logger.error(
                    "코드 그래프 ingest 롤백 실패: project=%s error=%s",
                    project_id,
                    rollback_error,
                    extra={"_extra": {
                        "projectId": project_id,
                        "elapsedMs": _elapsed_ms(start),
                    }},
                )
        logger.warning(
            "코드 그래프 ingest 실패",
            extra={"_extra": {
                "projectId": project_id,
                "stagingProjectId": staging_project_id,
                "statusCode": exc.status_code,
                "error": str(exc.detail),
                "elapsedMs": _elapsed_ms(start),
                "timeoutMs": x_timeout_ms,
                "neo4jStageMs": neo4j_stage_ms,
                "vectorStageMs": vector_stage_ms,
                "activationMs": activation_ms,
                "cleanupMs": cleanup_ms,
            }},
        )
        raise
    else:
        try:
            cleanup_start = time.monotonic()
            _cleanup_staging(project_id, staging_project_id)
            cleanup_ms = _elapsed_ms(cleanup_start)
        except Exception as cleanup_error:
            logger.error(
                "코드 그래프 staging 정리 실패: project=%s staging=%s error=%s",
                project_id,
                staging_project_id,
                cleanup_error,
                extra={"_extra": {
                    "projectId": project_id,
                    "stagingProjectId": staging_project_id,
                    "elapsedMs": _elapsed_ms(start),
                }},
            )

    status, readiness, warnings = _ingest_readiness(
        result.get("nodeCount", 0),
        result.get("vectorCount", 0),
        len(req.functions),
    )
    result["operation"] = {
        "mode": result.get("replaceMode", "replace_project_graph"),
        "repeatable": True,
        "replacedExistingGraph": result.get("replacedExistingGraph", False),
    }
    result["readiness"] = readiness
    result["status"] = status
    if warnings:
        result["warnings"] = warnings

    logger.info(
        "코드 그래프 ingest 완료",
        extra={"_extra": {
            "projectId": project_id,
            "stagingProjectId": staging_project_id,
            "status": status,
            "nodeCount": result.get("nodeCount", 0),
            "edgeCount": result.get("edgeCount", 0),
            "vectorCount": result.get("vectorCount", 0),
            "expectedVectorCount": len(req.functions),
            "readinessNeo4jGraph": readiness["neo4jGraph"],
            "readinessVectorIndex": readiness["vectorIndex"],
            "readinessGraphRag": readiness["graphRag"],
            "warningCount": len(warnings),
            "warnings": warnings,
            "replacedExistingGraph": result["operation"]["replacedExistingGraph"],
            "elapsedMs": _elapsed_ms(start),
            "timeoutMs": x_timeout_ms,
            "neo4jStageMs": neo4j_stage_ms,
            "vectorStageMs": vector_stage_ms,
            "activationMs": activation_ms,
            "cleanupMs": cleanup_ms,
        }},
    )

    return result


@router.get("/{project_id}/stats")
async def stats(
    project_id: str,
    build_snapshot_id: str | None = Query(default=None, alias="buildSnapshotId"),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    start = time.monotonic()
    _require_service()
    result = _service.get_stats(project_id, build_snapshot_id=build_snapshot_id)
    logger.info(
        "코드 그래프 stats 조회",
        extra={"_extra": {
            "projectId": project_id,
            "buildSnapshotId": build_snapshot_id,
            "nodeCount": result.get("nodeCount", 0),
            "edgeCount": result.get("edgeCount", 0),
            "fileCount": len(result.get("files", [])),
            "elapsedMs": _elapsed_ms(start),
        }},
    )
    return result


@router.get("/{project_id}/callers/{function_name}")
async def callers(
    project_id: str,
    function_name: str,
    depth: int = Query(default=2, ge=1, le=10),
    build_snapshot_id: str | None = Query(default=None, alias="buildSnapshotId"),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    start = time.monotonic()
    _require_service()
    results = _service.get_callers(
        project_id, function_name, depth=depth, build_snapshot_id=build_snapshot_id,
    )
    logger.info(
        "코드 그래프 callers 조회",
        extra={"_extra": {
            "projectId": project_id,
            "functionName": function_name,
            "depth": depth,
            "buildSnapshotId": build_snapshot_id,
            "resultCount": len(results),
            "elapsedMs": _elapsed_ms(start),
        }},
    )
    return {"function": function_name, "depth": depth, "callers": results}


@router.get("/{project_id}/callees/{function_name}")
async def callees(
    project_id: str,
    function_name: str,
    build_snapshot_id: str | None = Query(default=None, alias="buildSnapshotId"),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    start = time.monotonic()
    _require_service()
    results = _service.get_callees(
        project_id, function_name, build_snapshot_id=build_snapshot_id,
    )
    logger.info(
        "코드 그래프 callees 조회",
        extra={"_extra": {
            "projectId": project_id,
            "functionName": function_name,
            "buildSnapshotId": build_snapshot_id,
            "resultCount": len(results),
            "elapsedMs": _elapsed_ms(start),
        }},
    )
    return {"function": function_name, "callees": results}


@router.post("/{project_id}/dangerous-callers")
async def dangerous_callers(
    project_id: str, req: DangerousCallersRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    start = time.monotonic()
    deadline, _ = parse_timeout(x_timeout_ms)
    _require_service()
    results = await run_sync_with_deadline(
        deadline,
        "dangerous-callers",
        _service.find_dangerous_callers,
        project_id,
        req.dangerous_functions,
        build_snapshot_id=req.build_snapshot_id,
    )
    logger.info(
        "코드 그래프 dangerous-callers 조회",
        extra={"_extra": {
            "projectId": project_id,
            "dangerousFunctionCount": len(req.dangerous_functions),
            "buildSnapshotId": req.build_snapshot_id,
            "resultCount": len(results),
            "elapsedMs": _elapsed_ms(start),
            "timeoutMs": x_timeout_ms,
        }},
    )
    return {"results": results}


@router.post("/{project_id}/search")
async def search(
    project_id: str,
    req: CodeSearchRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    if _code_assembler is None:
        raise HTTPException(503, "Code graph search not initialized")

    start = time.monotonic()
    search_kwargs = {
        "top_k": req.top_k,
        "min_score": req.min_score,
        "graph_depth": req.graph_depth,
        "include_call_chain": req.include_call_chain,
        "build_snapshot_id": req.build_snapshot_id,
    }
    if req.query_intent is not None:
        search_kwargs["query_intent"] = req.query_intent
    if req.corpus_partitions:
        search_kwargs["corpus_partitions"] = req.corpus_partitions
    if req.profiles:
        search_kwargs["profiles"] = req.profiles
    if req.allow_global_embedding is not None:
        search_kwargs["allow_global_embedding"] = req.allow_global_embedding
    result = await run_sync_with_deadline(
        deadline,
        "code-graph-search",
        _code_assembler.search,
        project_id,
        req.query,
        **search_kwargs,
    )
    elapsed_ms = int((time.monotonic() - start) * 1000)

    logger.info(
        "코드 그래프 검색",
        extra={"_extra": {
            "projectId": project_id,
            "query": req.query,
            "hits": result["total"],
            "matchTypeCounts": result.get("match_type_counts", {}),
            "buildSnapshotId": req.build_snapshot_id,
            "timeoutMs": x_timeout_ms,
            "latencyMs": elapsed_ms,
        }},
    )

    return {**result, "latency_ms": elapsed_ms}


@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    start = time.monotonic()
    _require_service()
    deleted = _service.delete_project(project_id)
    if not deleted:
        raise HTTPException(404, f"Project '{project_id}' not found")

    if _code_vector_search is not None:
        try:
            _code_vector_search.delete_project(project_id)
        except Exception as e:
            logger.warning("코드 함수 벡터 삭제 실패: %s", e)

    logger.info(
        "코드 그래프 삭제",
        extra={"_extra": {
            "projectId": project_id,
            "deleted": True,
            "elapsedMs": _elapsed_ms(start),
        }},
    )
    return {"deleted": True, "project_id": project_id}


@router.get("")
async def list_projects(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    start = time.monotonic()
    _require_service()
    projects = _service.list_projects()
    logger.info(
        "코드 그래프 프로젝트 목록 조회",
        extra={"_extra": {
            "projectCount": len(projects),
            "elapsedMs": _elapsed_ms(start),
        }},
    )
    return {"projects": projects}
