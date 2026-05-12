"""Knowledge Base API — 위협 지식 검색 엔드포인트."""

import logging
import time

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from app.config import settings
from app.context import set_request_id
from app.errors import error_response
from app.timeout import parse_timeout, run_sync_with_deadline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["v1"])

# 런타임에 lifespan에서 주입
_assembler = None
_neo4j_graph = None
_qdrant_ready: bool = False


def set_assembler(assembler) -> None:
    global _assembler
    _assembler = assembler


def set_neo4j_graph(graph) -> None:
    global _neo4j_graph
    _neo4j_graph = graph


def set_qdrant_ready(ready: bool) -> None:
    global _qdrant_ready
    _qdrant_ready = ready


class SearchRequest(BaseModel):
    query: str
    top_k: int = Field(default=5, ge=1, le=20)
    min_score: float = Field(default=0.35, ge=0.0, le=1.0)
    graph_depth: int = Field(default=2, ge=0, le=5)
    exclude_ids: list[str] = Field(default_factory=list, max_length=100)
    source_filter: list[str] | None = Field(
        default=None,
        description="소스 필터: CWE, ATT&CK, CAPEC 중 선택",
    )
    query_intent: str | None = Field(default=None, alias="queryIntent")
    corpus_partitions: list[str] | None = Field(default=None, alias="corpusPartitions")
    profiles: list[str] = Field(default_factory=list)
    allow_global_embedding: bool | None = Field(default=None, alias="allowGlobalEmbedding")

    model_config = {"populate_by_name": True}


class SearchBatchItem(BaseModel):
    query: str
    top_k: int = Field(default=5, ge=1, le=20)
    min_score: float = Field(default=0.35, ge=0.0, le=1.0)
    graph_depth: int = Field(default=2, ge=0, le=5)
    source_filter: list[str] | None = None
    query_intent: str | None = Field(default=None, alias="queryIntent")
    corpus_partitions: list[str] | None = Field(default=None, alias="corpusPartitions")
    profiles: list[str] = Field(default_factory=list)
    allow_global_embedding: bool | None = Field(default=None, alias="allowGlobalEmbedding")

    model_config = {"populate_by_name": True}


class SearchBatchRequest(BaseModel):
    queries: list[SearchBatchItem] = Field(
        ..., min_length=1, max_length=20,
        description="배치 검색 쿼리 목록 (최대 20개)",
    )


@router.post("/search")
async def search(
    req: SearchRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()

    if _assembler is None or _neo4j_graph is None:
        logger.warning("검색 요청 — Knowledge base 미초기화")
        return error_response(503, "KB_NOT_READY", "Knowledge base not initialized", retryable=True)

    result = await run_sync_with_deadline(
        deadline,
        "threat-search",
        _assembler.assemble,
        req.query,
        top_k=req.top_k,
        min_score=req.min_score,
        graph_depth=req.graph_depth,
        exclude_ids=req.exclude_ids,
        source_filter=req.source_filter,
        query_intent=req.query_intent,
        corpus_partitions=req.corpus_partitions,
        profiles=req.profiles,
        allow_global_embedding=req.allow_global_embedding,
    )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    hits = result.get("hits", [])
    logger.info(
        "검색 요청",
        extra={"_extra": {
            "query": req.query,
            "top_k": req.top_k,
            "hits": len(hits),
            "latencyMs": elapsed_ms,
        }},
    )

    return result


@router.post("/search/batch")
async def search_batch(
    req: SearchBatchRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    start = time.monotonic()

    if _assembler is None or _neo4j_graph is None:
        return error_response(503, "KB_NOT_READY", "Knowledge base not initialized", retryable=True)

    queries = [
        {
            "query": q.query,
            "top_k": q.top_k,
            "min_score": q.min_score,
            "graph_depth": q.graph_depth,
            "source_filter": q.source_filter,
            "query_intent": q.query_intent,
            "corpus_partitions": q.corpus_partitions,
            "profiles": q.profiles,
            "allow_global_embedding": q.allow_global_embedding,
        }
        for q in req.queries
    ]

    result = await run_sync_with_deadline(
        deadline,
        "threat-search-batch",
        _assembler.batch_assemble,
        queries,
    )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "배치 검색",
        extra={"_extra": {
            "queryCount": len(req.queries),
            "totalHits": result["global_stats"]["total_hits"],
            "latencyMs": elapsed_ms,
        }},
    )

    return {**result, "latency_ms": elapsed_ms}


@router.get("/graph/stats")
async def graph_stats(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    if _neo4j_graph is None:
        return error_response(503, "KB_NOT_READY", "Graph not initialized", retryable=True)
    return _neo4j_graph.get_stats()


@router.get("/graph/neighbors/{node_id}")
async def graph_neighbors(
    node_id: str,
    depth: int = Query(default=2, ge=1, le=5),
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    if _neo4j_graph is None:
        return error_response(503, "KB_NOT_READY", "Graph not initialized", retryable=True)

    node_info = _neo4j_graph.get_node_info(node_id)
    if node_info is None:
        raise HTTPException(404, f"Node '{node_id}' not found")

    neighbor_ids = _neo4j_graph.neighbors(node_id, depth=depth)
    neighbors = []
    for nid in neighbor_ids[:50]:  # 상위 50개 제한
        info = _neo4j_graph.get_node_info(nid)
        if info:
            neighbors.append(info)

    related = _neo4j_graph.get_related(node_id)

    return {
        "nodeId": node_id,
        "nodeInfo": node_info,
        "neighbors": neighbors,
        "related": related,
    }


@router.get("/health")
async def health() -> dict:
    """Liveness probe — 프로세스가 살아있으면 200."""
    return {
        "service": "aegis-knowledge-base",
        "status": "ok",
        "version": "0.2.0",
    }


@router.get("/ready")
async def ready(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
):
    """Readiness probe — Qdrant+Neo4j 준비 시 200, 아니면 503."""
    set_request_id(x_request_id)

    qdrant_ok = _qdrant_ready
    neo4j_ok = _neo4j_graph is not None

    neo4j_info: dict = {"connected": False}
    if neo4j_ok:
        try:
            neo4j_info = {
                "connected": True,
                "nodeCount": _neo4j_graph.node_count,
                "edgeCount": _neo4j_graph.edge_count,
            }
        except Exception:
            neo4j_ok = False

    # ontology 메타 (Phase 3에서 KBMeta 노드 추가 후 활성화)
    ontology = None
    if neo4j_ok and hasattr(_neo4j_graph, "get_kb_meta"):
        ontology = _neo4j_graph.get_kb_meta()

    body = {
        "service": "aegis-knowledge-base",
        "ready": qdrant_ok and neo4j_ok,
        "components": {
            "qdrant": {"initialized": qdrant_ok},
            "neo4j": neo4j_info,
        },
    }
    if ontology:
        body["ontology"] = ontology

    if not (qdrant_ok and neo4j_ok):
        return error_response(503, "KB_NOT_READY", "Service not fully initialized", retryable=True)

    return body
