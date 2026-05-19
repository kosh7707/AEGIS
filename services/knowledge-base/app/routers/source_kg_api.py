"""Source Code KG ingestion API.

This endpoint persists source/build graph facts into the S5 SQLite ledger only.
Production Neo4j/Qdrant projections are intentionally outside this route.
"""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from app.context import set_request_id
from app.ledger.repository import SQLiteLedgerRepository
from app.source_kg.models import (
    SourceCodeKgContextRequest,
    SourceCodeKgContextResult,
    SourceCodeKgIngestRequest,
)
from app.source_kg.service import ingest_source_kg
from app.timeout import parse_timeout, run_sync_durable_write_with_deadline, run_sync_with_deadline

router = APIRouter(prefix="/v1/source-code-kg", tags=["source-code-kg"])

_ledger_repository: SQLiteLedgerRepository | None = None


def set_ledger_repository(repo: SQLiteLedgerRepository | None) -> None:
    global _ledger_repository
    _ledger_repository = repo


def _require_ledger() -> SQLiteLedgerRepository:
    if _ledger_repository is None:
        raise HTTPException(
            503,
            {
                "message": "Source Code KG ledger not initialized",
                "reason": "ledger_not_initialized",
            },
        )
    return _ledger_repository


def _ingest_error_reason(message: str) -> str:
    if message.startswith(
        (
            "invalid source KG checksum format:",
            "source KG checksum mismatch:",
        )
    ):
        return "source_kg_checksum_invalid"
    if message.startswith("invalid source KG line span:"):
        return "source_kg_line_span_invalid"
    if message.startswith("source KG explicit ID content conflict:"):
        return "source_kg_identity_content_conflict"
    if message.startswith(
        (
            "duplicate source graph node id in request:",
            "duplicate source graph node stable id in request:",
            "duplicate generated source graph node id in request:",
        )
    ):
        return "duplicate_source_graph_node_identity"
    if message.startswith(
        (
            "duplicate source repository artifact id in request:",
            "duplicate evidence snippet id in request:",
            "duplicate source graph edge id in request:",
            "duplicate rich IR artifact id in request:",
            "duplicate generated source repository artifact id in request:",
            "duplicate generated evidence snippet id in request:",
            "duplicate generated source graph edge id in request:",
            "duplicate generated rich IR artifact id in request:",
        )
    ):
        return "duplicate_source_kg_identity"
    if message.startswith("unknown compile commands artifact id:"):
        return "build_context_references_unknown_source_artifact"
    if message.startswith(
        (
            "source repository artifact id reused across repository snapshots:",
            "repository snapshot id reused across repository versions:",
            "build context id reused across repository snapshots:",
            "analysis artifact set id reused across build contexts:",
        )
    ):
        return "source_kg_lineage_rebind_forbidden"
    if message.startswith("unknown evidence snippet id:"):
        return "graph_node_references_unknown_evidence_snippet"
    if message.startswith(
        (
            "unknown source graph node id:",
            "unknown target graph node id:",
            "unknown source stable id:",
            "unknown target stable id:",
        )
    ):
        return "graph_edge_references_unknown_node"
    return "request_schema_invalid"


def _ingest_sync(repo: SQLiteLedgerRepository, req: SourceCodeKgIngestRequest) -> dict:
    try:
        result = ingest_source_kg(repo, req)
    except ValueError as exc:
        message = str(exc)
        raise HTTPException(422, {"message": message, "reason": _ingest_error_reason(message)}) from exc
    return result.model_dump(by_alias=True)


def _context_sync(repo: SQLiteLedgerRepository, req: SourceCodeKgContextRequest) -> dict:
    context = repo.get_source_kg_context(
        repository_snapshot_id=req.repository_snapshot_id,
        build_context_id=req.build_context_id,
        analysis_artifact_set_id=req.analysis_artifact_set_id,
        graph_node_ids=req.graph_node_ids or None,
        evidence_snippet_ids=req.evidence_snippet_ids or None,
        rich_ir_artifact_ids=req.rich_ir_artifact_ids or None,
    )
    return SourceCodeKgContextResult.model_validate(
        {"schemaVersion": "s5-source-code-kg-context-result-v1", **context}
    ).model_dump(by_alias=True)


@router.post("/ingest")
async def ingest(
    req: SourceCodeKgIngestRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await run_sync_durable_write_with_deadline(deadline, "source-code-kg-ledger-ingest", _ingest_sync, repo, req)


@router.post("/context")
async def context(
    req: SourceCodeKgContextRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await run_sync_with_deadline(deadline, "source-code-kg-context", _context_sync, repo, req)
