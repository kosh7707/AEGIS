"""Source Code KG ingestion API.

This endpoint persists source/build graph facts into the S5 SQLite ledger only.
Production Neo4j/Qdrant projections are intentionally outside this route.
"""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from app.context import set_request_id
from app.ledger.repository import SQLiteLedgerRepository
from app.source_kg.models import SourceCodeKgIngestRequest
from app.source_kg.service import ingest_source_kg
from app.timeout import parse_timeout, run_sync_with_deadline

router = APIRouter(prefix="/v1/source-code-kg", tags=["source-code-kg"])

_ledger_repository: SQLiteLedgerRepository | None = None


def set_ledger_repository(repo: SQLiteLedgerRepository | None) -> None:
    global _ledger_repository
    _ledger_repository = repo


def _require_ledger() -> SQLiteLedgerRepository:
    if _ledger_repository is None:
        raise HTTPException(503, "Source Code KG ledger not initialized")
    return _ledger_repository


def _ingest_sync(repo: SQLiteLedgerRepository, req: SourceCodeKgIngestRequest) -> dict:
    try:
        result = ingest_source_kg(repo, req)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return result.model_dump(by_alias=True)


@router.post("/ingest")
async def ingest(
    req: SourceCodeKgIngestRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id)
    deadline, _ = parse_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await run_sync_with_deadline(deadline, "source-code-kg-ledger-ingest", _ingest_sync, repo, req)
