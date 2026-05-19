"""S3-consumable S5 paper-context API projection."""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from app.context import set_request_id
from app.ledger.repository import SQLiteLedgerRepository
from app.paper_context.models import (
    PrepareCodeKbRequest,
    RetrieveFindingContextRequest,
    RetrieveGenericThreatContextRequest,
)
from app.paper_context.service import (
    paper_http_error,
    prepare_code_kb,
    reset_paper_context_state as _reset_service_state,
    retrieve_finding_context,
    retrieve_generic_threat_context,
)
from app.timeout import parse_timeout, run_sync_durable_write_with_deadline, run_sync_with_deadline

router = APIRouter(prefix="/v1/paper", tags=["paper-context"])

_ledger_repository: SQLiteLedgerRepository | None = None


def set_ledger_repository(repo: SQLiteLedgerRepository | None) -> None:
    global _ledger_repository
    _ledger_repository = repo


def reset_paper_context_state() -> None:
    _reset_service_state()


def _require_ledger() -> SQLiteLedgerRepository:
    if _ledger_repository is None:
        raise HTTPException(
            503,
            {
                "message": "S5 paper-context ledger not initialized",
                "code": "S5_PAPER_SOURCE_KG_NOT_AVAILABLE",
                "reason": "S5_PAPER_SOURCE_KG_NOT_AVAILABLE",
            },
        )
    return _ledger_repository


def _parse_paper_timeout(x_timeout_ms: int | None) -> tuple[float, float]:
    try:
        return parse_timeout(x_timeout_ms)
    except HTTPException as exc:
        reason = exc.detail.get("reason") if isinstance(exc.detail, dict) else None
        if reason == "timeout_header_missing_or_invalid":
            raise paper_http_error(
                400,
                "S5_PAPER_TIMEOUT_HEADER_MISSING_OR_INVALID",
                "X-Timeout-Ms header is required and must be a positive integer for paper-context POST requests.",
            ) from exc
        raise


@router.post("/code-kb/prepare")
async def prepare(
    req: PrepareCodeKbRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id or req.request_id)
    deadline, _ = _parse_paper_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await run_sync_durable_write_with_deadline(deadline, "s5-paper-code-kb-prepare", prepare_code_kb, repo, req, x_request_id)


@router.post("/finding-context/retrieve")
async def finding_context(
    req: RetrieveFindingContextRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id or req.request_id)
    deadline, _ = _parse_paper_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await run_sync_with_deadline(deadline, "s5-paper-finding-context", retrieve_finding_context, repo, req, x_request_id)


@router.post("/threat-context/generic")
async def generic_threat_context(
    req: RetrieveGenericThreatContextRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id or req.request_id)
    deadline, _ = _parse_paper_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await run_sync_with_deadline(deadline, "s5-paper-generic-threat-context", retrieve_generic_threat_context, repo, req, x_request_id)
