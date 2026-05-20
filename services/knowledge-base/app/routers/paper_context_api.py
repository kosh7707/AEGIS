"""S3-consumable S5 paper-context API projection."""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, Header, HTTPException, Response

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

router = APIRouter(prefix="/v1/paper", tags=["paper-context"])
logger = logging.getLogger(__name__)

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


def _validate_optional_paper_timeout(x_timeout_ms: int | None) -> None:
    """Accept legacy timeout headers without making them semantic deadlines.

    S3 paper orchestration no longer treats a caller-side wall-clock deadline as
    a terminal producer result.  These endpoints are synchronous and bounded by
    their internal work shape; when the service is alive and progressing, S3 may
    wait without a fixed absolute read timeout.  If an old client still sends
    ``X-Timeout-Ms``, S5 validates that it is positive but does not convert it
    into a semantic 408 for paper calls.
    """
    if x_timeout_ms is not None and x_timeout_ms <= 0:
        raise paper_http_error(
            400,
            "S5_PAPER_TIMEOUT_HEADER_MISSING_OR_INVALID",
            "X-Timeout-Ms, when supplied for paper-context POST requests, must be a positive integer.",
        )


def _paper_request_id(req, x_request_id: str | None) -> str:
    return x_request_id or req.request_id


def _paper_log_extra(req, *, path: str, request_id: str, status: int | None = None, elapsed_ms: int | None = None, result: dict | None = None, error_code: str | None = None) -> dict:
    extra = {
        "service": "s5-kb",
        "requestId": request_id,
        "method": "POST",
        "path": path,
        "caseId": req.case_id,
        "buildTargetId": req.build_target_id,
        "paperRunId": req.paper_run_id,
    }
    finding_id = getattr(req, "finding_id", None)
    if finding_id:
        extra["findingId"] = finding_id
    if status is not None:
        extra["status"] = status
    if elapsed_ms is not None:
        extra["elapsedMs"] = elapsed_ms
    if result:
        for key in ("s5ProducerRunId", "retrievalRunId", "codeKbRunId", "surfaceStatus", "stageReadiness"):
            if key in result:
                extra[key] = result[key]
    if error_code:
        extra["errorCode"] = error_code
    return extra


def _error_code(exc: Exception) -> str:
    if isinstance(exc, HTTPException) and isinstance(exc.detail, dict):
        return str(exc.detail.get("code") or exc.detail.get("reason") or exc.status_code)
    if isinstance(exc, HTTPException):
        return str(exc.status_code)
    return exc.__class__.__name__


async def _run_observed_paper_call(*, path: str, req, x_request_id: str | None, response: Response, compute):
    request_id = _paper_request_id(req, x_request_id)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id
    started = time.monotonic()
    logger.info("S5 paper endpoint start", extra={"_extra": _paper_log_extra(req, path=path, request_id=request_id)})
    try:
        result = await asyncio.to_thread(compute)
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        status = exc.status_code if isinstance(exc, HTTPException) else 500
        logger.error(
            "S5 paper endpoint error",
            extra={"_extra": _paper_log_extra(req, path=path, request_id=request_id, status=status, elapsed_ms=elapsed_ms, error_code=_error_code(exc))},
        )
        raise
    elapsed_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "S5 paper endpoint end",
        extra={"_extra": _paper_log_extra(req, path=path, request_id=request_id, status=200, elapsed_ms=elapsed_ms, result=result)},
    )
    return result


@router.post("/code-kb/prepare")
async def prepare(
    req: PrepareCodeKbRequest,
    response: Response,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id or req.request_id)
    _validate_optional_paper_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await _run_observed_paper_call(
        path="/v1/paper/code-kb/prepare",
        req=req,
        x_request_id=x_request_id,
        response=response,
        compute=lambda: prepare_code_kb(repo, req, x_request_id),
    )


@router.post("/finding-context/retrieve")
async def finding_context(
    req: RetrieveFindingContextRequest,
    response: Response,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id or req.request_id)
    _validate_optional_paper_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await _run_observed_paper_call(
        path="/v1/paper/finding-context/retrieve",
        req=req,
        x_request_id=x_request_id,
        response=response,
        compute=lambda: retrieve_finding_context(repo, req, x_request_id),
    )


@router.post("/threat-context/generic")
async def generic_threat_context(
    req: RetrieveGenericThreatContextRequest,
    response: Response,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
    x_timeout_ms: int | None = Header(None, alias="X-Timeout-Ms"),
) -> dict:
    set_request_id(x_request_id or req.request_id)
    _validate_optional_paper_timeout(x_timeout_ms)
    repo = _require_ledger()
    return await _run_observed_paper_call(
        path="/v1/paper/threat-context/generic",
        req=req,
        x_request_id=x_request_id,
        response=response,
        compute=lambda: retrieve_generic_threat_context(repo, req, x_request_id),
    )
