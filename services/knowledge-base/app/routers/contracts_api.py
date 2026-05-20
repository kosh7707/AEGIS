"""Machine-readable S5 contract endpoints."""

from __future__ import annotations

import logging
import time
from uuid import uuid4

from fastapi import APIRouter, Header, Response

from app.context import get_request_id, set_request_id
from app.contracts.acquisition import contract_snapshot
from app.contracts.analyst import analyst_brief_contract_snapshot
from app.contracts.judge import judge_contract_snapshot
from app.contracts.paper_context import paper_context_contract_snapshot
from app.contracts.source_kg import source_code_kg_contract_snapshot

router = APIRouter(prefix="/v1/contracts", tags=["contracts"])
logger = logging.getLogger(__name__)


@router.get("/acquisition")
async def acquisition_contract(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    return contract_snapshot()


@router.get("/source-code-kg")
async def source_code_kg_contract(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    return source_code_kg_contract_snapshot()


@router.get("/analyst-brief")
async def analyst_brief_contract(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    return analyst_brief_contract_snapshot()


@router.get("/judge")
async def judge_contract(
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    set_request_id(x_request_id)
    return judge_contract_snapshot()


@router.get("/paper-context")
async def paper_context_contract(
    response: Response,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict:
    request_id = x_request_id or get_request_id() or f"req-{uuid4()}"
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id
    path = "/v1/contracts/paper-context"
    started = time.monotonic()
    base_extra = {
        "service": "s5-kb",
        "requestId": request_id,
        "method": "GET",
        "path": path,
    }
    logger.info("S5 paper endpoint start", extra={"_extra": base_extra})
    try:
        snapshot = paper_context_contract_snapshot()
    except Exception as exc:
        logger.error(
            "S5 paper endpoint error",
            extra={
                "_extra": {
                    **base_extra,
                    "status": 500,
                    "elapsedMs": int((time.monotonic() - started) * 1000),
                    "errorCode": exc.__class__.__name__,
                }
            },
        )
        raise
    logger.info(
        "S5 paper endpoint end",
        extra={
            "_extra": {
                **base_extra,
                "status": 200,
                "elapsedMs": int((time.monotonic() - started) * 1000),
            }
        },
    )
    return snapshot
