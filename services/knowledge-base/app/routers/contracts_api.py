"""Machine-readable S5 contract endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Header

from app.context import set_request_id
from app.contracts.acquisition import contract_snapshot
from app.contracts.source_kg import source_code_kg_contract_snapshot

router = APIRouter(prefix="/v1/contracts", tags=["contracts"])


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
