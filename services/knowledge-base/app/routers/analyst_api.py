"""Human-readable analyst brief endpoint for S5 acquisition artifacts."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app.analyst.brief import SUPPORTED_AUDIENCES, SUPPORTED_LANGUAGES, build_analyst_brief
from app.context import set_request_id

router = APIRouter(prefix="/v1", tags=["analyst"])

MAX_ANALYST_BRIEF_SELECTOR_LENGTH = 32


class AnalystBriefRequest(BaseModel):
    """Request body for deterministic S5 analyst brief generation."""

    artifact: dict[str, Any] = Field(default_factory=dict)
    audience: str = Field(default="s3", max_length=MAX_ANALYST_BRIEF_SELECTOR_LENGTH)
    language: str = Field(default="ko", max_length=MAX_ANALYST_BRIEF_SELECTOR_LENGTH)


@router.post("/analyst-brief")
async def analyst_brief(
    req: AnalystBriefRequest,
    x_request_id: str | None = Header(None, alias="X-Request-Id"),
) -> dict[str, Any]:
    """Translate an acquisition artifact into a S3-consumable analyst brief.

    This endpoint is a pure transformation helper. It intentionally does not
    require X-Timeout-Ms because it performs no external I/O.
    """

    set_request_id(x_request_id)
    if req.audience not in SUPPORTED_AUDIENCES:
        raise HTTPException(422, {"message": "Unsupported analyst brief audience", "reason": "unsupported_analyst_brief_audience"})
    if req.language not in SUPPORTED_LANGUAGES:
        raise HTTPException(422, {"message": "Unsupported analyst brief language", "reason": "unsupported_analyst_brief_language"})
    return build_analyst_brief(req.artifact, audience=req.audience, language=req.language)
