"""S4/S5 upstream 서비스 응답 Pydantic adapter 모델.

raw dict 접근 대신 이 모델로 변환하면 KeyError 없이 안전하게 필드에 접근할 수 있다.
model_validate()가 누락 필드에 대해 기본값을 제공하므로 upstream 스키마 변경에도 강건하다.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ─── S4 SAST Runner 응답 ───


class SastFinding(BaseModel):
    """S4 /v1/scan → scan.findings[] 항목."""

    ruleId: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    severity: str = ""
    tool: str = ""
    metadata: dict = Field(default_factory=dict)


class CodeFunction(BaseModel):
    """S4 /v1/functions → functions[] 항목."""

    name: str = ""
    file: str = ""
    line: int = 0
    origin: str | None = None
    params: list[str] = Field(default_factory=list)


# ─── S5 Knowledge Base 응답 ───


class KbSearchHit(BaseModel):
    """S5 /v1/search → hits[] 항목."""

    id: str = ""
    score: float = 0.0
    content: str = ""
    source: str = ""


class ScaLibrary(BaseModel):
    """S4 /v1/libraries → libraries[] 항목."""

    name: str = ""
    version: str = ""
    license: str = ""
