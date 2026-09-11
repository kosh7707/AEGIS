"""에이전트 전용 DTO — 17개 객체 간 통신 규약."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ToolCostTier(StrEnum):
    CHEAP = "cheap"
    MEDIUM = "medium"
    EXPENSIVE = "expensive"


class ToolCallRequest(BaseModel):
    """LLM 응답에서 파싱된 단일 tool call."""

    id: str
    name: str
    arguments: dict
    args_hash: str = ""

    def model_post_init(self, __context) -> None:
        if not self.args_hash:
            canonical = json.dumps(
                {"name": self.name, "args": self.arguments},
                sort_keys=True, ensure_ascii=False,
            )
            self.args_hash = hashlib.sha256(canonical.encode()).hexdigest()[:16]


class ToolResult(BaseModel):
    """단일 tool 실행 결과."""

    tool_call_id: str
    name: str
    success: bool
    content: str
    new_evidence_refs: list[str] = Field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None


class LlmResponse(BaseModel):
    """단일 LLM 턴의 파싱된 응답."""

    content: str | None = None
    reasoning: str | None = None
    tool_calls: list[ToolCallRequest] = Field(default_factory=list)
    finish_reason: str = "stop"
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class ToolTraceStep(BaseModel):
    """tool 실행 프로비넌스 기록."""

    step_id: str
    turn_number: int
    tool: str
    args_hash: str
    cost_tier: ToolCostTier
    duration_ms: int = 0
    success: bool = True
    new_evidence_refs: list[str] = Field(default_factory=list)
    error: str | None = None


class TurnRecord(BaseModel):
    """에이전트 턴 기록."""

    turn_number: int
    audit_order: int = 0
    llm_response_type: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tool_steps: list[ToolTraceStep] = Field(default_factory=list)


class BudgetState(BaseModel):
    """예산 상태 — 변이 가능."""

    total_completion_tokens: int = 0
    max_completion_tokens: int = 2000
    total_prompt_tokens: int = 0
    max_prompt_tokens: int = 100_000
    total_steps: int = 0
    max_steps: int = 6
    cheap_calls: int = 0
    max_cheap_calls: int = 3
    medium_calls: int = 0
    max_medium_calls: int = 2
    expensive_calls: int = 0
    max_expensive_calls: int = 1
    consecutive_no_evidence_turns: int = 0
    max_consecutive_no_evidence: int = 2
    duplicate_call_hashes: set[str] = Field(default_factory=set)


class AgentAuditInfo(BaseModel):
    """deep-analyze 확장 감사 정보."""

    model_config = ConfigDict(protected_namespaces=())

    input_hash: str
    latency_ms: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    turn_count: int = 0
    tool_call_count: int = 0
    trace: list[ToolTraceStep] = Field(default_factory=list)
    turns: list[TurnRecord] = Field(default_factory=list)
    termination_reason: str = ""
    created_at: str = ""
    model_name: str = ""          # S7에서 사용된 LLM 모델 식별자
    prompt_version: str = ""      # 에이전트 시스템 프롬프트 버전
    evidenceCatalogDiagnostics: dict = Field(default_factory=dict)
