"""ToolRegistry — tool 스키마 등록/조회. LLM에 전달할 function 목록 관리."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.agent_runtime.schemas.agent import ToolCostTier


class ToolSideEffect(StrEnum):
    """도구의 부수 효과 수준."""

    PURE = "pure"         # 부수 효과 없음 (list_files 등)
    READ = "read"         # 외부 상태 읽기 (sast.scan, knowledge.search)
    WRITE = "write"       # 파일시스템 쓰기 (write_file, edit_file, delete_file)
    EXECUTE = "execute"   # 프로세스 실행 (try_build)


@dataclass
class ToolSchema:
    """OpenAI function calling 스키마 + 비용 등급 + 부수 효과 메타데이터."""

    name: str
    description: str
    parameters: dict = field(default_factory=dict)
    cost_tier: ToolCostTier = ToolCostTier.CHEAP
    side_effect: ToolSideEffect = ToolSideEffect.PURE


class ToolRegistry:
    """tool 스키마를 등록하고 조회한다."""

    def __init__(self) -> None:
        self._schemas: dict[str, ToolSchema] = {}

    def register(self, schema: ToolSchema) -> None:
        self._schemas[schema.name] = schema

    def unregister(self, name: str) -> None:
        self._schemas.pop(name, None)

    def get(self, name: str) -> ToolSchema | None:
        return self._schemas.get(name)

    def get_cost_tier(self, name: str) -> ToolCostTier:
        schema = self._schemas.get(name)
        return schema.cost_tier if schema else ToolCostTier.CHEAP

    def get_all_schemas(self) -> list[dict]:
        """OpenAI tools 형식으로 반환."""
        return [
            {
                "type": "function",
                "function": {
                    "name": s.name,
                    "description": s.description,
                    "parameters": s.parameters,
                },
            }
            for s in self._schemas.values()
        ]

    def list_names(self) -> list[str]:
        return list(self._schemas.keys())

    def get_available_schemas(self, budget_manager) -> list[dict] | None:
        """예산이 남은 tier의 도구만 OpenAI tools 형식으로 반환. 전부 소진 시 None."""
        available = []
        for s in self._schemas.values():
            if budget_manager.can_make_call(s.cost_tier):
                available.append({
                    "type": "function",
                    "function": {
                        "name": s.name,
                        "description": s.description,
                        "parameters": s.parameters,
                    },
                })
        return available if available else None
