"""ToolImplementation — tool 구현체의 공통 Protocol."""

from __future__ import annotations

from typing import Protocol

from app.agent_runtime.schemas.agent import ToolResult


class ToolImplementation(Protocol):
    """모든 tool 구현체가 따르는 인터페이스."""

    async def execute(self, arguments: dict) -> ToolResult: ...
