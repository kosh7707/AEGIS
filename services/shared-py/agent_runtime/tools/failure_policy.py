"""Shared fallback policy for failed tool calls."""

from __future__ import annotations

from app.agent_runtime.schemas.agent import ToolCallRequest, ToolResult


class ToolFailurePolicy:
    """Return a structured ToolResult for tool execution failures."""

    def handle(self, call: ToolCallRequest, error: str, session) -> ToolResult:
        return ToolResult(
            tool_call_id=call.id,
            name=call.name,
            success=False,
            content=(
                f'{{"error": "Tool execution failed: {error}", '
                f'"tool": "{call.name}", '
                '"suggestion": "Try an alternative approach or skip this tool."}'
            ),
            error=error,
        )
