"""ToolExecutor — 단일 tool 실행 + asyncio.wait_for 타임아웃."""

from __future__ import annotations

import asyncio
import logging
import time

from app.agent_runtime.observability import agent_log
from app.agent_runtime.schemas.agent import ToolCallRequest, ToolResult
from app.agent_runtime.tools.base import ToolImplementation

logger = logging.getLogger(__name__)


class ToolExecutor:
    """단일 tool 구현체를 실행하고 ToolResult를 반환한다."""

    def __init__(self, timeout_ms: int = 30_000) -> None:
        self._timeout_s = timeout_ms / 1000.0

    async def execute(
        self,
        impl: ToolImplementation,
        call: ToolCallRequest,
        *,
        turn: int | None = None,
    ) -> ToolResult:
        agent_log(
            logger, "Tool 실행 시작",
            component="tool_executor", phase="tool_execute",
            turn=turn, tool=call.name, level=logging.DEBUG,
        )

        start = time.monotonic()
        try:
            if getattr(impl, "wait_while_alive", False):
                result = await impl.execute(call.arguments)
            else:
                result = await asyncio.wait_for(
                    impl.execute(call.arguments),
                    timeout=self._timeout_s,
                )
            result.tool_call_id = call.id
            result.name = call.name
            result.duration_ms = int((time.monotonic() - start) * 1000)
            return result
        except asyncio.TimeoutError:
            elapsed = int((time.monotonic() - start) * 1000)
            agent_log(
                logger, "Tool 타임아웃",
                component="tool_executor", phase="tool_timeout",
                turn=turn, tool=call.name, durationMs=elapsed,
                level=logging.WARNING,
            )
            return ToolResult(
                tool_call_id=call.id,
                name=call.name,
                success=False,
                content=f'{{"error": "Tool execution timed out after {elapsed}ms"}}',
                error=f"Timeout after {elapsed}ms",
                duration_ms=elapsed,
            )
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            agent_log(
                logger, "Tool 실행 실패",
                component="tool_executor", phase="tool_error",
                turn=turn, tool=call.name,
                errorType=type(e).__name__, errorMsg=str(e),
                level=logging.ERROR,
            )
            return ToolResult(
                tool_call_id=call.id,
                name=call.name,
                success=False,
                content=f'{{"error": "{type(e).__name__}: {e}"}}',
                error=str(e),
                duration_ms=elapsed,
            )
