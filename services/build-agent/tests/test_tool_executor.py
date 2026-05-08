"""ToolExecutor 단위 테스트."""

from __future__ import annotations

import asyncio

import pytest

from app.agent_runtime.schemas.agent import ToolCallRequest, ToolResult
from app.agent_runtime.tools.executor import ToolExecutor


# ── 헬퍼 ──────────────────────────────────────────────────


def _make_call(name: str = "test_tool") -> ToolCallRequest:
    return ToolCallRequest(id="call-exec-001", name=name, arguments={"key": "value"})


class _NormalImpl:
    """즉시 성공 결과 반환."""

    async def execute(self, arguments: dict) -> ToolResult:
        return ToolResult(
            tool_call_id="",
            name="",
            success=True,
            content='{"result": "ok"}',
        )


class _SlowImpl:
    """2초 대기 후 반환 (타임아웃 테스트용)."""

    async def execute(self, arguments: dict) -> ToolResult:
        await asyncio.sleep(2.0)
        return ToolResult(
            tool_call_id="",
            name="",
            success=True,
            content='{"result": "slow"}',
        )


class _ExplodingImpl:
    """RuntimeError를 발생시키는 구현체."""

    async def execute(self, arguments: dict) -> ToolResult:
        raise RuntimeError("Boom!")


# ── 정상 실행 ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_normal_execution() -> None:
    """정상 실행 → success, duration_ms 설정."""
    executor = ToolExecutor(timeout_ms=5000)
    call = _make_call()
    result = await executor.execute(_NormalImpl(), call, turn=1)
    assert result.success is True
    assert result.duration_ms >= 0
    assert result.tool_call_id == "call-exec-001"
    assert result.name == "test_tool"


# ── 타임아웃 ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_timeout_handling() -> None:
    """구현체가 timeout_ms를 초과하면 error result."""
    executor = ToolExecutor(timeout_ms=100)  # 100ms timeout
    call = _make_call()
    result = await executor.execute(_SlowImpl(), call, turn=1)
    assert result.success is False
    assert "timed out" in result.content.lower() or "timeout" in result.content.lower()
    assert result.error is not None


# ── 예외 처리 ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_exception_handling() -> None:
    """구현체에서 예외 발생 시 error result."""
    executor = ToolExecutor(timeout_ms=5000)
    call = _make_call()
    result = await executor.execute(_ExplodingImpl(), call, turn=1)
    assert result.success is False
    assert "RuntimeError" in result.content
    assert result.error == "Boom!"


# ── tool_call_id 매핑 ──────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_call_id_set() -> None:
    """result.tool_call_id가 call.id와 일치해야 한다."""
    executor = ToolExecutor(timeout_ms=5000)
    call = ToolCallRequest(id="unique-id-42", name="my_tool", arguments={})
    result = await executor.execute(_NormalImpl(), call, turn=1)
    assert result.tool_call_id == "unique-id-42"
    assert result.name == "my_tool"


class _SlowWaitWhileAliveImpl:
    wait_while_alive = True

    async def execute(self, arguments: dict) -> ToolResult:
        await asyncio.sleep(0.05)
        return ToolResult(tool_call_id="", name="", success=True, content='{"result":"alive"}')


@pytest.mark.asyncio
async def test_wait_while_alive_tool_is_not_cut_off_by_executor_timeout() -> None:
    executor = ToolExecutor(timeout_ms=1)
    call = _make_call("try_build")
    result = await executor.execute(_SlowWaitWhileAliveImpl(), call, turn=1)
    assert result.success is True
    assert result.name == "try_build"
    assert result.tool_call_id == "call-exec-001"
