from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agent_runtime.errors import LlmHttpError, LlmTimeoutError, StrictJsonContractError
from app.agent_runtime.schemas.agent import LlmResponse
from app.core.agent_loop import AgentLoop, _tool_choice_for_turn
from app.types import FailureCode, TaskStatus


def _make_loop(llm_caller):
    message_manager = MagicMock()
    message_manager.get_token_estimate.return_value = 0
    message_manager.get_messages.return_value = [{"role": "user", "content": "hi"}]
    message_manager.compact = AsyncMock(return_value=0)

    retry_policy = MagicMock()
    retry_policy._max_retries = 0
    retry_policy.should_retry.return_value = False

    return AgentLoop(
        llm_caller=llm_caller,
        message_manager=message_manager,
        tool_registry=MagicMock(),
        tool_router=MagicMock(),
        termination_policy=MagicMock(),
        budget_manager=MagicMock(),
        token_counter=MagicMock(),
        result_assembler=MagicMock(),
        turn_summarizer=MagicMock(),
        retry_policy=retry_policy,
    )


def _make_session():
    session = MagicMock()
    session.turn_count = 0
    session.trace = []
    session.request = SimpleNamespace(
        taskId="build-test-001",
        constraints=SimpleNamespace(
            enableThinking=None,
            temperature=None,
            topP=None,
            topK=None,
            minP=None,
            presencePenalty=None,
            repetitionPenalty=None,
        ),
    )
    session.budget = SimpleNamespace(
        max_steps=10,
        total_steps=0,
        total_completion_tokens=0,
        cheap_calls=0,
        medium_calls=0,
        expensive_calls=0,
        max_completion_tokens=20000,
    )
    session.build_state_summary.return_value = "state"
    session.total_tool_calls.return_value = 0
    session.total_prompt_tokens.return_value = 0
    session.total_completion_tokens.return_value = 0
    session.elapsed_ms.return_value = 0
    return session


@pytest.mark.asyncio
async def test_call_with_retry_prefers_async_ownership_when_no_tools():
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(return_value=LlmResponse(content='{"summary":"ok"}'))
    loop = _make_loop(llm_caller)

    await loop._call_with_retry(_make_session(), None)

    kwargs = llm_caller.call.await_args.kwargs
    assert kwargs["prefer_async_ownership"] is True
    assert kwargs["generation"].temperature == 1.0


@pytest.mark.asyncio
async def test_call_with_retry_keeps_sync_path_when_tools_present():
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(return_value=LlmResponse(content=None, tool_calls=[]))
    loop = _make_loop(llm_caller)

    await loop._call_with_retry(_make_session(), [{"type": "function", "function": {"name": "tool"}}])

    kwargs = llm_caller.call.await_args.kwargs
    assert kwargs["prefer_async_ownership"] is False


def test_tool_choice_avoids_required_after_toolintent_runtime_dispatch():
    session = MagicMock()
    session.trace = []
    assert _tool_choice_for_turn(session=session, current_tools=[{"name": "try_build"}], force_report=False) == "auto"

    session.trace = [MagicMock(success=False)]
    assert _tool_choice_for_turn(session=session, current_tools=[{"name": "try_build"}], force_report=False) == "auto"

    session.trace = [MagicMock(success=True)]
    assert _tool_choice_for_turn(session=session, current_tools=[{"name": "try_build"}], force_report=False) == "auto"


@pytest.mark.asyncio
async def test_run_maps_empty_live_completion_to_output_deficient_not_model_unavailable():
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(return_value=LlmResponse(content="", prompt_tokens=1, completion_tokens=0))
    loop = _make_loop(llm_caller)
    loop._termination_policy.should_stop.return_value = False
    loop._tool_registry.get_all_schemas.return_value = None
    loop._budget_manager.no_callable_tools_remaining.return_value = True
    sentinel = object()
    loop._result_assembler.build.return_value = sentinel

    result = await loop.run(_make_session())

    assert result is sentinel
    loop._result_assembler.build_failure.assert_not_called()
    content, *_ = loop._result_assembler.build.call_args.args
    assert "output_deficient" in content
    assert "buildResult" in content


@pytest.mark.asyncio
async def test_run_maps_llm_timeout_to_timeout_boundary():
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(side_effect=LlmTimeoutError("llm wait interrupted"))
    loop = _make_loop(llm_caller)
    loop._termination_policy.should_stop.return_value = False
    loop._tool_registry.get_all_schemas.return_value = None
    loop._budget_manager.no_callable_tools_remaining.return_value = True
    sentinel = object()
    loop._result_assembler.build_failure.return_value = sentinel

    result = await loop.run(_make_session())

    assert result is sentinel
    _, status, code, *_ = loop._result_assembler.build_failure.call_args.args
    assert status == TaskStatus.TIMEOUT
    assert code == FailureCode.TIMEOUT


@pytest.mark.asyncio
async def test_run_maps_llm_overload_to_completed_output_deficient_outcome():
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(side_effect=LlmHttpError(503, "busy"))
    loop = _make_loop(llm_caller)
    loop._termination_policy.should_stop.return_value = False
    loop._tool_registry.get_all_schemas.return_value = None
    loop._budget_manager.no_callable_tools_remaining.return_value = True
    sentinel = object()
    loop._result_assembler.build.return_value = sentinel

    result = await loop.run(_make_session())

    assert result is sentinel
    loop._result_assembler.build_failure.assert_not_called()
    content, *_ = loop._result_assembler.build.call_args.args
    assert "output_deficient" in content
    assert "LLM output/call deficiency" in content


@pytest.mark.asyncio
async def test_run_maps_strict_json_contract_to_output_deficient_synthesis_failure():
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(side_effect=StrictJsonContractError(error_detail="invalid json"))
    loop = _make_loop(llm_caller)
    loop._termination_policy.should_stop.return_value = False
    loop._tool_registry.get_all_schemas.return_value = None
    loop._budget_manager.no_callable_tools_remaining.return_value = True
    sentinel = object()
    loop._result_assembler.build.return_value = sentinel

    result = await loop.run(_make_session())

    assert result is sentinel
    loop._result_assembler.build_failure.assert_not_called()
    content, *_ = loop._result_assembler.build.call_args.args
    assert "output_deficient" in content
    assert "LLM strict JSON output deficient" in content
