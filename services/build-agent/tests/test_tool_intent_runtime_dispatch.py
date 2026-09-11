from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agent_runtime.schemas.agent import LlmResponse, ToolResult
from app.tools.tool_intent import (
    ToolIntentError,
    parse_tool_intent,
    tool_intent_to_request,
)
from app.core.agent_loop import AgentLoop


def test_tool_intent_parser_accepts_single_call_tool_intent() -> None:
    intent = parse_tool_intent(
        json.dumps({
            "action": "call_tool",
            "tool_name": "read_file",
            "arguments": {"path": "package.json"},
            "rationale": "Inspect package metadata before choosing a build command.",
        }),
        available_tool_names={"read_file"},
    )

    assert intent.tool_name == "read_file"
    assert intent.arguments == {"path": "package.json"}
    assert "package" in intent.rationale


def test_tool_intent_parser_rejects_unknown_tool_and_non_object_arguments() -> None:
    with pytest.raises(ToolIntentError, match="unknown tool"):
        parse_tool_intent(
            '{"action":"call_tool","tool_name":"delete_world","arguments":{}}',
            available_tool_names={"read_file"},
        )

    with pytest.raises(ToolIntentError, match="arguments"):
        parse_tool_intent(
            '{"action":"call_tool","tool_name":"read_file","arguments":"package.json"}',
            available_tool_names={"read_file"},
        )


def test_tool_intent_to_request_uses_runtime_owned_synthetic_call_id() -> None:
    intent = parse_tool_intent(
        '{"action":"call_tool","tool_name":"list_files","arguments":{"max_depth":2}}',
        available_tool_names={"list_files"},
    )

    request = tool_intent_to_request(intent, turn=3)

    assert request.id == "runtime-toolintent-03"
    assert request.name == "list_files"
    assert request.arguments == {"max_depth": 2}


def _make_loop(llm_caller: MagicMock) -> AgentLoop:
    message_manager = MagicMock()
    message_manager.get_token_estimate.return_value = 0
    message_manager.get_messages.return_value = [{"role": "user", "content": "build this"}]
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
        taskId="build-toolintent-test",
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
    session.build_state_summary.return_value = {}
    session.total_tool_calls.return_value = 0
    session.total_prompt_tokens.return_value = 0
    session.total_completion_tokens.return_value = 0
    session.elapsed_ms.return_value = 0
    return session


@pytest.mark.asyncio
async def test_build_loop_dispatches_initial_required_acquisition_via_tool_intent() -> None:
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(return_value=LlmResponse(
        content=json.dumps({
            "action": "call_tool",
            "tool_name": "list_files",
            "arguments": {"max_depth": 3},
            "rationale": "Need the project tree before editing build scripts.",
        }),
        prompt_tokens=11,
        completion_tokens=17,
    ))
    loop = _make_loop(llm_caller)
    loop._termination_policy.should_stop.side_effect = [False, True]
    loop._tool_registry.get_all_schemas.return_value = [
        {"type": "function", "function": {"name": "list_files", "parameters": {"type": "object"}}},
    ]
    loop._budget_manager.no_callable_tools_remaining.return_value = False
    loop._tool_router.execute = AsyncMock(return_value=[
        ToolResult(tool_call_id="runtime-toolintent-01", name="list_files", success=True, content="[]"),
    ])
    sentinel = object()
    loop._result_assembler.build_from_exhaustion.return_value = sentinel

    result = await loop.run(_make_session())

    assert result is sentinel
    call_kwargs = llm_caller.call.await_args.kwargs
    assert call_kwargs["tools"] is None
    assert "tool_choice" not in call_kwargs
    assert call_kwargs["generation"].enable_thinking is True
    dispatched_calls = loop._tool_router.execute.await_args.args[0]
    assert dispatched_calls[0].id == "runtime-toolintent-01"
    assert dispatched_calls[0].name == "list_files"
    loop._message_manager.add_assistant_tool_calls.assert_called_once()
