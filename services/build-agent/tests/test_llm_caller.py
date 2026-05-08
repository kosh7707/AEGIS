"""Build Agent LlmCaller request-contract tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agent_runtime.errors import LlmContractViolationError, LlmUnavailableError
from app.agent_runtime.llm.caller import LlmCaller
from app.agent_runtime.llm.generation_policy import THINKING_CODING


def _make_response(data: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = data
    resp.text = ""
    resp.headers = {}
    return resp



def _assert_complete_generation_tuple(body: dict, *, temperature: float = 1.0, enable_thinking: bool = True) -> None:
    assert body["temperature"] == temperature
    assert body["top_p"] == 0.95
    assert body["top_k"] == 20
    assert body["min_p"] == 0.0
    assert body["presence_penalty"] == 0.0
    assert body["repetition_penalty"] == 1.0
    assert body["chat_template_kwargs"] == {"enable_thinking": enable_thinking}


def _content_response(content: str = '{"summary":"ok"}') -> dict:
    return {
        "choices": [{
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


def _tool_calls_response(tool_calls: list[dict]) -> dict:
    return {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": tool_calls,
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


def _reasoning_only_response(reasoning: str, *, finish_reason: str = "stop") -> dict:
    return {
        "choices": [{
            "message": {"role": "assistant", "content": None, "reasoning": reasoning},
            "finish_reason": finish_reason,
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


@pytest.mark.asyncio
async def test_build_llm_caller_defaults_to_thinking_for_tool_turns():
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    caller._client.post = AsyncMock(return_value=_make_response(_content_response()))

    await caller.call(
        [{"role": "user", "content": "build"}],
        tools=[{"type": "function", "function": {"name": "try_build"}}],
    )

    body = caller._client.post.await_args.kwargs["json"]
    headers = caller._client.post.await_args.kwargs["headers"]
    _assert_complete_generation_tuple(body)
    assert "response_format" not in body
    assert "X-AEGIS-Strict-JSON" not in headers


@pytest.mark.asyncio
async def test_build_llm_caller_preserves_reasoning_diagnostics():
    caller = LlmCaller("http://fake:8000", "qwen")
    resp_data = _content_response()
    resp_data["choices"][0]["message"]["reasoning"] = "diagnostic chain summary"
    caller._client = MagicMock()
    caller._client.post = AsyncMock(return_value=_make_response(resp_data))

    result = await caller.call([{"role": "user", "content": "build"}])

    assert result.content == '{"summary":"ok"}'
    assert result.reasoning == "diagnostic chain summary"


@pytest.mark.asyncio
async def test_build_llm_caller_empty_tool_calls_contract_violation():
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    caller._client.post = AsyncMock(return_value=_make_response(_tool_calls_response([])))

    with pytest.raises(LlmContractViolationError) as exc_info:
        await caller.call(
            [{"role": "user", "content": "build"}],
            tools=[{"type": "function", "function": {"name": "try_build"}}],
        )

    assert exc_info.value.retryable is True
    assert exc_info.value.violation_reason == "finish_reason_tool_calls_with_empty_array"


@pytest.mark.asyncio
async def test_build_llm_caller_reasoning_only_contract_violation():
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    caller._client.post = AsyncMock(return_value=_make_response(_reasoning_only_response("I will call try_build")))

    with pytest.raises(LlmContractViolationError) as exc_info:
        await caller.call([{"role": "user", "content": "build"}])

    assert exc_info.value.violation_reason == "all_output_absorbed_into_reasoning"
    assert exc_info.value.reasoning_excerpt == "I will call try_build"


@pytest.mark.asyncio
@pytest.mark.parametrize("unsupported", ["required", {"type": "function", "function": {"name": "try_build"}}])
async def test_build_llm_caller_rejects_unsupported_tool_choice_before_http(unsupported):
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    caller._client.post = AsyncMock()

    with pytest.raises(ValueError, match="auto.*none"):
        await caller.call(
            [{"role": "user", "content": "build"}],
            tools=[{"type": "function", "function": {"name": "try_build"}}],
            tool_choice=unsupported,  # type: ignore[arg-type]
        )

    caller._client.post.assert_not_awaited()


@pytest.mark.asyncio
async def test_build_llm_caller_defaults_to_thinking_for_strict_json_finalizer():
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    caller._client.post = AsyncMock(return_value=_make_response(_content_response()))

    await caller.call([{"role": "user", "content": "final"}])

    body = caller._client.post.await_args.kwargs["json"]
    headers = caller._client.post.await_args.kwargs["headers"]
    _assert_complete_generation_tuple(body)
    assert body["response_format"] == {"type": "json_object"}
    assert headers["X-AEGIS-Strict-JSON"] == "true"


@pytest.mark.asyncio
async def test_build_llm_caller_scalar_temperature_compatibility_warns():
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    caller._client.post = AsyncMock(return_value=_make_response(_content_response()))

    with pytest.warns(DeprecationWarning, match="GenerationControls"):
        await caller.call([{ "role": "user", "content": "build" }], temperature=0.25)

    body = caller._client.post.await_args.kwargs["json"]
    assert body["temperature"] == 0.25


@pytest.mark.asyncio
async def test_build_llm_caller_422_invalid_tool_choice_is_non_retryable_contract_failure():
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    resp = _make_response({}, status_code=422)
    resp.text = '{"code":"INVALID_TOOL_CHOICE","message":"unsupported tool_choice"}'
    caller._client.post = AsyncMock(return_value=resp)

    from app.agent_runtime.errors import LlmHttpError

    with pytest.raises(LlmHttpError) as exc_info:
        await caller.call([{"role": "user", "content": "build"}])

    assert exc_info.value.upstream_status == 422
    assert exc_info.value.retryable is False
    assert exc_info.value.code == "LLM_HTTP_ERROR"


@pytest.mark.asyncio
async def test_build_llm_caller_503_llm_parse_retry_is_retryable_transport_failure():
    caller = LlmCaller("http://fake:8000", "qwen")
    caller._client = MagicMock()
    resp = _make_response({}, status_code=503)
    resp.text = '{"code":"LLM_PARSE_RETRY","reason":"response_contract_violation"}'
    caller._client.post = AsyncMock(return_value=resp)

    from app.agent_runtime.errors import LlmHttpError

    with pytest.raises(LlmHttpError) as exc_info:
        await caller.call([{"role": "user", "content": "build"}])

    assert exc_info.value.upstream_status == 503
    assert exc_info.value.retryable is True
    assert exc_info.value.code == "LLM_OVERLOADED"


@pytest.mark.asyncio
async def test_build_llm_caller_accepts_explicit_generation_controls():
    caller = LlmCaller("http://fake:8000", "qwen", enable_thinking=False)
    caller._client = MagicMock()
    caller._client.post = AsyncMock(return_value=_make_response(_content_response()))

    await caller.call(
        [{"role": "user", "content": "build"}],
        generation=THINKING_CODING,
        max_tokens=1234,
    )

    body = caller._client.post.await_args.kwargs["json"]
    assert body["max_tokens"] == 1234
    assert body["temperature"] == 0.6
    assert body["top_p"] == 0.95
    assert body["top_k"] == 20
    assert body["chat_template_kwargs"] == {"enable_thinking": True}


@pytest.mark.asyncio
async def test_build_llm_caller_async_ownership_continues_until_completed(monkeypatch):
    caller = LlmCaller("http://fake:8000", "qwen")
    status_calls = 0

    async def fake_post(url, **kwargs):
        if url.endswith("/v1/async-chat-requests"):
            return _make_response({
                "requestId": "acr_build",
                "statusUrl": "/v1/async-chat-requests/acr_build",
                "resultUrl": "/v1/async-chat-requests/acr_build/result",
            }, status_code=202)
        raise AssertionError(f"sync fallback must not be attempted: {url}")

    async def fake_get(url, **kwargs):
        nonlocal status_calls
        if url.endswith("/v1/health"):
            return _make_response({
                "status": "ok",
                "ready": True,
                "llmReady": True,
                "blockedReason": None,
                "dependencyStatus": {"llmBackend": {"status": "ok"}},
            })
        if url.endswith("/v1/async-chat-requests/acr_build"):
            status_calls += 1
            if status_calls < 3:
                return _make_response({
                    "requestId": "acr_build",
                    "state": "running",
                    "localAckState": "transport-only",
                    "blockedReason": None,
                    "resultReady": False,
                })
            return _make_response({
                "requestId": "acr_build",
                "state": "completed",
                "localAckState": None,
                "resultReady": True,
            })
        if url.endswith("/v1/async-chat-requests/acr_build/result"):
            return _make_response({
                "requestId": "acr_build",
                "response": _content_response('{"summary":"build async"}'),
            })
        raise AssertionError(f"unexpected GET url: {url}")

    caller._client = MagicMock()
    caller._client.post = AsyncMock(side_effect=fake_post)
    caller._client.get = AsyncMock(side_effect=fake_get)
    monkeypatch.setattr("asyncio.sleep", AsyncMock())

    result = await caller.call(
        [{"role": "user", "content": "final"}],
        prefer_async_ownership=True,
    )

    assert result.content == '{"summary":"build async"}'
    assert status_calls == 3


@pytest.mark.asyncio
async def test_build_llm_caller_async_preflight_rejects_unready_llm_backend():
    caller = LlmCaller("http://fake:8000", "qwen")

    async def fake_get(url, **kwargs):
        if url.endswith("/v1/health"):
            return _make_response({
                "status": "ok",
                "ready": False,
                "llmReady": False,
                "degraded": True,
                "degradeReasons": ["llm_backend_unreachable"],
                "blockedReason": "backend_unreachable",
                "dependencyStatus": {"llmBackend": {"status": "unreachable"}},
            })
        raise AssertionError(f"unexpected GET url: {url}")

    caller._client = MagicMock()
    caller._client.get = AsyncMock(side_effect=fake_get)
    caller._client.post = AsyncMock()

    with pytest.raises(LlmUnavailableError) as exc_info:
        await caller.call(
            [{"role": "user", "content": "final"}],
            prefer_async_ownership=True,
        )

    assert "backend_unreachable" in str(exc_info.value)
    caller._client.post.assert_not_awaited()
