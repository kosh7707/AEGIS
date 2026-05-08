import json
import logging
import time
from typing import Any
from uuid import uuid4

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.async_chat_manager import AsyncChatRequestRecord
from app.config import settings
from app.context import get_request_id, set_request_id
from app.generation_policy import TimeoutDefaults
from app.generation_observability import effective_enable_thinking, generation_log_fields
from app.metrics import prom
from app.schemas.request import AsyncChatSubmitRequest, TaskRequest
from app.schemas.response import (
    AsyncChatAcceptedResponse,
    AsyncChatResultResponse,
    AsyncChatStatusResponse,
    TaskFailureResponse,
    TaskSuccessResponse,
)

logger = logging.getLogger(__name__)
_exchange_logger = logging.getLogger("llm_exchange")

router = APIRouter(prefix="/v1", tags=["v1"])
_STRICT_JSON_HEADER = "x-aegis-strict-json"
_ALLOWED_TOOL_CHOICE_VALUES = {"auto", "none"}
_REQUIRED_CHAT_GENERATION_FIELDS = (
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "presence_penalty",
    "repetition_penalty",
)
_CHAT_GENERATION_FIELD_RANGES: dict[str, tuple[type, float, float | None]] = {
    "max_tokens": (int, 1, 32768),
    "temperature": (float, 0.0, 2.0),
    "top_p": (float, 0.0, 1.0),
    "top_k": (int, -1, None),
    "min_p": (float, 0.0, 1.0),
    "presence_penalty": (float, -2.0, 2.0),
    "repetition_penalty": (float, 0.0, 2.0),
}


def _health_readiness(
    *,
    llm_mode: str,
    llm_backend: dict[str, Any] | None,
    circuit_breaker: dict[str, Any] | None,
    rag: dict[str, Any],
) -> dict[str, Any]:
    """Expose process liveness separately from LLM dependency readiness.

    `/v1/health.status` intentionally remains process-liveness (`ok` when the
    gateway process can serve the health route).  Callers that need to know
    whether LLM work can proceed must use these readiness fields instead.
    """

    dependency_status: dict[str, Any] = {
        "llmBackend": llm_backend or {"status": "mock", "endpoint": None},
        "rag": {
            "status": rag["status"],
            "enabled": rag["enabled"],
            "kbEndpoint": rag["kbEndpoint"],
        },
    }
    if circuit_breaker is not None:
        dependency_status["circuitBreaker"] = circuit_breaker

    degrade_reasons: list[str] = []
    blocked_reason: str | None = None

    backend_ready = True
    if llm_mode == "real":
        backend_ready = bool(llm_backend and llm_backend.get("status") == "ok")
        if not backend_ready:
            degrade_reasons.append("llm_backend_unreachable")
            blocked_reason = "backend_unreachable"

    cb_state = circuit_breaker.get("state") if circuit_breaker else None
    circuit_ready = cb_state not in {"open", "half_open"}
    if not circuit_ready:
        reason = (
            "llm_circuit_half_open"
            if cb_state == "half_open"
            else "llm_circuit_open"
        )
        degrade_reasons.append(reason)
        blocked_reason = blocked_reason or (
            "circuit_half_open"
            if cb_state == "half_open"
            else "circuit_open"
        )

    llm_ready = backend_ready and circuit_ready
    return {
        "ready": llm_ready,
        "llmReady": llm_ready,
        "degraded": not llm_ready,
        "degradeReasons": degrade_reasons,
        "blockedReason": blocked_reason,
        "dependencyStatus": dependency_status,
    }


def _ensure_request_id(req: Request) -> str:
    request_id = req.headers.get("x-request-id") or get_request_id() or f"gw-{uuid4().hex[:12]}"
    set_request_id(request_id)
    return request_id


def _json_response(
    data: TaskSuccessResponse | TaskFailureResponse,
) -> JSONResponse:
    request_id = get_request_id()
    headers = {"X-Request-Id": request_id} if request_id else {}
    return JSONResponse(
        content=data.model_dump(mode="json"),
        headers=headers,
    )


def _error_response(
    *,
    status_code: int,
    request_id: str,
    code: str,
    message: str,
    retryable: bool,
    headers: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
    error_detail_extra: dict[str, Any] | None = None,
) -> JSONResponse:
    error_detail: dict[str, Any] = {
        "code": code,
        "message": message,
        "requestId": request_id,
        "retryable": retryable,
    }
    if error_detail_extra:
        error_detail.update(error_detail_extra)
    content: dict[str, Any] = {
        "success": False,
        "error": message,
        "retryable": retryable,
        "errorDetail": error_detail,
    }
    if extra:
        content.update(extra)
    response_headers = {"X-Request-Id": request_id} if request_id else {}
    if headers:
        response_headers.update(headers)
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers=response_headers,
    )


def _exchange_payload_from_response(resp: httpx.Response, resp_data: Any) -> Any:
    if isinstance(resp_data, (dict, list)):
        return resp_data
    text = resp.text
    return {"rawText": text}


def _log_llm_exchange(
    *,
    request_id: str,
    exchange_type: str,
    request_body: dict,
    response: httpx.Response,
    response_data: Any,
    elapsed_ms: int,
    strict_json: bool,
    async_request_id: str | None = None,
) -> None:
    choices = response_data.get("choices", [{}]) if isinstance(response_data, dict) else [{}]
    finish_reason = choices[0].get("finish_reason", "?") if choices else "?"
    tool_choice = request_body.get("tool_choice", "none")
    generation = generation_log_fields(request_body, task_type=None)
    prom.record_generation_observability(
        endpoint=exchange_type,
        generation=generation,
        response_data=response_data,
        tool_choice=tool_choice,
    )
    entry: dict[str, Any] = {
        "service": "s7-gateway",
        "level": 30,
        "time": int(time.time() * 1000),
        "requestId": request_id,
        "msg": f"[LLM exchange] {exchange_type} {request_body.get('model', '')} latencyMs={elapsed_ms}",
        "type": exchange_type,
        "elapsedMs": elapsed_ms,
        "latencyMs": elapsed_ms,
        "status": "ok" if response.status_code == 200 else f"HTTP_{response.status_code}",
        "model": request_body.get("model", ""),
        "usage": response_data.get("usage") if isinstance(response_data, dict) else None,
        "finishReason": finish_reason,
        "strictJson": strict_json,
        "effectiveThinking": _effective_enable_thinking(request_body),
        "generation": generation,
        "toolChoice": tool_choice,
        "toolCount": len(request_body.get("tools", [])),
        "request": request_body,
        "response": _exchange_payload_from_response(response, response_data),
    }
    if async_request_id:
        entry["asyncRequestId"] = async_request_id
    _exchange_logger.info(json.dumps(entry, ensure_ascii=False))

def _is_truthy_header(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _strict_json_requested(req: Request) -> bool:
    return _is_truthy_header(req.headers.get(_STRICT_JSON_HEADER))


def _build_forward_headers(request_id: str) -> dict[str, str]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.llm_api_key:
        headers["Authorization"] = f"Bearer {settings.llm_api_key}"
    if request_id:
        headers["X-Request-Id"] = request_id
    return headers


def _prepare_chat_forward(
    request_body: dict,
    *,
    model_registry,
    strict_json: bool,
) -> tuple[dict, str]:
    body = dict(request_body)
    profile = model_registry.get_default()
    llm_endpoint = profile.endpoint if profile else settings.llm_endpoint
    body["model"] = profile.modelName if profile else settings.llm_model
    if strict_json:
        _enforce_strict_json_request_controls(body)
    return body, llm_endpoint


def _chat_timeout_from_header(raw_value: str | None) -> float:
    try:
        return min(float(raw_value or TimeoutDefaults.CHAT_DEFAULT_SECONDS), TimeoutDefaults.CHAT_MAX_SECONDS)
    except (ValueError, TypeError):
        return TimeoutDefaults.CHAT_DEFAULT_SECONDS


def _async_chat_backend_timeout() -> httpx.Timeout:
    """Timeout policy for async wait-while-alive ownership.

    `/v1/chat` remains finite through `X-Timeout-Seconds`, but async ownership
    must not fail a live non-streaming backend attempt solely because elapsed
    read time crossed the former sync ceiling. Keep connect/write/pool bounds
    for transport establishment/resource waits and leave read unbounded.
    """
    return httpx.Timeout(
        connect=settings.llm_connect_timeout,
        read=None,
        write=10.0,
        pool=10.0,
    )


def _strict_json_violation(
    request_id: str,
    model: str,
    elapsed_ms: int,
    detail: str,
) -> JSONResponse:
    logger.warning(
        "[chat proxy] strict JSON contract violation requestId=%s, latencyMs=%d, detail=%s",
        request_id, elapsed_ms, detail,
        extra={"elapsedMs": elapsed_ms},
    )
    return _error_response(
        status_code=502,
        request_id=request_id,
        code="LLM_PARSE_ERROR",
        message="Strict JSON contract violated",
        retryable=True,
        headers={
            "X-Request-Id": request_id,
            "X-Model": model,
            "X-Gateway-Latency-Ms": str(elapsed_ms),
            "X-AEGIS-Strict-JSON": "applied",
        },
        extra={
            "strictJson": True,
        },
        error_detail_extra={"detail": detail},
    )


def _effective_enable_thinking(body: dict) -> bool | None:
    return effective_enable_thinking(body)


def _is_valid_chat_generation_value(
    value: Any,
    *,
    expected_type: type,
    minimum: float,
    maximum: float | None,
) -> bool:
    if isinstance(value, bool):
        return False
    if expected_type is int:
        if not isinstance(value, int):
            return False
        numeric = value
    elif expected_type is float:
        if not isinstance(value, (int, float)):
            return False
        numeric = float(value)
    else:
        return False
    if numeric < minimum:
        return False
    return maximum is None or numeric <= maximum


def _chat_generation_control_errors(body: dict) -> tuple[list[str], list[str]]:
    missing = [
        field
        for field in _REQUIRED_CHAT_GENERATION_FIELDS
        if field not in body or body.get(field) is None
    ]
    invalid = [
        field
        for field, (expected_type, minimum, maximum) in _CHAT_GENERATION_FIELD_RANGES.items()
        if field not in missing
        and not _is_valid_chat_generation_value(
            body.get(field),
            expected_type=expected_type,
            minimum=minimum,
            maximum=maximum,
        )
    ]

    chat_template_kwargs = body.get("chat_template_kwargs")
    if not isinstance(chat_template_kwargs, dict):
        missing.append("chat_template_kwargs.enable_thinking")
    elif not isinstance(chat_template_kwargs.get("enable_thinking"), bool):
        invalid.append("chat_template_kwargs.enable_thinking")

    return missing, invalid


def _chat_generation_controls_error(
    *,
    request_id: str,
    missing_fields: list[str],
    invalid_fields: list[str],
) -> JSONResponse:
    detail_extra: dict[str, Any] = {}
    if missing_fields:
        detail_extra["missingFields"] = missing_fields
    if invalid_fields:
        detail_extra["invalidFields"] = invalid_fields
    return _error_response(
        status_code=422,
        request_id=request_id,
        code="INVALID_GENERATION_CONTROLS",
        message="Invalid caller-owned generation controls",
        retryable=False,
        error_detail_extra=detail_extra,
    )


def _tool_choice_error(body: dict) -> str | None:
    if "tool_choice" not in body or body.get("tool_choice") is None:
        return None
    value = body.get("tool_choice")
    if isinstance(value, str) and value in _ALLOWED_TOOL_CHOICE_VALUES:
        return None
    if isinstance(value, str):
        return (
            f"unsupported tool_choice value: {value!r}; "
            "supported values are 'auto' and 'none'"
        )
    if isinstance(value, dict):
        return (
            "named tool_choice objects are not supported by the current "
            "S7 Qwen/vLLM/MTP stack; use 'auto' or 'none'"
        )
    return (
        f"unsupported tool_choice type: {type(value).__name__}; "
        "supported values are 'auto' and 'none'"
    )


def _tool_choice_validation_error(
    *,
    request_id: str,
    detail: str,
) -> JSONResponse:
    return _error_response(
        status_code=422,
        request_id=request_id,
        code="INVALID_TOOL_CHOICE",
        message="Unsupported tool_choice for current S7 LLM stack",
        retryable=False,
        error_detail_extra={
            "detail": detail,
            "allowedToolChoice": sorted(_ALLOWED_TOOL_CHOICE_VALUES),
        },
    )


def _enforce_strict_json_request_controls(body: dict) -> None:
    body["response_format"] = {"type": "json_object"}


def _apply_strict_json_response_contract(resp_data: dict) -> tuple[dict | None, str | None]:
    choices = resp_data.get("choices")
    if not isinstance(choices, list) or not choices:
        return None, "LLM response missing choices[0] in strict JSON mode"

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return None, "LLM response choices[0] is not an object in strict JSON mode"

    message = first_choice.get("message")
    if not isinstance(message, dict):
        return None, "LLM response missing choices[0].message in strict JSON mode"

    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        return None, "LLM response missing JSON content in strict JSON mode"

    try:
        parsed_content = json.loads(content)
    except json.JSONDecodeError as exc:
        return None, f"LLM response content is not valid JSON in strict JSON mode: {exc.msg}"

    if not isinstance(parsed_content, dict):
        return None, "LLM response content is not a JSON object in strict JSON mode"

    normalized = dict(resp_data)
    normalized_choices = list(choices)
    normalized_choice = dict(first_choice)
    normalized_message = dict(message)
    normalized_message["content"] = json.dumps(parsed_content, ensure_ascii=False, separators=(",", ":"))
    if "reasoning" in normalized_message:
        normalized_message["reasoning"] = None
    normalized_choice["message"] = normalized_message
    normalized_choices[0] = normalized_choice
    normalized["choices"] = normalized_choices
    return normalized, None


def _raw_response_excerpt(resp_data: Any) -> str:
    try:
        return json.dumps(resp_data, ensure_ascii=False)[:1000]
    except TypeError:
        return repr(resp_data)[:1000]


def _is_empty_content(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _validate_llm_response_contract(resp_data: dict) -> str | None:
    choices = resp_data.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return None
    finish_reason = first_choice.get("finish_reason")
    message = first_choice.get("message")
    if not isinstance(message, dict):
        return None

    tool_calls = message.get("tool_calls")
    has_tool_calls = isinstance(tool_calls, list) and len(tool_calls) > 0
    content = message.get("content")
    reasoning = message.get("reasoning")

    if finish_reason == "tool_calls" and not has_tool_calls:
        return "finish_reason_tool_calls_with_empty_array"
    if (
        finish_reason in {"stop", "tool_calls"}
        and not has_tool_calls
        and _is_empty_content(content)
        and isinstance(reasoning, str)
        and reasoning.strip()
    ):
        return "all_output_absorbed_into_reasoning"
    return None


def _llm_response_contract_violation(
    request_id: str,
    model: str,
    elapsed_ms: int,
    reason: str,
    resp_data: Any,
) -> JSONResponse:
    logger.warning(
        "[chat proxy] LLM response contract violation requestId=%s, latencyMs=%d, reason=%s",
        request_id, elapsed_ms, reason,
        extra={"elapsedMs": elapsed_ms},
    )
    prom.record_response_contract_violation(
        endpoint="chat_proxy",
        reason=reason,
    )
    return _error_response(
        status_code=503,
        request_id=request_id,
        code="LLM_PARSE_RETRY",
        message="LLM response contract violated",
        retryable=True,
        headers={
            "X-Request-Id": request_id,
            "X-Model": model,
            "X-Gateway-Latency-Ms": str(elapsed_ms),
        },
        extra={
            "contractViolation": True,
            "violationReason": reason,
        },
        error_detail_extra={
            "violationReason": reason,
            "rawResponseExcerpt": _raw_response_excerpt(resp_data),
        },
    )


async def _record_contract_violation_failure(
    *,
    token_tracker,
    request_tracker,
    request_id: str,
    endpoint: str,
    duration_s: float,
    reason: str,
    resp_data: Any,
) -> None:
    usage = resp_data.get("usage", {}) if isinstance(resp_data, dict) else {}
    if token_tracker:
        await token_tracker.record(
            endpoint=endpoint,
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            success=False,
            duration_s=duration_s,
            error_type="LLM_PARSE_RETRY",
        )
    if request_tracker and request_id:
        request_tracker.mark_ack_break(
            request_id,
            blocked_reason="response_contract_violation",
            ack_source="contract-validator",
        )
        request_tracker.clear(request_id)


@router.post("/tasks")
async def create_task(request: TaskRequest, req: Request) -> JSONResponse:
    request_id = _ensure_request_id(req)
    logger.info(
        "[v1] Task received: taskId=%s, taskType=%s",
        request.taskId, request.taskType,
    )

    pipeline = req.app.state.pipeline
    token_tracker = getattr(req.app.state, "token_tracker", None)
    request_tracker = getattr(req.app.state, "request_tracker", None)

    if request_tracker and request_id:
        request_tracker.register(
            request_id,
            endpoint="tasks",
            task_type=request.taskType.value,
        )

    task_start = time.monotonic()
    try:
        result = await pipeline.execute(request)
    except Exception:
        logger.error("[v1] Unexpected error", exc_info=True)
        task_duration = time.monotonic() - task_start
        if token_tracker:
            await token_tracker.record(
                endpoint="tasks", task_type=request.taskType,
                success=False, duration_s=task_duration,
                error_type="INTERNAL_ERROR",
            )
        request_id = get_request_id()
        if request_tracker and request_id:
            request_tracker.mark_ack_break(
                request_id,
                blocked_reason="internal_error",
                ack_source="router-exception",
            )
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": "Internal server error",
                "errorDetail": {
                    "code": "INTERNAL_ERROR",
                    "message": "Internal server error",
                    "requestId": request_id,
                    "retryable": False,
                },
            },
            headers={"X-Request-Id": request_id} if request_id else {},
        )
    finally:
        if request_tracker and request_id:
            request_tracker.clear(request_id)

    task_duration = time.monotonic() - task_start
    if token_tracker:
        is_success = hasattr(result, "status") and result.status == "completed"
        token_usage = getattr(getattr(result, "audit", None), "tokenUsage", None)
        await token_tracker.record(
            endpoint="tasks",
            task_type=request.taskType,
            prompt_tokens=token_usage.prompt if token_usage else 0,
            completion_tokens=token_usage.completion if token_usage else 0,
            success=is_success,
            duration_s=task_duration,
            error_type=getattr(result, "failureCode", None) if not is_success else None,
        )

    return _json_response(result)


def _async_result_error(
    *,
    status_code: int,
    request_id: str,
    trace_request_id: str,
    state: str,
    expires_at: str | None,
    error: str,
    blocked_reason: str | None = None,
    error_detail: str | None = None,
    retryable: bool = False,
) -> JSONResponse:
    code = "CONFLICT"
    if status_code == 410:
        code = "ASYNC_RESULT_EXPIRED"
    elif status_code == 404:
        code = "NOT_FOUND"
    return _error_response(
        status_code=status_code,
        request_id=trace_request_id or request_id,
        code=code,
        message=error,
        retryable=retryable,
        extra={
            "requestId": request_id,
            "traceRequestId": trace_request_id,
            "state": state,
            "expiresAt": expires_at,
            "error": error,
            "blockedReason": blocked_reason,
        },
        error_detail_extra={
            "detail": error_detail or blocked_reason or error,
            "blockedReason": blocked_reason,
        },
    )


async def _run_async_chat_request(
    *,
    app,
    record: AsyncChatRequestRecord,
    request_body: dict,
    strict_json: bool,
) -> None:
    set_request_id(record.trace_request_id)

    model_registry = app.state.model_registry
    body, llm_endpoint = _prepare_chat_forward(
        request_body,
        model_registry=model_registry,
        strict_json=strict_json,
    )
    fwd_headers = _build_forward_headers(record.trace_request_id)
    req_timeout = _async_chat_backend_timeout()

    circuit_breaker = getattr(app.state, "circuit_breaker", None)
    token_tracker = getattr(app.state, "token_tracker", None)
    llm_semaphore = app.state.llm_semaphore
    proxy_client = app.state.proxy_client
    async_chat_manager = app.state.async_chat_manager

    start = time.monotonic()

    if circuit_breaker:
        from app.errors import LlmCircuitOpenError
        try:
            await circuit_breaker.check()
        except LlmCircuitOpenError:
            if token_tracker:
                await token_tracker.record(
                    endpoint="async_chat",
                    success=False,
                    duration_s=0.0,
                    error_type="LLM_CIRCUIT_OPEN",
                )
            await async_chat_manager.fail(
                record.request_id,
                blocked_reason="circuit_open",
                ack_source="circuit-open",
                error="LLM Engine circuit open",
                error_detail="Circuit breaker is open for the LLM backend",
                retryable=True,
            )
            return

    try:
        async with llm_semaphore:
            prom.CONCURRENT_REQUESTS.inc()
            try:
                await async_chat_manager.mark_phase(
                    record.request_id,
                    phase="llm-inference",
                    state="running",
                    ack_source="queue-exit",
                )
                await async_chat_manager.mark_transport_only(
                    record.request_id,
                    phase="llm-inference",
                )
                resp = await proxy_client.post(
                    f"{llm_endpoint}/v1/chat/completions",
                    json=body,
                    headers=fwd_headers,
                    timeout=req_timeout,
                )
            finally:
                prom.CONCURRENT_REQUESTS.dec()
    except httpx.ConnectError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if circuit_breaker:
            await circuit_breaker.record_failure()
        if token_tracker:
            await token_tracker.record(
                endpoint="async_chat",
                success=False,
                duration_s=elapsed_ms / 1000,
                error_type="CONNECT",
            )
        await async_chat_manager.fail(
            record.request_id,
            blocked_reason="backend_unreachable",
            ack_source="connect-error",
            error="LLM Engine unreachable",
            error_detail="Could not connect to LLM backend",
            retryable=True,
        )
        return
    except httpx.TimeoutException:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if circuit_breaker:
            await circuit_breaker.record_failure()
        if token_tracker:
            await token_tracker.record(
                endpoint="async_chat",
                success=False,
                duration_s=elapsed_ms / 1000,
                error_type="TIMEOUT",
            )
        await async_chat_manager.fail(
            record.request_id,
            blocked_reason="backend_timeout",
            ack_source="backend-timeout",
            error="LLM Engine timeout",
            error_detail=(
                "LLM backend transport timed out while establishing or writing the "
                "async request; async ownership does not impose an elapsed read ceiling"
            ),
            retryable=True,
        )
        return

    elapsed_ms = int((time.monotonic() - start) * 1000)
    try:
        resp_data = resp.json()
    except Exception:
        resp_data = {}

    _log_llm_exchange(
        request_id=record.trace_request_id,
        exchange_type="async_chat",
        request_body=body,
        response=resp,
        response_data=resp_data,
        elapsed_ms=elapsed_ms,
        strict_json=strict_json,
        async_request_id=record.request_id,
    )

    if resp.status_code == 200 and isinstance(resp_data, dict):
        contract_violation = _validate_llm_response_contract(resp_data)
        if contract_violation:
            prom.record_response_contract_violation(
                endpoint="async_chat",
                reason=contract_violation,
            )
            usage = resp_data.get("usage", {})
            if token_tracker:
                await token_tracker.record(
                    endpoint="async_chat",
                    prompt_tokens=usage.get("prompt_tokens", 0) if isinstance(usage, dict) else 0,
                    completion_tokens=usage.get("completion_tokens", 0) if isinstance(usage, dict) else 0,
                    success=False,
                    duration_s=elapsed_ms / 1000,
                    error_type="LLM_PARSE_RETRY",
                )
            await async_chat_manager.fail(
                record.request_id,
                blocked_reason="response_contract_violation",
                ack_source="contract-validator",
                error="LLM response contract violated",
                error_detail=contract_violation,
                retryable=True,
            )
            return

    if strict_json and resp.status_code == 200:
        normalized_resp_data, strict_error = _apply_strict_json_response_contract(
            resp_data if isinstance(resp_data, dict) else {},
        )
        if strict_error:
            await async_chat_manager.fail(
                record.request_id,
                blocked_reason="strict_json_contract_violation",
                ack_source="strict-json-contract",
                error="Strict JSON contract violated",
                error_detail=strict_error,
                retryable=True,
            )
            return
        resp_data = normalized_resp_data

    if resp.status_code == 200:
        if circuit_breaker:
            await circuit_breaker.record_success()
        usage = resp_data.get("usage", {}) if isinstance(resp_data, dict) else {}
        if token_tracker:
            await token_tracker.record(
                endpoint="async_chat",
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                success=True,
                duration_s=elapsed_ms / 1000,
            )
        await async_chat_manager.complete(
            record.request_id,
            response_payload=resp_data,
        )
        return

    if circuit_breaker and resp.status_code >= 500:
        await circuit_breaker.record_failure()
    if token_tracker:
        await token_tracker.record(
            endpoint="async_chat",
            success=False,
            duration_s=elapsed_ms / 1000,
            error_type=f"HTTP_{resp.status_code}",
        )
    await async_chat_manager.fail(
        record.request_id,
        blocked_reason=f"http_{resp.status_code}",
        ack_source="backend-error",
        error=f"LLM Engine HTTP_{resp.status_code}",
        error_detail=(resp.text[:500] if resp.text else f"LLM backend returned HTTP {resp.status_code}"),
        retryable=resp.status_code in {429, 500, 502, 503, 504},
    )


@router.post("/async-chat-requests")
async def create_async_chat_request(
    request: AsyncChatSubmitRequest,
    req: Request,
) -> JSONResponse:
    trace_request_id = _ensure_request_id(req)
    strict_json = _strict_json_requested(req)
    request_body = request.model_dump(mode="json", exclude_none=True)
    tool_choice_error = _tool_choice_error(request_body)
    if tool_choice_error:
        return _tool_choice_validation_error(
            request_id=trace_request_id,
            detail=tool_choice_error,
        )

    async_chat_manager = req.app.state.async_chat_manager
    record = await async_chat_manager.submit(
        trace_request_id=trace_request_id,
        runner=lambda submitted_record: _run_async_chat_request(
            app=req.app,
            record=submitted_record,
            request_body=request_body,
            strict_json=strict_json,
        ),
    )

    accepted = AsyncChatAcceptedResponse(**record.to_submit_response())
    headers = {"X-Request-Id": trace_request_id} if trace_request_id else {}
    return JSONResponse(
        status_code=202,
        content=accepted.model_dump(mode="json"),
        headers=headers,
    )


@router.get("/async-chat-requests/{request_id}")
async def get_async_chat_request_status(request_id: str, req: Request) -> JSONResponse:
    trace_request_id = _ensure_request_id(req)
    async_chat_manager = req.app.state.async_chat_manager
    status_payload = await async_chat_manager.status(request_id)
    if status_payload is None:
        return _error_response(
            status_code=404,
            request_id=trace_request_id,
            code="NOT_FOUND",
            message="Async request not found",
            retryable=False,
            extra={"requestId": request_id},
        )

    status_response = AsyncChatStatusResponse(**status_payload)
    return JSONResponse(
        content=status_response.model_dump(mode="json"),
        headers={"X-Request-Id": trace_request_id},
    )


@router.get("/async-chat-requests/{request_id}/result")
async def get_async_chat_request_result(request_id: str, req: Request) -> JSONResponse:
    trace_request_id = _ensure_request_id(req)
    async_chat_manager = req.app.state.async_chat_manager
    record = await async_chat_manager.result(request_id)
    if record is None:
        return _error_response(
            status_code=404,
            request_id=trace_request_id,
            code="NOT_FOUND",
            message="Async request not found",
            retryable=False,
            extra={"requestId": request_id},
        )

    if record.state == "completed" and record.response_payload is not None:
        result_response = AsyncChatResultResponse(**record.to_result_response())
        return JSONResponse(
            content=result_response.model_dump(mode="json"),
            headers={"X-Request-Id": trace_request_id},
        )

    if record.state == "expired":
        return _async_result_error(
            status_code=410,
            request_id=record.request_id,
            trace_request_id=record.trace_request_id,
            state=record.state,
            expires_at=record.to_status_response()["expiresAt"],
            error="Async result expired",
        )

    if record.state in {"queued", "running"}:
        return _async_result_error(
            status_code=409,
            request_id=record.request_id,
            trace_request_id=record.trace_request_id,
            state=record.state,
            expires_at=record.to_status_response()["expiresAt"],
            error="Async result not ready",
            blocked_reason=record.blocked_reason,
            retryable=True,
        )

    return _async_result_error(
        status_code=409,
        request_id=record.request_id,
        trace_request_id=record.trace_request_id,
        state=record.state,
        expires_at=record.to_status_response()["expiresAt"],
        error=record.error or "Async request did not complete successfully",
        error_detail=record.error_detail,
        retryable=record.retryable,
        blocked_reason=record.blocked_reason,
    )


@router.delete("/async-chat-requests/{request_id}")
async def cancel_async_chat_request(request_id: str, req: Request) -> JSONResponse:
    trace_request_id = _ensure_request_id(req)
    async_chat_manager = req.app.state.async_chat_manager
    record = await async_chat_manager.cancel(request_id)
    if record is None:
        return _error_response(
            status_code=404,
            request_id=trace_request_id,
            code="NOT_FOUND",
            message="Async request not found",
            retryable=False,
            extra={"requestId": request_id},
        )

    status_response = AsyncChatStatusResponse(**record.to_status_response())
    return JSONResponse(
        content=status_response.model_dump(mode="json"),
        headers={"X-Request-Id": trace_request_id},
    )


@router.get("/health")
async def health(req: Request) -> JSONResponse:
    request_id = _ensure_request_id(req)
    model_registry = req.app.state.model_registry
    prompt_registry = req.app.state.prompt_registry

    result = {
        "service": "s7-gateway",
        "status": "ok",
        "version": "1.0.0",
        "llmMode": settings.llm_mode,
        "modelProfiles": [
            p["profileId"] for p in model_registry.list_all()
        ],
        "activePromptVersions": {
            p["taskType"]: p["version"]
            for p in prompt_registry.list_all()
        },
    }
    llm_backend = None
    if settings.llm_mode == "real":
        llm_backend = await _check_llm_backend(model_registry, req.app.state.proxy_client)
        result["llmBackend"] = llm_backend
        result["llmConcurrency"] = settings.llm_concurrency

    # Circuit Breaker 상태
    circuit_breaker_snapshot = None
    cb = getattr(req.app.state, "circuit_breaker", None)
    if cb:
        circuit_breaker_snapshot = cb.snapshot()
        result["circuitBreaker"] = circuit_breaker_snapshot

    # RAG 상태
    threat_search = getattr(req.app.state, "threat_search", None)
    rag = {
        "enabled": settings.rag_enabled,
        "kbEndpoint": settings.kb_endpoint,
        "topK": settings.rag_top_k,
        "minScore": settings.rag_min_score,
        "policy": "task-pipeline-context-enrichment",
        "status": "ok" if threat_search else "disabled",
    }
    result["rag"] = rag
    result.update(_health_readiness(
        llm_mode=settings.llm_mode,
        llm_backend=llm_backend,
        circuit_breaker=circuit_breaker_snapshot,
        rag=rag,
    ))

    request_tracker = getattr(req.app.state, "request_tracker", None)
    if request_tracker:
        target_request_id = req.query_params.get("requestId")
        result.update(request_tracker.snapshot(request_id=target_request_id))

    return JSONResponse(content=result, headers={"X-Request-Id": request_id})


@router.post("/chat")
async def chat_proxy(req: Request) -> Response:
    """LLM Engine 프록시 — OpenAI-compatible chat completion 요청을 전달한다.

    S3 Agent 등 LLM 소비자가 이 엔드포인트를 통해 LLM Engine에 접근한다.
    Gateway가 단일 관문 역할을 하므로 LLM 벤더/API 변경 시 이곳만 수정하면 된다.
    """
    request_id = _ensure_request_id(req)

    original_body = await req.json()
    strict_json = _strict_json_requested(req)
    missing_generation_controls, invalid_generation_controls = _chat_generation_control_errors(original_body)
    if missing_generation_controls or invalid_generation_controls:
        return _chat_generation_controls_error(
            request_id=request_id,
            missing_fields=missing_generation_controls,
            invalid_fields=invalid_generation_controls,
        )
    tool_choice_error = _tool_choice_error(original_body)
    if tool_choice_error:
        return _tool_choice_validation_error(
            request_id=request_id,
            detail=tool_choice_error,
        )

    model_registry = req.app.state.model_registry
    body, llm_endpoint = _prepare_chat_forward(
        original_body,
        model_registry=model_registry,
        strict_json=strict_json,
    )

    fwd_headers = _build_forward_headers(request_id)

    # 호출자 타임아웃: X-Timeout-Seconds 헤더로 전달, 미전달 시 기본 1800초
    caller_timeout = _chat_timeout_from_header(req.headers.get("x-timeout-seconds"))
    req_timeout = httpx.Timeout(
        connect=settings.llm_connect_timeout,
        read=caller_timeout,
        write=10.0,
        pool=10.0,
    )

    start = time.monotonic()

    circuit_breaker = getattr(req.app.state, "circuit_breaker", None)
    token_tracker = getattr(req.app.state, "token_tracker", None)
    request_tracker = getattr(req.app.state, "request_tracker", None)
    llm_semaphore = req.app.state.llm_semaphore
    proxy_client = req.app.state.proxy_client

    if request_tracker and request_id:
        request_tracker.register(request_id, endpoint="chat")

    # Circuit Breaker 확인
    if circuit_breaker:
        from app.errors import LlmCircuitOpenError
        try:
            await circuit_breaker.check()
        except LlmCircuitOpenError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning("[chat proxy] Circuit Breaker OPEN — 즉시 실패")
            if request_tracker and request_id:
                request_tracker.mark_ack_break(
                    request_id,
                    blocked_reason="circuit_open",
                    ack_source="circuit-open",
                )
                request_tracker.clear(request_id)
            return _error_response(
                status_code=503,
                request_id=request_id,
                code="LLM_CIRCUIT_OPEN",
                message="LLM Engine circuit open",
                retryable=True,
                headers={
                    "X-Request-Id": request_id,
                    "X-Model": body.get("model", ""),
                    "X-Gateway-Latency-Ms": str(elapsed_ms),
                },
            )

    try:
        if request_tracker and request_id:
            request_tracker.mark_phase(
                request_id,
                phase="llm-inference",
                state="queued",
                ack_source="chat-accepted",
            )
        async with llm_semaphore:
            prom.CONCURRENT_REQUESTS.inc()
            try:
                if request_tracker and request_id:
                    request_tracker.mark_phase(
                        request_id,
                        phase="llm-inference",
                        state="running",
                        ack_source="queue-exit",
                    )
                    request_tracker.mark_transport_only(
                        request_id,
                        phase="llm-inference",
                    )
                resp = await proxy_client.post(
                    f"{llm_endpoint}/v1/chat/completions",
                    json=body,
                    headers=fwd_headers,
                    timeout=req_timeout,
                )
            finally:
                prom.CONCURRENT_REQUESTS.dec()
    except httpx.ConnectError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        has_tools = bool(body.get("tools"))
        logger.error(
            "[chat proxy] 실패 requestId=%s, latencyMs=%d, error=CONNECT, hasTools=%s",
            request_id, elapsed_ms, has_tools,
        )
        if circuit_breaker:
            await circuit_breaker.record_failure()
        if request_tracker and request_id:
            request_tracker.mark_ack_break(
                request_id,
                blocked_reason="backend_unreachable",
                ack_source="connect-error",
            )
            request_tracker.clear(request_id)
        return _error_response(
            status_code=503,
            request_id=request_id,
            code="LLM_UNAVAILABLE",
            message="LLM Engine unreachable",
            retryable=True,
            headers={
                "X-Request-Id": request_id,
                "X-Model": body.get("model", ""),
                "X-Gateway-Latency-Ms": str(elapsed_ms),
            },
        )
    except httpx.TimeoutException:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        has_tools = bool(body.get("tools"))
        logger.error(
            "[chat proxy] 실패 requestId=%s, latencyMs=%d, error=TIMEOUT, hasTools=%s",
            request_id, elapsed_ms, has_tools,
        )
        if circuit_breaker:
            await circuit_breaker.record_failure()
        if request_tracker and request_id:
            request_tracker.mark_ack_break(
                request_id,
                blocked_reason="transport_timeout",
                ack_source="transport-timeout",
            )
            request_tracker.clear(request_id)
        return _error_response(
            status_code=504,
            request_id=request_id,
            code="LLM_TIMEOUT",
            message="LLM Engine timeout",
            retryable=True,
            headers={
                "X-Request-Id": request_id,
                "X-Model": body.get("model", ""),
                "X-Gateway-Latency-Ms": str(elapsed_ms),
            },
        )

    elapsed_ms = int((time.monotonic() - start) * 1000)

    # 교환 로그 기록
    resp_data = None
    try:
        resp_data = resp.json()
    except Exception:
        pass

    # finish_reason 추출 (교환 로그 + 성공 로그 공용)
    _choices = resp_data.get("choices", [{}]) if resp_data else [{}]
    _finish_reason = _choices[0].get("finish_reason", "?") if _choices else "?"

    _log_llm_exchange(
        request_id=request_id,
        exchange_type="chat_proxy",
        request_body=body,
        response=resp,
        response_data=resp_data,
        elapsed_ms=elapsed_ms,
        strict_json=strict_json,
    )

    if resp.status_code == 200 and isinstance(resp_data, dict):
        contract_violation = _validate_llm_response_contract(resp_data)
        if contract_violation:
            await _record_contract_violation_failure(
                token_tracker=token_tracker,
                request_tracker=request_tracker,
                request_id=request_id,
                endpoint="chat",
                duration_s=elapsed_ms / 1000,
                reason=contract_violation,
                resp_data=resp_data,
            )
            return _llm_response_contract_violation(
                request_id=request_id,
                model=body.get("model", ""),
                elapsed_ms=elapsed_ms,
                reason=contract_violation,
                resp_data=resp_data,
            )

    if strict_json and resp.status_code == 200:
        normalized_resp_data, strict_error = _apply_strict_json_response_contract(
            resp_data if isinstance(resp_data, dict) else {},
        )
        if strict_error:
            if request_tracker and request_id:
                request_tracker.mark_ack_break(
                    request_id,
                    blocked_reason="strict_json_contract_violation",
                    ack_source="strict-json-contract",
                )
                request_tracker.clear(request_id)
            return _strict_json_violation(
                request_id=request_id,
                model=body.get("model", ""),
                elapsed_ms=elapsed_ms,
                detail=strict_error,
            )
        resp_data = normalized_resp_data

    if resp.status_code == 200:
        if circuit_breaker:
            await circuit_breaker.record_success()
        usage = resp_data.get("usage", {}) if resp_data else {}
        if token_tracker:
            await token_tracker.record(
                endpoint="chat",
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                success=True,
                duration_s=elapsed_ms / 1000,
            )
        logger.info(
            "[chat proxy] 완료 requestId=%s, latencyMs=%d, model=%s, "
            "promptTokens=%d, completionTokens=%d, finishReason=%s, strictJson=%s, "
            "hasTools=%s, toolChoice=%s, toolCount=%d",
            request_id, elapsed_ms, body.get("model", ""),
            usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0),
            _finish_reason, strict_json, bool(body.get("tools")),
            body.get("tool_choice", "none"), len(body.get("tools", [])),
            extra={"elapsedMs": elapsed_ms},
        )
    else:
        if circuit_breaker and resp.status_code >= 500:
            await circuit_breaker.record_failure()
        if token_tracker:
            await token_tracker.record(
                endpoint="chat", success=False,
                duration_s=elapsed_ms / 1000,
                error_type=f"HTTP_{resp.status_code}",
            )
        logger.warning(
            "[chat proxy] LLM Engine HTTP_%d, requestId=%s, latencyMs=%d",
            resp.status_code, request_id, elapsed_ms,
        )
        if request_tracker and request_id and resp.status_code >= 500:
            request_tracker.mark_ack_break(
                request_id,
                blocked_reason=f"http_{resp.status_code}",
                ack_source="backend-error",
            )

    resp_headers: dict[str, str] = {}
    if request_id:
        resp_headers["X-Request-Id"] = request_id
    resp_headers["X-Model"] = body.get("model", "")
    resp_headers["X-Gateway-Latency-Ms"] = str(elapsed_ms)
    resp_headers["X-AEGIS-Effective-Thinking"] = (
        "true" if _effective_enable_thinking(body) else "false"
    )
    if strict_json:
        resp_headers["X-AEGIS-Strict-JSON"] = "applied"

    response = Response(
        content=json.dumps(resp_data, ensure_ascii=False).encode() if strict_json and resp_data else resp.content,
        status_code=resp.status_code,
        media_type="application/json",
        headers=resp_headers,
    )
    if request_tracker and request_id:
        request_tracker.clear(request_id)
    return response


async def _check_llm_backend(model_registry, proxy_client: httpx.AsyncClient) -> dict:
    """vLLM 백엔드 연결 상태를 확인한다. 실패해도 health는 정상 반환."""
    profile = model_registry.get_default()
    endpoint = profile.endpoint if profile else settings.llm_endpoint

    try:
        resp = await proxy_client.get(f"{endpoint}/health", timeout=5.0)
        resp.raise_for_status()
        return {"status": "ok", "endpoint": endpoint}
    except Exception as e:
        return {"status": "unreachable", "endpoint": endpoint, "error": str(e)}


@router.get("/usage")
async def usage(req: Request) -> JSONResponse:
    request_id = _ensure_request_id(req)
    token_tracker = getattr(req.app.state, "token_tracker", None)
    if token_tracker:
        return JSONResponse(
            content=await token_tracker.snapshot(),
            headers={"X-Request-Id": request_id},
        )
    return _error_response(
        status_code=500,
        request_id=request_id,
        code="INTERNAL_ERROR",
        message="TokenTracker not initialized",
        retryable=False,
    )


@router.get("/models")
async def list_models(req: Request) -> JSONResponse:
    request_id = _ensure_request_id(req)
    return JSONResponse(
        content={"profiles": req.app.state.model_registry.list_all()},
        headers={"X-Request-Id": request_id},
    )


@router.get("/prompts")
async def list_prompts(req: Request) -> JSONResponse:
    request_id = _ensure_request_id(req)
    return JSONResponse(
        content={"prompts": req.app.state.prompt_registry.list_all()},
        headers={"X-Request-Id": request_id},
    )


# Prometheus 메트릭 — /v1 prefix 밖에 위치
from fastapi import APIRouter as _AR
_metrics_router = _AR()


@_metrics_router.get("/metrics")
async def metrics() -> Response:
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
