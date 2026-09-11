"""LlmCaller — S7 Gateway 경유 LLM 호출 + tool_calls 파싱. 분기 판단은 하지 않음."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import warnings
from typing import Any

import httpx

from app.agent_runtime.context import get_request_id
from app.agent_runtime.errors import (
    LlmContractViolationError, LlmHttpError, LlmInputTooLargeError, LlmPoolExhaustedError,
    LlmTimeoutError, LlmUnavailableError, StrictJsonContractError,
)
from app.agent_runtime.llm.generation_policy import DEFAULT_GENERATION, GenerationControls, TimeoutDefaults
from app.agent_runtime.observability import agent_log, get_log_dir
from app.agent_runtime.schemas.agent import LlmResponse, ToolCallRequest

logger = logging.getLogger(__name__)
_exchange_logger = logging.getLogger("llm_exchange")

_ALLOWED_TOOL_CHOICE_VALUES = {"auto", "none"}
_CONTRACT_VIOLATION_MARKERS = (
    "llm_parse_retry",
    "response_contract_violation",
    "finish_reason_tool_calls_with_empty_array",
    "all_output_absorbed_into_reasoning",
)


class LlmCaller:
    """S7 Gateway 경유 LLM 호출. tool_calls 파싱을 지원한다."""

    # Adaptive timeout 파라미터 (S7 Qwen3.6-27B live guidance, 2026-04-24)
    # S7 WR: quality-heavy prompts can reach p95 ~1245s; /v1/chat allows up to 1800s.
    # Keep the estimator conservative for deep finalizers without silently exceeding S7's cap.
    _TOKENS_PER_SECOND = 7.0        # 병렬 부하 시 보수적 생성 속도
    _PREFILL_PER_1K_TOKENS = 15.0   # 병렬 시 prefill도 경합 → 여유 확보
    _OVERHEAD_SECONDS = 60.0        # 네트워크 + 스케줄링 + torch + 큐 대기
    _SAFETY_FACTOR = 2.0            # 안전 배수
    _MIN_TIMEOUT = TimeoutDefaults.TOOL_EXECUTION_SECONDS
    _MAX_TIMEOUT = TimeoutDefaults.CHAT_MAX_SECONDS
    _ASYNC_SUBMIT_TIMEOUT = 30.0
    _ASYNC_HEALTH_TIMEOUT = 5.0
    _ASYNC_POLL_INTERVAL = 1.0
    _ASYNC_UNSUPPORTED_RETRY_SECONDS = 60.0

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str = "",
        *,
        enable_thinking: bool = True,
        default_max_tokens: int = 4096,
        service_id: str = "",
        async_poll_interval_seconds: float | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._model = model
        self._api_key = api_key
        self._enable_thinking = enable_thinking
        self._default_max_tokens = default_max_tokens
        self._service_id = service_id
        self._async_surface_retry_at = 0.0
        self._async_poll_interval_seconds = max(
            0.1,
            float(async_poll_interval_seconds or self._ASYNC_POLL_INTERVAL),
        )
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=self._MAX_TIMEOUT + 30.0, write=10.0, pool=10.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=4),
        )

    def _estimate_timeout(self, messages: list[dict], max_tokens: int, has_tools: bool) -> float:
        """요청별 adaptive timeout을 계산한다.

        입력 크기(prefill) + 예상 생성량(generation) + 오버헤드로 산출.
        도구 호출 턴은 짧은 응답, 최종 보고서 턴은 max_tokens 전체를 기대한다.
        """
        # 입력 토큰 추정 (한영 혼재 보수적 기준 ~2자/토큰)
        input_chars = sum(len(m.get("content", "") or "") for m in messages)
        est_input_tokens = input_chars / 2

        # prefill 시간
        prefill = est_input_tokens / 1000 * self._PREFILL_PER_1K_TOKENS

        # 예상 생성 토큰
        if has_tools:
            # 도구 호출 응답은 짧음 (tool_call JSON ~200-1000 토큰)
            est_output = min(max_tokens, 1000)
        else:
            # 최종 보고서 — max_tokens 전체 사용 가능
            est_output = max_tokens

        generation = est_output / self._TOKENS_PER_SECOND
        timeout = (prefill + generation + self._OVERHEAD_SECONDS) * self._SAFETY_FACTOR

        return max(self._MIN_TIMEOUT, min(timeout, self._MAX_TIMEOUT))

    async def call(
        self,
        messages: list[dict],
        session: Any = None,
        *,
        tools: list[dict] | None = None,
        tool_choice: str = "auto",
        max_tokens: int | None = None,
        generation: GenerationControls | None = None,
        temperature: float | None = None,
        prefer_async_ownership: bool = False,
    ) -> LlmResponse:
        """LLM에 messages를 보내고 LlmResponse를 반환한다."""
        if max_tokens is None:
            max_tokens = self._default_max_tokens

        if not isinstance(tool_choice, str) or tool_choice not in _ALLOWED_TOOL_CHOICE_VALUES:
            raise ValueError(
                "S3 LlmCaller only supports tool_choice='auto' or 'none'; "
                "do not send gateway-unsupported required/named function choices"
            )

        controls = generation or DEFAULT_GENERATION.with_updates(enable_thinking=self._enable_thinking)
        # Transitional compatibility for existing call sites that still pass a
        # scalar temperature. Deprecation milestone: remove this argument after
        # the S3 readiness gate proves all active callers pass GenerationControls.
        if temperature is not None:
            warnings.warn(
                "LlmCaller.call(temperature=...) is deprecated; pass "
                "generation=GenerationControls instead",
                DeprecationWarning,
                stacklevel=2,
            )
        controls = controls.with_updates(temperature=temperature)

        body: dict = {
            "model": self._model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        body.update(controls.to_gateway_fields())

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        request_id = get_request_id()
        if request_id:
            headers["X-Request-Id"] = request_id

        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice
        else:
            body["response_format"] = {"type": "json_object"}
            headers["X-AEGIS-Strict-JSON"] = "true"

        turn = (session.turn_count + 1) if session else None

        # Adaptive timeout: 입력 크기 + 예상 생성량 기반
        req_timeout = self._estimate_timeout(messages, max_tokens, has_tools=bool(tools))
        # S7 Gateway에 타임아웃 동기화 (X-Timeout-Seconds)
        headers["X-Timeout-Seconds"] = str(int(req_timeout))

        if prefer_async_ownership and not tools:
            async_result = await self._call_via_async_ownership(
                body=body,
                headers=headers,
                request_id=request_id,
                turn=turn,
            )
            if async_result is not None:
                return async_result

        agent_log(
            logger, "LLM 호출",
            component="llm_caller", phase="llm_request",
            turn=turn, messageCount=len(messages),
            hasTools=bool(tools), toolCount=len(tools) if tools else 0,
            adaptiveTimeoutSec=round(req_timeout, 1),
        )

        url = f"{self._endpoint}/v1/chat"
        start = time.monotonic()

        try:
            resp = await self._client.post(
                url, json=body, headers=headers,
                timeout=httpx.Timeout(connect=10.0, read=req_timeout, write=10.0, pool=10.0),
            )
        except httpx.PoolTimeout:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            agent_log(
                logger, "LLM 에러",
                component="llm_caller", phase="llm_error",
                turn=turn, errorCode="POOL_EXHAUSTED", retryable=True,
                latencyMs=elapsed_ms, level=logging.WARNING,
            )
            self._write_exchange_and_dump(
                request_id, turn, elapsed_ms, "error",
                error_code="POOL_EXHAUSTED", body=body, data=None,
            )
            raise LlmPoolExhaustedError()
        except httpx.TimeoutException:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            agent_log(
                logger, "LLM 에러",
                component="llm_caller", phase="llm_error",
                turn=turn, errorCode="LLM_TIMEOUT", retryable=True,
                latencyMs=elapsed_ms, level=logging.ERROR,
            )
            self._write_exchange_and_dump(
                request_id, turn, elapsed_ms, "error",
                error_code="LLM_TIMEOUT", body=body, data=None,
            )
            raise LlmTimeoutError()
        except httpx.ConnectError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            agent_log(
                logger, "LLM 에러",
                component="llm_caller", phase="llm_error",
                turn=turn, errorCode="LLM_UNAVAILABLE", retryable=True,
                latencyMs=elapsed_ms, level=logging.ERROR,
            )
            self._write_exchange_and_dump(
                request_id, turn, elapsed_ms, "error",
                error_code="LLM_UNAVAILABLE", body=body, data=None,
            )
            raise LlmUnavailableError()

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if resp.status_code != 200:
            text = resp.text[:500]
            is_circuit_open = resp.status_code == 503 and "circuit" in text.lower()
            is_invalid_tool_choice = (
                resp.status_code == 422
                and ("invalid_tool_choice" in text.lower() or "tool_choice" in text.lower())
            )
            is_contract_violation = (
                resp.status_code == 503 and self._is_response_contract_violation(text)
            )
            if is_circuit_open:
                error_code = "CIRCUIT_OPEN"
            elif is_invalid_tool_choice:
                error_code = "INVALID_TOOL_CHOICE"
            elif is_contract_violation:
                error_code = "LLM_PARSE_RETRY"
            else:
                error_code = f"HTTP_{resp.status_code}"
            retryable = resp.status_code in (429, 503)
            agent_log(
                logger, "LLM 에러",
                component="llm_caller", phase="llm_error",
                turn=turn, errorCode=error_code, retryable=retryable,
                latencyMs=elapsed_ms, level=logging.ERROR,
            )
            self._write_exchange_and_dump(
                request_id, turn, elapsed_ms, "error",
                error_code=error_code, body=body, data=None,
            )
            if resp.status_code == 400 and "too large" in text.lower():
                raise LlmInputTooLargeError(chars=0, limit=0)
            # Retry-After 헤더 파싱 (429/503 시 S7이 전달할 수 있음)
            retry_after: float | None = None
            raw_retry = resp.headers.get("Retry-After")
            if raw_retry:
                try:
                    retry_after = float(raw_retry)
                except (ValueError, TypeError):
                    pass
            raise LlmHttpError(resp.status_code, text, retry_after=retry_after)

        try:
            data = resp.json()
        except Exception:
            self._write_exchange_and_dump(
                request_id, turn, elapsed_ms, "error",
                error_code="INVALID_JSON", body=body, data=None,
            )
            raise LlmHttpError(502, "Invalid JSON from LLM")

        # 파싱
        result = self._parse_response(data, turn)

        # 구조화된 로그
        tool_names = [tc.name for tc in result.tool_calls]
        agent_log(
            logger, "LLM 응답",
            component="llm_caller", phase="llm_response",
            turn=turn, finishReason=result.finish_reason,
            toolCallCount=len(result.tool_calls),
            reasoningChars=len(result.reasoning or ""),
            promptTokens=result.prompt_tokens,
            completionTokens=result.completion_tokens,
            latencyMs=elapsed_ms,
        )

        # 교환 로그 + 전문 덤프
        self._write_exchange_and_dump(
            request_id, turn, elapsed_ms, "ok",
            finish_reason=result.finish_reason,
            tool_calls=tool_names or None,
            usage={"prompt": result.prompt_tokens, "completion": result.completion_tokens},
            body=body, data=data,
        )

        return result

    async def _call_via_async_ownership(
        self,
        *,
        body: dict,
        headers: dict[str, str],
        request_id: str | None,
        turn: int | None,
    ) -> LlmResponse | None:
        now = time.monotonic()
        if now < self._async_surface_retry_at:
            agent_log(
                logger, "LLM async ownership 프로브 건너뜀 (cooldown)",
                component="llm_caller", phase="llm_async_cooldown",
                turn=turn, requestId=request_id,
                retryAtMs=int(self._async_surface_retry_at * 1000),
                level=logging.DEBUG,
            )
            return None

        # Preserve X-Timeout-Seconds on the async submit path as well as /v1/chat.
        # The S7 async endpoint uses it to size request ownership/expiry; dropping it
        # leaves long finalizers at the gateway default even when the caller's local
        # budget is larger, which can strand the caller polling an already-expired request.
        submit_headers = dict(headers)
        await self._ensure_async_gateway_ready(submit_headers, request_id=request_id, turn=turn)
        submit_url = f"{self._endpoint}/v1/async-chat-requests"
        start = time.monotonic()

        agent_log(
            logger, "LLM async ownership 제출 시도",
            component="llm_caller", phase="llm_async_submit",
            turn=turn, requestId=request_id,
        )

        try:
            submit_resp = await self._client.post(
                submit_url,
                json=body,
                headers=submit_headers,
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=self._ASYNC_SUBMIT_TIMEOUT,
                    write=10.0,
                    pool=10.0,
                ),
            )
        except httpx.TimeoutException:
            raise LlmTimeoutError("LLM async submit 시간 초과")
        except httpx.ConnectError:
            raise LlmUnavailableError()

        if submit_resp.status_code in (404, 405, 501):
            self._async_surface_retry_at = time.monotonic() + self._ASYNC_UNSUPPORTED_RETRY_SECONDS
            agent_log(
                logger, "LLM async ownership 미지원 — sync chat로 폴백",
                component="llm_caller", phase="llm_async_fallback",
                turn=turn, statusCode=submit_resp.status_code,
                cooldownSeconds=self._ASYNC_UNSUPPORTED_RETRY_SECONDS,
                level=logging.WARNING,
            )
            return None

        if submit_resp.status_code not in (200, 202):
            text = submit_resp.text[:500]
            if submit_resp.status_code == 400 and "too large" in text.lower():
                raise LlmInputTooLargeError(chars=0, limit=0)
            raise LlmHttpError(submit_resp.status_code, text)

        try:
            submit_data = submit_resp.json()
        except Exception:
            raise LlmHttpError(502, "Malformed async submit response")

        async_request_id = submit_data.get("requestId")
        if not async_request_id:
            raise LlmHttpError(502, "Async submit response missing requestId")

        status_url = self._resolve_endpoint_url(
            submit_data.get("statusUrl"),
            f"/v1/async-chat-requests/{async_request_id}",
        )
        result_url = self._resolve_endpoint_url(
            submit_data.get("resultUrl"),
            f"/v1/async-chat-requests/{async_request_id}/result",
        )
        poll_headers = {k: v for k, v in submit_headers.items() if k != "Content-Type"}

        while True:
            status_data = await self._get_async_json(status_url, poll_headers)
            state = status_data.get("state")
            local_ack_state = status_data.get("localAckState")
            blocked_reason = status_data.get("blockedReason")
            result_ready = bool(status_data.get("resultReady"))

            agent_log(
                logger, "LLM async ownership 상태 조회",
                component="llm_caller", phase="llm_async_poll",
                turn=turn, requestId=async_request_id,
                state=state, localAckState=local_ack_state,
                blockedReason=blocked_reason,
            )

            if blocked_reason or local_ack_state == "ack-break":
                if blocked_reason == "strict_json_contract_violation":
                    raise StrictJsonContractError(
                        blocked_reason=blocked_reason,
                        error_detail=status_data.get("errorDetail") or status_data.get("error"),
                        async_request_id=async_request_id,
                        gateway_request_id=status_data.get("requestId") or status_data.get("gatewayRequestId"),
                        raw_excerpt=json.dumps(status_data, ensure_ascii=False)[:1000],
                    )
                if self._is_response_contract_violation(
                    blocked_reason,
                    status_data.get("errorDetail"),
                    status_data.get("error"),
                ):
                    raise LlmContractViolationError(
                        violation_reason=blocked_reason or "response_contract_violation",
                        async_request_id=async_request_id,
                        gateway_request_id=status_data.get("requestId") or status_data.get("gatewayRequestId"),
                        raw_excerpt=json.dumps(status_data, ensure_ascii=False)[:1000],
                    )
                raise LlmHttpError(409, blocked_reason or "Async chat request reached ack-break")

            if state in {"queued", "running"} and not result_ready:
                await asyncio.sleep(self._async_poll_interval_seconds)
                continue

            if state == "completed" or result_ready:
                result_resp = await self._client.get(
                    result_url,
                    headers=poll_headers,
                    timeout=httpx.Timeout(
                        connect=10.0,
                        read=self._ASYNC_SUBMIT_TIMEOUT,
                        write=10.0,
                        pool=10.0,
                    ),
                )
                if result_resp.status_code == 409:
                    await asyncio.sleep(self._async_poll_interval_seconds)
                    continue
                if result_resp.status_code == 410:
                    raise LlmHttpError(410, result_resp.text[:500] or "Async chat request expired")
                if result_resp.status_code != 200:
                    raise LlmHttpError(result_resp.status_code, result_resp.text[:500])

                try:
                    result_data = result_resp.json()
                except Exception:
                    raise LlmHttpError(502, "Malformed async result response")

                wrapped = result_data.get("response")
                if not isinstance(wrapped, dict):
                    raise LlmHttpError(502, "Async result response missing wrapped response")

                elapsed_ms = int((time.monotonic() - start) * 1000)
                result = self._parse_response(wrapped, turn)
                tool_names = [tc.name for tc in result.tool_calls]

                agent_log(
                    logger, "LLM async ownership 완료",
                    component="llm_caller", phase="llm_async_complete",
                    turn=turn, requestId=async_request_id,
                    finishReason=result.finish_reason,
                    reasoningChars=len(result.reasoning or ""),
                    latencyMs=elapsed_ms,
                )

                self._write_exchange_and_dump(
                    request_id or submit_data.get("traceRequestId") or async_request_id,
                    turn,
                    elapsed_ms,
                    "ok",
                    finish_reason=result.finish_reason,
                    tool_calls=tool_names or None,
                    usage={"prompt": result.prompt_tokens, "completion": result.completion_tokens},
                    body=body,
                    data=result_data,
                )
                return result

            if state in {"failed", "cancelled", "expired"}:
                if blocked_reason == "strict_json_contract_violation":
                    raise StrictJsonContractError(
                        blocked_reason=blocked_reason,
                        error_detail=status_data.get("errorDetail") or status_data.get("error"),
                        async_request_id=async_request_id,
                        gateway_request_id=status_data.get("requestId") or status_data.get("gatewayRequestId"),
                        raw_excerpt=json.dumps(status_data, ensure_ascii=False)[:1000],
                    )
                if self._is_response_contract_violation(
                    blocked_reason,
                    status_data.get("errorDetail"),
                    status_data.get("error"),
                ):
                    raise LlmContractViolationError(
                        violation_reason=blocked_reason or "response_contract_violation",
                        async_request_id=async_request_id,
                        gateway_request_id=status_data.get("requestId") or status_data.get("gatewayRequestId"),
                        raw_excerpt=json.dumps(status_data, ensure_ascii=False)[:1000],
                    )
                raise LlmHttpError(409, blocked_reason or f"Async chat request ended with state={state}")

            raise LlmHttpError(502, f"Unknown async chat state: {state}")

    async def _ensure_async_gateway_ready(
        self,
        headers: dict[str, str],
        *,
        request_id: str | None,
        turn: int | None,
    ) -> None:
        """Consume S7 /v1/health readiness before async ownership submit.

        S7's top-level ``status`` is process liveness only.  The LLM dependency
        readiness contract lives in ``ready`` / ``llmReady`` / ``blockedReason``
        and the backend dependency snapshot.  Failing fast here prevents S3 from
        treating "Gateway process is alive" as "DGX/vLLM is usable".
        """
        url = f"{self._endpoint}/v1/health"
        health_headers = {k: v for k, v in headers.items() if k != "Content-Type"}
        try:
            resp = await self._client.get(
                url,
                headers=health_headers,
                timeout=httpx.Timeout(
                    connect=self._ASYNC_HEALTH_TIMEOUT,
                    read=self._ASYNC_HEALTH_TIMEOUT,
                    write=self._ASYNC_HEALTH_TIMEOUT,
                    pool=self._ASYNC_HEALTH_TIMEOUT,
                ),
            )
        except httpx.TimeoutException:
            raise LlmTimeoutError("LLM Gateway health check 시간 초과")
        except httpx.ConnectError:
            raise LlmUnavailableError("LLM Gateway health check 연결 불가")

        if resp.status_code == 404:
            # Compatibility for older local S7 builds: absence of the health
            # readiness surface should not disable the async endpoint probe.
            return
        if resp.status_code != 200:
            raise LlmHttpError(resp.status_code, resp.text[:500] or "LLM Gateway health check failed")

        try:
            data = resp.json()
        except Exception:
            raise LlmHttpError(502, "Malformed LLM Gateway health response")

        blocked_reason = self._health_blocked_reason(data)
        if not blocked_reason:
            return

        agent_log(
            logger, "LLM Gateway readiness 차단",
            component="llm_caller", phase="llm_health_blocked",
            turn=turn, requestId=request_id,
            blockedReason=blocked_reason,
            level=logging.WARNING,
        )
        raise LlmUnavailableError(f"LLM Gateway dependency not ready: {blocked_reason}")

    @classmethod
    def _health_blocked_reason(cls, data: Any) -> str | None:
        if not isinstance(data, dict):
            return None

        blocked = data.get("blockedReason")
        if isinstance(blocked, str) and blocked.strip():
            return blocked.strip()

        degrade_reasons = data.get("degradeReasons")
        first_degrade_reason = cls._first_string(degrade_reasons)

        ready = data.get("ready")
        llm_ready = data.get("llmReady")
        if ready is False or llm_ready is False:
            return first_degrade_reason or "llm_not_ready"

        dependency_status = data.get("dependencyStatus")
        if not isinstance(dependency_status, dict):
            dependency_status = {}

        llm_backend = dependency_status.get("llmBackend")
        if not isinstance(llm_backend, dict):
            llm_backend = data.get("llmBackend")
        backend_status = cls._status_value(llm_backend)
        if backend_status and backend_status != "ok":
            if backend_status == "unreachable":
                return first_degrade_reason or "llm_backend_unreachable"
            return first_degrade_reason or f"llm_backend_{backend_status}"

        circuit_breaker = dependency_status.get("circuitBreaker")
        if not isinstance(circuit_breaker, dict):
            circuit_breaker = data.get("circuitBreaker")
        circuit_state = cls._status_value(circuit_breaker, key="state")
        if circuit_state == "open":
            return first_degrade_reason or "circuit_open"
        if circuit_state == "half_open":
            return first_degrade_reason or "circuit_half_open"

        return None

    @staticmethod
    def _first_string(value: Any) -> str | None:
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    return item.strip()
        return None

    @staticmethod
    def _status_value(value: Any, *, key: str = "status") -> str | None:
        if isinstance(value, dict):
            raw = value.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip().lower()
        return None

    async def _cancel_async_request(
        self,
        url: str,
        headers: dict[str, str],
        *,
        async_request_id: str,
        turn: int | None,
        reason: str,
    ) -> None:
        try:
            resp = await self._client.delete(
                url,
                headers=headers,
                timeout=httpx.Timeout(
                    connect=5.0,
                    read=5.0,
                    write=5.0,
                    pool=5.0,
                ),
            )
            agent_log(
                logger, "LLM async ownership 취소 요청",
                component="llm_caller", phase="llm_async_cancel",
                turn=turn, requestId=async_request_id,
                reason=reason, statusCode=resp.status_code,
                level=logging.INFO if resp.status_code in (200, 202, 204, 404, 409) else logging.WARNING,
            )
        except Exception as exc:
            agent_log(
                logger, "LLM async ownership 취소 실패",
                component="llm_caller", phase="llm_async_cancel",
                turn=turn, requestId=async_request_id,
                reason=reason, error=str(exc),
                level=logging.WARNING,
            )

    async def _get_async_json(self, url: str, headers: dict[str, str]) -> dict:
        try:
            resp = await self._client.get(
                url,
                headers=headers,
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=self._ASYNC_SUBMIT_TIMEOUT,
                    write=10.0,
                    pool=10.0,
                ),
            )
        except httpx.TimeoutException:
            raise LlmTimeoutError("LLM async status 조회 시간 초과")
        except httpx.ConnectError:
            raise LlmUnavailableError()

        if resp.status_code != 200:
            raise LlmHttpError(resp.status_code, resp.text[:500])
        try:
            return resp.json()
        except Exception:
            raise LlmHttpError(502, "Malformed async status response")

    def _resolve_endpoint_url(self, value: str | None, fallback_path: str) -> str:
        if isinstance(value, str) and value:
            if value.startswith("http://") or value.startswith("https://"):
                return value
            if value.startswith("/"):
                return f"{self._endpoint}{value}"
        return f"{self._endpoint}{fallback_path}"

    def _write_exchange_and_dump(
        self,
        request_id: str | None,
        turn: int | None,
        latency_ms: int,
        status: str,
        *,
        error_code: str | None = None,
        finish_reason: str | None = None,
        tool_calls: list[str] | None = None,
        usage: dict | None = None,
        body: dict | None = None,
        data: dict | None = None,
    ) -> None:
        """S4 교환 JSONL 요약 + LLM 호출별 전문 덤프 기록."""
        ts = int(time.time() * 1000)
        turn_str = f"{(turn or 0):02d}"
        rid = request_id or "unknown"
        dump_filename = f"{rid}_turn-{turn_str}_{ts}.json"
        dump_relative = f"logs/llm-dumps/{dump_filename}"

        # JSONL 요약
        entry: dict = {
            "time": ts,
            "requestId": request_id,
            "turn": turn,
            "type": "llm_call",
            "latencyMs": latency_ms,
            "status": status,
        }
        if self._service_id:
            entry["service"] = self._service_id
        if finish_reason:
            entry["finishReason"] = finish_reason
        if tool_calls:
            entry["toolCalls"] = tool_calls
        if usage:
            entry["usage"] = usage
        if error_code:
            entry["errorCode"] = error_code
        entry["dumpFile"] = dump_relative

        _exchange_logger.info(json.dumps(entry, ensure_ascii=False))

        # 전문 덤프
        try:
            log_dir = get_log_dir()
            dump_path = log_dir / "llm-dumps" / dump_filename
            dump_path.parent.mkdir(parents=True, exist_ok=True)
            dump = {
                "meta": {
                    "requestId": request_id,
                    "turn": turn,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "latencyMs": latency_ms,
                    "status": status,
                },
                "request": body,
                "response": data,
            }
            dump_path.write_text(json.dumps(dump, ensure_ascii=False, indent=2))
        except Exception:
            logger.debug("LLM dump 쓰기 실패: %s", dump_filename)

    def _parse_response(self, data: dict, turn: int | None = None) -> LlmResponse:
        """OpenAI-format 응답을 LlmResponse로 파싱한다."""
        try:
            choice = data["choices"][0]
            message = choice["message"]
            finish_reason = choice.get("finish_reason", "stop")
            usage = data.get("usage", {})
        except (KeyError, IndexError):
            raise LlmHttpError(502, "Malformed LLM response structure")

        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        # tool_calls 파싱
        raw_tool_calls = message.get("tool_calls") or []
        tool_calls = []
        for tc in raw_tool_calls:
            try:
                func = tc["function"]
                args_str = func.get("arguments", "{}")
                arguments = json.loads(args_str) if isinstance(args_str, str) else args_str
                tool_calls.append(ToolCallRequest(
                    id=tc.get("id", ""),
                    name=func["name"],
                    arguments=arguments,
                ))
            except (json.JSONDecodeError, KeyError) as e:
                agent_log(
                    logger, "tool_call 파싱 실패",
                    component="llm_caller", phase="tool_parse_fail",
                    turn=turn, rawToolCall=str(tc)[:200],
                    level=logging.WARNING,
                )
                continue

        content = message.get("content")
        reasoning = message.get("reasoning")

        if finish_reason == "tool_calls" and not tool_calls:
            self._raise_contract_violation(
                violation_reason="finish_reason_tool_calls_with_empty_array",
                finish_reason=finish_reason,
                reasoning=reasoning,
                content=content,
                data=data,
            )

        if not tool_calls and not self._has_actionable_content(content) and self._has_actionable_content(reasoning):
            self._raise_contract_violation(
                violation_reason="all_output_absorbed_into_reasoning",
                finish_reason=finish_reason,
                reasoning=reasoning,
                content=content,
                data=data,
            )

        return LlmResponse(
            content=content,
            reasoning=reasoning,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    @staticmethod
    def _has_actionable_content(value: Any) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _is_response_contract_violation(*values: Any) -> bool:
        text = " ".join(str(value) for value in values if value is not None).lower()
        return any(marker in text for marker in _CONTRACT_VIOLATION_MARKERS)

    @staticmethod
    def _raise_contract_violation(
        *,
        violation_reason: str,
        finish_reason: str | None,
        reasoning: Any,
        content: Any,
        data: dict,
    ) -> None:
        reasoning_text = reasoning if isinstance(reasoning, str) else None
        content_text = content if isinstance(content, str) else None
        raise LlmContractViolationError(
            violation_reason=violation_reason,
            finish_reason=finish_reason,
            reasoning_excerpt=reasoning_text[:500] if reasoning_text else None,
            content_excerpt=content_text[:500] if content_text else None,
            raw_excerpt=json.dumps(data, ensure_ascii=False)[:1000],
        )

    async def aclose(self) -> None:
        await self._client.aclose()
