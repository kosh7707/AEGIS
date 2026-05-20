from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute

from app.agent_runtime.context import get_request_id, reset_request_id, set_request_id

from .errors import PaperError

logger = logging.getLogger(__name__)
_exchange_logger = logging.getLogger("llm_exchange")

_RESERVED_ERROR_DETAIL_KEYS = {"code", "message", "requestId", "retryable"}


def generate_request_id() -> str:
    return f"req-{uuid.uuid4()}"


def request_id_from_header(value: str | None) -> str:
    clean = (value or "").strip()
    return clean or generate_request_id()


def current_request_id_or(fallback: str | None = None) -> str | None:
    return get_request_id() or fallback


def log_event(message: str, *, level: int = logging.INFO, **extra: Any) -> None:
    logger.log(level, message, extra={"_extra": _drop_none(extra)})


def log_http_start(
    *,
    target: str,
    method: str,
    path: str,
    case_id: str | None = None,
    build_target_id: str | None = None,
    paper_run_id: str | None = None,
    finding_id: str | None = None,
    operation_request_id: str | None = None,
    child_request_id: str | None = None,
) -> float:
    log_event(
        f"→ {method} {path}",
        event="paper_http_call_start",
        target=target,
        method=method,
        path=path,
        caseId=case_id,
        buildTargetId=build_target_id,
        paperRunId=paper_run_id,
        findingId=finding_id,
        operationRequestId=operation_request_id,
        childRequestId=child_request_id,
    )
    return time.monotonic()


def log_http_end(
    *,
    started_at: float,
    target: str,
    method: str,
    path: str,
    status: int,
    case_id: str | None = None,
    build_target_id: str | None = None,
    paper_run_id: str | None = None,
    finding_id: str | None = None,
    operation_request_id: str | None = None,
    child_request_id: str | None = None,
    level: int = logging.INFO,
) -> int:
    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    log_event(
        f"← {status} from {method} {path}",
        level=level,
        event="paper_http_call_end",
        target=target,
        method=method,
        path=path,
        status=status,
        elapsedMs=elapsed_ms,
        caseId=case_id,
        buildTargetId=build_target_id,
        paperRunId=paper_run_id,
        findingId=finding_id,
        operationRequestId=operation_request_id,
        childRequestId=child_request_id,
    )
    return elapsed_ms


def log_http_error(
    *,
    started_at: float,
    target: str,
    method: str,
    path: str,
    error_code: str,
    case_id: str | None = None,
    build_target_id: str | None = None,
    paper_run_id: str | None = None,
    finding_id: str | None = None,
    operation_request_id: str | None = None,
    child_request_id: str | None = None,
) -> int:
    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    log_event(
        f"× {method} {path}",
        level=logging.ERROR,
        event="paper_http_call_error",
        target=target,
        method=method,
        path=path,
        errorCode=error_code,
        elapsedMs=elapsed_ms,
        caseId=case_id,
        buildTargetId=build_target_id,
        paperRunId=paper_run_id,
        findingId=finding_id,
        operationRequestId=operation_request_id,
        childRequestId=child_request_id,
    )
    return elapsed_ms


def log_llm_exchange_metadata(
    *,
    phase: str,
    mode: str,
    model: str | None,
    max_tokens: int | None,
    latency_ms: int,
    case_id: str,
    build_target_id: str,
    paper_run_id: str,
    finding_id: str,
    finish_reason: str | None = None,
    tool_call_count: int | None = None,
    usage: dict[str, Any] | None = None,
    status: str = "ok",
    error_code: str | None = None,
) -> None:
    payload = _drop_none(
        {
            "level": 30 if status == "ok" else 50,
            "time": int(time.time() * 1000),
            "service": "s3-agent",
            "requestId": get_request_id(),
            "msg": "paper llm exchange",
            "phase": phase,
            "mode": mode,
            "model": model,
            "maxTokens": max_tokens,
            "latencyMs": latency_ms,
            "caseId": case_id,
            "buildTargetId": build_target_id,
            "paperRunId": paper_run_id,
            "findingId": finding_id,
            "finishReason": finish_reason,
            "toolCallCount": tool_call_count,
            "usage": usage,
            "status": status,
            "errorCode": error_code,
        }
    )
    _exchange_logger.info(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def paper_error_response(exc: PaperError) -> JSONResponse:
    request_id = get_request_id()
    detail = {k: v for k, v in exc.detail.items() if k not in _RESERVED_ERROR_DETAIL_KEYS}
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.message,
            "errorDetail": {
                "code": exc.code,
                "message": exc.message,
                "requestId": request_id,
                "retryable": False,
                **detail,
            },
        },
        headers={"X-Request-Id": request_id} if request_id else {},
    )


def validation_error_response(exc: RequestValidationError) -> JSONResponse:
    request_id = get_request_id()
    error_count = len(exc.errors())
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": "request validation failed",
            "errorDetail": {
                "code": "REQUEST_VALIDATION_FAILED",
                "message": "request validation failed",
                "requestId": request_id,
                "retryable": False,
                "validationErrorCount": error_count,
            },
        },
        headers={"X-Request-Id": request_id} if request_id else {},
    )


class PaperObservedRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Awaitable[Response]]:
        original_route_handler = super().get_route_handler()

        async def observed_route_handler(request: Request) -> Response:
            request_id = request_id_from_header(request.headers.get("x-request-id"))
            token = set_request_id(request_id)
            started_at = time.monotonic()
            path = request.url.path
            method = request.method
            try:
                log_event(
                    f"paper request start {method} {path}",
                    event="paper_request_start",
                    method=method,
                    path=path,
                )
                response = await original_route_handler(request)
                response.headers["X-Request-Id"] = request_id
                _log_request_end(started_at, method=method, path=path, status=response.status_code)
                return response
            except RequestValidationError as exc:
                response = validation_error_response(exc)
                _log_request_end(
                    started_at,
                    method=method,
                    path=path,
                    status=422,
                    level=logging.WARNING,
                    validationErrorCount=len(exc.errors()),
                )
                return response
            except PaperError as exc:
                response = paper_error_response(exc)
                _log_request_end(started_at, method=method, path=path, status=exc.status_code, level=logging.ERROR)
                return response
            except Exception as exc:  # paper-only safety envelope: do not leak raw exception text
                log_event(
                    "paper request internal error",
                    level=logging.ERROR,
                    event="paper_request_error",
                    method=method,
                    path=path,
                    errorClass=type(exc).__name__,
                )
                response = JSONResponse(
                    status_code=500,
                    content={
                        "success": False,
                        "error": "internal paper request error",
                        "errorDetail": {
                            "code": "INTERNAL_ERROR",
                            "message": "internal paper request error",
                            "requestId": request_id,
                            "retryable": False,
                        },
                    },
                    headers={"X-Request-Id": request_id},
                )
                _log_request_end(started_at, method=method, path=path, status=500, level=logging.ERROR)
                return response
            finally:
                reset_request_id(token)

        return observed_route_handler


def _log_request_end(
    started_at: float,
    *,
    method: str,
    path: str,
    status: int,
    level: int = logging.INFO,
    **extra: Any,
) -> None:
    elapsed_ms = int((time.monotonic() - started_at) * 1000)
    log_event(
        f"paper request end {method} {path}",
        level=level,
        event="paper_request_end",
        method=method,
        path=path,
        status=status,
        elapsedMs=elapsed_ms,
        **extra,
    )


def _drop_none(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}
