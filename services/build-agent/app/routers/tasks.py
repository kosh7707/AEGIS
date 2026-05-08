"""Thin build-agent task router preserving public /v1 surfaces."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.agent_runtime.context import get_request_id, set_request_id
from app.routers.build_resolve_handler import handle_build_resolve as _handle_build_resolve
from app.routers.build_route_support import json_response as _json_response
from app.routers.sdk_analyze_handler import handle_sdk_analyze as _handle_sdk_analyze
from app.schemas.request import TaskRequest
from app.schemas.response import BUILD_RESPONSE_SCHEMA_VERSION
from app.types import TaskStatus, TaskType
from app.runtime.request_summary import request_summary_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["v1"])


@router.post("/tasks")
async def create_task(request: TaskRequest, req: Request) -> JSONResponse:
    set_request_id(req.headers.get("x-request-id"))
    logger.info("[v1] Task received: taskId=%s, taskType=%s", request.taskId, request.taskType)
    request_id = get_request_id() or request.taskId
    request_summary_tracker.register(request_id, endpoint="tasks")

    try:
        if request.taskType == TaskType.BUILD_RESOLVE:
            result = await _handle_build_resolve(request)
        elif request.taskType == TaskType.SDK_ANALYZE:
            result = await _handle_sdk_analyze(request)
        else:
            request_summary_tracker.mark_failed(request_id, "UNKNOWN_TASK_TYPE")
            response_request_id = get_request_id()
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": f"Unsupported taskType: {request.taskType}",
                    "errorDetail": {
                        "code": "UNKNOWN_TASK_TYPE",
                        "message": f"Build Agent supports 'build-resolve' and 'sdk-analyze', got '{request.taskType}'",
                        "requestId": response_request_id,
                        "retryable": False,
                    },
                },
                headers={"X-Request-Id": response_request_id} if response_request_id else {},
            )
    except Exception:
        logger.error("[v1] Unexpected error", exc_info=True)
        request_summary_tracker.mark_failed(request_id, "INTERNAL_ERROR")
        response_request_id = get_request_id()
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
            headers={"X-Request-Id": response_request_id} if response_request_id else {},
        )

    if getattr(result, "status", None) == TaskStatus.COMPLETED:
        request_summary_tracker.mark_completed(request_id)
    else:
        request_summary_tracker.mark_failed(request_id, str(getattr(result, "failureCode", None) or getattr(result, "status", "failed")))

    return _json_response(result)


@router.get("/health")
async def health(requestId: str | None = Query(default=None)) -> dict:
    return {
        "service": "s3-build",
        "status": "ok",
        "version": "1.0.0",
        "llmMode": settings.llm_mode,
        "activeResponseSchemas": {
            "build-resolve": BUILD_RESPONSE_SCHEMA_VERSION,
            "sdk-analyze": BUILD_RESPONSE_SCHEMA_VERSION,
        },
        "proposedResponseSchemas": {},
        "activeRequestCount": request_summary_tracker.active_request_count(),
        "requestSummary": request_summary_tracker.get_summary(requestId),
        "agentConfig": {
            "maxSteps": settings.agent_max_steps,
            "maxCompletionTokens": settings.agent_max_completion_tokens,
            "taskDeadlineMs": settings.build_task_deadline_ms,
            "partialEnvelopeDeadlineMs": settings.build_partial_envelope_deadline_ms,
            "llmAsyncPollIntervalSeconds": settings.llm_async_poll_interval_seconds,
            "toolBudget": {
                "cheap": settings.agent_max_cheap_calls,
                "medium": settings.agent_max_medium_calls,
                "expensive": settings.agent_max_expensive_calls,
            },
        },
    }
