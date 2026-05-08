import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.agent_runtime.context import get_request_id, set_request_id
from app.registry.model_registry import create_default_registry as create_model_registry
from app.registry.prompt_registry import create_default_registry as create_prompt_registry
from app.runtime.request_summary import request_summary_tracker
from app.routers.deep_analyze_handler import handle_deep_analyze as _handle_deep_analyze_impl
from app.routers.generate_poc_handler import handle_generate_poc as _handle_generate_poc_impl
from app.schemas.request import TaskRequest
from app.schemas.response import TaskFailureResponse, TaskSuccessResponse
from app.types import FailureCode, TaskStatus, TaskType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["v1"])

_prompt_registry = create_prompt_registry()
_model_registry = create_model_registry()


def _failure_reason(result: TaskFailureResponse | TaskSuccessResponse) -> str:
    failure_code = getattr(result, "failureCode", None)
    if hasattr(failure_code, "value"):
        return failure_code.value
    status = getattr(result, "status", None)
    if hasattr(status, "value"):
        return status.value
    return str(failure_code or status or "failed")


def _json_response(
    data: TaskSuccessResponse | TaskFailureResponse,
) -> JSONResponse:
    request_id = get_request_id()
    headers = {"X-Request-Id": request_id} if request_id else {}
    headers["X-AEGIS-Task-Status"] = str(data.status)
    headers["X-AEGIS-Task-Ok"] = "true" if data.status == TaskStatus.COMPLETED else "false"
    return JSONResponse(
        status_code=_http_status_for_task_result(data),
        content=data.model_dump(mode="json"),
        headers=headers,
    )


def _http_status_for_task_result(
    data: TaskSuccessResponse | TaskFailureResponse,
) -> int:
    """Map terminal task outcome to transport status.

    `/v1/tasks` is synchronous for S3.  A parsed task envelope is not enough to
    mean the task itself succeeded, so terminal task failures must not be
    hidden behind HTTP 200.
    """
    if data.status == TaskStatus.COMPLETED:
        return 200

    failure_code = getattr(data, "failureCode", None)
    if failure_code == FailureCode.UNKNOWN_TASK_TYPE:
        return 400
    if failure_code in {
        FailureCode.INVALID_SCHEMA,
        FailureCode.INVALID_GROUNDING,
        FailureCode.INSUFFICIENT_EVIDENCE,
        FailureCode.UNSAFE_CONTENT,
        FailureCode.EMPTY_RESPONSE,
        FailureCode.ALL_TOOLS_EXHAUSTED,
    }:
        return 422
    if failure_code in {
        FailureCode.INPUT_TOO_LARGE,
        FailureCode.TOKEN_BUDGET_EXCEEDED,
        FailureCode.MAX_STEPS_EXCEEDED,
    }:
        return 413
    if failure_code == FailureCode.TIMEOUT:
        return 504
    if failure_code in {
        FailureCode.MODEL_UNAVAILABLE,
        FailureCode.LLM_OVERLOADED,
    }:
        return 503

    if data.status in {
        TaskStatus.VALIDATION_FAILED,
        TaskStatus.UNSAFE_OUTPUT,
        TaskStatus.EMPTY_RESULT,
    }:
        return 422
    if data.status == TaskStatus.BUDGET_EXCEEDED:
        return 413
    if data.status == TaskStatus.TIMEOUT:
        return 504
    if data.status == TaskStatus.MODEL_ERROR:
        return 503
    return 500


async def _handle_deep_analyze(request: TaskRequest) -> TaskSuccessResponse | TaskFailureResponse:
    """Compatibility wrapper to preserve tasks-module handler seam."""
    return await _handle_deep_analyze_impl(request, _model_registry)


async def _handle_generate_poc(request: TaskRequest) -> TaskSuccessResponse | TaskFailureResponse:
    """Compatibility wrapper to preserve tasks-module handler seam."""
    return await _handle_generate_poc_impl(request, _model_registry)


@router.post("/tasks")
async def create_task(request: TaskRequest, req: Request) -> JSONResponse:
    set_request_id(req.headers.get("x-request-id"))
    request_id = get_request_id() or request.taskId
    logger.info(
        "[v1] Task received: taskId=%s, taskType=%s",
        request.taskId, request.taskType,
    )
    request_summary_tracker.register(request_id, endpoint="tasks")

    try:
        if request.taskType == TaskType.DEEP_ANALYZE:
            result = await _handle_deep_analyze(request)
        elif request.taskType == TaskType.GENERATE_POC:
            result = await _handle_generate_poc(request)
        else:
            request_summary_tracker.mark_failed(request_id, "UNKNOWN_TASK_TYPE")
            request_id = get_request_id()
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": f"Unsupported taskType: {request.taskType}",
                    "errorDetail": {
                        "code": "UNKNOWN_TASK_TYPE",
                        "message": (
                            "Analysis Agent supports only 'deep-analyze' and "
                            "'generate-poc'. Legacy task types are handled by "
                            "S7 LLM Gateway."
                        ),
                        "requestId": request_id,
                        "retryable": False,
                    },
                },
                headers={"X-Request-Id": request_id} if request_id else {},
            )
        if result.status == "completed":
            request_summary_tracker.mark_completed(request_id)
        else:
            request_summary_tracker.mark_failed(request_id, _failure_reason(result))
    except Exception:
        logger.error("[v1] Unexpected error", exc_info=True)
        request_summary_tracker.mark_failed(request_id, "INTERNAL_ERROR")
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

    return _json_response(result)


@router.get("/health")
async def health(req: Request, requestId: str | None = Query(default=None)) -> dict:
    prompt_versions = {
        "deep-analyze": "agent-v1",
        "generate-poc": next(
            (p["version"] for p in _prompt_registry.list_all() if p["taskType"] == "generate-poc"),
            "v1",
        ),
    }
    result = {
        "service": "s3-agent",
        "status": "ok",
        "version": "0.1.0",
        "llmMode": settings.llm_mode,
        "modelProfiles": [
            p["profileId"] for p in _model_registry.list_all()
        ],
        "activePromptVersions": prompt_versions,
        "activeResponseSchemas": {
            "deep-analyze": "agent-v1.1",
            "generate-poc": "agent-v1.1",
        },
        "agentConfig": {
            "maxSteps": settings.agent_max_steps,
            "maxCompletionTokens": settings.agent_max_completion_tokens,
            "taskDeadlineMs": settings.analysis_task_deadline_ms,
            "partialEnvelopeDeadlineMs": settings.analysis_partial_envelope_deadline_ms,
            "llmAsyncPollIntervalSeconds": settings.llm_async_poll_interval_seconds,
            "toolBudget": {
                "cheap": settings.agent_max_cheap_calls,
                "medium": settings.agent_max_medium_calls,
                "expensive": settings.agent_max_expensive_calls,
            },
        },
    }
    result["activeRequestCount"] = request_summary_tracker.active_request_count()
    result["requestSummary"] = request_summary_tracker.get_summary(requestId)
    if settings.llm_mode == "real":
        result["llmBackend"] = await _check_llm_backend()
        result["llmConcurrency"] = settings.llm_concurrency

    threat_search = getattr(req.app.state, "threat_search", None)
    result["rag"] = {
        "enabled": settings.rag_enabled,
        "kbEndpoint": settings.kb_endpoint,
        "status": "ok" if threat_search else "disabled",
    }

    return result


async def _check_llm_backend() -> dict:
    """S7 Gateway 연결 상태를 확인한다."""
    import httpx

    endpoint = settings.llm_endpoint  # S7 Gateway 주소

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{endpoint}/v1/health")
            resp.raise_for_status()
            data = resp.json()
            return {
                "status": "ok",
                "gateway": endpoint,
                "gatewayLlmBackend": data.get("llmBackend"),
            }
    except Exception as e:
        return {"status": "unreachable", "gateway": endpoint, "error": str(e)}


@router.get("/models")
async def list_models() -> dict:
    return {"profiles": _model_registry.list_all()}


@router.get("/prompts")
async def list_prompts() -> dict:
    return {"prompts": _prompt_registry.list_all()}
