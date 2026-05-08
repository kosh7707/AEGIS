"""SDK-analyze task handler extracted from tasks router."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from app.config import settings
from app.agent_runtime.context import get_request_id
from app.routers.sdk_analyze_support import (
    build_sdk_analyze_prompt as _build_sdk_analyze_prompt,
    discover_sdk_profile as _discover_sdk_profile,
)
from app.schemas.request import TaskRequest
from app.schemas.response import AuditInfo, TaskFailureResponse, TaskSuccessResponse, TokenUsage
from app.types import FailureCode, TaskStatus


def _invalid_sdk_request(request: TaskRequest, detail: str) -> TaskFailureResponse:
    input_str = json.dumps(request.model_dump(mode="json"), sort_keys=True)
    return TaskFailureResponse(
        taskId=request.taskId,
        taskType=request.taskType,
        status=TaskStatus.VALIDATION_FAILED,
        failureCode=FailureCode.INVALID_SCHEMA,
        failureDetail=detail,
        retryable=False,
        audit=AuditInfo(
            inputHash=f"sha256:{__import__('hashlib').sha256(input_str.encode()).hexdigest()[:16]}",
            latencyMs=0,
            tokenUsage=TokenUsage(),
            retryCount=0,
            ragHits=0,
            createdAt=datetime.now(timezone.utc).isoformat(),
        ),
    )


def _validated_sdk_path(request: TaskRequest) -> tuple[str | None, TaskFailureResponse | None]:
    trusted = request.context.trusted if isinstance(request.context.trusted, dict) else {}
    raw_path = trusted.get("projectPath")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None, _invalid_sdk_request(request, "context.trusted.projectPath is required for sdk-analyze")
    if not os.path.isabs(raw_path):
        return None, _invalid_sdk_request(request, "context.trusted.projectPath must be an absolute path")
    sdk_path = os.path.normpath(raw_path)
    if not os.path.isdir(sdk_path):
        return None, _invalid_sdk_request(
            request,
            "sdk-analyze requires context.trusted.projectPath to exist and be a directory",
        )
    return sdk_path, None


async def handle_sdk_analyze(request: TaskRequest) -> TaskSuccessResponse | TaskFailureResponse:
    """sdk-analyze: SDK 디렉토리 분석 → sdkProfile 추출."""
    from app.budget.manager import BudgetManager
    from app.budget.token_counter import TokenCounter
    from app.core.agent_loop import AgentLoop
    from app.core.agent_session import AgentSession
    from app.core.result_assembler import ResultAssembler
    from app.agent_runtime.llm.caller import LlmCaller
    from app.agent_runtime.llm.message_manager import MessageManager
    from app.agent_runtime.llm.turn_summarizer import TurnSummarizer
    from app.agent_runtime.policy.retry import RetryPolicy
    from app.policy.termination import TerminationPolicy
    from app.policy.tool_failure import ToolFailurePolicy
    from app.agent_runtime.schemas.agent import BudgetState, ToolCostTier
    from app.agent_runtime.tools.executor import ToolExecutor
    from app.agent_runtime.tools.registry import ToolRegistry, ToolSchema, ToolSideEffect
    from app.tools.router import ToolRouter
    from app.tools.implementations.list_files import ListFilesTool
    from app.tools.implementations.read_file import ReadFileTool
    from app.tools.implementations.try_build import TryBuildTool

    sdk_path, failure = _validated_sdk_path(request)
    if failure is not None:
        return failure
    assert sdk_path is not None
    request_id = get_request_id() or request.taskId

    # sdk-analyze는 list_files + read_file + try_build(컴파일러 버전 확인용)만 사용
    budget = BudgetState(
        max_steps=settings.agent_max_steps,
        max_completion_tokens=settings.agent_max_completion_tokens,
        max_cheap_calls=settings.agent_max_cheap_calls,
        max_medium_calls=0,
        max_expensive_calls=2,  # 컴파일러 --version 확인용
        max_consecutive_no_evidence=settings.agent_no_evidence_threshold,
    )
    bm = BudgetManager(budget)
    session = AgentSession(request, budget)
    result_assembler = ResultAssembler(model_name=settings.llm_model, prompt_version="build-v3")

    deterministic_profile = _discover_sdk_profile(sdk_path)
    if deterministic_profile:
        deterministic_payload = {
            "summary": "SDK 디렉토리에서 environment-setup 및 compiler 경로를 결정론적으로 추출했습니다.",
            "sdkProfile": deterministic_profile,
            "claims": [
                {
                    "statement": "SDK 프로파일을 environment-setup 및 compiler 경로에서 추출했습니다.",
                    "supportingEvidenceRefs": [],
                }
            ],
            "caveats": [
                "gccVersion은 별도 실행 확인 없이 비워 둘 수 있습니다.",
            ],
            "usedEvidenceRefs": [],
            "needsHumanReview": False,
            "recommendedNextSteps": [],
            "policyFlags": ["deterministic_sdk_scan"],
        }
        return result_assembler.build(json.dumps(deterministic_payload, ensure_ascii=False), session)

    registry = ToolRegistry()
    registry.register(ToolSchema(
        name="list_files",
        description="SDK 디렉토리 구조를 트리 형태로 반환한다. 분석 시작 시 가장 먼저 사용하라.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "(선택) SDK 루트 기준 하위 디렉토리"},
                "max_depth": {"type": "integer", "description": "(선택) 탐색 깊이 제한. 기본 3"},
            },
        },
        cost_tier=ToolCostTier.CHEAP,
        side_effect=ToolSideEffect.PURE,
    ))
    registry.register(ToolSchema(
        name="read_file",
        description="SDK 내 파일을 읽는다 (읽기 전용, 50KB 제한).",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "SDK 루트 기준 상대 경로"},
            },
            "required": ["path"],
        },
        cost_tier=ToolCostTier.CHEAP,
    ))
    registry.register(ToolSchema(
        name="try_build",
        description="명령어를 실행한다. 컴파일러 버전 확인에 사용 (예: 'arm-gcc --version').",
        parameters={
            "type": "object",
            "properties": {
                "build_command": {"type": "string", "description": "실행할 명령어"},
            },
            "required": ["build_command"],
        },
        cost_tier=ToolCostTier.EXPENSIVE,
    ))

    executor = ToolExecutor(timeout_ms=30_000)
    failure_policy = ToolFailurePolicy()
    tool_router = ToolRouter(registry, executor, bm, failure_policy)

    list_tool = ListFilesTool(sdk_path)
    read_tool = ReadFileTool(sdk_path)
    build_tool = TryBuildTool(settings.sast_endpoint, sdk_path, request_id)
    tool_router.register_implementation("list_files", list_tool)
    tool_router.register_implementation("read_file", read_tool)
    tool_router.register_implementation("try_build", build_tool)

    system_prompt = _build_sdk_analyze_prompt(sdk_path)
    user_message = f"## SDK 분석 목표\n`{sdk_path}` SDK를 분석하여 프로파일을 추출하라.\n"

    if settings.llm_mode == "real":
        llm_caller = LlmCaller(
            endpoint=settings.llm_endpoint,
            model=settings.llm_model,
            api_key=settings.llm_api_key,
            default_max_tokens=settings.agent_llm_max_tokens,
            service_id="s3-build",
            async_poll_interval_seconds=settings.llm_async_poll_interval_seconds,
        )
    else:
        from app.agent_runtime.llm.static_caller import StaticLlmCaller

        mock_result = json.dumps({
            "summary": "[Mock] SDK 분석 mock 응답",
            "sdkProfile": {
                "compiler": "mock-gcc",
                "compilerPrefix": "mock",
                "gccVersion": "0.0.0",
                "targetArch": "mock-arch",
                "languageStandard": "c11",
                "sysroot": "",
                "environmentSetup": "",
                "includePaths": [],
                "defines": {},
            },
            "claims": [{"statement": "Mock SDK 분석 완료", "supportingEvidenceRefs": []}],
            "caveats": ["Mock 모드"],
            "usedEvidenceRefs": [],
            "needsHumanReview": True,
            "recommendedNextSteps": [],
            "policyFlags": [],
        }, ensure_ascii=False)

        llm_caller = StaticLlmCaller(
            content=mock_result,
            prompt_tokens=50,
            completion_tokens=40,
        )

    mm = MessageManager(system_prompt=system_prompt, initial_user_message=user_message)

    loop = AgentLoop(
        llm_caller=llm_caller,
        message_manager=mm,
        tool_registry=registry,
        tool_router=tool_router,
        termination_policy=TerminationPolicy(timeout_ms=request.constraints.timeoutMs),
        budget_manager=bm,
        token_counter=TokenCounter(),
        result_assembler=result_assembler,
        turn_summarizer=TurnSummarizer(),
        retry_policy=RetryPolicy(max_retries=settings.agent_llm_retry_max),
    )

    try:
        return await loop.run(session)
    finally:
        if settings.llm_mode == "real" and hasattr(llm_caller, "aclose"):
            await llm_caller.aclose()
