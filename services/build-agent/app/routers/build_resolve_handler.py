"""Build-resolve task handler extracted from tasks router."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

from app.config import settings
from app.agent_runtime.context import get_request_id
from app.routers.build_route_support import (
    build_system_prompt as _build_system_prompt,
    run_build_request_preflight as _run_build_request_preflight,
)
from app.schemas.request import TaskRequest
from app.schemas.response import (
    ArtifactVerification,
    AssessmentResult,
    AuditInfo,
    BUILD_RESPONSE_SCHEMA_VERSION,
    BuildArtifact,
    BuildDiagnostics,
    BuildOutcome,
    BuildPreparation,
    BuildResult,
    TaskFailureResponse,
    TaskSuccessResponse,
    TokenUsage,
    ValidationInfo,
)
from app.types import TaskStatus
from app.validators.build_request_contract import normalize_contract_version

logger = logging.getLogger(__name__)


def _request_scoped_build_subdir(request_id: str | None) -> str:
    """Return a collision-resistant build workspace name for one request."""
    digest = hashlib.sha256((request_id or "default").encode()).hexdigest()[:16]
    return f"build-aegis-{digest}"


def _expected_artifact_labels(preflight) -> list[str]:
    labels: list[str] = []
    for artifact in preflight.contract.expectedArtifacts:
        labels.append(artifact.path or artifact.name or artifact.artifactType.value)
    return labels


def _collect_expected_artifacts(effective_root: str, preflight) -> tuple[list[BuildArtifact], list[str], list[str]]:
    produced: list[BuildArtifact] = []
    produced_labels: list[str] = []
    missing: list[str] = []
    root = Path(effective_root)
    for artifact in preflight.contract.expectedArtifacts:
        label = artifact.path or artifact.name or artifact.artifactType.value
        found_path: Path | None = None
        if artifact.path:
            candidate = (root / artifact.path).resolve()
            try:
                candidate.relative_to(root.resolve())
            except ValueError:
                candidate = None
            if candidate is not None and candidate.exists():
                found_path = candidate
        elif artifact.name:
            for candidate in root.rglob(artifact.name):
                if candidate.is_file() or candidate.is_dir():
                    found_path = candidate
                    break
        if found_path is None:
            missing.append(label)
            produced.append(BuildArtifact(path=label, kind=artifact.artifactType.value, exists=False))
        else:
            rel = str(found_path.relative_to(root))
            produced_labels.append(rel)
            produced.append(BuildArtifact(path=rel, kind=artifact.artifactType.value, exists=True))
    return produced, produced_labels, missing


def _build_deterministic_success_response(
    *,
    request: TaskRequest,
    preflight,
    effective_root: str,
    build_subdir: str,
    build_environment: dict[str, str],
    started_at: float,
    tool_content: str,
) -> TaskSuccessResponse:
    build_command = f"bash {build_subdir}/aegis-build.sh"
    expected = _expected_artifact_labels(preflight)
    produced_artifacts, produced_labels, missing = _collect_expected_artifacts(effective_root, preflight)
    clean_pass = not missing
    outcome = "built" if clean_pass else "artifact_mismatch"
    failure_code = None if clean_pass else "EXPECTED_ARTIFACTS_MISMATCH"
    reasons = ["deterministic phase0 build script succeeded"]
    if missing:
        reasons.append("expected artifact mismatch")

    build_result = BuildResult(
        success=clean_pass,
        declaredMode=preflight.contract.buildMode.value if preflight.contract.buildMode else None,
        sdkId=preflight.contract.sdkId,
        buildCommand=build_command,
        buildScript=f"{build_subdir}/aegis-build.sh",
        buildDir=build_subdir,
        errorLog=None if clean_pass else "Expected artifacts were not found after deterministic build.",
        producedArtifacts=produced_artifacts,
        artifactVerification=ArtifactVerification(
            strict=preflight.contract.strictMode is True,
            expected=expected,
            produced=produced_labels,
            matched=clean_pass,
            missing=missing,
        ),
    )
    result = AssessmentResult(
        summary=(
            "Deterministic phase0 build wrapper completed with expected artifacts."
            if clean_pass
            else "Deterministic phase0 build wrapper ran, but expected artifacts were missing."
        ),
        claims=[],
        caveats=[] if clean_pass else ["Expected artifacts were not found after deterministic build."],
        usedEvidenceRefs=["eref-build-success"] if clean_pass else [],
        confidence=1.0 if clean_pass else 0.6,
        needsHumanReview=not clean_pass,
        recommendedNextSteps=[] if clean_pass else ["Review expectedArtifacts or generated build output."],
        policyFlags=["deterministic_phase0_build"],
        buildResult=build_result,
        buildPreparation=BuildPreparation(
            declaredMode=build_result.declaredMode,
            sdkId=build_result.sdkId,
            buildCommand=build_result.buildCommand,
            buildScript=build_result.buildScript,
            buildDir=build_result.buildDir,
            buildEnvironment=build_environment,
            expectedArtifacts=expected,
            producedArtifacts=produced_labels,
        ),
        buildOutcome=BuildOutcome(
            outcome=outcome,
            taskCompleted=True,
            cleanPass=clean_pass,
            reasons=reasons,
        ),
        cleanPass=clean_pass,
        buildDiagnostics=BuildDiagnostics(
            failureCode=failure_code,
            failureCategory=None if clean_pass else "artifact_mismatch",
            expectedArtifacts=expected,
            producedArtifacts=produced_labels,
            missingArtifacts=missing,
            caveats=[] if clean_pass else ["Expected artifacts were not found after deterministic build."],
        ),
    )
    input_str = json.dumps(request.model_dump(mode="json"), sort_keys=True)
    input_hash = f"sha256:{hashlib.sha256(input_str.encode()).hexdigest()[:16]}"
    return TaskSuccessResponse(
        taskId=request.taskId,
        taskType=request.taskType,
        contractVersion=normalize_contract_version(preflight.contract),
        strictMode=preflight.contract.strictMode,
        status=TaskStatus.COMPLETED,
        modelProfile="deterministic-phase0",
        promptVersion="build-v3",
        schemaVersion=BUILD_RESPONSE_SCHEMA_VERSION,
        validation=ValidationInfo(valid=True, errors=[]),
        result=result,
        audit=AuditInfo(
            inputHash=input_hash,
            latencyMs=int((monotonic() - started_at) * 1000),
            tokenUsage=TokenUsage(prompt=0, completion=0),
            retryCount=0,
            ragHits=0,
            createdAt=datetime.now(timezone.utc).isoformat(),
            agentAudit={
                "phase": "deterministic-phase0-build",
                "buildCommand": build_command,
                "toolContentPreview": tool_content[:2000],
            },
        ),
    )


async def handle_build_resolve(request: TaskRequest) -> TaskSuccessResponse | TaskFailureResponse:
    """build-resolve v2: 빌드 스크립트 작성 + 빌드 성공."""
    started_at = monotonic()
    from app.budget.manager import BudgetManager
    from app.budget.token_counter import TokenCounter
    from app.core.agent_loop import AgentLoop
    from app.core.agent_session import AgentSession
    from app.core.result_assembler import ResultAssembler
    from app.agent_runtime.llm.caller import LlmCaller
    from app.agent_runtime.llm.message_manager import MessageManager
    from app.agent_runtime.llm.turn_summarizer import TurnSummarizer
    from app.agent_runtime.policy.retry import RetryPolicy
    from app.policy.file_policy import FilePolicy
    from app.policy.termination import TerminationPolicy
    from app.policy.tool_failure import ToolFailurePolicy
    from app.agent_runtime.schemas.agent import BudgetState, ToolCostTier
    from app.agent_runtime.tools.executor import ToolExecutor
    from app.agent_runtime.tools.registry import ToolRegistry, ToolSchema, ToolSideEffect
    from app.tools.router import ToolRouter
    from app.tools.implementations.list_files import ListFilesTool
    from app.tools.implementations.read_file import ReadFileTool
    from app.tools.implementations.write_file import WriteFileTool
    from app.tools.implementations.edit_file import EditFileTool
    from app.tools.implementations.delete_file import DeleteFileTool
    from app.tools.implementations.try_build import TryBuildTool

    preflight, failure = await _run_build_request_preflight(request)
    if failure is not None:
        return failure
    assert preflight is not None

    project_path = preflight.project_path
    target_path = preflight.target_path
    target_name = preflight.target_name
    request_id = get_request_id() or request.taskId

    # BuildTarget 스코핑: build-aegis/는 canonical buildTargetPath 기준
    effective_root = os.path.join(project_path, target_path) if target_path else project_path

    # ─── 0. Request-scoped 빌드 워크스페이스 (동시 요청 격리) ───
    import shutil
    build_subdir = _request_scoped_build_subdir(request_id)
    build_aegis_dir = os.path.join(effective_root, build_subdir)
    if os.path.isdir(build_aegis_dir):
        shutil.rmtree(build_aegis_dir, ignore_errors=True)
        logger.info("[build] 이전 빌드 캐시 정리: %s", build_aegis_dir)

    # ─── 0b. 정책 엔진 (request-scoped build dir) ───
    file_policy = FilePolicy(effective_root, build_dir=build_subdir)

    # ─── 1. Phase 0 결정론적 사전 분석 ───
    from app.core.phase_zero import Phase0Executor
    phase0 = Phase0Executor(project_path, target_path)
    phase0_result = await phase0.execute(request_id)
    if preflight.script_hint:
        phase0_result.build_system = "shell"
    sdk_materialization = preflight.sdk_materialization
    effective_build_environment = (
        sdk_materialization.effective_environment
        if sdk_materialization is not None
        else preflight.contract.buildEnvironment
    )
    setup_script = (
        sdk_materialization.setup_script
        if sdk_materialization is not None and sdk_materialization.setup_script
        else preflight.contract.setupScript
    )
    build_material = {
        "sdkRootPath": sdk_materialization.sdk_root_path if sdk_materialization else (preflight.contract.sdkRootPath or ""),
        "setupScript": setup_script or "",
        "setupScriptRaw": sdk_materialization.setup_script_raw if sdk_materialization else preflight.contract.setupScript,
        "sysroot": sdk_materialization.sysroot if sdk_materialization else (preflight.contract.sysroot or ""),
        "sysrootRaw": sdk_materialization.sysroot_raw if sdk_materialization else preflight.contract.sysroot,
        "toolchainTriplet": preflight.contract.toolchainTriplet or "",
        "buildEnvironment": effective_build_environment,
        "callerBuildEnvironment": sdk_materialization.caller_environment if sdk_materialization else preflight.contract.buildEnvironment,
        "derivedBuildEnvironment": sdk_materialization.derived_environment if sdk_materialization else {},
        "scriptHint": {
            "path": preflight.script_hint.path,
            "content": preflight.script_hint.content,
            "sizeBytes": preflight.script_hint.size_bytes,
            "sha256": preflight.script_hint.sha256,
        } if preflight.script_hint else None,
    }
    build_files = phase0_result.build_files

    # ─── 1b. 초기 빌드 스크립트 결정론적 생성 (cmake/make/autotools 템플릿) ───
    initial_script = phase0.generate_initial_script(
        setup_script,
        sdk_environment=sdk_materialization.derived_environment if sdk_materialization else None,
        script_hint_path=preflight.script_hint.path if preflight.script_hint else None,
    )
    initial_script_hint = ""
    if initial_script:
        os.makedirs(os.path.join(effective_root, build_subdir), exist_ok=True)
        script_path = os.path.join(effective_root, build_subdir, "aegis-build.sh")
        with open(script_path, "w") as f:
            f.write(initial_script)
        file_policy.record_created("aegis-build.sh")
        initial_script_hint = (
            f"\n\n[Phase 0 자동 생성] {build_subdir}/aegis-build.sh에 "
            f"{phase0_result.build_system} 템플릿 스크립트가 생성되었다. "
            "이 스크립트를 기반으로 수정하거나, 필요 시 새로 작성하라."
        )
        logger.info("[build] 초기 스크립트 생성: %s (%s)", script_path, phase0_result.build_system)

    # ─── 3. 예산 구성 ───
    budget = BudgetState(
        max_steps=settings.agent_max_steps,
        max_completion_tokens=settings.agent_max_completion_tokens,
        max_cheap_calls=settings.agent_max_cheap_calls,
        max_medium_calls=settings.agent_max_medium_calls,
        max_expensive_calls=settings.agent_max_expensive_calls,
        max_consecutive_no_evidence=settings.agent_no_evidence_threshold,
    )
    bm = BudgetManager(budget)
    session = AgentSession(request, budget)

    # ─── 4. Tool 스키마 등록 ───
    registry = ToolRegistry()
    registry.register(ToolSchema(
        name="list_files",
        description="프로젝트 디렉토리 구조를 트리 형태로 반환한다. 전체 구조를 파악할 때 가장 먼저 사용하라.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "(선택) 특정 하위 디렉토리만 탐색. 기본: 프로젝트 루트"},
                "max_depth": {"type": "integer", "description": "(선택) 탐색 깊이 제한. 기본: 3"},
            },
        },
        cost_tier=ToolCostTier.CHEAP,
        side_effect=ToolSideEffect.PURE,
    ))
    registry.register(ToolSchema(
        name="read_file",
        description="프로젝트 내 파일을 읽는다 (읽기 전용, 8KB 제한).",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "프로젝트 루트 기준 상대 경로"},
            },
            "required": ["path"],
        },
        cost_tier=ToolCostTier.CHEAP,
        side_effect=ToolSideEffect.READ,
    ))
    registry.register(ToolSchema(
        name="write_file",
        description=f"{build_subdir}/ 폴더 안에 파일을 생성한다 (빌드 스크립트, toolchain 파일 등).",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": f"{build_subdir}/ 기준 상대 경로 (예: 'aegis-build.sh')"},
                "content": {"type": "string", "description": "파일 내용"},
            },
            "required": ["path", "content"],
        },
        cost_tier=ToolCostTier.CHEAP,
        side_effect=ToolSideEffect.WRITE,
    ))
    registry.register(ToolSchema(
        name="edit_file",
        description=f"{build_subdir}/ 내 에이전트가 생성한 파일을 수정한다 (전체 덮어쓰기).",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": f"{build_subdir}/ 기준 상대 경로"},
                "content": {"type": "string", "description": "새 파일 내용 (전체 교체)"},
            },
            "required": ["path", "content"],
        },
        cost_tier=ToolCostTier.CHEAP,
        side_effect=ToolSideEffect.WRITE,
    ))
    registry.register(ToolSchema(
        name="delete_file",
        description=f"{build_subdir}/ 내 에이전트가 생성한 파일을 삭제한다.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": f"{build_subdir}/ 기준 상대 경로"},
            },
            "required": ["path"],
        },
        cost_tier=ToolCostTier.CHEAP,
        side_effect=ToolSideEffect.WRITE,
    ))
    registry.register(ToolSchema(
        name="try_build",
        description="S4에 빌드 명령어를 전송하여 실행한다. success=true, readiness.status=ready, compileCommandsReady=true, quickEligible=true, compileCommandsPath 존재, userEntries>0, exitCode=0이 모두 만족되어야 성공.",
        parameters={
            "type": "object",
            "properties": {
                "build_command": {"type": "string", "description": f"빌드 명령어 (예: 'bash {build_subdir}/aegis-build.sh')"},
                "build_environment": {
                    "type": "object",
                    "description": "(선택) caller가 제공한 명시적 환경변수 주입. 값은 문자열이어야 한다.",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["build_command"],
        },
        cost_tier=ToolCostTier.EXPENSIVE,
        side_effect=ToolSideEffect.EXECUTE,
    ))

    # ─── 5. Tool 구현체 등록 ───
    executor = ToolExecutor(timeout_ms=settings.agent_tool_timeout_ms)
    failure_policy = ToolFailurePolicy()
    tool_router = ToolRouter(registry, executor, bm, failure_policy)

    list_tool = ListFilesTool(effective_root)
    read_tool = ReadFileTool(effective_root)
    write_tool = WriteFileTool(effective_root, build_dir=build_subdir, file_policy=file_policy)
    edit_tool = EditFileTool(effective_root, file_policy, build_dir=build_subdir)
    delete_tool = DeleteFileTool(effective_root, file_policy, build_dir=build_subdir)
    provenance = request.context.trusted.get("provenance", {}) if isinstance(request.context.trusted, dict) else {}
    if not isinstance(provenance, dict):
        provenance = {}
    build_tool = TryBuildTool(
        settings.sast_endpoint,
        effective_root,
        request_id,
        default_build_environment=effective_build_environment,
        provenance=provenance,
        build_dir=build_subdir,
    )

    tool_router.register_implementation("list_files", list_tool)
    tool_router.register_implementation("read_file", read_tool)
    tool_router.register_implementation("write_file", write_tool)
    tool_router.register_implementation("edit_file", edit_tool)
    tool_router.register_implementation("delete_file", delete_tool)
    tool_router.register_implementation("try_build", build_tool)

    if initial_script:
        deterministic_result = await build_tool.execute({
            "build_command": f"bash {build_subdir}/aegis-build.sh",
        })
        if deterministic_result.success:
            return _build_deterministic_success_response(
                request=request,
                preflight=preflight,
                effective_root=effective_root,
                build_subdir=build_subdir,
                build_environment=effective_build_environment,
                started_at=started_at,
                tool_content=deterministic_result.content,
            )
        logger.info(
            "[build] deterministic phase0 build did not pass; continuing agent loop: %s",
            deterministic_result.error or deterministic_result.content[:500],
        )

    # ─── 6. 시스템 프롬프트 + LLM ───
    system_prompt = _build_system_prompt(
        build_material, build_files, project_path,
        target_path=target_path, target_name=target_name,
        phase0=phase0_result,
        build_subdir=build_subdir,
        initial_script_hint=initial_script_hint,
        build_contract=preflight,
    )
    build_source = os.path.join(project_path, target_path) if target_path else project_path
    user_message = (
        f"## 빌드 목표\n"
        f"`{build_source}` 프로젝트를 빌드하는 스크립트를 작성하고 빌드를 성공시켜라.\n\n"
        f"## 프로젝트 경로\n{project_path}\n"
    )
    if target_path:
        user_message += f"## 빌드 대상 BuildTarget\n{target_path}\n"
    if preflight.contract.strictMode:
        user_message += (
            f"## 호출자 선언 contractVersion\n{normalize_contract_version(preflight.contract)}\n"
            f"## 호출자 선언 build.mode\n{preflight.contract.buildMode.value if preflight.contract.buildMode else 'unspecified'}\n"
        )
    if preflight.script_hint:
        user_message += (
            "## caller build script hint\n"
            f"provided at `{preflight.script_hint.path}` "
            "(uploaded-project path, text-only, reference-only)\n"
        )

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

        mock_build_result = json.dumps({
            "summary": "[Mock] 빌드 에이전트 mock 응답",
            "buildResult": {
                "success": True,
                "buildCommand": f"bash {build_subdir}/aegis-build.sh",
                "buildScript": f"{build_subdir}/aegis-build.sh",
                "buildDir": build_subdir,
                "errorLog": None,
            },
            "claims": [{"statement": "Mock 빌드 완료", "supportingEvidenceRefs": []}],
            "caveats": ["Mock 모드"],
            "usedEvidenceRefs": [],
            "needsHumanReview": True,
            "recommendedNextSteps": ["실제 LLM 모드에서 빌드 재시도"],
            "policyFlags": [],
        }, ensure_ascii=False)

        llm_caller = StaticLlmCaller(
            content=mock_build_result,
            prompt_tokens=100,
            completion_tokens=80,
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
        result_assembler=ResultAssembler(model_name=settings.llm_model, prompt_version="build-v3"),
        turn_summarizer=TurnSummarizer(),
        retry_policy=RetryPolicy(max_retries=settings.agent_llm_retry_max),
    )

    try:
        result = await loop.run(session)
        return result
    finally:
        if settings.llm_mode == "real" and hasattr(llm_caller, "aclose"):
            await llm_caller.aclose()
