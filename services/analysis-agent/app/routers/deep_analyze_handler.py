"""Deep-analyze task handler extracted from tasks router."""

from __future__ import annotations

import logging
from app.config import settings
from app.agent_runtime.llm.generation_policy import TimeoutDefaults
from app.agent_runtime.context import get_request_id
from app.runtime.request_summary import request_summary_tracker
from app.schemas.request import TaskRequest
from app.schemas.response import Claim, TaskFailureResponse, TaskSuccessResponse
from app.state_machine import diagnose_claim_evidence, plan_next_action, transition_claim_status
from app.types import ClaimStatus

logger = logging.getLogger(__name__)


def _configure_phase2_graph_tools(registry, phase1_result, project_id, callers_tool=None, callees_tool=None, search_tool=None) -> None:
    from app.tools.router import register_tools_for_session

    register_tools_for_session(
        registry,
        phase1_result,
        project_id=project_id,
        callers_tool=callers_tool,
        callees_tool=callees_tool,
        search_tool=search_tool,
    )


def _suggest_next_evidence_action(phase1_result, session, registry) -> dict | None:
    """Return one deterministic advisory acquisition action for an under-evidenced Phase 1 claim."""
    claim = _phase1_claim_for_planner(phase1_result, session)
    if claim is None:
        return None

    diagnosis = diagnose_claim_evidence(
        claim,
        session.evidence_catalog,
        allowed_local_refs=set(session.evidence_catalog.ref_ids()),
    )
    transitioned = transition_claim_status(claim, diagnosis)
    action = plan_next_action(
        transitioned,
        set(registry.list_names()),
        session.planned_action_keys,
        catalog=session.evidence_catalog,
    )
    if action is None:
        return None

    session.planned_action_keys.add(action.dedup_key)
    return {
        "tool_name": action.tool_name,
        "arguments": action.arguments,
        "rationale": action.rationale,
        "target_slot": action.target_slot,
        "dedup_key": action.dedup_key,
    }


def _phase1_claim_for_planner(phase1_result, session) -> Claim | None:
    """Build a conservative planner-only claim from Phase 1 evidence."""
    if not phase1_result.sast_findings:
        return None

    finding = phase1_result.sast_findings[0]
    if not isinstance(finding, dict):
        return None

    supporting_ref = _first_sast_ref_id(session)
    if supporting_ref is None:
        return None

    required = ["local_or_derived_support"]
    if not phase1_result.threat_context and not phase1_result.kb_not_ready and not phase1_result.kb_timed_out:
        required.append("threat_knowledge")
    if not phase1_result.dangerous_callers and phase1_result.code_graph_neo4j_ready is not False:
        required.append("caller_chain")

    if len(required) == 1:
        return None

    loc = finding.get("location", {}) if isinstance(finding.get("location"), dict) else {}
    metadata = finding.get("metadata", {}) if isinstance(finding.get("metadata"), dict) else {}
    cwe = metadata.get("cweId") or metadata.get("cwe") or finding.get("ruleId") or ""
    statement = " ".join(str(part) for part in (cwe, finding.get("message")) if part).strip()

    return Claim(
        statement=statement or "Phase 1 finding requires more evidence",
        detail=finding.get("message") or statement,
        supportingEvidenceRefs=[supporting_ref],
        location=_format_planner_location(loc),
        claimId="planner-phase1-0",
        status=ClaimStatus.CANDIDATE,
        requiredEvidence=required,
    )


def _first_sast_ref_id(session) -> str | None:
    for entry in session.evidence_catalog.entries():
        if entry.category == "sast":
            return entry.ref_id
    return None


def _format_planner_location(location: dict) -> str | None:
    file = location.get("file")
    line = location.get("line")
    if file and line:
        return f"{file}:{line}"
    if file:
        return str(file)
    return None


async def handle_deep_analyze(request: TaskRequest, model_registry) -> TaskSuccessResponse | TaskFailureResponse:
    """deep-analyze 요청을 AgentLoop로 처리한다."""
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
    from app.tools.implementations.mock_tools import MockKnowledgeTool
    from app.agent_runtime.tools.registry import ToolRegistry, ToolSchema
    from app.tools.router import ToolRouter

    request_id = get_request_id() or request.taskId
    request_summary_tracker.mark_phase_advancing(request_id, source="deep-analyze-start")

    # 예산 구성
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

    # Tool 구성 — Phase 2에서 LLM이 호출 가능한 도구만 등록
    # (sast.scan은 Phase 1에서 자동 실행되므로 Phase 2 registry에서 제외)
    registry = ToolRegistry()
    registry.register(ToolSchema(
        name="code_graph.callers",
        description="특정 함수를 호출하는 함수 체인을 조회한다 (코드 그래프 기반). Phase 1에서 적재된 코드 그래프에서 역방향 BFS로 호출자를 추적한다.",
        parameters={
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "조회할 함수명 (예: 'popen', 'getenv')"},
                "depth": {"type": "integer", "description": "탐색 깊이 (기본 2)", "default": 2},
            },
            "required": ["function_name"],
        },
        cost_tier=ToolCostTier.MEDIUM,
    ))
    registry.register(ToolSchema(
        name="code_graph.callees",
        description="특정 함수가 호출하는 함수 목록을 조회한다. 취약 함수 호출 전 입력 검증 여부, 위험 함수 호출 여부 확인에 사용.",
        parameters={
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "조회할 함수명 (예: 'handleRequest', 'postJson')"},
            },
            "required": ["function_name"],
        },
        cost_tier=ToolCostTier.CHEAP,
    ))
    registry.register(ToolSchema(
        name="code_graph.search",
        description="자연어 쿼리로 코드 함수를 시맨틱 검색한다. 함수명 정확 매칭 + 벡터 유사도 + 호출 그래프 확장을 결합. 예: '시스템 명령을 실행하는 네트워크 핸들러'",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "자연어 검색 쿼리 또는 함수명 (예: 'popen을 호출하는 네트워크 함수')"},
                "top_k": {"type": "integer", "description": "최대 반환 건수 (기본 10)", "default": 10},
                "include_call_chain": {"type": "boolean", "description": "결과에 callers/callees 포함 (기본 true)", "default": True},
            },
            "required": ["query"],
        },
        cost_tier=ToolCostTier.MEDIUM,
    ))
    registry.register(ToolSchema(
        name="knowledge.search",
        description="위협 지식 DB에서 공격 시나리오/CWE/CAPEC/CVE를 검색한다. 이전 결과가 부적절하면 exclude_ids로 제외하고 재검색 가능.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "검색 쿼리 (예: 'command injection CWE-78')"},
                "top_k": {"type": "integer", "description": "반환할 최대 결과 수", "default": 5},
                "source_filter": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "검색 소스 필터 (예: ['CWE'], ['ATT&CK'], ['CWE', 'CVE']). 미지정 시 전체 검색",
                },
                "exclude_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "결과에서 제외할 노드 ID 목록 (예: ['CWE-78', 'CAPEC-88']). 이전 검색에서 부적절한 결과를 제외하고 다른 결과를 받을 때 사용",
                },
            },
            "required": ["query"],
        },
        cost_tier=ToolCostTier.CHEAP,
    ))
    registry.register(ToolSchema(
        name="code.read_file",
        description="프로젝트 소스 파일을 읽는다. 코드 그래프에서 호출 체인이 끊기거나 함수 포인터/매크로 경유가 의심될 때 소스를 직접 확인하라. 최대 8,000자.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "프로젝트 루트 기준 상대 경로 (예: 'src/main.c', 'include/config.h')"},
            },
            "required": ["path"],
        },
        cost_tier=ToolCostTier.CHEAP,
    ))
    registry.register(ToolSchema(
        name="build.metadata",
        description="타겟 빌드 환경의 매크로와 아키텍처 정보를 조회한다. 포인터 크기(__SIZEOF_POINTER__), 엔디안(__BYTE_ORDER__), 정수 크기(__SIZEOF_LONG__) 등 취약점 심각도 판단에 사용.",
        parameters={
            "type": "object",
            "properties": {},
        },
        cost_tier=ToolCostTier.CHEAP,
    ))

    executor = ToolExecutor(timeout_ms=settings.agent_tool_timeout_ms)
    failure_policy = ToolFailurePolicy()
    router = ToolRouter(registry, executor, bm, failure_policy)

    # Tool 구현체 등록
    sast_impl = None
    codegraph_impl = None
    sca_impl = None
    callers_tool = None

    search_tool = None

    if settings.llm_mode == "real":
        from app.tools.implementations.sast_tool import SastScanTool
        from app.tools.implementations.codegraph_phase1_tool import CodeGraphPhase1Tool
        from app.tools.implementations.codegraph_callers_tool import CodeGraphCallersTool
        from app.tools.implementations.codegraph_callees_tool import CodeGraphCalleesTool
        from app.tools.implementations.codegraph_search_tool import CodeGraphSearchTool
        from app.tools.implementations.knowledge_tool import KnowledgeTool
        from app.tools.implementations.metadata_tool import MetadataTool
        from app.tools.implementations.read_file_tool import ReadFileTool
        from app.tools.implementations.sca_tool import ScaTool
        # NDJSON 스트리밍 모드: inactivity timeout(60s)으로 제어.
        # X-Timeout-Ms는 S4 내부 도구별 예산으로 전달 (전체 데드라인 아님).
        sast_tool_budget_s = max(TimeoutDefaults.TOOL_EXECUTION_SECONDS, request.constraints.timeoutMs / 1000.0 * 0.5)
        sast_impl = SastScanTool(timeout_s=sast_tool_budget_s)
        codegraph_impl = CodeGraphPhase1Tool()  # Phase 1: S4 /v1/functions
        sca_impl = ScaTool()
        # Phase 2 도구 등록 (LLM이 호출)
        callers_tool = CodeGraphCallersTool(base_url=settings.kb_endpoint)
        callees_tool = CodeGraphCalleesTool(base_url=settings.kb_endpoint)
        search_tool = CodeGraphSearchTool(base_url=settings.kb_endpoint)
        project_path = request.context.trusted.get("projectPath", "")
        build_profile = request.context.trusted.get("buildProfile", {})
        router.register_implementation("sast.scan", sast_impl)
        router.register_implementation("code_graph.callers", callers_tool)
        router.register_implementation("code_graph.callees", callees_tool)
        router.register_implementation("code_graph.search", search_tool)
        router.register_implementation("knowledge.search", KnowledgeTool())
        if project_path:
            router.register_implementation("code.read_file", ReadFileTool(project_path))
            router.register_implementation("build.metadata", MetadataTool(
                sast_endpoint=settings.sast_endpoint,
                project_path=project_path,
                build_profile=build_profile,
            ))
    else:
        router.register_implementation("knowledge.search", MockKnowledgeTool())

    # ─── Phase 1: 결정론적 도구 실행 (LLM 없이) ───
    from app.core.phase_one import Phase1Executor, build_phase2_prompt

    phase1_budget_ms = int(request.constraints.timeoutMs * 0.6)
    phase1_executor = Phase1Executor(
        sast_tool=sast_impl,
        codegraph_tool=codegraph_impl,
        sca_tool=sca_impl,
        kb_endpoint=settings.kb_endpoint,
        sast_endpoint=settings.sast_endpoint,
        timeout_budget_ms=phase1_budget_ms,
    )
    try:
        phase1_result = await phase1_executor.execute(session)
    finally:
        await phase1_executor.aclose()
    degrade_reasons: list[str] = []
    if phase1_result.sast_partial_tools:
        degrade_reasons.append("phase1-partial-tools")
    if phase1_result.build_failure_detail:
        degrade_reasons.append("build-path-fallback")
    request_summary_tracker.mark_phase_advancing(
        request_id,
        source="phase-one-complete",
        degraded=bool(degrade_reasons),
        degrade_reasons=degrade_reasons,
    )

    # Phase 2 코드 그래프 도구에 project_id 주입
    project_id = session.request.context.trusted.get("projectId", session.request.taskId)
    if settings.llm_mode == "real":
        _configure_phase2_graph_tools(
            registry,
            phase1_result,
            project_id,
            callers_tool=callers_tool,
            callees_tool=callees_tool,
            search_tool=search_tool,
        )

    # ─── Phase 2 준비: LLM 프롬프트에 Phase 1 결과 주입 ───

    # LLM 구성
    if settings.llm_mode == "real":
        profile = model_registry.get_default()
        llm_caller = LlmCaller(
            endpoint=profile.endpoint if profile else settings.llm_endpoint,
            model=profile.modelName if profile else settings.llm_model,
            api_key=profile.apiKey if profile else settings.llm_api_key,
            default_max_tokens=settings.agent_llm_max_tokens,
            service_id="s3-agent",
            async_poll_interval_seconds=settings.llm_async_poll_interval_seconds,
        )
    else:
        import json
        from app.agent_runtime.llm.static_caller import StaticLlmCaller

        ref_ids = [ref.refId for ref in request.evidenceRefs]
        llm_caller = StaticLlmCaller(
            content=json.dumps({
                "summary": "[Mock] Deep analysis completed",
                "claims": [{
                    "statement": "Mock analysis result",
                    "detail": "Mock deep analysis detail.",
                    "supportingEvidenceRefs": ref_ids[:1],
                    "location": "mock:1",
                }],
                "caveats": ["This is a mock response"],
                "usedEvidenceRefs": ref_ids[:1],
                "suggestedSeverity": "info",
                "needsHumanReview": True,
                "recommendedNextSteps": [],
                "policyFlags": [],
            }),
            prompt_tokens=100,
            completion_tokens=50,
        )

    session.evidence_catalog.ingest_phase1_result(phase1_result)
    session.extra_allowed_refs = set(session.evidence_catalog.ref_ids())
    all_evidence_refs = session.evidence_catalog.as_evidence_refs()
    live_recovery_summary = session.live_recovery_trace_summary()
    suggested_next_action = _suggest_next_evidence_action(phase1_result, session, registry)

    # 프롬프트 조립 — Phase 1 결과를 포함
    system_prompt, user_message = build_phase2_prompt(
        phase1_result, request.context.trusted,
        evidence_refs=all_evidence_refs,
        budget=session.budget,
        live_recovery_summary=live_recovery_summary,
        suggested_next_action=suggested_next_action,
    )
    mm = MessageManager(
        system_prompt=system_prompt,
        initial_user_message=user_message,
    )

    loop = AgentLoop(
        llm_caller=llm_caller,
        message_manager=mm,
        tool_registry=registry,
        tool_router=router,
        termination_policy=TerminationPolicy(timeout_ms=request.constraints.timeoutMs),
        budget_manager=bm,
        token_counter=TokenCounter(),
        result_assembler=ResultAssembler(
            model_name=settings.llm_model,
            prompt_version="agent-v1",
        ),
        turn_summarizer=TurnSummarizer(),
        retry_policy=RetryPolicy(max_retries=settings.agent_llm_retry_max),
    )

    try:
        result = await loop.run(session)
        request_summary_tracker.mark_phase_advancing(request_id, source="llm-loop-complete")

        # 분석 완료 시 프로젝트 메모리에 결과 저장
        if isinstance(result, TaskSuccessResponse) and project_id and settings.llm_mode == "real":
            await save_analysis_memory(project_id, result)

        return result
    finally:
        if settings.llm_mode == "real" and hasattr(llm_caller, 'aclose'):
            await llm_caller.aclose()

async def save_analysis_memory(project_id: str, result: TaskSuccessResponse) -> None:
    """분석 결과를 S5 프로젝트 메모리에 저장한다."""
    import httpx
    from datetime import datetime, timezone

    try:
        claims_summary = [
            {
                "statement": c.statement,
                "location": c.location,
                "severity": result.result.suggestedSeverity,
            }
            for c in result.result.claims
        ]

        memory_data = {
            "type": "analysis_history",
            "data": {
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "claimCount": len(result.result.claims),
                "severity": result.result.suggestedSeverity,
                "confidence": result.result.confidence,
                "claims": claims_summary,
            },
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            headers = {}
            request_id = get_request_id()
            if request_id:
                headers["X-Request-Id"] = request_id
            resp = await client.post(
                f"{settings.kb_endpoint}/v1/project-memory/{project_id}",
                json=memory_data,
                headers=headers,
            )
            if resp.status_code == 409:
                logger.info("[memory] 중복 메모리 (deduplicated): projectId=%s", project_id)
            elif resp.status_code == 503:
                logger.warning("[memory] S5 KB 미초기화 (503): projectId=%s", project_id)
            else:
                resp.raise_for_status()
                logger.info("[memory] 분석 결과 메모리 저장 완료: projectId=%s", project_id)
    except Exception as e:
        logger.warning("[memory] 분석 결과 메모리 저장 실패 (무시): %s", e)
