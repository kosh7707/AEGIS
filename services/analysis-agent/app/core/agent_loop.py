"""AgentLoop — 에이전트 메인 루프. 분기 판단(tool_call vs content)은 여기서."""

from __future__ import annotations

import asyncio
import json
import logging

from app.budget.manager import BudgetManager
from app.budget.token_counter import TokenCounter
from app.core.agent_session import AgentSession
from app.core.result_assembler import ResultAssembler
from app.pipeline.response_parser import V1ResponseParser
from app.validators.schema_validator import SchemaValidator
from app.agent_runtime.context import get_request_id
from app.agent_runtime.errors import BudgetExhaustedError, LlmHttpError, LlmTimeoutError, S3Error, StrictJsonContractError
from app.agent_runtime.llm.caller import LlmCaller
from app.agent_runtime.llm.generation_policy import STRICT_JSON_REPAIR, THINKING_GENERAL, controls_from_constraints
from app.agent_runtime.llm.message_manager import MessageManager
from app.agent_runtime.llm.turn_summarizer import TurnSummarizer
from app.agent_runtime.observability import agent_log
from app.agent_runtime.policy.retry import RetryPolicy
from app.agent_runtime.schemas.agent import LlmResponse
from app.agent_runtime.tools.tool_intent import (
    ToolIntentError,
    available_tool_names,
    build_tool_intent_messages,
    parse_tool_intent,
    tool_intent_to_request,
)
from app.policy.termination import TerminationPolicy
from app.runtime.request_summary import request_summary_tracker
from app.schemas.response import TaskFailureResponse, TaskSuccessResponse
from app.agent_runtime.tools.registry import ToolRegistry
from app.tools.router import ToolRouter
from app.state_machine.outcomes import outcome_for_deficiency
from app.state_machine.recovery_triage import recovery_trace
from app.state_machine.types import DeficiencyClass
from app.state_machine.types import DependencyState
from app.types import FailureCode, TaskStatus

logger = logging.getLogger(__name__)

# 메시지 토큰 추정치가 이 값을 초과하면 컨텍스트 압축 실행
_COMPACT_TOKEN_THRESHOLD = 16_000
_COMPACT_KEEP_LAST_N = 4
_RETRIEVAL_REF_PREFIXES = (
    "eref-knowledge-",
    "eref-caller-",
    "eref-callee-",
    "eref-file-",
    "eref-codesearch-",
    "eref-metadata-",
    "eref-mock-",
)
_GROUNDING_UNCERTAINTY_MARKERS = (
    "exploitability is plausible but not fully confirmed",
    "low-confidence",
    "low_confidence_claim_present",
    "추가 확인",
    "추가 검증",
    "불확실",
    "가능성",
    "plausible",
    "not fully confirmed",
)
_TOOL_INTENT_STALL_SECONDS = 45.0


def _budget_snapshot(session: AgentSession) -> dict:
    b = session.budget
    return {
        "steps": b.total_steps,
        "tokens": b.total_completion_tokens,
        "cheap": b.cheap_calls,
        "medium": b.medium_calls,
        "expensive": b.expensive_calls,
    }


def _collect_response_refs(parsed: dict) -> set[str]:
    refs = set(parsed.get("usedEvidenceRefs", []) or [])
    for claim in parsed.get("claims", []) or []:
        if isinstance(claim, dict):
            refs.update(claim.get("supportingEvidenceRefs", []) or [])
    return {ref for ref in refs if isinstance(ref, str)}


def _collect_trace_retrieval_refs(session: AgentSession) -> set[str]:
    refs: set[str] = set()
    for step in session.trace:
        for ref in step.new_evidence_refs:
            if isinstance(ref, str) and ref.startswith(_RETRIEVAL_REF_PREFIXES):
                refs.add(ref)
    return refs


def _content_has_uncertainty_markers(final_content: str, parsed: dict) -> bool:
    haystack = " ".join([
        final_content,
        parsed.get("summary", ""),
        " ".join(parsed.get("caveats", []) or []),
        " ".join(parsed.get("policyFlags", []) or []),
        " ".join(
            str(claim.get("detail", ""))
            for claim in parsed.get("claims", []) or []
            if isinstance(claim, dict)
        ),
    ]).lower()
    return any(marker in haystack for marker in _GROUNDING_UNCERTAINTY_MARKERS)


def _should_request_extra_grounding_lookup(
    *,
    final_content: str,
    parsed: dict | None,
    session: AgentSession,
    current_tools_available: bool,
    force_report: bool,
    grounding_nudge_used: bool,
) -> bool:
    if grounding_nudge_used or force_report or not current_tools_available:
        return False
    if session.budget.total_completion_tokens >= session.budget.max_completion_tokens:
        return False
    if session.budget.total_steps >= session.budget.max_steps:
        return False
    if session.total_tool_calls() == 0 or parsed is None:
        return False

    response_refs = _collect_response_refs(parsed)
    if not response_refs:
        return False

    trace_retrieval_refs = _collect_trace_retrieval_refs(session)
    no_new_retrieval_refs = not bool(response_refs & trace_retrieval_refs)
    has_uncertainty_markers = _content_has_uncertainty_markers(final_content, parsed)
    return has_uncertainty_markers or no_new_retrieval_refs


def _schema_repair_detail(parsed: dict, task_type) -> str | None:
    """Return schema errors that should trigger strict repair."""
    validation = SchemaValidator().validate(parsed, task_type)
    if validation.valid:
        return None
    return "; ".join(validation.errors)


def _has_successful_tool_calls(session: AgentSession) -> bool:
    return any(step.success for step in session.trace)


def _has_local_analysis_evidence(session: AgentSession) -> bool:
    return any(
        entry.can_support_claim and entry.category in {"sast", "source", "caller", "callee"}
        for entry in session.evidence_catalog.entries()
    )


def _tool_choice_for_turn(
    *,
    session: AgentSession,
    current_tools: list[dict] | None,
    force_report: bool,
) -> str:
    # P10 intent remains: before evidence is acquired, do not let the model
    # silently finalize. The enforcement mechanism is now ToolIntent runtime
    # dispatch, not vLLM `tool_choice="required"`; required+thinking is a known
    # Qwen/vLLM failure path (rootcause-20260503).
    return "auto"


def _requires_tool_intent_dispatch(
    *,
    session: AgentSession,
    current_tools: list[dict] | None,
    force_report: bool,
) -> bool:
    return bool(current_tools) and not force_report and not _has_successful_tool_calls(session)


class AgentLoop:
    """멀티 턴 에이전트 루프를 실행한다."""

    def __init__(
        self,
        llm_caller: LlmCaller,
        message_manager: MessageManager,
        tool_registry: ToolRegistry,
        tool_router: ToolRouter,
        termination_policy: TerminationPolicy,
        budget_manager: BudgetManager,
        token_counter: TokenCounter,
        result_assembler: ResultAssembler,
        turn_summarizer: TurnSummarizer,
        retry_policy: RetryPolicy,
    ) -> None:
        self._llm_caller = llm_caller
        self._message_manager = message_manager
        self._tool_registry = tool_registry
        self._tool_router = tool_router
        self._termination_policy = termination_policy
        self._budget_manager = budget_manager
        self._token_counter = token_counter
        self._result_assembler = result_assembler
        self._turn_summarizer = turn_summarizer
        self._retry_policy = retry_policy

    async def run(self, session: AgentSession) -> TaskSuccessResponse | TaskFailureResponse:
        """에이전트 루프를 종료 조건까지 실행한다."""
        tools_schema = self._tool_registry.get_all_schemas() or None
        tool_count = len(tools_schema) if tools_schema else 0

        agent_log(
            logger, "에이전트 세션 시작",
            component="agent_loop", phase="session_start",
            taskId=session.request.taskId, toolCount=tool_count,
            budget={"max_steps": session.budget.max_steps,
                    "max_tokens": session.budget.max_completion_tokens},
        )

        # Live Qwen thinking turns can take minutes. Keep Phase 2 bounded enough
        # for the certificate-maker E2E's 1200s deep-analyze client deadline
        # while still allowing initial graph/source/knowledge acquisition.
        _FORCE_REPORT_AFTER_TOOLS = 4  # 도구 4회 호출 후 보고서 강제
        _WARN_BEFORE_FORCE = 3        # 도구 3회 도달 시 사전 경고
        force_report = False
        warned_approaching_limit = False
        structured_retry_used = False
        schema_repair_used = False
        grounding_nudge_used = False
        response_parser = V1ResponseParser()

        while not self._termination_policy.should_stop(session):
            turn = session.turn_count + 1

            # 도구 예산: 예산 남은 tier의 도구만 제공, force_report 시 전부 제거
            if force_report:
                current_tools = None
            else:
                current_tools = self._tool_registry.get_available_schemas(self._budget_manager)

            # 도구 상한 직전 → 사전 경고 (자발적 전환 유도)
            if (not warned_approaching_limit
                    and not force_report
                    and session.total_tool_calls() >= _WARN_BEFORE_FORCE):
                warned_approaching_limit = True
                remaining = _FORCE_REPORT_AFTER_TOOLS - session.total_tool_calls()
                self._message_manager.add_user_message(
                    f"[시스템] 도구 호출 잔여 횟수: {remaining}회. "
                    "충분한 증거가 모였으면 JSON 보고서를 작성하라. "
                    "리마인더: 존재하지 않는 refId를 만들지 마라. "
                    "코드를 확인하지 않은 경로에 claim을 작성하지 마라. "
                    "비밀 정보는 마스킹하라. 순수 JSON만 출력하라."
                )
                agent_log(
                    logger, "도구 예산 사전 경고",
                    component="agent_loop", phase="tool_budget_warn",
                    turn=turn, remaining=remaining,
                )

            # 도구 호출 횟수 상한 도달 → 보고서 강제 지시
            if not force_report and session.total_tool_calls() >= _FORCE_REPORT_AFTER_TOOLS:
                force_report = True
                current_tools = None
                self._message_manager.add_user_message(
                    "[시스템] 도구 호출 한도 도달. "
                    "추가 도구 호출 없이 즉시 JSON 보고서를 출력하십시오."
                )
                agent_log(
                    logger, "보고서 작성 지시 메시지 주입",
                    component="agent_loop", phase="force_report",
                    turn=turn, totalToolCalls=session.total_tool_calls(),
                )

            agent_log(
                logger, "턴 시작",
                component="agent_loop", phase="turn_start",
                turn=turn, budget=_budget_snapshot(session),
                toolsAvailable=current_tools is not None,
            )

            # LLM 호출 (재시도 포함)
            try:
                if _requires_tool_intent_dispatch(
                    session=session,
                    current_tools=current_tools,
                    force_report=force_report,
                ):
                    response = await self._call_tool_intent_with_retry(session, current_tools)
                else:
                    response = await self._call_with_retry(
                        session,
                        current_tools,
                        tool_choice=_tool_choice_for_turn(
                            session=session,
                            current_tools=current_tools,
                            force_report=force_report,
                        ),
                    )
            except S3Error as e:
                logger.error("LLM 호출 실패 (재시도 소진): %s", e)
                if isinstance(e, LlmTimeoutError):
                    return self._result_assembler.build_failure(
                        session,
                        TaskStatus.TIMEOUT,
                        FailureCode.TIMEOUT,
                        str(e),
                        retryable=e.retryable,
                    )
                if isinstance(e, StrictJsonContractError):
                    outcome = outcome_for_deficiency(DeficiencyClass.STRICT_JSON_VIOLATION)
                    return self._result_assembler.build_completed_outcome(
                        session,
                        summary="S3 검토는 완료되었지만 S7 strict JSON 계약을 만족하는 최종 Assessment를 확정하지 못해 inconclusive로 분류했습니다.",
                        analysis_outcome=outcome.analysis_outcome,
                        quality_outcome=outcome.quality_outcome,
                        poc_outcome=outcome.poc_outcome,
                        caveats=[f"Strict JSON contract violation: {e.error_detail or e}"],
                        policy_flags=["recovery_classified", "strict_json_deficient"],
                        recovery_trace=[recovery_trace(
                            deficiency="LLM_OUTPUT_DEFICIENT",
                            action="strict_json_contract_recovery",
                            outcome="inconclusive",
                            detail=str(e),
                            deficiency_class=DeficiencyClass.STRICT_JSON_VIOLATION,
                            dependency_state=DependencyState.OUTPUT_DEFICIENT,
                        )],
                        termination_reason="strict_json_contract_recovered",
                    )
                if getattr(e, "code", "") == "INPUT_TOO_LARGE":
                    return self._result_assembler.build_failure(
                        session,
                        TaskStatus.VALIDATION_FAILED,
                        FailureCode.INPUT_TOO_LARGE,
                        str(e),
                        retryable=e.retryable,
                    )
                if getattr(e, "code", "") == "LLM_UNAVAILABLE":
                    return self._result_assembler.build_failure(
                        session,
                        TaskStatus.MODEL_ERROR,
                        FailureCode.MODEL_UNAVAILABLE,
                        str(e),
                        retryable=e.retryable,
                    )
                # 도구 결과가 이미 축적되어 있으면 부분 결과 시도
                if session.total_tool_calls() > 0:
                    agent_log(
                        logger, "LLM 실패 — 부분 결과로 대체 시도",
                        component="agent_loop", phase="partial_result_fallback",
                        turn=turn, toolCallsSoFar=session.total_tool_calls(),
                        errorCode=e.code,
                    )
                    if _has_local_analysis_evidence(session):
                        return self._result_assembler.build_from_available_evidence(
                            session,
                            deficiency_detail=str(e),
                            termination_reason=f"llm_failure_partial_local_evidence:{e.code}",
                        )
                    session.set_termination_reason(f"llm_failure_partial:{e.code}")
                    return self._result_assembler.build_from_exhaustion(session)
                if _has_local_analysis_evidence(session):
                    return self._result_assembler.build_from_available_evidence(
                        session,
                        deficiency_detail=str(e),
                        termination_reason=f"llm_failure_local_evidence:{e.code}",
                    )
                outcome = outcome_for_deficiency(DeficiencyClass.MALFORMED_LLM_OUTPUT)
                return self._result_assembler.build_completed_outcome(
                    session,
                    summary="S3 검토는 완료되었지만 LLM 호출이 정상 Assessment를 반환하지 못해 inconclusive로 분류했습니다.",
                    analysis_outcome=outcome.analysis_outcome,
                    quality_outcome=outcome.quality_outcome,
                    poc_outcome=outcome.poc_outcome,
                    caveats=[f"LLM output/call deficiency: {e}"],
                    policy_flags=["recovery_classified", "llm_output_deficient"],
                    recovery_trace=[recovery_trace(
                        deficiency="LLM_OUTPUT_DEFICIENT",
                        action="llm_call_recovered",
                        outcome="inconclusive",
                        detail=str(e),
                        deficiency_class=DeficiencyClass.MALFORMED_LLM_OUTPUT,
                        dependency_state=DependencyState.OUTPUT_DEFICIENT,
                    )],
                    termination_reason="llm_call_recovered",
                )

            # 토큰 기록
            self._token_counter.record(response, session)

            # 분기: tool_call vs content
            if response.has_tool_calls():
                agent_log(
                    logger, "턴 분기: tool_calls",
                    component="agent_loop", phase="turn_branch",
                    turn=turn, responseType="tool_calls",
                    toolCallCount=len(response.tool_calls),
                )
                self._message_manager.add_assistant_tool_calls(response.tool_calls)
                results = await self._tool_router.execute(response.tool_calls, session)
                by_call_id = {call.id: call for call in response.tool_calls}
                # 도구가 생성한 evidence ref ID를 tool result에 주입 → LLM이 정확한 refId를 볼 수 있게 함
                for r in results:
                    call = by_call_id.get(r.tool_call_id)
                    if call:
                        session.evidence_catalog.ingest_tool_result(call, r)
                        session.extra_allowed_refs.update(session.evidence_catalog.ref_ids())
                    if r.success and r.new_evidence_refs:
                        ref_list = ", ".join(f"`{ref}`" for ref in r.new_evidence_refs)
                        r.content += f"\n\n[Evidence Refs: {ref_list}]"
                self._message_manager.add_tool_results(results)
                session.record_tool_turn(response, results)

                # Plan-before-act 넛지: 첫 턴에서 계획 없이 도구부터 호출 시 다음 턴에 계획 요청
                if session.turn_count == 1:
                    self._message_manager.add_user_message(
                        "[시스템] 다음 도구 호출 전에 남은 findings 분석 계획을 우선순위와 함께 기술하라. "
                        "어떤 finding을 어떤 도구로 분석할 것인지 명시하라."
                    )

                agent_log(
                    logger, "턴 종료",
                    component="agent_loop", phase="turn_end",
                    turn=turn,
                    promptTokens=response.prompt_tokens,
                    completionTokens=response.completion_tokens,
                )
                request_summary_tracker.mark_phase_advancing(
                    get_request_id() or session.request.taskId,
                    source="tool-complete",
                )
            else:
                agent_log(
                    logger, "턴 분기: content",
                    component="agent_loop", phase="turn_branch",
                    turn=turn, responseType="content",
                )

                final_content = response.content or ""
                if not final_content.strip():
                    session.record_content_turn(response)
                    agent_log(
                        logger, "턴 종료",
                        component="agent_loop", phase="turn_end",
                        turn=turn,
                        promptTokens=response.prompt_tokens,
                        completionTokens=response.completion_tokens,
                    )
                    request_summary_tracker.mark_phase_advancing(
                        get_request_id() or session.request.taskId,
                        source="turn-complete-empty",
                    )
                    agent_log(
                        logger, "LLM이 빈 응답 반환 — outcome 분류",
                        component="agent_loop", phase="empty_response",
                        turn=turn, level=logging.WARNING,
                    )
                    outcome = outcome_for_deficiency(DeficiencyClass.EMPTY_LLM_OUTPUT)
                    return self._result_assembler.build_completed_outcome(
                        session,
                        summary="S3 검토는 완료되었지만 LLM이 빈 최종 응답을 반환해 accepted claim을 확정하지 못했습니다.",
                        analysis_outcome=outcome.analysis_outcome,
                        quality_outcome=outcome.quality_outcome,
                        poc_outcome=outcome.poc_outcome,
                        caveats=["LLM returned neither tool_calls nor non-empty content."],
                        policy_flags=["recovery_classified", "empty_llm_output"],
                        recovery_trace=[recovery_trace(
                            deficiency="LLM_OUTPUT_DEFICIENT",
                            action="empty_output_recovery",
                            outcome="inconclusive",
                            detail="LLM returned empty content without tool calls.",
                            deficiency_class=DeficiencyClass.EMPTY_LLM_OUTPUT,
                            dependency_state=DependencyState.OUTPUT_DEFICIENT,
                        )],
                        termination_reason="empty_llm_output_recovered",
                    )

                parsed_content = response_parser.parse(final_content)

                if parsed_content is None and not structured_retry_used:
                    structured_retry_used = True
                    session.record_recovery_turn(response)
                    self._message_manager.add_assistant_content(final_content)
                    self._message_manager.add_user_message(
                        "[시스템] 방금 응답은 최종 Assessment JSON이 아니었습니다. "
                        "이전 분석 내용을 유지하되, 이제 반드시 최종 보고서 JSON만 출력하십시오. "
                        "계획/메모/설명문 없이 첫 문자가 `{`인 순수 JSON 객체로만 응답하십시오. "
                        "만약 claims를 빈 배열로 둘 경우, 주요 고위험 finding을 왜 dismiss했는지 caveats에 구체적으로 설명하십시오."
                    )
                    agent_log(
                        logger, "구조화 출력 재시도 요청",
                        component="agent_loop", phase="structured_retry",
                        turn=turn, level=logging.WARNING,
                    )
                    request_summary_tracker.mark_phase_advancing(
                        get_request_id() or session.request.taskId,
                        source="structured-retry-scheduled",
                    )
                    continue
                if parsed_content is None and structured_retry_used:
                    session.record_recovery_turn(response)
                    try:
                        finalizer_response = await self._call_structured_finalizer(session, final_content)
                    except S3Error as e:
                        outcome = outcome_for_deficiency(DeficiencyClass.MALFORMED_LLM_OUTPUT)
                        return self._result_assembler.build_completed_outcome(
                            session,
                            summary="S3 검토는 완료되었지만 structured finalizer가 유효한 Assessment를 확정하지 못해 inconclusive로 분류했습니다.",
                            analysis_outcome=outcome.analysis_outcome,
                            quality_outcome=outcome.quality_outcome,
                            poc_outcome=outcome.poc_outcome,
                            caveats=[f"Structured finalizer failed: {e}"],
                            policy_flags=["recovery_classified", "strict_json_deficient"],
                            recovery_trace=[recovery_trace(
                                deficiency="LLM_OUTPUT_DEFICIENT",
                                action="structured_finalizer_recovery",
                                outcome="inconclusive",
                                detail=str(e),
                                deficiency_class=DeficiencyClass.MALFORMED_LLM_OUTPUT,
                                dependency_state=DependencyState.OUTPUT_DEFICIENT,
                            )],
                            termination_reason="structured_finalizer_recovered",
                        )

                    self._token_counter.record(finalizer_response, session)
                    session.record_content_turn(finalizer_response)
                    finalizer_content = finalizer_response.content or ""
                    agent_log(
                        logger,
                        "구조화 최종화 응답 수신",
                        component="agent_loop",
                        phase="structured_finalizer_response",
                        turn=session.turn_count,
                        hasContent=bool(finalizer_content.strip()),
                        level=logging.WARNING,
                    )

                    result = self._result_assembler.build(finalizer_content, session)
                    request_summary_tracker.mark_phase_advancing(
                        get_request_id() or session.request.taskId,
                        source="result-assembled-finalizer",
                    )
                    agent_log(
                        logger, "세션 종료",
                        component="agent_loop", phase="session_end",
                        totalTurns=session.turn_count,
                        totalPromptTokens=session.total_prompt_tokens(),
                        totalCompletionTokens=session.total_completion_tokens(),
                        terminationReason="content_returned_structured_finalizer",
                        latencyMs=session.elapsed_ms(),
                    )
                    return result

                schema_repair_detail = (
                    _schema_repair_detail(parsed_content, session.request.taskType)
                    if parsed_content is not None
                    else None
                )
                if schema_repair_detail and not schema_repair_used:
                    schema_repair_used = True
                    session.record_recovery_turn(response)
                    self._message_manager.add_assistant_content(final_content)
                    repair_input = (
                        "The previous response was valid JSON but failed the Assessment schema. "
                        "Repair it into one valid Assessment JSON object.\n\n"
                        f"Schema errors: {schema_repair_detail}\n\n"
                        "Invalid JSON content:\n"
                        f"{final_content}"
                    )
                    try:
                        finalizer_response = await self._call_structured_finalizer(session, repair_input)
                    except S3Error as e:
                        outcome = outcome_for_deficiency(DeficiencyClass.SCHEMA)
                        return self._result_assembler.build_completed_outcome(
                            session,
                            summary="S3 검토는 완료되었지만 structured schema repair가 유효한 Assessment를 확정하지 못해 inconclusive로 분류했습니다.",
                            analysis_outcome=outcome.analysis_outcome,
                            quality_outcome=outcome.quality_outcome,
                            poc_outcome=outcome.poc_outcome,
                            caveats=[f"Structured schema repair failed: {e}"],
                            policy_flags=["recovery_classified", "schema_deficient", "strict_json_deficient"],
                            recovery_trace=[recovery_trace(
                                deficiency="SCHEMA_DEFICIENT",
                                action="structured_schema_repair_recovery",
                                outcome="inconclusive",
                                detail=str(e),
                                deficiency_class=DeficiencyClass.SCHEMA,
                                dependency_state=DependencyState.OUTPUT_DEFICIENT,
                            )],
                            termination_reason="structured_schema_repair_recovered",
                        )

                    self._token_counter.record(finalizer_response, session)
                    session.record_content_turn(finalizer_response)
                    finalizer_content = finalizer_response.content or ""
                    agent_log(
                        logger,
                        "구조화 schema repair 응답 수신",
                        component="agent_loop",
                        phase="structured_schema_repair_response",
                        turn=session.turn_count,
                        schemaErrors=schema_repair_detail,
                        hasContent=bool(finalizer_content.strip()),
                        level=logging.WARNING,
                    )

                    result = self._result_assembler.build(finalizer_content, session)
                    request_summary_tracker.mark_phase_advancing(
                        get_request_id() or session.request.taskId,
                        source="result-assembled-schema-repair",
                    )
                    agent_log(
                        logger, "세션 종료",
                        component="agent_loop", phase="session_end",
                        totalTurns=session.turn_count,
                        totalPromptTokens=session.total_prompt_tokens(),
                        totalCompletionTokens=session.total_completion_tokens(),
                        terminationReason="content_returned_structured_schema_repair",
                        latencyMs=session.elapsed_ms(),
                    )
                    return result

                if _should_request_extra_grounding_lookup(
                    final_content=final_content,
                    parsed=parsed_content,
                    session=session,
                    current_tools_available=current_tools is not None,
                    force_report=force_report,
                    grounding_nudge_used=grounding_nudge_used,
                ):
                    grounding_nudge_used = True
                    session.record_recovery_turn(response)
                    self._message_manager.add_assistant_content(final_content)
                    self._message_manager.add_user_message(
                        "[시스템] 방금 최종 보고서는 CWE/CVE 또는 exploitability grounding이 아직 약해 보입니다. "
                        "도구가 아직 사용 가능하므로 최종 JSON을 확정하기 전에 "
                        "`knowledge.search`, `code_graph.callers`, `code_graph.callees`, `code_graph.search`, `code.read_file` 중 하나로 "
                        "한 번 더 근거를 보강하십시오. "
                        "`build.metadata`는 이 grounding 보강 경로에 사용하지 마십시오. "
                        "추가 조회 후 최종 보고서 JSON만 다시 출력하십시오."
                    )
                    agent_log(
                        logger, "grounding 보강용 one-shot nudge 주입",
                        component="agent_loop", phase="grounding_nudge",
                        turn=turn, level=logging.WARNING,
                    )
                    request_summary_tracker.mark_phase_advancing(
                        get_request_id() or session.request.taskId,
                        source="grounding-nudge-scheduled",
                    )
                    continue

                session.record_content_turn(response)
                agent_log(
                    logger, "턴 종료",
                    component="agent_loop", phase="turn_end",
                    turn=turn,
                    promptTokens=response.prompt_tokens,
                    completionTokens=response.completion_tokens,
                )
                result = self._result_assembler.build(final_content, session)
                request_summary_tracker.mark_phase_advancing(
                    get_request_id() or session.request.taskId,
                    source="result-assembled",
                )

                agent_log(
                    logger, "세션 종료",
                    component="agent_loop", phase="session_end",
                    totalTurns=session.turn_count,
                    totalPromptTokens=session.total_prompt_tokens(),
                    totalCompletionTokens=session.total_completion_tokens(),
                    terminationReason="content_returned",
                    latencyMs=session.elapsed_ms(),
                )
                return result

        # 종료 정책에 의한 종료
        agent_log(
            logger, "세션 종료",
            component="agent_loop", phase="session_end",
            totalTurns=session.turn_count,
            totalPromptTokens=session.total_prompt_tokens(),
            totalCompletionTokens=session.total_completion_tokens(),
            terminationReason=session.termination_reason,
            latencyMs=session.elapsed_ms(),
        )
        return self._result_assembler.build_from_exhaustion(session)

    async def _messages_after_compaction(self, session) -> list[dict]:
        # 컨텍스트 압축: 토큰 추정치 초과 시 오래된 턴 제거
        token_est = self._message_manager.get_token_estimate()
        if token_est > _COMPACT_TOKEN_THRESHOLD:
            removed = await self._message_manager.compact(
                self._turn_summarizer, keep_last_n=_COMPACT_KEEP_LAST_N,
                state_summary=session.analysis_state_summary(),
            )
            if removed > 0:
                agent_log(
                    logger, "컨텍스트 압축",
                    component="agent_loop", phase="context_compact",
                    turn=session.turn_count + 1,
                    tokensBefore=token_est,
                    tokensAfter=self._message_manager.get_token_estimate(),
                    messagesRemoved=removed,
                )

        return self._message_manager.get_messages()

    async def _call_with_retry(self, session, tools_schema, *, tool_choice: str = "auto"):
        """LLM 호출 + 재시도."""
        messages = await self._messages_after_compaction(session)
        turn = session.turn_count + 1
        last_error = None

        for attempt in range(1 + self._retry_policy._max_retries):
            try:
                request_summary_tracker.mark_transport_only(
                    get_request_id() or session.request.taskId,
                    source="llm-inference",
                )
                return await self._llm_caller.call(
                    messages,
                    session,
                    tools=tools_schema,
                    tool_choice=tool_choice,
                    generation=controls_from_constraints(THINKING_GENERAL, session.request.constraints),
                    prefer_async_ownership=tools_schema is None,
                )
            except S3Error as e:
                last_error = e
                if self._retry_policy.should_retry(e, attempt):
                    delay = self._retry_policy.get_delay_seconds(e, attempt)
                    agent_log(
                        logger, "LLM 재시도",
                        component="llm_caller", phase="llm_retry",
                        turn=turn, attempt=attempt + 1,
                        errorCode=type(e).__name__,
                        delaySeconds=delay,
                        level=logging.WARNING,
                    )
                    await asyncio.sleep(delay)
                    continue
                raise

        raise last_error  # type: ignore[misc]

    async def _call_tool_intent_with_retry(self, session, tools_schema) -> LlmResponse:
        """Plan one mandatory acquisition tool via JSON ToolIntent and dispatch it locally."""
        base_messages = await self._messages_after_compaction(session)
        messages = build_tool_intent_messages(base_messages, tools_schema)
        names = available_tool_names(tools_schema)
        turn = session.turn_count + 1
        last_error: ToolIntentError | None = None

        for attempt in range(1 + self._retry_policy._max_retries):
            request_summary_tracker.mark_transport_only(
                get_request_id() or session.request.taskId,
                source="tool-intent-inference",
            )
            try:
                planner_response = await asyncio.wait_for(
                    self._llm_caller.call(
                        messages,
                        session,
                        tools=None,
                        generation=controls_from_constraints(STRICT_JSON_REPAIR, session.request.constraints),
                        prefer_async_ownership=True,
                    ),
                    timeout=_TOOL_INTENT_STALL_SECONDS,
                )
            except asyncio.TimeoutError as exc:
                raise LlmHttpError(
                    502,
                    f"tool_intent_planning_stalled_after_{_TOOL_INTENT_STALL_SECONDS:.0f}s",
                ) from exc
            # Unit tests and future compatibility shims may still inject already
            # parsed tool calls or final content. Real ToolIntent calls pass
            # tools=None, so live vLLM cannot produce OpenAI tool_calls here, but
            # preserving this fallback keeps the runtime loop backward-compatible.
            if planner_response.has_tool_calls():
                return planner_response
            try:
                intent = parse_tool_intent(planner_response.content, available_tool_names=names)
                tool_call = tool_intent_to_request(intent, turn=turn)
                agent_log(
                    logger, "ToolIntent 디스패치 준비",
                    component="agent_loop", phase="tool_intent_dispatch",
                    turn=turn, tool=tool_call.name,
                )
                return LlmResponse(
                    tool_calls=[tool_call],
                    finish_reason="tool_intent",
                    prompt_tokens=planner_response.prompt_tokens,
                    completion_tokens=planner_response.completion_tokens,
                )
            except ToolIntentError as e:
                last_error = e
                if planner_response.content is not None:
                    return planner_response
                if attempt < self._retry_policy._max_retries:
                    messages = [
                        *messages,
                        {"role": "assistant", "content": planner_response.content or ""},
                        {
                            "role": "user",
                            "content": (
                                "The previous ToolIntent was invalid: "
                                f"{e}. Return one valid ToolIntent JSON object now."
                            ),
                        },
                    ]
                    continue
                break

        raise LlmHttpError(502, f"Invalid ToolIntent response: {last_error}")

    async def _call_structured_finalizer(self, session: AgentSession, non_json_content: str):
        """Ask S7 for a strict final Assessment JSON with tools disabled."""
        remaining_completion_tokens = (
            session.budget.max_completion_tokens - session.budget.total_completion_tokens
        )
        if remaining_completion_tokens < 512:
            raise BudgetExhaustedError(
                "structured finalizer skipped: remaining completion-token budget below useful minimum"
            )
        finalizer_max_tokens = min(remaining_completion_tokens, 6000)
        refs = _allowed_finalizer_refs(session)
        ref_lines = "\n".join(f"- `{ref}`" for ref in refs[:40]) or "- (no refs available)"
        state = session.analysis_state_summary()
        trusted = session.request.context.trusted if isinstance(session.request.context.trusted, dict) else {}
        objective = trusted.get("objective") or trusted.get("task") or "security assessment"
        system = (
            "You are the AEGIS structured-output finalizer. "
            "Convert the prior analysis notes into one valid Assessment JSON object. "
            "Do not add prose, markdown fences, or comments. The first character must be `{`.\n\n"
            "Required top-level fields: summary, claims, caveats, usedEvidenceRefs, "
            "suggestedSeverity, needsHumanReview, recommendedNextSteps, policyFlags.\n"
            "Never omit caveats or usedEvidenceRefs; output [] when there is no content for them.\n"
            "Each claim must be an object with statement, detail, supportingEvidenceRefs, and location.\n"
            "Use only project-local evidence refs listed by the user. Knowledge/CWE refs are contextual "
            "background and must not be used in usedEvidenceRefs or claims[].supportingEvidenceRefs. "
            "If a claim cannot be grounded in project-local refs, "
            "do not include that claim; put the limitation in caveats instead.\n"
            "If no grounded claims remain, output claims: [] with explicit caveats and needsHumanReview: true.\n"
        )
        user = (
            f"Objective: {objective}\n\n"
            "Allowed evidence refs:\n"
            f"{ref_lines}\n\n"
            "Session state summary:\n"
            f"{json.dumps(state, ensure_ascii=False)}\n\n"
            "Prior non-JSON content to convert/summarize:\n"
            f"{non_json_content[:6000]}\n\n"
            "Return only a JSON object matching this shape:\n"
            "{"
            "\"summary\":\"...\","
            "\"claims\":[{\"statement\":\"...\",\"detail\":\"...\",\"supportingEvidenceRefs\":[\"eref-...\"],\"location\":\"file:line\"}],"
            "\"caveats\":[\"...\"],"
            "\"usedEvidenceRefs\":[\"eref-...\"],"
            "\"suggestedSeverity\":\"critical|high|medium|low|info\","
            "\"needsHumanReview\":true,"
            "\"recommendedNextSteps\":[\"...\"],"
            "\"policyFlags\":[\"structured_finalizer\"]"
            "}"
        )
        agent_log(
            logger,
            "구조화 최종화 호출",
            component="agent_loop",
            phase="structured_finalizer_request",
            refCount=len(refs),
            remainingCompletionTokens=remaining_completion_tokens,
            maxTokens=finalizer_max_tokens,
            level=logging.WARNING,
        )
        request_summary_tracker.mark_transport_only(
            get_request_id() or session.request.taskId,
            source="structured-finalizer",
        )
        return await self._llm_caller.call(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            session,
            tools=None,
            max_tokens=finalizer_max_tokens,
            # P7/§4.9: structured finalization is schema-enforced narrowing over
            # prior notes, so use the strict repair tuple unless explicitly overridden.
            generation=controls_from_constraints(STRICT_JSON_REPAIR, session.request.constraints),
            prefer_async_ownership=True,
        )


def _allowed_finalizer_refs(session: AgentSession) -> list[str]:
    refs: list[str] = []
    refs.extend(ref.refId for ref in session.request.evidenceRefs)
    refs.extend(sorted(session.extra_allowed_refs))
    refs.extend(session.evidence_catalog.ref_ids())
    refs.extend(ref for step in session.trace for ref in step.new_evidence_refs)
    return [
        ref for ref in dict.fromkeys(refs)
        if isinstance(ref, str) and ref and not ref.startswith("eref-knowledge-")
    ]
