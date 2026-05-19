"""AgentLoop — 에이전트 메인 루프. 분기 판단(tool_call vs content)은 여기서."""

from __future__ import annotations

import asyncio
import json
import logging

from app.budget.manager import BudgetManager
from app.budget.token_counter import TokenCounter
from app.core.agent_session import AgentSession
from app.core.result_assembler import ResultAssembler
from app.agent_runtime.errors import LlmHttpError, LlmTimeoutError, S3Error, StrictJsonContractError
from app.agent_runtime.llm.caller import LlmCaller
from app.agent_runtime.llm.generation_policy import THINKING_GENERAL, controls_from_constraints
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
from app.schemas.response import TaskFailureResponse, TaskSuccessResponse
from app.agent_runtime.tools.registry import ToolRegistry
from app.tools.router import ToolRouter
from app.types import FailureCode, TaskStatus

logger = logging.getLogger(__name__)

# 메시지 토큰 추정치가 이 값을 초과하면 컨텍스트 압축 실행
_COMPACT_TOKEN_THRESHOLD = 16_000
_COMPACT_KEEP_LAST_N = 4


def _budget_snapshot(session: AgentSession) -> dict:
    b = session.budget
    return {
        "steps": b.total_steps,
        "tokens": b.total_completion_tokens,
        "cheap": b.cheap_calls,
        "medium": b.medium_calls,
        "expensive": b.expensive_calls,
    }


def _output_deficient_build_content(detail: str) -> str:
    return json.dumps({
        "summary": "Build Agent 검토는 완료되었지만 LLM이 유효한 buildResult를 반환하지 못했습니다.",
        "claims": [],
        "caveats": [detail],
        "usedEvidenceRefs": [],
        "needsHumanReview": True,
        "recommendedNextSteps": ["Review audit trace and rerun if a clean build pass is required."],
        "policyFlags": ["state_machine_outcome", "output_deficient"],
        "buildResult": {
            "success": False,
            "buildCommand": "",
            "buildScript": "",
            "buildDir": "build-aegis",
            "errorLog": detail,
            "producedArtifacts": [],
        },
    })


def _has_successful_tool_calls(session: AgentSession) -> bool:
    return any(step.success for step in session.trace)


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
        build_succeeded = False
        force_report = False  # 빌드 성공 또는 연속 실패 시 보고서 강제
        consecutive_build_failures = 0
        max_build_failures = 3

        agent_log(
            logger, "에이전트 세션 시작",
            component="agent_loop", phase="session_start",
            taskId=session.request.taskId, toolCount=tool_count,
            budget={"max_steps": session.budget.max_steps,
                    "max_tokens": session.budget.max_completion_tokens},
        )

        while not self._termination_policy.should_stop(session):
            turn = session.turn_count + 1

            # 빌드 성공/연속 실패/도구 예산 소진 시 → 도구 제거 + 보고서 작성 강제
            if force_report or self._budget_manager.no_callable_tools_remaining():
                current_tools = None
                if force_report:
                    self._message_manager.add_assistant_content(
                        "보고서를 작성합니다."
                    )
                    if build_succeeded:
                        directive = (
                            "빌드가 canonical readiness 조건을 모두 만족해 성공했다. "
                            "더 이상 도구를 호출하지 마라. "
                            "시스템 프롬프트의 출력 형식에 맞는 최종 JSON 보고서를 출력하라. "
                            "buildCommand에 성공한 명령어를, buildScript에 스크립트 경로를 기입하라. "
                            "첫 문자는 반드시 `{`이어야 한다."
                        )
                    else:
                        directive = (
                            f"빌드가 {consecutive_build_failures}회 연속 실패했다. "
                            "더 이상 도구를 호출하지 마라. "
                            "시스템 프롬프트의 출력 형식에 맞는 진단 보고서를 JSON으로 출력하라. "
                            "실패 원인과 필요한 조치(누락 라이브러리, SDK 문제 등)를 summary에 명시하라. "
                            "첫 문자는 반드시 `{`이어야 한다."
                        )
                    self._message_manager.add_user_message(directive)
                    force_report = False  # 메시지 한 번만 주입
                    agent_log(
                        logger, "보고서 작성 지시 메시지 주입",
                        component="agent_loop", phase="force_report",
                        turn=turn, buildSucceeded=build_succeeded,
                        consecutiveFailures=consecutive_build_failures,
                    )
            else:
                current_tools = tools_schema

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
                    return self._result_assembler.build(
                        _output_deficient_build_content(
                            f"LLM strict JSON output deficient: {e.error_detail or e}"
                        ),
                        session,
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
                    session.set_termination_reason(f"llm_failure_partial:{e.code}")
                    return self._result_assembler.build_from_exhaustion(session)
                return self._result_assembler.build(
                    _output_deficient_build_content(f"LLM output/call deficiency: {e}"),
                    session,
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
                self._message_manager.add_tool_results(results)
                session.record_tool_turn(response, results)

                # try_build 결과 감지
                for r in results:
                    if r.name == "try_build":
                        if r.success and "eref-build-success" in r.new_evidence_refs:
                            build_succeeded = True
                            force_report = True
                            consecutive_build_failures = 0
                            agent_log(
                                logger, "try_build 성공 — 보고서 작성 예정",
                                component="agent_loop", phase="build_success_detected",
                                turn=turn,
                            )
                            break
                        elif not r.success:
                            consecutive_build_failures += 1
                            # 빌드 에러 분류 결과를 LLM에 주입 (결정론적 힌트)
                            try:
                                from app.pipeline.build_error_classifier import classify_build_error
                                classifications = classify_build_error(r.content)
                                if classifications:
                                    hints = "\n".join(
                                        f"- [{c.category}] {c.suggestion}"
                                        for c in classifications
                                    )
                                    self._message_manager.add_user_message(
                                        f"[시스템 에러 분류]\n{hints}\n"
                                        "위 분류를 참고하여 빌드 스크립트를 수정하라."
                                    )
                            except Exception:
                                pass  # 분류 실패 시 무시 — LLM이 직접 에러 해석
                            if consecutive_build_failures >= max_build_failures:
                                force_report = True
                                agent_log(
                                    logger, f"try_build {consecutive_build_failures}회 연속 실패 — 진단 보고서 예정",
                                    component="agent_loop", phase="build_failure_threshold",
                                    turn=turn, consecutiveFailures=consecutive_build_failures,
                                )

                agent_log(
                    logger, "턴 종료",
                    component="agent_loop", phase="turn_end",
                    turn=turn,
                    promptTokens=response.prompt_tokens,
                    completionTokens=response.completion_tokens,
                )
            else:
                agent_log(
                    logger, "턴 분기: content",
                    component="agent_loop", phase="turn_branch",
                    turn=turn, responseType="content",
                )
                session.record_content_turn(response)

                agent_log(
                    logger, "턴 종료",
                    component="agent_loop", phase="turn_end",
                    turn=turn,
                    promptTokens=response.prompt_tokens,
                    completionTokens=response.completion_tokens,
                )

                final_content = response.content or ""
                if not final_content.strip():
                    agent_log(
                        logger, "LLM이 빈 응답 반환 — output deficient 처리",
                        component="agent_loop", phase="empty_response",
                        turn=turn, level=logging.WARNING,
                    )
                    return self._result_assembler.build(
                        _output_deficient_build_content("LLM이 유효한 tool_calls도 content도 반환하지 않음"),
                        session,
                    )

                result = self._result_assembler.build(final_content, session)

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
                state_summary=session.build_state_summary(),
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
            planner_response = await self._llm_caller.call(
                messages,
                session,
                tools=None,
                generation=controls_from_constraints(THINKING_GENERAL, session.request.constraints),
                prefer_async_ownership=True,
            )
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
