"""AgentLoop 통합 테스트 — mock LlmCaller로 전체 루프 검증."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agent_runtime.errors import StrictJsonContractError
from app.budget.manager import BudgetManager
from app.budget.token_counter import TokenCounter
from app.core.agent_loop import AgentLoop
from app.core.agent_session import AgentSession
from app.core.evidence_catalog import EvidenceCatalogEntry
from app.core.phase_one_types import Phase1Result
from app.core.result_assembler import ResultAssembler
from app.agent_runtime.llm.message_manager import MessageManager
from app.agent_runtime.llm.turn_summarizer import TurnSummarizer
from app.agent_runtime.policy.retry import RetryPolicy
from app.policy.termination import TerminationPolicy
from app.policy.tool_failure import ToolFailurePolicy
from app.agent_runtime.schemas.agent import BudgetState, LlmResponse, ToolCallRequest, ToolCostTier, ToolResult, ToolTraceStep
from app.schemas.request import Context, EvidenceRef, TaskRequest
from app.agent_runtime.tools.executor import ToolExecutor
from app.tools.implementations.mock_tools import MockKnowledgeTool
from app.agent_runtime.tools.registry import ToolRegistry, ToolSchema
from app.tools.router import ToolRouter
from app.types import TaskType


def _make_request(**overrides) -> TaskRequest:
    defaults = dict(
        taskType=TaskType.DEEP_ANALYZE,
        taskId="test-001",
        context=Context(trusted={"findings": [{"ruleId": "CWE-78"}]}),
        evidenceRefs=[
            EvidenceRef(
                refId="eref-001", artifactId="art-1",
                artifactType="source", locatorType="lineRange",
                locator={"file": "main.c", "fromLine": 1, "toLine": 50},
            ),
        ],
    )
    defaults.update(overrides)
    return TaskRequest(**defaults)


def _final_assessment_json(*, include_retrieval_ref: bool = False) -> str:
    used_refs = ["eref-001"]
    if include_retrieval_ref:
        used_refs.append("eref-mock-CWE-78")
    return json.dumps({
        "summary": "CWE-78 OS Command Injection detected",
        "claims": [{
            "statement": "User input flows to popen()",
            "detail": "User input reaches the popen sink through the cited path.",
            "supportingEvidenceRefs": used_refs,
            "location": "main.c:42",
        }],
        "caveats": ["Requires runtime verification"],
        "usedEvidenceRefs": used_refs,
        "suggestedSeverity": "critical",
        "needsHumanReview": True,
        "recommendedNextSteps": ["Replace popen with execve"],
        "policyFlags": [],
    })


def _structured_zero_claim_json() -> str:
    return json.dumps({
        "summary": "검토 결과 actionable claim은 확인되지 않았습니다.",
        "claims": [],
        "caveats": ["style/info finding은 claim으로 승격하지 않았습니다."],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })


def _structured_zero_claim_no_refs_json() -> str:
    return json.dumps({
        "summary": "검토 결과 actionable claim은 확인되지 않았습니다.",
        "claims": [],
        "caveats": ["duplicate retrieval attempt was blocked"],
        "usedEvidenceRefs": [],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })


def _gateway_webserver_plan_text() -> str:
    return (
        "## Phase A: 우선순위 수립\n"
        "1. popen 사용 (clients/http_client.cpp:62) - CWE-78 Command Injection 가능성\n"
        "확인 전략: code_graph.callers 와 code.read_file로 검증\n"
    )


def _gateway_webserver_claim_json() -> str:
    return json.dumps({
        "summary": "gateway-webserver의 외부 입력이 popen으로 이어져 RCE 가능성이 있습니다.",
        "claims": [{
            "statement": "외부 입력이 run_curl/popen 경로로 전달되어 원격 명령 실행(RCE)이 가능합니다.",
            "detail": "clients/http_client.cpp:62의 popen 호출은 외부 URL/escape 입력이 run_curl 경로를 통해 명령 문자열에 반영될 수 있어 command injection과 RCE로 이어질 수 있습니다.",
            "supportingEvidenceRefs": ["eref-001"],
            "location": "clients/http_client.cpp:62",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": ["popen 기반 실행 경로를 제거하고 안전한 API로 대체"],
        "policyFlags": [],
    })


def _malformed_claim_shape_json() -> str:
    return json.dumps({
        "summary": "claim 구조가 깨진 Assessment JSON입니다.",
        "claims": [
            "User input flows to popen(), but this claim was emitted as a string instead of an object."
        ],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })


def _missing_caveats_json() -> str:
    return json.dumps({
        "summary": "required top-level caveats가 누락된 Assessment JSON입니다.",
        "claims": [{
            "statement": "User input flows to popen().",
            "detail": "This JSON is otherwise valid but omits top-level caveats.",
            "supportingEvidenceRefs": ["eref-001"],
            "location": "main.c:42",
        }],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })


def _wrong_collection_types_json() -> str:
    return json.dumps({
        "summary": "collection 타입이 깨진 Assessment JSON입니다.",
        "claims": [{
            "statement": "User input flows to popen().",
            "detail": "supportingEvidenceRefs가 리스트가 아닌 문자열입니다.",
            "supportingEvidenceRefs": "eref-001",
            "location": "main.c:42",
        }],
        "caveats": "none",
        "usedEvidenceRefs": "eref-001",
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })


def _gateway_webserver_low_confidence_json(*, include_retrieval_ref: bool) -> str:
    used_refs = ["eref-001"]
    contextual_refs = ["eref-mock-CWE-36"] if include_retrieval_ref else []
    return json.dumps({
        "summary": "readlink 경로는 추가 검증이 필요하지만 보안상 무시하기엔 이릅니다.",
        "claims": [{
            "statement": "utils/fs.cpp:22의 readlink 사용은 TOCTOU 가능성이 있으나 exploitability closure가 완전히 닫히지 않았습니다.",
            "detail": (
                "Exploitability is plausible but not fully confirmed from the available evidence. "
                "현재 코드 경로는 race-condition 가능성을 보여주지만 실제 공격 전제와 가드 부재는 추가 확인이 필요합니다."
            ),
            "supportingEvidenceRefs": used_refs,
            "location": "utils/fs.cpp:22",
        }],
        "caveats": ["low-confidence claim: guard/validation 및 실제 공격 전제를 추가 검증해야 합니다."],
        "usedEvidenceRefs": used_refs,
        "suggestedSeverity": "medium",
        "needsHumanReview": True,
        "recommendedNextSteps": ["knowledge.search로 CWE/CVE 연결 근거를 보강", "코드 경로를 추가 확인"],
        "policyFlags": ["low_confidence_claim_present"],
        "contextualEvidenceRefs": contextual_refs,
    })


def _build_agent_loop(
    llm_responses: list[LlmResponse],
    budget_overrides: dict | None = None,
) -> tuple[AgentLoop, AgentSession]:
    """mock LlmCaller로 AgentLoop를 구성한다."""
    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(side_effect=llm_responses)

    mm = MessageManager("You are a security analyst.", "Analyze the findings.")

    registry = ToolRegistry()
    registry.register(ToolSchema(
        name="knowledge.search",
        description="Search threat knowledge",
        parameters={"type": "object", "properties": {"query": {"type": "string"}}},
        cost_tier=ToolCostTier.CHEAP,
    ))

    budget = BudgetState(**(budget_overrides or {}))
    bm = BudgetManager(budget)
    executor = ToolExecutor(timeout_ms=5000)
    failure_policy = ToolFailurePolicy()

    router = ToolRouter(registry, executor, bm, failure_policy)
    router.register_implementation("knowledge.search", MockKnowledgeTool())

    session = AgentSession(_make_request(), budget)

    loop = AgentLoop(
        llm_caller=llm_caller,
        message_manager=mm,
        tool_registry=registry,
        tool_router=router,
        termination_policy=TerminationPolicy(timeout_ms=300_000),
        budget_manager=bm,
        token_counter=TokenCounter(),
        result_assembler=ResultAssembler(),
        turn_summarizer=TurnSummarizer(),
        retry_policy=RetryPolicy(max_retries=1),
    )
    return loop, session


def _add_command_injection_supporting_slice(
    session: AgentSession,
    *,
    ref_id: str = "eref-001",
    file: str = "main.c",
    line: int = 42,
    sast_backed: bool = False,
) -> None:
    roles = ["source_location", "source_slice", "sink_or_dangerous_api"]
    if sast_backed:
        roles.append("sast_finding")
    session.evidence_catalog.add(EvidenceCatalogEntry(
        ref_id=ref_id,
        evidence_class="local",
        roles=tuple(roles),
        file=file,
        line=line,
        sink="popen",
        cwe_id="CWE-78",
    ))



@pytest.mark.asyncio
async def test_single_turn_content_only():
    """LLM이 즉시 content를 반환하면 1턴에 종료."""
    responses = [
        LlmResponse(content=_final_assessment_json(), prompt_tokens=100, completion_tokens=50),
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 10, "max_cheap_calls": 6})
    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.summary == "CWE-78 OS Command Injection detected"
    assert session.turn_count == 1


@pytest.mark.asyncio
async def test_two_turn_tool_then_content():
    """Turn 1: tool_call → Turn 2: content."""
    responses = [
        # Turn 1: tool call
        LlmResponse(
            tool_calls=[ToolCallRequest(id="call_1", name="knowledge.search", arguments={"query": "CWE-78"})],
            finish_reason="tool_calls",
            prompt_tokens=100, completion_tokens=30,
        ),
        # Turn 2: final content
        LlmResponse(
                content=json.dumps({
                    "summary": "Tool-backed control case completed without actionable claim.",
                    "claims": [{
                        "statement": "readlink path needs follow-up review.",
                        "detail": "This non-command-injection control claim keeps the tool-turn test focused on loop behavior.",
                        "supportingEvidenceRefs": ["eref-001", "eref-mock-CWE-78"],
                        "location": "utils/fs.cpp:22",
                    }],
                    "caveats": ["knowledge.search was used only as contextual background."],
                "usedEvidenceRefs": ["eref-001", "eref-mock-CWE-78"],
                "suggestedSeverity": "info",
                "needsHumanReview": True,
                "recommendedNextSteps": [],
                "policyFlags": [],
            }),
            prompt_tokens=200, completion_tokens=80,
        ),
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 10, "max_cheap_calls": 6})
    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 2
    assert len(session.trace) >= 1  # at least one tool trace


@pytest.mark.asyncio
async def test_three_turn_scenario():
    """Turn 1: tool → Turn 2: tool → Turn 3: content."""
    responses = [
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c1", name="knowledge.search", arguments={"query": "CWE-78"})],
            finish_reason="tool_calls", prompt_tokens=100, completion_tokens=20,
        ),
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c2", name="knowledge.search", arguments={"query": "CAPEC-88"})],
            finish_reason="tool_calls", prompt_tokens=200, completion_tokens=25,
        ),
        LlmResponse(content=json.dumps({
            "summary": "Tool-backed control case completed without actionable claim.",
            "claims": [{
                "statement": "readlink path needs follow-up review.",
                "detail": "This non-command-injection control claim keeps the tool-turn test focused on loop behavior.",
                "supportingEvidenceRefs": ["eref-001", "eref-mock-CWE-78"],
                "location": "utils/fs.cpp:22",
            }],
            "caveats": ["knowledge.search was used only as contextual background."],
            "usedEvidenceRefs": ["eref-001", "eref-mock-CWE-78", "eref-mock-CAPEC-88"],
            "suggestedSeverity": "info",
            "needsHumanReview": True,
            "recommendedNextSteps": [],
            "policyFlags": [],
        }), prompt_tokens=300, completion_tokens=100),
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 10, "max_cheap_calls": 6})
    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 3


@pytest.mark.asyncio
async def test_multi_turn_planner_dedup_in_agent_loop(caplog):
    duplicate_call = ToolCallRequest(id="c1", name="knowledge.search", arguments={"query": "CWE-78"})
    responses = [
        LlmResponse(
            tool_calls=[duplicate_call],
            finish_reason="tool_calls", prompt_tokens=100, completion_tokens=20,
        ),
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c2", name="knowledge.search", arguments={"query": "CWE-78"})],
            finish_reason="tool_calls", prompt_tokens=110, completion_tokens=20,
        ),
        LlmResponse(content=_structured_zero_claim_no_refs_json(), prompt_tokens=120, completion_tokens=40),
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 10, "max_cheap_calls": 6})

    with caplog.at_level("INFO", logger="app.agent_runtime.tools.router_core"):
        result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 3
    assert session.total_tool_calls() == 1
    assert "중복 tool 호출 차단" in caplog.text


@pytest.mark.asyncio
async def test_duplicate_tool_call_does_not_add_second_evidence_ref():
    responses = [
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c1", name="knowledge.search", arguments={"query": "CWE-78"})],
            finish_reason="tool_calls", prompt_tokens=100, completion_tokens=20,
        ),
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c2", name="knowledge.search", arguments={"query": "CWE-78"})],
            finish_reason="tool_calls", prompt_tokens=110, completion_tokens=20,
        ),
        LlmResponse(content=_structured_zero_claim_no_refs_json(), prompt_tokens=120, completion_tokens=40),
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 10, "max_cheap_calls": 6})

    result = await loop.run(session)

    assert result.status == "completed"
    knowledge_refs = [
        ref
        for step in session.trace
        for ref in step.new_evidence_refs
        if ref.startswith("eref-mock-")
    ]
    assert knowledge_refs == ["eref-mock-CWE-78"]


@pytest.mark.asyncio
async def test_max_steps_exhaustion():
    """max_steps에 도달하면 completed repair_exhausted outcome으로 분류."""
    # max_steps=2인데 계속 tool_call만 반환
    responses = [
        LlmResponse(
            tool_calls=[ToolCallRequest(id=f"c{i}", name="knowledge.search", arguments={"query": f"q{i}"})],
            finish_reason="tool_calls", prompt_tokens=100, completion_tokens=20,
        )
        for i in range(5)
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 2})
    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiency == "RECOVERY_EXHAUSTED"
    assert session.termination_reason == "max_steps_recovered"


@pytest.mark.asyncio
async def test_token_budget_exhaustion():
    """completion token 예산 초과는 hard timeout이 아니면 completed outcome으로 분류."""
    responses = [
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c1", name="knowledge.search", arguments={"query": "a"})],
            finish_reason="tool_calls", prompt_tokens=100, completion_tokens=1500,
        ),
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c2", name="knowledge.search", arguments={"query": "b"})],
            finish_reason="tool_calls", prompt_tokens=100, completion_tokens=600,
        ),
    ]
    loop, session = _build_agent_loop(responses, {"max_completion_tokens": 2000})
    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiency == "RECOVERY_EXHAUSTED"
    assert session.termination_reason == "budget_exhausted_recovered"


@pytest.mark.asyncio
async def test_llm_error_returns_failure():
    """LLM 호출이 재시도 후에도 실패하면 MODEL_ERROR 반환."""
    from app.agent_runtime.errors import LlmUnavailableError

    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(side_effect=LlmUnavailableError())

    budget = BudgetState()
    bm = BudgetManager(budget)
    registry = ToolRegistry()

    loop = AgentLoop(
        llm_caller=llm_caller,
        message_manager=MessageManager("sys", "usr"),
        tool_registry=registry,
        tool_router=ToolRouter(registry, ToolExecutor(), bm, ToolFailurePolicy()),
        termination_policy=TerminationPolicy(),
        budget_manager=bm,
        token_counter=TokenCounter(),
        result_assembler=ResultAssembler(),
        turn_summarizer=TurnSummarizer(),
        retry_policy=RetryPolicy(max_retries=1),
    )
    session = AgentSession(_make_request(), budget)
    result = await loop.run(session)

    assert result.status == "model_error"
    assert result.retryable is True


@pytest.mark.asyncio
async def test_llm_timeout_remains_task_failure_boundary():
    """Hard LLM deadline is a public timeout boundary, not a recovered domain outcome."""
    from app.agent_runtime.errors import LlmTimeoutError

    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(side_effect=LlmTimeoutError("llm wait interrupted"))

    budget = BudgetState()
    bm = BudgetManager(budget)
    registry = ToolRegistry()

    loop = AgentLoop(
        llm_caller=llm_caller,
        message_manager=MessageManager("sys", "usr"),
        tool_registry=registry,
        tool_router=ToolRouter(registry, ToolExecutor(), bm, ToolFailurePolicy()),
        termination_policy=TerminationPolicy(),
        budget_manager=bm,
        token_counter=TokenCounter(),
        result_assembler=ResultAssembler(),
        turn_summarizer=TurnSummarizer(),
        retry_policy=RetryPolicy(max_retries=0),
    )
    session = AgentSession(_make_request(), budget)
    result = await loop.run(session)

    assert result.status == "timeout"
    assert result.failureCode == "TIMEOUT"


@pytest.mark.asyncio
async def test_llm_overload_becomes_completed_output_deficient_outcome():
    """LLM_BUSY/overload is an output/runtime deficiency, not MODEL_UNAVAILABLE."""
    from app.agent_runtime.errors import LlmHttpError

    llm_caller = MagicMock()
    llm_caller.call = AsyncMock(side_effect=LlmHttpError(503, "busy"))

    budget = BudgetState()
    bm = BudgetManager(budget)
    registry = ToolRegistry()

    loop = AgentLoop(
        llm_caller=llm_caller,
        message_manager=MessageManager("sys", "usr"),
        tool_registry=registry,
        tool_router=ToolRouter(registry, ToolExecutor(), bm, ToolFailurePolicy()),
        termination_policy=TerminationPolicy(),
        budget_manager=bm,
        token_counter=TokenCounter(),
        result_assembler=ResultAssembler(),
        turn_summarizer=TurnSummarizer(),
        retry_policy=RetryPolicy(max_retries=0),
    )
    session = AgentSession(_make_request(), budget)
    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].action == "llm_call_recovered"
    assert not hasattr(result, "failureCode")


@pytest.mark.asyncio
async def test_empty_llm_content_becomes_completed_output_deficient_outcome():
    responses = [LlmResponse(content="", prompt_tokens=100, completion_tokens=0)]
    loop, session = _build_agent_loop(responses)

    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiencyClass == "empty_llm_output"


@pytest.mark.asyncio
async def test_audit_info_populated():
    """성공 응답의 audit에 agentAudit가 포함되는지 확인."""
    responses = [
        LlmResponse(content=_final_assessment_json(), prompt_tokens=100, completion_tokens=50),
    ]
    loop, session = _build_agent_loop(responses)
    _add_command_injection_supporting_slice(
        session,
        file="clients/http_client.cpp",
        line=62,
    )
    result = await loop.run(session)

    assert result.audit.agentAudit is not None
    agent_audit = result.audit.agentAudit
    assert agent_audit["turn_count"] == 1
    assert agent_audit["termination_reason"] == "content_returned"


@pytest.mark.asyncio
async def test_structured_zero_claim_control_case_still_completes():
    """정당한 0-claim structured JSON은 여전히 completed가 가능하다."""
    responses = [
        LlmResponse(content=_structured_zero_claim_json(), prompt_tokens=100, completion_tokens=40),
    ]
    loop, session = _build_agent_loop(responses)
    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.claims == []
    assert result.result.usedEvidenceRefs == ["eref-001"]


@pytest.mark.asyncio
async def test_unstructured_content_retries_and_promotes_gateway_webserver_claim():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=_gateway_webserver_claim_json(), prompt_tokens=140, completion_tokens=90),
    ]
    loop, session = _build_agent_loop(responses)
    _add_command_injection_supporting_slice(
        session,
        file="clients/http_client.cpp",
        line=62,
    )
    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 1
    assert len(session.recovery_turns) == 1
    assert len(result.result.claims) == 1
    assert result.result.claims[0].location == "clients/http_client.cpp:62"
    assert result.result.suggestedSeverity == "high"


@pytest.mark.asyncio
async def test_first_tool_turn_uses_toolintent_path_then_relaxes_to_auto_after_success():
    responses = [
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c1", name="knowledge.search", arguments={"query": "CWE-78"})],
            finish_reason="tool_calls",
            prompt_tokens=100,
            completion_tokens=20,
        ),
        LlmResponse(
            content=_final_assessment_json(include_retrieval_ref=True),
            prompt_tokens=140,
            completion_tokens=90,
        ),
    ]
    loop, session = _build_agent_loop(responses)
    result = await loop.run(session)

    assert result.status == "completed"
    first_call = loop._llm_caller.call.await_args_list[0]
    second_call = loop._llm_caller.call.await_args_list[1]
    assert first_call.kwargs["tools"] is None
    assert "tool_choice" not in first_call.kwargs
    assert second_call.kwargs["tool_choice"] == "auto"
    assert first_call.kwargs["generation"].temperature == 1.0


@pytest.mark.asyncio
async def test_unstructured_content_twice_returns_completed_inconclusive():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=120, completion_tokens=35),
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=130, completion_tokens=30),
    ]
    loop, session = _build_agent_loop(responses)
    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiency == "LLM_OUTPUT_DEFICIENT"
    assert session.turn_count == 1
    assert len(session.recovery_turns) == 2


@pytest.mark.asyncio
async def test_unstructured_content_twice_uses_strict_structured_finalizer():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content="분석 결과 popen 사용은 CWE-78 위험입니다. 하지만 JSON은 생략합니다.", prompt_tokens=120, completion_tokens=35),
        LlmResponse(content=json.dumps({
            "summary": "Structured finalizer converted prior notes to JSON.",
            "claims": [{
                "statement": "CWE-78 popen finding is preserved for review.",
                "detail": "Finalizer output grounded in deterministic SAST evidence.",
                "supportingEvidenceRefs": ["eref-sast-flawfinder:shell/popen"],
                "location": "main.cpp:35",
            }],
            "caveats": ["Generated by strict structured finalizer after non-JSON content."],
            "usedEvidenceRefs": ["eref-sast-flawfinder:shell/popen"],
            "suggestedSeverity": "high",
            "needsHumanReview": True,
            "recommendedNextSteps": ["Inspect cited evidence manually."],
            "policyFlags": ["structured_finalizer"],
        }), prompt_tokens=130, completion_tokens=90),
    ]
    loop, session = _build_agent_loop(responses)
    session.request = _make_request(
        context=Context(trusted={
            "quickContext": {
                "sastFindings": [{
                    "toolId": "flawfinder",
                    "ruleId": "flawfinder:shell/popen",
                    "severity": "error",
                    "message": "This causes a new program to execute and is difficult to use safely (CWE-78).",
                    "location": {"file": "main.cpp", "line": 35},
                    "metadata": {"cweId": "CWE-78", "name": "popen"},
                }]
            }
        }),
        evidenceRefs=[],
    )
    session.extra_allowed_refs = {"eref-sast-flawfinder:shell/popen"}
    _add_command_injection_supporting_slice(
        session,
        ref_id="eref-sast-flawfinder:shell/popen",
        file="main.cpp",
        line=35,
        sast_backed=True,
    )

    result = await loop.run(session)

    assert result.status == "completed"
    assert len(result.result.claims) == 1
    assert "CWE-78" in result.result.claims[0].statement
    assert result.result.claims[0].supportingEvidenceRefs == ["eref-sast-flawfinder:shell/popen"]
    assert result.result.usedEvidenceRefs == ["eref-sast-flawfinder:shell/popen"]
    assert result.result.confidenceBreakdown.grounding == 1.0
    assert result.result.policyFlags == ["structured_finalizer"]


@pytest.mark.asyncio
async def test_structured_finalizer_caps_max_tokens_to_remaining_budget():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=200),
        LlmResponse(content="still not json", prompt_tokens=120, completion_tokens=300),
        LlmResponse(content=_structured_zero_claim_json(), prompt_tokens=130, completion_tokens=80),
    ]
    loop, session = _build_agent_loop(responses, {"max_completion_tokens": 1100})

    result = await loop.run(session)

    assert result.status == "completed"
    finalizer_call = loop._llm_caller.call.call_args_list[-1]
    assert finalizer_call.kwargs["max_tokens"] == 600
    assert finalizer_call.kwargs["generation"].temperature == 0.0


@pytest.mark.asyncio
async def test_structured_finalizer_skips_when_remaining_budget_too_low():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=300),
        LlmResponse(content="still not json", prompt_tokens=120, completion_tokens=250),
    ]
    loop, session = _build_agent_loop(responses, {"max_completion_tokens": 1000})

    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.recoveryTrace[0].action == "structured_finalizer_recovery"
    assert loop._llm_caller.call.call_count == 2
    assert session.turn_count == 0
    assert len(session.recovery_turns) == 2


@pytest.mark.asyncio
async def test_structured_finalizer_strict_json_error_becomes_completed_outcome():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=120, completion_tokens=35),
        StrictJsonContractError(
            async_request_id="acr-finalizer",
            gateway_request_id="req-finalizer",
            error_detail="invalid json",
        ),
    ]
    loop, session = _build_agent_loop(responses)
    result = await loop.run(session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiency == "LLM_OUTPUT_DEFICIENT"
    assert "strict_json_contract_violation" in (result.result.recoveryTrace[0].detail or "")
    assert session.turn_count == 0
    assert len(session.recovery_turns) == 2


@pytest.mark.asyncio
async def test_malformed_recovery_at_max_steps_minus_one_still_gets_retry_turn():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=_structured_zero_claim_json(), prompt_tokens=120, completion_tokens=50),
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 1})

    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 1
    assert len(session.recovery_turns) == 1


@pytest.mark.asyncio
async def test_audit_turns_include_recovery_in_chronological_audit_order():
    responses = [
        LlmResponse(content=_gateway_webserver_plan_text(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=_structured_zero_claim_json(), prompt_tokens=120, completion_tokens=50),
    ]
    loop, session = _build_agent_loop(responses, {"max_steps": 1})

    result = await loop.run(session)

    turns = result.audit.agentAudit["turns"]
    assert [(turn["audit_order"], turn["turn_number"], turn["llm_response_type"]) for turn in turns] == [
        (1, 1, "recovery_content"),
        (2, 1, "content"),
    ]


@pytest.mark.asyncio
async def test_missing_caveats_uses_strict_schema_repair_not_normalize():
    responses = [
        LlmResponse(content=_missing_caveats_json(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=json.dumps({
            "summary": "Structured schema repair preserved the claim and restored required caveats.",
            "claims": [{
                "statement": "User input flows to popen().",
                "detail": "The repaired output explicitly includes all required top-level fields.",
                "supportingEvidenceRefs": ["eref-001"],
                "location": "main.c:42",
            }],
            "caveats": ["Generated by strict schema repair after missing caveats output."],
            "usedEvidenceRefs": ["eref-001"],
            "suggestedSeverity": "high",
            "needsHumanReview": True,
            "recommendedNextSteps": ["Inspect cited evidence manually."],
            "policyFlags": ["structured_finalizer"],
        }), prompt_tokens=130, completion_tokens=90),
    ]
    loop, session = _build_agent_loop(responses)
    _add_command_injection_supporting_slice(session)

    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 1
    assert len(session.recovery_turns) == 1
    assert result.result.caveats == [
        "Generated by strict schema repair after missing caveats output."
    ]
    assert result.result.policyFlags == ["structured_finalizer"]


@pytest.mark.asyncio
async def test_wrong_collection_types_use_strict_schema_repair():
    responses = [
        LlmResponse(content=_wrong_collection_types_json(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=json.dumps({
            "summary": "Structured schema repair converted scalar fields to required arrays.",
            "claims": [{
                "statement": "User input flows to popen().",
                "detail": "The repaired output uses list-valued evidence fields.",
                "supportingEvidenceRefs": ["eref-001"],
                "location": "main.c:42",
            }],
            "caveats": [],
            "usedEvidenceRefs": ["eref-001"],
            "suggestedSeverity": "high",
            "needsHumanReview": True,
            "recommendedNextSteps": ["Inspect cited evidence manually."],
            "policyFlags": ["structured_finalizer"],
        }), prompt_tokens=130, completion_tokens=90),
    ]
    loop, session = _build_agent_loop(responses)
    _add_command_injection_supporting_slice(session)

    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 1
    assert len(session.recovery_turns) == 1
    assert result.result.usedEvidenceRefs == ["eref-001"]
    assert result.result.claims[0].supportingEvidenceRefs == ["eref-001"]
    assert result.result.policyFlags == ["structured_finalizer"]


@pytest.mark.asyncio
async def test_malformed_claim_shape_uses_strict_schema_repair():
    responses = [
        LlmResponse(content=_malformed_claim_shape_json(), prompt_tokens=100, completion_tokens=40),
        LlmResponse(content=json.dumps({
            "summary": "Structured schema repair converted malformed claims to valid objects.",
            "claims": [{
                "statement": "User input flows to popen().",
                "detail": "The repaired claim is grounded in the supplied source evidence.",
                "supportingEvidenceRefs": ["eref-001"],
                "location": "main.c:42",
            }],
            "caveats": ["Generated by strict schema repair after malformed claims output."],
            "usedEvidenceRefs": ["eref-001"],
            "suggestedSeverity": "high",
            "needsHumanReview": True,
            "recommendedNextSteps": ["Inspect cited evidence manually."],
            "policyFlags": ["structured_finalizer"],
        }), prompt_tokens=130, completion_tokens=90),
    ]
    loop, session = _build_agent_loop(responses)
    _add_command_injection_supporting_slice(session)

    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 1
    assert len(session.recovery_turns) == 1
    assert len(result.result.claims) == 1
    assert result.result.claims[0].supportingEvidenceRefs == ["eref-001"]
    assert result.result.policyFlags == ["structured_finalizer"]


@pytest.mark.asyncio
async def test_low_confidence_claim_triggers_one_shot_grounding_nudge():
    responses = [
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c1", name="knowledge.search", arguments={"query": "CWE-362"})],
            finish_reason="tool_calls",
            prompt_tokens=100,
            completion_tokens=20,
        ),
        LlmResponse(
            content=_gateway_webserver_low_confidence_json(include_retrieval_ref=False),
            prompt_tokens=180,
            completion_tokens=90,
        ),
        LlmResponse(
            tool_calls=[ToolCallRequest(id="c2", name="knowledge.search", arguments={"query": "CWE-36"})],
            finish_reason="tool_calls",
            prompt_tokens=220,
            completion_tokens=25,
        ),
        LlmResponse(
            content=_gateway_webserver_low_confidence_json(include_retrieval_ref=True),
            prompt_tokens=260,
            completion_tokens=110,
        ),
    ]
    loop, session = _build_agent_loop(responses)
    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 3
    assert len(session.recovery_turns) == 1
    assert result.result.policyFlags == ["low_confidence_claim_present"]
    assert "Exploitability is plausible but not fully confirmed" in result.result.claims[0].detail
    assert "eref-mock-CWE-36" in result.result.contextualEvidenceRefs
    assert "eref-mock-CWE-36" not in result.result.usedEvidenceRefs


@pytest.mark.asyncio
async def test_grounding_nudge_does_not_fire_after_force_report_disables_tools():
    responses = [
        LlmResponse(
            tool_calls=[ToolCallRequest(id=f"c{i}", name="knowledge.search", arguments={"query": f"CWE-{i}"})],
            finish_reason="tool_calls",
            prompt_tokens=100 + i,
            completion_tokens=20,
        )
        for i in range(4)
    ]
    responses.append(
        LlmResponse(
            content=_gateway_webserver_low_confidence_json(include_retrieval_ref=False),
            prompt_tokens=300,
            completion_tokens=120,
        )
    )
    loop, session = _build_agent_loop(responses, {"max_steps": 10, "max_cheap_calls": 6})
    result = await loop.run(session)

    assert result.status == "completed"
    assert session.turn_count == 5
    assert result.result.policyFlags == ["low_confidence_claim_present"]


def test_structured_finalizer_allowed_refs_exclude_knowledge_refs():
    from app.core.agent_loop import _allowed_finalizer_refs

    session = AgentSession(_make_request(evidenceRefs=[]), BudgetState())
    session.extra_allowed_refs.update({"eref-sast-flawfinder:shell/popen", "eref-knowledge-CWE-78"})
    session.trace.append(ToolTraceStep(
        step_id="step-knowledge",
        turn_number=1,
        tool="knowledge.search",
        args_hash="hash",
        cost_tier=ToolCostTier.CHEAP,
        duration_ms=1,
        success=True,
        new_evidence_refs=["eref-knowledge-CWE-78", "eref-caller-run"],
    ))

    refs = _allowed_finalizer_refs(session)

    assert "eref-sast-flawfinder:shell/popen" in refs
    assert "eref-caller-run" in refs
    assert "eref-knowledge-CWE-78" not in refs
