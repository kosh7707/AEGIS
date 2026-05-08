import json
from unittest.mock import MagicMock

import pytest

from app.config import settings
from app.core.agent_session import AgentSession
from app.core.evidence_catalog import EvidenceCatalogEntry
from app.core.phase_one_types import Phase1Result
from app.agent_runtime.schemas.agent import BudgetState
from app.routers import deep_analyze_handler
from app.routers.deep_analyze_handler import _configure_phase2_graph_tools, _suggest_next_evidence_action, handle_deep_analyze
from app.schemas.request import Context, TaskRequest
from app.types import TaskType
from app.agent_runtime.tools.registry import ToolRegistry, ToolSchema


def _register_graph_tools(registry: ToolRegistry) -> None:
    for name in ("code_graph.callers", "code_graph.callees", "code_graph.search"):
        registry.register(ToolSchema(name=name, description=name))


def _register_knowledge_tool(registry: ToolRegistry) -> None:
    registry.register(ToolSchema(name="knowledge.search", description="knowledge.search"))


class _Tool:
    def __init__(self):
        self.project_id = None

    def set_project_id(self, project_id: str) -> None:
        self.project_id = project_id


def test_configure_phase2_graph_tools_removes_unready_graph_search():
    registry = ToolRegistry()
    _register_graph_tools(registry)
    callers = _Tool()
    callees = _Tool()
    search = _Tool()

    phase1 = Phase1Result(
        code_graph_neo4j_ready=True,
        code_graph_graph_rag_ready=False,
    )

    _configure_phase2_graph_tools(
        registry,
        phase1,
        "proj-1",
        callers_tool=callers,
        callees_tool=callees,
        search_tool=search,
    )

    assert registry.get("code_graph.callers") is not None
    assert registry.get("code_graph.callees") is not None
    assert registry.get("code_graph.search") is None
    assert callers.project_id == "proj-1"
    assert callees.project_id == "proj-1"
    assert search.project_id is None


def test_configure_phase2_graph_tools_removes_all_graph_tools_when_neo4j_not_ready():
    registry = ToolRegistry()
    _register_graph_tools(registry)
    callers = _Tool()
    callees = _Tool()
    search = _Tool()

    phase1 = Phase1Result(
        code_graph_neo4j_ready=False,
        code_graph_graph_rag_ready=False,
    )

    _configure_phase2_graph_tools(
        registry,
        phase1,
        "proj-1",
        callers_tool=callers,
        callees_tool=callees,
        search_tool=search,
    )

    assert registry.get("code_graph.callers") is None
    assert registry.get("code_graph.callees") is None
    assert registry.get("code_graph.search") is None


def test_configure_phase2_tools_removes_knowledge_when_kb_not_ready():
    registry = ToolRegistry()
    _register_graph_tools(registry)
    _register_knowledge_tool(registry)

    phase1 = Phase1Result(kb_not_ready=True)

    _configure_phase2_graph_tools(registry, phase1, "proj-1")

    assert registry.get("knowledge.search") is None
    assert registry.get("code_graph.callers") is not None


def test_advisory_diagnose_resolves_planner_claim_refs(monkeypatch):
    request = TaskRequest(
        taskType=TaskType.DEEP_ANALYZE,
        taskId="deep-advisory-refs",
        context=Context(trusted={"projectId": "proj-1"}),
    )
    session = AgentSession(request, BudgetState())
    session.evidence_catalog.add(EvidenceCatalogEntry(
        ref_id="eref-sast-CWE-78",
        category="sast",
        artifact_type="sast-finding",
        file="src/http_client.cpp",
        line=62,
        sink="popen",
        cwe_id="CWE-78",
        evidence_class="local",
        roles=("sast_finding", "source_location", "sink_or_dangerous_api"),
    ))
    registry = ToolRegistry()
    _register_knowledge_tool(registry)
    captured: dict[str, object] = {}
    real_diagnose = deep_analyze_handler.diagnose_claim_evidence

    def capture_diagnose(*args, **kwargs):
        captured["allowed_local_refs"] = kwargs.get("allowed_local_refs")
        return real_diagnose(*args, **kwargs)

    monkeypatch.setattr(deep_analyze_handler, "diagnose_claim_evidence", capture_diagnose)

    action = _suggest_next_evidence_action(
        Phase1Result(
            sast_findings=[{
                "ruleId": "CWE-78",
                "message": "popen command injection",
                "location": {"file": "src/http_client.cpp", "line": 62},
                "metadata": {"cweId": "CWE-78"},
            }],
            threat_context=[],
            dangerous_callers=[{"function": "run_curl"}],
        ),
        session,
        registry,
    )

    assert action is not None
    assert captured["allowed_local_refs"] == set(session.evidence_catalog.ref_ids())


def _sast_finding(rule_id: str = "CWE-78", line: int = 62) -> dict:
    return {
        "toolId": "flawfinder",
        "ruleId": rule_id,
        "severity": "error",
        "message": "popen command injection reaches a shell sink",
        "location": {"file": "src/http_client.cpp", "line": line},
        "metadata": {"cweId": rule_id},
    }


def _deep_claim_payload(refs: list[str]) -> dict:
    return {
        "summary": "Deep analysis completed with live recovery caveats.",
        "claims": [{
            "statement": "SAST finding needs additional caller-chain evidence.",
            "detail": "The finding is plausible, but Phase 1 recovery diagnostics must remain caveats.",
            "supportingEvidenceRefs": refs,
            "location": "src/http_client.cpp:62",
        }],
        "caveats": ["KB or graph enrichment was unavailable during Phase 1."],
        "usedEvidenceRefs": refs,
        "suggestedSeverity": "medium",
        "needsHumanReview": True,
        "recommendedNextSteps": ["Re-run enrichment when dependencies recover."],
        "policyFlags": [],
    }


@pytest.mark.asyncio
async def test_deep_analyze_kb_timeout_produces_honest_envelope(monkeypatch):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")
    phase1 = Phase1Result(
        sast_findings=[_sast_finding()],
        threat_context=[],
        kb_timed_out=True,
    )

    async def fake_phase1_execute(self, session):
        return phase1

    async def fake_phase1_aclose(self):
        return None

    async def fake_call(self, messages, *args, **kwargs):
        from app.agent_runtime.schemas.agent import LlmResponse
        return LlmResponse(
            content=json.dumps(_deep_claim_payload(["eref-sast-CWE-78"])),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr("app.core.phase_one.Phase1Executor.execute", fake_phase1_execute)
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.aclose", fake_phase1_aclose)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)
    monkeypatch.setattr("app.core.agent_loop._requires_tool_intent_dispatch", lambda *args, **kwargs: False)
    model_registry = MagicMock()
    model_registry.get_default.return_value = MagicMock(
        endpoint="http://localhost:8000",
        modelName="test-model",
        apiKey="",
    )
    request = TaskRequest(
        taskType=TaskType.DEEP_ANALYZE,
        taskId="deep-kb-timeout",
        context=Context(trusted={"projectId": "proj-1", "projectPath": "/tmp/project"}),
    )

    try:
        result = await handle_deep_analyze(request, model_registry)

        assert result.status == "completed"
        attempted = result.result.evidenceDiagnostics.attemptedAcquisitions
        assert any(item.tool == "kb.threat_query" and item.status == "timeout" for item in attempted)
        assert all(
            not ref.startswith("eref-knowledge-")
            for claim in result.result.claims
            for ref in claim.supportingEvidenceRefs
        )
        assert result.result.analysisOutcome != "accepted_claims"
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)


@pytest.mark.asyncio
async def test_deep_analyze_kb_timeout_prompt_marks_absence_as_non_negative(monkeypatch):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")
    seen: dict[str, str] = {}

    async def fake_phase1_execute(self, session):
        return Phase1Result(
            sast_findings=[_sast_finding()],
            threat_context=[],
            kb_timed_out=True,
        )

    async def fake_phase1_aclose(self):
        return None

    async def fake_call(self, messages, *args, **kwargs):
        from app.agent_runtime.schemas.agent import LlmResponse
        if len(messages) == 1:
            return LlmResponse(
                content=json.dumps({
                    "action": "call_tool",
                    "tool_name": "build.metadata",
                    "arguments": {},
                    "rationale": "collect existing build metadata before final analysis",
                }),
                prompt_tokens=3,
                completion_tokens=2,
            )
        seen["user_message"] = messages[1]["content"]
        return LlmResponse(
            content=json.dumps({
                "summary": "KB timeout was caveated.",
                "claims": [],
                "caveats": ["KB timeout means absence is not negative evidence."],
                "usedEvidenceRefs": [],
                "suggestedSeverity": "info",
                "needsHumanReview": True,
                "recommendedNextSteps": ["Retry KB enrichment."],
                "policyFlags": [],
            }),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr("app.core.phase_one.Phase1Executor.execute", fake_phase1_execute)
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.aclose", fake_phase1_aclose)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)
    monkeypatch.setattr("app.core.agent_loop._requires_tool_intent_dispatch", lambda *args, **kwargs: False)
    model_registry = MagicMock()
    model_registry.get_default.return_value = MagicMock(
        endpoint="http://localhost:8000",
        modelName="test-model",
        apiKey="",
    )

    try:
        result = await handle_deep_analyze(
            TaskRequest(
                taskType=TaskType.DEEP_ANALYZE,
                taskId="deep-kb-timeout-prompt",
                context=Context(trusted={"projectId": "proj-1"}),
            ),
            model_registry,
        )

        assert result.status == "completed"
        assert "KB timeout" in seen["user_message"]
        assert "absence" in seen["user_message"]
        assert "negative evidence" in seen["user_message"]
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)


@pytest.mark.asyncio
async def test_deep_analyze_cve_timeout_records_operational_diagnostic(monkeypatch):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")
    phase1 = Phase1Result(
        sca_libraries=[{"name": "openssl", "version": "1.1.1"}],
        cve_lookup_timed_out=True,
    )

    async def fake_phase1_execute(self, session):
        return phase1

    async def fake_phase1_aclose(self):
        return None

    async def fake_call(self, messages, *args, **kwargs):
        from app.agent_runtime.schemas.agent import LlmResponse
        return LlmResponse(
            content=json.dumps({
                "summary": "Library CVE enrichment timed out.",
                "claims": [],
                "caveats": ["CVE lookup timed out."],
                "usedEvidenceRefs": [],
                "suggestedSeverity": "info",
                "needsHumanReview": True,
                "recommendedNextSteps": ["Retry CVE lookup later."],
                "policyFlags": [],
            }),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr("app.core.phase_one.Phase1Executor.execute", fake_phase1_execute)
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.aclose", fake_phase1_aclose)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)
    monkeypatch.setattr("app.core.agent_loop._requires_tool_intent_dispatch", lambda *args, **kwargs: False)
    model_registry = MagicMock()
    model_registry.get_default.return_value = MagicMock(
        endpoint="http://localhost:8000",
        modelName="test-model",
        apiKey="",
    )

    try:
        result = await handle_deep_analyze(
            TaskRequest(
                taskType=TaskType.DEEP_ANALYZE,
                taskId="deep-cve-timeout",
                context=Context(trusted={"projectId": "proj-1"}),
            ),
            model_registry,
        )

        assert result.status == "completed"
        attempted = result.result.evidenceDiagnostics.attemptedAcquisitions
        assert any(item.tool == "cve.batch_lookup" and item.status == "timeout" for item in attempted)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)


@pytest.mark.asyncio
async def test_deep_analyze_partial_phase1_failure_propagates_to_phase2_prompt(monkeypatch):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")
    phase1 = Phase1Result(
        sast_findings=[_sast_finding("CWE-78", 62), _sast_finding("CWE-77", 70)],
        threat_context=[],
        kb_timed_out=True,
        code_graph_neo4j_ready=False,
        code_graph_graph_rag_ready=False,
        code_graph_status="partial",
        code_graph_warnings=["neo4j not ready"],
    )
    seen: dict[str, object] = {}

    async def fake_phase1_execute(self, session):
        return phase1

    async def fake_phase1_aclose(self):
        return None

    async def fake_call(self, messages, *args, **kwargs):
        from app.agent_runtime.schemas.agent import LlmResponse
        if len(messages) == 1:
            return LlmResponse(
                content=json.dumps({
                    "action": "call_tool",
                    "tool_name": "build.metadata",
                    "arguments": {},
                    "rationale": "collect existing build metadata before final analysis",
                }),
                prompt_tokens=3,
                completion_tokens=2,
            )
        seen["user_message"] = messages[1]["content"]
        seen["tools"] = kwargs.get("tools") or []
        return LlmResponse(
            content=json.dumps(_deep_claim_payload(["eref-sast-CWE-78"])),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr("app.core.phase_one.Phase1Executor.execute", fake_phase1_execute)
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.aclose", fake_phase1_aclose)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)
    monkeypatch.setattr("app.core.agent_loop._requires_tool_intent_dispatch", lambda *args, **kwargs: False)
    model_registry = MagicMock()
    model_registry.get_default.return_value = MagicMock(
        endpoint="http://localhost:8000",
        modelName="test-model",
        apiKey="",
    )

    try:
        result = await handle_deep_analyze(
            TaskRequest(
                taskType=TaskType.DEEP_ANALYZE,
                taskId="deep-partial-phase1",
                context=Context(trusted={"projectId": "proj-1", "projectPath": "/tmp/project"}),
            ),
            model_registry,
        )

        tool_names = {tool["function"]["name"] for tool in seen["tools"]}
        assert not any(name.startswith("code_graph.") for name in tool_names)
        user_message = str(seen["user_message"])
        assert "Live Recovery / Evidence Ledger Summary" in user_message
        assert "kb.threat_query" in user_message
        assert "code graph not ready" in user_message
        assert len(result.result.evidenceDiagnostics.availableLocalRefs) >= 2
        assert all(
            not ref.startswith("eref-knowledge-")
            for claim in result.result.claims
            for ref in claim.supportingEvidenceRefs
        )
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)


@pytest.mark.asyncio
async def test_deep_analyze_phase2_tool_surface_never_exposes_sast(monkeypatch):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")
    seen: dict[str, object] = {}

    async def fake_phase1_execute(self, session):
        return Phase1Result(sast_findings=[_sast_finding()])

    async def fake_phase1_aclose(self):
        return None

    async def fake_call(self, messages, *args, **kwargs):
        seen["tools"] = kwargs.get("tools") or []
        from app.agent_runtime.schemas.agent import LlmResponse
        return LlmResponse(
            content=json.dumps({
                "summary": "Deep analysis completed.",
                "claims": [],
                "caveats": [],
                "usedEvidenceRefs": [],
                "suggestedSeverity": "info",
                "needsHumanReview": True,
                "recommendedNextSteps": [],
                "policyFlags": [],
            }),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr("app.core.phase_one.Phase1Executor.execute", fake_phase1_execute)
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.aclose", fake_phase1_aclose)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)
    monkeypatch.setattr("app.core.agent_loop._requires_tool_intent_dispatch", lambda *args, **kwargs: False)
    model_registry = MagicMock()
    model_registry.get_default.return_value = MagicMock(
        endpoint="http://localhost:8000",
        modelName="test-model",
        apiKey="",
    )

    try:
        await handle_deep_analyze(
            TaskRequest(
                taskType=TaskType.DEEP_ANALYZE,
                taskId="deep-no-sast-phase2",
                context=Context(trusted={"projectId": "proj-1", "projectPath": "/tmp/project"}),
            ),
            model_registry,
        )

        tool_names = {tool["function"]["name"] for tool in seen["tools"]}
        assert "sast.scan" not in tool_names
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)


@pytest.mark.asyncio
async def test_handle_deep_analyze_requests_async_ownership_on_toolless_turn(monkeypatch):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")

    request = TaskRequest(
        taskType=TaskType.DEEP_ANALYZE,
        taskId="deep-async-001",
        context=Context(trusted={
            "objective": "test",
            "projectPath": "/tmp/project",
            "projectId": "proj-1",
        }),
    )

    seen: dict[str, object] = {}

    async def fake_phase1_execute(self, session):
        return Phase1Result()

    async def fake_phase1_aclose(self):
        seen["phase1_closed"] = True

    async def fake_call(self, *args, **kwargs):
        seen["prefer_async_ownership"] = kwargs.get("prefer_async_ownership")
        from app.agent_runtime.schemas.agent import LlmResponse
        return LlmResponse(
            content=json.dumps({
                "summary": "Deep analysis completed",
                "claims": [],
                "caveats": [],
                "usedEvidenceRefs": [],
                "suggestedSeverity": "info",
                "needsHumanReview": True,
                "recommendedNextSteps": [],
                "policyFlags": [],
            }),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr(
        "app.agent_runtime.tools.registry.ToolRegistry.get_available_schemas",
        lambda self, budget_manager: None,
    )
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.execute", fake_phase1_execute)
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.aclose", fake_phase1_aclose)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)

    model_registry = MagicMock()
    model_registry.get_default.return_value = MagicMock(
        endpoint="http://localhost:8000",
        modelName="test-model",
        apiKey="",
    )

    try:
        result = await handle_deep_analyze(request, model_registry)
        assert result.status == "completed"
        assert seen["prefer_async_ownership"] is True
        assert seen["phase1_closed"] is True
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)


@pytest.mark.asyncio
async def test_handle_deep_analyze_injects_deterministic_acquisition_suggestion(monkeypatch):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")

    request = TaskRequest(
        taskType=TaskType.DEEP_ANALYZE,
        taskId="deep-planner-001",
        context=Context(trusted={
            "objective": "test",
            "projectPath": "/tmp/project",
            "projectId": "proj-1",
        }),
    )

    seen: dict[str, object] = {}

    async def fake_phase1_execute(self, session):
        return Phase1Result(
            sast_findings=[{
                "ruleId": "CWE-78",
                "message": "popen command injection requires threat context",
                "location": {"file": "src/http_client.cpp", "line": 62},
                "metadata": {"cweId": "CWE-78"},
            }],
            threat_context=[],
        )

    async def fake_phase1_aclose(self):
        return None

    async def fake_call(self, messages, *args, **kwargs):
        seen["user_message"] = messages[1]["content"]
        from app.agent_runtime.schemas.agent import LlmResponse
        return LlmResponse(
            content=json.dumps({
                "summary": "Deep analysis completed",
                "claims": [],
                "caveats": [],
                "usedEvidenceRefs": [],
                "suggestedSeverity": "info",
                "needsHumanReview": True,
                "recommendedNextSteps": [],
                "policyFlags": [],
            }),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr(
        "app.agent_runtime.tools.registry.ToolRegistry.get_available_schemas",
        lambda self, budget_manager: None,
    )
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.execute", fake_phase1_execute)
    monkeypatch.setattr("app.core.phase_one.Phase1Executor.aclose", fake_phase1_aclose)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)

    model_registry = MagicMock()
    model_registry.get_default.return_value = MagicMock(
        endpoint="http://localhost:8000",
        modelName="test-model",
        apiKey="",
    )

    try:
        result = await handle_deep_analyze(request, model_registry)
        assert result.status == "completed"
        user_message = seen["user_message"]
        assert "Suggested Next Evidence Acquisition Action" in user_message
        assert "knowledge.search" in user_message
        assert '"target_slot": "threat_knowledge"' in user_message
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)
