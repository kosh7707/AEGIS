import json
import logging

from app.agent_runtime.schemas.agent import AgentAuditInfo, BudgetState
from app.agent_runtime.schemas.agent import ToolCallRequest, ToolCostTier, ToolResult, ToolTraceStep
from app.core.agent_session import AgentSession
from app.core.evidence_catalog import EvidenceCatalogEntry
from app.core.phase_one_types import Phase1Result
from app.core.result_assembler import ResultAssembler, _build_claim_lifecycle_outputs
from app.schemas.request import Context, EvidenceRef, TaskRequest
from app.types import TaskType


def _make_session() -> AgentSession:
    request = TaskRequest(
        taskType=TaskType.DEEP_ANALYZE,
        taskId="result-assembler-test",
        context=Context(trusted={}),
        evidenceRefs=[
            EvidenceRef(
                refId="eref-001",
                artifactId="art-1",
                artifactType="source",
                locatorType="lineRange",
                locator={"file": "clients/http_client.cpp", "fromLine": 60, "toLine": 70},
            )
        ],
    )
    return AgentSession(request, BudgetState())


def _add_command_injection_slot_refs(session: AgentSession) -> None:
    session.evidence_catalog.add(EvidenceCatalogEntry(
        ref_id="eref-local-sink",
        evidence_class="local",
        roles=("sink_or_dangerous_api", "source_slice"),
        file="clients/http_client.cpp",
        line=64,
        sink="popen",
    ))



def test_unstructured_response_returns_completed_inconclusive_outcome():
    assembler = ResultAssembler()
    session = _make_session()

    result = assembler.build("## Phase A: 우선순위 수립\n1. popen 위험 분석", session)

    assert result.status == "completed"
    assert result.validation.valid is True
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiency == "LLM_OUTPUT_DEFICIENT"


def test_legitimate_structured_zero_claim_response_is_allowed():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "검토 결과 actionable claim으로 승격할 근거가 충분하지 않습니다.",
        "claims": [],
        "caveats": ["high-risk로 보였던 finding은 입력 검증과 호출 맥락상 false positive로 판단했습니다."],
        "usedEvidenceRefs": ["eref-001", "eref-local-sink"],
        "suggestedSeverity": "low",
        "needsHumanReview": True,
        "recommendedNextSteps": ["추가 런타임 검증 시나리오 검토"],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.validation.valid is True
    assert result.result.claims == []
    assert result.result.analysisOutcome == "no_accepted_claims"


def test_result_evidence_diagnostics_include_negative_attempts_and_audit_history():
    assembler = ResultAssembler()
    session = _make_session()
    session.evidence_catalog.add_negative(
        "knowledge.search",
        {"query": "CWE-78"},
        "no_hits",
    )
    final_content = json.dumps({
        "summary": "검토 결과 accepted claim으로 승격할 근거가 충분하지 않습니다.",
        "claims": [],
        "caveats": ["knowledge.search returned no useful hit."],
        "usedEvidenceRefs": [],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": ["수동 evidence 확인"],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.evidenceDiagnostics.negativeAttempts
    attempt = result.result.evidenceDiagnostics.negativeAttempts[0]
    assert attempt.tool == "knowledge.search"
    assert attempt.status == "no_hits"
    assert result.result.evidenceDiagnostics.attemptedAcquisitions == [
        attempt
    ]
    audit_diagnostics = result.audit.agentAudit["evidenceCatalogDiagnostics"]  # type: ignore[index]
    assert audit_diagnostics["liveRecoveryTrace"]["negativeCount"] == 1
    assert audit_diagnostics["attemptHistory"][0]["sourceTool"] == "knowledge.search"


def test_agent_audit_envelope_includes_evidence_catalog_diagnostics():
    assembler = ResultAssembler()
    session = _make_session()
    session.evidence_catalog.add_negative(
        "knowledge.search",
        {"query": "CWE-78"},
        "no_hits",
    )
    final_content = json.dumps({
        "summary": "검토 결과 accepted claim으로 승격할 근거가 충분하지 않습니다.",
        "claims": [],
        "caveats": [],
        "usedEvidenceRefs": [],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    agent_audit = AgentAuditInfo.model_validate(result.audit.agentAudit)
    diagnostics = agent_audit.evidenceCatalogDiagnostics
    assert diagnostics["liveRecoveryTrace"]["negativeCount"] == 1
    assert diagnostics["attemptHistory"][0]["sourceTool"] == "knowledge.search"


def test_attempted_acquisitions_distinct_from_negative_attempts():
    assembler = ResultAssembler()
    session = _make_session()
    session.evidence_catalog.add(EvidenceCatalogEntry(
        ref_id="eref-caller-run_curl",
        category="caller",
        source_tool="code_graph.callers",
        tool_arguments={"function_name": "popen"},
        artifact_type="code-graph",
        function="run_curl",
        evidence_class="local",
        roles=("caller_chain",),
    ))
    session.evidence_catalog.add_negative(
        "knowledge.search",
        {"query": "CWE-78"},
        "no_hits",
    )
    final_content = json.dumps({
        "summary": "검토 결과 accepted claim으로 승격할 근거가 충분하지 않습니다.",
        "claims": [],
        "caveats": [],
        "usedEvidenceRefs": [],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    diagnostics = result.result.evidenceDiagnostics
    assert diagnostics.attemptedAcquisitions != diagnostics.negativeAttempts
    assert [attempt.tool for attempt in diagnostics.negativeAttempts] == ["knowledge.search"]
    assert {attempt.tool for attempt in diagnostics.attemptedAcquisitions} == {
        "code_graph.callers",
        "knowledge.search",
    }


def test_negative_ref_is_not_reported_as_available_local_ref_when_cataloged():
    assembler = ResultAssembler()
    session = _make_session()
    negative_ref = session.evidence_catalog.add_negative(
        "knowledge.search",
        {"query": "CWE-78"},
        "no_hits",
    )
    final_content = json.dumps({
        "summary": "negative diagnostic ref를 claim support로 쓰면 안 됩니다.",
        "claims": [{
            "statement": "no-hit diagnostic으로 취약점을 확정합니다.",
            "detail": "negative evidence는 proof ref가 아닙니다.",
            "supportingEvidenceRefs": [negative_ref],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": [negative_ref],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert negative_ref not in result.result.evidenceDiagnostics.availableLocalRefs
    assert result.result.evidenceDiagnostics.invalidRefRoles[0].refId == negative_ref
    assert result.result.evidenceDiagnostics.invalidRefRoles[0].actualClass == "negative"


def test_legacy_negative_ref_prefix_is_not_fallback_classified_as_local():
    assembler = ResultAssembler()
    session = _make_session()
    session.trace.append(ToolTraceStep(
        step_id="negative-legacy",
        turn_number=1,
        tool="knowledge.search",
        args_hash="hash",
        cost_tier=ToolCostTier.CHEAP,
        duration_ms=1,
        success=True,
        new_evidence_refs=["eref-negative-legacy"],
    ))
    final_content = json.dumps({
        "summary": "legacy negative-looking ref를 claim support로 쓰면 안 됩니다.",
        "claims": [{
            "statement": "negative prefix diagnostic으로 취약점을 확정합니다.",
            "detail": "negative evidence는 proof ref가 아닙니다.",
            "supportingEvidenceRefs": ["eref-negative-legacy"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-negative-legacy"],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert "eref-negative-legacy" not in result.result.evidenceDiagnostics.availableLocalRefs
    assert result.result.evidenceDiagnostics.invalidRefRoles[0].actualClass == "negative"


def test_broad_eref_prefix_is_not_fallback_classified_as_local():
    assembler = ResultAssembler()
    session = _make_session()
    session.trace.append(ToolTraceStep(
        step_id="fake-ref",
        turn_number=1,
        tool="unknown.tool",
        args_hash="hash",
        cost_tier=ToolCostTier.CHEAP,
        duration_ms=1,
        success=True,
        new_evidence_refs=["eref-totally-fake"],
    ))
    final_content = json.dumps({
        "summary": "fake eref prefix should not be accepted.",
        "claims": [{
            "statement": "Fake ref proves a vulnerability.",
            "detail": "The broad eref-* prefix is not sufficient.",
            "supportingEvidenceRefs": ["eref-totally-fake"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-totally-fake"],
        "suggestedSeverity": "info",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.claims == []
    assert "eref-totally-fake" not in result.result.evidenceDiagnostics.availableLocalRefs
    assert result.result.evidenceDiagnostics.invalidRefRoles[0].actualClass == "unclassified"


def test_agent_v11_clean_pass_fields_and_contextual_refs_are_populated():
    assembler = ResultAssembler()
    session = _make_session()
    _add_command_injection_slot_refs(session)
    session.trace.append(ToolTraceStep(
        step_id="knowledge-1",
        turn_number=1,
        tool="knowledge.search",
        args_hash="hash",
        cost_tier=ToolCostTier.CHEAP,
        duration_ms=1,
        success=True,
        new_evidence_refs=["eref-knowledge-CWE-78"],
    ))
    final_content = json.dumps({
        "summary": "프로젝트 로컬 증거로 command injection claim이 확인되었습니다.",
        "claims": [{
            "statement": "사용자 입력이 popen 호출에 도달합니다.",
            "detail": "source ref가 취약 호출 위치를 직접 지시합니다.",
            "supportingEvidenceRefs": ["eref-001", "eref-local-sink"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001"],
        "contextualEvidenceRefs": ["eref-knowledge-CWE-78"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.schemaVersion == "agent-v1.1"
    assert result.result.cleanPass is True
    assert result.result.evaluationVerdict.cleanPass is True
    assert result.result.qualityGate.outcome == "accepted"
    assert result.result.contextualEvidenceRefs == ["eref-knowledge-CWE-78"]
    assert "eref-001" in result.result.evidenceDiagnostics.availableLocalRefs
    assert "eref-knowledge-CWE-78" in result.result.evidenceDiagnostics.availableKnowledgeRefs


def test_contextual_knowledge_ref_cannot_support_final_claim():
    assembler = ResultAssembler()
    session = _make_session()
    _add_command_injection_slot_refs(session)
    session.trace.append(ToolTraceStep(
        step_id="knowledge-1",
        turn_number=1,
        tool="knowledge.search",
        args_hash="hash",
        cost_tier=ToolCostTier.CHEAP,
        duration_ms=1,
        success=True,
        new_evidence_refs=["eref-knowledge-CWE-78"],
    ))
    final_content = json.dumps({
        "summary": "knowledge ref를 final claim support로 쓰면 안 됩니다.",
        "claims": [{
            "statement": "CWE 근거만으로 취약점을 확정합니다.",
            "detail": "이 claim은 프로젝트 로컬 ref가 아닌 knowledge ref를 claim support로 사용합니다.",
            "supportingEvidenceRefs": ["eref-knowledge-CWE-78"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-knowledge-CWE-78"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "no_accepted_claims"
    assert result.result.cleanPass is False
    assert result.result.evidenceDiagnostics.invalidRefRoles[0].refId == "eref-knowledge-CWE-78"
    assert result.result.evidenceDiagnostics.invalidRefRoles[0].actualClass == "knowledge"


def test_contextual_knowledge_ref_is_moved_when_local_ref_already_supports_claim():
    assembler = ResultAssembler()
    session = _make_session()
    _add_command_injection_slot_refs(session)
    session.trace.append(ToolTraceStep(
        step_id="knowledge-1",
        turn_number=1,
        tool="knowledge.search",
        args_hash="hash",
        cost_tier=ToolCostTier.CHEAP,
        duration_ms=1,
        success=True,
        new_evidence_refs=["eref-knowledge-CWE-78"],
    ))
    final_content = json.dumps({
        "summary": "프로젝트 로컬 증거와 CWE 컨텍스트가 함께 제공되었습니다.",
        "claims": [{
            "statement": "사용자 입력이 popen 호출에 도달합니다.",
            "detail": "source ref가 취약 호출 위치를 직접 지시하고 CWE ref는 배경지식입니다.",
            "supportingEvidenceRefs": ["eref-001", "eref-local-sink", "eref-knowledge-CWE-78"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001", "eref-local-sink", "eref-knowledge-CWE-78"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "accepted_claims"
    assert result.result.claims[0].supportingEvidenceRefs == ["eref-001", "eref-local-sink"]
    assert result.result.usedEvidenceRefs == ["eref-001", "eref-local-sink"]
    assert result.result.contextualEvidenceRefs == ["eref-knowledge-CWE-78"]
    assert result.result.evidenceDiagnostics.invalidRefRoles == []
    assert "evidence_role_normalized" in result.result.policyFlags


def test_family_specific_slots_prevent_under_evidenced_clean_pass():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "source ref 하나만으로 command injection을 확정하면 안 됩니다.",
        "claims": [{
            "statement": "CWE-78 command injection reaches popen.",
            "detail": "Only a source location ref was attached.",
            "supportingEvidenceRefs": ["eref-001"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.claims == []
    assert result.result.cleanPass is False
    assert result.result.analysisOutcome == "no_accepted_claims"
    diagnostic = result.result.claimDiagnostics.nonAcceptedClaims[0]
    assert diagnostic.status == "under_evidenced"
    assert diagnostic.missingEvidence == [
        "sink_or_dangerous_api",
        "caller_chain_or_source_slice",
    ]


def test_recoverable_loop_exhaustion_returns_completed_repair_exhausted():
    assembler = ResultAssembler()
    session = _make_session()
    session.set_termination_reason("all_tiers_exhausted")

    result = assembler.build_from_exhaustion(session)

    assert result.status == "completed"
    assert result.validation.valid is True
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiency == "RECOVERY_EXHAUSTED"


def test_llm_failure_can_recover_grounded_claim_from_available_local_evidence(tmp_path):
    assembler = ResultAssembler()
    session = _make_session()
    session.request.context.trusted["projectPath"] = str(tmp_path)
    source_lines = [""] * 40
    source_lines[28] = "static int run(const std::string &cmd) {"
    source_lines[34] = 'FILE *p = popen(cmd.c_str(), "r");'
    source_lines[35] = "}"
    source_lines[39] = 'int rc = run("openssl req -new -key " + key);'
    (tmp_path / "main.cpp").write_text("\n".join(source_lines))
    session.evidence_catalog.add(EvidenceCatalogEntry(
        ref_id="eref-sast-flawfinder-shell-popen",
        category="sast",
        source_tool="sast",
        artifact_type="sast-finding",
        file="main.cpp",
        line=35,
        sink="popen",
        rule_id="flawfinder:shell/popen",
        cwe_id="CWE-78",
        summary="popen executes an OpenSSL command assembled from input and may allow command injection.",
        evidence_class="local",
        roles=("sast_finding", "source_location", "sink_or_dangerous_api"),
    ))
    session.evidence_catalog.add(EvidenceCatalogEntry(
        ref_id="eref-caller-run-main-cpp-29",
        category="caller",
        source_tool="code_graph.callers",
        artifact_type="code-graph",
        file="main.cpp",
        line=29,
        function="run",
        sink="popen",
        summary="caller chain reaches popen from run().",
        evidence_class="local",
        roles=("caller_chain", "function_symbol"),
    ))

    result = assembler.build_from_available_evidence(
        session,
        deficiency_detail="internal_error",
    )

    assert result.status == "completed"
    assert result.result.analysisOutcome == "accepted_claims"
    assert result.result.claims
    assert result.result.claims[0].status == "grounded"
    assert "popen" in result.result.claims[0].detail
    assert "OpenSSL" in result.result.claims[0].detail
    assert result.result.recoveryTrace[0].action == "deterministic_local_evidence_fallback"
    assert "deterministic_local_evidence_fallback" in result.result.policyFlags


def test_llm_failure_source_hotspot_fallback_scans_project_local_sources(tmp_path):
    assembler = ResultAssembler()
    session = _make_session()
    session.request.context.trusted["projectPath"] = str(tmp_path)
    (tmp_path / "cJSON.c").write_text(
        "\n".join([
            "void helper(void) {}",
            "cJSON_bool cJSON_InsertItemInArray(cJSON *array, int which, cJSON *newitem) {",
            "    return newitem->prev != 0;",
            "}",
        ])
    )

    result = assembler.build_from_available_evidence(
        session,
        deficiency_detail="tool_intent_planning_stalled_after_45s",
    )

    assert result.status == "completed"
    assert result.result.analysisOutcome == "accepted_claims"
    claim_text = json.dumps(result.result.claims[0].model_dump(mode="json"), ensure_ascii=False)
    assert "cJSON_InsertItemInArray" in claim_text
    assert "CWE-476" in claim_text
    assert "source.hotspot_scan" in json.dumps(
        result.result.evidenceDiagnostics.attemptedAcquisitions[0].model_dump(mode="json"),
        ensure_ascii=False,
    )


def test_timeout_exhaustion_remains_task_failure():
    assembler = ResultAssembler()
    session = _make_session()
    session.set_termination_reason("timeout")

    result = assembler.build_from_exhaustion(session)

    assert result.status == "timeout"
    assert result.failureCode == "TIMEOUT"


def test_low_confidence_claim_shape_is_allowed_without_schema_change():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "추가 검증이 필요하지만 보안상 무시할 수 없는 claim입니다.",
        "claims": [{
            "statement": "readlink 사용 경로는 exploitability closure가 불완전하지만 위험 신호가 있습니다.",
            "detail": (
                "Exploitability is plausible but not fully confirmed from the available evidence. "
                "guard/validation evidence가 더 필요합니다."
            ),
            "supportingEvidenceRefs": ["eref-001"],
            "location": "utils/fs.cpp:22",
        }],
        "caveats": ["low-confidence claim: 추가 검증이 필요합니다."],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "medium",
        "needsHumanReview": True,
        "recommendedNextSteps": ["knowledge.search로 CWE/CVE 연결 근거 보강"],
        "policyFlags": ["low_confidence_claim_present"],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert len(result.result.claims) == 1
    assert result.result.policyFlags == ["low_confidence_claim_present"]
    assert "Exploitability is plausible but not fully confirmed" in result.result.claims[0].detail


def test_missing_top_level_caveats_is_scaffolded_when_claim_is_grounded():
    assembler = ResultAssembler()
    session = _make_session()
    _add_command_injection_slot_refs(session)
    final_content = json.dumps({
        "summary": "popen 호출 경로가 확인되어 command injection 가능성이 있습니다.",
        "claims": [{
            "statement": "사용자 입력이 popen 호출에 도달합니다.",
            "detail": "입력값이 shell command 문자열로 연결된 뒤 popen으로 실행됩니다.",
            "supportingEvidenceRefs": ["eref-001", "eref-local-sink"],
            "location": "clients/http_client.cpp:64",
        }],
        "usedEvidenceRefs": ["eref-001", "eref-local-sink"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": ["shell escaping 제거 및 execve argv 배열로 대체"],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.caveats == []
    assert "deterministic_schema_scaffold" in result.result.policyFlags


def test_missing_top_level_used_refs_is_synced_from_claim_refs_when_grounded():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "증거 ref가 claim 수준에는 존재하지만 top-level usedEvidenceRefs가 누락되었습니다.",
        "claims": [{
            "statement": "취약 호출 경로가 증거 ref로 뒷받침됩니다.",
            "detail": "claim-level supportingEvidenceRefs에서 top-level refs를 안전하게 복구합니다.",
            "supportingEvidenceRefs": ["eref-001"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.usedEvidenceRefs == ["eref-001"]
    assert "deterministic_schema_scaffold" in result.result.policyFlags


def test_missing_contract_required_metadata_fields_become_completed_schema_outcome():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "메타데이터 required field가 누락되었습니다.",
        "claims": [{
            "statement": "취약 호출 경로가 증거 ref로 뒷받침됩니다.",
            "detail": "policyFlags/recommendedNextSteps 등도 계약상 required입니다.",
            "supportingEvidenceRefs": ["eref-001"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001"],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.validation.valid is True
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert result.result.recoveryTrace[0].deficiency == "SCHEMA_DEFICIENT"
    assert "필수 필드 'suggestedSeverity' 누락" in result.result.caveats


def test_missing_claim_supporting_refs_become_completed_schema_outcome():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "claim-level required refs가 누락되었습니다.",
        "claims": [{
            "statement": "취약 호출 경로가 있다고 주장하지만 claim refs가 없습니다.",
            "detail": "supportingEvidenceRefs 누락은 sanitizer가 []로 숨기면 안 됩니다.",
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert any("supportingEvidenceRefs" in c for c in result.result.caveats)


def test_missing_claim_detail_and_location_become_completed_schema_outcome():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "claim detail/location 누락은 계약 위반입니다.",
        "claims": [{
            "statement": "취약 호출 경로가 있다고 주장합니다.",
            "supportingEvidenceRefs": ["eref-001"],
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-001"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert any("'detail' 누락" in c for c in result.result.caveats)
    assert any("'location' 누락" in c for c in result.result.caveats)


def test_claim_with_only_hallucinated_refs_becomes_completed_no_accepted_claims():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "환각 ref만으로 claim을 만들면 안 됩니다.",
        "claims": [{
            "statement": "지원되지 않는 증거 ref만 가진 claim입니다.",
            "detail": "sanitizer가 fake ref를 제거한 뒤 claim이 ungrounded가 됩니다.",
            "supportingEvidenceRefs": ["eref-totally-fake"],
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [],
        "usedEvidenceRefs": ["eref-totally-fake"],
        "suggestedSeverity": "high",
        "needsHumanReview": True,
        "recommendedNextSteps": [],
        "policyFlags": [],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "no_accepted_claims"
    assert result.result.qualityOutcome == "rejected"
    assert result.result.recoveryTrace[0].deficiency == "REFS_OR_GROUNDING_DEFICIENT"
    assert "eref-totally-fake" in (result.result.recoveryTrace[0].detail or "")


def test_required_collection_fields_with_wrong_types_become_completed_schema_outcome():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": "필수 collection field 타입이 깨졌습니다.",
        "claims": [{
            "statement": "supportingEvidenceRefs가 문자열이면 안 됩니다.",
            "detail": "schema repair 또는 failure 대상입니다.",
            "supportingEvidenceRefs": "eref-001",
            "location": "clients/http_client.cpp:64",
        }],
        "caveats": [123],
        "usedEvidenceRefs": [123],
        "suggestedSeverity": 123,
        "needsHumanReview": "yes",
        "recommendedNextSteps": [123],
        "policyFlags": [123],
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert any("caveats[0]가 문자열이 아님" in c for c in result.result.caveats)
    assert any("usedEvidenceRefs[0]가 문자열이 아님" in c for c in result.result.caveats)
    assert any("'supportingEvidenceRefs'가 리스트가 아님" in c for c in result.result.caveats)


def test_required_fields_with_null_values_become_completed_schema_outcome_without_exception():
    assembler = ResultAssembler()
    session = _make_session()
    final_content = json.dumps({
        "summary": None,
        "claims": None,
        "caveats": None,
        "usedEvidenceRefs": None,
        "suggestedSeverity": None,
        "needsHumanReview": None,
        "recommendedNextSteps": None,
        "policyFlags": None,
    })

    result = assembler.build(final_content, session)

    assert result.status == "completed"
    assert result.result.analysisOutcome == "inconclusive"
    assert result.result.qualityOutcome == "repair_exhausted"
    assert any("'summary'가 문자열이 아님" in c for c in result.result.caveats)
    assert any("'claims'가 리스트가 아님" in c for c in result.result.caveats)


def test_non_dict_claim_logged_and_skipped(caplog):
    session = _make_session()
    parsed = {"claims": ["not-a-claim"]}

    with caplog.at_level(logging.WARNING, logger="app.core.result_assembler"):
        claims, diagnostics = _build_claim_lifecycle_outputs(parsed, session)

    assert claims == []
    assert diagnostics.lifecycleCounts == {}
    assert "non-dict claim entry skipped" in caplog.text
