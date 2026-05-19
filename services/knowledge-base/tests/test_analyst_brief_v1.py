"""S5 Analyst Brief v1 contract tests."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.analyst import brief as analyst_brief_contract
from app.analyst.brief import build_analyst_brief
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


def _artifact(**overrides):
    base = {
        "schemaVersion": "acquisition-envelope-v1",
        "surface": "threat-search",
        "targetKnowledgeId": "tk-re100",
        "acquisitionStatus": "completed_hit",
        "acquisitionQualityGate": "accepted",
        "consumerPolicy": "contextual_only",
        "providerState": {"state": "not_applicable"},
        "projectionState": {"state": "ready"},
        "methodsAttempted": ["exact_id_match", "graph_expansion"],
        "methodsSucceeded": ["exact_id_match", "graph_expansion"],
        "sourceEvidenceRefs": ["eref-sast-1"],
        "derivedFromEvidenceRefs": ["eref-lib-1"],
        "results": {"hits": [{"id": "CWE-78"}], "total": 1},
    }
    base.update(overrides)
    return base


def test_contextual_completed_hit_is_context_not_claim_support():
    brief = build_analyst_brief(_artifact())

    assert brief["schemaVersion"] == "s5-analyst-brief-v1"
    assert brief["stance"] == "contextual"
    assert brief["evidencePlacement"]["recommendedRole"] == "knowledge_context"
    assert "use_as_knowledge_context" in brief["allowedUses"]
    assert "s5_final_security_verdict" in brief["forbiddenInferences"]
    assert "accepted_claim" in brief["forbiddenInferences"]
    assert "derived_local_support" in brief["forbiddenInferences"]


def test_local_support_candidate_requires_s3_ref_validation():
    brief = build_analyst_brief(_artifact(
        surface="code-search",
        consumerPolicy="s3_may_derive_local_support_if_refs_validate",
    ))

    assert brief["stance"] == "local_support_candidate"
    assert brief["evidencePlacement"]["recommendedRole"] == "derived_local_candidate"
    assert "use_as_local_support_candidate_after_s3_ref_validation" in brief["allowedUses"]
    assert "claim_support_before_local_ref_validation" in brief["forbiddenInferences"]
    assert any(a["actionType"] == "validate_source_evidence_refs" for a in brief["nextActions"])


def test_safe_completed_no_hit_is_scoped_record_only():
    brief = build_analyst_brief(_artifact(
        surface="cveCandidateEvaluation",
        acquisitionStatus="completed_no_hit",
        consumerPolicy="scoped_no_hit_record_only",
        methodsAttempted=["exact_id_match", "provider_range_eval"],
        methodsSucceeded=["exact_id_match", "provider_range_eval"],
        results={"candidateEvaluation": {"candidateCveId": "CVE-2026-0001"}},
        scope={
            "libraryKey": "libcurl@7.88.1",
            "candidateCveId": "CVE-2026-0001",
            "methodsRequiredForNoHit": ["exact_id_match", "provider_range_eval"],
            "noHitBasis": "candidate_version_range_evaluated",
        },
    ))

    assert brief["stance"] == "scoped_negative_record"
    assert brief["evidencePlacement"]["recommendedRole"] == "scoped_acquisition_record"
    assert "record_scoped_acquisition_no_hit" in brief["allowedUses"]
    assert "library_safe" in brief["forbiddenInferences"]
    assert "target_safe" in brief["forbiddenInferences"]
    assert "complete_project_safety" in brief["forbiddenInferences"]


def test_unsafe_no_hit_with_projection_debt_stays_diagnostic():
    brief = build_analyst_brief(_artifact(
        surface="dangerous-callers",
        acquisitionStatus="completed_no_hit",
        consumerPolicy="scoped_no_hit_record_only",
        methodsAttempted=["neo4j_call_graph_traversal"],
        methodsSucceeded=[],
        projectionState={"state": "partial"},
        scope={
            "projectId": "re100",
            "methodsRequiredForNoHit": ["neo4j_call_graph_traversal"],
            "noHitBasis": "embedding_only_no_result",
        },
        diagnostics=[{"code": "NO_HIT_TRACE_MISSING", "message": "trace missing"}],
    ))

    assert brief["stance"] == "diagnostic"
    assert brief["evidencePlacement"]["recommendedRole"] == "operational_diagnostic"
    assert "no_caller_or_path" in brief["forbiddenInferences"]
    assert any("Projection state" in warning for warning in brief["qualityWarnings"])
    assert any(a["actionType"] == "sync_or_rebuild_projection" for a in brief["nextActions"])
    assert any(a["actionType"] == "rerun_with_retrieval_trace" for a in brief["nextActions"])


def test_input_insufficient_is_blocked_with_missing_input_guidance():
    brief = build_analyst_brief(_artifact(
        surface="target-context-ingest",
        acquisitionStatus="input_insufficient",
        acquisitionQualityGate="rejected",
        consumerPolicy="do_not_use",
        readiness={"missingInputs": ["projectId", "target.targetId"]},
        results={"missingFields": ["provenance.buildSnapshotId"]},
        diagnostics=[{"code": "TARGET_IDENTITY_INSUFFICIENT", "message": "missing target identity"}],
    ))

    assert brief["stance"] == "blocked"
    assert brief["evidencePlacement"]["recommendedRole"] == "do_not_use"
    assert "global_default_answer" in brief["forbiddenInferences"]
    assert any(a["actionType"] == "provide_missing_inputs" for a in brief["nextActions"])
    assert "projectId" in brief["nextActions"][0]["requiredInputs"]


def test_empty_artifact_returns_blocked_brief_not_silent_fallback():
    brief = build_analyst_brief({})

    assert brief["stance"] == "blocked"
    assert brief["evidencePlacement"]["consumerPolicy"] == "do_not_use"
    assert "artifact" in brief["nextActions"][0]["requiredInputs"]
    assert "fallback_answer" in brief["forbiddenInferences"]


def test_malformed_non_empty_artifact_is_blocked_not_diagnostic_guess():
    brief = build_analyst_brief({"surface": "legacy-search", "results": {"hits": []}})

    assert brief["stance"] == "blocked"
    assert brief["evidencePlacement"]["recommendedRole"] == "do_not_use"
    assert any(a["actionType"] == "send_valid_acquisition_artifact" for a in brief["nextActions"])
    assert any("AcquisitionEnvelopeV1" in warning for warning in brief["qualityWarnings"])


def test_runtime_brief_does_not_leak_offline_metric_vocabulary():
    brief = build_analyst_brief(_artifact())
    payload = json.dumps(brief, sort_keys=True).lower()

    for forbidden in ("true_positive", "false_positive", "false_negative", "recall", "precision", "ndcg", "mrr"):
        assert forbidden not in payload


def test_analyst_brief_api_is_pure_transform_without_timeout_header():
    resp = client.post(
        "/v1/analyst-brief",
        json={"artifact": _artifact(), "audience": "s3", "language": "ko"},
        headers={"X-Request-Id": "req-analyst-brief"},
    )

    assert resp.status_code == 200
    assert resp.headers["X-Request-Id"] == "req-analyst-brief"
    body = resp.json()
    assert body["schemaVersion"] == "s5-analyst-brief-v1"
    assert body["stance"] == "contextual"


def test_analyst_brief_api_rejects_unsupported_audience_and_language():
    bad_audience = client.post("/v1/analyst-brief", json={"artifact": _artifact(), "audience": "s4"})
    bad_language = client.post("/v1/analyst-brief", json={"artifact": _artifact(), "language": "fr"})

    assert bad_audience.status_code == 422
    assert bad_language.status_code == 422


def test_analyst_brief_api_rejects_oversized_selectors_without_echo():
    oversized = "secret-audience-" + ("x" * 100_000)

    resp = client.post(
        "/v1/analyst-brief",
        json={"artifact": _artifact(), "audience": oversized},
        headers={"X-Request-Id": "req-analyst-brief-oversized-selector"},
    )

    assert resp.status_code == 422
    body_text = resp.text
    body = resp.json()
    assert len(body_text) < 4096
    assert oversized not in body_text
    assert body["errorDetail"]["reason"] == "request_schema_invalid"
    assert body["errorDetail"]["requestId"] == "req-analyst-brief-oversized-selector"


def test_analyst_brief_contract_endpoint_freezes_judge_answer_consumption_policy():
    resp = client.get("/v1/contracts/analyst-brief", headers={"X-Request-Id": "req-analyst-brief-contract"})

    assert resp.status_code == 200
    assert resp.headers["X-Request-Id"] == "req-analyst-brief-contract"
    body = resp.json()
    judge_policy = body["judgeAnswerArtifactPolicy"]

    assert body["schemaVersion"] == "s5-analyst-brief-contract-v1"
    assert body["endpoint"] == {"method": "POST", "path": "/v1/analyst-brief"}
    assert "s5-judge-answer-v1" in body["acceptedArtifactSchemaVersions"]
    assert judge_policy["consumerPolicy"] == "judge_verdict_context_only"
    assert judge_policy["requiredBoundary"] == {
        "notFinalSecurityVerdict": True,
        "verdictAuthority": "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict",
    }
    assert judge_policy["boundaryFailure"] == {
        "stance": "blocked",
        "recommendedRole": "do_not_use",
        "actionType": "send_valid_judge_answer",
        "qualityWarning": "judge_final_verdict_boundary_missing",
    }
    assert judge_policy["verdictMapping"]["affected"] == {
        "stance": "contextual",
        "forbiddenInferences": ["treat_judge_verdict_as_s3_final_verdict", "accepted_claim"],
    }
    assert judge_policy["verdictMapping"]["not_affected"]["stance"] == "contextual"
    assert "target_safe" in judge_policy["verdictMapping"]["not_affected"]["forbiddenInferences"]
    assert judge_policy["diagnosticTriggers"] == [
        "verdict_unknown",
        "verdict_unsupported",
        "status_unknown",
        "status_unsupported",
        "status_requires_requery",
        "status_degraded_quality",
        "quality_gate_rejected",
        "quality_gate_accepted_with_caveats",
        "quality_gate_unsupported",
        "uncertainty_required_inputs_present",
        "uncertainty_conflicts_present",
        "follow_up_affordances_present",
    ]
    assert judge_policy["scalarEchoPolicy"] == {
        "maxScalarEchoChars": 128,
        "oversizedScalarRedaction": "<redacted-judge-answer-scalar:original_length>",
        "valueRedactionWarning": "judge_answer_scalar_value_redacted",
        "fields": ["verdict", "status", "qualityGate.gate"],
    }
    assert judge_policy["sourceRefExtraction"]["sourceArtifacts"] == [
        "sourceRepositoryArtifactId",
        "sourceArtifactId",
        "artifactId",
    ]
    assert judge_policy["sourceRefExtraction"]["maxEchoRefs"] == 64
    assert judge_policy["sourceRefExtraction"]["maxRefEchoChars"] == 512
    assert judge_policy["sourceRefExtraction"]["oversizedRefRedaction"] == "<redacted-source-ref:original_length>"
    assert judge_policy["sourceRefExtraction"]["truncationWarning"] == "source_evidence_refs_truncated"
    assert judge_policy["sourceRefExtraction"]["countFields"] == {
        "total": "evidencePlacement.sourceEvidenceRefTotalCount",
        "returned": "evidencePlacement.sourceEvidenceRefReturnedCount",
        "truncated": "evidencePlacement.sourceEvidenceRefsTruncated",
    }
    assert judge_policy["sourceRefExtraction"]["actionType"] == "validate_source_evidence_refs"
    assert judge_policy["diagnosticCodeEchoPolicy"] == {
        "maxCodeEchoChars": 128,
        "maxCodeEchoCount": 64,
        "warningPreviewCount": 8,
        "oversizedCodeRedaction": "<redacted-diagnostic-code:original_length>",
        "valueRedactionWarning": "diagnostic_code_value_redacted",
        "truncationWarning": "diagnostic_codes_truncated",
        "countFields": {
            "total": "evidencePlacement.diagnosticCodeTotalCount",
            "returned": "evidencePlacement.diagnosticCodeReturnedCount",
            "truncated": "evidencePlacement.diagnosticCodesTruncated",
        },
    }
    assert judge_policy["requiredInputEchoPolicy"] == {
        "maxInputEchoChars": 128,
        "maxInputEchoCount": 16,
        "oversizedInputRedaction": "<redacted-required-input:original_length>",
        "valueRedactionWarning": "required_input_value_redacted",
        "truncationWarning": "required_inputs_truncated",
        "countFields": {
            "total": "evidencePlacement.requiredInputTotalCount",
            "returned": "evidencePlacement.requiredInputReturnedCount",
            "truncated": "evidencePlacement.requiredInputsTruncated",
        },
    }
    assert judge_policy["followUpEchoPolicy"] == {
        "rawFieldsEchoed": False,
        "presenceOnly": True,
        "actionType": "follow_judge_affordance",
        "qualityWarning": "Judge follow-up affordances are present and should be routed before promotion.",
    }
    assert judge_policy["conflictEchoPolicy"] == {
        "rawFieldsEchoed": False,
        "presenceOnly": True,
        "qualityWarning": "Judge uncertainty conflicts are present; do not collapse them into a single claim.",
    }
    assert set(judge_policy["baselineForbiddenInferences"]) == set(analyst_brief_contract.BASELINE_FORBIDDEN_INFERENCES)


def test_analyst_brief_contract_endpoint_freezes_acquisition_artifact_echo_policy():
    resp = client.get("/v1/contracts/analyst-brief")

    assert resp.status_code == 200
    policy = resp.json()["acquisitionArtifactPolicy"]

    assert policy["schemaVersion"] == "acquisition-envelope-v1"
    assert policy["diagnosticCodeEchoPolicy"] == {
        "maxCodeEchoChars": 128,
        "maxCodeEchoCount": 64,
        "warningPreviewCount": 8,
        "oversizedCodeRedaction": "<redacted-acquisition-diagnostic-code:original_length>",
        "valueRedactionWarning": "acquisition_diagnostic_code_value_redacted",
        "truncationWarning": "acquisition_diagnostic_codes_truncated",
        "countFields": {
            "total": "evidencePlacement.diagnosticCodeTotalCount",
            "returned": "evidencePlacement.diagnosticCodeReturnedCount",
            "truncated": "evidencePlacement.diagnosticCodesTruncated",
        },
    }
    assert policy["missingInputEchoPolicy"] == {
        "maxInputEchoChars": 128,
        "maxInputEchoCount": 16,
        "oversizedInputRedaction": "<redacted-acquisition-required-input:original_length>",
        "valueRedactionWarning": "acquisition_required_input_value_redacted",
        "truncationWarning": "acquisition_required_inputs_truncated",
        "countFields": {
            "total": "evidencePlacement.requiredInputTotalCount",
            "returned": "evidencePlacement.requiredInputReturnedCount",
            "truncated": "evidencePlacement.requiredInputsTruncated",
        },
    }
    assert policy["evidenceRefEchoPolicy"] == {
        "maxRefEchoChars": 512,
        "maxRefsPerField": 64,
        "oversizedRefRedaction": "<redacted-acquisition-evidence-ref:original_length>",
        "valueRedactionWarning": "acquisition_evidence_ref_value_redacted",
        "sourceTruncationWarning": "acquisition_source_evidence_refs_truncated",
        "derivedTruncationWarning": "acquisition_derived_evidence_refs_truncated",
        "countFields": {
            "sourceTotal": "evidencePlacement.sourceEvidenceRefTotalCount",
            "sourceReturned": "evidencePlacement.sourceEvidenceRefReturnedCount",
            "sourceTruncated": "evidencePlacement.sourceEvidenceRefsTruncated",
            "derivedTotal": "evidencePlacement.derivedFromEvidenceRefTotalCount",
            "derivedReturned": "evidencePlacement.derivedFromEvidenceRefReturnedCount",
            "derivedTruncated": "evidencePlacement.derivedFromEvidenceRefsTruncated",
        },
    }
    assert policy["identityEchoPolicy"] == {
        "maxIdentityEchoChars": 128,
        "oversizedIdentityRedaction": "<redacted-acquisition-identity:original_length>",
        "valueRedactionWarning": "acquisition_identity_value_redacted",
        "fields": [
            "surface",
            "targetKnowledgeId",
            "acquisitionStatus",
            "acquisitionQualityGate",
            "consumerPolicy",
        ],
    }
    assert policy["stateEchoPolicy"] == {
        "maxStateEchoChars": 128,
        "oversizedStateRedaction": "<redacted-acquisition-state:original_length>",
        "valueRedactionWarning": "acquisition_state_value_redacted",
        "fields": ["providerState.state", "projectionState.state"],
    }
    assert policy["methodEchoPolicy"] == {
        "maxMethodEchoChars": 128,
        "maxMethodEchoCount": 32,
        "oversizedMethodRedaction": "<redacted-acquisition-method:original_length>",
        "valueRedactionWarning": "acquisition_method_value_redacted",
        "truncationWarning": "acquisition_methods_truncated",
        "fields": ["methodsSucceeded", "methodsRequiredForNoHit"],
    }
    assert policy["scopeForbiddenInferenceEchoPolicy"] == {
        "maxInferenceEchoChars": 128,
        "maxInferenceEchoCount": 32,
        "oversizedInferenceRedaction": "<redacted-acquisition-scope-forbidden-inference:original_length>",
        "valueRedactionWarning": "acquisition_scope_forbidden_inference_value_redacted",
        "truncationWarning": "acquisition_scope_forbidden_inferences_truncated",
        "field": "scope.forbiddenInferences",
    }


def test_acquisition_brief_bounds_diagnostic_code_and_missing_input_echoes():
    oversized_code = "secret-acquisition-diagnostic-code-" + ("x" * 100_000)
    oversized_input = "secret-acquisition-required-input-" + ("x" * 100_000)
    diagnostic_codes = [{"code": f"ACQ_DIAG_{index:03d}"} for index in range(70)]
    diagnostic_codes.append({"code": oversized_code})
    missing_inputs = [f"missing-input-{index:03d}" for index in range(20)]
    missing_inputs.append(oversized_input)

    brief = build_analyst_brief(_artifact(
        acquisitionStatus="input_insufficient",
        acquisitionQualityGate="rejected",
        consumerPolicy="do_not_use",
        diagnostics=diagnostic_codes,
        readiness={"missingInputs": missing_inputs},
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized_code not in payload
    assert oversized_input not in payload
    assert "ACQ_DIAG_063" in payload
    assert "ACQ_DIAG_064" not in payload
    assert "missing-input-015" in payload
    assert "missing-input-016" not in payload
    assert brief["evidencePlacement"]["diagnosticCodeTotalCount"] == 71
    assert brief["evidencePlacement"]["diagnosticCodeReturnedCount"] == 64
    assert brief["evidencePlacement"]["diagnosticCodesTruncated"] is True
    assert brief["evidencePlacement"]["requiredInputTotalCount"] == 21
    assert brief["evidencePlacement"]["requiredInputReturnedCount"] == 16
    assert brief["evidencePlacement"]["requiredInputsTruncated"] is True
    assert "acquisition_diagnostic_codes_truncated" in brief["qualityWarnings"]
    assert "acquisition_required_inputs_truncated" in brief["qualityWarnings"]
    assert any(len(a["requiredInputs"]) == 16 for a in brief["nextActions"] if a["actionType"] == "provide_missing_inputs")
    diagnostic_warning = next(
        warning for warning in brief["qualityWarnings"] if warning.startswith("Diagnostics present:")
    )
    assert "ACQ_DIAG_007" in diagnostic_warning
    assert "ACQ_DIAG_008" not in diagnostic_warning
    assert "+56 more returned codes" in diagnostic_warning


def test_acquisition_brief_bounds_source_and_derived_evidence_refs_without_echo():
    oversized_source = "secret-source-evidence-ref-" + ("x" * 100_000)
    oversized_derived = "secret-derived-evidence-ref-" + ("x" * 100_000)
    source_refs = [f"source-ref-{index:03d}" for index in range(70)] + [oversized_source]
    derived_refs = [f"derived-ref-{index:03d}" for index in range(70)] + [oversized_derived]

    brief = build_analyst_brief(_artifact(
        sourceEvidenceRefs=source_refs,
        derivedFromEvidenceRefs=derived_refs,
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized_source not in payload
    assert oversized_derived not in payload
    assert "source-ref-063" in payload
    assert "source-ref-064" not in payload
    assert "derived-ref-063" in payload
    assert "derived-ref-064" not in payload
    assert len(brief["evidencePlacement"]["sourceEvidenceRefs"]) == 64
    assert len(brief["evidencePlacement"]["derivedFromEvidenceRefs"]) == 64
    assert brief["evidencePlacement"]["sourceEvidenceRefTotalCount"] == 71
    assert brief["evidencePlacement"]["sourceEvidenceRefReturnedCount"] == 64
    assert brief["evidencePlacement"]["sourceEvidenceRefsTruncated"] is True
    assert brief["evidencePlacement"]["derivedFromEvidenceRefTotalCount"] == 71
    assert brief["evidencePlacement"]["derivedFromEvidenceRefReturnedCount"] == 64
    assert brief["evidencePlacement"]["derivedFromEvidenceRefsTruncated"] is True
    assert "acquisition_source_evidence_refs_truncated" in brief["qualityWarnings"]
    assert "acquisition_derived_evidence_refs_truncated" in brief["qualityWarnings"]


def test_acquisition_brief_redacts_oversized_identity_fields_without_echo():
    oversized_surface = "secret-surface-" + ("x" * 100_000)
    oversized_target = "secret-target-knowledge-id-" + ("x" * 100_000)
    oversized_policy = "secret-consumer-policy-" + ("x" * 100_000)
    oversized_status = "secret-status-" + ("x" * 100_000)
    oversized_gate = "secret-gate-" + ("x" * 100_000)

    brief = build_analyst_brief(_artifact(
        surface=oversized_surface,
        targetKnowledgeId=oversized_target,
        acquisitionStatus=oversized_status,
        acquisitionQualityGate=oversized_gate,
        consumerPolicy=oversized_policy,
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized_surface not in payload
    assert oversized_target not in payload
    assert oversized_policy not in payload
    assert oversized_status not in payload
    assert oversized_gate not in payload
    assert "<redacted-acquisition-identity:" in payload
    assert "acquisition_identity_value_redacted" in brief["qualityWarnings"]


def test_acquisition_brief_bounds_state_and_method_echoes_without_raw_leak():
    oversized_provider = "secret-provider-state-" + ("x" * 100_000)
    oversized_projection = "secret-projection-state-" + ("x" * 100_000)
    oversized_method = "secret-method-" + ("x" * 100_000)
    methods = [f"method-{index:03d}" for index in range(40)] + [oversized_method]

    brief = build_analyst_brief(_artifact(
        providerState={"state": oversized_provider},
        projectionState={"state": oversized_projection},
        methodsSucceeded=methods,
        readiness={"methodsRequiredForNoHit": methods},
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized_provider not in payload
    assert oversized_projection not in payload
    assert oversized_method not in payload
    assert "method-031" in payload
    assert "method-032" not in payload
    assert "<redacted-acquisition-state:" in payload
    assert "acquisition_state_value_redacted" in brief["qualityWarnings"]
    assert "acquisition_methods_truncated" in brief["qualityWarnings"]


def test_acquisition_brief_bounds_scope_forbidden_inferences_without_raw_leak():
    oversized_inference = "secret-scope-forbidden-inference-" + ("x" * 100_000)
    scope_forbidden = [f"scope-forbidden-{index:03d}" for index in range(40)]
    scope_forbidden.insert(0, oversized_inference)

    brief = build_analyst_brief(_artifact(
        scope={"forbiddenInferences": scope_forbidden},
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized_inference not in payload
    assert "scope-forbidden-030" in payload
    assert "scope-forbidden-031" not in payload
    assert "<redacted-acquisition-scope-forbidden-inference:" in payload
    assert "acquisition_scope_forbidden_inference_value_redacted" in brief["qualityWarnings"]
    assert "acquisition_scope_forbidden_inferences_truncated" in brief["qualityWarnings"]


def test_acquisition_brief_redacts_first_window_methods_without_raw_leak():
    oversized_method = "secret-method-first-window-" + ("x" * 100_000)

    brief = build_analyst_brief(_artifact(
        methodsSucceeded=[oversized_method],
        readiness={"methodsRequiredForNoHit": [oversized_method]},
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized_method not in payload
    assert "<redacted-acquisition-method:" in payload
    assert "acquisition_method_value_redacted" in brief["qualityWarnings"]


def test_acquisition_brief_uses_raw_method_identity_for_no_hit_authority():
    required = "secret-required-method-" + ("x" * 128)
    succeeded = "secret-succeeded-method-" + ("x" * 127)
    assert len(required) == len(succeeded)

    brief = build_analyst_brief(_artifact(
        acquisitionStatus="completed_no_hit",
        acquisitionQualityGate="accepted",
        consumerPolicy="scoped_no_hit_record_only",
        providerState={"state": "complete"},
        projectionState={"state": "complete"},
        methodsSucceeded=[succeeded],
        scope={
            "methodsRequiredForNoHit": [required],
            "noHitBasis": "package_identity",
        },
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert brief["stance"] == "diagnostic"
    assert brief["evidencePlacement"]["recommendedRole"] == "operational_diagnostic"
    assert required not in payload
    assert succeeded not in payload
    assert "<redacted-acquisition-method:" in payload
    assert "No-hit safety conditions are incomplete" in " ".join(brief["qualityWarnings"])


def test_completed_no_hit_requires_required_methods_attempted_and_succeeded():
    brief = build_analyst_brief(_artifact(
        acquisitionStatus="completed_no_hit",
        acquisitionQualityGate="accepted",
        consumerPolicy="scoped_no_hit_record_only",
        providerState={"state": "complete"},
        projectionState={"state": "complete"},
        methodsAttempted=[],
        methodsSucceeded=["exact_id_match"],
        scope={
            "methodsRequiredForNoHit": ["exact_id_match"],
            "noHitBasis": "package_identity",
        },
    ))

    assert brief["stance"] == "diagnostic"
    assert brief["evidencePlacement"]["recommendedRole"] == "operational_diagnostic"
    assert "No-hit safety conditions are incomplete" in " ".join(brief["qualityWarnings"])


def _judge_answer(**overrides):
    base = {
        "schemaVersion": "s5-judge-answer-v1",
        "status": "complete",
        "verdict": "affected",
        "notFinalSecurityVerdict": True,
        "verdictAuthority": "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict",
        "qualityGate": {"gate": "accepted", "diagnostics": []},
        "uncertainty": {"reason": None, "evidenceGaps": [], "requiredInputs": [], "conflicts": []},
        "followUpAffordances": [],
        "evidence": {
            "sourceCodeKg": {
                "resolved": True,
                "sourceArtifacts": [{"sourceArtifactId": "artifact-compile-db"}],
                "graphNodes": [{"sourceGraphNodeId": "node-curl-call"}],
                "evidenceSnippets": [{"evidenceSnippetId": "snippet-curl-call"}],
            },
            "threatRetrieval": {"candidateEvidence": [{"advisoryId": "adv-cve-2026-0001"}]},
        },
    }
    base.update(overrides)
    return base


def test_judge_answer_brief_treats_affected_as_context_not_final_verdict():
    brief = build_analyst_brief(_judge_answer())

    assert brief["schemaVersion"] == "s5-analyst-brief-v1"
    assert brief["stance"] == "contextual"
    assert brief["evidencePlacement"]["recommendedRole"] == "knowledge_context"
    assert brief["evidencePlacement"]["consumerPolicy"] == "judge_verdict_context_only"
    assert "use_as_knowledge_context" in brief["allowedUses"]
    assert "treat_judge_verdict_as_s3_final_verdict" in brief["forbiddenInferences"]
    assert "accepted_claim" in brief["forbiddenInferences"]
    assert "s5-judge-answer-v1" in brief["contractRefs"]
    assert any(a["actionType"] == "validate_source_evidence_refs" for a in brief["nextActions"])


def test_judge_answer_brief_bounds_scalar_echoes_without_raw_leak():
    oversized_verdict = "secret-verdict-" + ("x" * 100_000)
    oversized_status = "secret-status-" + ("x" * 100_000)
    oversized_gate = "secret-gate-" + ("x" * 100_000)

    brief = build_analyst_brief(_judge_answer(
        verdict=oversized_verdict,
        status=oversized_status,
        qualityGate={"gate": oversized_gate, "diagnostics": []},
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert brief["stance"] == "diagnostic"
    assert oversized_verdict not in payload
    assert oversized_status not in payload
    assert oversized_gate not in payload
    assert "<redacted-judge-answer-scalar:" in payload
    assert "judge_answer_scalar_value_redacted" in brief["qualityWarnings"]
    assert "unsupported_judge_verdict" in brief["qualityWarnings"]
    assert "unsupported_judge_status" in brief["qualityWarnings"]
    assert "unsupported_judge_quality_gate" in brief["qualityWarnings"]


def test_judge_answer_brief_demotes_unsupported_status_and_quality_gate():
    brief = build_analyst_brief(_judge_answer(
        status="unexpected_complete",
        qualityGate={"gate": "unexpected_accepted", "diagnostics": []},
    ))

    assert brief["stance"] == "diagnostic"
    assert brief["evidencePlacement"]["recommendedRole"] == "operational_diagnostic"
    assert "unsupported_judge_status" in brief["qualityWarnings"]
    assert "unsupported_judge_quality_gate" in brief["qualityWarnings"]
    assert "use_for_retry_planning" in brief["allowedUses"]


def test_judge_answer_brief_extracts_canonical_source_repository_artifact_refs():
    brief = build_analyst_brief(_judge_answer(evidence={
        "sourceCodeKg": {
            "resolved": True,
            "sourceArtifacts": [{"sourceRepositoryArtifactId": "source-artifact-canonical"}],
            "graphNodes": [],
            "evidenceSnippets": [],
        }
    }))

    assert brief["evidencePlacement"]["sourceEvidenceRefs"] == ["source-artifact-canonical"]
    assert any(a["actionType"] == "validate_source_evidence_refs" for a in brief["nextActions"])


def test_judge_answer_brief_bounds_source_evidence_ref_echoes():
    source_artifacts = [
        {"sourceRepositoryArtifactId": f"source-artifact-{index:03d}"}
        for index in range(80)
    ]
    graph_nodes = [{"sourceGraphNodeId": f"source-node-{index:03d}"} for index in range(80)]
    snippets = [{"evidenceSnippetId": f"snippet-{index:03d}"} for index in range(80)]

    brief = build_analyst_brief(_judge_answer(evidence={
        "sourceCodeKg": {
            "resolved": True,
            "sourceArtifacts": source_artifacts,
            "graphNodes": graph_nodes,
            "evidenceSnippets": snippets,
        }
    }))

    assert len(brief["evidencePlacement"]["sourceEvidenceRefs"]) == 64
    assert brief["evidencePlacement"]["sourceEvidenceRefTotalCount"] == 240
    assert brief["evidencePlacement"]["sourceEvidenceRefReturnedCount"] == 64
    assert brief["evidencePlacement"]["sourceEvidenceRefsTruncated"] is True
    assert brief["evidencePlacement"]["sourceEvidenceRefs"][0] == "source-artifact-000"
    assert "source-node-000" not in brief["evidencePlacement"]["sourceEvidenceRefs"]
    assert "source_evidence_refs_truncated" in brief["qualityWarnings"]
    assert any(a["actionType"] == "validate_source_evidence_refs" for a in brief["nextActions"])


def test_judge_answer_brief_redacts_oversized_source_evidence_refs_without_echo():
    oversized = "secret-source-ref-" + ("x" * 100_000)

    brief = build_analyst_brief(_judge_answer(evidence={
        "sourceCodeKg": {
            "resolved": True,
            "sourceArtifacts": [{"sourceRepositoryArtifactId": oversized}],
            "graphNodes": [],
            "evidenceSnippets": [],
        }
    }))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized not in payload
    assert len(payload) < 8192
    assert brief["evidencePlacement"]["sourceEvidenceRefs"] == [
        "<redacted-source-ref:100018>"
    ]
    assert brief["evidencePlacement"]["sourceEvidenceRefTotalCount"] == 1
    assert brief["evidencePlacement"]["sourceEvidenceRefsTruncated"] is False
    assert "source_evidence_ref_value_redacted" in brief["qualityWarnings"]
    assert any(a["actionType"] == "validate_source_evidence_refs" for a in brief["nextActions"])


def test_judge_answer_brief_counts_distinct_oversized_same_length_refs_before_redaction():
    source_artifacts = [
        {"sourceRepositoryArtifactId": f"secret-source-ref-{index:03d}-" + ("x" * 1000)}
        for index in range(70)
    ]

    brief = build_analyst_brief(_judge_answer(evidence={
        "sourceCodeKg": {
            "resolved": True,
            "sourceArtifacts": source_artifacts,
            "graphNodes": [],
            "evidenceSnippets": [],
        }
    }))

    assert brief["evidencePlacement"]["sourceEvidenceRefTotalCount"] == 70
    assert brief["evidencePlacement"]["sourceEvidenceRefReturnedCount"] == 64
    assert brief["evidencePlacement"]["sourceEvidenceRefsTruncated"] is True
    assert len(brief["evidencePlacement"]["sourceEvidenceRefs"]) == 64
    assert set(brief["evidencePlacement"]["sourceEvidenceRefs"]) == {
        "<redacted-source-ref:1022>"
    }
    assert "source_evidence_refs_truncated" in brief["qualityWarnings"]
    assert "source_evidence_ref_value_redacted" in brief["qualityWarnings"]


def test_judge_answer_brief_redacts_oversized_diagnostic_codes_without_echo():
    oversized = "secret-diagnostic-code-" + ("x" * 100_000)

    brief = build_analyst_brief(_judge_answer(
        status="degraded_quality",
        qualityGate={"gate": "accepted_with_caveats", "diagnostics": [{"code": oversized}]},
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized not in payload
    assert len(payload) < 8192
    assert brief["evidencePlacement"]["diagnosticCodes"] == [
        "<redacted-diagnostic-code:100023>"
    ]
    assert "diagnostic_code_value_redacted" in brief["qualityWarnings"]
    assert any("Diagnostics present: <redacted-diagnostic-code:100023>." == warning for warning in brief["qualityWarnings"])


def test_judge_answer_brief_bounds_diagnostic_code_echo_count():
    diagnostics = [{"code": f"DIAG_{index:03d}"} for index in range(100)]

    brief = build_analyst_brief(_judge_answer(
        status="degraded_quality",
        qualityGate={"gate": "accepted_with_caveats", "diagnostics": diagnostics},
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert len(brief["evidencePlacement"]["diagnosticCodes"]) == 64
    assert brief["evidencePlacement"]["diagnosticCodeTotalCount"] == 100
    assert brief["evidencePlacement"]["diagnosticCodeReturnedCount"] == 64
    assert brief["evidencePlacement"]["diagnosticCodesTruncated"] is True
    assert "DIAG_063" in payload
    assert "DIAG_064" not in payload
    assert "diagnostic_codes_truncated" in brief["qualityWarnings"]


def test_judge_answer_brief_bounds_diagnostic_warning_preview():
    diagnostics = [{"code": f"DIAG_{index:03d}"} for index in range(20)]

    brief = build_analyst_brief(_judge_answer(
        status="degraded_quality",
        qualityGate={"gate": "accepted_with_caveats", "diagnostics": diagnostics},
    ))
    diagnostic_warning = next(
        warning for warning in brief["qualityWarnings"] if warning.startswith("Diagnostics present:")
    )

    assert "DIAG_007" in diagnostic_warning
    assert "DIAG_008" not in diagnostic_warning
    assert "+12 more returned codes" in diagnostic_warning
    assert "DIAG_019" in brief["evidencePlacement"]["diagnosticCodes"]


def test_judge_answer_brief_redacts_oversized_required_inputs_without_echo():
    oversized = "secret-required-input-" + ("x" * 100_000)
    redacted = f"<redacted-required-input:{len(oversized)}>"

    brief = build_analyst_brief(_judge_answer(
        status="requires_requery",
        verdict="unknown",
        uncertainty={
            "reason": "missing deterministic input",
            "evidenceGaps": ["input missing"],
            "requiredInputs": [oversized],
            "conflicts": [],
        },
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized not in payload
    assert len(payload) < 8192
    assert redacted in payload
    assert "required_input_value_redacted" in brief["qualityWarnings"]
    assert any(a["requiredInputs"] == [redacted] for a in brief["nextActions"])
    assert any(redacted in question for question in brief["humanQuestions"])


def test_judge_answer_brief_bounds_required_input_echo_count():
    required_inputs = [f"required-input-{index:03d}" for index in range(40)]

    brief = build_analyst_brief(_judge_answer(
        status="requires_requery",
        verdict="unknown",
        uncertainty={
            "reason": "many deterministic follow-up inputs",
            "evidenceGaps": ["input missing"],
            "requiredInputs": required_inputs,
            "conflicts": [],
        },
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert brief["evidencePlacement"]["requiredInputTotalCount"] == 40
    assert brief["evidencePlacement"]["requiredInputReturnedCount"] == 16
    assert brief["evidencePlacement"]["requiredInputsTruncated"] is True
    assert "required-input-015" in payload
    assert "required-input-016" not in payload
    assert "required_inputs_truncated" in brief["qualityWarnings"]
    assert any(len(a["requiredInputs"]) == 16 for a in brief["nextActions"] if a["actionType"] == "provide_missing_inputs")


def test_judge_answer_brief_treats_follow_up_affordance_fields_as_presence_only():
    oversized = "secret-followup-field-" + ("x" * 100_000)

    brief = build_analyst_brief(_judge_answer(
        status="requires_requery",
        verdict="unknown",
        followUpAffordances=[
            {
                "requestKind": oversized,
                "ownerLane": oversized,
                "reason": oversized,
            }
        ],
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized not in payload
    assert len(payload) < 8192
    assert brief["stance"] == "diagnostic"
    assert any(a["actionType"] == "follow_judge_affordance" for a in brief["nextActions"])
    assert "Judge follow-up affordances are present and should be routed before promotion." in brief["qualityWarnings"]


def test_judge_answer_brief_treats_conflict_fields_as_presence_only():
    oversized = "secret-conflict-field-" + ("x" * 100_000)

    brief = build_analyst_brief(_judge_answer(
        status="requires_requery",
        verdict="unknown",
        uncertainty={
            "reason": "conflict requires external resolution",
            "evidenceGaps": ["conflict resolution"],
            "requiredInputs": [],
            "conflicts": [
                {
                    "conflictRecordId": oversized,
                    "conflictKind": oversized,
                    "issueCode": oversized,
                    "conflictingValues": [oversized],
                }
            ],
        },
    ))
    payload = json.dumps(brief, sort_keys=True)

    assert oversized not in payload
    assert len(payload) < 8192
    assert brief["stance"] == "diagnostic"
    assert "Judge uncertainty conflicts are present; do not collapse them into a single claim." in brief["qualityWarnings"]


def test_judge_answer_brief_unknown_required_inputs_is_diagnostic_with_requery_guidance():
    brief = build_analyst_brief(_judge_answer(
        status="requires_requery",
        verdict="unknown",
        qualityGate={"gate": "accepted_with_caveats", "diagnostics": [{"code": "SOURCE_KG_CONTEXT_PARTIAL"}]},
        uncertainty={
            "reason": "source context is partial",
            "evidenceGaps": ["complete Source KG context"],
            "requiredInputs": ["complete_or_consistent_source_code_kg_context"],
            "conflicts": [],
        },
        followUpAffordances=[{"requestKind": "source_context_enrichment", "ownerLane": "S3/S4", "reason": "partial"}],
    ))

    assert brief["stance"] == "diagnostic"
    assert brief["evidencePlacement"]["recommendedRole"] == "operational_diagnostic"
    assert "use_as_operational_diagnostic" in brief["allowedUses"]
    assert any(a["actionType"] == "provide_missing_inputs" for a in brief["nextActions"])
    assert any(a["actionType"] == "rerun_judge_with_required_inputs" for a in brief["nextActions"])
    assert any(a["actionType"] == "follow_judge_affordance" for a in brief["nextActions"])
    assert "complete_or_consistent_source_code_kg_context" in brief["nextActions"][0]["requiredInputs"]
    assert "SOURCE_KG_CONTEXT_PARTIAL" in brief["evidencePlacement"]["diagnosticCodes"]


def test_judge_answer_brief_unknown_verdict_forbids_absence_claims():
    brief = build_analyst_brief(_judge_answer(verdict="unknown", status="requires_requery"))

    assert brief["stance"] == "diagnostic"
    assert "absence_of_vulnerability" in brief["forbiddenInferences"]
    assert "negative_absence_claim" in brief["forbiddenInferences"]


def test_judge_answer_brief_missing_status_is_diagnostic_not_contextual():
    answer = _judge_answer()
    answer.pop("status")

    brief = build_analyst_brief(answer)

    assert brief["stance"] == "diagnostic"
    assert brief["evidencePlacement"]["recommendedRole"] == "operational_diagnostic"
    assert "Judge status is `unknown`." in brief["qualityWarnings"]
    assert "use_as_operational_diagnostic" in brief["allowedUses"]


def test_judge_answer_brief_unsupported_verdict_is_diagnostic_not_contextual():
    brief = build_analyst_brief(_judge_answer(verdict="conflicting", status="complete"))

    assert brief["stance"] == "diagnostic"
    assert brief["evidencePlacement"]["recommendedRole"] == "operational_diagnostic"
    assert "unsupported_judge_verdict" in brief["qualityWarnings"]
    assert "use_as_operational_diagnostic" in brief["allowedUses"]


def test_judge_answer_brief_blocks_untrusted_final_verdict_boundary():
    brief = build_analyst_brief(_judge_answer(notFinalSecurityVerdict=False))

    assert brief["stance"] == "blocked"
    assert brief["evidencePlacement"]["recommendedRole"] == "do_not_use"
    assert "judge_final_verdict_boundary_missing" in brief["qualityWarnings"]
    assert any(a["actionType"] == "send_valid_judge_answer" for a in brief["nextActions"])


def test_judge_answer_brief_not_affected_still_forbids_clean_pass():
    brief = build_analyst_brief(_judge_answer(verdict="not_affected"))

    assert brief["stance"] == "contextual"
    assert "s5_clean_pass" in brief["forbiddenInferences"]
    assert "target_safe" in brief["forbiddenInferences"]
    assert "complete_project_safety" in brief["forbiddenInferences"]


def test_analyst_brief_api_accepts_judge_answer_artifact_without_timeout_header():
    resp = client.post(
        "/v1/analyst-brief",
        json={"artifact": _judge_answer(), "audience": "s3", "language": "ko"},
        headers={"X-Request-Id": "req-analyst-brief-judge"},
    )

    assert resp.status_code == 200
    assert resp.headers["X-Request-Id"] == "req-analyst-brief-judge"
    body = resp.json()
    assert body["schemaVersion"] == "s5-analyst-brief-v1"
    assert body["stance"] == "contextual"
    assert body["evidencePlacement"]["consumerPolicy"] == "judge_verdict_context_only"
