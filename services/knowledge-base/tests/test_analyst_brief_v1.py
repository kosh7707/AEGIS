"""S5 Analyst Brief v1 contract tests."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

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
