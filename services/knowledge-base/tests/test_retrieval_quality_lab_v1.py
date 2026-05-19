from __future__ import annotations

from app.evaluation.retrieval_quality_lab import (
    REQUIRED_FAMILIES,
    judge_retrieval_observation_from_answer,
    load_retrieval_quality_lab,
    summarize_retrieval_quality_lab,
    validate_judge_policy_case_observation,
    validate_retrieval_quality_lab,
)
from app.judge.service import build_judge_answer
from app.serving import reset_decision_cache

from tests.test_serving_requery_contract_v1 import _repo, _request, _source_context


def test_retrieval_quality_lab_manifest_is_schema_valid_and_covers_families():
    manifest = load_retrieval_quality_lab()

    assert validate_retrieval_quality_lab(manifest) == []
    families = {case["family"] for case in manifest["cases"]}
    assert REQUIRED_FAMILIES <= families
    assert len(manifest["cases"]) >= 8


def test_retrieval_quality_lab_report_has_policy_and_quality_breakdowns():
    report = summarize_retrieval_quality_lab(load_retrieval_quality_lab())

    assert report["systemStability"]["status"] == "passed"
    assert report["qualityGate"]["status"] == "evaluated"
    assert report["policySummary"]["topKMeans"] == "final_returned_count"
    assert report["policySummary"]["casesWithCandidatePoolLargerThanTopK"] >= 8
    breakdowns = report["qualityGate"]["breakdowns"]
    assert "keyword_match" in breakdowns["method"]
    assert "affectedness_evidence" in breakdowns["method"]
    assert "judge_threat_context" in breakdowns["queryIntent"]
    assert "code_context" in breakdowns["queryIntent"]
    assert "code_graph" in breakdowns["corpusPartition"]
    assert "embedded-system-specialization" in breakdowns["profile"]
    assert report["qualityGate"]["metrics"]["caseCount"] >= 10


def test_retrieval_quality_lab_covers_judge_threat_context_policy_cases():
    manifest = load_retrieval_quality_lab()
    cases = {case["caseId"]: case for case in manifest["cases"]}

    affectedness_first = cases["rq-judge-affectedness-first-topk"]
    assert affectedness_first["surface"] == "evidenceGroundedJudge"
    assert affectedness_first["queryIntent"] == "judge_threat_context"
    assert affectedness_first["methodsUsed"][0] == "affectedness_evidence"
    assert affectedness_first["retrievedCandidateIds"][0] == "CVE-2026-0001"
    assert affectedness_first["runtimeObservation"]["verdictLinkedEvidenceOutranksRiskOnlyContext"] is True
    assert affectedness_first["runtimeObservation"]["topK"] == 1
    assert affectedness_first["runtimeObservation"]["negativeEvidenceAllowed"] is False

    fusion = cases["rq-judge-multisource-alias-fusion"]
    assert fusion["surface"] == "evidenceGroundedJudge"
    assert fusion["queryIntent"] == "judge_threat_context"
    assert fusion["runtimeObservation"]["equivalenceKey"] == "CVE-2026-0001"
    assert set(fusion["runtimeObservation"]["equivalentSourceKinds"]) >= {"NVD_CVE", "GHSA", "OSV"}
    assert fusion["runtimeObservation"]["equivalentAdvisoryCount"] >= 3
    assert fusion["runtimeObservation"]["negativeEvidenceAllowed"] is False


def test_retrieval_quality_lab_rejects_offline_metric_terms_in_runtime_observation():
    manifest = load_retrieval_quality_lab()
    manifest["cases"][0]["runtimeObservation"]["note"] = "do not leak recall precision fp fn into runtime"

    issues = validate_retrieval_quality_lab(manifest)

    assert any("offline metric vocabulary" in issue for issue in issues)


def test_retrieval_quality_lab_judge_cases_are_backed_by_live_judge_observations(tmp_path):
    manifest = load_retrieval_quality_lab()
    cases = {case["caseId"]: case for case in manifest["cases"]}
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-9999",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-9999",
        payload={
            "externalId": "CVE-2099-9999",
            "aliases": ["CVE-2099-9999"],
            "packageIdentityId": "pkg:generic/curl",
            "cweIds": ["CWE-78"],
        },
        freshness={"fixture": True},
    )
    repo.upsert_risk_signal(
        risk_signal_id="risk:CVSS:CVE-2099-9999",
        advisory_id="advisory:NVD_CVE:CVE-2099-9999",
        signal_kind="CVSS",
        source_kind="NVD_CVE",
        signal_value=10.0,
        payload={"cve": "CVE-2099-9999", "baseScore": 10.0},
        provenance={"fixture": "higher-risk-context"},
    )

    affectedness_answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    affectedness_observation = judge_retrieval_observation_from_answer(affectedness_answer)

    assert validate_judge_policy_case_observation(
        cases["rq-judge-affectedness-first-topk"],
        affectedness_observation,
    ) == []

    fusion_answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    fusion_observation = judge_retrieval_observation_from_answer(fusion_answer)

    assert validate_judge_policy_case_observation(
        cases["rq-judge-multisource-alias-fusion"],
        fusion_observation,
    ) == []
