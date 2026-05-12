from __future__ import annotations

from app.evaluation.golden_set import (
    OFFLINE_METRIC_FIELDS,
    REQUIRED_CVE_CASE_IDS,
    REQUIRED_EVIDENCE_POLICIES,
    REQUIRED_FAMILIES,
    REQUIRED_RETRIEVAL_CASE_IDS,
    RUNTIME_STATUS_WORDS,
    build_gate_report,
    compute_quality_metrics,
    load_golden_set,
    validate_manifest,
)


def _cases_by_id():
    manifest = load_golden_set()
    return {case["caseId"]: case for case in manifest["cases"]}


def test_golden_set_manifest_is_schema_valid():
    manifest = load_golden_set()

    assert validate_manifest(manifest) == []
    assert manifest["schemaVersion"] == "s5-golden-set-v1"
    assert manifest["goldenSetVersion"] == "golden-set-v1"


def test_golden_set_covers_required_families_and_cases():
    manifest = load_golden_set()
    case_ids = {case["caseId"] for case in manifest["cases"]}
    families = {case["family"] for case in manifest["cases"]}
    policies = {case["consumerPolicy"] for case in manifest["cases"]}

    assert REQUIRED_FAMILIES <= families
    assert REQUIRED_CVE_CASE_IDS <= case_ids
    assert REQUIRED_RETRIEVAL_CASE_IDS <= case_ids
    assert REQUIRED_EVIDENCE_POLICIES <= policies


def test_runtime_observations_do_not_expose_offline_quality_metrics():
    manifest = load_golden_set()

    for case in manifest["cases"]:
        runtime_fields = set(case["runtimeObservation"])
        assert runtime_fields.isdisjoint(OFFLINE_METRIC_FIELDS), case["caseId"]
        assert "acquisitionStatus" in case["runtimeObservation"]
        assert case["runtimeObservation"]["acquisitionStatus"] in RUNTIME_STATUS_WORDS


def test_manifest_validation_rejects_offline_metric_vocabulary_inside_runtime_values():
    manifest = load_golden_set()
    manifest["cases"][0]["runtimeObservation"]["notes"] = "runtime must not say TP/FN, recall, precision, NDCG, or MRR"

    issues = validate_manifest(manifest)

    assert any("runtimeObservation contains offline metric vocabulary" in issue for issue in issues)


def test_gate_report_separates_stability_readiness_and_quality_gate():
    manifest = load_golden_set()

    report = build_gate_report(manifest)

    assert report["systemStability"]["status"] == "passed"
    assert report["evidenceReadiness"]["status"] == "passed"
    assert report["qualityGate"]["status"] == "evaluated"
    assert report["qualityGate"]["offlineOnly"] is True
    assert report["qualityGate"]["metrics"]["caseCount"] > 0
    assert "precisionAtK" in report["qualityGate"]["metrics"]
    assert "recallAtK" in report["qualityGate"]["metrics"]
    assert report["qualityGate"]["metrics"]["falsePositiveCount"] >= 1
    assert report["qualityGate"]["metrics"]["falseNegativeCount"] >= 1
    manifest_statuses = {case["runtimeObservation"]["acquisitionStatus"] for case in manifest["cases"]}
    assert manifest_statuses <= set(report["runtimeStatusVocabulary"])
    assert "stale_cache_only" in report["runtimeStatusVocabulary"]


def test_quality_breakdowns_include_method_query_partition_and_profile_axes():
    manifest = load_golden_set()

    quality = compute_quality_metrics(manifest)
    breakdowns = quality["breakdowns"]

    assert "keyword_match" in breakdowns["method"]
    assert "constrained_embedding_rerank" in breakdowns["method"]
    assert "weakness_context" in breakdowns["queryIntent"]
    assert "public_vulnerability" in breakdowns["corpusPartition"]
    assert "automotive-specialization" in breakdowns["profile"]
    assert breakdowns["method"]["keyword_match"]["caseCount"] >= 2


def test_quality_gate_includes_g009_retrieval_quality_summary_offline_only():
    manifest = load_golden_set()

    report = build_gate_report(manifest)
    summary = report["qualityGate"]["retrievalQuality"]

    assert summary["schemaVersion"] == "s5-g009-retrieval-quality-summary-v1"
    assert summary["offlineOnly"] is True
    assert summary["runtimeTraceFieldsExcluded"] is True
    assert summary["retrievalCaseCount"] >= 1
    assert summary["breakdownsPresent"] == {
        "method": True,
        "queryIntent": True,
        "corpusPartition": True,
        "profile": True,
    }
    assert summary["globalEmbeddingPolicy"] == {
        "method": "global_embedding_search",
        "trust": "low",
        "caseCovered": True,
        "negativeEvidenceAllowed": False,
    }


def test_retrieval_cases_encode_s3_keyword_embedding_scenarios():
    cases = _cases_by_id()

    no_auto = cases["retrieval-command-exec-no-automotive-keyword"]
    assert "automotive-specialization" not in no_auto["profiles"]
    assert "CWE-78" in no_auto["expectedCandidateIds"]

    keyword_absence = cases["retrieval-keyword-absence-not-no-hit"]
    assert "completed_no_hit" in keyword_absence["runtimeObservation"]["forbiddenInferences"]

    weak_fp = cases["retrieval-keyword-fp-weak-candidate"]
    assert weak_fp["expectedCandidateIds"] == []
    assert weak_fp["retrievedCandidateIds"]

    keyword_fn = cases["retrieval-keyword-fn-offline-miss-only"]
    assert keyword_fn["expectedCandidateIds"]
    assert keyword_fn["retrievedCandidateIds"] == []
    assert keyword_fn["qualityOracle"]["evaluated"] is True

    cpe_alias = cases["retrieval-package-identity-alias-no-nvd-keyword-only"]
    assert "alias_resolution" in cpe_alias["methodsUsed"]
    assert "cpe_lookup" in cpe_alias["methodsUsed"]


def test_cve_cases_separate_candidate_evaluation_from_discovery():
    cases = _cases_by_id()

    scoped_no_hit = cases["cve-candidate-range-out-discovery-no-hit"]
    assert scoped_no_hit["surface"] == "cveCandidateEvaluation"
    assert scoped_no_hit["consumerPolicy"] == "scoped_no_hit_record_only"
    assert scoped_no_hit["evidenceReadinessOracle"]["mayBeNegativeEvidence"] is True

    other_hit = cases["cve-candidate-range-out-discovery-other-hit"]
    assert other_hit["surface"] == "cveDiscovery"
    assert other_hit["expectedCandidateIds"] == ["CVE-2026-0002"]

    keyword_miss = cases["cve-keyword-only-no-result-not-no-hit"]
    assert keyword_miss["runtimeObservation"]["acquisitionStatus"] == "incomplete_acquisition"
    assert "completed_no_hit" in keyword_miss["runtimeObservation"]["forbiddenInferences"]


def test_etl_transform_oracles_capture_raw_normalized_provenance_and_freshness():
    manifest = load_golden_set()
    etl_cases = [case for case in manifest["cases"] if case["family"] == "etl-transform"]

    assert len(etl_cases) >= 2
    for case in etl_cases:
        transform = case["transformOracle"]
        assert transform["rawInput"]
        assert transform["normalizedExpected"]
        assert transform["transformDiagnostics"]
        assert transform["provenanceExpectations"]
        assert transform["freshnessExpectations"]


def test_evidence_readiness_policy_slots_are_explicit_for_s3_consumers():
    cases = _cases_by_id()

    contextual = cases["evidence-contextual-only-slot"]
    assert contextual["consumerPolicy"] == "contextual_only"
    assert contextual["evidenceReadinessOracle"]["maySupportClaim"] is False

    diagnostic = cases["evidence-diagnostic-only-slot"]
    assert diagnostic["consumerPolicy"] == "diagnostic_only"
    assert diagnostic["runtimeObservation"]["acquisitionStatus"] == "incomplete_acquisition"

    scoped_no_hit = cases["evidence-scoped-no-hit-slot"]
    assert scoped_no_hit["consumerPolicy"] == "scoped_no_hit_record_only"
    assert scoped_no_hit["evidenceReadinessOracle"]["mayBeNegativeEvidence"] is True

    derived_support = cases["evidence-s3-derived-local-support-slot"]
    assert derived_support["consumerPolicy"] == "s3_may_derive_local_support_if_refs_validate"
    assert derived_support["evidenceReadinessOracle"]["maySupportClaim"] is True
    assert "targetLocalValidationRequired" in derived_support["evidenceReadinessOracle"]["requiredDiagnostics"]
