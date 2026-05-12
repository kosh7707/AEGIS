from __future__ import annotations

from app.evaluation.retrieval_quality_lab import (
    REQUIRED_FAMILIES,
    load_retrieval_quality_lab,
    summarize_retrieval_quality_lab,
    validate_retrieval_quality_lab,
)


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
    assert "code_context" in breakdowns["queryIntent"]
    assert "code_graph" in breakdowns["corpusPartition"]
    assert "embedded-system-specialization" in breakdowns["profile"]
    assert report["qualityGate"]["metrics"]["caseCount"] >= 8


def test_retrieval_quality_lab_rejects_offline_metric_terms_in_runtime_observation():
    manifest = load_retrieval_quality_lab()
    manifest["cases"][0]["runtimeObservation"]["note"] = "do not leak recall precision fp fn into runtime"

    issues = validate_retrieval_quality_lab(manifest)

    assert any("offline metric vocabulary" in issue for issue in issues)
