"""CVE candidate-evaluation/discovery split helper tests."""

from __future__ import annotations

from app.cve.acquisition_split import (
    CANDIDATE_RANGE_OUT_FORBIDDEN_INFERENCES,
    OFFLINE_QUALITY_RUNTIME_FORBIDDEN_TOKENS,
    candidate_methods,
    cve_method_plan,
    provider_methods_succeeded,
)


def test_cve_method_completeness_matrix_is_conservative():
    commit_plan = cve_method_plan({
        "name": "libfoo",
        "version": "1.0.0",
        "repoUrl": "https://github.com/org/libfoo.git",
        "commit": "abc123",
    })
    assert commit_plan["primaryMethod"] == "osv_commit"
    assert commit_plan["methodsRequiredForNoHit"] == ["osv_commit", "nvd_cpe"]
    assert commit_plan["noHitEligible"] is True

    repo_plan = cve_method_plan({
        "name": "libfoo",
        "version": "1.0.0",
        "repoUrl": "https://github.com/org/libfoo.git",
    })
    assert repo_plan["primaryMethod"] == "nvd_cpe"
    assert repo_plan["methodsRequiredForNoHit"] == ["nvd_cpe"]
    assert repo_plan["noHitEligible"] is True

    keyword_plan = cve_method_plan({"name": "libfoo", "version": "1.0.0"})
    assert keyword_plan["primaryMethod"] == "nvd_keyword"
    assert keyword_plan["methodsRequiredForNoHit"] == ["nvd_keyword"]
    assert keyword_plan["noHitEligible"] is False
    assert keyword_plan["noHitBasis"] == "keyword_only_no_result"


def test_candidate_methods_require_exact_id_and_range_eval():
    plan = cve_method_plan({
        "name": "libfoo",
        "version": "1.0.0",
        "repoUrl": "https://github.com/org/libfoo.git",
    })
    methods = candidate_methods(plan)

    assert methods["methodsRequiredForNoHit"] == ["exact_id_match", "provider_range_eval", "nvd_cpe"]
    assert {"exact_id_match", "provider_range_eval", "nvd_cpe", "nvd_keyword"} <= set(methods["methodsAttempted"])


def test_provider_method_success_never_upgrades_keyword_miss_to_no_hit():
    keyword_plan = cve_method_plan({"name": "libfoo", "version": "1.0.0"})
    succeeded = provider_methods_succeeded(keyword_plan, {"cves": [], "total": 0}, status="incomplete_acquisition")
    assert succeeded == ["nvd_keyword"]
    assert keyword_plan["noHitEligible"] is False


def test_range_out_forbidden_inferences_and_offline_vocab_are_explicitly_separate():
    assert {"library_safe", "no_other_cves", "target_clean"} <= set(CANDIDATE_RANGE_OUT_FORBIDDEN_INFERENCES)
    assert {"true_positive", "false_positive", "false_negative", "recall", "precision", "NDCG", "MRR"} <= set(OFFLINE_QUALITY_RUNTIME_FORBIDDEN_TOKENS)
