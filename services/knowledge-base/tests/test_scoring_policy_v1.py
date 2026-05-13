from __future__ import annotations

import json

import pytest

from app.quality.scoring_policy import ScoringPolicyError, evaluate_score_vector, load_scoring_policy


def _good_vector(**overrides):
    vector = {
        "retrievalRelevance": 0.0,
        "identityConfidence": 0.9,
        "affectednessConfidence": 0.9,
        "versionRangeConfidence": 0.9,
        "evidenceStrength": 0.9,
        "sourceReliability": 0.9,
        "freshness": 0.9,
        "coverageScore": 0.9,
        "conflictPenalty": 0.0,
        "controlCompliance": 1.0,
        "overallAnswerability": 0.9,
    }
    vector.update(overrides)
    return vector


def test_default_scoring_policy_loads_with_identity_hash_and_profiles():
    policy = load_scoring_policy()

    assert policy["schemaVersion"] == "s5-scoring-policy-v1"
    assert policy["policyId"] == "s5-default-scoring-policy"
    assert policy["policyVersion"] == "v1"
    assert policy["policyHash"].startswith("sha256:")
    assert {"strict", "balanced", "exploratory"} <= set(policy["profiles"])
    assert {"etl_projection", "serving"} <= set(policy["profiles"]["balanced"])


def test_policy_hash_changes_when_runtime_policy_file_changes(tmp_path):
    policy = load_scoring_policy()
    path1 = tmp_path / "policy1.json"
    path2 = tmp_path / "policy2.json"
    raw = {key: value for key, value in policy.items() if key not in {"policyHash", "policyPath", "policySource"}}
    path1.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    changed = json.loads(json.dumps(raw))
    changed["profiles"]["balanced"]["serving"]["overallAnswerability"] = 0.61
    path2.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")

    assert load_scoring_policy(path1)["policyHash"] != load_scoring_policy(path2)["policyHash"]


def test_score_policy_profiles_strict_rejects_where_balanced_caveats():
    vector = _good_vector(identityConfidence=0.6, affectednessConfidence=0.6, versionRangeConfidence=0.6, evidenceStrength=0.6, sourceReliability=0.6, freshness=0.6, coverageScore=0.6, overallAnswerability=0.49)

    strict = evaluate_score_vector(vector, phase="serving", profile="strict")
    balanced = evaluate_score_vector(vector, phase="serving", profile="balanced")

    assert strict["gate"] == "rejected"
    assert strict["hardFail"] is True
    assert balanced["gate"] == "accepted_with_caveats"
    assert balanced["hardFail"] is False
    assert balanced["appliedProfile"] == "balanced"
    assert balanced["requestedProfile"] is None
    assert balanced["rejectedProfiles"] == []


def test_score_policy_hard_blockers_reject_control_and_conflict():
    low_control = evaluate_score_vector(_good_vector(controlCompliance=0.0), phase="serving", profile="exploratory")
    high_conflict = evaluate_score_vector(_good_vector(conflictPenalty=1.0), phase="serving", profile="exploratory")

    assert low_control["gate"] == "rejected"
    assert any(item["field"] == "controlCompliance" for item in low_control["failedThresholds"])
    assert high_conflict["gate"] == "rejected"
    assert any(item["field"] == "conflictPenalty" and item["direction"] == "max" for item in high_conflict["failedThresholds"])


def test_score_policy_rejects_invalid_profile_phase_score_and_policy(tmp_path):
    with pytest.raises(ScoringPolicyError):
        evaluate_score_vector(_good_vector(), phase="serving", profile="missing")
    with pytest.raises(ScoringPolicyError):
        evaluate_score_vector(_good_vector(), phase="runtime", profile="balanced")
    with pytest.raises(ScoringPolicyError):
        evaluate_score_vector({"identityConfidence": 1.0}, phase="serving", profile="balanced")

    policy = load_scoring_policy()
    bad = {key: value for key, value in policy.items() if key not in {"policyHash", "policyPath", "policySource"}}
    del bad["profiles"]["balanced"]["serving"]["overallAnswerability"]
    path = tmp_path / "bad-policy.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ScoringPolicyError):
        load_scoring_policy(path)
