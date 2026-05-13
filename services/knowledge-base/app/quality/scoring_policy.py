"""Runtime-configurable S5 scoring policy.

This module is intentionally deterministic and file-backed.  It does not call
GraphRAG, providers, or LLMs; it evaluates an already-computed score vector
against an audited policy file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCORE_VECTOR_FIELDS = (
    "retrievalRelevance",
    "identityConfidence",
    "affectednessConfidence",
    "versionRangeConfidence",
    "evidenceStrength",
    "sourceReliability",
    "freshness",
    "coverageScore",
    "conflictPenalty",
    "controlCompliance",
    "overallAnswerability",
)
THRESHOLD_FIELDS = tuple(
    "conflictPenaltyMax" if field == "conflictPenalty" else field
    for field in SCORE_VECTOR_FIELDS
)
REQUIRED_PROFILES = {"strict", "balanced", "exploratory"}
REQUIRED_PHASES = {"etl_projection", "serving"}
SCHEMA_VERSION = "s5-scoring-policy-v1"
EVALUATION_SCHEMA_VERSION = "s5-score-policy-evaluation-v1"


class ScoringPolicyError(ValueError):
    """Raised when a scoring policy or score vector is invalid."""


def _service_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_policy_path(path: str | Path | None = None) -> Path:
    if path is None:
        from app.config import settings

        path = settings.scoring_policy_path
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    cwd_candidate = Path.cwd() / candidate
    if cwd_candidate.exists():
        return cwd_candidate
    return _service_root() / candidate


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _policy_hash(policy: dict[str, Any]) -> str:
    canonical = {
        key: value
        for key, value in policy.items()
        if key not in {"policyHash", "policyPath", "policySource"}
    }
    return "sha256:" + hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()


def _as_float(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScoringPolicyError(f"{field} must be numeric")
    number = float(value)
    if number < 0.0 or number > 1.0:
        raise ScoringPolicyError(f"{field} must be between 0 and 1")
    return number


def validate_scoring_policy(policy: dict[str, Any]) -> None:
    if not isinstance(policy, dict):
        raise ScoringPolicyError("policy must be object")
    if policy.get("schemaVersion") != SCHEMA_VERSION:
        raise ScoringPolicyError(f"schemaVersion must be {SCHEMA_VERSION}")
    for field in ("policyId", "policyVersion"):
        if not isinstance(policy.get(field), str) or not policy[field].strip():
            raise ScoringPolicyError(f"{field} must be non-empty string")
    profiles = policy.get("profiles")
    if not isinstance(profiles, dict):
        raise ScoringPolicyError("profiles must be object")
    missing_profiles = REQUIRED_PROFILES - set(profiles)
    if missing_profiles:
        raise ScoringPolicyError(f"missing profiles: {sorted(missing_profiles)}")
    for profile_name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ScoringPolicyError(f"profiles.{profile_name} must be object")
        missing_phases = REQUIRED_PHASES - set(profile)
        if missing_phases:
            raise ScoringPolicyError(f"profiles.{profile_name} missing phases: {sorted(missing_phases)}")
        for phase_name, thresholds in profile.items():
            if phase_name not in REQUIRED_PHASES:
                raise ScoringPolicyError(f"unknown phase {phase_name!r} in profile {profile_name}")
            if not isinstance(thresholds, dict):
                raise ScoringPolicyError(f"profiles.{profile_name}.{phase_name} must be object")
            missing_thresholds = set(THRESHOLD_FIELDS) - set(thresholds)
            if missing_thresholds:
                raise ScoringPolicyError(f"profiles.{profile_name}.{phase_name} missing thresholds: {sorted(missing_thresholds)}")
            for field in THRESHOLD_FIELDS:
                _as_float(thresholds[field], field=f"profiles.{profile_name}.{phase_name}.{field}")
            if not isinstance(thresholds.get("rejectOnThresholdFailure"), bool):
                raise ScoringPolicyError(f"profiles.{profile_name}.{phase_name}.rejectOnThresholdFailure must be bool")


def load_scoring_policy(path: str | Path | None = None) -> dict[str, Any]:
    policy_path = _resolve_policy_path(path)
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScoringPolicyError(f"scoring policy not found: {policy_path}") from exc
    except json.JSONDecodeError as exc:
        raise ScoringPolicyError(f"scoring policy is not valid JSON: {policy_path}: {exc}") from exc
    validate_scoring_policy(policy)
    return {
        **policy,
        "policyPath": str(policy_path),
        "policySource": str(policy_path),
        "policyHash": _policy_hash(policy),
    }


def _validate_score_vector(score_vector: dict[str, Any]) -> dict[str, float]:
    if not isinstance(score_vector, dict):
        raise ScoringPolicyError("scoreVector must be object")
    missing = set(SCORE_VECTOR_FIELDS) - set(score_vector)
    if missing:
        raise ScoringPolicyError(f"scoreVector missing fields: {sorted(missing)}")
    return {field: _as_float(score_vector[field], field=f"scoreVector.{field}") for field in SCORE_VECTOR_FIELDS}


def default_score_vector(
    *,
    source_resolved: bool,
    affectedness_status: str = "unknown",
    excluded: bool = False,
    hard_issue_count: int = 0,
    soft_issue_count: int = 0,
) -> dict[str, float]:
    evidence_strength = 0.85 if affectedness_status in {"affected", "known_not_affected"} else 0.35
    if excluded:
        evidence_strength = 0.45
    issue_penalty = min(1.0, hard_issue_count * 0.2 + soft_issue_count * 0.05)
    return {
        "retrievalRelevance": 0.0,
        "identityConfidence": max(0.0, (0.7 if affectedness_status != "unknown" else 0.35) - issue_penalty),
        "affectednessConfidence": max(0.0, (0.85 if affectedness_status == "affected" else (0.75 if affectedness_status == "known_not_affected" else 0.25)) - issue_penalty),
        "versionRangeConfidence": max(0.0, (0.8 if affectedness_status in {"affected", "known_not_affected"} else 0.2) - issue_penalty),
        "evidenceStrength": max(0.0, evidence_strength - issue_penalty),
        "sourceReliability": max(0.0, (0.8 if affectedness_status != "unknown" else 0.45) - issue_penalty),
        "freshness": max(0.0, 0.6 - soft_issue_count * 0.03),
        "coverageScore": max(0.0, (0.75 if source_resolved else 0.25) - issue_penalty),
        "conflictPenalty": min(1.0, issue_penalty),
        "controlCompliance": 0.0 if hard_issue_count else 1.0,
        "overallAnswerability": max(0.0, (0.78 if affectedness_status in {"affected", "known_not_affected"} and source_resolved else 0.45) - issue_penalty),
    }


def evaluate_score_vector(
    score_vector: dict[str, Any],
    *,
    phase: str,
    profile: str | None = None,
    requested_profile: str | None = None,
    policy: dict[str, Any] | None = None,
    policy_path: str | Path | None = None,
) -> dict[str, Any]:
    if policy is None:
        policy = load_scoring_policy(policy_path)
    else:
        validate_scoring_policy(policy)
        policy = {
            **policy,
            "policyPath": str(policy_path or policy.get("policyPath") or "<memory>"),
            "policySource": str(policy_path or policy.get("policySource") or "<memory>"),
            "policyHash": policy.get("policyHash") or _policy_hash(policy),
        }

    if phase not in REQUIRED_PHASES:
        raise ScoringPolicyError(f"unknown scoring phase: {phase}")
    if profile is None:
        from app.config import settings

        profile = settings.default_scoring_profile
    if profile not in policy["profiles"]:
        raise ScoringPolicyError(f"unknown scoring profile: {profile}")

    vector = _validate_score_vector(score_vector)
    thresholds = policy["profiles"][profile][phase]
    failed: list[dict[str, Any]] = []
    hard_fail = False
    for field in SCORE_VECTOR_FIELDS:
        actual = vector[field]
        if field == "conflictPenalty":
            threshold = float(thresholds["conflictPenaltyMax"])
            if actual > threshold:
                failed.append({"field": field, "actual": actual, "threshold": threshold, "direction": "max"})
                hard_fail = True
            continue
        threshold = float(thresholds[field])
        if actual < threshold:
            failed.append({"field": field, "actual": actual, "threshold": threshold, "direction": "min"})
            if field == "controlCompliance":
                hard_fail = True
    reject_on_threshold_failure = bool(thresholds["rejectOnThresholdFailure"])
    if hard_fail or (failed and reject_on_threshold_failure):
        gate = "rejected"
    elif failed:
        gate = "accepted_with_caveats"
    else:
        gate = "accepted"

    return {
        "schemaVersion": EVALUATION_SCHEMA_VERSION,
        "phase": phase,
        "requestedProfile": requested_profile,
        "appliedProfile": profile,
        "rejectedProfiles": [] if requested_profile in (None, profile) else [requested_profile],
        "policyId": policy["policyId"],
        "policyVersion": policy["policyVersion"],
        "policyHash": policy["policyHash"],
        "policySource": policy["policySource"],
        "policyPath": policy["policyPath"],
        "gate": gate,
        "hardFail": gate == "rejected",
        "scoreVector": vector,
        "thresholds": {field: thresholds[field] for field in THRESHOLD_FIELDS},
        "rejectOnThresholdFailure": reject_on_threshold_failure,
        "failedThresholds": failed,
        "diagnostics": [
            {"code": "SCORE_THRESHOLD_FAILED", "field": item["field"], "direction": item["direction"]}
            for item in failed
        ],
    }
