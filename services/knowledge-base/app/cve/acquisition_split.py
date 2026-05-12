"""CVE candidate-evaluation/discovery runtime helpers.

These helpers keep runtime CVE semantics separate from offline Golden Set metrics.
They intentionally describe candidates, methods, provider state, and scoped no-hit
eligibility; they never emit TP/FP/FN/precision/recall vocabulary.
"""

from __future__ import annotations

from typing import Any

CANDIDATE_RANGE_OUT_FORBIDDEN_INFERENCES = [
    "library_safe",
    "no_other_cves",
    "target_clean",
    "complete_project_safety",
]

OFFLINE_QUALITY_RUNTIME_FORBIDDEN_TOKENS = [
    "true_positive",
    "false_positive",
    "false_negative",
    "recall",
    "precision",
    "NDCG",
    "MRR",
    "Precision@k",
    "Recall@k",
    "NDCG@k",
]


def _pick(source: dict[str, Any] | None, *keys: str) -> Any:
    if not isinstance(source, dict):
        return None
    for key in keys:
        if key in source and source[key] not in (None, ""):
            return source[key]
    return None


def normalize_cve_id(value: Any) -> str:
    return str(value or "").strip().upper()


def cve_method_plan(library: dict[str, Any]) -> dict[str, Any]:
    """Return a conservative method-completeness plan for CVE runtime calls.

    Existing provider results do not report every attempted sub-method, so S5
    derives the *required-for-no-hit* set from caller inputs and treats
    keyword-only results as observation-only.
    """

    repo_url = _pick(library, "repoUrl", "repo_url")
    commit = _pick(library, "commit")
    attempted: list[str] = []
    required_for_no_hit: list[str] = []
    fallback_trace: list[dict[str, Any]] = []

    if commit and repo_url:
        attempted.extend(["osv_commit", "nvd_cpe", "nvd_keyword"])
        required_for_no_hit.extend(["osv_commit", "nvd_cpe"])
        primary_method = "osv_commit"
        no_hit_basis = "completed_required_methods"
        no_hit_eligible = True
    elif repo_url:
        attempted.extend(["nvd_cpe", "nvd_keyword"])
        required_for_no_hit.append("nvd_cpe")
        primary_method = "nvd_cpe"
        no_hit_basis = "completed_required_methods"
        no_hit_eligible = True
        fallback_trace.append({
            "from": "osv_commit",
            "to": "nvd_cpe",
            "reason": "commit_not_available",
            "confidenceImpact": ["commit_specific_lookup_unavailable"],
        })
    else:
        attempted.append("nvd_keyword")
        required_for_no_hit.append("nvd_keyword")
        primary_method = "nvd_keyword"
        no_hit_basis = "keyword_only_no_result"
        no_hit_eligible = False
        fallback_trace.append({
            "from": "precise_repo_lookup",
            "to": "nvd_keyword",
            "reason": "no_precise_input",
            "confidenceImpact": ["reduced_specificity", "version_match_uncertain"],
        })

    return {
        "primaryMethod": primary_method,
        "methodsAttempted": attempted,
        "methodsRequiredForNoHit": required_for_no_hit,
        "fallbackTrace": fallback_trace,
        "noHitEligible": no_hit_eligible,
        "noHitBasis": no_hit_basis,
    }


def provider_methods_succeeded(
    plan: dict[str, Any],
    result: dict[str, Any],
    *,
    status: str,
) -> list[str]:
    """Return runtime method-success observations without upgrading keyword misses."""

    cache_info = result.get("cacheInfo") if isinstance(result.get("cacheInfo"), dict) else {}
    if status == "stale_cache_only" or cache_info.get("stale") or result.get("stale_cache_only"):
        return ["cache"]
    if result.get("error") or status in {"timeout", "error", "not_ready"}:
        return []
    if plan.get("noHitEligible"):
        return list(plan.get("methodsRequiredForNoHit") or [])
    return ["nvd_keyword"]


def candidate_methods(plan: dict[str, Any]) -> dict[str, list[str]]:
    """Return candidate-evaluation methods layered over provider methods."""

    provider_required = list(plan.get("methodsRequiredForNoHit") or [])
    provider_attempted = list(plan.get("methodsAttempted") or [])
    semantic_methods = ["exact_id_match", "provider_range_eval"]
    return {
        "methodsAttempted": [*semantic_methods, *provider_attempted],
        "methodsRequiredForNoHit": [*semantic_methods, *provider_required],
    }


def cve_ids(cves: list[dict[str, Any]]) -> list[str]:
    return [str(cve.get("id")) for cve in cves if isinstance(cve, dict) and cve.get("id")]
