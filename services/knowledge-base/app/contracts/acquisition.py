"""S5 acquisition/coverage contract v1.

This module is intentionally data-first.  Runtime routers, tests, and docs use
this single snapshot so S5 does not silently drift between code and wiki when it
communicates acquisition/readiness semantics to S3.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

KNOWLEDGE_COVERAGE_CONTRACT_VERSION = "knowledge-coverage-v1"
ACQUISITION_READINESS_CONTRACT_VERSION = "acquisition-readiness-v1"

ACQUISITION_STATUSES = [
    "completed_hit",
    "completed_no_hit",
    "partial_hit",
    "incomplete_acquisition",
    "input_insufficient",
    "stale_cache_only",
    "conflicting_evidence",
    "timeout",
    "not_ready",
    "error",
]

ACQUISITION_QUALITY_GATES = [
    "accepted",
    "accepted_with_caveats",
    "inconclusive",
    "rejected",
]

CONSUMER_POLICIES = {
    "s3_may_derive_local_support_if_refs_validate": {
        "s3EvidenceRole": "derived_local_candidate_only",
        "claimSupportAllowed": "only_after_s3_validates_source_local_refs",
        "negativeEvidenceAllowed": False,
    },
    "contextual_only": {
        "s3EvidenceRole": "knowledge_context_only",
        "claimSupportAllowed": False,
        "negativeEvidenceAllowed": False,
    },
    "scoped_no_hit_record_only": {
        "s3EvidenceRole": "scoped_acquisition_record_only",
        "claimSupportAllowed": False,
        "negativeEvidenceAllowed": "only_as_scoped_no_hit_record_not_clean_pass",
    },
    "diagnostic_only": {
        "s3EvidenceRole": "operational_diagnostic_only",
        "claimSupportAllowed": False,
        "negativeEvidenceAllowed": False,
    },
    "do_not_use": {
        "s3EvidenceRole": "invalid_for_evidence",
        "claimSupportAllowed": False,
        "negativeEvidenceAllowed": False,
    },
    "do_not_use_as_negative_evidence": {
        "s3EvidenceRole": "diagnostic_or_contextual_only",
        "claimSupportAllowed": False,
        "negativeEvidenceAllowed": False,
    },
}

RUNTIME_VOCABULARY = [
    "candidate_returned",
    "no_candidate_returned",
    "candidate_count",
    "method_used",
    "methodsUsed",
    "confidence",
    "score",
    "consumerPolicy",
    "projectionState",
    "providerState",
    "retrievalTrace",
]

OFFLINE_QUALITY_VOCABULARY = [
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

S3_FINAL_CLAIM_VOCABULARY = {
    "owner": "s3",
    "notS5Outputs": [
        "accepted_claim",
        "rejected_claim",
        "inconclusive_outcome",
        "clean_pass",
        "final_security_verdict",
        "claim_support",
    ],
}

REQUIRED_SURFACES = [
    "weaknessTaxonomy",
    "attackPatternMapping",
    "mitigationKnowledge",
    "publicVulnerabilityKnowledge",
    "cveCandidateEvaluation",
    "cveDiscovery",
    "versionRangeEvaluation",
    "semanticThreatRetrieval",
    "semanticCodeRetrieval",
    "structuralCodeProjection",
    "dangerousCallerTraversal",
    "projectMemoryContext",
    "providerFreshness",
    "cacheFreshness",
    "projectionState",
]

NOT_PROVIDED_SURFACES = [
    "finalSecurityVerdict",
    "cleanPass",
    "runtimeBehavior",
    "exploitabilityJudgment",
    "completeProjectSafety",
]

READINESS_STATES = [
    "ready",
    "partial",
    "not_ready",
    "input_insufficient",
    "provider_unavailable",
    "projection_debt",
    "stale_cache_only",
    "conflicting_evidence",
]

READINESS_REQUIRED_FIELDS = [
    "scope",
    "requiredInputs",
    "missingInputs",
    "providerState",
    "projectionState",
    "methodsRequiredForNoHit",
    "methodsAttempted",
    "methodsSucceeded",
    "fallbackPolicy",
    "retryGuidance",
    "diagnostics",
]

NO_HIT_GUARD_REQUIREMENTS = [
    "target context resolved",
    "explicit stable scope",
    "methodsRequiredForNoHit is non-empty",
    "methodsRequiredForNoHit are all attempted",
    "methodsRequiredForNoHit all succeeded",
    "providerState is not timeout/error/unavailable/stale_cache_only",
    "projectionState is not failed/stale/debt/partial for projection-dependent surfaces",
    "basis is not keyword_only_no_result",
    "basis is not embedding_only_no_result",
    "basis is not global_embedding_only_no_result",
    "consumerPolicy is scoped_no_hit_record_only",
]

CVE_SPLIT_ORACLES = [
    {
        "id": "candidate-range-out-discovery-no-hit",
        "candidateEvaluation": "version_match=false may exclude only the specific candidate CVE",
        "discovery": "completed_no_hit only if discovery methods are complete",
        "expectedRuntimeStatus": "completed_no_hit",
        "forbiddenInference": "library_safe",
    },
    {
        "id": "candidate-range-out-discovery-hit",
        "candidateEvaluation": "specific candidate range-out",
        "discovery": "different CVE candidate_returned/completed_hit can coexist",
        "expectedRuntimeStatus": "completed_hit",
        "forbiddenInference": "reject_all_public_vulnerability_context",
    },
    {
        "id": "unknown-version-input-insufficient",
        "candidateEvaluation": "version cannot be evaluated",
        "discovery": "input diagnostic only",
        "expectedRuntimeStatus": "input_insufficient",
        "forbiddenInference": "not_affected",
    },
    {
        "id": "keyword-only-no-result-not-no-hit",
        "candidateEvaluation": "keyword-only miss",
        "discovery": "incomplete acquisition",
        "expectedRuntimeStatus": "incomplete_acquisition",
        "forbiddenInference": "completed_no_hit",
    },
    {
        "id": "provider-timeout-error-envelope",
        "candidateEvaluation": "provider unavailable",
        "discovery": "timeout/error envelope",
        "expectedRuntimeStatus": "timeout_or_error",
        "forbiddenInference": "completed_no_hit",
    },
    {
        "id": "stale-cache-only-diagnostic",
        "candidateEvaluation": "stale cache only",
        "discovery": "diagnostic/contextual only",
        "expectedRuntimeStatus": "stale_cache_only",
        "forbiddenInference": "completed_no_hit",
    },
    {
        "id": "projection-debt-empty-code-not-no-caller",
        "candidateEvaluation": "projection unavailable/debt",
        "discovery": "empty code traversal is not no caller/path",
        "expectedRuntimeStatus": "incomplete_acquisition",
        "forbiddenInference": "no_dangerous_caller",
    },
    {
        "id": "no-hit-plus-failure-not-partial-hit",
        "candidateEvaluation": "mixed completed_no_hit with failure",
        "discovery": "no real completed_hit exists",
        "expectedRuntimeStatus": "incomplete_acquisition",
        "forbiddenInference": "partial_hit",
    },
]

SURFACE_READINESS = {
    surface: {
        "surface": surface,
        "state": "not_ready",
        "scope": {},
        "requiredInputs": [],
        "missingInputs": [],
        "providerState": {"state": "not_evaluated"},
        "projectionState": {"state": "not_evaluated"},
        "methodsRequiredForNoHit": [],
        "methodsAttempted": [],
        "methodsSucceeded": [],
        "fallbackPolicy": "fallback_must_be_explicit_and_traced",
        "retryGuidance": "retry_only_after_missing_inputs_or_provider_projection_state_changes",
        "diagnostics": [],
    }
    for surface in REQUIRED_SURFACES
}

CVE_SURFACES = {
    "cveCandidateEvaluation": {
        "question": "Does this specific candidate CVE affect this library/version/scope?",
        "versionMatchFalseMeaning": "specific_candidate_range_out_only",
        "doesNotMean": ["library_safe", "no_other_cves", "target_clean"],
    },
    "cveDiscovery": {
        "question": "Are there public vulnerability candidates for this library/version/scope?",
        "noHitRequirement": "all required discovery methods completed for explicit scope",
        "canCoexistWithCandidateRangeOut": True,
    },
}

RELATION_METHODS = [
    "exact_id_match",
    "curated_mapping",
    "direct_source_relation",
    "provider_range_eval",
    "graph_expansion",
    "keyword_match",
    "embedding_similarity",
    "constrained_embedding_rerank",
    "global_embedding_search",
]


def _contract() -> dict[str, Any]:
    return {
        "schemaVersion": "s5-acquisition-contracts-v1",
        "knowledgeCoverageContractVersion": KNOWLEDGE_COVERAGE_CONTRACT_VERSION,
        "acquisitionReadinessContractVersion": ACQUISITION_READINESS_CONTRACT_VERSION,
        "knowledgeCoverage": {
            "providedSurfaces": REQUIRED_SURFACES,
            "notProvidedSurfaces": NOT_PROVIDED_SURFACES,
            "cveSurfaces": CVE_SURFACES,
            "relationMethods": RELATION_METHODS,
        },
        "acquisitionReadiness": {
            "states": READINESS_STATES,
            "requiredFields": READINESS_REQUIRED_FIELDS,
            "surfaces": SURFACE_READINESS,
            "noHitGuardRequirements": NO_HIT_GUARD_REQUIREMENTS,
        },
        "vocabulary": {
            "runtimeAcquisition": RUNTIME_VOCABULARY,
            "offlineQualityEvaluation": OFFLINE_QUALITY_VOCABULARY,
            "s3FinalClaimQuality": S3_FINAL_CLAIM_VOCABULARY,
        },
        "consumerPolicies": CONSUMER_POLICIES,
        "cveSplitOracles": CVE_SPLIT_ORACLES,
        "semanticGuards": [
            "completed_hit != true_positive",
            "completed_hit != accepted vulnerability claim",
            "completed_no_hit != no_candidate_returned",
            "completed_no_hit != proof of target safety",
            "no_candidate_returned != completed_no_hit",
            "candidate_returned != accepted claim",
            "keyword_only_no_result != completed_no_hit",
            "embedding_only_no_result != completed_no_hit",
        ],
    }


def contract_snapshot() -> dict[str, Any]:
    """Return a deep-copy snapshot safe for API response use."""
    return deepcopy(_contract())


def runtime_semantics_metadata() -> dict[str, Any]:
    return {
        "layer": "runtime_acquisition",
        "runtimeVocabulary": RUNTIME_VOCABULARY,
        "offlineQualityVocabularyPolicy": "forbidden_not_enumerated_in_runtime_envelopes",
        "offlineQualityVocabularySource": "contract_snapshot.vocabulary.offlineQualityEvaluation",
        "s3FinalClaimQualityOwner": "s3",
        "guards": [
            "completed_hit is runtime acquisition only and is not accepted claim support",
            "completed_no_hit is scoped acquisition record only and is not proof of safety or clean pass",
            "candidate_returned is runtime acquisition only and is not accepted claim",
        ],
    }


def _state_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("state") or value.get("status") or "unknown")
    if value is None:
        return "not_applicable"
    return str(value)


def evaluate_no_hit_eligibility(record: dict[str, Any]) -> tuple[bool, list[str]]:
    """Return whether a runtime envelope/item may safely claim completed_no_hit."""
    if record.get("acquisitionStatus") != "completed_no_hit":
        return True, []

    reasons: list[str] = []
    scope = record.get("scope") if isinstance(record.get("scope"), dict) else {}
    required = list(scope.get("methodsRequiredForNoHit") or record.get("methodsRequiredForNoHit") or [])
    attempted = set(record.get("methodsAttempted") or record.get("results", {}).get("lookupMethodsAttempted", []) or [])
    succeeded = set(record.get("methodsSucceeded") or record.get("results", {}).get("lookupMethodsSucceeded", []) or [])

    if not scope:
        reasons.append("NO_HIT_SCOPE_MISSING")
    if not required:
        reasons.append("NO_HIT_REQUIRED_METHODS_MISSING")
    missing_attempts = sorted(set(required) - attempted)
    if missing_attempts:
        reasons.append("NO_HIT_METHODS_NOT_ATTEMPTED:" + ",".join(missing_attempts))
    missing_success = sorted(set(required) - succeeded)
    if missing_success:
        reasons.append("NO_HIT_METHODS_NOT_SUCCEEDED:" + ",".join(missing_success))

    provider_state = _state_name(record.get("providerState") or scope.get("providerState"))
    projection_state = _state_name(record.get("projectionState") or scope.get("projectionState"))
    if provider_state in {"timeout", "error", "unavailable", "stale_cache_only", "failed"}:
        reasons.append("NO_HIT_PROVIDER_STATE_UNSAFE:" + provider_state)
    if projection_state in {"timeout", "error", "failed", "stale", "debt", "projection_debt", "partial"}:
        reasons.append("NO_HIT_PROJECTION_STATE_UNSAFE:" + projection_state)

    basis = str(scope.get("noHitBasis") or record.get("noHitBasis") or "")
    if basis in {"keyword_only_no_result", "embedding_only_no_result", "global_embedding_only_no_result", "semantic_only_no_result"}:
        reasons.append("NO_HIT_BASIS_UNSAFE:" + basis)
    if record.get("consumerPolicy") != "scoped_no_hit_record_only":
        reasons.append("NO_HIT_CONSUMER_POLICY_UNSAFE")

    return not reasons, reasons


def apply_no_hit_safety(record: dict[str, Any]) -> dict[str, Any]:
    """Downgrade unsafe completed_no_hit records without mutating caller data."""
    out = deepcopy(record)
    eligible, reasons = evaluate_no_hit_eligibility(out)
    if eligible:
        return out

    diagnostics = list(out.get("diagnostics") or [])
    diagnostics.append({
        "code": "UNSAFE_COMPLETED_NO_HIT_DOWNGRADED",
        "message": "completed_no_hit requires explicit scope, completed required methods, safe provider/projection state, and non-keyword/non-embedding-only basis",
        "reasons": reasons,
    })
    out["acquisitionStatus"] = "incomplete_acquisition"
    out["acquisitionQualityGate"] = "inconclusive"
    out["consumerPolicy"] = "do_not_use_as_negative_evidence"
    out["diagnostics"] = diagnostics
    return out
