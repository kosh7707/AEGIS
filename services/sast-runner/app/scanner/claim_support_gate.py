from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_MISSING_POLICY = "do_not_use_as_negative_evidence"
_SUPPORTED_POLICY = "use_as_bounded_local_static_evidence"
_PARTIAL_POLICY = "use_only_with_missing_surface_metadata"
_NOT_APPLICABLE_POLICY = "no_reported_finding_to_support"
_GATE_POLICY = "not_a_quality_score_not_a_security_verdict"

_REQUIRED_LOCAL_SURFACES = (
    "staticToolExecution",
    "sastFindings",
    "findingLocations",
    "findingCweMapping",
    "originClassification",
)
_FINDING_SUPPORT_SURFACES = (
    "findingLocations",
    "findingCweMapping",
    "findingDataflow",
    "originClassification",
)


def build_claim_support_readiness_gate(
    *,
    success: bool,
    coverage: Mapping[str, Mapping[str, Any]],
    system_stability: Mapping[str, Any],
    evidence_readiness: Mapping[str, Any],
    policy_failure_reason_codes: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Classify whether bounded S4 claim support can be consumed.

    This gate intentionally evaluates normalized evidence surfaces, not
    individual runner identities. It is a claim-support readiness classifier;
    validation scores remain owned by the separate quality-evaluation surface.
    """

    blocking_surfaces = _blocking_surfaces(coverage, evidence_readiness)
    partial_surfaces = _partial_surfaces(coverage, evidence_readiness)
    policy_reasons = [str(code) for code in (policy_failure_reason_codes or [])]
    stability_status = _status(system_stability)
    readiness_status = _status(evidence_readiness)

    if not success or stability_status == "fail":
        reason_codes = _unique(["LOCAL_ARTIFACT_FAILED", *policy_reasons])
        if blocking_surfaces:
            reason_codes.append("ANALYSIS_REQUIRED_SURFACE_MISSING")
        result: dict[str, Any] = {
            "status": "fail",
            "reasonCodes": reason_codes,
            "consumerPolicy": _GATE_POLICY,
        }
        if blocking_surfaces:
            result["blockingSurfaces"] = blocking_surfaces
        if partial_surfaces:
            result["partialSurfaces"] = partial_surfaces
        return result

    if readiness_status == "not_ready" or blocking_surfaces:
        return {
            "status": "fail",
            "reasonCodes": ["ANALYSIS_REQUIRED_SURFACE_MISSING"],
            "consumerPolicy": _GATE_POLICY,
            "blockingSurfaces": blocking_surfaces,
            **({"partialSurfaces": partial_surfaces} if partial_surfaces else {}),
        }

    reason_codes: list[str] = []
    if stability_status == "degraded":
        reason_codes.append("LOCAL_ARTIFACT_DEGRADED")
    if readiness_status == "partial" or partial_surfaces:
        reason_codes.append("NORMALIZED_EVIDENCE_PARTIAL")

    if reason_codes:
        return {
            "status": "partial",
            "reasonCodes": _unique(reason_codes),
            "consumerPolicy": _GATE_POLICY,
            "partialSurfaces": partial_surfaces,
        }

    if stability_status == "unknown" or readiness_status == "unknown":
        return {
            "status": "unknown",
            "reasonCodes": ["CLAIM_SUPPORT_CLASSIFICATION_UNKNOWN"],
            "consumerPolicy": _GATE_POLICY,
        }

    return {
        "status": "pass",
        "reasonCodes": [],
        "consumerPolicy": _GATE_POLICY,
    }


def build_claim_boundary_matrix(
    *,
    coverage: Mapping[str, Mapping[str, Any]],
    findings: Sequence[Any] | None,
) -> list[dict[str, Any]]:
    findings_count = _findings_count(coverage, findings)
    return [
        _local_static_artifact_claim(coverage),
        _reported_finding_claim(coverage, findings_count),
        _unsupported_claim(
            "absence-of-vulnerability",
            "negative-security-claim",
            "EMPTY_OR_MISSING_S4_EVIDENCE_IS_NOT_NEGATIVE_EVIDENCE",
            ["claimBoundaries.negativeEvidencePolicy", "coverage.sastFindings"],
            "S4 local static evidence cannot support a vulnerability-absence claim.",
        ),
        _unsupported_claim(
            "cwe-absence",
            "negative-cwe-claim",
            "CWE_COVERAGE_IS_NOT_ABSENCE_EVIDENCE",
            ["coverage.findingCweMapping", "claimBoundaries.negativeEvidencePolicy"],
            "CWE mapping on reported findings cannot support a CWE absence claim.",
        ),
        _unsupported_claim(
            "build-configuration-dependent-negative-claim",
            "build-context-negative-claim",
            "BUILD_CONTEXT_IS_NOT_NEGATIVE_EVIDENCE",
            ["coverage.targetMetadata"],
            "Target metadata may bound observations but cannot prove build-configuration-dependent absence.",
        ),
        _unsupported_claim(
            "runtime-behavior",
            "out-of-scope-claim",
            "RUNTIME_NOT_ANALYZED",
            ["coverage.runtimeBehavior"],
            "Runtime behavior is outside this local static artifact.",
        ),
        _unsupported_claim(
            "external-vulnerability-affectedness",
            "out-of-scope-claim",
            "EXTERNAL_KNOWLEDGE_NOT_QUERIED",
            ["coverage.externalVulnerabilityKnowledge"],
            "External vulnerability affectedness is outside this local static artifact.",
        ),
        _unsupported_claim(
            "semantic-graph-completeness",
            "out-of-scope-claim",
            "SEMANTIC_RETRIEVAL_NOT_PERFORMED",
            ["coverage.semanticGraphRetrieval"],
            "Semantic graph completeness is outside this local static artifact.",
        ),
        _unsupported_claim(
            "exploitability-judgment",
            "out-of-scope-claim",
            "EXPLOITABILITY_NOT_JUDGED",
            ["coverage.exploitabilityJudgment"],
            "Exploitability judgment is outside this local static artifact.",
        ),
        _unsupported_claim(
            "final-security-verdict",
            "out-of-scope-claim",
            "FINAL_VERDICT_NOT_PROVIDED",
            ["coverage.finalSecurityVerdict"],
            "Final security judgment is outside this local static artifact.",
        ),
    ]


def _local_static_artifact_claim(coverage: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    blocking = [
        surface
        for surface in _REQUIRED_LOCAL_SURFACES
        if _surface_status(coverage, surface) not in {"provided", "partial"}
    ]
    partial = [
        surface
        for surface in _REQUIRED_LOCAL_SURFACES
        if _surface_status(coverage, surface) == "partial"
    ]
    if blocking:
        return _claim(
            claim_id="local-static-artifact",
            claim_type="local-static-observation",
            support_status="unsupported",
            reason_codes=["ANALYSIS_REQUIRED_SURFACE_MISSING"],
            consumer_policy=_MISSING_POLICY,
            evidence_refs=[f"coverage.{surface}" for surface in blocking],
            summary="Required normalized local static evidence surfaces are missing.",
            blocking_surfaces=blocking,
        )
    if partial:
        return _claim(
            claim_id="local-static-artifact",
            claim_type="local-static-observation",
            support_status="partially_supported",
            reason_codes=["NORMALIZED_EVIDENCE_PARTIAL"],
            consumer_policy=_PARTIAL_POLICY,
            evidence_refs=[f"coverage.{surface}" for surface in partial],
            summary="S4 local static artifact exists, but normalized evidence surfaces are partial.",
            partial_surfaces=partial,
        )
    return _claim(
        claim_id="local-static-artifact",
        claim_type="local-static-observation",
        support_status="supported",
        reason_codes=[],
        consumer_policy=_SUPPORTED_POLICY,
        evidence_refs=[f"coverage.{surface}" for surface in _REQUIRED_LOCAL_SURFACES],
        summary="Required normalized local static evidence surfaces are present.",
    )


def _reported_finding_claim(
    coverage: Mapping[str, Mapping[str, Any]],
    findings_count: int | None,
) -> dict[str, Any]:
    if findings_count == 0:
        return _claim(
            claim_id="reported-finding-positive-evidence",
            claim_type="positive-local-static-finding",
            support_status="not_applicable",
            reason_codes=["NO_REPORTED_FINDINGS"],
            consumer_policy=_NOT_APPLICABLE_POLICY,
            evidence_refs=["coverage.sastFindings", "findings[]"],
            summary="No reported finding exists to support a positive local finding claim.",
        )
    if findings_count is None:
        return _claim(
            claim_id="reported-finding-positive-evidence",
            claim_type="positive-local-static-finding",
            support_status="unsupported",
            reason_codes=["FINDINGS_NOT_PROVIDED"],
            consumer_policy=_MISSING_POLICY,
            evidence_refs=["coverage.sastFindings"],
            summary="Finding list was not provided to the contract.",
        )

    partial = [
        surface
        for surface in _FINDING_SUPPORT_SURFACES
        if _surface_status(coverage, surface) == "partial"
    ]
    blocking = [
        surface
        for surface in _FINDING_SUPPORT_SURFACES
        if _surface_status(coverage, surface) not in {"provided", "partial"}
    ]
    if blocking:
        return _claim(
            claim_id="reported-finding-positive-evidence",
            claim_type="positive-local-static-finding",
            support_status="unsupported",
            reason_codes=["ANALYSIS_REQUIRED_SURFACE_MISSING"],
            consumer_policy=_MISSING_POLICY,
            evidence_refs=[f"coverage.{surface}" for surface in blocking],
            summary="Reported findings lack required normalized support surfaces.",
            blocking_surfaces=blocking,
        )
    if partial:
        return _claim(
            claim_id="reported-finding-positive-evidence",
            claim_type="positive-local-static-finding",
            support_status="partially_supported",
            reason_codes=["NORMALIZED_EVIDENCE_PARTIAL"],
            consumer_policy=_PARTIAL_POLICY,
            evidence_refs=[f"coverage.{surface}" for surface in partial],
            summary="Reported findings are present, but some normalized support surfaces are partial.",
            partial_surfaces=partial,
        )
    return _claim(
        claim_id="reported-finding-positive-evidence",
        claim_type="positive-local-static-finding",
        support_status="supported",
        reason_codes=[],
        consumer_policy=_SUPPORTED_POLICY,
        evidence_refs=["findings[]", *[f"coverage.{surface}" for surface in _FINDING_SUPPORT_SURFACES]],
        summary="Reported findings have normalized local static evidence support.",
    )


def _unsupported_claim(
    claim_id: str,
    claim_type: str,
    reason_code: str,
    evidence_refs: list[str],
    summary: str,
) -> dict[str, Any]:
    return _claim(
        claim_id=claim_id,
        claim_type=claim_type,
        support_status="unsupported",
        reason_codes=[reason_code],
        consumer_policy=_MISSING_POLICY,
        evidence_refs=evidence_refs,
        summary=summary,
    )


def _claim(
    *,
    claim_id: str,
    claim_type: str,
    support_status: str,
    reason_codes: list[str],
    consumer_policy: str,
    evidence_refs: list[str],
    summary: str,
    blocking_surfaces: list[str] | None = None,
    partial_surfaces: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "claimId": claim_id,
        "claimType": claim_type,
        "supportStatus": support_status,
        "reasonCodes": reason_codes,
        "consumerPolicy": consumer_policy,
        "evidenceRefs": evidence_refs,
        "summary": summary,
    }
    if blocking_surfaces:
        result["blockingSurfaces"] = blocking_surfaces
    if partial_surfaces:
        result["partialSurfaces"] = partial_surfaces
    return result


def _blocking_surfaces(
    coverage: Mapping[str, Mapping[str, Any]],
    evidence_readiness: Mapping[str, Any],
) -> list[str]:
    explicit = _string_list(evidence_readiness.get("blockingSurfaces"))
    if explicit:
        return explicit
    return [
        surface
        for surface in _REQUIRED_LOCAL_SURFACES
        if _surface_status(coverage, surface) not in {"provided", "partial"}
    ]


def _partial_surfaces(
    coverage: Mapping[str, Mapping[str, Any]],
    evidence_readiness: Mapping[str, Any],
) -> list[str]:
    explicit = _string_list(evidence_readiness.get("partialSurfaces"))
    if explicit:
        return explicit
    return [
        surface
        for surface in _REQUIRED_LOCAL_SURFACES
        if _surface_status(coverage, surface) == "partial"
    ]


def _findings_count(
    coverage: Mapping[str, Mapping[str, Any]],
    findings: Sequence[Any] | None,
) -> int | None:
    if findings is not None:
        return len(findings)
    finding_surface = coverage.get("sastFindings")
    if isinstance(finding_surface, Mapping):
        count = finding_surface.get("observedCount")
        if isinstance(count, int):
            return count
    return None


def _surface_status(coverage: Mapping[str, Mapping[str, Any]], surface: str) -> str:
    entry = coverage.get(surface)
    if not isinstance(entry, Mapping):
        return "unknown"
    return _status(entry)


def _status(entry: Mapping[str, Any]) -> str:
    value = entry.get("status")
    return value if isinstance(value, str) and value else "unknown"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _unique(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
