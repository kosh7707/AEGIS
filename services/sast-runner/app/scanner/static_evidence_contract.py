from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.scanner.claim_support_gate import (
    build_claim_boundary_matrix,
    build_claim_support_readiness_gate,
)

SCHEMA_VERSION = "s4-static-evidence-contract-v1"
ANALYSIS_PROFILE = "c-cpp-core"
ARTIFACT_KIND = "s4-static-evidence-artifact"
PRODUCER = {"service": "s4-sast-runner", "deterministic": True}

_POSITIVE_POLICY = "observed_positive_evidence_only"
_STRUCTURAL_POLICY = "structural_positive_evidence_only"
_MISSING_POLICY = "do_not_use_as_negative_evidence"

TOOL_EVIDENCE_ORDER = ("semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer")
_ALLOWED_SKIP_REASONS = {"operator-requested-subset", "profile-not-applicable"}
_BLOCKING_SKIP_REASONS = {"runtime-tool-missing", "environment-drift", "tool-check-failed"}
_TOOL_EVIDENCE_ROLES = {
    "semgrep": {
        "role": "pattern-taint",
        "uniqueContribution": "fast project-specific pattern and taint evidence",
        "overlap": ["flawfinder dangerous API patterns"],
        "limitations": ["coverage depends on configured rulesets", "local evidence only"],
    },
    "cppcheck": {
        "role": "c-cpp-static-diagnostics",
        "uniqueContribution": "deterministic C/C++ diagnostic evidence",
        "overlap": ["clang-tidy general diagnostics", "gcc-fanalyzer diagnostics"],
        "limitations": ["dataflow may be absent", "path sensitivity is limited"],
    },
    "flawfinder": {
        "role": "dangerous-function-canary",
        "uniqueContribution": "fast dangerous API visibility",
        "overlap": ["semgrep dangerous API rules"],
        "limitations": ["text evidence only", "not semantic proof"],
    },
    "clang-tidy": {
        "role": "cert-compiler-diagnostics",
        "uniqueContribution": "compile-profile CERT and static diagnostics",
        "overlap": ["cppcheck diagnostics", "scan-build compiler-backed diagnostics"],
        "limitations": ["compile profile affects coverage", "some checks lack CWE mapping"],
    },
    "scan-build": {
        "role": "clang-path-sensitive-analysis",
        "uniqueContribution": "Clang Static Analyzer path-sensitive diagnostics",
        "overlap": ["gcc-fanalyzer path-sensitive diagnostics"],
        "limitations": ["can be partial under timeout", "requires compile-capable units"],
    },
    "gcc-fanalyzer": {
        "role": "gcc-path-sensitive-analysis",
        "uniqueContribution": "independent GCC analyzer diagnostics",
        "overlap": ["scan-build path-sensitive diagnostics"],
        "limitations": ["requires analyzer-capable GCC", "profile constraints apply"],
    },
}

_NOT_PROVIDED_SURFACES = {
    "externalVulnerabilityKnowledge": "EXTERNAL_KNOWLEDGE_NOT_QUERIED",
    "semanticGraphRetrieval": "SEMANTIC_RETRIEVAL_NOT_PERFORMED",
    "runtimeBehavior": "RUNTIME_NOT_ANALYZED",
    "exploitabilityJudgment": "EXPLOITABILITY_NOT_JUDGED",
    "finalSecurityVerdict": "FINAL_VERDICT_NOT_PROVIDED",
}


_REQUIRED_READINESS_SURFACES = (
    "staticToolExecution",
    "sastFindings",
    "findingLocations",
    "findingCweMapping",
    "originClassification",
)
_OPTIONAL_READINESS_SURFACES = (
    "findingDataflow",
    "structuralCodeGraph",
    "includeGraph",
    "targetMetadata",
    "scaIdentity",
    "scaVersionEvidence",
    "scaDiffEvidence",
)
_REQUIRED_NOT_READY_STATUSES = {"not_computed", "not_applicable", "failed", "unavailable", "unknown"}
_OPTIONAL_PARTIAL_STATUSES = {"partial", "failed", "unavailable", "unknown"}


def build_static_evidence_contract(
    *,
    success: bool,
    provenance: Any | None = None,
    findings: list[Any] | None = None,
    execution: Any | None = None,
    code_graph: Any | None = None,
    sca: Any | None = None,
    metadata: Any | None = None,
    policy_failure_reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    coverage = _coverage(
        findings=findings,
        execution=execution,
        code_graph=code_graph,
        sca=sca,
        metadata=metadata,
    )
    system_stability = _system_stability(
        success=success,
        execution=execution,
        policy_failure_reason_codes=policy_failure_reason_codes,
    )
    coverage_reason_codes = _tool_coverage_reason_codes(execution)
    evidence_readiness = _evidence_readiness(
        coverage,
        success=success,
        policy_failure_reason_codes=policy_failure_reason_codes,
    )
    claim_boundary_matrix = build_claim_boundary_matrix(
        coverage=coverage,
        findings=findings,
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "analysisProfile": ANALYSIS_PROFILE,
        "artifactKind": ARTIFACT_KIND,
        "producer": dict(PRODUCER),
        "provenance": _as_mapping(provenance) or {},
        "gates": {
            "systemStability": system_stability,
            "evidenceReadiness": evidence_readiness,
            "claimSupportReadiness": build_claim_support_readiness_gate(
                success=success,
                coverage=coverage,
                system_stability=system_stability,
                evidence_readiness=evidence_readiness,
                policy_failure_reason_codes=policy_failure_reason_codes,
            ),
            "qualityEvaluation": _quality_evaluation(),
            "coverageQuality": _coverage_quality(coverage_reason_codes),
        },
        "coverage": coverage,
        "claimBoundaries": {
            "maySupport": [
                "local-static-tool-observations",
                "normalized-cwe-location-dataflow-origin-evidence",
                "structural-callgraph-evidence-when-provided",
                "sca-identity-version-diff-evidence-when-provided",
            ],
            "mustNotSupportAlone": [
                "external-vulnerability-affectedness",
                "semantic-graph-completeness",
                "runtime-exploitability",
                "final-security-verdict",
                "absence-of-vulnerability-from-empty-findings",
            ],
            "negativeEvidencePolicy": "empty-or-missing-s4-evidence-is-not-negative-security-evidence",
        },
        "claimBoundaryMatrix": claim_boundary_matrix,
        "toolEvidenceMatrix": _tool_evidence_matrix(execution),
        "followUpHints": _follow_up_hints(coverage),
    }


def _coverage(
    *,
    findings: list[Any] | None,
    execution: Any | None,
    code_graph: Any | None,
    sca: Any | None,
    metadata: Any | None,
) -> dict[str, dict[str, Any]]:
    findings_missing = findings is None
    findings_list = [] if findings_missing else list(findings)
    coverage = {
        "staticToolExecution": _static_tool_execution(execution),
        "sastFindings": _not_computed(
            "FINDINGS_NOT_PROVIDED",
            "The normalized finding list was not provided to the static evidence contract.",
        ) if findings_missing else _provided(
            evidence_refs=["findings[]"],
            summary="S4 emitted the normalized finding list for this artifact.",
            observed_count=len(findings_list),
        ),
        "findingLocations": _not_computed(
            "FINDINGS_NOT_PROVIDED",
            "Finding location evidence cannot be computed without a finding list.",
        ) if findings_missing else _finding_locations(findings_list),
        "findingCweMapping": _not_computed(
            "FINDINGS_NOT_PROVIDED",
            "Finding CWE mapping evidence cannot be computed without a finding list.",
        ) if findings_missing else _finding_cwe_mapping(findings_list),
        "findingDataflow": _not_computed(
            "FINDINGS_NOT_PROVIDED",
            "Finding dataflow evidence cannot be computed without a finding list.",
        ) if findings_missing else _finding_dataflow(findings_list),
        "originClassification": _not_computed(
            "FINDINGS_NOT_PROVIDED",
            "Finding origin evidence cannot be computed without a finding list.",
        ) if findings_missing else _origin_classification(findings_list),
        "structuralCodeGraph": _structural_code_graph(code_graph),
        "includeGraph": _not_computed("INCLUDE_GRAPH_NOT_REQUESTED", "Include graph was not computed in this artifact."),
        "targetMetadata": _target_metadata(metadata),
        "scaIdentity": _sca_identity(sca),
        "scaVersionEvidence": _sca_version_evidence(sca),
        "scaDiffEvidence": _sca_diff_evidence(sca),
    }
    for surface, reason_code in _NOT_PROVIDED_SURFACES.items():
        coverage[surface] = _not_provided(reason_code, f"{surface} is outside this S4 artifact.")
    return coverage


def _static_tool_execution(execution: Any | None) -> dict[str, Any]:
    if execution is None:
        return _not_computed("TOOL_EXECUTION_NOT_RECORDED", "Tool execution metadata was not recorded.")
    execution_map = _as_mapping(execution) or {}
    tools_run = execution_map.get("toolsRun") or execution_map.get("tools_run") or []
    tool_results = execution_map.get("toolResults") or execution_map.get("tool_results") or {}
    observed_count = len(tool_results) if isinstance(tool_results, Mapping) else len(tools_run)
    anomaly_reason_codes = _tool_anomaly_reason_codes(execution)
    if anomaly_reason_codes:
        entry = _partial(
            "TOOL_EXECUTION_PARTIAL",
            "Some local static tool execution evidence is incomplete, degraded, or failed.",
            ["execution", "execution.toolResults"],
            observed_count,
        )
        entry["anomalyReasonCodes"] = anomaly_reason_codes
        return entry
    return _provided(
        evidence_refs=["execution", "execution.toolResults"],
        summary="S4 recorded local static tool execution metadata.",
        observed_count=observed_count,
    )


def _finding_locations(findings: list[Any]) -> dict[str, Any]:
    located = sum(1 for finding in findings if _finding_location(finding) is not None)
    if located == len(findings):
        return _provided(["findings[].location"], "Finding location fields are present.", located)
    return _partial(
        "FINDING_LOCATION_PARTIAL",
        "Some findings lack location fields.",
        ["findings[].location"],
        located,
    )


def _finding_cwe_mapping(findings: list[Any]) -> dict[str, Any]:
    mapped = sum(1 for finding in findings if _finding_evidence(finding).get("cwe", {}).get("status") == "known")
    if mapped == len(findings):
        return _provided(["findings[].metadata.evidenceResolution.cwe"], "Finding CWE mapping evidence is present.", mapped)
    return _partial(
        "CWE_MAPPING_PARTIAL",
        "Some findings lack known CWE mapping evidence.",
        ["findings[].metadata.evidenceResolution.cwe"],
        mapped,
    )


def _finding_dataflow(findings: list[Any]) -> dict[str, Any]:
    with_flow = sum(1 for finding in findings if bool(_finding_evidence(finding).get("dataFlow", {}).get("present")))
    if with_flow == len(findings):
        return _provided(["findings[].dataFlow"], "Tool-provided dataflow evidence is present.", with_flow)
    return _partial(
        "DATAFLOW_NOT_PROVIDED_BY_TOOLS",
        "Some findings do not include tool-provided dataflow evidence.",
        ["findings[].dataFlow"],
        with_flow,
    )


def _origin_classification(findings: list[Any]) -> dict[str, Any]:
    classified = sum(1 for finding in findings if bool(_finding_evidence(finding).get("origin", {}).get("status")))
    if classified == len(findings):
        return _provided(
            ["findings[].metadata.evidenceResolution.origin"],
            "Finding origin classification evidence is present.",
            classified,
        )
    return _partial(
        "ORIGIN_CLASSIFICATION_PARTIAL",
        "Some findings lack origin classification evidence.",
        ["findings[].metadata.evidenceResolution.origin"],
        classified,
    )


def _structural_code_graph(code_graph: Any | None) -> dict[str, Any]:
    graph = _as_mapping(code_graph)
    if graph is None:
        return _not_computed("CODE_GRAPH_NOT_REQUESTED", "Structural call graph was not computed in this artifact.")
    functions = graph.get("functions") or []
    entry = _provided(
        evidence_refs=["codeGraph.functions[]"],
        summary="S4 emitted a structural call graph.",
        observed_count=len(functions) if isinstance(functions, list) else None,
        consumer_policy=_STRUCTURAL_POLICY,
    )
    entry.update({
        "graphKind": "structural-callgraph",
        "semanticRetrieval": "not_provided",
        "graphRag": "not_provided",
    })
    return entry


def _target_metadata(metadata: Any | None) -> dict[str, Any]:
    meta = _as_mapping(metadata)
    if not meta:
        return _not_computed("TARGET_METADATA_NOT_COMPUTED", "Target metadata was not computed in this artifact.")
    return _provided(["metadata"], "Target metadata is present.", len(meta))


def _sca_identity(sca: Any | None) -> dict[str, Any]:
    libraries = _libraries(sca)
    if libraries is None:
        return _not_computed("SCA_NOT_COMPUTED", "SCA identity evidence was not computed in this artifact.")
    return _provided(["sca.libraries[]", "libraries[]"], "SCA library identity evidence is present.", len(libraries))


def _sca_version_evidence(sca: Any | None) -> dict[str, Any]:
    libraries = _libraries(sca)
    if libraries is None:
        return _not_computed("SCA_NOT_COMPUTED", "SCA version evidence was not computed in this artifact.")
    known = 0
    for library in libraries:
        item = _as_mapping(library) or {}
        evidence = item.get("versionEvidence") or {}
        if isinstance(evidence, Mapping) and evidence.get("status") == "observed":
            known += 1
    if known == len(libraries):
        return _provided(["sca.libraries[].versionEvidence"], "SCA version evidence is present.", known)
    return _partial(
        "SCA_VERSION_EVIDENCE_PARTIAL",
        "Some libraries lack observed version evidence.",
        ["sca.libraries[].versionEvidence"],
        known,
    )


def _sca_diff_evidence(sca: Any | None) -> dict[str, Any]:
    libraries = _libraries(sca)
    if libraries is None:
        return _not_computed("SCA_NOT_COMPUTED", "SCA diff evidence was not computed in this artifact.")
    available = 0
    for library in libraries:
        item = _as_mapping(library) or {}
        if item.get("diffAvailable") is True:
            available += 1
    if available == len(libraries):
        return _provided(["sca.libraries[].diffSummary"], "SCA diff evidence is present.", available)
    if available > 0:
        return _partial(
            "SCA_DIFF_EVIDENCE_PARTIAL",
            "SCA diff evidence is present for some libraries but not every library.",
            ["sca.libraries[].diffSummary"],
            available,
        )
    return _not_computed("DIFF_NOT_COMPUTED", "SCA diff evidence was not computed for every library.")


def _system_stability(
    *,
    success: bool,
    execution: Any | None,
    policy_failure_reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    if not success or policy_failure_reason_codes:
        reason_codes = []
        if not success:
            reason_codes.append("RESPONSE_FAILED")
        if policy_failure_reason_codes:
            reason_codes.extend(policy_failure_reason_codes)
        if not reason_codes:
            reason_codes.append("RESPONSE_FAILED")
        return {
            "status": "fail",
            "reasonCodes": reason_codes,
            "consumerPolicy": "do_not_treat_as_successful_artifact",
        }
    execution_map = _as_mapping(execution) or {}
    execution_degrade_reasons = list(execution_map.get("degradeReasons") or execution_map.get("degrade_reasons") or [])
    tool_anomaly_reason_codes = _tool_anomaly_reason_codes(execution)
    if execution_map.get("degraded") or execution_degrade_reasons or tool_anomaly_reason_codes:
        reason_codes: list[str] = []
        if execution_map.get("degraded") or execution_degrade_reasons:
            reason_codes.extend(execution_degrade_reasons or ["EXECUTION_DEGRADED"])
        reason_codes.extend(tool_anomaly_reason_codes)
        return {
            "status": "degraded",
            "reasonCodes": reason_codes,
            "consumerPolicy": "use_with_degradation_metadata",
        }
    return {
        "status": "pass",
        "reasonCodes": [],
        "consumerPolicy": "local_artifact_stable",
    }


def _evidence_readiness(
    coverage: Mapping[str, Mapping[str, Any]],
    *,
    success: bool,
    policy_failure_reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    if not success or policy_failure_reason_codes:
        reason_codes = []
        if not success:
            reason_codes.append("ARTIFACT_FAILED")
        if policy_failure_reason_codes:
            reason_codes.extend(policy_failure_reason_codes)
        if not reason_codes:
            reason_codes.append("ARTIFACT_FAILED")
        return {
            "status": "not_ready",
            "reasonCodes": reason_codes,
            "consumerPolicy": _MISSING_POLICY,
        }

    blocking_surfaces: list[str] = []
    partial_surfaces: list[str] = []

    for surface in _REQUIRED_READINESS_SURFACES:
        entry = coverage.get(surface)
        status = entry.get("status") if entry else None
        if status == "provided":
            continue
        if status == "partial":
            partial_surfaces.append(surface)
            continue
        if status in _REQUIRED_NOT_READY_STATUSES or status is None:
            blocking_surfaces.append(surface)
            continue
        blocking_surfaces.append(surface)

    if blocking_surfaces:
        result: dict[str, Any] = {
            "status": "not_ready",
            "reasonCodes": ["REQUIRED_EVIDENCE_MISSING"],
            "consumerPolicy": _MISSING_POLICY,
            "blockingSurfaces": blocking_surfaces,
        }
        if partial_surfaces:
            result["partialSurfaces"] = partial_surfaces
        return result

    for surface in _OPTIONAL_READINESS_SURFACES:
        entry = coverage.get(surface)
        status = entry.get("status") if entry else None
        if status in _OPTIONAL_PARTIAL_STATUSES:
            partial_surfaces.append(surface)

    if partial_surfaces:
        return {
            "status": "partial",
            "reasonCodes": ["LOCAL_EVIDENCE_PARTIAL"],
            "consumerPolicy": _MISSING_POLICY,
            "partialSurfaces": partial_surfaces,
        }

    return {
        "status": "ready",
        "reasonCodes": [],
        "consumerPolicy": "local_static_evidence_ready",
    }


def _follow_up_hints(coverage: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    hints = []
    for surface in _NOT_PROVIDED_SURFACES:
        entry = coverage[surface]
        hints.append({
            "surface": surface,
            "status": entry["status"],
            "reasonCode": entry["reasonCodes"][0],
            "consumerPolicy": entry["consumerPolicy"],
            "message": "This evidence surface is outside the S4 static artifact.",
        })
    return hints


def _tool_evidence_matrix(execution: Any | None) -> list[dict[str, Any]]:
    execution_map = _as_mapping(execution) or {}
    tool_results = execution_map.get("toolResults") or execution_map.get("tool_results") or {}
    if not isinstance(tool_results, Mapping):
        tool_results = {}

    matrix = []
    for tool_id in TOOL_EVIDENCE_ORDER:
        role = _TOOL_EVIDENCE_ROLES[tool_id]
        result = _as_mapping(tool_results.get(tool_id))
        base = {
            "toolId": tool_id,
            "role": role["role"],
            "uniqueContribution": role["uniqueContribution"],
            "overlap": list(role["overlap"]),
            "limitations": list(role["limitations"]),
            "deterministic": True,
            "requiresNetwork": False,
            "requiresExternalKnowledge": False,
            "emitsFinalVerdict": False,
            "verdictPolicy": "local-tool-state-is-not-a-vulnerability-verdict",
        }
        if result is None:
            matrix.append({
                **base,
                "status": "not_recorded",
                "findingsCount": None,
                "elapsedMs": None,
                "version": None,
                "skipReason": None,
                "degraded": False,
                "degradeReasons": [],
                "consumerPolicy": "metadata_absent_do_not_infer",
                "evidenceRefs": [],
            })
            continue

        status = str(_first_present(result, "status") or "unknown")
        skip_reason = _first_present(result, "skipReason", "skip_reason")
        degraded = bool(_first_present(result, "degraded") or False)
        degrade_reasons = list(_first_present(result, "degradeReasons", "degrade_reasons") or [])
        coverage_degraded = bool(_first_present(result, "coverageDegraded", "coverage_degraded") or False)
        coverage_reasons = list(_first_present(result, "coverageReasons", "coverage_reasons") or [])
        coverage = _first_present(result, "coverage")
        matrix.append({
            **base,
            "status": status,
            "findingsCount": _first_present(result, "findingsCount", "findings_count"),
            "elapsedMs": _first_present(result, "elapsedMs", "elapsed_ms"),
            "version": _first_present(result, "version"),
            "skipReason": skip_reason,
            "degraded": degraded,
            "degradeReasons": degrade_reasons,
            "coverageDegraded": coverage_degraded,
            "coverageReasons": coverage_reasons,
            "coverage": coverage if isinstance(coverage, Mapping) else None,
            "consumerPolicy": _tool_consumer_policy(status, skip_reason, degraded, coverage_degraded),
            "evidenceRefs": [f"execution.toolResults.{tool_id}"],
        })
    return matrix


def _tool_anomaly_reason_codes(execution: Any | None) -> list[str]:
    execution_map = _as_mapping(execution)
    if execution_map is None:
        return []

    tool_results = execution_map.get("toolResults") or execution_map.get("tool_results") or {}
    if not isinstance(tool_results, Mapping):
        tool_results = {}

    reason_codes: list[str] = []
    for tool_id in TOOL_EVIDENCE_ORDER:
        result = _as_mapping(tool_results.get(tool_id))
        if result is None:
            reason_codes.append(f"TOOL_NOT_RECORDED:{tool_id}")
            continue

        status = str(_first_present(result, "status") or "unknown")
        skip_reason = _first_present(result, "skipReason", "skip_reason")
        degraded = bool(_first_present(result, "degraded") or False)

        if status == "skipped":
            if skip_reason in _ALLOWED_SKIP_REASONS:
                continue
            reason_codes.append(f"TOOL_BLOCKING_SKIP:{tool_id}")
            continue
        if status == "partial":
            reason_codes.append(f"TOOL_PARTIAL:{tool_id}")
            continue
        if status == "failed":
            reason_codes.append(f"TOOL_FAILED:{tool_id}")
            continue
        if status == "ok":
            if degraded:
                reason_codes.append(f"TOOL_DEGRADED:{tool_id}")
            continue

        reason_codes.append(f"TOOL_STATUS_UNKNOWN:{tool_id}")

    return reason_codes


def _tool_coverage_reason_codes(execution: Any | None) -> list[str]:
    execution_map = _as_mapping(execution)
    if execution_map is None:
        return []
    tool_results = execution_map.get("toolResults") or execution_map.get("tool_results") or {}
    if not isinstance(tool_results, Mapping):
        return []
    reason_codes: list[str] = []
    for tool_id in TOOL_EVIDENCE_ORDER:
        result = _as_mapping(tool_results.get(tool_id))
        if result is None:
            continue
        if not bool(_first_present(result, "coverageDegraded", "coverage_degraded") or False):
            continue
        reasons = list(_first_present(result, "coverageReasons", "coverage_reasons") or [])
        if reasons:
            reason_codes.extend(f"TOOL_COVERAGE_DEGRADED:{tool_id}:{reason}" for reason in reasons)
        else:
            reason_codes.append(f"TOOL_COVERAGE_DEGRADED:{tool_id}")
    return sorted(dict.fromkeys(reason_codes))


def _quality_evaluation(reason_codes: list[str] | None = None) -> dict[str, Any]:
    _ = reason_codes
    return {
        "status": "not_evaluated",
        "reasonCodes": ["NO_VALIDATION_PROFILE_RAN"],
        "consumerPolicy": "do_not_treat_as_quality_score",
    }


def _coverage_quality(reason_codes: list[str]) -> dict[str, Any]:
    if reason_codes:
        return {
            "status": "degraded",
            "reasonCodes": reason_codes,
            "consumerPolicy": "effective_coverage_partial_do_not_infer_negative_security_evidence",
        }
    return {
        "status": "pass",
        "reasonCodes": [],
        "consumerPolicy": "effective_coverage_metadata_has_no_reported_caveats",
    }


def _tool_consumer_policy(status: str, skip_reason: Any | None, degraded: bool, coverage_degraded: bool = False) -> str:
    if status == "skipped":
        if skip_reason in _ALLOWED_SKIP_REASONS:
            return "not_requested_or_not_applicable"
        if skip_reason in _BLOCKING_SKIP_REASONS or skip_reason:
            return "blocks_successful_artifact"
        return "blocks_successful_artifact"
    if status == "partial" or degraded:
        return "local_tool_partial_use_with_degradation_metadata"
    if status == "failed":
        return "local_tool_failed_do_not_use_as_negative_evidence"
    if status == "ok" and coverage_degraded:
        return "local_tool_effective_coverage_partial_not_negative_evidence"
    if status == "ok":
        return "local_tool_execution_state_only_not_vulnerability_verdict"
    return "metadata_absent_do_not_infer"


def _provided(
    evidence_refs: list[str],
    summary: str,
    observed_count: int | None = None,
    *,
    consumer_policy: str = _POSITIVE_POLICY,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "status": "provided",
        "reasonCodes": [],
        "consumerPolicy": consumer_policy,
        "evidenceRefs": evidence_refs,
        "summary": summary,
    }
    if observed_count is not None:
        entry["observedCount"] = observed_count
    return entry


def _partial(reason_code: str, summary: str, evidence_refs: list[str], observed_count: int | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "status": "partial",
        "reasonCodes": [reason_code],
        "consumerPolicy": _MISSING_POLICY,
        "evidenceRefs": evidence_refs,
        "summary": summary,
    }
    if observed_count is not None:
        entry["observedCount"] = observed_count
    return entry


def _not_provided(reason_code: str, summary: str) -> dict[str, Any]:
    return {
        "status": "not_provided",
        "reasonCodes": [reason_code],
        "consumerPolicy": _MISSING_POLICY,
        "summary": summary,
    }


def _not_computed(reason_code: str, summary: str) -> dict[str, Any]:
    return {
        "status": "not_computed",
        "reasonCodes": [reason_code],
        "consumerPolicy": _MISSING_POLICY,
        "summary": summary,
    }


def _first_present(mapping: Mapping[str, Any], *keys: str) -> Any | None:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _libraries(sca: Any | None) -> list[Any] | None:
    sca_map = _as_mapping(sca)
    if sca_map is None:
        return None
    libraries = sca_map.get("libraries")
    return libraries if isinstance(libraries, list) else []


def _finding_location(finding: Any) -> Any | None:
    if hasattr(finding, "location"):
        return finding.location
    if isinstance(finding, Mapping):
        return finding.get("location")
    return None


def _finding_evidence(finding: Any) -> Mapping[str, Any]:
    metadata: Any | None = None
    if hasattr(finding, "metadata"):
        metadata = finding.metadata
    elif isinstance(finding, Mapping):
        metadata = finding.get("metadata")
    if not isinstance(metadata, Mapping):
        return {}
    evidence = metadata.get("evidenceResolution")
    return evidence if isinstance(evidence, Mapping) else {}


def _as_mapping(value: Any | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items() if item is not None}
    return None
