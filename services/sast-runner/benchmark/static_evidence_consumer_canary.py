from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_ABSENT_REASON = "STATIC_EVIDENCE_CONTRACT_ABSENT"
_MALFORMED_REASON = "STATIC_EVIDENCE_CONTRACT_MALFORMED"
_UNSAFE_PROJECTION_REASON = "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"
SUMMARY_SCHEMA_VERSION = "s4-static-evidence-contract-consumer-summary-v1"
_CLI_INPUT_INVALID_REASON = "STATIC_EVIDENCE_CONSUMER_CLI_INPUT_INVALID"
_CLI_OUTPUT_FAILED_REASON = "STATIC_EVIDENCE_CONSUMER_CLI_OUTPUT_FAILED"
_CLI_INPUT_INVALID_ERROR = "input validation failed"
_CLI_OUTPUT_FAILED_ERROR = "summary output failed"

_SYSTEM_STABILITY_STATUSES = {"pass", "degraded", "fail", "unknown"}
_EVIDENCE_READINESS_STATUSES = {"ready", "partial", "not_ready", "unknown"}
_CLAIM_SUPPORT_READINESS_STATUSES = {"pass", "partial", "fail", "unknown"}
_QUALITY_EVALUATION_STATUSES = {"not_evaluated", "unknown"}
_COVERAGE_STATUSES = {
    "provided",
    "partial",
    "not_computed",
    "not_provided",
    "not_applicable",
    "failed",
    "unavailable",
    "unknown",
}
_CLAIM_SUPPORT_STATUSES = {"supported", "partially_supported", "unsupported", "not_applicable"}
_TOOL_MATRIX_STATUSES = {"ok", "partial", "failed", "skipped", "unknown", "not_recorded"}
_CONSUMER_POLICIES = {
    "blocks_successful_artifact",
    "do_not_use_as_negative_evidence",
    "local_tool_partial_use_with_degradation_metadata",
    "local_tool_execution_state_only_not_vulnerability_verdict",
    "local_tool_effective_coverage_partial_not_negative_evidence",
    "local_tool_failed_do_not_use_as_negative_evidence",
    "metadata_absent_do_not_infer",
    "no_reported_finding_to_support",
    "not_requested_or_not_applicable",
    "use_as_bounded_local_static_evidence",
    "use_only_with_missing_surface_metadata",
}
_SURFACE_IDS = {
    "staticToolExecution",
    "sastFindings",
    "findingLocations",
    "findingCweMapping",
    "findingDataflow",
    "originClassification",
    "includeGraph",
    "structuralCodeGraph",
    "targetMetadata",
    "scaIdentity",
    "scaVersionEvidence",
    "scaDiffEvidence",
    "runtimeBehavior",
    "externalVulnerabilityKnowledge",
    "semanticGraphRetrieval",
    "exploitabilityJudgment",
    "finalSecurityVerdict",
}
_CLAIM_IDS = {
    "local-static-artifact",
    "reported-finding-positive-evidence",
    "absence-of-vulnerability",
    "absence-of-vulnerability-from-empty-findings",
    "cwe-absence",
    "build-configuration-dependent-negative-claim",
    "runtime-behavior",
    "runtime-exploitability",
    "external-vulnerability-affectedness",
    "semantic-graph-completeness",
    "exploitability-judgment",
    "final-security-verdict",
}
_TOOL_IDS = {"semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"}
_REQUIRED_READY_COVERAGE_SURFACES = {
    "staticToolExecution",
    "sastFindings",
    "findingLocations",
    "findingCweMapping",
    "originClassification",
}
_REQUIRED_BOUNDARY_CLAIMS = {
    "absence-of-vulnerability-from-empty-findings",
    "external-vulnerability-affectedness",
    "final-security-verdict",
    "runtime-exploitability",
    "semantic-graph-completeness",
}
_REQUIRED_READY_CLAIM_STATUSES = {
    "local-static-artifact": "supported",
    "absence-of-vulnerability": "unsupported",
    "cwe-absence": "unsupported",
}
_STATIC_REASON_CODES = {
    "ANALYSIS_REQUIRED_SURFACE_MISSING",
    "BUILD_CONTEXT_IS_NOT_NEGATIVE_EVIDENCE",
    "CODE_GRAPH_NOT_REQUESTED",
    "CWE_COVERAGE_IS_NOT_ABSENCE_EVIDENCE",
    "DISALLOWED_TOOL_ENVIRONMENT_DRIFT",
    "EMPTY_OR_MISSING_S4_EVIDENCE_IS_NOT_NEGATIVE_EVIDENCE",
    "EXPLOITABILITY_NOT_JUDGED",
    "EXTERNAL_KNOWLEDGE_NOT_QUERIED",
    "FINAL_VERDICT_NOT_PROVIDED",
    "INCLUDE_GRAPH_NOT_REQUESTED",
    "LOCAL_ARTIFACT_DEGRADED",
    "LOCAL_ARTIFACT_FAILED",
    "LOCAL_EVIDENCE_PARTIAL",
    "NORMALIZED_EVIDENCE_PARTIAL",
    "NO_REPORTED_FINDINGS",
    "NO_VALIDATION_PROFILE_RAN",
    "POLICY_VIOLATION",
    "REQUIRED_EVIDENCE_MISSING",
    "RESPONSE_FAILED",
    "RUNTIME_NOT_ANALYZED",
    "SCA_NOT_COMPUTED",
    "SEMANTIC_RETRIEVAL_NOT_PERFORMED",
    "TARGET_METADATA_NOT_COMPUTED",
    "TOOL_EXECUTION_PARTIAL",
    "ARTIFACT_FAILED",
    "CLAIM_SUPPORT_CLASSIFICATION_UNKNOWN",
    "EXECUTION_DEGRADED",
    "SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN",
    "SEMGREP_CPP_TARGETS_EXCLUDED_BY_EXTENSION_FILTER",
    "SEMGREP_C_EFFECTIVE_COVERAGE_UNPROVEN",
    "SEMGREP_NO_C_OR_CPP_TARGETS_REPORTED",
    "SEMGREP_NO_SOURCE_FILES_REPORTED",
}
_TOOL_REASON_PREFIXES = (
    "TOOL_FAILED:",
    "TOOL_NOT_RECORDED:",
    "TOOL_BLOCKING_SKIP:",
    "TOOL_PARTIAL:",
    "TOOL_DEGRADED:",
    "TOOL_STATUS_UNKNOWN:",
    "TOOL_COVERAGE_DEGRADED:",
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ValueError(_CLI_INPUT_INVALID_REASON)


def summarize_static_evidence_contract(payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Summarize only the S4 static evidence contract surfaces in a JSON payload.

    This helper is intentionally pure JSON: it does not import S4 runtime app modules,
    execute tools, read raw execution results, call services, or score security impact.
    """

    contract, location = _locate_contract(payload)
    if contract is None:
        reason = _MALFORMED_REASON if location == "malformed" else _ABSENT_REASON
        return {
            "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
            "contractPresent": False,
            "contractLocation": location,
            "systemStability": "unknown",
            "evidenceReadiness": "not_ready",
            "claimSupportReadiness": "unknown",
            "qualityEvaluation": "unknown",
            "localStaticEvidenceReady": False,
            "systemReasonCodes": [reason],
            "evidenceReasonCodes": [reason],
            "claimSupportReasonCodes": [reason],
            "toolAnomalyReasonCodes": [],
            "notProvidedSurfaces": [],
            "partialSurfaces": [],
            "blockingSurfaces": [],
            "mustNotSupportAlone": [],
            "unsupportedClaims": [],
            "claimSupportStatuses": {},
            "toolMatrixStatuses": {},
            "toolConsumerPolicies": {},
        }

    unsafe_projection: list[bool] = []

    gates = _mapping_field(contract, "gates", unsafe_projection)
    coverage = _mapping_field(contract, "coverage", unsafe_projection)
    boundaries = _mapping_field(contract, "claimBoundaries", unsafe_projection)
    static_execution = _mapping_field(coverage, "staticToolExecution", unsafe_projection)
    system_gate = _mapping_field(gates, "systemStability", unsafe_projection)
    readiness_gate = _mapping_field(gates, "evidenceReadiness", unsafe_projection)
    claim_support_gate = _mapping_field(gates, "claimSupportReadiness", unsafe_projection)
    quality_gate = _mapping_field(gates, "qualityEvaluation", unsafe_projection)

    _inspect_coverage(coverage, unsafe_projection)

    system_status = _status(
        system_gate,
        "unknown",
        allowed=_SYSTEM_STABILITY_STATUSES,
        unsafe_projection=unsafe_projection,
    )
    readiness_status = _status(
        readiness_gate,
        "not_ready",
        allowed=_EVIDENCE_READINESS_STATUSES,
        unsafe_projection=unsafe_projection,
    )
    claim_support_status = _status(
        claim_support_gate,
        "unknown",
        allowed=_CLAIM_SUPPORT_READINESS_STATUSES,
        unsafe_projection=unsafe_projection,
    )
    quality_status = _status(
        quality_gate,
        "unknown",
        allowed=_QUALITY_EVALUATION_STATUSES,
        unsafe_projection=unsafe_projection,
    )

    system_reason_codes = _reason_codes(system_gate.get("reasonCodes"), unsafe_projection)
    evidence_reason_codes = _reason_codes(readiness_gate.get("reasonCodes"), unsafe_projection)
    claim_support_reason_codes = _reason_codes(claim_support_gate.get("reasonCodes"), unsafe_projection)
    tool_anomaly_reason_codes = _reason_codes(
        static_execution.get("anomalyReasonCodes"),
        unsafe_projection,
    )
    partial_surfaces = _surface_list(readiness_gate.get("partialSurfaces"), unsafe_projection)
    blocking_surfaces = _surface_list(readiness_gate.get("blockingSurfaces"), unsafe_projection)
    not_provided_surfaces = _not_provided_surfaces(coverage, unsafe_projection)
    must_not_support_alone = _claim_id_list(boundaries.get("mustNotSupportAlone"), unsafe_projection)
    unsupported_claims = _claims_by_status(contract, "unsupported", unsafe_projection)
    claim_support_statuses = _claim_matrix_field(
        contract,
        "supportStatus",
        allowed_values=_CLAIM_SUPPORT_STATUSES,
        unsafe_projection=unsafe_projection,
    )
    tool_matrix_statuses = _tool_matrix_field(
        contract,
        "status",
        allowed_values=_TOOL_MATRIX_STATUSES,
        unsafe_projection=unsafe_projection,
    )
    tool_consumer_policies = _tool_matrix_field(
        contract,
        "consumerPolicy",
        allowed_values=_CONSUMER_POLICIES,
        unsafe_projection=unsafe_projection,
    )

    gates_claim_ready = (
        system_status == "pass"
        and readiness_status == "ready"
        and claim_support_status == "pass"
    )
    if gates_claim_ready and not _ready_projection_complete(
        coverage=coverage,
        must_not_support_alone=must_not_support_alone,
        claim_support_statuses=claim_support_statuses,
        tool_matrix_statuses=tool_matrix_statuses,
        tool_consumer_policies=tool_consumer_policies,
        unsafe_projection=unsafe_projection,
    ):
        _mark_unsafe(unsafe_projection)

    if unsafe_projection:
        system_reason_codes = _with_unsafe_reason(system_reason_codes)
        evidence_reason_codes = _with_unsafe_reason(evidence_reason_codes)
        claim_support_reason_codes = _with_unsafe_reason(claim_support_reason_codes)

    return {
        "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
        "contractPresent": True,
        "contractLocation": location,
        "systemStability": system_status,
        "evidenceReadiness": readiness_status,
        "claimSupportReadiness": claim_support_status,
        "qualityEvaluation": quality_status,
        "localStaticEvidenceReady": (
            gates_claim_ready
            and not unsafe_projection
        ),
        "systemReasonCodes": system_reason_codes,
        "evidenceReasonCodes": evidence_reason_codes,
        "claimSupportReasonCodes": claim_support_reason_codes,
        "toolAnomalyReasonCodes": tool_anomaly_reason_codes,
        "notProvidedSurfaces": not_provided_surfaces,
        "partialSurfaces": partial_surfaces,
        "blockingSurfaces": blocking_surfaces,
        "mustNotSupportAlone": must_not_support_alone,
        "unsupportedClaims": unsupported_claims,
        "claimSupportStatuses": claim_support_statuses,
        "toolMatrixStatuses": tool_matrix_statuses,
        "toolConsumerPolicies": tool_consumer_policies,
    }


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        description="Summarize an S4 staticEvidenceContract response for consumer canaries.",
        add_help=True,
    )
    parser.add_argument("--response", required=True, help="Path to response JSON containing staticEvidenceContract.")
    parser.add_argument(
        "--require-local-static-ready",
        action="store_true",
        help="Exit 2 when the sanitized summary is not locally static-evidence ready.",
    )

    try:
        args = parser.parse_args(argv)
        payload = json.loads(Path(args.response).read_text(encoding="utf-8"))
    except Exception:
        _emit_cli_error()
        return 1

    summary = summarize_static_evidence_contract(payload)
    if not _emit_summary_stdout(summary):
        _emit_cli_error(_CLI_OUTPUT_FAILED_REASON)
        return 1
    if summary.get("contractPresent") is not True:
        return 2
    if args.require_local_static_ready and not summary.get("localStaticEvidenceReady"):
        return 2
    return 0


def _locate_contract(payload: Mapping[str, Any] | Any) -> tuple[Mapping[str, Any] | None, str]:
    payload_map = _mapping(payload)
    if payload_map is None:
        return None, "malformed"

    if "staticEvidenceContract" in payload_map:
        contract = _mapping(payload_map.get("staticEvidenceContract"))
        if contract is None:
            return None, "malformed"
        return contract, "top-level"

    scan_value = payload_map.get("scan")
    scan = _mapping(scan_value)
    if scan is None and "scan" in payload_map and scan_value is not None:
        return None, "malformed"
    if scan is not None and "staticEvidenceContract" in scan:
        contract = _mapping(scan.get("staticEvidenceContract"))
        if contract is None:
            return None, "malformed"
        return contract, "scan.staticEvidenceContract"

    return None, "missing"


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _mapping_field(parent: Mapping[str, Any], key: str, unsafe_projection: list[bool]) -> Mapping[str, Any]:
    if key not in parent or parent.get(key) is None:
        return {}
    value = parent[key]
    if isinstance(value, Mapping):
        return value
    _mark_unsafe(unsafe_projection)
    return {}


def _mark_unsafe(unsafe_projection: list[bool]) -> None:
    unsafe_projection.append(True)


def _status(
    gate: Mapping[str, Any],
    default: str,
    *,
    allowed: set[str],
    unsafe_projection: list[bool],
) -> str:
    value = gate.get("status")
    if value is None:
        return default
    if isinstance(value, str) and value in allowed:
        return value
    _mark_unsafe(unsafe_projection)
    return default


def _reason_codes(value: Any, unsafe_projection: list[bool], *, mark_unsafe: bool = True) -> list[str]:
    if not isinstance(value, list):
        if value is not None and mark_unsafe:
            _mark_unsafe(unsafe_projection)
        return []
    result: list[str] = []
    for item in value:
        if _is_allowed_reason_code(item):
            result.append(item)
        elif mark_unsafe:
            _mark_unsafe(unsafe_projection)
    return _unique(result)


def _surface_list(value: Any, unsafe_projection: list[bool]) -> list[str]:
    if not isinstance(value, list):
        if value is not None:
            _mark_unsafe(unsafe_projection)
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item in _SURFACE_IDS:
            result.append(item)
        else:
            _mark_unsafe(unsafe_projection)
    return _unique(result)


def _claim_id_list(value: Any, unsafe_projection: list[bool]) -> list[str]:
    if not isinstance(value, list):
        if value is not None:
            _mark_unsafe(unsafe_projection)
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item in _CLAIM_IDS:
            result.append(item)
        else:
            _mark_unsafe(unsafe_projection)
    return _unique(result)


def _inspect_coverage(coverage: Mapping[str, Any], unsafe_projection: list[bool]) -> None:
    for surface, entry in coverage.items():
        if not isinstance(surface, str) or surface not in _SURFACE_IDS:
            _mark_unsafe(unsafe_projection)
            continue
        entry_map = _mapping(entry)
        if entry_map is None:
            _mark_unsafe(unsafe_projection)
            continue
        _coverage_status(entry_map, unsafe_projection)


def _coverage_status(entry: Mapping[str, Any], unsafe_projection: list[bool]) -> str:
    value = entry.get("status")
    if value is None:
        return "unknown"
    if isinstance(value, str) and value in _COVERAGE_STATUSES:
        return value
    _mark_unsafe(unsafe_projection)
    return "unknown"


def _not_provided_surfaces(coverage: Mapping[str, Any], unsafe_projection: list[bool]) -> list[str]:
    surfaces: list[str] = []
    for surface, entry in coverage.items():
        if not isinstance(surface, str) or surface not in _SURFACE_IDS:
            _mark_unsafe(unsafe_projection)
            continue
        entry_map = _mapping(entry)
        if entry_map is None:
            _mark_unsafe(unsafe_projection)
            continue
        if _coverage_status(entry_map, unsafe_projection) == "not_provided":
            surfaces.append(surface)
    return surfaces


def _tool_matrix_field(
    contract: Mapping[str, Any],
    field: str,
    *,
    allowed_values: set[str],
    unsafe_projection: list[bool],
) -> dict[str, str]:
    matrix = contract.get("toolEvidenceMatrix")
    if not isinstance(matrix, list):
        if matrix is not None:
            _mark_unsafe(unsafe_projection)
        return {}

    result: dict[str, str] = {}
    for entry in matrix:
        entry_map = _mapping(entry)
        if entry_map is None:
            _mark_unsafe(unsafe_projection)
            continue
        tool_id = entry_map.get("toolId")
        value = entry_map.get(field)
        if not isinstance(tool_id, str) or tool_id not in _TOOL_IDS:
            _mark_unsafe(unsafe_projection)
            continue
        if isinstance(value, str) and value in allowed_values:
            if tool_id in result:
                _mark_unsafe(unsafe_projection)
                continue
            result[tool_id] = value
        else:
            _mark_unsafe(unsafe_projection)
    return result


def _claim_matrix_field(
    contract: Mapping[str, Any],
    field: str,
    *,
    allowed_values: set[str],
    unsafe_projection: list[bool],
) -> dict[str, str]:
    matrix = contract.get("claimBoundaryMatrix")
    if not isinstance(matrix, list):
        if matrix is not None:
            _mark_unsafe(unsafe_projection)
        return {}

    result: dict[str, str] = {}
    for entry in matrix:
        entry_map = _mapping(entry)
        if entry_map is None:
            _mark_unsafe(unsafe_projection)
            continue
        claim_id = entry_map.get("claimId")
        value = entry_map.get(field)
        if not isinstance(claim_id, str) or claim_id not in _CLAIM_IDS:
            _mark_unsafe(unsafe_projection)
            continue
        if isinstance(value, str) and value in allowed_values:
            if claim_id in result:
                _mark_unsafe(unsafe_projection)
                continue
            result[claim_id] = value
        else:
            _mark_unsafe(unsafe_projection)
    return result


def _claims_by_status(contract: Mapping[str, Any], status: str, unsafe_projection: list[bool]) -> list[str]:
    matrix = contract.get("claimBoundaryMatrix")
    if not isinstance(matrix, list):
        if matrix is not None:
            _mark_unsafe(unsafe_projection)
        return []

    claims: list[str] = []
    seen_claim_ids: set[str] = set()
    for entry in matrix:
        entry_map = _mapping(entry)
        if entry_map is None:
            _mark_unsafe(unsafe_projection)
            continue
        claim_id = entry_map.get("claimId")
        support_status = entry_map.get("supportStatus")
        if not isinstance(claim_id, str) or claim_id not in _CLAIM_IDS:
            _mark_unsafe(unsafe_projection)
            continue
        if not isinstance(support_status, str) or support_status not in _CLAIM_SUPPORT_STATUSES:
            _mark_unsafe(unsafe_projection)
            continue
        if claim_id in seen_claim_ids:
            _mark_unsafe(unsafe_projection)
            continue
        seen_claim_ids.add(claim_id)
        if support_status == status:
            claims.append(claim_id)
    return _unique(claims)


def _ready_projection_complete(
    *,
    coverage: Mapping[str, Any],
    must_not_support_alone: list[str],
    claim_support_statuses: dict[str, str],
    tool_matrix_statuses: dict[str, str],
    tool_consumer_policies: dict[str, str],
    unsafe_projection: list[bool],
) -> bool:
    return (
        _required_coverage_surfaces_provided(coverage, unsafe_projection)
        and _required_claim_boundaries_present(must_not_support_alone)
        and _required_claim_statuses_present(claim_support_statuses)
        and _required_tool_matrix_ready(tool_matrix_statuses, tool_consumer_policies)
    )


def _required_coverage_surfaces_provided(
    coverage: Mapping[str, Any],
    unsafe_projection: list[bool],
) -> bool:
    for surface in _REQUIRED_READY_COVERAGE_SURFACES:
        entry_map = _mapping(coverage.get(surface))
        if entry_map is None:
            return False
        if _coverage_status(entry_map, unsafe_projection) != "provided":
            return False
    return True


def _required_claim_boundaries_present(must_not_support_alone: list[str]) -> bool:
    return _REQUIRED_BOUNDARY_CLAIMS.issubset(set(must_not_support_alone))


def _required_claim_statuses_present(claim_support_statuses: dict[str, str]) -> bool:
    for claim_id, expected_status in _REQUIRED_READY_CLAIM_STATUSES.items():
        if claim_support_statuses.get(claim_id) != expected_status:
            return False
    return True


def _required_tool_matrix_ready(
    tool_matrix_statuses: dict[str, str],
    tool_consumer_policies: dict[str, str],
) -> bool:
    for tool_id in _TOOL_IDS:
        status = tool_matrix_statuses.get(tool_id)
        policy = tool_consumer_policies.get(tool_id)
        if status == "ok" and policy in {
            "local_tool_execution_state_only_not_vulnerability_verdict",
            "local_tool_effective_coverage_partial_not_negative_evidence",
        }:
            continue
        if status == "skipped" and policy == "not_requested_or_not_applicable":
            continue
        return False
    return True


def _is_allowed_reason_code(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value in _STATIC_REASON_CODES:
        return True
    for prefix in _TOOL_REASON_PREFIXES:
        suffix = value.removeprefix(prefix) if value.startswith(prefix) else None
        if suffix in _TOOL_IDS:
            return True
        if prefix == "TOOL_COVERAGE_DEGRADED:" and isinstance(suffix, str):
            parts = suffix.split(":", 1)
            if len(parts) == 2 and parts[0] in _TOOL_IDS and parts[1] in _STATIC_REASON_CODES:
                return True
    return False


def _with_unsafe_reason(reason_codes: list[str]) -> list[str]:
    return _unique([*reason_codes, _UNSAFE_PROJECTION_REASON])


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _emit_summary_stdout(summary: dict[str, Any]) -> bool:
    try:
        sys.stdout.write(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, TypeError, UnicodeError):
        return False
    return True


def _emit_cli_error(reason: str = _CLI_INPUT_INVALID_REASON) -> None:
    error = _CLI_OUTPUT_FAILED_ERROR if reason == _CLI_OUTPUT_FAILED_REASON else _CLI_INPUT_INVALID_ERROR
    stage = "output" if reason == _CLI_OUTPUT_FAILED_REASON else "input"
    try:
        sys.stderr.write(json.dumps({
            "error": error,
            "reasonCode": reason,
            "reasonCodes": [reason],
            "stage": stage,
            "summaryEmitted": False,
        }, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, TypeError, ValueError, UnicodeError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
