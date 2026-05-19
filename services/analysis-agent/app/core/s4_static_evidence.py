"""S4 staticEvidenceContract consumer helpers.

These helpers classify only whether S4's local deterministic static evidence
artifact is ready enough to use as a clean SAST artifact. They do not score
vulnerability quality and do not emit a final security verdict.
"""

from __future__ import annotations

from typing import Any

SUMMARY_SCHEMA_VERSION = "s4-static-evidence-contract-consumer-summary-v1"
UNSAFE_REASON = "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"
CURRENT_SIX_TOOL_IDS = ["semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"]
_REQUIRED_COVERAGE_SURFACES = [
    "staticToolExecution",
    "sastFindings",
    "findingLocations",
    "findingCweMapping",
    "originClassification",
]
_REQUIRED_CLAIM_STATUSES = {
    "local-static-artifact": {"supported"},
    "reported-finding-positive-evidence": {"supported", "partially_supported", "not_applicable"},
    "absence-of-vulnerability": {"unsupported"},
    "cwe-absence": {"unsupported"},
    "build-configuration-dependent-negative-claim": {"unsupported"},
    "runtime-behavior": {"unsupported"},
    "external-vulnerability-affectedness": {"unsupported"},
    "semantic-graph-completeness": {"unsupported"},
    "exploitability-judgment": {"unsupported"},
    "final-security-verdict": {"unsupported"},
}
_LOCAL_TOOL_POLICIES = {
    "local_tool_execution_state_only_not_vulnerability_verdict",
    "local_tool_partial_use_with_degradation_metadata",
    "not_requested_or_not_applicable",
}
_OK_TOOL_STATUSES = {"ok", "complete"}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            result.append(item.strip())
        elif isinstance(item, dict):
            for key in ("toolId", "id", "name", "claimId"):
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    result.append(candidate.strip())
                    break
    return result


def _declared_required_tool_ids(contract: dict) -> list[str]:
    """Return S4-declared required/default tool ids without inventing S4 tool policy."""
    candidates: list[Any] = [
        contract.get("requiredToolIds"),
        contract.get("defaultToolIds"),
        contract.get("requiredTools"),
    ]
    for key in ("expectedToolSet", "declaredToolSet", "toolSet", "toolCoverage"):
        nested = contract.get(key)
        if isinstance(nested, dict):
            candidates.extend([
                nested.get("requiredToolIds"),
                nested.get("defaultToolIds"),
                nested.get("requiredTools"),
                nested.get("tools"),
            ])

    seen: set[str] = set()
    result: list[str] = []
    for candidate in candidates:
        for tool_id in _string_list(candidate):
            if tool_id not in seen:
                seen.add(tool_id)
                result.append(tool_id)
    return result


def extract_static_evidence_contract(*payloads: Any) -> dict:
    """Return the first S4 staticEvidenceContract dict from response payloads."""
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        contract = payload.get("staticEvidenceContract")
        if isinstance(contract, dict):
            return contract
    return {}


def _container(value: Any, *, present: bool) -> tuple[dict, bool]:
    if isinstance(value, dict):
        return value, False
    if present and value is not None:
        return {}, True
    return {}, False


def _list_container(value: Any, *, present: bool) -> tuple[list, bool]:
    if isinstance(value, list):
        return value, False
    if present and value is not None:
        return [], True
    return [], False


def _summary_base(*, reason_codes: list[str] | None = None) -> dict:
    return {
        "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
        "ready": False,
        "localStaticEvidenceReady": False,
        "reasonCodes": sorted(set(reason_codes or [])),
        "summary": "S4 static evidence artifact is not clean complete local evidence.",
        "systemStability": None,
        "evidenceReadiness": None,
        "claimSupportReadiness": None,
        "hasClaimBoundaryMatrix": False,
        "hasToolEvidenceMatrix": False,
        "claimBoundaryMatrixCount": 0,
        "toolEvidenceMatrixCount": 0,
        "declaredRequiredToolIds": [],
        "observedToolIds": [],
        "missingRequiredToolIds": [],
        "requiredCoverageStatuses": {},
        "claimSupportStatuses": {},
        "toolMatrixStatuses": {},
        "toolConsumerPolicies": {},
        "unsupportedClaims": [],
        "unsafeProjection": False,
    }


def summarize_static_evidence_contract(contract: Any) -> dict:
    """Summarize S3 consumer-readiness for an S4 static evidence contract.

    Ready means the contract is present and S4-local runtime gates plus the
    projected evidence surfaces are complete enough for bounded local static
    claim support. The summary intentionally mirrors S4's consumer-canary
    vocabulary without importing S4 code.
    """
    if not isinstance(contract, dict) or not contract:
        summary = _summary_base(reason_codes=["STATIC_EVIDENCE_CONTRACT_MISSING"])
        summary["summary"] = "S4 staticEvidenceContract is absent; local SAST artifact readiness is unknown."
        return summary

    reason_codes: list[str] = []
    unsafe_projection = False

    gates, malformed_gates = _container(contract.get("gates"), present="gates" in contract)
    system_gate, malformed_system = _container(gates.get("systemStability"), present="systemStability" in gates)
    evidence_gate, malformed_evidence = _container(gates.get("evidenceReadiness"), present="evidenceReadiness" in gates)
    claim_gate, malformed_claim = _container(gates.get("claimSupportReadiness"), present="claimSupportReadiness" in gates)
    coverage, malformed_coverage = _container(contract.get("coverage"), present="coverage" in contract)
    claim_boundaries, malformed_claim_boundaries = _container(
        contract.get("claimBoundaries"), present="claimBoundaries" in contract,
    )
    claim_boundary_matrix, malformed_claim_matrix = _list_container(
        contract.get("claimBoundaryMatrix"), present="claimBoundaryMatrix" in contract,
    )
    tool_evidence_matrix, malformed_tool_matrix = _list_container(
        contract.get("toolEvidenceMatrix"), present="toolEvidenceMatrix" in contract,
    )

    if any((
        malformed_gates,
        malformed_system,
        malformed_evidence,
        malformed_claim,
        malformed_coverage,
        malformed_claim_boundaries,
        malformed_claim_matrix,
        malformed_tool_matrix,
    )):
        unsafe_projection = True
        reason_codes.append(UNSAFE_REASON)

    system_status = system_gate.get("status")
    evidence_status = evidence_gate.get("status")
    claim_status = claim_gate.get("status")
    positive_gates = system_status == "pass" and evidence_status == "ready" and claim_status == "pass"

    for gate_name, gate, expected in (
        ("systemStability", system_gate, "pass"),
        ("evidenceReadiness", evidence_gate, "ready"),
        ("claimSupportReadiness", claim_gate, "pass"),
    ):
        status = gate.get("status")
        if status != expected:
            reason_codes.append(f"{gate_name}:{status or 'missing'}")
        gate_reasons = gate.get("reasonCodes")
        if isinstance(gate_reasons, list):
            reason_codes.extend(str(reason) for reason in gate_reasons if reason)

    if "claimBoundaryMatrix" not in contract or not isinstance(contract.get("claimBoundaryMatrix"), list):
        reason_codes.append("CLAIM_BOUNDARY_MATRIX_MISSING")
    elif not claim_boundary_matrix:
        reason_codes.append("CLAIM_BOUNDARY_MATRIX_EMPTY")
    if "toolEvidenceMatrix" not in contract or not isinstance(contract.get("toolEvidenceMatrix"), list):
        reason_codes.append("TOOL_EVIDENCE_MATRIX_MISSING")
    elif not tool_evidence_matrix:
        reason_codes.append("TOOL_EVIDENCE_MATRIX_EMPTY")

    required_coverage_statuses: dict[str, str | None] = {}
    for surface in _REQUIRED_COVERAGE_SURFACES:
        raw_entry = coverage.get(surface) if isinstance(coverage, dict) else None
        entry = raw_entry if isinstance(raw_entry, dict) else {}
        status = entry.get("status") if isinstance(entry.get("status"), str) else None
        required_coverage_statuses[surface] = status
        if status != "provided":
            reason_codes.append(f"COVERAGE_SURFACE_MISSING:{surface}" if status is None else f"COVERAGE_SURFACE_NOT_PROVIDED:{surface}:{status}")

    claim_support_statuses: dict[str, str] = {}
    unsupported_claims: list[str] = []
    seen_claims: set[str] = set()
    duplicate_claim = False
    for item in claim_boundary_matrix:
        if not isinstance(item, dict):
            if positive_gates:
                duplicate_claim = True
            continue
        claim_id = item.get("claimId")
        if not isinstance(claim_id, str) or not claim_id.strip():
            if positive_gates:
                duplicate_claim = True
            continue
        claim_id = claim_id.strip()
        status = item.get("supportStatus") or item.get("support")
        if not isinstance(status, str) or not status.strip():
            status = "missing"
        status = status.strip()
        if claim_id in seen_claims:
            duplicate_claim = True
            continue
        seen_claims.add(claim_id)
        claim_support_statuses[claim_id] = status
        if status == "unsupported":
            unsupported_claims.append(claim_id)

    if duplicate_claim:
        unsafe_projection = True
        reason_codes.append(UNSAFE_REASON)

    for claim_id, allowed_statuses in _REQUIRED_CLAIM_STATUSES.items():
        status = claim_support_statuses.get(claim_id)
        if status not in allowed_statuses:
            reason_codes.append(f"CLAIM_BOUNDARY_STATUS_UNSAFE:{claim_id}:{status or 'missing'}")

    # Human-readable claimBoundaries must also declare the broad forbidden classes.
    must_not = claim_boundaries.get("mustNotSupportAlone")
    if isinstance(must_not, list):
        must_not_joined = "\n".join(str(item) for item in must_not)
        for token in ("absence", "external", "semantic", "runtime", "final"):
            if token not in must_not_joined:
                reason_codes.append(f"CLAIM_BOUNDARIES_MISSING_FORBIDDEN_CLASS:{token}")
    elif positive_gates:
        reason_codes.append("CLAIM_BOUNDARIES_MISSING")

    tool_statuses: dict[str, str] = {}
    tool_policies: dict[str, str] = {}
    observed_tool_ids: list[str] = []
    seen_tools: set[str] = set()
    duplicate_tool = False
    for item in tool_evidence_matrix:
        if not isinstance(item, dict):
            if positive_gates:
                duplicate_tool = True
            continue
        tool_id = item.get("toolId")
        if not isinstance(tool_id, str) or not tool_id.strip():
            if positive_gates:
                duplicate_tool = True
            continue
        tool_id = tool_id.strip()
        status = item.get("status") if isinstance(item.get("status"), str) else "missing"
        policy = item.get("consumerPolicy") if isinstance(item.get("consumerPolicy"), str) else "missing"
        if tool_id in seen_tools:
            duplicate_tool = True
            continue
        seen_tools.add(tool_id)
        observed_tool_ids.append(tool_id)
        tool_statuses[tool_id] = status
        tool_policies[tool_id] = policy

    if duplicate_tool:
        unsafe_projection = True
        reason_codes.append(UNSAFE_REASON)

    if observed_tool_ids != CURRENT_SIX_TOOL_IDS:
        reason_codes.append("TOOL_EVIDENCE_MATRIX_CURRENT_SIX_ORDER_MISMATCH")
    for tool_id in CURRENT_SIX_TOOL_IDS:
        status = tool_statuses.get(tool_id)
        policy = tool_policies.get(tool_id)
        if status not in _OK_TOOL_STATUSES:
            reason_codes.append(f"TOOL_EVIDENCE_MATRIX_TOOL_NOT_OK:{tool_id}:{status or 'missing'}")
        if policy not in _LOCAL_TOOL_POLICIES:
            reason_codes.append(f"TOOL_EVIDENCE_MATRIX_POLICY_UNSAFE:{tool_id}:{policy or 'missing'}")

    declared_required_tools = _declared_required_tool_ids(contract)
    missing_required_tools = [tool_id for tool_id in declared_required_tools if tool_id not in seen_tools]
    for tool_id in missing_required_tools:
        reason_codes.append(f"TOOL_EVIDENCE_MATRIX_MISSING_REQUIRED_TOOL:{tool_id}")

    # Only a contract that claims clean gates is unsafe for incomplete positive projection.
    completeness_reasons = [
        code for code in reason_codes
        if code.startswith((
            "COVERAGE_SURFACE_",
            "CLAIM_BOUNDARY_STATUS_UNSAFE:",
            "CLAIM_BOUNDARIES_MISSING",
            "TOOL_EVIDENCE_MATRIX_CURRENT_SIX_ORDER_MISMATCH",
            "TOOL_EVIDENCE_MATRIX_TOOL_NOT_OK:",
            "TOOL_EVIDENCE_MATRIX_POLICY_UNSAFE:",
            "TOOL_EVIDENCE_MATRIX_MISSING_REQUIRED_TOOL:",
        ))
    ]
    if positive_gates and completeness_reasons:
        unsafe_projection = True
        reason_codes.append(UNSAFE_REASON)

    ready = positive_gates and not reason_codes and not unsafe_projection
    summary = _summary_base(reason_codes=reason_codes)
    summary.update({
        "ready": ready,
        "localStaticEvidenceReady": ready,
        "summary": (
            "S4 static evidence artifact is ready for bounded local claim support."
            if ready
            else "S4 static evidence artifact is not clean complete local evidence."
        ),
        "systemStability": system_status,
        "evidenceReadiness": evidence_status,
        "claimSupportReadiness": claim_status,
        "hasClaimBoundaryMatrix": bool(claim_boundary_matrix),
        "hasToolEvidenceMatrix": bool(tool_evidence_matrix),
        "claimBoundaryMatrixCount": len(claim_boundary_matrix),
        "toolEvidenceMatrixCount": len(tool_evidence_matrix),
        "declaredRequiredToolIds": declared_required_tools,
        "observedToolIds": observed_tool_ids,
        "missingRequiredToolIds": missing_required_tools,
        "requiredCoverageStatuses": required_coverage_statuses,
        "claimSupportStatuses": claim_support_statuses,
        "toolMatrixStatuses": tool_statuses,
        "toolConsumerPolicies": tool_policies,
        "unsupportedClaims": sorted(unsupported_claims),
        "unsafeProjection": unsafe_projection,
    })
    summary["reasonCodes"] = sorted(set(summary["reasonCodes"]))
    return summary
