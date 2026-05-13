"""S4 staticEvidenceContract consumer helpers.

These helpers intentionally classify only whether S4's local deterministic
static evidence artifact is ready enough to use as a clean SAST artifact.  They
do not score vulnerability quality and do not emit a final security verdict.
"""

from __future__ import annotations

from typing import Any


def extract_static_evidence_contract(*payloads: Any) -> dict:
    """Return the first S4 staticEvidenceContract dict from response payloads."""
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        contract = payload.get("staticEvidenceContract")
        if isinstance(contract, dict):
            return contract
    return {}


def summarize_static_evidence_contract(contract: Any) -> dict:
    """Summarize S3 consumer-readiness for an S4 static evidence contract.

    Ready means the contract is present and the S4-local runtime gates all say
    the artifact is cleanly consumable for bounded local static claim support:

    - systemStability == pass
    - evidenceReadiness == ready
    - claimSupportReadiness == pass
    - claimBoundaryMatrix[] present
    - toolEvidenceMatrix[] present

    This is deliberately stricter than transport success. A degraded/partial
    artifact can still contain useful positive findings, but S3 must not treat
    it as clean complete evidence or convert empty findings into negative
    security evidence.
    """
    if not isinstance(contract, dict) or not contract:
        return {
            "ready": False,
            "reasonCodes": ["STATIC_EVIDENCE_CONTRACT_MISSING"],
            "summary": "S4 staticEvidenceContract is absent; local SAST artifact readiness is unknown.",
            "systemStability": None,
            "evidenceReadiness": None,
            "claimSupportReadiness": None,
            "hasClaimBoundaryMatrix": False,
            "hasToolEvidenceMatrix": False,
        }

    gates = contract.get("gates") if isinstance(contract.get("gates"), dict) else {}
    system_gate = gates.get("systemStability") if isinstance(gates.get("systemStability"), dict) else {}
    evidence_gate = gates.get("evidenceReadiness") if isinstance(gates.get("evidenceReadiness"), dict) else {}
    claim_gate = gates.get("claimSupportReadiness") if isinstance(gates.get("claimSupportReadiness"), dict) else {}

    system_status = system_gate.get("status")
    evidence_status = evidence_gate.get("status")
    claim_status = claim_gate.get("status")
    has_claim_boundary_matrix = isinstance(contract.get("claimBoundaryMatrix"), list)
    has_tool_evidence_matrix = isinstance(contract.get("toolEvidenceMatrix"), list)

    reason_codes: list[str] = []
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

    if not has_claim_boundary_matrix:
        reason_codes.append("CLAIM_BOUNDARY_MATRIX_MISSING")
    if not has_tool_evidence_matrix:
        reason_codes.append("TOOL_EVIDENCE_MATRIX_MISSING")

    ready = (
        system_status == "pass"
        and evidence_status == "ready"
        and claim_status == "pass"
        and has_claim_boundary_matrix
        and has_tool_evidence_matrix
    )
    return {
        "ready": ready,
        "reasonCodes": sorted(set(reason_codes)),
        "summary": (
            "S4 static evidence artifact is ready for bounded local claim support."
            if ready
            else "S4 static evidence artifact is not clean complete local evidence."
        ),
        "systemStability": system_status,
        "evidenceReadiness": evidence_status,
        "claimSupportReadiness": claim_status,
        "hasClaimBoundaryMatrix": has_claim_boundary_matrix,
        "hasToolEvidenceMatrix": has_tool_evidence_matrix,
    }
