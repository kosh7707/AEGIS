from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_ABSENT_REASON = "STATIC_EVIDENCE_CONTRACT_ABSENT"
_MALFORMED_REASON = "STATIC_EVIDENCE_CONTRACT_MALFORMED"


def summarize_static_evidence_contract(payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Summarize only the S4 static evidence contract surfaces in a JSON payload.

    This helper is intentionally pure JSON: it does not import S4 runtime app modules,
    execute tools, read raw execution results, call services, or score security impact.
    """

    contract, location = _locate_contract(payload)
    if contract is None:
        reason = _MALFORMED_REASON if location == "malformed" else _ABSENT_REASON
        return {
            "contractPresent": False,
            "contractLocation": location,
            "systemStability": "unknown",
            "evidenceReadiness": "not_ready",
            "qualityEvaluation": "unknown",
            "localStaticEvidenceReady": False,
            "systemReasonCodes": [reason],
            "evidenceReasonCodes": [reason],
            "toolAnomalyReasonCodes": [],
            "notProvidedSurfaces": [],
            "partialSurfaces": [],
            "blockingSurfaces": [],
            "mustNotSupportAlone": [],
            "toolMatrixStatuses": {},
            "toolConsumerPolicies": {},
        }

    gates = _mapping(contract.get("gates")) or {}
    coverage = _mapping(contract.get("coverage")) or {}
    boundaries = _mapping(contract.get("claimBoundaries")) or {}
    static_execution = _mapping(coverage.get("staticToolExecution")) or {}
    system_gate = _mapping(gates.get("systemStability")) or {}
    readiness_gate = _mapping(gates.get("evidenceReadiness")) or {}
    quality_gate = _mapping(gates.get("qualityEvaluation")) or {}

    system_status = _status(system_gate, "unknown")
    readiness_status = _status(readiness_gate, "not_ready")

    return {
        "contractPresent": True,
        "contractLocation": location,
        "systemStability": system_status,
        "evidenceReadiness": readiness_status,
        "qualityEvaluation": _status(quality_gate, "unknown"),
        "localStaticEvidenceReady": system_status == "pass" and readiness_status == "ready",
        "systemReasonCodes": _string_list(system_gate.get("reasonCodes")),
        "evidenceReasonCodes": _string_list(readiness_gate.get("reasonCodes")),
        "toolAnomalyReasonCodes": _string_list(static_execution.get("anomalyReasonCodes")),
        "notProvidedSurfaces": _not_provided_surfaces(coverage),
        "partialSurfaces": _string_list(readiness_gate.get("partialSurfaces")),
        "blockingSurfaces": _string_list(readiness_gate.get("blockingSurfaces")),
        "mustNotSupportAlone": _string_list(boundaries.get("mustNotSupportAlone")),
        "toolMatrixStatuses": _tool_matrix_field(contract, "status"),
        "toolConsumerPolicies": _tool_matrix_field(contract, "consumerPolicy"),
    }


def _locate_contract(payload: Mapping[str, Any] | Any) -> tuple[Mapping[str, Any] | None, str]:
    payload_map = _mapping(payload)
    if payload_map is None:
        return None, "malformed"

    if "staticEvidenceContract" in payload_map:
        contract = _mapping(payload_map.get("staticEvidenceContract"))
        if contract is None:
            return None, "malformed"
        return contract, "top-level"

    scan = _mapping(payload_map.get("scan"))
    if scan is not None and "staticEvidenceContract" in scan:
        contract = _mapping(scan.get("staticEvidenceContract"))
        if contract is None:
            return None, "malformed"
        return contract, "scan.staticEvidenceContract"

    return None, "missing"


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _status(gate: Mapping[str, Any], default: str) -> str:
    value = gate.get("status")
    return value if isinstance(value, str) and value else default


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _not_provided_surfaces(coverage: Mapping[str, Any]) -> list[str]:
    surfaces: list[str] = []
    for surface, entry in coverage.items():
        entry_map = _mapping(entry)
        if entry_map is not None and entry_map.get("status") == "not_provided":
            surfaces.append(str(surface))
    return surfaces


def _tool_matrix_field(contract: Mapping[str, Any], field: str) -> dict[str, str]:
    matrix = contract.get("toolEvidenceMatrix")
    if not isinstance(matrix, list):
        return {}

    result: dict[str, str] = {}
    for entry in matrix:
        entry_map = _mapping(entry)
        if entry_map is None:
            continue
        tool_id = entry_map.get("toolId")
        value = entry_map.get(field)
        if isinstance(tool_id, str) and isinstance(value, str):
            result[tool_id] = value
    return result
