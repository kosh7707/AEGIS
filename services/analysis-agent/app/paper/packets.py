from __future__ import annotations

import re
from typing import Any

from .errors import PaperContractError


def rows_for_finding(ledger_rows: list[dict[str, Any]], finding_id: str) -> list[dict[str, Any]]:
    primary_ref = f"s3-evidence:s4:finding:{finding_id}"
    rows = []
    for row in ledger_rows:
        related = row.get("relatedFindingId")
        if row.get("evidenceRef") == primary_ref:
            rows.append(row)
        elif row.get("producer") == "s4" and related == finding_id:
            rows.append(row)
        elif row.get("producer") == "s5" and related == finding_id:
            rows.append(row)
        elif row.get("diagnostic") and related in {None, finding_id}:
            rows.append(row)
    return rows


def render_packets(*, case_id: str, findings: list[dict[str, Any]], ledger_rows: list[dict[str, Any]], triage_rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    triage_by_finding = {row["findingId"]: row for row in triage_rows}
    finding_packets: dict[str, dict[str, Any]] = {}
    case_packets = {name: {"caseId": case_id, "condition": name, "findings": []} for name in ["b0", "b1", "b2", "b3", "b4"]}
    for finding in findings:
        fid = finding["findingId"]
        triage = triage_by_finding.get(fid)
        rows = rows_for_finding(ledger_rows, fid)
        public_finding = _public_finding_view(finding)
        evidence_dump = [{"text": _public_text(r.get("text")), "evidenceType": r.get("evidenceType"), "diagnostic": r.get("diagnostic", False)} for r in rows]
        ledger_dump = [
            {
                "evidenceRef": r.get("evidenceRef"),
                "text": r.get("text"),
                "producer": r.get("producer"),
                "producerTrace": r.get("producerTrace", {}),
                "claimLinks": r.get("claimLinks", []),
                "diagnostic": r.get("diagnostic", False),
            }
            for r in rows
        ]
        packet = {
            "b0": {"finding": public_finding, "machineVerdict": None},
            "b1": {"finding": public_finding, "machineVerdict": _rationale_only_view(triage), "rawRationaleOnly": True},
            "b2": {"finding": public_finding, "machineVerdict": _evidence_dump_verdict_view(triage), "evidenceRows": evidence_dump, "ledgerVisible": False},
            "b3": {"finding": finding, "machineVerdict": None, "ledgerRows": ledger_dump, "ledgerVisible": True},
            "b4": {"finding": finding, "machineVerdict": triage, "ledgerRows": ledger_dump, "ledgerVisible": True},
        }
        validate_b2_b4_same_rows(packet["b2"], packet["b4"])
        finding_packets[fid] = packet
        for name, data in packet.items():
            case_packets[name]["findings"].append(data)
    return case_packets, finding_packets


def validate_b2_b4_same_rows(b2: dict[str, Any], b4: dict[str, Any]) -> None:
    b2_texts = [r.get("text") for r in b2.get("evidenceRows", [])]
    b4_texts = [r.get("text") for r in b4.get("ledgerRows", [])]
    if b2_texts != b4_texts:
        raise PaperContractError("B2/B4 evidence row text/order mismatch")


def _rationale_only_view(triage: dict[str, Any] | None) -> dict[str, Any] | None:
    if triage is None:
        return None
    return _sanitize_public_value({
        "findingId": triage.get("findingId"),
        "verdict": triage.get("verdict"),
        "rationale": triage.get("rationale"),
    })


def _public_finding_view(finding: dict[str, Any]) -> dict[str, Any]:
    return _strip_structural_keys(finding)


_STRUCTURAL_PACKET_KEYS = {
    "evidenceRef",
    "evidenceRefs",
    "s4Trace",
    "producerTrace",
    "rawObjectRef",
    "claimLinks",
    "claimEvidenceLinks",
}


def _strip_structural_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_structural_keys(child)
            for key, child in value.items()
            if key not in _STRUCTURAL_PACKET_KEYS
        }
    if isinstance(value, list):
        return [_strip_structural_keys(child) for child in value]
    return value


def _evidence_dump_verdict_view(triage: dict[str, Any] | None) -> dict[str, Any] | None:
    if triage is None:
        return None
    return _sanitize_public_value({
        "findingId": triage.get("findingId"),
        "verdict": triage.get("verdict"),
        "rationale": triage.get("rationale"),
        "unsupportedClaims": triage.get("unsupportedClaims", []),
        "unknownReason": triage.get("unknownReason"),
        "boundaryNotes": triage.get("boundaryNotes", []),
    })


_EVIDENCE_REF_RE = re.compile(r"\bs3-(?:evidence|diagnostic):[A-Za-z0-9_.:/-]+")


def _public_text(value: Any) -> Any:
    if isinstance(value, str):
        return _EVIDENCE_REF_RE.sub("[hidden-evidence-ref]", value)
    return value


def _sanitize_public_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _sanitize_public_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_sanitize_public_value(child) for child in value]
    return _public_text(value)


def validate_case_finding_packet_consistency(case_packets: dict[str, Any], finding_packets: dict[str, dict[str, Any]]) -> None:
    for condition, case_packet in case_packets.items():
        by_id = {item["finding"]["findingId"]: item for item in case_packet.get("findings", [])}
        for fid, packets in finding_packets.items():
            if by_id.get(fid) != packets[condition]:
                raise PaperContractError(f"case/finding packet mismatch for {condition}/{fid}")
