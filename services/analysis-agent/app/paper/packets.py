from __future__ import annotations

from typing import Any

from .errors import PaperContractError


def rows_for_finding(ledger_rows: list[dict[str, Any]], finding_id: str) -> list[dict[str, Any]]:
    primary_ref = f"s3-evidence:s4:finding:{finding_id}"
    rows = []
    for row in ledger_rows:
        related = row.get("relatedFindingId")
        if row.get("evidenceRef") == primary_ref:
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
        evidence_dump = [{"text": r.get("text"), "evidenceType": r.get("evidenceType"), "diagnostic": r.get("diagnostic", False)} for r in rows]
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
            "b0": {"finding": finding, "machineVerdict": None},
            "b1": {"finding": finding, "machineVerdict": triage, "rawRationaleOnly": True},
            "b2": {"finding": finding, "machineVerdict": triage, "evidenceRows": evidence_dump, "ledgerVisible": False},
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


def validate_case_finding_packet_consistency(case_packets: dict[str, Any], finding_packets: dict[str, dict[str, Any]]) -> None:
    for condition, case_packet in case_packets.items():
        by_id = {item["finding"]["findingId"]: item for item in case_packet.get("findings", [])}
        for fid, packets in finding_packets.items():
            if by_id.get(fid) != packets[condition]:
                raise PaperContractError(f"case/finding packet mismatch for {condition}/{fid}")
