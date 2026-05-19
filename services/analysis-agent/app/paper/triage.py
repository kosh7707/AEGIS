from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from .errors import PaperContractError
from .models import EvidenceLedgerRow, TriageEnvelopeRow, TriageVerdict


def validate_triage_row(row: dict[str, Any], *, known_evidence_refs: set[str]) -> TriageEnvelopeRow:
    try:
        parsed = TriageEnvelopeRow.model_validate(row)
    except ValidationError as exc:
        raise PaperContractError(f"Invalid triage row: {exc.errors()}") from exc
    missing = [ref for ref in parsed.citedEvidenceRefs if ref not in known_evidence_refs]
    if missing:
        raise PaperContractError(f"Triage row cites unknown evidence refs: {missing}")
    if parsed.verdict in {TriageVerdict.TP, TriageVerdict.FP} and not parsed.citedEvidenceRefs:
        raise PaperContractError("TP/FP without evidence refs is invalid")
    return parsed


def fallback_unknown_for_finding(finding: dict[str, Any], *, reason: str = "UNKNOWN_INSUFFICIENT_CONTEXT") -> dict[str, Any]:
    return {
        "findingId": finding["findingId"],
        "verdict": "UNKNOWN",
        "rationale": "The available bounded evidence is insufficient for a responsible TP/FP decision.",
        "citedEvidenceRefs": [],
        "claimEvidenceLinks": [],
        "unsupportedClaims": [],
        "unknownReason": reason,
        "diagnosticRefsUsed": [],
        "boundaryNotes": ["UNKNOWN is a triage outcome, not producer diagnostic promotion."],
    }


def attach_claim_links_to_ledger(ledger: list[EvidenceLedgerRow], triage_rows: list[TriageEnvelopeRow]) -> list[EvidenceLedgerRow]:
    by_ref = {row.evidenceRef: row for row in ledger}
    for triage in triage_rows:
        for link in triage.claimEvidenceLinks:
            for ref in link.evidenceRefs:
                if ref in by_ref:
                    by_ref[ref].claimLinks.append({"findingId": triage.findingId, **link.model_dump(mode="json")})
        for ref in triage.citedEvidenceRefs:
            if ref in by_ref and not any(c.get("findingId") == triage.findingId for c in by_ref[ref].claimLinks):
                by_ref[ref].claimLinks.append({"findingId": triage.findingId, "claim": triage.rationale, "stance": "cited", "evidenceRefs": [ref]})
    return list(by_ref.values())
