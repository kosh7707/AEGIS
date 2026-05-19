from __future__ import annotations

from typing import Any

from .models import EvidenceLedgerRow


def normalize_s4(bundle: dict[str, Any]) -> tuple[dict[str, Any], list[EvidenceLedgerRow], list[dict[str, Any]]]:
    case_id = bundle["caseId"]
    build_target_id = bundle["buildTargetId"]
    producer_run = bundle.get("s4ProducerRunId")
    ledger: list[EvidenceLedgerRow] = []
    findings = []
    for finding in bundle.get("findings", []):
        finding_id = finding["findingId"]
        text = finding.get("message") or finding.get("ruleId") or finding_id
        evidence_ref = f"s3-evidence:s4:finding:{finding_id}"
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=evidence_ref,
                caseId=case_id,
                buildTargetId=build_target_id,
                producer="s4",
                producerRunId=producer_run,
                rawObjectRef=finding.get("trace", {}).get("rawObjectRef"),
                sourceId=finding_id,
                relatedFindingId=finding_id,
                evidenceType="s4_finding",
                text=text,
                surfaceStatus="produced",
                producerTrace=finding.get("trace", {}),
            )
        )
        normalized = {
            "findingId": finding_id,
            "toolId": finding.get("toolId"),
            "ruleId": finding.get("ruleId"),
            "severity": finding.get("severity"),
            "message": finding.get("message"),
            "cweCandidates": finding.get("cweCandidates", []),
            "location": finding.get("location", {}),
            "functionId": finding.get("functionId"),
            "evidenceRefs": [evidence_ref],
            "s4Trace": finding.get("trace", {}),
        }
        findings.append(normalized)
    for diagnostic in bundle.get("diagnostics", []):
        diagnostic_id = diagnostic.get("diagnosticId", f"diagnostic:{len(ledger)}")
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=f"s3-diagnostic:s4:{diagnostic_id}",
                caseId=case_id,
                buildTargetId=build_target_id,
                producer="s4",
                producerRunId=producer_run,
                rawObjectRef=diagnostic.get("trace", {}).get("rawObjectRef"),
                sourceId=diagnostic_id,
                evidenceType="s4_diagnostic",
                text=diagnostic.get("message", "S4 producer diagnostic"),
                surfaceStatus=diagnostic.get("surfaceStatus") or "diagnostic",
                producerTrace=diagnostic.get("trace", {}),
                diagnostic=True,
            )
        )
    normalized_bundle = {
        "schemaVersion": "s3-normalized-s4-static-evidence-v1",
        "caseId": case_id,
        "buildTargetId": build_target_id,
        "s4ProducerRunId": producer_run,
        "bundleRef": bundle.get("bundleRef"),
        "surfaceStatus": bundle.get("surfaceStatus", {}),
        "findings": findings,
        "diagnostics": bundle.get("diagnostics", []),
        "claimBoundaries": bundle.get("claimBoundaries", {}),
        "claimBoundaryMatrix": bundle.get("claimBoundaryMatrix", []),
    }
    return normalized_bundle, ledger, findings


def normalize_s5_rows(response: dict[str, Any], *, evidence_type: str) -> tuple[dict[str, Any], list[EvidenceLedgerRow]]:
    case_id = response["caseId"]
    build_target_id = response["buildTargetId"]
    producer_run = response.get("s5ProducerRunId")
    finding_id = response.get("findingId")
    ledger: list[EvidenceLedgerRow] = []
    rows = response.get("rows", []) or []
    for row in rows:
        item_id = row["itemId"]
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=f"s3-evidence:s5:{item_id}",
                caseId=case_id,
                buildTargetId=build_target_id,
                producer="s5",
                producerRunId=producer_run,
                rawObjectRef=item_id,
                sourceId=item_id,
                relatedFindingId=finding_id,
                evidenceType=evidence_type,
                text=row.get("text", ""),
                surfaceStatus=row.get("surfaceStatus"),
                visibleLeakageClass=row.get("visibleLeakageClass"),
                producerTrace=row.get("producerTrace", {}),
            )
        )
    for diagnostic in response.get("diagnostics", []) or []:
        diag_id = diagnostic.get("code", "S5_DIAGNOSTIC") + f":{len(ledger)}"
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=f"s3-diagnostic:s5:{response.get('findingId', 'target')}:{diag_id}",
                caseId=case_id,
                buildTargetId=build_target_id,
                producer="s5",
                producerRunId=producer_run,
                rawObjectRef=diag_id,
                sourceId=diag_id,
                relatedFindingId=finding_id,
                evidenceType="s5_diagnostic",
                text=diagnostic.get("message", "S5 producer diagnostic"),
                surfaceStatus=diagnostic.get("surfaceStatus"),
                visibleLeakageClass=diagnostic.get("visibleLeakageClass"),
                producerTrace={},
                diagnostic=True,
            )
        )
    normalized = {
        "schemaVersion": "s3-normalized-s5-context-v1",
        "caseId": case_id,
        "buildTargetId": build_target_id,
        "findingId": response.get("findingId"),
        "s5ProducerRunId": producer_run,
        "retrievalRunId": response.get("retrievalRunId"),
        "rowSetId": response.get("rowSetId"),
        "surfaceStatus": response.get("surfaceStatus"),
        "rows": rows,
        "diagnostics": response.get("diagnostics", []),
        "retrievalTrace": response.get("retrievalTrace", {}),
    }
    return normalized, ledger
