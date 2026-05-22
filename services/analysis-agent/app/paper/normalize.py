from __future__ import annotations

from typing import Any

from .models import EvidenceLedgerRow


def normalize_s4(bundle: dict[str, Any]) -> tuple[dict[str, Any], list[EvidenceLedgerRow], list[dict[str, Any]]]:
    case_id = bundle["caseId"]
    build_target_id = bundle["buildTargetId"]
    producer_run = bundle.get("s4ProducerRunId")
    ledger: list[EvidenceLedgerRow] = []
    findings = []
    source_file_to_finding: dict[str, str] = {}
    function_to_finding: dict[str, str] = {}
    for finding in bundle.get("findings", []):
        finding_id = finding["findingId"]
        source_file_id = (finding.get("location") or {}).get("sourceFileId")
        if source_file_id and source_file_id not in source_file_to_finding:
            source_file_to_finding[source_file_id] = finding_id
        function_id = finding.get("functionId")
        if function_id and function_id not in function_to_finding:
            function_to_finding[function_id] = finding_id
    for finding in bundle.get("findings", []):
        finding_id = finding["findingId"]
        text = finding.get("message") or finding.get("ruleId") or finding_id
        surface_status = _s4_surface_status(bundle, "findings")
        diagnostic_row = surface_status != "produced"
        prefix = "s3-diagnostic" if diagnostic_row else "s3-evidence"
        evidence_ref = f"{prefix}:s4:finding:{finding_id}"
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
                surfaceStatus=surface_status,
                producerTrace=finding.get("trace", {}),
                diagnostic=diagnostic_row,
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
    for surface in ["evidence", "sourceFiles", "functions", "includeEdges", "libraries", "toolRuns"]:
        surface_status = _s4_surface_status(bundle, surface)
        for row in bundle.get(surface, []):
            row_id = _s4_row_id(row, surface)
            diagnostic_row = _s4_row_is_diagnostic(row, surface, surface_status)
            related_finding_id = _s4_related_finding_id(
                row,
                surface,
                source_file_to_finding=source_file_to_finding,
                function_to_finding=function_to_finding,
            )
            ledger.append(
                EvidenceLedgerRow(
                    evidenceRef=f"{'s3-diagnostic' if diagnostic_row else 's3-evidence'}:s4:{surface}:{row_id}",
                    caseId=case_id,
                    buildTargetId=build_target_id,
                    producer="s4",
                    producerRunId=producer_run,
                    rawObjectRef=row.get("trace", {}).get("rawObjectRef"),
                    sourceId=row_id,
                    relatedFindingId=related_finding_id,
                    evidenceType=_s4_evidence_type(surface),
                    text=_s4_row_text(row, surface),
                    surfaceStatus=surface_status,
                    producerTrace=row.get("trace", {}),
                    diagnostic=diagnostic_row,
                )
            )
    for surface in ["targetMetadata", "staticEvidenceContract", "claimBoundaryMatrix", "claimBoundaries"]:
        surface_status = _s4_surface_status(bundle, surface)
        row_value = bundle.get(surface)
        if row_value is None:
            continue
        diagnostic_row = surface_status != "produced"
        prefix = "s3-diagnostic" if diagnostic_row else "s3-evidence"
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=f"{prefix}:s4:{surface}:{surface}",
                caseId=case_id,
                buildTargetId=build_target_id,
                producer="s4",
                producerRunId=producer_run,
                rawObjectRef=_s4_singleton_raw_ref(row_value, surface),
                sourceId=surface,
                evidenceType=_s4_evidence_type(surface),
                text=_s4_singleton_text(row_value, surface),
                surfaceStatus=surface_status,
                producerTrace=_s4_singleton_trace(row_value, surface, bundle),
                diagnostic=diagnostic_row,
            )
        )
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
        "evidence": bundle.get("evidence", []),
        "sourceFiles": bundle.get("sourceFiles", []),
        "functions": bundle.get("functions", []),
        "includeEdges": bundle.get("includeEdges", []),
        "libraries": bundle.get("libraries", []),
        "toolRuns": bundle.get("toolRuns", []),
        "staticEvidenceContract": bundle.get("staticEvidenceContract", {}),
        "diagnostics": bundle.get("diagnostics", []),
        "claimBoundaries": bundle.get("claimBoundaries", {}),
        "claimBoundaryMatrix": bundle.get("claimBoundaryMatrix", []),
    }
    return normalized_bundle, ledger, findings


def _s4_row_id(row: dict[str, Any], surface: str) -> str:
    id_fields = {
        "evidence": "evidenceId",
        "sourceFiles": "sourceFileId",
        "functions": "functionId",
        "includeEdges": "includeEdgeId",
        "libraries": "libraryId",
        "toolRuns": "toolRunId",
    }
    return str(row[id_fields[surface]])


def _s4_evidence_type(surface: str) -> str:
    return {
        "evidence": "s4_evidence",
        "sourceFiles": "s4_source_file",
        "functions": "s4_function",
        "includeEdges": "s4_include_edge",
        "libraries": "s4_library",
        "toolRuns": "s4_tool_run",
        "targetMetadata": "s4_target_metadata",
        "staticEvidenceContract": "s4_static_evidence_contract",
        "claimBoundaryMatrix": "s4_claim_boundary_matrix",
        "claimBoundaries": "s4_claim_boundaries",
    }[surface]


def _s4_related_finding_id(
    row: dict[str, Any],
    surface: str,
    *,
    source_file_to_finding: dict[str, str],
    function_to_finding: dict[str, str],
) -> str | None:
    if surface == "evidence":
        return row.get("findingId")
    if surface == "sourceFiles":
        return source_file_to_finding.get(row.get("sourceFileId"))
    if surface == "functions":
        return function_to_finding.get(row.get("functionId"))
    return None


def _s4_row_text(row: dict[str, Any], surface: str) -> str:
    if surface == "evidence":
        return row.get("text") or row.get("evidenceId") or ""
    if surface == "sourceFiles":
        path = row.get("path") or row.get("sourceFileId")
        language = row.get("language")
        return f"Source file {path}" + (f" ({language})" if language else "")
    if surface == "functions":
        return row.get("qualifiedName") or row.get("name") or row.get("functionId") or ""
    if surface == "includeEdges":
        return row.get("text") or row.get("includeEdgeId") or ""
    if surface == "libraries":
        return row.get("name") or row.get("libraryId") or ""
    if surface == "toolRuns":
        tool = row.get("toolId") or row.get("toolRunId")
        status = row.get("status")
        count = row.get("findingsCount")
        parts = [f"SAST tool run {tool}"]
        if status is not None:
            parts.append(f"status={status}")
        if count is not None:
            parts.append(f"findings={count}")
        if row.get("coverageDegraded") is True:
            reasons = row.get("coverageReasons") or []
            reason_text = ",".join(str(reason) for reason in reasons) if isinstance(reasons, list) else str(reasons)
            parts.append("coverageDegraded=true")
            if reason_text:
                parts.append(f"coverageReasons={reason_text}")
        coverage = row.get("coverage")
        if isinstance(coverage, dict) and coverage.get("coverageKind"):
            parts.append(f"coverageKind={coverage['coverageKind']}")
        return "; ".join(parts)
    return ""


def _s4_row_is_diagnostic(row: dict[str, Any], surface: str, surface_status: str) -> bool:
    """Classify producer caveats as diagnostic rows without marking liveness failed.

    S4 may report `status=success` for a Semgrep tool run while also exposing
    effective-coverage caveats. Those caveats are producer diagnostics/contract
    notes, not positive or negative security evidence. Prefixing the row as
    `s3-diagnostic` keeps it visible to B2/B4 packets without letting a
    finalizer cite it as ordinary S4 evidence.
    """

    if surface_status != "produced":
        return True
    if surface == "toolRuns" and row.get("coverageDegraded") is True:
        return True
    return False


def _s4_surface_status(bundle: dict[str, Any], surface: str) -> str:
    return ((bundle.get("surfaceStatus") or {}).get(surface) or {}).get("status") or "produced"


def _s4_singleton_text(value: Any, surface: str) -> str:
    if surface == "targetMetadata" and isinstance(value, dict):
        language = value.get("language")
        compile_context = (value.get("compileContext") or {}).get("ref")
        parts = ["S4 target metadata"]
        if language:
            parts.append(f"language={language}")
        if compile_context:
            parts.append(f"compileContextRef={compile_context}")
        return "; ".join(parts)
    if surface == "staticEvidenceContract":
        return "S4 static evidence contract and producer claim boundaries."
    if surface == "claimBoundaryMatrix":
        count = len(value) if isinstance(value, list) else 0
        return f"S4 claim boundary matrix entries={count}."
    if surface == "claimBoundaries":
        return "S4 claim boundary policy."
    return f"S4 {surface}."


def _s4_singleton_trace(value: Any, surface: str, bundle: dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("trace"), dict):
        return value["trace"]
    return {
        "caseId": bundle.get("caseId"),
        "buildTargetId": bundle.get("buildTargetId"),
        "bundleRef": bundle.get("bundleRef"),
        "s4ProducerRunId": bundle.get("s4ProducerRunId"),
        "surface": surface,
        "rawObjectRef": surface,
    }


def _s4_singleton_raw_ref(value: Any, surface: str) -> str:
    if isinstance(value, dict):
        trace = value.get("trace") or {}
        if trace.get("rawObjectRef"):
            return str(trace["rawObjectRef"])
    return surface


def normalize_s5_rows(response: dict[str, Any], *, evidence_type: str) -> tuple[dict[str, Any], list[EvidenceLedgerRow]]:
    case_id = response["caseId"]
    build_target_id = response["buildTargetId"]
    producer_run = response.get("s5ProducerRunId")
    finding_id = response.get("findingId")
    ledger: list[EvidenceLedgerRow] = []
    rows = response.get("rows", []) or []
    response_surface_status = response.get("surfaceStatus")
    coverage = response.get("contextCoverage") if isinstance(response.get("contextCoverage"), dict) else {}
    coverage_status = coverage.get("coverageStatus") if evidence_type == "s5_finding_context" else None
    coverage_marks_context_diagnostic = coverage_status in {"partial", "non_overlapping", "not_available", "error"}
    for row in rows:
        item_id = row["itemId"]
        row_surface_status = row.get("surfaceStatus")
        effective_surface_status = row_surface_status if response_surface_status == "produced" else response_surface_status
        if coverage_marks_context_diagnostic:
            effective_surface_status = coverage_status
        diagnostic_row = effective_surface_status != "produced"
        prefix = "s3-diagnostic" if diagnostic_row else "s3-evidence"
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=f"{prefix}:s5:{evidence_type}:{item_id}",
                caseId=case_id,
                buildTargetId=build_target_id,
                producer="s5",
                producerRunId=producer_run,
                rawObjectRef=item_id,
                sourceId=item_id,
                relatedFindingId=finding_id,
                evidenceType=evidence_type,
                text=row.get("text", ""),
                surfaceStatus=effective_surface_status,
                visibleLeakageClass=row.get("visibleLeakageClass"),
                producerTrace=row.get("producerTrace", {}),
                diagnostic=diagnostic_row,
            )
        )
    for diagnostic in response.get("diagnostics", []) or []:
        diag_id = diagnostic.get("code", "S5_DIAGNOSTIC") + f":{len(ledger)}"
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=f"s3-diagnostic:s5:{evidence_type}:{response.get('findingId', 'target')}:{diag_id}",
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
    for diagnostic in coverage.get("diagnostics", []) or []:
        code = diagnostic.get("code", "S5_CONTEXT_COVERAGE_DIAGNOSTIC")
        diag_id = f"{code}:contextCoverage:{len(ledger)}"
        ledger.append(
            EvidenceLedgerRow(
                evidenceRef=f"s3-diagnostic:s5:{evidence_type}:{response.get('findingId', 'target')}:{diag_id}",
                caseId=case_id,
                buildTargetId=build_target_id,
                producer="s5",
                producerRunId=producer_run,
                rawObjectRef=diag_id,
                sourceId=diag_id,
                relatedFindingId=finding_id,
                evidenceType="s5_diagnostic",
                text=diagnostic.get("message") or f"S5 contextCoverage diagnostic: {code}",
                surfaceStatus=diagnostic.get("surfaceStatus") or coverage.get("coverageStatus") or response_surface_status,
                visibleLeakageClass=diagnostic.get("visibleLeakageClass") or "generic",
                producerTrace={"contextCoverage": True},
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
        "contextCoverage": response.get("contextCoverage"),
        "exploration": response.get("exploration"),
        "diagnostics": response.get("diagnostics", []),
        "retrievalTrace": response.get("retrievalTrace", {}),
    }
    return normalized, ledger
