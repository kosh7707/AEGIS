from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from .artifacts import CaseArtifacts, trace_stage
from .errors import PaperContractError
from .llm_client import LlmTriageClient
from .models import CaseStage, EvidenceLedgerRow, PaperCaseCreateRequest, StageProgress, StageResult
from .normalize import normalize_s4, normalize_s5_rows
from .observability import log_event
from .packets import render_packets, rows_for_finding, validate_case_finding_packet_consistency
from .s4_client import S4PaperClient
from .s5_client import S5PaperClient
from .triage import attach_claim_links_to_ledger, fallback_unknown_for_finding, validate_triage_row


MAX_ACQUISITION_ROUNDS = 3


class PaperCaseRunner:
    def __init__(self, *, s4_client: S4PaperClient | None = None, s5_client: S5PaperClient | None = None, llm_client: LlmTriageClient | None = None):
        self.s4_client = s4_client or S4PaperClient()
        self.s5_client = s5_client or S5PaperClient()
        self.llm_client = llm_client or LlmTriageClient()
        self.stage_results: dict[CaseStage, StageResult] = {}

    def _trace(
        self,
        artifacts: CaseArtifacts,
        stage: CaseStage,
        status: StageProgress,
        *,
        artifactRef: str | None = None,
        message: str | None = None,
    ) -> None:
        trace_stage(artifacts, stage, status, artifactRef=artifactRef, message=message)
        self.stage_results[stage] = StageResult(stage=stage, status=status, artifactRef=artifactRef, diagnostic=message)
        log_event(
            "paper stage updated",
            event="paper_stage",
            caseId=getattr(self, "_current_case_id", None),
            buildTargetId=getattr(self, "_current_build_target_id", None),
            paperRunId=getattr(self, "_current_paper_run_id", None),
            stage=stage.value,
            status=status.value,
            artifactRef=artifactRef,
            diagnostic=message,
        )

    async def run(self, case: PaperCaseCreateRequest) -> dict[str, Any]:
        self.stage_results = {}
        self._current_case_id = case.caseId
        self._current_build_target_id = case.buildTargetId
        self._current_paper_run_id = case.paperRunId
        artifacts = CaseArtifacts.from_request(case)
        log_event(
            "paper case run started",
            event="paper_case_run_started",
            caseId=case.caseId,
            buildTargetId=case.buildTargetId,
            paperRunId=case.paperRunId,
        )
        try:
            return await self._run_impl(case, artifacts)
        except Exception as exc:
            log_event(
                "paper case run failed",
                level=logging.ERROR,
                event="paper_case_run_failed",
                caseId=case.caseId,
                buildTargetId=case.buildTargetId,
                paperRunId=case.paperRunId,
                errorClass=type(exc).__name__,
            )
            raise

    async def _run_impl(self, case: PaperCaseCreateRequest, artifacts: CaseArtifacts) -> dict[str, Any]:
        self._trace(artifacts, CaseStage.BUILD_CONTEXT_READY, StageProgress.DONE, message="admitted build context ready")
        self._trace(artifacts, CaseStage.SETUP_RUNNING, StageProgress.RUNNING, message="producer setup started")
        _initialize_run_jsonl(artifacts)

        s4_raw, s4_request = await self.s4_client.produce_static_evidence(case)
        artifacts.append_jsonl("s4-requests.jsonl", s4_request)
        artifacts.write_json("s4-static-evidence.raw.json", s4_raw)
        s4_normalized, ledger, findings = normalize_s4(s4_raw)
        artifacts.write_json("s4-static-evidence.normalized.json", s4_normalized)
        self._trace(artifacts, CaseStage.S4_STATIC_EVIDENCE_READY, StageProgress.DONE, artifactRef="s4-static-evidence.raw.json")

        s5_prepare_raw: dict[str, Any] | None = None
        if findings:
            await self.s5_client.contract_snapshot(case)
            s5_prepare_raw, s5_prepare_request = await self.s5_client.prepare_code_kb(case)
            artifacts.append_jsonl("s5-setup-requests.jsonl", s5_prepare_request)
            artifacts.write_json("s5-code-kb.raw.json", s5_prepare_raw)
            artifacts.write_json("s5-code-kb.normalized.json", _normalize_s5_prepare(s5_prepare_raw))
            self._trace(artifacts, CaseStage.S5_CODE_KB_READY, StageProgress.DONE, artifactRef="s5-code-kb.raw.json")
        else:
            artifacts.write_json("s5-code-kb.raw.json", {"surfaceStatus": "not_available", "diagnostics": [], "reason": "zero findings; setup skipped"})
            artifacts.write_json("s5-code-kb.normalized.json", {"surfaceStatus": "not_available", "diagnostics": []})
            self._trace(artifacts, CaseStage.S5_CODE_KB_READY, StageProgress.DONE, message="zero findings; S5 setup not required")
        self._trace(artifacts, CaseStage.SETUP_RUNNING, StageProgress.DONE, message="producer setup completed")

        triage_rows = []
        s5_context_norm_rows: list[dict[str, Any]] = []
        s5_exploration_norm_rows: list[dict[str, Any]] = []
        s5_threat_norm_rows: list[dict[str, Any]] = []
        acquisition_transcripts: dict[str, dict[str, Any]] = {}
        finding_summaries: list[dict[str, Any]] = []
        if findings:
            code_kb_ref = (s5_prepare_raw or {}).get("codeKbRef") or f"s5-code-kb:{case.caseId}:{case.buildTargetId}"
            source_kg_ref = (s5_prepare_raw or {}).get("sourceKgRef") or f"s5-source-kg:{case.caseId}:{case.buildTargetId}"
            for finding in findings:
                finding_id = finding["findingId"]
                acquisition_transcripts[finding_id] = await self._run_acquisition_loop(
                    case,
                    artifacts=artifacts,
                    finding=finding,
                    ledger=ledger,
                    context_rows=s5_context_norm_rows,
                    exploration_rows=s5_exploration_norm_rows,
                    threat_rows=s5_threat_norm_rows,
                    code_kb_ref=code_kb_ref,
                    source_kg_ref=source_kg_ref,
                )
                evidence_dicts = rows_for_finding([row.model_dump(mode="json") for row in ledger], finding["findingId"])
                acquisition_notes = acquisition_transcripts.get(finding_id, {})
                finalizer_notes = _finalizer_acquisition_notes(acquisition_notes)
                triage_raw, llm_request = await self.llm_client.finalize_finding(
                    case,
                    finding=finding,
                    evidence_rows=evidence_dicts,
                    acquisition_notes=finalizer_notes,
                )
                parsed = self._validate_or_recover_triage_row(triage_raw, finding=finding, ledger=ledger)
                parsed_dict = parsed.model_dump(mode="json")
                transcript = {
                    "findingId": finding_id,
                    "acquisition": acquisition_notes,
                    "request": llm_request,
                    "response": triage_raw,
                    "normalizedResponse": parsed_dict,
                }
                artifacts.append_jsonl("llm-transcript.raw.jsonl", transcript)
                artifacts.append_jsonl("llm-transcript.normalized.jsonl", parsed_dict)
                artifacts.append_jsonl("triage-envelope.jsonl", parsed_dict)
                triage_rows.append(parsed)
                summary_row = _finding_evidence_summary(
                    finding=finding,
                    triage=parsed_dict,
                    acquisition=acquisition_notes,
                    ledger_rows=rows_for_finding([row.model_dump(mode="json") for row in ledger], finding_id),
                    context_rows=s5_context_norm_rows,
                    exploration_rows=s5_exploration_norm_rows,
                    threat_rows=s5_threat_norm_rows,
                )
                finding_summaries.append(summary_row)
                artifacts.append_jsonl("finding-evidence-summary.jsonl", summary_row)
            self._trace(artifacts, CaseStage.S5_FINDING_CONTEXT_READY, StageProgress.DONE, artifactRef="s5-finding-context.raw.jsonl")
        else:
            self._trace(artifacts, CaseStage.S5_FINDING_CONTEXT_READY, StageProgress.DONE, message="zero findings; no finding context required")

        ledger = attach_claim_links_to_ledger(ledger, triage_rows)
        ledger_dicts = [row.model_dump(mode="json") for row in ledger]
        triage_dicts = [row.model_dump(mode="json") for row in triage_rows]
        artifacts.write_jsonl("evidence-ledger.jsonl", ledger_dicts)
        artifacts.write_jsonl("findings.jsonl", findings)
        self._trace(artifacts, CaseStage.S3_TRIAGE_COMPLETED, StageProgress.DONE, artifactRef="triage-envelope.jsonl")

        case_packets, finding_packets = render_packets(
            case_id=case.caseId,
            findings=findings,
            ledger_rows=ledger_dicts,
            triage_rows=triage_dicts,
        )
        validate_case_finding_packet_consistency(case_packets, finding_packets)
        _write_packets(artifacts, case_packets, finding_packets)
        artifacts.write_jsonl("packet-inputs.jsonl", [{"findingId": f["findingId"], "ledgerRowCount": len(ledger_dicts)} for f in findings])
        summary = {
            "findingCount": len(findings),
            "triageCounts": _triage_counts(triage_dicts),
            "qualityGate": _quality_gate(findings=findings, triage_rows=triage_dicts, finding_summaries=finding_summaries),
            "status": CaseStage.PAPER_EXPORT_READY.value,
            "stageResults": [stage.model_dump(mode="json") for stage in self.stage_results.values()],
        }
        artifacts.write_json("analysis-envelope.json", {"caseId": case.caseId, "buildTargetId": case.buildTargetId, "summary": summary})
        manifest = {"caseId": case.caseId, "exportSchemaVersion": "s3-paper-case-export-v1", "files": artifacts.list_files()}
        artifacts.write_json("case-export-manifest.json", manifest)
        self._trace(artifacts, CaseStage.PAPER_EXPORT_READY, StageProgress.DONE, artifactRef="case-export-manifest.json")
        summary["stageResults"] = [stage.model_dump(mode="json") for stage in self.stage_results.values()]
        artifacts.write_json("analysis-envelope.json", {"caseId": case.caseId, "buildTargetId": case.buildTargetId, "summary": summary})
        log_event(
            "paper case run completed",
            event="paper_case_run_completed",
            caseId=case.caseId,
            buildTargetId=case.buildTargetId,
            paperRunId=case.paperRunId,
            findingCount=summary.get("findingCount"),
            triageCounts=summary.get("triageCounts"),
        )
        return summary

    async def _run_acquisition_loop(
        self,
        case: PaperCaseCreateRequest,
        *,
        artifacts: CaseArtifacts,
        finding: dict[str, Any],
        ledger: list[EvidenceLedgerRow],
        context_rows: list[dict[str, Any]],
        exploration_rows: list[dict[str, Any]],
        threat_rows: list[dict[str, Any]],
        code_kb_ref: str,
        source_kg_ref: str,
    ) -> dict[str, Any]:
        rounds: list[dict[str, Any]] = []
        all_results: list[dict[str, Any]] = []
        messages: list[dict[str, Any]] | None = None
        executed: set[str] = set()
        successful_required_tools: set[str] = set()
        for round_index in range(1, MAX_ACQUISITION_ROUNDS + 1):
            evidence_dicts = rows_for_finding([row.model_dump(mode="json") for row in ledger], finding["findingId"])
            acquisition, acquisition_request = await self.llm_client.acquire_for_finding(
                case,
                finding=finding,
                evidence_rows=evidence_dicts,
                acquisition_messages=messages,
                round_index=round_index,
            )
            tool_results = await self._execute_acquisition_tools(
                case,
                artifacts=artifacts,
                finding=finding,
                acquisition=acquisition,
                ledger=ledger,
                context_rows=context_rows,
                exploration_rows=exploration_rows,
                threat_rows=threat_rows,
                code_kb_ref=code_kb_ref,
                source_kg_ref=source_kg_ref,
                executed=executed,
                successful_required_tools=successful_required_tools,
            )
            all_results.extend(tool_results)
            rounds.append({
                "round": round_index,
                "request": acquisition_request,
                "response": acquisition,
                "toolResults": tool_results,
            })
            calls = acquisition.get("toolCalls") or []
            if calls:
                if messages is None:
                    messages = list(((acquisition_request.get("body") or {}).get("messages")) or [])
                assistant_message = _assistant_message_from_acquisition(acquisition)
                if assistant_message is not None:
                    messages.append(assistant_message)
                    messages.extend(_tool_messages_for_history(tool_results))
            else:
                break

        fallback_results = []
        for call in _missing_required_tool_calls(successful_required_tools, finding["findingId"]):
            result, _added_refs = await self._execute_one_acquisition_tool(
                case,
                artifacts=artifacts,
                finding=finding,
                call=call,
                ledger=ledger,
                context_rows=context_rows,
                exploration_rows=exploration_rows,
                threat_rows=threat_rows,
                code_kb_ref=code_kb_ref,
                source_kg_ref=source_kg_ref,
                executed=executed,
                allow_duplicate_fallback=True,
            )
            fallback_results.append(result)
        all_results.extend(fallback_results)
        if fallback_results:
            rounds.append({"round": "deterministic_fallback", "toolResults": fallback_results})
        return {"rounds": rounds, "toolResults": all_results}

    async def _execute_acquisition_tools(
        self,
        case: PaperCaseCreateRequest,
        *,
        artifacts: CaseArtifacts,
        finding: dict[str, Any],
        acquisition: dict[str, Any],
        ledger: list[EvidenceLedgerRow],
        context_rows: list[dict[str, Any]],
        exploration_rows: list[dict[str, Any]],
        threat_rows: list[dict[str, Any]],
        code_kb_ref: str,
        source_kg_ref: str,
        executed: set[str],
        successful_required_tools: set[str],
    ) -> list[dict[str, Any]]:
        calls = list(acquisition.get("toolCalls") or [])
        results: list[dict[str, Any]] = []
        for call in calls:
            result, added_refs = await self._execute_one_acquisition_tool(
                case,
                artifacts=artifacts,
                finding=finding,
                call=call,
                ledger=ledger,
                context_rows=context_rows,
                exploration_rows=exploration_rows,
                threat_rows=threat_rows,
                code_kb_ref=code_kb_ref,
                source_kg_ref=source_kg_ref,
                executed=executed,
                successful_required_tools=successful_required_tools,
            )
            results.append(result)
        return results

    async def _execute_one_acquisition_tool(
        self,
        case: PaperCaseCreateRequest,
        *,
        artifacts: CaseArtifacts,
        finding: dict[str, Any],
        call: dict[str, Any],
        ledger: list[EvidenceLedgerRow],
        context_rows: list[dict[str, Any]],
        exploration_rows: list[dict[str, Any]],
        threat_rows: list[dict[str, Any]],
        code_kb_ref: str,
        source_kg_ref: str,
        executed: set[str],
        successful_required_tools: set[str] | None = None,
        allow_duplicate_fallback: bool = False,
    ) -> tuple[dict[str, Any], list[str]]:
        finding_id = finding["findingId"]
        name = call.get("name")
        arguments = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
        if arguments.get("findingId") not in {None, finding_id}:
            return _tool_result(call, success=False, error="finding_id_mismatch", content="Tool call findingId did not match current finding."), []
        dedup_key = str(name)
        if not allow_duplicate_fallback and dedup_key in executed and name in {"retrieve_finding_context", "retrieve_generic_threat_context"}:
            return _cached_required_context_tool_result(
                call,
                finding=finding,
                ledger=ledger,
                context_rows=context_rows,
                threat_rows=threat_rows,
            ), []
        executed.add(dedup_key)
        if name == "retrieve_finding_context":
            ctx_raw, ctx_request = await self.s5_client.retrieve_finding_context(
                case,
                finding=finding,
                code_kb_ref=code_kb_ref,
                source_kg_ref=source_kg_ref,
            )
            artifacts.append_jsonl("s5-finding-context-requests.jsonl", ctx_request)
            artifacts.append_jsonl("s5-finding-context.raw.jsonl", ctx_raw)
            ctx_norm, ctx_ledger = normalize_s5_rows(ctx_raw, evidence_type="s5_finding_context")
            context_rows.append(ctx_norm)
            artifacts.append_jsonl("s5-finding-context.normalized.jsonl", ctx_norm)
            ledger.extend(ctx_ledger)
            refs = [row.evidenceRef for row in ctx_ledger]
            if successful_required_tools is not None:
                successful_required_tools.add("retrieve_finding_context")
            return _tool_result(
                call,
                success=True,
                content=_s5_tool_content(
                    ctx_norm,
                    ledger_rows=[row.model_dump(mode="json") for row in ctx_ledger],
                    coverage=_s5_context_coverage(ctx_norm, finding),
                ),
                evidence_refs=refs,
            ), refs
        elif name == "retrieve_generic_threat_context":
            threat_raw, threat_request = await self.s5_client.retrieve_generic_threat_context(case, finding=finding)
            artifacts.append_jsonl("s5-generic-threat-context-requests.jsonl", threat_request)
            artifacts.append_jsonl("s5-generic-threat-context.raw.jsonl", threat_raw)
            threat_norm, threat_ledger = normalize_s5_rows(threat_raw, evidence_type="s5_generic_threat_context")
            threat_rows.append(threat_norm)
            artifacts.append_jsonl("s5-generic-threat-context.normalized.jsonl", threat_norm)
            ledger.extend(threat_ledger)
            refs = [row.evidenceRef for row in threat_ledger]
            if successful_required_tools is not None:
                successful_required_tools.add("retrieve_generic_threat_context")
            return _tool_result(
                call,
                success=True,
                content=_s5_tool_content(threat_norm, ledger_rows=[row.model_dump(mode="json") for row in threat_ledger]),
                evidence_refs=refs,
            ), refs
        elif name == "explore_source_kg":
            explore_raw, explore_request = await self.s5_client.explore_source_kg(
                case,
                finding=finding,
                code_kb_ref=code_kb_ref,
                source_kg_ref=source_kg_ref,
                exploration=arguments,
            )
            artifacts.append_jsonl("s5-source-kg-explore-requests.jsonl", explore_request)
            artifacts.append_jsonl("s5-source-kg-explore.raw.jsonl", explore_raw)
            explore_norm, explore_ledger = normalize_s5_rows(explore_raw, evidence_type="s5_source_kg_exploration")
            explore_norm["findingId"] = finding_id
            for ledger_row in explore_ledger:
                ledger_row.relatedFindingId = finding_id
            exploration_rows.append(explore_norm)
            artifacts.append_jsonl("s5-source-kg-explore.normalized.jsonl", explore_norm)
            ledger.extend(explore_ledger)
            refs = [row.evidenceRef for row in explore_ledger]
            return _tool_result(
                call,
                success=True,
                content=_s5_tool_content(
                    explore_norm,
                    ledger_rows=[row.model_dump(mode="json") for row in explore_ledger],
                    coverage=_source_context_coverage(finding, explore_norm.get("rows") or []),
                ),
                evidence_refs=refs,
            ), refs
        elif name == "list_evidence_rows":
            rows = rows_for_finding([row.model_dump(mode="json") for row in ledger], finding_id)
            content = json.dumps(
                {
                    "rowCount": len(rows),
                    "rows": [_private_evidence_row_summary(row) for row in rows[:24]],
                    "truncated": max(0, len(rows) - 24),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            return _tool_result(call, success=True, content=content), []
        return _tool_result(call, success=False, error="unknown_tool", content=f"Unknown paper acquisition tool: {name}"), []

    def _validate_or_recover_triage_row(
        self,
        row: dict[str, Any],
        *,
        finding: dict[str, Any],
        ledger: list[EvidenceLedgerRow],
    ):
        try:
            finding_ledger = _ledger_for_finding(ledger, finding["findingId"])
            parsed = validate_triage_row(
                row,
                known_evidence_refs={row.evidenceRef for row in finding_ledger},
                grounding_evidence_refs=_grounding_evidence_refs(finding_ledger),
                diagnostic_evidence_refs=_diagnostic_evidence_refs(finding_ledger),
                claim_support_evidence_refs=_claim_support_evidence_refs(finding_ledger),
            )
            if parsed.findingId != finding["findingId"]:
                raise PaperContractError(
                    f"Finalizer row findingId mismatch: expected {finding['findingId']}, got {parsed.findingId}"
                )
            return parsed
        except PaperContractError as exc:
            fallback = fallback_unknown_for_finding(
                finding,
                reason="UNKNOWN_CLAIM_BOUNDARY",
            )
            fallback["rationale"] = "The model-produced triage row could not be safely grounded, so S3 recovered to UNKNOWN."
            fallback["unsupportedClaims"] = [f"Recovered invalid model triage row: {exc.message}"]
            fallback["boundaryNotes"] = [
                "Recovered to UNKNOWN because S3 could not validate the finalizer row against known evidence refs.",
                "This is a result-level triage recovery, not producer diagnostic promotion.",
            ]
            finding_ledger = _ledger_for_finding(ledger, finding["findingId"])
            return validate_triage_row(
                fallback,
                known_evidence_refs={row.evidenceRef for row in finding_ledger},
                grounding_evidence_refs=_grounding_evidence_refs(finding_ledger),
                diagnostic_evidence_refs=_diagnostic_evidence_refs(finding_ledger),
                claim_support_evidence_refs=_claim_support_evidence_refs(finding_ledger),
            )


def _normalize_s5_prepare(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": "s3-normalized-s5-code-kb-v1",
        "caseId": data.get("caseId"),
        "buildTargetId": data.get("buildTargetId"),
        "surfaceStatus": data.get("surfaceStatus"),
        "stageReadiness": data.get("stageReadiness"),
        "codeKbRef": data.get("codeKbRef"),
        "sourceKgRef": data.get("sourceKgRef"),
        "readiness": data.get("readiness", {}),
        "diagnostics": data.get("diagnostics", []),
        "producerProvenance": data.get("producerProvenance", {}),
    }


def _initialize_run_jsonl(artifacts: CaseArtifacts) -> None:
    """Truncate per-run JSONL outputs before append-mode stages begin."""

    for name in [
        "s4-requests.jsonl",
        "s5-setup-requests.jsonl",
        "s5-finding-context-requests.jsonl",
        "s5-finding-context.raw.jsonl",
        "s5-finding-context.normalized.jsonl",
        "s5-source-kg-explore-requests.jsonl",
        "s5-source-kg-explore.raw.jsonl",
        "s5-source-kg-explore.normalized.jsonl",
        "s5-generic-threat-context-requests.jsonl",
        "s5-generic-threat-context.raw.jsonl",
        "s5-generic-threat-context.normalized.jsonl",
        "llm-transcript.raw.jsonl",
        "llm-transcript.normalized.jsonl",
        "triage-envelope.jsonl",
        "finding-evidence-summary.jsonl",
        "evidence-ledger.jsonl",
        "findings.jsonl",
        "packet-inputs.jsonl",
    ]:
        artifacts.write_jsonl(name, [])


def _private_evidence_row_summary(row: dict[str, Any]) -> dict[str, Any]:
    text = str(row.get("text") or "")
    return {
        "evidenceRef": row.get("evidenceRef"),
        "producer": row.get("producer"),
        "evidenceType": row.get("evidenceType"),
        "relatedFindingId": row.get("relatedFindingId"),
        "diagnostic": bool(row.get("diagnostic")),
        "surfaceStatus": row.get("surfaceStatus"),
        "textPreview": text[:320],
    }


def _finding_evidence_summary(
    *,
    finding: dict[str, Any],
    triage: dict[str, Any],
    acquisition: dict[str, Any],
    ledger_rows: list[dict[str, Any]],
    context_rows: list[dict[str, Any]],
    exploration_rows: list[dict[str, Any]],
    threat_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    timeline = _tool_timeline(acquisition)
    duplicate_or_skipped = [
        item
        for item in timeline
        if item.get("error") in {"duplicate_tool_call", "finding_id_mismatch", "unknown_tool"}
        or item.get("success") is False
    ]
    s5_context_refs = _s5_display_refs(context_rows, finding["findingId"])
    coverage = _s5_contexts_coverage_for_finding(context_rows, finding)
    exploration_coverage = _source_context_coverage(finding, _s5_rows_for_finding(exploration_rows, finding["findingId"]))
    return {
        "schemaVersion": "s3-finding-evidence-summary-v1",
        "findingId": finding["findingId"],
        "location": finding.get("location", {}),
        "ruleId": finding.get("ruleId"),
        "verdict": triage.get("verdict"),
        "unknownReason": triage.get("unknownReason"),
        "recovered": _is_recovered_triage(triage),
        "toolTimeline": timeline,
        "duplicateOrSkippedToolCalls": duplicate_or_skipped,
        "evidenceCounts": _evidence_counts(ledger_rows),
        "s5Context": {
            "displayRefs": s5_context_refs,
            "coverage": coverage,
            "rowCount": sum(len(row.get("rows") or []) for row in context_rows if row.get("findingId") == finding["findingId"]),
            "diagnosticCount": sum(len(row.get("diagnostics") or []) for row in context_rows if row.get("findingId") == finding["findingId"]),
        },
        "s5Exploration": {
            "rowCount": sum(len(row.get("rows") or []) for row in exploration_rows if row.get("findingId") == finding["findingId"]),
            "diagnosticCount": sum(len(row.get("diagnostics") or []) for row in exploration_rows if row.get("findingId") == finding["findingId"]),
            "coverage": exploration_coverage,
            "modes": _s5_exploration_modes(exploration_rows, finding["findingId"]),
        },
        "s5Threat": {
            "rowCount": sum(len(row.get("rows") or []) for row in threat_rows if row.get("findingId") == finding["findingId"]),
            "diagnosticCount": sum(len(row.get("diagnostics") or []) for row in threat_rows if row.get("findingId") == finding["findingId"]),
        },
        "finalizer": {
            "citedEvidenceRefCount": len(triage.get("citedEvidenceRefs") or []),
            "unsupportedClaimCount": len(triage.get("unsupportedClaims") or []),
            "boundaryNotes": triage.get("boundaryNotes") or [],
        },
    }


def _tool_timeline(acquisition: dict[str, Any]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for round_row in acquisition.get("rounds", []):
        response = round_row.get("response") if isinstance(round_row.get("response"), dict) else {}
        requested = response.get("toolCalls") or []
        for call in requested:
            timeline.append({
                "round": round_row.get("round"),
                "toolCallId": call.get("id"),
                "tool": call.get("name"),
                "requested": True,
                "arguments": call.get("arguments") or {},
            })
        for result in round_row.get("toolResults", []) or []:
            timeline.append({
                "round": round_row.get("round"),
                "toolCallId": result.get("toolCallId"),
                "tool": result.get("tool"),
                "requested": False,
                "success": bool(result.get("success")),
                "error": result.get("error"),
                "deterministicFallback": bool(result.get("deterministicFallback")),
                "cachedDuplicate": bool(result.get("cachedDuplicate")),
                "newEvidenceRefCount": len(result.get("newEvidenceRefs") or []),
            })
    return timeline


def _evidence_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "total": len(rows),
        "diagnostic": 0,
        "grounding": 0,
        "s4": 0,
        "s5": 0,
    }
    for row in rows:
        if row.get("diagnostic"):
            counts["diagnostic"] += 1
        else:
            counts["grounding"] += 1
        if row.get("producer") == "s4":
            counts["s4"] += 1
        if row.get("producer") == "s5":
            counts["s5"] += 1
    return counts


def _s5_display_refs(context_rows: list[dict[str, Any]], finding_id: str) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for context in context_rows:
        if context.get("findingId") != finding_id:
            continue
        for row in context.get("rows") or []:
            source = row.get("sourceEvidence") or {}
            ref = source.get("displayRef")
            if ref and ref not in seen:
                seen.add(ref)
                refs.append(str(ref))
    return refs


def _s5_rows_for_finding(context_rows: list[dict[str, Any]], finding_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for context in context_rows:
        if context.get("findingId") == finding_id:
            rows.extend(context.get("rows") or [])
    return rows


def _s5_contexts_coverage_for_finding(context_rows: list[dict[str, Any]], finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = finding["findingId"]
    matching = [context for context in context_rows if context.get("findingId") == finding_id]
    authoritative = [_s5_context_coverage(context, finding) for context in matching if isinstance(context.get("contextCoverage"), dict)]
    if authoritative:
        priority = {"covered": 0, "partial": 1, "non_overlapping": 2, "not_available": 3, "error": 4, "unknown": 5}
        return sorted(authoritative, key=lambda item: priority.get(str(item.get("status")), 99))[0]
    return _source_context_coverage(finding, _s5_rows_for_finding(context_rows, finding_id))


def _s5_context_coverage(context: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    coverage = context.get("contextCoverage")
    if isinstance(coverage, dict) and coverage.get("coverageStatus"):
        requested_anchors = coverage.get("requestedAnchors") if isinstance(coverage.get("requestedAnchors"), list) else []
        returned_spans = coverage.get("returnedSpans") if isinstance(coverage.get("returnedSpans"), list) else []
        return {
            "status": coverage.get("coverageStatus"),
            "source": "s5_contextCoverage",
            "requestedAnchor": requested_anchors[0] if requested_anchors else _requested_anchor(finding),
            "requestedAnchors": requested_anchors,
            "returnedSpans": returned_spans[:16],
            "lineOverlap": coverage.get("lineOverlap"),
            "diagnostics": coverage.get("diagnostics") if isinstance(coverage.get("diagnostics"), list) else [],
        }
    return _source_context_coverage(finding, context.get("rows") or [])


def _s5_exploration_modes(exploration_rows: list[dict[str, Any]], finding_id: str) -> list[str]:
    modes: list[str] = []
    seen: set[str] = set()
    for context in exploration_rows:
        if context.get("findingId") != finding_id:
            continue
        for mode in ((context.get("retrievalTrace") or {}).get("methodsAttempted") or []):
            if mode and str(mode) not in seen:
                seen.add(str(mode))
                modes.append(str(mode))
    return modes


_DISPLAY_REF_RE = re.compile(r"^(?P<path>.+):(?P<start>\d+)(?:-(?P<end>\d+))?$")


def _parse_display_ref(display_ref: Any) -> dict[str, Any] | None:
    if not isinstance(display_ref, str):
        return None
    match = _DISPLAY_REF_RE.match(display_ref.strip())
    if not match:
        return None
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    if end < start:
        start, end = end, start
    return {"path": match.group("path"), "startLine": start, "endLine": end, "displayRef": display_ref}


def _path_matches(left: Any, right: Any) -> bool:
    if not left or not right:
        return False
    left_s = str(left).replace("\\", "/")
    right_s = str(right).replace("\\", "/")
    return left_s == right_s or left_s.endswith("/" + right_s) or right_s.endswith("/" + left_s)


def _ranges_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return max(a_start, b_start) <= min(a_end, b_end)


def _source_context_coverage(finding: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    requested_anchor = _requested_anchor(finding)
    requested_path = requested_anchor.get("path")
    requested_start = requested_anchor.get("lineStart")
    requested_end = requested_anchor.get("lineEnd")
    returned_spans = []
    unparsed_refs = []
    for row in rows:
        source = row.get("sourceEvidence") or {}
        parsed = _parse_display_ref(source.get("displayRef"))
        if not parsed:
            if source.get("displayRef"):
                unparsed_refs.append(str(source.get("displayRef")))
            continue
        returned_spans.append(parsed)
    if not rows:
        status = "not_available"
    elif not returned_spans:
        status = "unknown"
    elif not requested_path or not isinstance(requested_start, int) or not isinstance(requested_end, int):
        status = "unknown"
    else:
        same_path = [span for span in returned_spans if _path_matches(span.get("path"), requested_path)]
        if not same_path:
            status = "unknown"
        else:
            overlapping = [
                span
                for span in same_path
                if _ranges_overlap(int(span["startLine"]), int(span["endLine"]), int(requested_start), int(requested_end))
            ]
            non_overlapping = [span for span in same_path if span not in overlapping]
            if overlapping and non_overlapping:
                status = "partial"
            elif overlapping:
                status = "covered"
            else:
                status = "non_overlapping"
    return {
        "status": status,
        "source": "s3_displayRef_fallback",
        "requestedAnchor": requested_anchor,
        "returnedSpans": returned_spans[:16],
        "unparsedDisplayRefs": unparsed_refs[:16],
    }


def _requested_anchor(finding: dict[str, Any]) -> dict[str, Any]:
    location = finding.get("location") or {}
    requested_start = location.get("startLine")
    return {
        "path": location.get("path"),
        "lineStart": requested_start,
        "lineEnd": location.get("endLine") or requested_start,
        "functionRef": finding.get("functionId"),
    }


def _s5_tool_content(context: dict[str, Any], *, ledger_rows: list[dict[str, Any]], coverage: dict[str, Any] | None = None) -> str:
    rows = context.get("rows") or []
    diagnostics = context.get("diagnostics") or []
    payload = {
        "surfaceStatus": context.get("surfaceStatus"),
        "rowCount": len(rows),
        "diagnostics": [
            {
                "code": diagnostic.get("code"),
                "message": str(diagnostic.get("message") or "")[:320],
                "surfaceStatus": diagnostic.get("surfaceStatus"),
            }
            for diagnostic in diagnostics[:8]
        ],
        "rows": [
            {
                "evidenceRef": ledger_rows[index].get("evidenceRef") if index < len(ledger_rows) else None,
                "displayRef": (row.get("sourceEvidence") or {}).get("displayRef"),
                "sourceType": row.get("sourceType"),
                "queryIntent": row.get("queryIntent"),
                "surfaceStatus": row.get("surfaceStatus"),
                "diagnostic": bool(row.get("diagnostics")),
                "textPreview": str(row.get("text") or "")[:640],
            }
            for index, row in enumerate(rows[:5])
        ],
        "truncatedRows": max(0, len(rows) - 5),
    }
    if coverage is not None:
        payload["coverage"] = coverage
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _cached_required_context_tool_result(
    call: dict[str, Any],
    *,
    finding: dict[str, Any],
    ledger: list[EvidenceLedgerRow],
    context_rows: list[dict[str, Any]],
    threat_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return prior required-tool evidence without duplicating S5 calls.

    Qwen may repeat a required context call after seeing tool history. Treat the
    repeat as an idempotent cache hit instead of an error so the acquisition
    loop stays focused on missing evidence rather than on a duplicate-tool
    failure. No new evidence refs are minted; the content points back to the
    already-known refs.
    """

    finding_id = finding["findingId"]
    tool_name = call.get("name")
    if tool_name == "retrieve_finding_context":
        cached_context = _latest_context_for_finding(context_rows, finding_id)
        evidence_type = "s5_finding_context"
        coverage = _s5_context_coverage(cached_context, finding) if cached_context else None
    elif tool_name == "retrieve_generic_threat_context":
        cached_context = _latest_context_for_finding(threat_rows, finding_id)
        evidence_type = "s5_generic_threat_context"
        coverage = None
    else:
        return _tool_result(call, success=False, error="unknown_tool", content=f"Unknown paper acquisition tool: {tool_name}")

    if cached_context is None:
        return _tool_result(
            call,
            success=False,
            error="missing_cached_context",
            content=f"Duplicate {tool_name} call could not find cached context for {finding_id}.",
        )

    cached_refs = [
        row.evidenceRef
        for row in _ledger_for_finding(ledger, finding_id)
        if row.evidenceType == evidence_type
    ]
    ledger_dicts = [row.model_dump(mode="json") for row in _ledger_for_finding(ledger, finding_id) if row.evidenceType == evidence_type]
    payload = json.loads(_s5_tool_content(cached_context, ledger_rows=ledger_dicts, coverage=coverage))
    payload["cached"] = True
    payload["cachedDuplicate"] = True
    payload["message"] = f"{tool_name} was already executed for this finding; reusing existing evidence refs."
    payload["existingEvidenceRefs"] = cached_refs
    result = _tool_result(
        call,
        success=True,
        content=json.dumps(payload, ensure_ascii=False, sort_keys=True),
        evidence_refs=[],
    )
    result["cachedDuplicate"] = True
    return result


def _latest_context_for_finding(context_rows: list[dict[str, Any]], finding_id: str) -> dict[str, Any] | None:
    for context in reversed(context_rows):
        if context.get("findingId") == finding_id:
            return context
    return None


def _is_recovered_triage(triage: dict[str, Any]) -> bool:
    if triage.get("unknownReason") == "UNKNOWN_CLAIM_BOUNDARY":
        return True
    text = " ".join(str(item) for item in (triage.get("unsupportedClaims") or []) + (triage.get("boundaryNotes") or []))
    return "Recovered" in text or "recovered" in text


def _quality_gate(*, findings: list[dict[str, Any]], triage_rows: list[dict[str, Any]], finding_summaries: list[dict[str, Any]]) -> dict[str, Any]:
    finding_count = len(findings)
    verdict_counts = _triage_counts(triage_rows)
    unknown_count = verdict_counts.get("UNKNOWN", 0)
    unknown_rate = (unknown_count / finding_count) if finding_count else 0.0
    recovery_count = sum(1 for row in finding_summaries if row.get("recovered"))
    duplicate_or_skipped_count = sum(len(row.get("duplicateOrSkippedToolCalls") or []) for row in finding_summaries)
    context_with_rows = sum(1 for row in finding_summaries if (row.get("s5Context") or {}).get("rowCount", 0) > 0)
    exploration_with_rows = sum(1 for row in finding_summaries if (row.get("s5Exploration") or {}).get("rowCount", 0) > 0)
    context_overlapping = sum(
        1
        for row in finding_summaries
        if ((row.get("s5Context") or {}).get("coverage") or {}).get("status") == "covered"
    )
    non_overlapping_findings = [
        row.get("findingId")
        for row in finding_summaries
        if ((row.get("s5Context") or {}).get("coverage") or {}).get("status") == "non_overlapping"
    ]
    partial_context_findings = [
        row.get("findingId")
        for row in finding_summaries
        if ((row.get("s5Context") or {}).get("coverage") or {}).get("status") == "partial"
    ]
    unavailable_or_error_context_findings = [
        row.get("findingId")
        for row in finding_summaries
        if ((row.get("s5Context") or {}).get("coverage") or {}).get("status") in {"not_available", "error"}
    ]
    unmitigated_non_overlapping_findings = [
        row.get("findingId")
        for row in finding_summaries
        if ((row.get("s5Context") or {}).get("coverage") or {}).get("status") == "non_overlapping"
        and ((row.get("s5Exploration") or {}).get("coverage") or {}).get("status") not in {"covered", "partial"}
    ]
    reasons: list[str] = []
    status = "pass"
    if finding_count and unknown_count == finding_count:
        status = "fail"
        reasons.append("ALL_FINDINGS_UNKNOWN")
    elif unknown_count:
        status = "warn"
        reasons.append("SOME_FINDINGS_UNKNOWN")
    if recovery_count:
        status = "fail" if status == "fail" else "warn"
        reasons.append("FINALIZER_RECOVERY_USED")
    if duplicate_or_skipped_count:
        status = "fail" if status == "fail" else "warn"
        reasons.append("ACQUISITION_TOOL_CALLS_SKIPPED_OR_DUPLICATED")
    if finding_count and context_with_rows == 0:
        status = "fail"
        reasons.append("NO_FINDING_CONTEXT_ROWS")
    if partial_context_findings:
        if status == "pass":
            status = "warn"
        reasons.append("SOURCE_CONTEXT_PARTIAL")
    if unavailable_or_error_context_findings:
        status = "fail"
        reasons.append("SOURCE_CONTEXT_UNAVAILABLE_OR_ERROR")
    if unmitigated_non_overlapping_findings:
        status = "fail"
        reasons.append("SOURCE_CONTEXT_NON_OVERLAPPING")
        reasons.append("SOURCE_CONTEXT_NON_OVERLAPPING_UNMITIGATED")
    return {
        "schemaVersion": "s3-paper-quality-gate-v1",
        "status": status,
        "findingCount": finding_count,
        "unknownCount": unknown_count,
        "unknownRate": unknown_rate,
        "recoveryCount": recovery_count,
        "duplicateOrSkippedToolCallCount": duplicate_or_skipped_count,
        "contextCoverage": {
            "findingsWithS5ContextRows": context_with_rows,
            "findingsWithOverlappingS5ContextRows": context_overlapping,
            "findingsWithNonOverlappingOnlyS5ContextRows": len(non_overlapping_findings),
            "nonOverlappingFindingIds": non_overlapping_findings[:32],
            "partialFindingIds": partial_context_findings[:32],
            "unavailableOrErrorFindingIds": unavailable_or_error_context_findings[:32],
            "unmitigatedNonOverlappingFindingIds": unmitigated_non_overlapping_findings[:32],
            "findingCount": finding_count,
            "coverageRate": (context_with_rows / finding_count) if finding_count else 1.0,
            "overlapRate": (context_overlapping / finding_count) if finding_count else 1.0,
        },
        "sourceKgExploration": {
            "findingsWithExplorationRows": exploration_with_rows,
            "findingCount": finding_count,
            "explorationRate": (exploration_with_rows / finding_count) if finding_count else 1.0,
        },
        "reasons": reasons,
    }


def _triage_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"TP": 0, "FP": 0, "UNKNOWN": 0}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    return counts


def _grounding_evidence_refs(ledger: list[EvidenceLedgerRow]) -> set[str]:
    local_grounding_types = {
        "s4_finding",
        "s4_evidence",
        "s5_finding_context",
        "s5_source_kg_exploration",
    }
    return {
        row.evidenceRef
        for row in ledger
        if not row.diagnostic and row.surfaceStatus == "produced" and row.evidenceType in local_grounding_types
    }


def _diagnostic_evidence_refs(ledger: list[EvidenceLedgerRow]) -> set[str]:
    return {row.evidenceRef for row in ledger if row.diagnostic}


def _claim_support_evidence_refs(ledger: list[EvidenceLedgerRow]) -> set[str]:
    return {
        row.evidenceRef
        for row in ledger
        if not row.diagnostic and row.surfaceStatus == "produced"
    }


def _ledger_for_finding(ledger: list[EvidenceLedgerRow], finding_id: str) -> list[EvidenceLedgerRow]:
    rows = rows_for_finding([row.model_dump(mode="json") for row in ledger], finding_id)
    refs = {row["evidenceRef"] for row in rows}
    return [row for row in ledger if row.evidenceRef in refs]


def _write_packets(artifacts: CaseArtifacts, case_packets: dict[str, Any], finding_packets: dict[str, dict[str, Any]]) -> None:
    names = {
        "b0": "b0-sast-only.json",
        "b1": "b1-raw-llm-rationale.json",
        "b2": "b2-evidence-dump-no-ledger.json",
        "b3": "b3-aegis-ledger-no-verdict.json",
        "b4": "b4-aegis-full-packet.json",
    }
    for key, filename in names.items():
        artifacts.write_json(f"audit-packets/case-level/{filename}", case_packets[key])
    for finding_id, packets in finding_packets.items():
        for key, packet in packets.items():
            artifacts.write_json(f"audit-packets/findings/{finding_id}/{key}.json", packet)


def _missing_required_tool_calls(successful_required_tools: set[str], finding_id: str) -> list[dict[str, Any]]:
    missing = []
    for name in ["retrieve_finding_context", "retrieve_generic_threat_context"]:
        if name not in successful_required_tools:
            missing.append({
                "id": f"deterministic-{name}",
                "name": name,
                "arguments": {"findingId": finding_id},
                "deterministicFallback": True,
            })
    return missing


def _tool_result(call: dict[str, Any], *, success: bool, content: str, evidence_refs: list[str] | None = None, error: str | None = None) -> dict[str, Any]:
    return {
        "toolCallId": call.get("id"),
        "tool": call.get("name"),
        "arguments": call.get("arguments", {}),
        "deterministicFallback": bool(call.get("deterministicFallback")),
        "success": success,
        "content": content,
        "newEvidenceRefs": evidence_refs or [],
        "error": error,
    }


def _finalizer_acquisition_notes(acquisition: dict[str, Any]) -> dict[str, Any]:
    rounds = []
    for row in acquisition.get("rounds", []):
        response = row.get("response") if isinstance(row.get("response"), dict) else {}
        rounds.append({
            "round": row.get("round"),
            "toolCalls": response.get("toolCalls", []),
            "finishReason": response.get("finishReason"),
            "toolResultCount": len(row.get("toolResults", [])),
        })
    return {
        "rounds": rounds,
        "toolResults": acquisition.get("toolResults", []),
    }


def _assistant_message_from_acquisition(acquisition: dict[str, Any]) -> dict[str, Any] | None:
    assistant = acquisition.get("assistantMessage")
    if isinstance(assistant, dict):
        return assistant
    calls = acquisition.get("toolCalls") or []
    if not calls and acquisition.get("content") is None:
        return None
    message: dict[str, Any] = {"role": "assistant", "content": acquisition.get("content")}
    if calls:
        message["tool_calls"] = [
            {
                "id": call.get("id") or f"tool-call-{index}",
                "type": "function",
                "function": {
                    "name": call.get("name"),
                    "arguments": json.dumps(call.get("arguments") or {}, ensure_ascii=False, sort_keys=True),
                },
            }
            for index, call in enumerate(calls, start=1)
        ]
    return message


def _tool_messages_for_history(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    messages = []
    for result in results:
        tool_call_id = result.get("toolCallId")
        if not tool_call_id:
            continue
        content = {
            "success": result.get("success"),
            "content": result.get("content"),
            "newEvidenceRefs": result.get("newEvidenceRefs", []),
            "error": result.get("error"),
        }
        messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": result.get("tool"),
            "content": json.dumps(content, ensure_ascii=False, sort_keys=True),
        })
    return messages
