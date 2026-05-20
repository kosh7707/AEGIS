from __future__ import annotations

import json
import logging
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
        s5_threat_norm_rows: list[dict[str, Any]] = []
        acquisition_transcripts: dict[str, dict[str, Any]] = {}
        llm_transcripts = []
        if findings:
            code_kb_ref = (s5_prepare_raw or {}).get("codeKbRef") or f"s5-code-kb:{case.caseId}:{case.buildTargetId}"
            source_kg_ref = (s5_prepare_raw or {}).get("sourceKgRef") or f"s5-source-kg:{case.caseId}:{case.buildTargetId}"
            for finding in findings:
                acquisition_transcripts[finding["findingId"]] = await self._run_acquisition_loop(
                    case,
                    artifacts=artifacts,
                    finding=finding,
                    ledger=ledger,
                    context_rows=s5_context_norm_rows,
                    threat_rows=s5_threat_norm_rows,
                    code_kb_ref=code_kb_ref,
                    source_kg_ref=source_kg_ref,
                )
            self._trace(artifacts, CaseStage.S5_FINDING_CONTEXT_READY, StageProgress.DONE, artifactRef="s5-finding-context.raw.jsonl")

            for finding in findings:
                evidence_dicts = rows_for_finding([row.model_dump(mode="json") for row in ledger], finding["findingId"])
                acquisition_notes = acquisition_transcripts.get(finding["findingId"], {})
                finalizer_notes = _finalizer_acquisition_notes(acquisition_notes)
                triage_raw, llm_request = await self.llm_client.finalize_finding(
                    case,
                    finding=finding,
                    evidence_rows=evidence_dicts,
                    acquisition_notes=finalizer_notes,
                )
                parsed = self._validate_or_recover_triage_row(triage_raw, finding=finding, ledger=ledger)
                llm_transcripts.append({
                    "findingId": finding["findingId"],
                    "acquisition": acquisition_notes,
                    "request": llm_request,
                    "response": triage_raw,
                    "normalizedResponse": parsed.model_dump(mode="json"),
                })
                triage_rows.append(parsed)
        else:
            self._trace(artifacts, CaseStage.S5_FINDING_CONTEXT_READY, StageProgress.DONE, message="zero findings; no finding context required")

        ledger = attach_claim_links_to_ledger(ledger, triage_rows)
        ledger_dicts = [row.model_dump(mode="json") for row in ledger]
        triage_dicts = [row.model_dump(mode="json") for row in triage_rows]
        artifacts.write_jsonl("s5-finding-context.normalized.jsonl", s5_context_norm_rows)
        artifacts.write_jsonl("s5-generic-threat-context.normalized.jsonl", s5_threat_norm_rows)
        artifacts.write_jsonl("llm-transcript.raw.jsonl", llm_transcripts)
        artifacts.write_jsonl("llm-transcript.normalized.jsonl", triage_dicts)
        artifacts.write_jsonl("triage-envelope.jsonl", triage_dicts)
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
            return _tool_result(call, success=False, error="duplicate_tool_call", content="Duplicate required context call skipped."), []
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
            ledger.extend(ctx_ledger)
            refs = [row.evidenceRef for row in ctx_ledger]
            if successful_required_tools is not None:
                successful_required_tools.add("retrieve_finding_context")
            return _tool_result(call, success=True, content="S5 finding context retrieved.", evidence_refs=refs), refs
        elif name == "retrieve_generic_threat_context":
            threat_raw, threat_request = await self.s5_client.retrieve_generic_threat_context(case, finding=finding)
            artifacts.append_jsonl("s5-generic-threat-context-requests.jsonl", threat_request)
            artifacts.append_jsonl("s5-generic-threat-context.raw.jsonl", threat_raw)
            threat_norm, threat_ledger = normalize_s5_rows(threat_raw, evidence_type="s5_generic_threat_context")
            threat_rows.append(threat_norm)
            ledger.extend(threat_ledger)
            refs = [row.evidenceRef for row in threat_ledger]
            if successful_required_tools is not None:
                successful_required_tools.add("retrieve_generic_threat_context")
            return _tool_result(call, success=True, content="S5 generic threat context retrieved.", evidence_refs=refs), refs
        elif name == "list_evidence_rows":
            rows = rows_for_finding([row.model_dump(mode="json") for row in ledger], finding_id)
            return _tool_result(call, success=True, content=f"Current normalized evidence rows: {len(rows)}."), []
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
