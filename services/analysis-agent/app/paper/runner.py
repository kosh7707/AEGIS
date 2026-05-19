from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifacts import CaseArtifacts, trace_stage
from .llm_client import LlmTriageClient
from .models import CaseStage, EvidenceLedgerRow, PaperCaseCreateRequest, StageProgress, StageResult
from .normalize import normalize_s4, normalize_s5_rows
from .packets import render_packets, rows_for_finding, validate_case_finding_packet_consistency
from .s4_client import S4PaperClient
from .s5_client import S5PaperClient
from .triage import attach_claim_links_to_ledger, validate_triage_row


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

    async def run(self, case: PaperCaseCreateRequest) -> dict[str, Any]:
        self.stage_results = {}
        artifacts = CaseArtifacts.from_request(case)
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

        triage_rows = []
        s5_context_norm_rows: list[dict[str, Any]] = []
        s5_threat_norm_rows: list[dict[str, Any]] = []
        llm_transcripts = []
        if findings:
            code_kb_ref = (s5_prepare_raw or {}).get("codeKbRef") or f"s5-code-kb:{case.caseId}:{case.buildTargetId}"
            source_kg_ref = (s5_prepare_raw or {}).get("sourceKgRef") or f"s5-source-kg:{case.caseId}:{case.buildTargetId}"
            for finding in findings:
                ctx_raw, ctx_request = await self.s5_client.retrieve_finding_context(case, finding=finding, code_kb_ref=code_kb_ref, source_kg_ref=source_kg_ref)
                artifacts.append_jsonl("s5-finding-context-requests.jsonl", ctx_request)
                artifacts.append_jsonl("s5-finding-context.raw.jsonl", ctx_raw)
                ctx_norm, ctx_ledger = normalize_s5_rows(ctx_raw, evidence_type="s5_finding_context")
                s5_context_norm_rows.append(ctx_norm)
                ledger.extend(ctx_ledger)

                threat_raw, threat_request = await self.s5_client.retrieve_generic_threat_context(case, finding=finding)
                artifacts.append_jsonl("s5-generic-threat-context-requests.jsonl", threat_request)
                artifacts.append_jsonl("s5-generic-threat-context.raw.jsonl", threat_raw)
                threat_norm, threat_ledger = normalize_s5_rows(threat_raw, evidence_type="s5_generic_threat_context")
                s5_threat_norm_rows.append(threat_norm)
                ledger.extend(threat_ledger)

                evidence_dicts = rows_for_finding([row.model_dump(mode="json") for row in ledger], finding["findingId"])
                triage_raw, llm_request = await self.llm_client.triage_finding(case, finding=finding, evidence_rows=evidence_dicts)
                llm_transcripts.append({"findingId": finding["findingId"], "request": llm_request, "response": triage_raw})
                parsed = validate_triage_row(triage_raw, known_evidence_refs={row.evidenceRef for row in ledger})
                triage_rows.append(parsed)
            self._trace(artifacts, CaseStage.S5_FINDING_CONTEXT_READY, StageProgress.DONE, artifactRef="s5-finding-context.raw.jsonl")
        else:
            self._trace(artifacts, CaseStage.S5_FINDING_CONTEXT_READY, StageProgress.DONE, message="zero findings; no finding context required")

        self._trace(artifacts, CaseStage.SETUP_RUNNING, StageProgress.DONE, message="producer setup completed")
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
        return summary


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
