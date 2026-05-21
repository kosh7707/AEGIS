from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from app.agent_runtime.context import reset_request_id, set_request_id
from app.paper import api as paper_api
from app.paper.errors import PaperContractError, PaperOperationalError
from app.paper.s4_client import S4PaperClient
from app.paper.s5_client import S5PaperClient, build_generic_threat_request, build_prepare_code_kb_request, validate_prepare_alias_consistency


@pytest.fixture(autouse=True)
def clear_paper_registry():
    paper_api._CASES.clear()
    paper_api._RECORDS.clear()


@pytest.fixture()
def paper_source(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "src").mkdir()
    (source / "src" / "main.c").write_text("int main(){return 0;}\n")
    compile_commands = source / "compile_commands.json"
    compile_commands.write_text("[]\n")
    return source, compile_commands


def _surface(status="empty", count=0, policy="test_policy", reason=None, diagnostics=None):
    return {
        "status": status,
        "count": count,
        "consumerPolicy": policy,
        "reasonCodes": reason or [],
        "diagnosticRefs": diagnostics or [],
    }


def s4_bundle(case_id="case-001", build_target_id="target-001", *, findings=True, diagnostics=False):
    claim_boundaries = {
        "negativeEvidencePolicy": "empty-or-missing-s4-evidence-is-not-negative-security-evidence",
        "mustNotSupportAlone": ["final-security-verdict", "vulnerability-absence"],
    }
    claim_matrix = [
        {
            "claimId": "absence-of-vulnerability",
            "supportStatus": "unsupported",
            "reasonCodes": ["EMPTY_OR_MISSING_S4_EVIDENCE_IS_NOT_NEGATIVE_EVIDENCE"],
            "consumerPolicy": "do_not_use_as_negative_evidence",
            "evidenceRefs": ["claimBoundaries.negativeEvidencePolicy"],
            "summary": "S4 cannot support vulnerability absence.",
        }
    ]
    finding_rows = []
    evidence_rows = []
    if findings:
        finding_rows = [
            {
                "findingId": "s4-finding-001",
                "toolId": "semgrep",
                "ruleId": "CWE-120",
                "message": "Potential unchecked copy",
                "severity": "high",
                "cweCandidates": ["CWE-120"],
                "location": {"sourceFileId": "s4-source-file-001", "path": "src/main.c", "startLine": 1, "endLine": 1},
                "functionId": None,
                "evidenceRefs": [],
                "diagnosticRefs": [],
                "trace": _trace(case_id, build_target_id, "findings", "findings[0]"),
            }
        ]
        evidence_rows = [
            {
                "evidenceId": "s4-evidence-001",
                "evidenceType": "sast_message",
                "producer": "s4",
                "findingId": "s4-finding-001",
                "sourceFileId": "s4-source-file-001",
                "text": "Semgrep reported unchecked copy.",
                "consumerPolicy": "local_static_finding_only",
                "diagnosticRefs": [],
                "trace": _trace(case_id, build_target_id, "evidence", "evidence[0]"),
            }
        ]
    diag_rows = []
    if diagnostics:
        diag_rows = [
            {
                "diagnosticId": "s4:diagnostic:001",
                "severity": "warning",
                "category": "tool-execution",
                "reasonCode": "SURFACE_NOT_AVAILABLE",
                "surface": "libraries",
                "message": "Library surface unavailable.",
                "consumerPolicy": "producer_diagnostic_not_security_evidence",
                "trace": _trace(case_id, build_target_id, "diagnostics", "diagnostics[0]"),
            }
        ]
    return {
        "schemaVersion": "s4-paper-static-evidence-bundle-v1",
        "bundleProfile": "s4-paper-static-evidence-full-v1",
        "surfacePolicy": "always_attempt_full_bundle",
        "success": True,
        "bundleStatus": "produced",
        "evidenceCompleteness": {"status": "bounded_partial", "consumerPolicy": "not_complete_security_evidence"},
        "caseId": case_id,
        "buildTargetId": build_target_id,
        "s4RequestId": "s4-request-001",
        "s4ProducerRunId": "s4-run-001",
        "bundleRef": "s4-bundle:case-001",
        "producer": {"service": "s4-sast-runner", "serviceVersion": "0.11.2", "deterministic": True},
        "provenance": {
            "paperRunId": "paper-run-001",
            "buildSnapshotId": "build-snapshot-001",
            "buildUnitId": "build-unit-001",
            "sourceRootRef": "source-root:case-001:target-001",
            "compileContextRef": "compile-context:case-001:target-001",
        },
        "surfaceStatus": {
            "findings": _surface("produced" if findings else "empty", len(finding_rows)),
            "evidence": _surface("produced" if evidence_rows else "empty", len(evidence_rows)),
            "sourceFiles": _surface("produced", 1),
            "functions": _surface(),
            "includeEdges": _surface(),
            "libraries": _surface("not_available" if diagnostics else "empty", 0, diagnostics=["s4:diagnostic:001"] if diagnostics else []),
            "toolRuns": _surface("produced", 1),
            "targetMetadata": _surface("produced", 1),
            "staticEvidenceContract": _surface("produced", 1),
            "claimBoundaryMatrix": _surface("produced", 1),
            "claimBoundaries": _surface("produced", 1),
        },
        "diagnostics": diag_rows,
        "findings": finding_rows,
        "evidence": evidence_rows,
        "sourceFiles": [
            {
                "sourceFileId": "s4-source-file-001",
                "path": "src/main.c",
                "language": "c",
                "compileContextRef": "compile-context:case-001:target-001",
                "diagnosticRefs": [],
                "trace": _trace(case_id, build_target_id, "sourceFiles", "sourceFiles[0]"),
            }
        ],
        "functions": [],
        "includeEdges": [],
        "libraries": [],
        "toolRuns": [
            {
                "toolRunId": "s4-tool-run-semgrep",
                "toolId": "semgrep",
                "status": "ok",
                "findingsCount": len(finding_rows),
                "version": "1.0",
                "elapsedMs": 1,
                "degraded": False,
                "degradeReasons": [],
                "consumerPolicy": "local_tool_execution_state_only_not_vulnerability_verdict",
                "diagnosticRefs": [],
                "trace": _trace(case_id, build_target_id, "toolRuns", "toolRuns[0]"),
            }
        ],
        "targetMetadata": {
            "trace": _trace(case_id, build_target_id, "targetMetadata", "targetMetadata"),
            "language": "c/cpp",
            "sourceRootRef": "source-root:case-001:target-001",
            "compileContext": {"type": "compile_commands_json", "path": "compile_commands.json", "ref": "compile-context:case-001:target-001"},
            "scopeSummary": {"includePathCount": 0, "excludePathCount": 0, "thirdPartyPathCount": 0},
            "observedBuildProfile": {"compileDatabaseEntries": 1, "analyzableSourceFiles": 1},
        },
        "staticEvidenceContract": {"claimBoundaryMatrix": claim_matrix, "claimBoundaries": claim_boundaries},
        "claimBoundaryMatrix": claim_matrix,
        "claimBoundaries": claim_boundaries,
    }


def s4_bundle_with_semgrep_coverage_caveat(case_id="case-coverage", build_target_id="target-001"):
    bundle = s4_bundle(case_id=case_id, build_target_id=build_target_id, findings=False)
    diagnostic_id = "s4:diagnostic:semgrep-cpp-effective-coverage"
    bundle["diagnostics"].append(
        {
            "diagnosticId": diagnostic_id,
            "severity": "warning",
            "category": "tool-coverage",
            "reasonCode": "SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN",
            "surface": "toolRuns",
            "message": "Semgrep ran successfully, but C++ effective coverage is caveated.",
            "consumerPolicy": "producer_diagnostic_not_security_evidence",
            "trace": _trace(case_id, build_target_id, "diagnostics", "diagnostics[0]"),
        }
    )
    bundle["staticEvidenceContract"]["gates"] = {
        "qualityEvaluation": "not_evaluated",
        "coverageQuality": {
            "status": "caveated",
            "consumerPolicy": "coverage_caveat_not_negative_security_evidence",
        },
    }
    bundle["toolRuns"][0].update(
        {
            "findingsCount": 0,
            "coverage": {"coverageKind": "semgrep-effective-coverage-v1"},
            "coverageDegraded": True,
            "coverageReasons": ["SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"],
            "diagnosticRefs": [diagnostic_id],
        }
    )
    return bundle


def _trace(case_id, build_target_id, surface, raw):
    return {
        "caseId": case_id,
        "buildTargetId": build_target_id,
        "bundleRef": "s4-bundle:case-001",
        "s4RequestId": "s4-request-001",
        "s4ProducerRunId": "s4-run-001",
        "sourceRootRef": "source-root:case-001:target-001",
        "compileContextRef": "compile-context:case-001:target-001",
        "surfaceId": f"s4:surface:{surface}",
        "surface": surface,
        "rawObjectRef": raw,
    }


def s5_prepare(case_id="case-001", build_target_id="target-001"):
    return {
        "schemaVersion": "s5-prepare-code-kb-response-v1",
        "caseId": case_id,
        "buildTargetId": build_target_id,
        "paperRunId": "paper-run-001",
        "requestId": "s3-s5-prepare-001",
        "idempotencyKey": "case-001:target-001:s5:prepare-code-kb:v1",
        "codeKbRunId": "s5-code-kb-run-001",
        "s5ProducerRunId": "s5-run-code-001",
        "surfaceStatus": "produced",
        "stageReadiness": "ready",
        "codeKbRef": "s5-code-kb:case-001:target-001",
        "sourceKgRef": "s5-source-kg:case-001:target-001",
        "readiness": {"codeKbReady": True, "sourceKgReady": True, "contextSelectable": True},
        "producerProvenance": {"component": "s5-knowledge-base"},
        "diagnostics": [],
    }


def s5_context(case_id="case-001", build_target_id="target-001", *, finding_id="s4-finding-001", no_hit=False, text="Nearby code checks bounds before copy."):
    rows = [] if no_hit else [s5_row(finding_id=finding_id, text=text)]
    return {
        "schemaVersion": "s5-retrieve-finding-context-response-v1",
        "caseId": case_id,
        "buildTargetId": build_target_id,
        "paperRunId": "paper-run-001",
        "findingId": finding_id,
        "requestId": f"s3-s5-finding-context-{finding_id}",
        "idempotencyKey": f"case-001:{finding_id}:s5:finding-context:v1",
        "s5ProducerRunId": "s5-run-finding-001",
        "retrievalRunId": "s5-retrieval-finding-001",
        "rowSetId": "s5-row-set-finding-001",
        "surfaceStatus": "no_hit" if no_hit else "produced",
        "rows": rows,
        "retrievalTrace": {"orderingPolicy": "s5-paper-stable-row-order-v1", "b2b4StableRows": True, "returnedCount": len(rows)},
        "producerProvenance": {"component": "s5-knowledge-base"},
        "diagnostics": [
            {
                "code": "S5_PAPER_CONTEXT_NO_HIT",
                "message": "No source context row matched the S3-provided anchors.",
                "severity": "info",
                "surfaceStatus": "no_hit",
                "consumerPolicy": "diagnostic_only_not_security_evidence",
                "negativeEvidenceAllowed": False,
                "visibleLeakageClass": "generic",
                "relatedItemIds": [],
                "metadata": {},
            }
        ] if no_hit else [],
    }


def s5_row(*, finding_id="s4-finding-001", item_id="s5-code-row-001", text="Context row"):
    return {
        "schemaVersion": "s5-paper-evidence-row-v1",
        "retrievalRunId": "s5-retrieval-finding-001",
        "itemId": item_id,
        "sourceType": "code",
        "queryIntent": "finding_local_context",
        "sourceEvidence": {"kind": "source_kg_snippet", "ref": "source-kg-snippet:001", "displayRef": "src/main.c:1", "s3EvidenceRefs": [f"s3-evidence:s4:finding:{finding_id}"]},
        "surfaceStatus": "produced",
        "visibleLeakageClass": "generic",
        "text": text,
        "rank": 1,
        "score": 0.8,
        "orderingKey": "000001:s5-code-row-001",
        "producerTrace": {"s5ProducerRunId": "s5-run-finding-001", "retrievalPolicyVersion": "s5-paper-retrieval-policy-v1"},
        "diagnostics": [],
    }


def s5_threat(case_id="case-001", build_target_id="target-001", *, finding_id="s4-finding-001", no_hit=False):
    data = s5_context(case_id, build_target_id, finding_id=finding_id, no_hit=no_hit, text="CWE-120 concerns unchecked buffer copies.")
    data["schemaVersion"] = "s5-retrieve-generic-threat-context-response-v1"
    data["requestId"] = f"s3-s5-threat-context-{finding_id}"
    if data["rows"]:
        data["rows"][0]["itemId"] = "s5-threat-row-001"
        data["rows"][0]["sourceType"] = "cwe"
        data["rows"][0]["queryIntent"] = "generic_threat_context"
        data["rows"][0]["text"] = "CWE-120 concerns unchecked buffer copies."
    return data


def llm_tp(finding_id="s4-finding-001"):
    return {
        "findingId": finding_id,
        "verdict": "TP",
        "rationale": "SAST finding is supported by the cited local warning.",
        "citedEvidenceRefs": [f"s3-evidence:s4:finding:{finding_id}"],
        "claimEvidenceLinks": [{"claim": "SAST warning has local support", "stance": "supports", "evidenceRefs": [f"s3-evidence:s4:finding:{finding_id}"]}],
        "unsupportedClaims": [],
        "unknownReason": None,
        "diagnosticRefsUsed": [],
        "boundaryNotes": [],
    }


def llm_unknown(finding_id="s4-finding-001"):
    return {
        "findingId": finding_id,
        "verdict": "UNKNOWN",
        "rationale": "Context was insufficient for TP/FP.",
        "citedEvidenceRefs": [],
        "claimEvidenceLinks": [],
        "unsupportedClaims": [],
        "unknownReason": "UNKNOWN_INSUFFICIENT_CONTEXT",
        "diagnosticRefsUsed": [],
        "boundaryNotes": ["No-hit is not safe evidence."],
    }


def write_json(path: Path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return str(path)


def make_case_body(tmp_path: Path, paper_source, *, case_id="case-001", s4=None, s5_ctx=None, s5_threat_data=None, llm=None):
    source, compile_commands = paper_source
    artifacts = tmp_path / "producer"
    artifacts.mkdir(exist_ok=True)
    s4_path = write_json(artifacts / f"{case_id}-s4.json", s4 or s4_bundle(case_id=case_id))
    s5_prepare_path = write_json(artifacts / f"{case_id}-s5-prepare.json", s5_prepare(case_id=case_id))
    ctx = s5_ctx if s5_ctx is not None else s5_context(case_id=case_id)
    threat = s5_threat_data if s5_threat_data is not None else s5_threat(case_id=case_id)
    ctx_path = write_json(artifacts / f"{case_id}-s5-context.json", ctx)
    threat_path = write_json(artifacts / f"{case_id}-s5-threat.json", threat)
    llm_path = write_json(artifacts / f"{case_id}-llm.json", llm or llm_tp())
    return {
        "paperRunId": "paper-run-001",
        "paperRunRoot": str(tmp_path / "paper-run"),
        "caseId": case_id,
        "buildTargetId": "target-001",
        "targetManifestRef": "manifest:target-001",
        "datasetRootRef": "dataset-root:build-targets-v1",
        "sourceRootRef": "source-root:case-001:target-001",
        "sourceRoot": str(source),
        "compileContextRef": "compile-context:case-001:target-001",
        "compileCommandsPath": str(compile_commands),
        "buildSnapshotId": "build-snapshot-001",
        "buildUnitId": "build-unit-001",
        "producerArtifacts": {
            "s4StaticEvidencePath": s4_path,
            "s5CodeKbPath": s5_prepare_path,
            "s5FindingContextByFindingId": {"s4-finding-001": ctx_path},
            "s5GenericThreatContextByFindingId": {"s4-finding-001": threat_path},
            "llmTriageByFindingId": {"s4-finding-001": llm_path},
        },
    }


def test_create_list_and_start_finding_case_reaches_paper_export_ready(client, tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    created = client.post("/v1/paper/analysis-cases", json=body, headers={"X-Request-Id": "req-paper-start"})
    assert created.status_code == 201
    assert created.headers["X-Request-Id"] == "req-paper-start"
    assert created.json()["status"] == "CASE_REGISTERED"

    listed = client.get("/v1/paper/analysis-cases", params={"paperRunId": "paper-run-001"})
    assert listed.status_code == 200
    assert listed.headers["X-Request-Id"].startswith("req-")
    assert len(listed.json()["cases"]) == 1

    started = client.post("/v1/paper/analysis-cases/case-001/start")
    assert started.status_code == 200
    start_body = started.json()
    assert start_body["status"] == "PAPER_EXPORT_READY"
    assert start_body["summary"]["findingCount"] == 1
    assert start_body["summary"]["triageCounts"]["TP"] == 1

    artifacts = client.get("/v1/paper/analysis-cases/case-001/artifacts").json()
    assert "case-export-manifest.json" in artifacts["files"]
    assert "audit-packets/case-level/b4-aegis-full-packet.json" in artifacts["files"]
    state_trace = Path(body["paperRunRoot"]) / "cases" / "case-001" / "state-trace.jsonl"
    trace_rows = [json.loads(line) for line in state_trace.read_text().splitlines()]
    stages = [row["stage"] for row in trace_rows]
    for expected in ["CASE_REGISTERED", "BUILD_CONTEXT_READY", "SETUP_RUNNING", "S4_STATIC_EVIDENCE_READY", "S5_CODE_KB_READY", "S5_FINDING_CONTEXT_READY", "S3_TRIAGE_COMPLETED", "PAPER_EXPORT_READY"]:
        assert expected in stages
    setup_done_index = next(
        i for i, row in enumerate(trace_rows)
        if row["stage"] == "SETUP_RUNNING" and row["status"] == "done"
    )
    finding_context_index = next(i for i, row in enumerate(trace_rows) if row["stage"] == "S5_FINDING_CONTEXT_READY")
    assert setup_done_index < finding_context_index


def test_paper_runner_emits_stage_service_logs(client, tmp_path, paper_source, caplog):
    caplog.set_level(logging.INFO)
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body, headers={"X-Request-Id": "req-stage"}).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start", headers={"X-Request-Id": "req-stage"})
    assert response.status_code == 200

    stage_logs = [
        record for record in caplog.records
        if getattr(record, "_extra", {}).get("event") == "paper_stage"
    ]
    assert any(getattr(record, "_extra", {}).get("stage") == "S4_STATIC_EVIDENCE_READY" for record in stage_logs)
    assert any(getattr(record, "_extra", {}).get("stage") == "PAPER_EXPORT_READY" for record in stage_logs)
    for record in stage_logs:
        extra = getattr(record, "_extra", {})
        assert extra["caseId"] == "case-001"
        assert extra["buildTargetId"] == "target-001"
        assert extra["paperRunId"] == "paper-run-001"


def test_paper_error_and_validation_responses_include_request_id(client, tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body, headers={"X-Request-Id": "req-create"}).status_code == 201

    not_found = client.get("/v1/paper/analysis-cases/missing-case", headers={"X-Request-Id": "req-missing"})
    assert not_found.status_code == 404
    assert not_found.headers["X-Request-Id"] == "req-missing"
    assert not_found.json()["errorDetail"]["requestId"] == "req-missing"

    invalid = client.post(
        "/v1/paper/analysis-cases",
        json={"caseId": "case-bad", "sourceRoot": "SECRET_SOURCE_ROOT_SHOULD_NOT_LEAK"},
        headers={"X-Request-Id": "req-invalid"},
    )
    assert invalid.status_code == 422
    assert invalid.headers["X-Request-Id"] == "req-invalid"
    payload = invalid.json()
    assert payload["success"] is False
    assert payload["errorDetail"]["code"] == "REQUEST_VALIDATION_FAILED"
    assert payload["errorDetail"]["requestId"] == "req-invalid"
    assert "SECRET_SOURCE_ROOT_SHOULD_NOT_LEAK" not in invalid.text


def test_paper_error_detail_cannot_override_reserved_fields():
    token = set_request_id("req-reserved")
    try:
        response = paper_api._error_response(
            paper_api.PaperError(
                "boom",
                detail={"code": "EVIL", "requestId": "evil", "retryable": True, "safe": "ok"},
            )
        )
    finally:
        reset_request_id(token)

    payload = json.loads(response.body)
    assert payload["errorDetail"]["code"] == "PAPER_ERROR"
    assert payload["errorDetail"]["requestId"] == "req-reserved"
    assert payload["errorDetail"]["retryable"] is False
    assert payload["errorDetail"]["safe"] == "ok"


def test_zero_finding_case_reaches_paper_export_ready_without_s5_or_llm(client, tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source, case_id="case-zero", s4=s4_bundle(case_id="case-zero", findings=False))
    body["producerArtifacts"]["s5FindingContextByFindingId"] = {}
    body["producerArtifacts"]["s5GenericThreatContextByFindingId"] = {}
    body["producerArtifacts"]["llmTriageByFindingId"] = {}
    created = client.post("/v1/paper/analysis-cases", json=body)
    assert created.status_code == 201
    started = client.post("/v1/paper/analysis-cases/case-zero/start")
    assert started.status_code == 200
    assert started.json()["status"] == "PAPER_EXPORT_READY"
    assert started.json()["summary"]["findingCount"] == 0


def test_s4_semgrep_coverage_caveat_is_preserved_as_diagnostic_not_clean_evidence(client, tmp_path, paper_source):
    body = make_case_body(
        tmp_path,
        paper_source,
        case_id="case-coverage",
        s4=s4_bundle_with_semgrep_coverage_caveat(case_id="case-coverage"),
    )
    body["producerArtifacts"]["s5FindingContextByFindingId"] = {}
    body["producerArtifacts"]["s5GenericThreatContextByFindingId"] = {}
    body["producerArtifacts"]["llmTriageByFindingId"] = {}

    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    started = client.post("/v1/paper/analysis-cases/case-coverage/start")

    assert started.status_code == 200, started.text
    assert started.json()["status"] == "PAPER_EXPORT_READY"
    assert started.json()["summary"]["findingCount"] == 0
    assert started.json()["summary"]["triageCounts"] == {"TP": 0, "FP": 0, "UNKNOWN": 0}

    case_root = Path(body["paperRunRoot"]) / "cases" / "case-coverage"
    normalized = json.loads((case_root / "s4-static-evidence.normalized.json").read_text())
    tool_run = normalized["toolRuns"][0]
    assert tool_run["coverageDegraded"] is True
    assert tool_run["coverageReasons"] == ["SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"]
    assert tool_run["coverage"]["coverageKind"] == "semgrep-effective-coverage-v1"
    assert normalized["staticEvidenceContract"]["gates"]["coverageQuality"]["status"] == "caveated"

    ledger = [json.loads(line) for line in (case_root / "evidence-ledger.jsonl").read_text().splitlines()]
    tool_rows = [row for row in ledger if row["sourceId"] == "s4-tool-run-semgrep"]
    assert len(tool_rows) == 1
    tool_row = tool_rows[0]
    assert tool_row["evidenceRef"] == "s3-diagnostic:s4:toolRuns:s4-tool-run-semgrep"
    assert tool_row["diagnostic"] is True
    assert "coverageDegraded=true" in tool_row["text"]
    assert "SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN" in tool_row["text"]
    diagnostic_refs = {row["evidenceRef"] for row in ledger if row["diagnostic"]}
    assert "s3-diagnostic:s4:s4:diagnostic:semgrep-cpp-effective-coverage" in diagnostic_refs


def test_s4_non_consumable_bundle_fails_normal_start(client, tmp_path, paper_source):
    bad = s4_bundle()
    bad["success"] = False
    bad["bundleStatus"] = "failed"
    body = make_case_body(tmp_path, paper_source, s4=bad)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert response.json()["errorDetail"]["code"] == "PAPER_CONTRACT_ERROR"


def test_s4_missing_diagnostic_refs_fails_validation(client, tmp_path, paper_source):
    bad = s4_bundle()
    del bad["surfaceStatus"]["findings"]["diagnosticRefs"]
    body = make_case_body(tmp_path, paper_source, s4=bad)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "diagnosticRefs" in response.json()["error"]


def test_s4_claim_boundary_mirror_mismatch_fails_validation(client, tmp_path, paper_source):
    bad = s4_bundle()
    bad["claimBoundaries"] = {"negativeEvidencePolicy": "different"}
    body = make_case_body(tmp_path, paper_source, s4=bad)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "mirror mismatch" in response.json()["error"]


def test_s5_no_hit_carries_as_diagnostic_without_verdict_promotion(client, tmp_path, paper_source):
    body = make_case_body(
        tmp_path,
        paper_source,
        s5_ctx=s5_context(no_hit=True),
        s5_threat_data=s5_threat(no_hit=True),
        llm=llm_unknown(),
    )
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200
    assert response.json()["summary"]["triageCounts"]["UNKNOWN"] == 1
    ledger_path = Path(body["paperRunRoot"]) / "cases" / "case-001" / "evidence-ledger.jsonl"
    ledger = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    assert any(row["producer"] == "s5" and row["diagnostic"] is True for row in ledger)


def test_tp_cannot_cite_s5_diagnostic_ref_as_security_evidence(client, tmp_path, paper_source):
    diagnostic_ref = "s3-diagnostic:s5:s5_finding_context:s4-finding-001:S5_PAPER_CONTEXT_NO_HIT:0"
    bad_llm = llm_tp()
    bad_llm["citedEvidenceRefs"] = [diagnostic_ref]
    bad_llm["claimEvidenceLinks"] = [
        {
            "claim": "No S5 hit means this is exploitable.",
            "stance": "supports",
            "evidenceRefs": [diagnostic_ref],
        }
    ]
    body = make_case_body(
        tmp_path,
        paper_source,
        s5_ctx=s5_context(no_hit=True),
        s5_threat_data=s5_threat(no_hit=True),
        llm=bad_llm,
    )
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["triageCounts"]["UNKNOWN"] == 1
    triage_path = Path(body["paperRunRoot"]) / "cases" / "case-001" / "triage-envelope.jsonl"
    row = json.loads(triage_path.read_text().splitlines()[0])
    assert row["findingId"] == "s4-finding-001"
    assert row["verdict"] == "UNKNOWN"
    assert any("diagnostic refs cannot support" in claim for claim in row["unsupportedClaims"])


def test_tp_cannot_cite_non_produced_s4_surface_row_as_security_evidence(client, tmp_path, paper_source):
    partial_s4 = s4_bundle(diagnostics=True)
    partial_s4["surfaceStatus"]["evidence"]["status"] = "partial"
    partial_s4["surfaceStatus"]["evidence"]["reasonCodes"] = ["BOUNDED_PARTIAL"]
    partial_s4["surfaceStatus"]["evidence"]["diagnosticRefs"] = ["s4:diagnostic:001"]
    bad_llm = llm_tp()
    bad_llm["citedEvidenceRefs"] = ["s3-evidence:s4:evidence:s4-evidence-001"]
    bad_llm["claimEvidenceLinks"] = [
        {
            "claim": "A partial producer surface proves this finding.",
            "stance": "supports",
            "evidenceRefs": ["s3-evidence:s4:evidence:s4-evidence-001"],
        }
    ]
    body = make_case_body(tmp_path, paper_source, s4=partial_s4, llm=bad_llm)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["triageCounts"]["UNKNOWN"] == 1


def test_s5_forbidden_leakage_fails_closed(client, tmp_path, paper_source):
    leaky = s5_context(text="This mentions CVE-2024-12345 directly.")
    body = make_case_body(tmp_path, paper_source, s5_ctx=leaky)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "forbidden leakage" in response.json()["error"]


def test_tp_without_evidence_refs_is_rejected(client, tmp_path, paper_source):
    bad_llm = llm_tp()
    bad_llm["citedEvidenceRefs"] = []
    bad_llm["claimEvidenceLinks"] = []
    body = make_case_body(tmp_path, paper_source, llm=bad_llm)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200
    assert response.json()["summary"]["triageCounts"]["UNKNOWN"] == 1
    triage_path = Path(body["paperRunRoot"]) / "cases" / "case-001" / "triage-envelope.jsonl"
    row = json.loads(triage_path.read_text().splitlines()[0])
    assert row["verdict"] == "UNKNOWN"
    assert row["unsupportedClaims"]
    assert any("recovered" in note.lower() for note in row["boundaryNotes"])


def test_s4_producer_rows_are_absorbed_into_evidence_ledger_and_packets(client, tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text

    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    ledger = [json.loads(line) for line in (case_root / "evidence-ledger.jsonl").read_text().splitlines()]
    refs = {row["evidenceRef"] for row in ledger}
    assert "s3-evidence:s4:evidence:s4-evidence-001" in refs
    assert "s3-evidence:s4:sourceFiles:s4-source-file-001" in refs
    assert "s3-evidence:s4:toolRuns:s4-tool-run-semgrep" in refs
    assert "s3-evidence:s4:targetMetadata:targetMetadata" in refs
    assert "s3-evidence:s4:staticEvidenceContract:staticEvidenceContract" in refs
    assert "s3-evidence:s4:claimBoundaryMatrix:claimBoundaryMatrix" in refs
    assert "s3-evidence:s4:claimBoundaries:claimBoundaries" in refs
    b4 = json.loads((case_root / "audit-packets/findings/s4-finding-001/b4.json").read_text())
    b4_texts = [row["text"] for row in b4["ledgerRows"]]
    assert "Semgrep reported unchecked copy." in b4_texts
    assert any(text.startswith("Source file src/main.c") for text in b4_texts)


def test_s5_wrong_finding_response_fails_closed(client, tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source, s5_ctx=s5_context(finding_id="other-finding"))
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "findingId mismatch" in response.json()["error"]


def test_s4_non_produced_finding_surface_cannot_ground_tp(client, tmp_path, paper_source):
    partial_s4 = s4_bundle(diagnostics=True)
    partial_s4["surfaceStatus"]["findings"]["status"] = "partial"
    partial_s4["surfaceStatus"]["findings"]["reasonCodes"] = ["BOUNDED_PARTIAL"]
    partial_s4["surfaceStatus"]["findings"]["diagnosticRefs"] = ["s4:diagnostic:001"]
    body = make_case_body(tmp_path, paper_source, s4=partial_s4, llm=llm_tp())
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["triageCounts"]["UNKNOWN"] == 1


def test_s5_top_level_non_produced_status_makes_rows_diagnostic(client, tmp_path, paper_source):
    partial_ctx = s5_context()
    partial_ctx["surfaceStatus"] = "partial"
    partial_ctx["diagnostics"] = [
        {
            "code": "S5_PARTIAL",
            "message": "S5 returned partial context.",
            "severity": "warning",
            "surfaceStatus": "partial",
            "consumerPolicy": "diagnostic_only_not_security_evidence",
            "negativeEvidenceAllowed": False,
            "visibleLeakageClass": "generic",
            "relatedItemIds": [],
            "metadata": {},
        }
    ]
    bad_llm = llm_tp()
    bad_llm["citedEvidenceRefs"] = ["s3-diagnostic:s5:s5_finding_context:s5-code-row-001"]
    bad_llm["claimEvidenceLinks"] = [
        {
            "claim": "Partial S5 context proves the finding.",
            "stance": "supports",
            "evidenceRefs": ["s3-diagnostic:s5:s5_finding_context:s5-code-row-001"],
        }
    ]
    body = make_case_body(tmp_path, paper_source, s5_ctx=partial_ctx, llm=bad_llm)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["triageCounts"]["UNKNOWN"] == 1


def test_s5_forbidden_leakage_in_visible_keys_fails_closed(client, tmp_path, paper_source):
    leaky = s5_context()
    leaky["rows"][0]["sourceEvidence"]["CVE-2024-12345"] = "hidden case-specific key"
    body = make_case_body(tmp_path, paper_source, s5_ctx=leaky)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "forbidden leakage" in response.json()["error"]


def test_finalizer_cannot_cite_cross_finding_known_evidence_ref(client, tmp_path, paper_source):
    body = write_multi_case_body(tmp_path, paper_source)
    artifacts = Path(body["producerArtifacts"]["llmTriageByFindingId"]["s4-finding-001"]).parent
    wrong_ref_llm = llm_tp(finding_id="s4-finding-001")
    wrong_ref_llm["citedEvidenceRefs"] = ["s3-evidence:s4:finding:s4-finding-002"]
    wrong_ref_llm["claimEvidenceLinks"] = [
        {
            "claim": "The other finding supports this finding.",
            "stance": "supports",
            "evidenceRefs": ["s3-evidence:s4:finding:s4-finding-002"],
        }
    ]
    body["producerArtifacts"]["llmTriageByFindingId"]["s4-finding-001"] = write_json(
        artifacts / "multi-s4-finding-001-cross-ref-llm.json",
        wrong_ref_llm,
    )
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-multi/start")
    assert response.status_code == 200, response.text
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-multi"
    triage = [json.loads(line) for line in (case_root / "triage-envelope.jsonl").read_text().splitlines()]
    by_finding = {row["findingId"]: row for row in triage}
    assert by_finding["s4-finding-001"]["verdict"] == "UNKNOWN"
    assert by_finding["s4-finding-002"]["verdict"] == "TP"


def test_b2_public_text_hides_evidence_refs_in_recovery_messages(client, tmp_path, paper_source):
    bad_llm = llm_tp()
    bad_llm["citedEvidenceRefs"] = ["s3-evidence:s4:finding:not-real"]
    bad_llm["claimEvidenceLinks"] = [
        {
            "claim": "Bad ref should be hidden in public packet.",
            "stance": "supports",
            "evidenceRefs": ["s3-evidence:s4:finding:not-real"],
        }
    ]
    body = make_case_body(tmp_path, paper_source, llm=bad_llm)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    b2 = json.loads((case_root / "audit-packets/findings/s4-finding-001/b2.json").read_text())
    public_text = json.dumps(b2, sort_keys=True)
    assert "s3-evidence:" not in public_text
    assert "s3-diagnostic:" not in public_text
    assert "[hidden-evidence-ref]" in public_text


def test_s5_request_builder_sets_generic_visibility_and_forbidden_classes(tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    from app.paper.models import PaperCaseCreateRequest

    case = PaperCaseCreateRequest.model_validate(body)
    request = build_prepare_code_kb_request(case)
    assert request["visibilityMode"] == "generic"
    assert request["forbiddenLeakageClasses"] == ["cve_id", "fix_commit", "advisory", "exploit_writeup", "patch_text"]
    assert request["schemaVersion"] == "s5-prepare-code-kb-request-v1"
    assert request["requestId"]
    assert request["idempotencyKey"]


def test_s5_prepare_request_forwards_source_kg_inputs(tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    body["s5SourceKgIngestRequest"] = {
        "schemaVersion": "s5-source-code-kg-ingest-request-v1",
        "repositorySnapshot": {"repositoryId": "fixture-repo"},
        "graphNodes": [{"sourceGraphNodeId": "node-main", "nodeKind": "function"}],
    }
    body["s5SourceKgSelectors"] = {
        "repositorySnapshotId": "src-snapshot-001",
        "graphNodeIds": ["node-main"],
    }
    from app.paper.models import PaperCaseCreateRequest

    case = PaperCaseCreateRequest.model_validate(body)
    request = build_prepare_code_kb_request(case)

    assert request["sourceContext"]["sourceKgIngestRequest"] == body["s5SourceKgIngestRequest"]
    assert request["sourceContext"]["sourceKgSelectors"] == body["s5SourceKgSelectors"]


def test_s5_generic_threat_request_omits_source_kg_producer_refs(tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    from app.paper.models import PaperCaseCreateRequest

    case = PaperCaseCreateRequest.model_validate(body)
    finding = s4_bundle()["findings"][0]
    request = build_generic_threat_request(case, finding=finding)

    assert "producerInputRefs" not in request
    assert request["schemaVersion"] == "s5-retrieve-generic-threat-context-request-v1"
    assert request["visibilityMode"] == "generic"


def test_s5_prepare_alias_mismatch_fails_closed(tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    from app.paper.models import PaperCaseCreateRequest

    case = PaperCaseCreateRequest.model_validate(body)
    request = build_prepare_code_kb_request(case)
    request["sourceRootRef"] = "different"
    with pytest.raises(PaperContractError):
        validate_prepare_alias_consistency(request)


@pytest.mark.asyncio
async def test_s4_live_post_prefers_durable_ownership(monkeypatch, tmp_path, paper_source):
    captured = {}

    class FakeResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return s4_bundle()

    class FakeClient:
        def __init__(self, timeout):
            captured["client_timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json, headers, timeout=None):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            captured["post_timeout"] = timeout
            return FakeResponse()

    monkeypatch.setattr("app.paper.s4_client.httpx.AsyncClient", FakeClient)
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["s4StaticEvidencePath"] = None
    case = PaperCaseCreateRequest.model_validate(body)
    token = set_request_id("req-s3-parent")
    try:
        await S4PaperClient(endpoint="http://s4.local").produce_static_evidence(case)
    finally:
        reset_request_id(token)

    assert captured["url"] == "http://s4.local/v1/paper/static-evidence"
    assert captured["client_timeout"].read is None
    assert captured["client_timeout"].connect == 10.0
    assert captured["headers"]["Prefer"] == "respond-async"
    assert captured["headers"]["X-Request-Id"].startswith("req-s3-parent:s4:v1-paper-static-evidence:paper-static-evidence:")
    assert captured["post_timeout"].read == 30.0
    assert "X-Timeout-Ms" not in captured["headers"]


@pytest.mark.asyncio
async def test_s4_live_post_polls_durable_ownership_result(monkeypatch, tmp_path, paper_source):
    captured = {"get_urls": []}

    class FakeResponse:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = "{}"

        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, timeout):
            captured["client_timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json, headers, timeout=None):
            captured["post_url"] = url
            captured["post_headers"] = headers
            return FakeResponse(202, {
                "requestId": "req-owned",
                "state": "queued",
                "statusUrl": "/v1/requests/req-owned",
                "resultUrl": "/v1/requests/req-owned/result",
            })

        async def get(self, url, headers, timeout=None):
            captured["get_urls"].append(url)
            captured["get_headers"] = headers
            if url.endswith("/v1/requests/req-owned"):
                return FakeResponse(200, {"requestId": "req-owned", "state": "completed", "resultReady": True})
            if url.endswith("/v1/requests/req-owned/result"):
                return FakeResponse(200, {"requestId": "req-owned", "result": s4_bundle()})
            raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr("app.paper.s4_client.httpx.AsyncClient", FakeClient)
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["s4StaticEvidencePath"] = None
    case = PaperCaseCreateRequest.model_validate(body)
    token = set_request_id("req-s3-parent")
    try:
        data, _request = await S4PaperClient(endpoint="http://s4.local").produce_static_evidence(case)
    finally:
        reset_request_id(token)

    assert data["schemaVersion"] == "s4-paper-static-evidence-bundle-v1"
    assert captured["post_url"] == "http://s4.local/v1/paper/static-evidence"
    assert captured["post_headers"]["Prefer"] == "respond-async"
    assert captured["get_urls"] == [
        "http://s4.local/v1/requests/req-owned",
        "http://s4.local/v1/requests/req-owned/result",
    ]
    assert captured["get_headers"]["X-Request-Id"].startswith("req-s3-parent:s4:v1-paper-static-evidence:paper-static-evidence:")


@pytest.mark.asyncio
async def test_s4_live_post_requires_durable_ownership(monkeypatch, tmp_path, paper_source):
    captured = {"post_count": 0}

    class FakeResponse:
        status_code = 404
        text = "unsupported"

        def json(self):
            return {"errorDetail": {"code": "REQUEST_NOT_FOUND"}}

    class FakeClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, json, headers, timeout=None):
            captured["post_count"] += 1
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr("app.paper.s4_client.httpx.AsyncClient", FakeClient)
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["s4StaticEvidencePath"] = None
    case = PaperCaseCreateRequest.model_validate(body)

    with pytest.raises(PaperOperationalError):
        await S4PaperClient(endpoint="http://s4.local").produce_static_evidence(case)

    assert captured["post_count"] == 1
    assert captured["headers"]["Prefer"] == "respond-async"


@pytest.mark.asyncio
async def test_s5_live_post_uses_x_request_id_and_maps_409(monkeypatch, caplog):
    captured = {}

    class FakeResponse:
        status_code = 409
        text = "conflict"

    class FakeClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, json, headers):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr("app.paper.s5_client.httpx.AsyncClient", FakeClient)
    client = S5PaperClient(endpoint="http://s5.local")
    caplog.set_level(logging.INFO)
    token = set_request_id("req-parent-s3")
    try:
        with pytest.raises(PaperOperationalError):
            await client._post(
                "/v1/paper/code-kb/prepare",
                {
                    "requestId": "req-1",
                    "idempotencyKey": "idem-1",
                    "visibilityMode": "generic",
                    "forbiddenLeakageClasses": ["cve_id", "fix_commit", "advisory", "exploit_writeup", "patch_text"],
                },
            )
    finally:
        reset_request_id(token)
    assert captured["timeout"].read is None
    assert captured["timeout"].connect == 10.0
    assert "X-AEGIS-Timeout-Policy" not in captured["headers"]
    assert "X-Timeout-Ms" not in captured["headers"]
    # S5 paper contract requires X-Request-Id to match body requestId.
    # S3 logs carry parent requestId and this operation request id separately.
    assert captured["headers"]["X-Request-Id"] == "req-1"
    assert captured["url"] == "http://s5.local/v1/paper/code-kb/prepare"
    s5_logs = [
        record for record in caplog.records
        if getattr(record, "_extra", {}).get("target") == "s5-kb"
    ]
    assert any(getattr(record, "_extra", {}).get("operationRequestId") == "req-1" for record in s5_logs)
    assert any(getattr(record, "_extra", {}).get("status") == 409 for record in s5_logs)


def s4_bundle_two_findings(case_id="case-multi", build_target_id="target-001"):
    bundle = s4_bundle(case_id=case_id, build_target_id=build_target_id)
    first = bundle["findings"][0]
    second = json.loads(json.dumps(first))
    second["findingId"] = "s4-finding-002"
    second["message"] = "Potential unchecked format string"
    second["ruleId"] = "CWE-134"
    second["cweCandidates"] = ["CWE-134"]
    second["trace"]["rawObjectRef"] = "findings[1]"
    bundle["findings"].append(second)
    bundle["surfaceStatus"]["findings"]["count"] = 2
    second_ev = json.loads(json.dumps(bundle["evidence"][0]))
    second_ev["evidenceId"] = "s4-evidence-002"
    second_ev["findingId"] = "s4-finding-002"
    second_ev["text"] = "Semgrep reported unchecked format string."
    second_ev["trace"]["rawObjectRef"] = "evidence[1]"
    bundle["evidence"].append(second_ev)
    bundle["surfaceStatus"]["evidence"]["count"] = 2
    return bundle


def write_multi_case_body(tmp_path: Path, paper_source):
    source, compile_commands = paper_source
    artifacts = tmp_path / "producer-multi"
    artifacts.mkdir(exist_ok=True)
    case_id = "case-multi"
    s4_path = write_json(artifacts / "multi-s4.json", s4_bundle_two_findings(case_id=case_id))
    s5_prepare_path = write_json(artifacts / "multi-s5-prepare.json", s5_prepare(case_id=case_id))
    context_paths = {}
    threat_paths = {}
    llm_paths = {}
    for idx, finding_id in enumerate(["s4-finding-001", "s4-finding-002"], start=1):
        ctx = s5_context(case_id=case_id, finding_id=finding_id, text=f"unique code context for {finding_id}")
        ctx["rows"][0]["itemId"] = f"s5-code-row-00{idx}"
        threat = s5_threat(case_id=case_id, finding_id=finding_id)
        threat["rows"][0]["itemId"] = f"s5-threat-row-00{idx}"
        threat["rows"][0]["text"] = f"unique threat context for {finding_id}"
        context_paths[finding_id] = write_json(artifacts / f"multi-{finding_id}-context.json", ctx)
        threat_paths[finding_id] = write_json(artifacts / f"multi-{finding_id}-threat.json", threat)
        llm_paths[finding_id] = write_json(artifacts / f"multi-{finding_id}-llm.json", llm_tp(finding_id=finding_id))
    return {
        "paperRunId": "paper-run-001",
        "paperRunRoot": str(tmp_path / "paper-run"),
        "caseId": case_id,
        "buildTargetId": "target-001",
        "targetManifestRef": "manifest:target-001",
        "datasetRootRef": "dataset-root:build-targets-v1",
        "sourceRootRef": "source-root:case-001:target-001",
        "sourceRoot": str(source),
        "compileContextRef": "compile-context:case-001:target-001",
        "compileCommandsPath": str(compile_commands),
        "buildSnapshotId": "build-snapshot-001",
        "buildUnitId": "build-unit-001",
        "producerArtifacts": {
            "s4StaticEvidencePath": s4_path,
            "s5CodeKbPath": s5_prepare_path,
            "s5FindingContextByFindingId": context_paths,
            "s5GenericThreatContextByFindingId": threat_paths,
            "llmTriageByFindingId": llm_paths,
        },
    }


def test_multi_finding_case_isolates_s5_rows_for_llm_and_packets(client, tmp_path, paper_source):
    body = write_multi_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-multi/start")
    assert response.status_code == 200, response.text
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-multi"
    transcripts = [json.loads(line) for line in (case_root / "llm-transcript.raw.jsonl").read_text().splitlines()]
    by_finding = {row["findingId"]: row for row in transcripts}
    assert "unique code context for s4-finding-001" in by_finding["s4-finding-001"]["request"]["prompt"]
    assert "unique code context for s4-finding-002" not in by_finding["s4-finding-001"]["request"]["prompt"]
    assert "unique code context for s4-finding-002" in by_finding["s4-finding-002"]["request"]["prompt"]
    b2_f1 = json.loads((case_root / "audit-packets/findings/s4-finding-001/b2.json").read_text())
    b4_f1 = json.loads((case_root / "audit-packets/findings/s4-finding-001/b4.json").read_text())
    b2_texts = [row["text"] for row in b2_f1["evidenceRows"]]
    b4_texts = [row["text"] for row in b4_f1["ledgerRows"]]
    assert b2_texts == b4_texts
    assert any("s4-finding-001" in text for text in b2_texts)
    assert not any("s4-finding-002" in text for text in b2_texts)


def _contains_forbidden_packet_key(value, forbidden: set[str]) -> bool:
    if isinstance(value, dict):
        return any(key in forbidden or _contains_forbidden_packet_key(child, forbidden) for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_forbidden_packet_key(child, forbidden) for child in value)
    return False


def test_b1_b2_packets_do_not_expose_ledger_refs_or_claim_links(client, tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text

    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    forbidden = {
        "evidenceRef",
        "evidenceRefs",
        "citedEvidenceRefs",
        "claimEvidenceLinks",
        "claimLinks",
        "s4Trace",
        "producerTrace",
        "rawObjectRef",
    }
    for condition in ["b1", "b2"]:
        packet = json.loads((case_root / f"audit-packets/findings/s4-finding-001/{condition}.json").read_text())
        assert not _contains_forbidden_packet_key(packet, forbidden)
        case_packet_name = "b1-raw-llm-rationale.json" if condition == "b1" else "b2-evidence-dump-no-ledger.json"
        case_packet = json.loads((case_root / "audit-packets/case-level" / case_packet_name).read_text())
        assert not _contains_forbidden_packet_key(case_packet, forbidden)
    b4 = json.loads((case_root / "audit-packets/findings/s4-finding-001/b4.json").read_text())
    assert _contains_forbidden_packet_key(b4, {"evidenceRef", "citedEvidenceRefs", "claimEvidenceLinks", "claimLinks"})


def test_file_backed_finalizer_still_records_deterministic_s5_tool_acquisition(client, tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text

    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    transcripts = [json.loads(line) for line in (case_root / "llm-transcript.raw.jsonl").read_text().splitlines()]
    tool_results = transcripts[0]["acquisition"]["toolResults"]
    assert {row["tool"] for row in tool_results if row["success"]} >= {"retrieve_finding_context", "retrieve_generic_threat_context"}
    assert all(row["deterministicFallback"] for row in tool_results if row["success"])
    assert (case_root / "s5-finding-context-requests.jsonl").read_text().strip()
    assert (case_root / "s5-generic-threat-context-requests.jsonl").read_text().strip()


def test_wrong_finding_tool_call_does_not_suppress_required_s5_fallback(client, tmp_path, paper_source, monkeypatch):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201

    async def wrong_finding_acquisition(self, case, *, finding, evidence_rows, acquisition_messages=None, round_index=1):
        return (
            {
                "toolCalls": [
                    {
                        "id": "bad-call",
                        "name": "retrieve_finding_context",
                        "arguments": {"findingId": "other-finding"},
                    }
                ],
                "content": None,
            },
            {"mode": "test-wrong-finding"},
        )

    monkeypatch.setattr("app.paper.llm_client.LlmTriageClient.acquire_for_finding", wrong_finding_acquisition)

    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    transcripts = [json.loads(line) for line in (case_root / "llm-transcript.raw.jsonl").read_text().splitlines()]
    tool_results = transcripts[0]["acquisition"]["toolResults"]
    assert any(row["tool"] == "retrieve_finding_context" and row["error"] == "finding_id_mismatch" for row in tool_results)
    assert any(row["tool"] == "retrieve_finding_context" and row["success"] and row["deterministicFallback"] for row in tool_results)
    assert any(row["tool"] == "retrieve_generic_threat_context" and row["success"] and row["deterministicFallback"] for row in tool_results)


def test_wrong_finding_finalizer_row_recovers_to_current_finding_unknown(client, tmp_path, paper_source, monkeypatch):
    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["llmTriageByFindingId"] = {}
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201

    async def no_acquisition(self, case, *, finding, evidence_rows, acquisition_messages=None, round_index=1):
        return ({"toolCalls": [], "content": None}, {"mode": "test-no-acquisition"})

    async def wrong_finding_finalizer(self, case, *, finding, evidence_rows, acquisition_notes=None):
        return (
            {
                "findingId": "other-finding",
                "verdict": "TP",
                "rationale": "Wrong finding id but valid current evidence ref.",
                "citedEvidenceRefs": ["s3-evidence:s4:finding:s4-finding-001"],
                "claimEvidenceLinks": [
                    {
                        "claim": "wrong id claim",
                        "stance": "supports",
                        "evidenceRefs": ["s3-evidence:s4:finding:s4-finding-001"],
                    }
                ],
                "unsupportedClaims": [],
                "unknownReason": None,
                "diagnosticRefsUsed": [],
                "boundaryNotes": [],
            },
            {"mode": "test-wrong-finalizer"},
        )

    monkeypatch.setattr("app.paper.llm_client.LlmTriageClient.acquire_for_finding", no_acquisition)
    monkeypatch.setattr("app.paper.llm_client.LlmTriageClient.finalize_finding", wrong_finding_finalizer)

    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    assert response.json()["summary"]["triageCounts"]["UNKNOWN"] == 1
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    triage = [json.loads(line) for line in (case_root / "triage-envelope.jsonl").read_text().splitlines()]
    assert len(triage) == 1
    assert triage[0]["findingId"] == "s4-finding-001"
    assert triage[0]["verdict"] == "UNKNOWN"
    b4 = json.loads((case_root / "audit-packets/findings/s4-finding-001/b4.json").read_text())
    assert b4["machineVerdict"]["findingId"] == "s4-finding-001"
    assert b4["machineVerdict"]["verdict"] == "UNKNOWN"


def test_runner_uses_multi_round_acquisition_before_required_fallback(client, tmp_path, paper_source, monkeypatch):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    rounds: list[dict] = []

    async def staged_acquisition(self, case, *, finding, evidence_rows, acquisition_messages=None, round_index=1):
        rounds.append({"round": round_index, "history": acquisition_messages})
        if round_index == 1:
            return (
                {
                    "toolCalls": [{"id": "call-list", "name": "list_evidence_rows", "arguments": {"findingId": finding["findingId"]}}],
                    "assistantMessage": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-list",
                                "type": "function",
                                "function": {"name": "list_evidence_rows", "arguments": json.dumps({"findingId": finding["findingId"]}, sort_keys=True)},
                            }
                        ],
                    },
                },
                {"mode": "test-round-1"},
            )
        if round_index == 2:
            assert acquisition_messages is not None
            assert any(message.get("role") == "tool" and message.get("tool_call_id") == "call-list" for message in acquisition_messages)
            return (
                {
                    "toolCalls": [{"id": "call-context", "name": "retrieve_finding_context", "arguments": {"findingId": finding["findingId"]}}],
                    "assistantMessage": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-context",
                                "type": "function",
                                "function": {"name": "retrieve_finding_context", "arguments": json.dumps({"findingId": finding["findingId"]}, sort_keys=True)},
                            }
                        ],
                    },
                },
                {"mode": "test-round-2"},
            )
        return ({"toolCalls": [], "assistantMessage": {"role": "assistant", "content": "done"}}, {"mode": "test-round-3"})

    monkeypatch.setattr("app.paper.llm_client.LlmTriageClient.acquire_for_finding", staged_acquisition)

    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    assert [row["round"] for row in rounds] == [1, 2, 3]
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    transcripts = [json.loads(line) for line in (case_root / "llm-transcript.raw.jsonl").read_text().splitlines()]
    tool_results = transcripts[0]["acquisition"]["toolResults"]
    assert any(row["tool"] == "list_evidence_rows" and row["success"] for row in tool_results)
    assert any(row["tool"] == "retrieve_finding_context" and row["success"] and not row["deterministicFallback"] for row in tool_results)
    assert any(row["tool"] == "retrieve_generic_threat_context" and row["success"] and row["deterministicFallback"] for row in tool_results)
    assert not any(row["tool"] == "retrieve_finding_context" and row["success"] and row["deterministicFallback"] for row in tool_results)


def test_runner_dedupes_required_tool_success_across_acquisition_rounds(client, tmp_path, paper_source, monkeypatch):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201

    async def duplicate_context_acquisition(self, case, *, finding, evidence_rows, acquisition_messages=None, round_index=1):
        if round_index in {1, 2}:
            return (
                {
                    "toolCalls": [{"id": f"call-context-{round_index}", "name": "retrieve_finding_context", "arguments": {"findingId": finding["findingId"]}}],
                    "assistantMessage": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": f"call-context-{round_index}",
                                "type": "function",
                                "function": {"name": "retrieve_finding_context", "arguments": json.dumps({"findingId": finding["findingId"]}, sort_keys=True)},
                            }
                        ],
                    },
                },
                {"mode": f"test-round-{round_index}"},
            )
        return ({"toolCalls": [], "assistantMessage": {"role": "assistant", "content": "done"}}, {"mode": "test-round-3"})

    monkeypatch.setattr("app.paper.llm_client.LlmTriageClient.acquire_for_finding", duplicate_context_acquisition)

    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    context_requests = (case_root / "s5-finding-context-requests.jsonl").read_text().splitlines()
    assert len(context_requests) == 1
    transcripts = [json.loads(line) for line in (case_root / "llm-transcript.raw.jsonl").read_text().splitlines()]
    tool_results = transcripts[0]["acquisition"]["toolResults"]
    assert any(row["tool"] == "retrieve_finding_context" and row["success"] for row in tool_results)
    assert any(row["tool"] == "retrieve_finding_context" and row["error"] == "duplicate_tool_call" for row in tool_results)


def test_runner_executes_round_three_then_stops_and_compacts_finalizer_notes(client, tmp_path, paper_source, monkeypatch):
    body = make_case_body(tmp_path, paper_source)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    rounds: list[int] = []

    async def round_three_threat_acquisition(self, case, *, finding, evidence_rows, acquisition_messages=None, round_index=1):
        rounds.append(round_index)
        tool_name = "list_evidence_rows"
        if round_index == 3:
            tool_name = "retrieve_generic_threat_context"
        return (
            {
                "toolCalls": [{"id": f"call-{round_index}", "name": tool_name, "arguments": {"findingId": finding["findingId"]}}],
                "assistantMessage": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call-{round_index}",
                            "type": "function",
                            "function": {"name": tool_name, "arguments": json.dumps({"findingId": finding["findingId"]}, sort_keys=True)},
                        }
                    ],
                },
            },
            {"mode": f"test-round-{round_index}", "rawResponse": {"must": "not reach finalizer notes"}},
        )

    monkeypatch.setattr("app.paper.llm_client.LlmTriageClient.acquire_for_finding", round_three_threat_acquisition)

    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text
    assert rounds == [1, 2, 3]
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    transcripts = [json.loads(line) for line in (case_root / "llm-transcript.raw.jsonl").read_text().splitlines()]
    prompt = transcripts[0]["request"]["prompt"]
    assert "rawResponse" not in prompt
    assert "must" not in prompt
    tool_results = transcripts[0]["acquisition"]["toolResults"]
    assert any(row["tool"] == "retrieve_generic_threat_context" and row["success"] and not row["deterministicFallback"] for row in tool_results)
    assert any(row["tool"] == "retrieve_finding_context" and row["success"] and row["deterministicFallback"] for row in tool_results)


def test_s5_prepare_not_ready_fails_start_as_operational_error(client, tmp_path, paper_source):
    not_ready = s5_prepare()
    not_ready["surfaceStatus"] = "not_available"
    not_ready["stageReadiness"] = "not_ready"
    not_ready["readiness"] = {"codeKbReady": False, "sourceKgReady": False, "contextSelectable": False}
    not_ready["diagnostics"] = [
        {
            "code": "S5_PAPER_CODE_KB_NOT_READY",
            "message": "Code KB is not available.",
            "consumerPolicy": "diagnostic_only_not_security_evidence",
            "negativeEvidenceAllowed": False,
        }
    ]
    body = make_case_body(tmp_path, paper_source)
    prep_path = Path(body["producerArtifacts"]["s5CodeKbPath"])
    write_json(prep_path, not_ready)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 502
    assert response.json()["errorDetail"]["code"] == "PAPER_OPERATIONAL_ERROR"


@pytest.mark.parametrize("surface_status", ["partial", "failed", "skipped", "not_available", "error"])
def test_s4_diagnostic_surface_status_requires_resolved_diagnostic_ref(client, tmp_path, paper_source, surface_status):
    partial = s4_bundle()
    partial["surfaceStatus"]["functions"]["status"] = surface_status
    partial["surfaceStatus"]["functions"]["reasonCodes"] = ["BOUNDED_DIAGNOSTIC"]
    body = make_case_body(tmp_path, paper_source, s4=partial)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "requires diagnosticRefs" in response.json()["error"]


@pytest.mark.parametrize("surface_status", ["partial", "failed", "skipped", "not_available", "error"])
def test_s4_diagnostic_surface_status_is_consumable_with_diagnostic_ref(client, tmp_path, paper_source, surface_status):
    partial = s4_bundle(diagnostics=True)
    partial["surfaceStatus"]["functions"]["status"] = surface_status
    partial["surfaceStatus"]["functions"]["reasonCodes"] = ["BOUNDED_DIAGNOSTIC"]
    partial["surfaceStatus"]["functions"]["diagnosticRefs"] = ["s4:diagnostic:001"]
    body = make_case_body(tmp_path, paper_source, s4=partial)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text


def test_s4_surface_status_unresolved_diagnostic_ref_fails(client, tmp_path, paper_source):
    bad = s4_bundle(diagnostics=True)
    bad["surfaceStatus"]["functions"]["status"] = "partial"
    bad["surfaceStatus"]["functions"]["diagnosticRefs"] = ["s4:diagnostic:missing"]
    body = make_case_body(tmp_path, paper_source, s4=bad)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "unresolved" in response.json()["error"]


def test_s4_surface_status_rejects_non_string_diagnostic_ref(client, tmp_path, paper_source):
    bad = s4_bundle(diagnostics=True)
    bad["surfaceStatus"]["functions"]["status"] = "partial"
    bad["surfaceStatus"]["functions"]["diagnosticRefs"] = [None]
    body = make_case_body(tmp_path, paper_source, s4=bad)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "non-empty strings" in response.json()["error"]


def test_s4_diagnostics_require_non_empty_diagnostic_id(client, tmp_path, paper_source):
    bad = s4_bundle(diagnostics=True)
    bad["diagnostics"][0]["diagnosticId"] = None
    bad["surfaceStatus"]["functions"]["status"] = "partial"
    bad["surfaceStatus"]["functions"]["diagnosticRefs"] = [None]
    body = make_case_body(tmp_path, paper_source, s4=bad)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 422
    assert "diagnosticId" in response.json()["error"]


def test_s5_ready_with_diagnostics_is_usable_when_context_selectable(client, tmp_path, paper_source):
    partial_ready = s5_prepare()
    partial_ready["surfaceStatus"] = "partial"
    partial_ready["stageReadiness"] = "ready_with_diagnostics"
    partial_ready["readiness"] = {"codeKbReady": True, "sourceKgReady": True, "contextSelectable": True}
    partial_ready["diagnostics"] = [
        {
            "code": "S5_PAPER_CODE_KB_PARTIAL",
            "message": "Code KB is usable with bounded diagnostics.",
            "consumerPolicy": "diagnostic_only_not_security_evidence",
            "negativeEvidenceAllowed": False,
        }
    ]
    body = make_case_body(tmp_path, paper_source)
    write_json(Path(body["producerArtifacts"]["s5CodeKbPath"]), partial_ready)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 200, response.text


def test_s5_partial_ready_source_kg_quality_gate_is_usable_with_caveats(client, tmp_path, paper_source):
    partial_ready = s5_prepare()
    partial_ready["surfaceStatus"] = "partial"
    partial_ready["stageReadiness"] = "ready"
    partial_ready["readiness"] = {
        "codeKbReady": True,
        "sourceKgReady": True,
        "contextSelectable": True,
        "sourceKgQualityGate": "accepted_with_caveats",
    }
    partial_ready["diagnostics"] = [
        {
            "code": "S5_PAPER_SOURCE_KG_SMOKE_HARNESS_PROVENANCE",
            "message": "Selectable Source KG came from a smoke/manual harness.",
            "consumerPolicy": "diagnostic_only_not_security_evidence",
            "negativeEvidenceAllowed": False,
        },
        {
            "code": "S5_PAPER_SOURCE_KG_RICH_IR_NOT_AVAILABLE",
            "message": "Rich IR artifacts are not available for this Source KG.",
            "consumerPolicy": "diagnostic_only_not_security_evidence",
            "negativeEvidenceAllowed": False,
        },
    ]
    body = make_case_body(tmp_path, paper_source)
    write_json(Path(body["producerArtifacts"]["s5CodeKbPath"]), partial_ready)

    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")

    assert response.status_code == 200, response.text
    case_root = Path(body["paperRunRoot"]) / "cases" / "case-001"
    normalized = json.loads((case_root / "s5-code-kb.normalized.json").read_text())
    assert normalized["surfaceStatus"] == "partial"
    assert normalized["stageReadiness"] == "ready"
    assert normalized["readiness"]["sourceKgQualityGate"] == "accepted_with_caveats"
    assert {diag["code"] for diag in normalized["diagnostics"]} >= {
        "S5_PAPER_SOURCE_KG_SMOKE_HARNESS_PROVENANCE",
        "S5_PAPER_SOURCE_KG_RICH_IR_NOT_AVAILABLE",
    }


def test_s5_ready_with_diagnostics_requires_context_selectable(client, tmp_path, paper_source):
    partial_not_selectable = s5_prepare()
    partial_not_selectable["surfaceStatus"] = "partial"
    partial_not_selectable["stageReadiness"] = "ready_with_diagnostics"
    partial_not_selectable["readiness"] = {"codeKbReady": True, "sourceKgReady": True, "contextSelectable": False}
    partial_not_selectable["diagnostics"] = [
        {
            "code": "S5_PAPER_CODE_KB_PARTIAL",
            "message": "Code KB is not selectable.",
            "consumerPolicy": "diagnostic_only_not_security_evidence",
            "negativeEvidenceAllowed": False,
        }
    ]
    body = make_case_body(tmp_path, paper_source)
    write_json(Path(body["producerArtifacts"]["s5CodeKbPath"]), partial_not_selectable)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 502


def test_s5_produced_ready_requires_context_selectable(client, tmp_path, paper_source):
    contradiction = s5_prepare()
    contradiction["surfaceStatus"] = "produced"
    contradiction["stageReadiness"] = "ready"
    contradiction["readiness"] = {"codeKbReady": True, "sourceKgReady": True, "contextSelectable": False}
    body = make_case_body(tmp_path, paper_source)
    write_json(Path(body["producerArtifacts"]["s5CodeKbPath"]), contradiction)
    assert client.post("/v1/paper/analysis-cases", json=body).status_code == 201
    response = client.post("/v1/paper/analysis-cases/case-001/start")
    assert response.status_code == 502


@pytest.mark.asyncio
async def test_live_s7_chat_request_uses_generation_controls_and_openai_response(monkeypatch, tmp_path, paper_source):
    from app.agent_runtime.llm.generation_policy import TRACEAUDIT_QWEN36_FINALIZER_V1
    from app.paper.llm_client import LlmTriageClient
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["llmTriageByFindingId"] = {}
    case = PaperCaseCreateRequest.model_validate(body)
    captured = {}
    exchange_logs = []

    class FakeResponse:
        status_code = 200
        text = "ok"
        def __init__(self, payload):
            self._payload = payload
        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, json, headers):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return FakeResponse({
                "requestId": "acr-finalizer-001",
                "traceRequestId": headers.get("X-Request-Id"),
                "status": "accepted",
                "statusUrl": "/v1/async-chat-requests/acr-finalizer-001",
                "resultUrl": "/v1/async-chat-requests/acr-finalizer-001/result",
            })
        async def get(self, url, headers):
            captured.setdefault("get_urls", []).append(url)
            if url.endswith("/v1/async-chat-requests/acr-finalizer-001"):
                return FakeResponse({"requestId": "acr-finalizer-001", "state": "completed", "resultReady": True})
            if url.endswith("/v1/async-chat-requests/acr-finalizer-001/result"):
                return FakeResponse({
                    "requestId": "acr-finalizer-001",
                    "state": "completed",
                    "response": {
                        "choices": [{"message": {"content": json.dumps(llm_unknown())}}],
                    },
                })
            raise AssertionError(f"unexpected GET url: {url}")

    monkeypatch.setattr("app.paper.llm_client.settings.llm_mode", "real")
    monkeypatch.setattr("app.paper.llm_client.httpx.AsyncClient", FakeClient)
    monkeypatch.setattr("app.paper.observability._exchange_logger.info", lambda message: exchange_logs.append(json.loads(message)))
    token = set_request_id("req-paper-llm")
    try:
        result, request = await LlmTriageClient(endpoint="http://s7.local", timeout_seconds=123).finalize_finding(
            case,
            finding={"findingId": "s4-finding-001", "ruleId": "CWE-120"},
            evidence_rows=[{"evidenceRef": "s3-evidence:s4:finding:s4-finding-001", "text": "finding text"}],
            acquisition_notes={"toolResults": []},
        )
    finally:
        reset_request_id(token)
    assert result["verdict"] == "UNKNOWN"
    assert captured["url"] == "http://s7.local/v1/async-chat-requests"
    assert captured["headers"]["X-AEGIS-Paper-Controls"] == "true"
    assert captured["headers"]["X-AEGIS-Strict-JSON"] == "true"
    assert captured["headers"]["X-Request-Id"] == "req-paper-llm"
    assert "X-AEGIS-Wait-While-Alive" not in captured["headers"]
    assert "tools" not in captured["json"]
    assert captured["json"]["tool_choice"] == "none"
    assert "structured_outputs" not in captured["json"]
    assert captured["json"]["response_format"]["type"] == "json_schema"
    assert captured["json"]["logprobs"] is False
    assert "top_logprobs" not in captured["json"]
    for field, value in TRACEAUDIT_QWEN36_FINALIZER_V1.to_gateway_fields().items():
        assert captured["json"][field] == value
    assert captured["json"]["chat_template_kwargs"]["enable_thinking"] is False
    assert captured["json"]["chat_template_kwargs"]["preserve_thinking"] is False
    assert captured["get_urls"] == [
        "http://s7.local/v1/async-chat-requests/acr-finalizer-001",
        "http://s7.local/v1/async-chat-requests/acr-finalizer-001/result",
    ]
    assert request["mode"] == "live"
    assert exchange_logs
    exchange = exchange_logs[-1]
    assert exchange["service"] == "s3-agent"
    assert exchange["requestId"] == "req-paper-llm"
    assert exchange["phase"] == "paper_finalizer"
    assert exchange["mode"] == "live"
    assert exchange["model"] == captured["json"]["model"]
    assert exchange["maxTokens"] == captured["json"]["max_tokens"]
    assert "prompt" not in exchange
    assert "rawResponse" not in exchange


@pytest.mark.asyncio
async def test_live_s7_finalizer_parse_error_logs_metadata(monkeypatch, tmp_path, paper_source):
    from app.paper.llm_client import LlmTriageClient
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["llmTriageByFindingId"] = {}
    case = PaperCaseCreateRequest.model_validate(body)
    exchange_logs = []

    class FakeResponse:
        status_code = 200
        text = "ok"
        def __init__(self, payload):
            self._payload = payload
        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, timeout):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, json, headers):
            return FakeResponse({
                "requestId": "acr-finalizer-error",
                "statusUrl": "/v1/async-chat-requests/acr-finalizer-error",
                "resultUrl": "/v1/async-chat-requests/acr-finalizer-error/result",
            })
        async def get(self, url, headers):
            if url.endswith("/v1/async-chat-requests/acr-finalizer-error"):
                return FakeResponse({"requestId": "acr-finalizer-error", "state": "completed", "resultReady": True})
            if url.endswith("/v1/async-chat-requests/acr-finalizer-error/result"):
                return FakeResponse({
                    "requestId": "acr-finalizer-error",
                    "state": "completed",
                    "response": {"choices": [{"finish_reason": "stop", "message": {"content": "not-json"}}]},
                })
            raise AssertionError(f"unexpected GET url: {url}")

    monkeypatch.setattr("app.paper.llm_client.settings.llm_mode", "real")
    monkeypatch.setattr("app.paper.llm_client.httpx.AsyncClient", FakeClient)
    monkeypatch.setattr("app.paper.observability._exchange_logger.info", lambda message: exchange_logs.append(json.loads(message)))

    token = set_request_id("req-finalizer-error")
    try:
        with pytest.raises(PaperOperationalError):
            await LlmTriageClient(endpoint="http://s7.local").finalize_finding(
                case,
                finding={"findingId": "s4-finding-001", "ruleId": "CWE-120"},
                evidence_rows=[{"evidenceRef": "s3-evidence:s4:finding:s4-finding-001", "text": "finding text"}],
                acquisition_notes={"toolResults": []},
            )
    finally:
        reset_request_id(token)

    error_logs = [entry for entry in exchange_logs if entry.get("status") == "error"]
    assert error_logs
    assert error_logs[-1]["phase"] == "paper_finalizer"
    assert error_logs[-1]["errorCode"] == "LLM_RESPONSE_CONTRACT_ERROR"
    assert error_logs[-1]["requestId"] == "req-finalizer-error"
    assert "prompt" not in error_logs[-1]
    assert "rawResponse" not in error_logs[-1]


@pytest.mark.asyncio
async def test_live_s7_acquisition_request_uses_tools_auto_without_strict_json(monkeypatch, tmp_path, paper_source):
    from app.agent_runtime.llm.generation_policy import TRACEAUDIT_QWEN36_ACQUISITION_V1
    from app.paper.llm_client import LlmTriageClient
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["llmTriageByFindingId"] = {}
    case = PaperCaseCreateRequest.model_validate(body)
    captured = {}

    tool_response = {
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "retrieve_finding_context",
                                "arguments": json.dumps({"findingId": "s4-finding-001"}),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 3},
    }

    class FakeResponse:
        status_code = 200
        text = "ok"
        def __init__(self, payload):
            self._payload = payload
        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, json, headers):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return FakeResponse({
                "requestId": "acr-acquire-001",
                "traceRequestId": headers.get("X-Request-Id"),
                "status": "accepted",
                "statusUrl": "/v1/async-chat-requests/acr-acquire-001",
                "resultUrl": "/v1/async-chat-requests/acr-acquire-001/result",
            })
        async def get(self, url, headers):
            captured.setdefault("get_urls", []).append(url)
            if url.endswith("/v1/async-chat-requests/acr-acquire-001"):
                return FakeResponse({"requestId": "acr-acquire-001", "state": "completed", "resultReady": True})
            if url.endswith("/v1/async-chat-requests/acr-acquire-001/result"):
                return FakeResponse({"requestId": "acr-acquire-001", "state": "completed", "response": tool_response})
            raise AssertionError(f"unexpected GET url: {url}")

    monkeypatch.setattr("app.paper.llm_client.settings.llm_mode", "real")
    monkeypatch.setattr("app.paper.llm_client.httpx.AsyncClient", FakeClient)

    token = set_request_id("req-paper-acquire")
    try:
        result, request = await LlmTriageClient(endpoint="http://s7.local").acquire_for_finding(
            case,
            finding={"findingId": "s4-finding-001", "ruleId": "CWE-120"},
            evidence_rows=[{"evidenceRef": "s3-evidence:s4:finding:s4-finding-001", "text": "finding text"}],
        )
    finally:
        reset_request_id(token)

    assert result["toolCalls"][0]["name"] == "retrieve_finding_context"
    assert captured["url"] == "http://s7.local/v1/async-chat-requests"
    assert captured["headers"]["X-AEGIS-Paper-Controls"] == "true"
    assert "X-AEGIS-Strict-JSON" not in captured["headers"]
    assert "X-AEGIS-Wait-While-Alive" not in captured["headers"]
    assert captured["headers"]["X-Request-Id"] == "req-paper-acquire"
    assert captured["json"]["tool_choice"] == "auto"
    assert {tool["function"]["name"] for tool in captured["json"]["tools"]} >= {"retrieve_finding_context", "retrieve_generic_threat_context", "list_evidence_rows"}
    assert "response_format" not in captured["json"]
    assert "structured_outputs" not in captured["json"]
    assert captured["json"]["logprobs"] is False
    assert "top_logprobs" not in captured["json"]
    for field, value in TRACEAUDIT_QWEN36_ACQUISITION_V1.to_gateway_fields().items():
        assert captured["json"][field] == value
    assert captured["json"]["chat_template_kwargs"]["preserve_thinking"] is False
    assert captured["get_urls"] == [
        "http://s7.local/v1/async-chat-requests/acr-acquire-001",
        "http://s7.local/v1/async-chat-requests/acr-acquire-001/result",
    ]
    assert request["mode"] == "live"
    assert request["modelProfile"] == TRACEAUDIT_QWEN36_ACQUISITION_V1.profile_id
    assert request["generationProfile"] == TRACEAUDIT_QWEN36_ACQUISITION_V1.to_metadata(model=captured["json"]["model"])


@pytest.mark.asyncio
async def test_live_s7_acquisition_parse_error_logs_metadata(monkeypatch, tmp_path, paper_source):
    from app.paper.llm_client import LlmTriageClient
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["llmTriageByFindingId"] = {}
    case = PaperCaseCreateRequest.model_validate(body)
    exchange_logs = []

    class FakeResponse:
        status_code = 200
        text = "ok"
        def __init__(self, payload):
            self._payload = payload
        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, timeout):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, json, headers):
            return FakeResponse({
                "requestId": "acr-acquisition-error",
                "statusUrl": "/v1/async-chat-requests/acr-acquisition-error",
                "resultUrl": "/v1/async-chat-requests/acr-acquisition-error/result",
            })
        async def get(self, url, headers):
            if url.endswith("/v1/async-chat-requests/acr-acquisition-error"):
                return FakeResponse({"requestId": "acr-acquisition-error", "state": "completed", "resultReady": True})
            if url.endswith("/v1/async-chat-requests/acr-acquisition-error/result"):
                return FakeResponse({
                    "requestId": "acr-acquisition-error",
                    "state": "completed",
                    "response": {"choices": []},
                })
            raise AssertionError(f"unexpected GET url: {url}")

    monkeypatch.setattr("app.paper.llm_client.settings.llm_mode", "real")
    monkeypatch.setattr("app.paper.llm_client.httpx.AsyncClient", FakeClient)
    monkeypatch.setattr("app.paper.observability._exchange_logger.info", lambda message: exchange_logs.append(json.loads(message)))

    token = set_request_id("req-acquisition-error")
    try:
        with pytest.raises(PaperOperationalError):
            await LlmTriageClient(endpoint="http://s7.local").acquire_for_finding(
                case,
                finding={"findingId": "s4-finding-001", "ruleId": "CWE-120"},
                evidence_rows=[{"evidenceRef": "s3-evidence:s4:finding:s4-finding-001", "text": "finding text"}],
            )
    finally:
        reset_request_id(token)

    error_logs = [entry for entry in exchange_logs if entry.get("status") == "error"]
    assert error_logs
    assert error_logs[-1]["phase"] == "paper_acquisition"
    assert error_logs[-1]["errorCode"] == "LLM_RESPONSE_CONTRACT_ERROR"
    assert error_logs[-1]["requestId"] == "req-acquisition-error"
    assert "prompt" not in error_logs[-1]
    assert "rawResponse" not in error_logs[-1]


@pytest.mark.asyncio
async def test_live_s7_acquisition_second_round_preserves_openai_tool_history(monkeypatch, tmp_path, paper_source):
    from app.paper.llm_client import LlmTriageClient
    from app.paper.models import PaperCaseCreateRequest

    body = make_case_body(tmp_path, paper_source)
    body["producerArtifacts"]["llmTriageByFindingId"] = {}
    case = PaperCaseCreateRequest.model_validate(body)
    captured = {}
    history = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "user"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {
                        "name": "list_evidence_rows",
                        "arguments": json.dumps({"findingId": "s4-finding-001"}, sort_keys=True),
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "call-1",
            "name": "list_evidence_rows",
            "content": json.dumps({"success": True, "content": "Current normalized evidence rows: 1."}, sort_keys=True),
        },
    ]

    class FakeResponse:
        status_code = 200
        text = "ok"
        def __init__(self, payload):
            self._payload = payload
        def json(self):
            return self._payload

    class FakeClient:
        def __init__(self, timeout):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def post(self, url, json, headers):
            captured["json"] = json
            captured["headers"] = headers
            return FakeResponse({
                "requestId": "acr-acquire-round2",
                "statusUrl": "/v1/async-chat-requests/acr-acquire-round2",
                "resultUrl": "/v1/async-chat-requests/acr-acquire-round2/result",
            })
        async def get(self, url, headers):
            if url.endswith("/v1/async-chat-requests/acr-acquire-round2"):
                return FakeResponse({"requestId": "acr-acquire-round2", "state": "completed", "resultReady": True})
            if url.endswith("/v1/async-chat-requests/acr-acquire-round2/result"):
                return FakeResponse({
                    "requestId": "acr-acquire-round2",
                    "state": "completed",
                    "response": {
                        "choices": [
                            {
                                "finish_reason": "stop",
                                "message": {"content": "No additional tools.", "tool_calls": []},
                            }
                        ]
                    },
                })
            raise AssertionError(f"unexpected GET url: {url}")

    monkeypatch.setattr("app.paper.llm_client.settings.llm_mode", "real")
    monkeypatch.setattr("app.paper.llm_client.httpx.AsyncClient", FakeClient)
    result, _request = await LlmTriageClient(endpoint="http://s7.local").acquire_for_finding(
        case,
        finding={"findingId": "s4-finding-001", "ruleId": "CWE-120"},
        evidence_rows=[{"evidenceRef": "s3-evidence:s4:finding:s4-finding-001", "text": "finding text"}],
        acquisition_messages=history,
        round_index=2,
    )

    assert captured["json"]["messages"] == history
    assert captured["json"]["tool_choice"] == "auto"
    assert "response_format" not in captured["json"]
    assert "X-AEGIS-Strict-JSON" not in captured["headers"]
    assert result["toolCalls"] == []
    assert result["assistantMessage"] == {"role": "assistant", "content": "No additional tools."}
