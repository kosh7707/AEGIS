from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.paper import api as paper_api
from app.paper.errors import PaperContractError, PaperOperationalError
from app.paper.s5_client import S5PaperClient, build_prepare_code_kb_request, validate_prepare_alias_consistency


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
    created = client.post("/v1/paper/analysis-cases", json=body)
    assert created.status_code == 201
    assert created.json()["status"] == "CASE_REGISTERED"

    listed = client.get("/v1/paper/analysis-cases", params={"paperRunId": "paper-run-001"})
    assert listed.status_code == 200
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
    stages = [json.loads(line)["stage"] for line in state_trace.read_text().splitlines()]
    for expected in ["CASE_REGISTERED", "BUILD_CONTEXT_READY", "SETUP_RUNNING", "S4_STATIC_EVIDENCE_READY", "S5_CODE_KB_READY", "S5_FINDING_CONTEXT_READY", "S3_TRIAGE_COMPLETED", "PAPER_EXPORT_READY"]:
        assert expected in stages


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
    assert response.status_code == 422
    assert "TP/FP" in response.json()["error"]


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


def test_s5_prepare_alias_mismatch_fails_closed(tmp_path, paper_source):
    body = make_case_body(tmp_path, paper_source)
    from app.paper.models import PaperCaseCreateRequest

    case = PaperCaseCreateRequest.model_validate(body)
    request = build_prepare_code_kb_request(case)
    request["sourceRootRef"] = "different"
    with pytest.raises(PaperContractError):
        validate_prepare_alias_consistency(request)


@pytest.mark.asyncio
async def test_s5_live_post_sends_timeout_header_and_maps_409(monkeypatch):
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
    client = S5PaperClient(endpoint="http://s5.local", timeout_ms=1234)
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
    assert captured["headers"]["X-Timeout-Ms"] == "1234"
    assert captured["headers"]["X-Request-Id"] == "req-1"
    assert captured["url"] == "http://s5.local/v1/paper/code-kb/prepare"
