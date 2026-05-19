from __future__ import annotations

import importlib
import json
import re
from collections.abc import Iterable
from copy import deepcopy
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.ledger.repository import SQLiteLedgerRepository
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

FORBIDDEN_LEAKAGE_CLASSES = ["cve_id", "fix_commit", "advisory", "exploit_writeup", "patch_text"]
HEADERS = {"X-Timeout-Ms": "30000", "X-Request-Id": "s3-s5-prepare-001"}
FORBIDDEN_LEAKAGE_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE),
    re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE),
    re.compile(r"advisory", re.IGNORECASE),
    re.compile(r"exploit\s+writeup", re.IGNORECASE),
    re.compile(r"patch\s+text", re.IGNORECASE),
]
FINAL_AUTHORITY_KEYS = {
    "verdict",
    "finalVerdict",
    "triageLabel",
    "truePositive",
    "falsePositive",
    "affectednessProof",
    "notAffected",
    "exploitabilityProven",
    "absenceEvidence",
}
FINAL_AUTHORITY_TEXT = re.compile(
    r"\b(TP|FP|UNKNOWN|true positive|false positive|vulnerable|safe|clean|affected|not affected|exploitability proven|absence evidence)\b",
    re.IGNORECASE,
)


@pytest.fixture
def paper_repo(tmp_path):
    paper_context_api = importlib.import_module("app.routers.paper_context_api")
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo)
    paper_context_api.reset_paper_context_state()
    paper_context_api.set_ledger_repository(repo)
    yield repo
    paper_context_api.reset_paper_context_state()
    paper_context_api.set_ledger_repository(None)


def _source_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": "s5-source-code-kg-ingest-request-v1",
        "repositorySnapshot": {
            "repositoryUrl": "https://github.com/aegis-fixtures/openssl-demo.git",
            "repositoryId": "fixture-openssl-demo",
            "commitHash": "abcdef1234567890",
            "treeHash": "tree-1111",
            "submoduleHashes": {"crypto-submodule": "sub-2222"},
            "metadata": {"languageScope": ["c", "cpp"]},
            "provenance": {"producerLane": "S4", "evidenceRef": "repo-snapshot-fixture"},
        },
        "sourceArtifacts": [
            {
                "artifactUri": "file:///fixtures/openssl-demo.tar.zst",
                "mediaType": "application/zstd",
                "checksumSha256": "sha256:" + "a" * 64,
                "storageMode": "content_addressed",
                "metadata": {"retention": "full_source_snapshot"},
                "provenance": {"capturedBy": "fixture"},
            }
        ],
        "buildContext": {
            "projectId": "paper-case-001",
            "targetId": "target-001",
            "buildTarget": "tls-gateway",
            "toolchain": {"compiler": "gcc", "targetArch": "armv7"},
            "dependencyGraph": {"libraries": [{"name": "openssl", "version": "1.0.1f"}]},
            "buildMetadata": {"defines": ["OPENSSL_NO_HEARTBEATS=0"]},
            "provenance": {"buildSnapshotId": "build-snapshot-001"},
        },
        "analysisArtifactSet": {
            "analyzerName": "s4-static-fixture",
            "analyzerVersion": "1.0",
            "analysisConfig": {"enabled": ["callgraph", "taint"]},
            "artifactHashes": {"callgraph": "sha256:callgraph"},
            "producedAt": "2026-05-12T00:00:00Z",
            "provenance": {"sourceBuildAttemptId": "attempt-openssl-1"},
        },
        "evidenceSnippets": [
            {
                "evidenceSnippetId": "snippet-heartbeat-read",
                "filePath": "ssl/t1_lib.c",
                "lineStart": 2580,
                "lineEnd": 2590,
                "language": "c",
                "snippetText": "memcpy(bp, pl, payload);",
                "provenance": {"finding": "heartbeat over-read fixture"},
            }
        ],
        "graphNodes": [
            {
                "sourceGraphNodeId": "node-ssl3-read",
                "nodeKind": "function",
                "stableId": "func:ssl3_read_bytes",
                "displayName": "ssl3_read_bytes",
                "filePath": "ssl/s3_pkt.c",
                "lineStart": 1200,
                "lineEnd": 1300,
                "symbol": {"name": "ssl3_read_bytes"},
                "metadata": {"component": "openssl"},
            },
            {
                "sourceGraphNodeId": "node-heartbeat",
                "nodeKind": "function",
                "stableId": "func:tls1_process_heartbeat",
                "displayName": "tls1_process_heartbeat",
                "filePath": "ssl/t1_lib.c",
                "lineStart": 2560,
                "lineEnd": 2620,
                "symbol": {"name": "tls1_process_heartbeat"},
                "metadata": {"component": "openssl", "reachable": True},
                "evidenceSnippetId": "snippet-heartbeat-read",
            },
        ],
        "graphEdges": [
            {
                "sourceGraphEdgeId": "edge-ssl3-heartbeat",
                "edgeKind": "calls",
                "sourceGraphNodeId": "node-ssl3-read",
                "targetGraphNodeId": "node-heartbeat",
                "evidence": {"pathKind": "call"},
                "metadata": {"confidence": 1.0},
            }
        ],
        "richIrArtifacts": [],
    }
    payload.update(overrides)
    return payload


def _base_prepare_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": "s5-prepare-code-kb-request-v1",
        "caseId": "case-001",
        "buildTargetId": "target-001",
        "paperRunId": "paper-run-001",
        "requestId": "s3-s5-prepare-001",
        "idempotencyKey": "case-001:target-001:s5:prepare-code-kb:v1",
        "producerInputRefs": {
            "sourceRootRef": "source-root:case-001:target-001",
            "compileContextRef": "compile-context:case-001:target-001",
            "buildSnapshotId": "build-snapshot-001",
            "buildUnitId": "build-unit-001",
        },
        "sourceContext": {
            "sourceRoot": "/paper-runs/run-001/targets/target-001/source",
            "compileCommandsPath": "/paper-runs/run-001/targets/target-001/evidence/compile_commands.json",
            "language": "c/cpp",
            "scope": {"includePaths": ["ssl/"], "excludePaths": [], "thirdPartyPaths": []},
        },
        "visibilityMode": "generic",
        "forbiddenLeakageClasses": list(FORBIDDEN_LEAKAGE_CLASSES),
    }
    payload.update(overrides)
    return payload


def _prepare_with_ingest_payload(**overrides: Any) -> dict[str, Any]:
    payload = _base_prepare_payload()
    payload["sourceContext"] = {**payload["sourceContext"], "sourceKgIngestRequest": _source_payload()}
    payload.update(overrides)
    return payload


def _finding_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": "s5-retrieve-finding-context-request-v1",
        "caseId": "case-001",
        "buildTargetId": "target-001",
        "paperRunId": "paper-run-001",
        "findingId": "s4-finding-001",
        "requestId": "s3-s5-finding-context-001",
        "idempotencyKey": "case-001:s4-finding-001:s5:finding-context:v1",
        "codeKbRef": "s5-code-kb:case-001:target-001",
        "sourceKgRef": "s5-source-kg:case-001:target-001",
        "finding": {
            "findingId": "s4-finding-001",
            "s3EvidenceRefs": ["s3-evidence:s4-finding-001"],
            "sourceAnchors": [
                {
                    "fileRef": "s4-source-file-001",
                    "displayPath": "ssl/t1_lib.c",
                    "functionRef": "s4-function-001",
                    "symbolName": "tls1_process_heartbeat",
                    "lineStart": 2580,
                    "lineEnd": 2590,
                }
            ],
            "ruleId": "clang-analyzer-security.insecureAPI.memcpy",
            "cweCandidates": ["CWE-120"],
            "toolMessage": "Potential bounded-copy issue from static analysis",
            "libraryIdentity": {"name": "openssl", "version": "1.0.1f", "confidence": "observed_by_s4"},
        },
        "queryIntent": "finding_local_context",
        "retrievalProfile": "paper-code-context-default-v1",
        "topK": 5,
        "visibilityMode": "generic",
        "forbiddenLeakageClasses": list(FORBIDDEN_LEAKAGE_CLASSES),
    }
    payload.update(overrides)
    return payload


def _threat_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": "s5-retrieve-generic-threat-context-request-v1",
        "caseId": "case-001",
        "buildTargetId": "target-001",
        "paperRunId": "paper-run-001",
        "findingId": "s4-finding-001",
        "requestId": "s3-s5-threat-context-001",
        "idempotencyKey": "case-001:s4-finding-001:s5:generic-threat:v1",
        "s3EvidenceRefs": ["s3-evidence:s4-finding-001"],
        "cweCandidates": ["CWE-120"],
        "capecCandidates": [],
        "apiNames": ["memcpy"],
        "libraryIdentity": {"name": "openssl", "version": "1.0.1f", "confidence": "observed_by_s4"},
        "queryIntent": "generic_threat_context",
        "retrievalProfile": "paper-generic-threat-default-v1",
        "topK": 5,
        "visibilityMode": "generic",
        "forbiddenLeakageClasses": list(FORBIDDEN_LEAKAGE_CLASSES),
    }
    payload.update(overrides)
    return payload


def _visible_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key)
            yield from _visible_strings(nested)
    elif isinstance(value, list):
        for item in value:
            yield from _visible_strings(item)
    elif value is not None:
        yield str(value)


def _assert_no_forbidden_leakage(value: Any) -> None:
    rendered = json.dumps(value, sort_keys=True)
    for pattern in FORBIDDEN_LEAKAGE_PATTERNS:
        assert pattern.search(rendered) is None, pattern.pattern


def _assert_no_final_authority(value: Any) -> None:
    def walk(node: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(node, dict):
            for key, nested in node.items():
                assert key not in FINAL_AUTHORITY_KEYS
                walk(nested, (*path, str(key)))
        elif isinstance(node, list):
            for item in node:
                walk(item, path)
        elif isinstance(node, str):
            if path and path[-1] == "code":
                return
            assert FINAL_AUTHORITY_TEXT.search(node) is None, node

    walk(value)


def _seed_prepare(paper_repo) -> dict[str, Any]:
    resp = client.post("/v1/paper/code-kb/prepare", json=_prepare_with_ingest_payload(), headers=HEADERS)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stageReadiness"] == "ready"
    return body


def test_paper_context_contract_snapshot_advertises_s3_consumable_boundary():
    resp = client.get("/v1/contracts/paper-context", headers={"X-Request-Id": "req-contract"})

    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Request-Id"] == "req-contract"
    body = resp.json()
    assert body["schemaVersion"] == "s5-paper-context-contract-v1"
    assert body["contractVersion"] == "s5-paper-context-api-v1"
    assert body["defaultVisibilityMode"] == "generic"
    assert body["negativeEvidenceAllowed"] is False
    assert body["consumerBoundary"] == "contextual_support_not_final_verdict"
    endpoints = {(item["method"], item["path"], item["toolName"]) for item in body["endpoints"]}
    assert endpoints == {
        ("POST", "/v1/paper/code-kb/prepare", "prepare_code_kb"),
        ("POST", "/v1/paper/finding-context/retrieve", "retrieve_finding_context"),
        ("POST", "/v1/paper/threat-context/generic", "retrieve_generic_threat_context"),
    }
    assert all(item["timeoutHeaderRequired"] is True for item in body["endpoints"])
    assert body["policies"]["mainlineForbiddenLeakageClasses"] == FORBIDDEN_LEAKAGE_CLASSES
    assert body["policies"]["forbiddenInferencePolicy"] == "producer_status_is_not_final_triage"
    assert body["freezeGate"]["s5VisiblePacketSchemaFinalized"] is False
    assert body["freezeGate"]["finalVerdictFieldsForbidden"] is True


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/v1/paper/code-kb/prepare", _prepare_with_ingest_payload()),
        ("/v1/paper/finding-context/retrieve", _finding_payload()),
        ("/v1/paper/threat-context/generic", _threat_payload()),
    ],
)
def test_paper_post_endpoints_require_timeout_header(path: str, payload: dict[str, Any]):
    resp = client.post(path, json=payload, headers={"X-Request-Id": payload["requestId"]})

    assert resp.status_code == 400, resp.text
    assert resp.json()["errorDetail"]["code"] == "S5_PAPER_TIMEOUT_HEADER_MISSING_OR_INVALID"


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda payload: payload.update({"visibilityMode": "appendix_registered"}), "S5_PAPER_VISIBILITY_MODE_UNSUPPORTED"),
        (lambda payload: payload.update({"forbiddenLeakageClasses": ["cve_id"]}), "S5_PAPER_FORBIDDEN_LEAKAGE_CLASSES_REQUIRED"),
    ],
)
def test_prepare_fails_closed_for_visibility_policy_violations(paper_repo, mutator, expected_code):
    payload = _prepare_with_ingest_payload()
    mutator(payload)

    resp = client.post("/v1/paper/code-kb/prepare", json=payload, headers=HEADERS)

    assert resp.status_code == 422, resp.text
    assert resp.json()["errorDetail"]["code"] == expected_code


def test_prepare_with_only_paths_does_not_synthesize_code_kb_readiness(paper_repo):
    resp = client.post("/v1/paper/code-kb/prepare", json=_base_prepare_payload(), headers=HEADERS)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["surfaceStatus"] == "not_available"
    assert body["stageReadiness"] == "not_ready"
    assert body["readiness"]["codeKbReady"] is False
    assert body["readiness"]["sourceKgReady"] is False
    assert body["readiness"]["contextSelectable"] is False
    assert body["diagnostics"][0]["code"] in {"S5_PAPER_SOURCE_KG_NOT_AVAILABLE", "S5_PAPER_CODE_KB_NOT_READY"}
    assert body["diagnostics"][0]["negativeEvidenceAllowed"] is False


def test_prepare_seeds_real_source_kg_and_returns_s3_consumable_refs(paper_repo):
    body = _seed_prepare(paper_repo)

    assert body["surfaceStatus"] == "produced"
    assert body["stageReadiness"] == "ready"
    assert body["codeKbRef"] == "s5-code-kb:case-001:target-001"
    assert body["sourceKgRef"] == "s5-source-kg:case-001:target-001"
    assert body["readiness"] == {
        "codeKbReady": True,
        "sourceKgReady": True,
        "contextSelectable": True,
        "acceptedSourceRootRef": "source-root:case-001:target-001",
        "acceptedCompileContextRef": "compile-context:case-001:target-001",
        "rowCounts": {
            "sourceArtifacts": 1,
            "graphNodes": 2,
            "graphEdges": 1,
            "evidenceSnippets": 1,
            "richIrArtifacts": 0,
        },
    }
    assert body["producerProvenance"]["codeKbRef"] == body["codeKbRef"]
    assert body["producerProvenance"]["sourceKgRef"] == body["sourceKgRef"]
    assert body["producerProvenance"]["visibilityMode"] == "generic"
    observations = paper_repo.list_provider_observations(provider="s5-paper-context")
    assert any(obs["subjectKey"] == body["sourceKgRef"] and obs["status"] == "ready" for obs in observations)


def test_finding_retrieve_projects_real_source_kg_rows_with_b2_b4_stable_shape(paper_repo):
    _seed_prepare(paper_repo)

    resp = client.post(
        "/v1/paper/finding-context/retrieve",
        json=_finding_payload(),
        headers={"X-Timeout-Ms": "30000", "X-Request-Id": "s3-s5-finding-context-001"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["surfaceStatus"] == "produced"
    assert body["rowSetId"].startswith("s5-row-set-")
    assert body["retrievalTrace"]["b2b4StableRows"] is True
    assert body["retrievalTrace"]["orderingPolicy"] == "s5-paper-stable-row-order-v1"
    assert body["retrievalTrace"]["returnedCount"] == len(body["rows"])
    assert body["rows"]
    item_ids = [row["itemId"] for row in body["rows"]]
    ordering_keys = [row["orderingKey"] for row in body["rows"]]
    assert item_ids == sorted(item_ids, key=lambda item: ordering_keys[item_ids.index(item)])
    first = body["rows"][0]
    assert {
        "schemaVersion",
        "retrievalRunId",
        "itemId",
        "sourceType",
        "queryIntent",
        "sourceEvidence",
        "surfaceStatus",
        "visibleLeakageClass",
        "text",
        "producerTrace",
    } <= set(first)
    assert first["visibleLeakageClass"] == "generic"
    assert first["producerTrace"]["s5ProducerRunId"] == body["s5ProducerRunId"]
    assert first["sourceEvidence"]["sourceCodeKgRefs"]["sourceKgRef"] == body["producerProvenance"]["sourceKgRef"]
    assert "tls1_process_heartbeat" in first["text"]
    _assert_no_forbidden_leakage(body)
    _assert_no_final_authority(body)


def test_finding_no_hit_is_diagnostic_only_not_negative_evidence(paper_repo):
    _seed_prepare(paper_repo)
    payload = _finding_payload(
        finding={
            **_finding_payload()["finding"],
            "sourceAnchors": [
                {
                    "displayPath": "ssl/missing.c",
                    "symbolName": "missing_symbol",
                    "lineStart": 1,
                    "lineEnd": 2,
                }
            ],
        },
        idempotencyKey="case-001:s4-finding-404:s5:finding-context:v1",
        requestId="s3-s5-finding-context-404",
        findingId="s4-finding-404",
    )
    payload["finding"]["findingId"] = "s4-finding-404"

    resp = client.post(
        "/v1/paper/finding-context/retrieve",
        json=payload,
        headers={"X-Timeout-Ms": "30000", "X-Request-Id": "s3-s5-finding-context-404"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["surfaceStatus"] == "no_hit"
    assert body["rows"] == []
    assert body["diagnostics"]
    assert body["diagnostics"][0]["code"] == "S5_PAPER_CONTEXT_NO_HIT"
    assert body["diagnostics"][0]["negativeEvidenceAllowed"] is False
    assert body["diagnostics"][0]["consumerPolicy"] == "diagnostic_only_not_security_evidence"
    _assert_no_final_authority(body)


def test_generic_threat_context_uses_real_threat_kb_without_hidden_ids_or_verdicts(paper_repo):
    resp = client.post(
        "/v1/paper/threat-context/generic",
        json=_threat_payload(),
        headers={"X-Timeout-Ms": "30000", "X-Request-Id": "s3-s5-threat-context-001"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["surfaceStatus"] in {"produced", "partial"}
    assert body["rows"]
    assert body["rowSetId"].startswith("s5-row-set-")
    assert body["retrievalTrace"]["b2b4StableRows"] is True
    assert {row["sourceType"] for row in body["rows"]} & {"cwe", "generic_security_note"}
    assert all(row["visibleLeakageClass"] == "generic" for row in body["rows"])
    assert all(row["queryIntent"] == "generic_threat_context" for row in body["rows"])
    assert body["producerProvenance"]["threatRetrievalContractVersion"] == "s5-threat-retrieval-evidence-v1"
    _assert_no_forbidden_leakage(body)
    _assert_no_final_authority(body)


def test_visible_field_guard_redacts_source_kg_leakage_before_returning_rows(paper_repo):
    malicious = _source_payload()
    malicious["repositorySnapshot"].update(
        {
            "repositoryUrl": "https://example.invalid/advisory/CVE-2099-4242.git",
            "commitHash": "0123456789abcdef0123456789abcdef01234567",
            "metadata": {"hidden": "GHSA-abcd-efgh-ijkl patch text"},
        }
    )
    malicious["evidenceSnippets"][0].update(
        {
            "filePath": "ssl/CVE-2099-4242_patch.c",
            "snippetText": "CVE-2099-4242 exploit writeup patch text should not be visible",
        }
    )
    malicious["graphNodes"][1].update(
        {
            "filePath": "ssl/CVE-2099-4242_patch.c",
            "displayName": "GHSA-abcd-efgh-ijkl",
            "metadata": {"hiddenCommit": "0123456789abcdef0123456789abcdef01234567"},
        }
    )
    payload = _prepare_with_ingest_payload(sourceContext={**_base_prepare_payload()["sourceContext"], "sourceKgIngestRequest": malicious})
    prep = client.post("/v1/paper/code-kb/prepare", json=payload, headers=HEADERS)
    assert prep.status_code == 200, prep.text

    finding = _finding_payload(
        finding={
            **_finding_payload()["finding"],
            "sourceAnchors": [{"displayPath": "ssl/CVE-2099-4242_patch.c", "lineStart": 2580, "lineEnd": 2590}],
        }
    )
    resp = client.post(
        "/v1/paper/finding-context/retrieve",
        json=finding,
        headers={"X-Timeout-Ms": "30000", "X-Request-Id": "s3-s5-finding-context-001"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    _assert_no_forbidden_leakage(body)
    assert any(diag["code"] == "S5_PAPER_FORBIDDEN_LEAKAGE_REDACTED" for diag in body.get("diagnostics", []))


def test_idempotency_replays_same_fingerprint_and_rejects_conflicting_body(paper_repo):
    _seed_prepare(paper_repo)
    payload = _finding_payload()
    headers = {"X-Timeout-Ms": "30000", "X-Request-Id": payload["requestId"]}

    first = client.post("/v1/paper/finding-context/retrieve", json=payload, headers=headers)
    second = client.post("/v1/paper/finding-context/retrieve", json=payload, headers=headers)
    changed = deepcopy(payload)
    changed["topK"] = 1

    conflict = client.post("/v1/paper/finding-context/retrieve", json=changed, headers=headers)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["rowSetId"] == second.json()["rowSetId"]
    assert [row["itemId"] for row in first.json()["rows"]] == [row["itemId"] for row in second.json()["rows"]]
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["errorDetail"]["code"] == "S5_PAPER_IDEMPOTENCY_CONFLICT"
