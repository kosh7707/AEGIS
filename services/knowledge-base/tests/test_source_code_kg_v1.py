from __future__ import annotations

from fastapi.testclient import TestClient

from app.ledger.repository import SQLiteLedgerRepository
from app.main import app
from app.routers import source_kg_api
from app.source_kg.models import SourceCodeKgIngestRequest
from app.source_kg.service import ingest_source_kg

client = TestClient(app, raise_server_exceptions=False)
_HEADERS = {"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-test"}


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    return repo


def _payload(**overrides):
    payload = {
        "schemaVersion": "s5-source-code-kg-ingest-request-v1",
        "repositorySnapshot": {
            "repositoryUrl": "https://github.com/aegis-fixtures/openssl-vuln.git",
            "repositoryId": "fixture-openssl-vuln",
            "commitHash": "abcdef1234567890",
            "treeHash": "tree-1111",
            "submoduleHashes": {"crypto-submodule": "sub-2222"},
            "metadata": {"languageScope": ["c", "cpp"]},
            "provenance": {"producerLane": "S4", "evidenceRef": "repo-snapshot-fixture"},
        },
        "sourceArtifacts": [
            {
                "artifactUri": "file:///fixtures/openssl-vuln.tar.zst",
                "mediaType": "application/zstd",
                "checksumSha256": "sha256:repoarchive",
                "storageMode": "content_addressed",
                "metadata": {"retention": "full_source_snapshot"},
                "provenance": {"capturedBy": "fixture"},
            }
        ],
        "buildContext": {
            "projectId": "re100",
            "targetId": "re100:tls-gateway",
            "buildTarget": "tls-gateway",
            "toolchain": {"compiler": "gcc", "targetArch": "armv7"},
            "dependencyGraph": {"libraries": [{"name": "openssl", "version": "1.0.1f"}]},
            "buildMetadata": {"defines": ["OPENSSL_NO_HEARTBEATS=0"]},
            "provenance": {"buildSnapshotId": "bsnap-openssl-1"},
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
                "edgeKind": "calls",
                "sourceStableId": "func:ssl3_read_bytes",
                "targetStableId": "func:tls1_process_heartbeat",
                "evidence": {"pathKind": "call"},
                "metadata": {"confidence": 1.0},
            }
        ],
        "richIrArtifacts": [
            {
                "artifactKind": "taint_trace",
                "mediaType": "application/json",
                "uri": "file:///fixtures/taint-heartbeat.json",
                "checksumSha256": "sha256:tainttrace",
                "payload": {"source": "payload", "sink": "memcpy"},
                "provenance": {"producerLane": "S4"},
            }
        ],
    }
    payload.update(overrides)
    return payload


def test_source_code_kg_ingest_roundtrips_stable_ids_and_rich_evidence(tmp_path):
    repo = _repo(tmp_path)
    req = SourceCodeKgIngestRequest.model_validate(_payload())

    first = ingest_source_kg(repo, req).model_dump(by_alias=True)
    second = ingest_source_kg(repo, req).model_dump(by_alias=True)

    assert first == second
    assert first["ledgerOnly"] is True
    assert first["productionWrites"] == {"neo4j": False, "qdrant": False}
    assert first["counts"] == {
        "sourceArtifacts": 1,
        "evidenceSnippets": 1,
        "graphNodes": 2,
        "graphEdges": 1,
        "richIrArtifacts": 1,
    }

    context = repo.get_source_kg_context(
        repository_snapshot_id=first["repositorySnapshotId"],
        build_context_id=first["buildContextId"],
        analysis_artifact_set_id=first["analysisArtifactSetId"],
        graph_node_ids=first["ids"]["sourceGraphNodeIds"],
        evidence_snippet_ids=first["ids"]["evidenceSnippetIds"],
        rich_ir_artifact_ids=first["ids"]["richIrArtifactIds"],
    )
    assert context["resolved"] is True
    assert context["repositorySnapshot"]["commitHash"] == "abcdef1234567890"
    assert context["repositorySnapshot"]["treeHash"] == "tree-1111"
    assert context["repositorySnapshot"]["submoduleHashes"] == {"crypto-submodule": "sub-2222"}
    assert context["buildContext"]["buildMetadata"]["defines"] == ["OPENSSL_NO_HEARTBEATS=0"]
    assert context["analysisArtifactSet"]["artifactHashes"] == {"callgraph": "sha256:callgraph"}
    assert {node["stableId"] for node in context["graphNodes"]} == {"func:ssl3_read_bytes", "func:tls1_process_heartbeat"}
    assert context["graphEdges"][0]["edgeKind"] == "calls"
    assert context["evidenceSnippets"][0]["checksumSha256"].startswith("sha256:")
    assert context["richIrArtifacts"][0]["artifactKind"] == "taint_trace"


def test_repository_snapshot_is_version_root_builds_are_derivations(tmp_path):
    repo = _repo(tmp_path)
    first = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_payload())).model_dump(by_alias=True)
    changed = _payload()
    changed["buildContext"]["buildMetadata"] = {"defines": ["OPENSSL_NO_HEARTBEATS=1"]}
    second = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(changed)).model_dump(by_alias=True)

    assert first["repositorySnapshotId"] == second["repositorySnapshotId"]
    assert first["buildContextId"] != second["buildContextId"]
    assert repo.count_rows("source_repository_snapshot") == 1
    assert repo.count_rows("source_build_context") == 2


def test_source_code_kg_api_is_ledger_only_and_timeout_enforced(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        missing_timeout = client.post("/v1/source-code-kg/ingest", json=_payload(), headers={"X-Request-Id": "req-no-timeout"})
        assert missing_timeout.status_code == 400

        resp = client.post("/v1/source-code-kg/ingest", json=_payload(), headers=_HEADERS)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["schemaVersion"] == "s5-source-code-kg-ingest-result-v1"
        assert body["ledgerOnly"] is True
        assert body["productionWrites"] == {"neo4j": False, "qdrant": False}
        assert repo.count_rows("source_graph_node") == 2
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_api_validation_errors_use_s5_error_envelope(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        invalid = _payload()
        invalid["repositorySnapshot"].pop("commitHash")
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=invalid,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-invalid-source-kg"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "INVALID_INPUT"
        assert body["errorDetail"]["requestId"] == "req-invalid-source-kg"
        assert body["errorDetail"]["retryable"] is False
    finally:
        source_kg_api.set_ledger_repository(old)
