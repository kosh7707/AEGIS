from __future__ import annotations

import hashlib
import json
import time

import pytest
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
                "checksumSha256": "sha256:" + "a" * 64,
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
                "checksumSha256": "sha256:" + "b" * 64,
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


def test_source_code_kg_edges_can_reference_stable_ids_when_node_ids_are_generated(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    for node in payload["graphNodes"]:
        node.pop("sourceGraphNodeId", None)
    payload["graphEdges"] = [
        {
            "edgeKind": "calls",
            "sourceStableId": "func:ssl3_read_bytes",
            "targetStableId": "func:tls1_process_heartbeat",
            "evidence": {"pathKind": "call"},
        }
    ]

    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        graph_node_ids=result["ids"]["sourceGraphNodeIds"],
    )
    assert context["resolved"] is True
    assert context["graphEdges"][0]["sourceGraphNodeId"] in result["ids"]["sourceGraphNodeIds"]
    assert context["graphEdges"][0]["targetGraphNodeId"] in result["ids"]["sourceGraphNodeIds"]


def test_source_kg_context_limits_edges_to_explicit_graph_node_subgraph(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["graphNodes"][0]["sourceGraphNodeId"] = "node-ssl3-read"
    payload["graphNodes"][1]["sourceGraphNodeId"] = "node-heartbeat"
    payload["graphNodes"].extend(
        [
            {
                "sourceGraphNodeId": "node-unrelated-source",
                "nodeKind": "function",
                "stableId": "func:unrelated_source",
                "displayName": "unrelated_source",
                "filePath": "ssl/unrelated.c",
                "lineStart": 10,
                "lineEnd": 20,
                "metadata": {"component": "openssl"},
            },
            {
                "sourceGraphNodeId": "node-unrelated-target",
                "nodeKind": "function",
                "stableId": "func:unrelated_target",
                "displayName": "unrelated_target",
                "filePath": "ssl/unrelated.c",
                "lineStart": 30,
                "lineEnd": 40,
                "metadata": {"component": "openssl"},
            },
        ]
    )
    payload["graphEdges"].append(
        {
            "sourceGraphEdgeId": "edge-unrelated",
            "edgeKind": "calls",
            "sourceGraphNodeId": "node-unrelated-source",
            "targetGraphNodeId": "node-unrelated-target",
            "evidence": {"pathKind": "call"},
            "metadata": {"confidence": 1.0},
        }
    )
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        graph_node_ids=["node-ssl3-read", "node-heartbeat"],
    )

    assert {node["sourceGraphNodeId"] for node in context["graphNodes"]} == {"node-ssl3-read", "node-heartbeat"}
    assert [edge["sourceGraphEdgeId"] for edge in context["graphEdges"]] == [
        result["ids"]["sourceGraphEdgeIds"][0]
    ]
    assert all(
        edge["sourceGraphNodeId"] in {"node-ssl3-read", "node-heartbeat"}
        and edge["targetGraphNodeId"] in {"node-ssl3-read", "node-heartbeat"}
        for edge in context["graphEdges"]
    )


def test_source_kg_context_truncates_dense_explicit_graph_node_induced_edges(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["evidenceSnippets"] = []
    payload["graphNodes"] = [
        {
            "sourceGraphNodeId": f"node-{index:02d}",
            "nodeKind": "function",
            "stableId": f"func:dense_{index:02d}",
            "displayName": f"dense_{index:02d}",
            "filePath": "ssl/dense.c",
            "lineStart": index + 1,
            "lineEnd": index + 1,
        }
        for index in range(20)
    ]
    payload["graphEdges"] = [
        {
            "sourceGraphEdgeId": f"edge-{source_index:02d}-{target_index:02d}",
            "edgeKind": "calls",
            "sourceGraphNodeId": f"node-{source_index:02d}",
            "targetGraphNodeId": f"node-{target_index:02d}",
            "evidence": {"pathKind": "dense_call"},
        }
        for source_index in range(20)
        for target_index in range(20)
        if source_index != target_index
    ]
    payload["richIrArtifacts"] = []
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        graph_node_ids=result["ids"]["sourceGraphNodeIds"],
    )

    assert len(context["graphEdges"]) == 128
    assert context["contextResolution"]["complete"] is False
    assert any(
        diagnostic["code"] == "SOURCE_KG_CONTEXT_TRUNCATED"
        and diagnostic["field"] == "graphEdges"
        and diagnostic["totalCount"] == 380
        and diagnostic["returnedCount"] == 128
        for diagnostic in context["contextResolution"]["diagnostics"]
    )


def test_source_kg_context_preserves_explicit_collection_request_order(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["evidenceSnippets"].append(
        {
            "evidenceSnippetId": "snippet-ssl3-read",
            "filePath": "ssl/s3_pkt.c",
            "lineStart": 1201,
            "lineEnd": 1205,
            "language": "c",
            "snippetText": "ssl3_read_bytes(s);",
            "provenance": {"finding": "caller fixture"},
        }
    )
    payload["graphNodes"][0]["sourceGraphNodeId"] = "node-ssl3-read"
    payload["graphNodes"][0]["evidenceSnippetId"] = "snippet-ssl3-read"
    payload["graphNodes"][1]["sourceGraphNodeId"] = "node-heartbeat"
    payload["richIrArtifacts"].append(
        {
            "richIrArtifactId": "rich-ir-callgraph",
            "artifactKind": "callgraph",
            "mediaType": "application/json",
            "checksumSha256": "sha256:" + "c" * 64,
            "payload": {"edges": [["ssl3_read_bytes", "tls1_process_heartbeat"]]},
            "provenance": {"producerLane": "S4"},
        }
    )
    payload["richIrArtifacts"][0]["richIrArtifactId"] = "rich-ir-taint"
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    requested_nodes = ["node-ssl3-read", "node-heartbeat"]
    requested_snippets = ["snippet-ssl3-read", "snippet-heartbeat-read"]
    requested_rich_ir = ["rich-ir-taint", "rich-ir-callgraph"]

    context = repo.get_source_kg_context(
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        graph_node_ids=requested_nodes,
        evidence_snippet_ids=requested_snippets,
        rich_ir_artifact_ids=requested_rich_ir,
    )

    assert [item["sourceGraphNodeId"] for item in context["graphNodes"]] == requested_nodes
    assert [item["evidenceSnippetId"] for item in context["evidenceSnippets"]] == requested_snippets
    assert [item["richIrArtifactId"] for item in context["richIrArtifacts"]] == requested_rich_ir
    assert context["contextResolution"]["graphNodes"]["resolvedIds"] == requested_nodes
    assert context["contextResolution"]["evidenceSnippets"]["resolvedIds"] == requested_snippets
    assert context["contextResolution"]["richIrArtifacts"]["resolvedIds"] == requested_rich_ir


def test_source_kg_context_reports_partial_requested_id_resolution(tmp_path):
    repo = _repo(tmp_path)
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_payload())).model_dump(by_alias=True)
    known_node_id = result["ids"]["sourceGraphNodeIds"][0]
    leaky_missing_node = "https://node_user:node_password@ids.example/missing-node?token=node-secret"
    leaky_missing_snippet = "https://snippet_user:snippet_password@ids.example/missing-snippet?token=snippet-secret"
    leaky_missing_rich_ir = "https://ir_user:ir_password@ids.example/missing-ir?token=ir-secret"

    context = repo.get_source_kg_context(
        repository_snapshot_id=result["repositorySnapshotId"],
        build_context_id=result["buildContextId"],
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        graph_node_ids=[known_node_id, leaky_missing_node],
        evidence_snippet_ids=[leaky_missing_snippet],
        rich_ir_artifact_ids=[leaky_missing_rich_ir],
    )

    resolution = context["contextResolution"]
    assert context["resolved"] is True
    assert resolution["complete"] is False
    assert resolution["partial"] is True
    assert resolution["graphNodes"]["requestedIds"] == [
        known_node_id,
        "https://***:***@ids.example/missing-node?token=***",
    ]
    assert resolution["graphNodes"]["resolvedIds"] == [known_node_id]
    assert resolution["graphNodes"]["missingIds"] == [
        "https://***:***@ids.example/missing-node?token=***"
    ]
    assert resolution["evidenceSnippets"]["missingIds"] == [
        "https://***:***@ids.example/missing-snippet?token=***"
    ]
    assert resolution["richIrArtifacts"]["missingIds"] == [
        "https://***:***@ids.example/missing-ir?token=***"
    ]
    assert {item["code"] for item in resolution["diagnostics"]} == {"SOURCE_KG_CONTEXT_PARTIAL"}
    assert "node_user" not in str(resolution)
    assert "node_password" not in str(resolution)
    assert "node-secret" not in str(resolution)
    assert "snippet_user" not in str(resolution)
    assert "snippet_password" not in str(resolution)
    assert "snippet-secret" not in str(resolution)
    assert "ir_user" not in str(resolution)
    assert "ir_password" not in str(resolution)
    assert "ir-secret" not in str(resolution)


def test_source_kg_context_caps_whole_analysis_collections_with_truncation_diagnostics(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["graphNodes"] = [
        {
            "sourceGraphNodeId": f"node-bulk-{index:03d}",
            "nodeKind": "function",
            "stableId": f"func:bulk_{index:03d}",
            "displayName": f"bulk_{index:03d}",
            "filePath": "ssl/bulk.c",
            "lineStart": index + 1,
            "lineEnd": index + 2,
            "metadata": {"component": "openssl"},
        }
        for index in range(65)
    ]
    payload["graphEdges"] = []
    payload["richIrArtifacts"] = [
        {
            "richIrArtifactId": f"rich-ir-bulk-{index:03d}",
            "artifactKind": "ast_fragment",
            "mediaType": "application/json",
            "checksumSha256": "sha256:" + f"{index:064x}"[-64:],
            "payload": {"index": index},
            "provenance": {"producerLane": "S4"},
        }
        for index in range(33)
    ]
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(analysis_artifact_set_id=result["analysisArtifactSetId"])

    assert len(context["graphNodes"]) == 64
    assert len(context["richIrArtifacts"]) == 32
    assert context["contextResolution"]["complete"] is False
    assert context["contextResolution"]["partial"] is True
    truncations = [
        item
        for item in context["contextResolution"]["diagnostics"]
        if item["code"] == "SOURCE_KG_CONTEXT_TRUNCATED"
    ]
    assert {item["field"] for item in truncations} >= {"graphNodes", "richIrArtifacts"}
    assert next(item for item in truncations if item["field"] == "graphNodes")["totalCount"] == 65
    assert next(item for item in truncations if item["field"] == "richIrArtifacts")["totalCount"] == 33


def test_source_kg_context_flags_collection_ids_outside_requested_lineage(tmp_path):
    repo = _repo(tmp_path)
    first = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_payload())).model_dump(by_alias=True)
    changed = _payload()
    changed["repositorySnapshot"]["commitHash"] = "fedcba0987654321"
    changed["repositorySnapshot"]["treeHash"] = "tree-2222"
    changed["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-second"
    changed["graphNodes"][1]["evidenceSnippetId"] = "snippet-second"
    second = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(changed)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        repository_snapshot_id=first["repositorySnapshotId"],
        build_context_id=first["buildContextId"],
        analysis_artifact_set_id=first["analysisArtifactSetId"],
        graph_node_ids=second["ids"]["sourceGraphNodeIds"],
        evidence_snippet_ids=second["ids"]["evidenceSnippetIds"],
        rich_ir_artifact_ids=second["ids"]["richIrArtifactIds"],
    )

    diagnostics = context["contextResolution"]["diagnostics"]
    assert context["resolved"] is True
    assert context["contextResolution"]["complete"] is False
    assert context["contextResolution"]["partial"] is True
    inconsistent = [item for item in diagnostics if item["code"] == "SOURCE_KG_CONTEXT_INCONSISTENT"]
    assert {item["field"] for item in inconsistent} >= {"graphNodeIds", "evidenceSnippetIds", "richIrArtifactIds"}
    node_diag = next(item for item in inconsistent if item["field"] == "graphNodeIds")
    assert node_diag["requestedContainerId"] == first["analysisArtifactSetId"]
    assert node_diag["outOfLineageIds"] == second["ids"]["sourceGraphNodeIds"]
    snippet_diag = next(item for item in inconsistent if item["field"] == "evidenceSnippetIds")
    assert snippet_diag["requestedContainerId"] == first["repositorySnapshotId"]
    assert snippet_diag["outOfLineageIds"] == second["ids"]["evidenceSnippetIds"]
    rich_diag = next(item for item in inconsistent if item["field"] == "richIrArtifactIds")
    assert rich_diag["requestedContainerId"] == first["analysisArtifactSetId"]
    assert rich_diag["outOfLineageIds"] == second["ids"]["richIrArtifactIds"]
    assert context["graphNodes"] == []
    assert context["evidenceSnippets"] == []
    assert context["richIrArtifacts"] == []
    assert context["contextResolution"]["graphNodes"]["missingIds"] == second["ids"]["sourceGraphNodeIds"]
    assert context["contextResolution"]["evidenceSnippets"]["missingIds"] == second["ids"]["evidenceSnippetIds"]
    assert context["contextResolution"]["richIrArtifacts"]["missingIds"] == second["ids"]["richIrArtifactIds"]


def test_source_kg_context_redacts_explicit_rows_when_requested_container_is_missing(tmp_path):
    repo = _repo(tmp_path)
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_payload())).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        repository_snapshot_id="missing-repository",
        analysis_artifact_set_id="missing-analysis",
        graph_node_ids=result["ids"]["sourceGraphNodeIds"],
        evidence_snippet_ids=result["ids"]["evidenceSnippetIds"],
        rich_ir_artifact_ids=result["ids"]["richIrArtifactIds"],
    )

    diagnostics = context["contextResolution"]["diagnostics"]
    assert context["graphNodes"] == []
    assert context["evidenceSnippets"] == []
    assert context["richIrArtifacts"] == []
    assert context["contextResolution"]["graphNodes"]["missingIds"] == result["ids"]["sourceGraphNodeIds"]
    assert context["contextResolution"]["evidenceSnippets"]["missingIds"] == result["ids"]["evidenceSnippetIds"]
    assert context["contextResolution"]["richIrArtifacts"]["missingIds"] == result["ids"]["richIrArtifactIds"]
    assert {item["field"] for item in diagnostics if item["code"] == "SOURCE_KG_CONTEXT_INCONSISTENT"} >= {
        "graphNodeIds",
        "evidenceSnippetIds",
        "richIrArtifactIds",
    }
    assert context["contextResolution"]["complete"] is False


def test_source_kg_context_truncates_large_rich_ir_payloads(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["richIrArtifacts"][0]["payload"] = {"largeIr": "x" * 5000}
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        rich_ir_artifact_ids=result["ids"]["richIrArtifactIds"],
    )

    rich_ir = context["richIrArtifacts"][0]
    assert rich_ir["richIrArtifactId"] == result["ids"]["richIrArtifactIds"][0]
    assert rich_ir["payload"] is None
    assert rich_ir["payloadTruncated"] is True
    assert rich_ir["payloadRedacted"] is True
    assert rich_ir["payloadByteLength"] > rich_ir["payloadMaxInlineBytes"]
    assert "x" * 100 not in str(rich_ir)


def test_source_kg_context_truncates_large_evidence_snippet_text(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["evidenceSnippets"][0]["snippetText"] = "void f() {\n" + ("x" * 5000) + "\nsecret_tail();\n}"
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        repository_snapshot_id=result["repositorySnapshotId"],
        evidence_snippet_ids=result["ids"]["evidenceSnippetIds"],
    )

    snippet = context["evidenceSnippets"][0]
    assert snippet["evidenceSnippetId"] == result["ids"]["evidenceSnippetIds"][0]
    assert snippet["snippetTextTruncated"] is True
    assert snippet["snippetTextByteLength"] > snippet["snippetTextMaxInlineBytes"]
    assert len(snippet["snippetText"].encode("utf-8")) <= snippet["snippetTextMaxInlineBytes"]
    assert "secret_tail" not in snippet["snippetText"]


@pytest.mark.parametrize(
    ("field_path", "context_path", "field_name"),
    [
        (("repositorySnapshot", "submoduleHashes"), ("repositorySnapshot",), "submoduleHashes"),
        (("repositorySnapshot", "metadata"), ("repositorySnapshot",), "metadata"),
        (("repositorySnapshot", "provenance"), ("repositorySnapshot",), "provenance"),
        (("buildContext", "toolchain"), ("buildContext",), "toolchain"),
        (("buildContext", "dependencyGraph"), ("buildContext",), "dependencyGraph"),
        (("buildContext", "buildMetadata"), ("buildContext",), "buildMetadata"),
        (("buildContext", "provenance"), ("buildContext",), "provenance"),
        (("analysisArtifactSet", "analysisConfig"), ("analysisArtifactSet",), "analysisConfig"),
        (("analysisArtifactSet", "artifactHashes"), ("analysisArtifactSet",), "artifactHashes"),
        (("analysisArtifactSet", "provenance"), ("analysisArtifactSet",), "provenance"),
        (("graphNodes", 0, "symbol"), ("graphNodes", 0), "symbol"),
        (("graphNodes", 0, "metadata"), ("graphNodes", 0), "metadata"),
        (("graphEdges", 0, "evidence"), ("graphEdges", 0), "evidence"),
        (("graphEdges", 0, "metadata"), ("graphEdges", 0), "metadata"),
        (("evidenceSnippets", 0, "provenance"), ("evidenceSnippets", 0), "provenance"),
        (("richIrArtifacts", 0, "provenance"), ("richIrArtifacts", 0), "provenance"),
    ],
)
def test_source_kg_context_redacts_large_nested_objects_from_serving_projection(
    tmp_path, field_path, context_path, field_name
):
    repo = _repo(tmp_path)
    secret = "secret-serving-nested-" + ("x" * 5000)
    payload = _payload()
    target = payload
    for part in field_path[:-1]:
        target = target[part]
    target[field_path[-1]] = {"large": secret}
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        repository_snapshot_id=result["repositorySnapshotId"],
        build_context_id=result["buildContextId"],
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        graph_node_ids=result["ids"]["sourceGraphNodeIds"],
        evidence_snippet_ids=result["ids"]["evidenceSnippetIds"],
        rich_ir_artifact_ids=result["ids"]["richIrArtifactIds"],
    )

    record = context
    for part in context_path:
        record = record[part]
    assert record[field_name] is None
    assert record[f"{field_name}Truncated"] is True
    assert record[f"{field_name}Redacted"] is True
    assert record[f"{field_name}ByteLength"] > record[f"{field_name}MaxInlineBytes"]
    assert secret not in str(context)
    diagnostics = context["contextResolution"]["diagnostics"]
    assert context["contextResolution"]["complete"] is False
    assert context["contextResolution"]["partial"] is True
    assert any(
        item["code"] == "SOURCE_KG_CONTEXT_REDACTED"
        and item["field"] == ".".join(str(part) for part in (*context_path, field_name))
        for item in diagnostics
    )


def test_source_kg_context_nested_url_redaction_preserves_raw_byte_budget(tmp_path):
    repo = _repo(tmp_path)
    raw_secret = "raw-secret-token-" + ("x" * 5000)
    credential_url = (
        "https://nested_user:nested_password@metadata.example.com/context.json"
        f"?api_key={raw_secret}&keep=1"
    )
    payload = _payload()
    payload["graphNodes"][0]["metadata"] = {"debugUrl": credential_url}
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        graph_node_ids=result["ids"]["sourceGraphNodeIds"][:1],
    )

    node = context["graphNodes"][0]
    assert node["metadata"] is None
    assert node["metadataByteLength"] > node["metadataMaxInlineBytes"]
    assert node["metadataTruncated"] is True
    assert node["metadataRedacted"] is True
    assert raw_secret not in json.dumps(context, ensure_ascii=False)
    assert context["contextResolution"]["complete"] is False
    assert context["contextResolution"]["partial"] is True
    assert any(
        item["code"] == "SOURCE_KG_CONTEXT_REDACTED"
        and item["field"] == "graphNodes.0.metadata"
        for item in context["contextResolution"]["diagnostics"]
    )


def test_source_kg_context_bounds_projection_redaction_diagnostics(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["evidenceSnippets"] = []
    payload["graphEdges"] = []
    payload["richIrArtifacts"] = []
    payload["graphNodes"] = [
        {
            "nodeKind": "function",
            "stableId": f"func:redacted_diagnostic_{index}",
            "metadata": {"large": "x" * 5000},
        }
        for index in range(80)
    ]
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        analysis_artifact_set_id=result["analysisArtifactSetId"],
        graph_node_ids=result["ids"]["sourceGraphNodeIds"],
    )

    diagnostics = context["contextResolution"]["diagnostics"]
    redaction_diagnostics = [
        item for item in diagnostics if item["code"] == "SOURCE_KG_CONTEXT_REDACTED"
    ]
    assert len(redaction_diagnostics) == 64
    truncation = next(
        item for item in diagnostics if item["code"] == "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED"
    )
    assert truncation["field"] == "projectionDiagnostics"
    assert truncation["totalCount"] == 80
    assert truncation["returnedCount"] == 64
    assert truncation["maxCount"] == 64
    assert context["contextResolution"]["complete"] is False
    assert context["contextResolution"]["partial"] is True


def test_source_kg_context_reports_inconsistent_repository_build_analysis_selectors(tmp_path):
    repo = _repo(tmp_path)
    first = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_payload())).model_dump(by_alias=True)
    changed = _payload()
    changed["repositorySnapshot"]["commitHash"] = "fedcba0987654321"
    changed["repositorySnapshot"]["treeHash"] = "tree-2222"
    changed["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-second"
    changed["graphNodes"][1]["evidenceSnippetId"] = "snippet-second"
    second = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(changed)).model_dump(by_alias=True)

    context = repo.get_source_kg_context(
        repository_snapshot_id=first["repositorySnapshotId"],
        analysis_artifact_set_id=second["analysisArtifactSetId"],
    )

    diagnostics = context["contextResolution"]["diagnostics"]
    assert context["resolved"] is True
    assert context["contextResolution"]["complete"] is False
    assert context["contextResolution"]["partial"] is True
    assert any(item["code"] == "SOURCE_KG_CONTEXT_INCONSISTENT" for item in diagnostics)
    inconsistency = next(item for item in diagnostics if item["code"] == "SOURCE_KG_CONTEXT_INCONSISTENT")
    assert inconsistency["field"] == "repositorySnapshotId"
    assert inconsistency["requestedId"] == first["repositorySnapshotId"]
    assert inconsistency["linkedId"] == second["repositorySnapshotId"]


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
        assert missing_timeout.json()["errorDetail"]["reason"] == "timeout_header_missing_or_invalid"

        resp = client.post("/v1/source-code-kg/ingest", json=_payload(), headers=_HEADERS)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["schemaVersion"] == "s5-source-code-kg-ingest-result-v1"
        assert body["ledgerOnly"] is True
        assert body["productionWrites"] == {"neo4j": False, "qdrant": False}
        assert repo.count_rows("source_graph_node") == 2
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_api_error_taxonomy_covers_uninitialized_ledger_and_deadline(tmp_path, monkeypatch):
    old = source_kg_api._ledger_repository
    try:
        source_kg_api.set_ledger_repository(None)
        uninitialized = client.post(
            "/v1/source-code-kg/ingest",
            json=_payload(),
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-no-ledger"},
        )
        assert uninitialized.status_code == 503
        assert uninitialized.json()["errorDetail"]["reason"] == "ledger_not_initialized"

        repo = _repo(tmp_path)
        source_kg_api.set_ledger_repository(repo)

        def _slow_ingest(*args, **kwargs):
            time.sleep(0.05)
            return {}

        monkeypatch.setattr(source_kg_api, "_ingest_sync", _slow_ingest)
        deadline = client.post(
            "/v1/source-code-kg/ingest",
            json=_payload(),
            headers={"X-Timeout-Ms": "1", "X-Request-Id": "req-source-kg-ingest-timeout"},
        )
        assert deadline.status_code == 408
        assert deadline.json()["errorDetail"]["reason"] == "deadline_exceeded_before_ledger_ingest_completed"
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_timeout_does_not_write_after_408(tmp_path, monkeypatch):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)

    def _slow_writing_ingest(repo_arg, req):
        time.sleep(0.05)
        return ingest_source_kg(repo_arg, req).model_dump(by_alias=True)

    monkeypatch.setattr(source_kg_api, "_ingest_sync", _slow_writing_ingest)
    try:
        deadline = client.post(
            "/v1/source-code-kg/ingest",
            json=_payload(),
            headers={"X-Timeout-Ms": "1", "X-Request-Id": "req-source-kg-ingest-timeout-no-write"},
        )
        time.sleep(0.1)

        assert deadline.status_code == 408
        assert deadline.json()["errorDetail"]["reason"] == "deadline_exceeded_before_ledger_ingest_completed"
        assert repo.count_rows("source_repository_snapshot") == 0
        assert repo.count_rows("source_graph_node") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_started_write_is_not_reported_as_timeout_with_late_side_effect(tmp_path, monkeypatch):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)

    def _slow_started_ingest(repo_arg, req):
        time.sleep(0.05)
        return ingest_source_kg(repo_arg, req).model_dump(by_alias=True)

    monkeypatch.setattr(source_kg_api, "_ingest_sync", _slow_started_ingest)
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=_payload(),
            headers={"X-Timeout-Ms": "20", "X-Request-Id": "req-source-kg-ingest-started-write"},
        )
        time.sleep(0.1)

        assert resp.status_code == 200, resp.text
        assert resp.json()["schemaVersion"] == "s5-source-code-kg-ingest-result-v1"
        assert repo.count_rows("source_repository_snapshot") == 1
        assert repo.count_rows("source_graph_node") == 2
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_context_api_resolves_ids_and_reports_partial(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        missing_timeout = client.post(
            "/v1/source-code-kg/context",
            json={"schemaVersion": "s5-source-code-kg-context-request-v1", "graphNodeIds": ["missing-node"]},
            headers={"X-Request-Id": "req-source-kg-context-no-timeout"},
        )
        assert missing_timeout.status_code == 400
        assert missing_timeout.json()["errorDetail"]["reason"] == "timeout_header_missing_or_invalid"

        ingest_resp = client.post("/v1/source-code-kg/ingest", json=_payload(), headers=_HEADERS)
        assert ingest_resp.status_code == 200, ingest_resp.text
        ingest_body = ingest_resp.json()
        known_node_id = ingest_body["ids"]["sourceGraphNodeIds"][0]
        known_snippet_id = ingest_body["ids"]["evidenceSnippetIds"][0]
        leaky_missing_node = "https://node_user:node_password@ids.example/missing-node?token=node-secret"
        leaky_missing_snippet = "https://snippet_user:snippet_password@ids.example/missing-snippet?token=snippet-secret"
        leaky_missing_rich_ir = "https://ir_user:ir_password@ids.example/missing-ir?token=ir-secret"

        resp = client.post(
            "/v1/source-code-kg/context",
            json={
                "schemaVersion": "s5-source-code-kg-context-request-v1",
                "repositorySnapshotId": ingest_body["repositorySnapshotId"],
                "buildContextId": ingest_body["buildContextId"],
                "analysisArtifactSetId": ingest_body["analysisArtifactSetId"],
                "graphNodeIds": [known_node_id, leaky_missing_node],
                "evidenceSnippetIds": [known_snippet_id, leaky_missing_snippet],
                "richIrArtifactIds": [leaky_missing_rich_ir],
            },
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-context"},
        )

        assert resp.status_code == 200, resp.text
        assert resp.headers["X-Request-Id"] == "req-source-kg-context"
        body = resp.json()
        assert body["schemaVersion"] == "s5-source-code-kg-context-result-v1"
        assert body["resolved"] is True
        assert body["repositorySnapshot"]["commitHash"] == "abcdef1234567890"
        assert body["contextResolution"]["partial"] is True
        assert body["contextResolution"]["graphNodes"]["missingIds"] == [
            "https://***:***@ids.example/missing-node?token=***"
        ]
        assert body["contextResolution"]["evidenceSnippets"]["missingIds"] == [
            "https://***:***@ids.example/missing-snippet?token=***"
        ]
        assert body["contextResolution"]["richIrArtifacts"]["missingIds"] == [
            "https://***:***@ids.example/missing-ir?token=***"
        ]
        assert "node_user" not in str(body)
        assert "snippet_user" not in str(body)
        assert "ir_user" not in str(body)
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_kg_context_redacts_credential_bearing_repository_and_artifact_urls(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    repository_url = "https://repo_user:repo_password@git.example.com/aegis.git?access_token=repo-token&ref=main"
    rich_ir_uri = "https://artifact_user:artifact_password@artifacts.example.com/taint.json?api_key=artifact-secret&download=1"
    payload = _payload()
    payload["repositorySnapshot"]["repositoryUrl"] = repository_url
    payload["richIrArtifacts"][0]["uri"] = rich_ir_uri
    try:
        ingest_resp = client.post("/v1/source-code-kg/ingest", json=payload, headers=_HEADERS)
        assert ingest_resp.status_code == 200, ingest_resp.text
        ingest_body = ingest_resp.json()

        resp = client.post(
            "/v1/source-code-kg/context",
            json={
                "schemaVersion": "s5-source-code-kg-context-request-v1",
                "repositorySnapshotId": ingest_body["repositorySnapshotId"],
                "richIrArtifactIds": ingest_body["ids"]["richIrArtifactIds"],
            },
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-redacted-urls"},
        )

        assert resp.status_code == 200, resp.text
        body_text = resp.text
        body = resp.json()
        assert body["repositorySnapshot"]["repositoryUrl"] == (
            "https://***:***@git.example.com/aegis.git?access_token=***&ref=main"
        )
        assert body["richIrArtifacts"][0]["uri"] == (
            "https://***:***@artifacts.example.com/taint.json?api_key=***&download=1"
        )
        for secret in ["repo_user", "repo_password", "repo-token", "artifact_user", "artifact_password", "artifact-secret"]:
            assert secret not in body_text
        assert repo.fetch_all("source_repository_snapshot")[0]["repository_url"] == repository_url
        assert repo.fetch_all("source_rich_ir_artifact")[0]["uri"] == rich_ir_uri
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_kg_context_redacts_credential_bearing_urls_inside_nested_objects(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    nested_url = "https://nested_user:nested_password@metadata.example.com/context.json?api_key=nested-secret&keep=1"
    key_url = "https://key_user:key_password@metadata.example.com/key?token=key-secret"
    payload = _payload()
    payload["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-nested-url"
    payload["sourceArtifacts"][0]["metadata"] = {
        "mirror": nested_url,
        key_url: "keyed-secret-url",
    }
    payload["buildContext"]["compileCommandsArtifactId"] = "artifact-nested-url"
    payload["graphNodes"][0]["metadata"] = {"debugUrl": nested_url}
    try:
        ingest_resp = client.post("/v1/source-code-kg/ingest", json=payload, headers=_HEADERS)
        assert ingest_resp.status_code == 200, ingest_resp.text
        ingest_body = ingest_resp.json()

        resp = client.post(
            "/v1/source-code-kg/context",
            json={
                "schemaVersion": "s5-source-code-kg-context-request-v1",
                "buildContextId": ingest_body["buildContextId"],
                "graphNodeIds": ingest_body["ids"]["sourceGraphNodeIds"][:1],
            },
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-nested-url-redaction"},
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        body_text = resp.text
        artifact_metadata = body["sourceArtifacts"][0]["metadata"]
        node_metadata = body["graphNodes"][0]["metadata"]
        assert artifact_metadata["mirror"] == (
            "https://***:***@metadata.example.com/context.json?api_key=***&keep=1"
        )
        assert "https://***:***@metadata.example.com/key?token=***" in artifact_metadata
        assert node_metadata["debugUrl"] == (
            "https://***:***@metadata.example.com/context.json?api_key=***&keep=1"
        )
        for secret in [
            "nested_user",
            "nested_password",
            "nested-secret",
            "key_user",
            "key_password",
            "key-secret",
        ]:
            assert secret not in body_text
        assert nested_url in repo.fetch_all("source_repository_artifact")[0]["metadata_json"]
        assert key_url in repo.fetch_all("source_repository_artifact")[0]["metadata_json"]
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_kg_context_api_includes_compile_commands_source_artifact_with_redacted_uri(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    artifact_uri = "https://artifact_user:artifact_password@artifacts.example.com/compile_commands.json?api_key=artifact-secret"
    payload = _payload()
    payload["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-compile-commands"
    payload["sourceArtifacts"][0]["artifactUri"] = artifact_uri
    payload["sourceArtifacts"][0]["mediaType"] = "application/json"
    payload["buildContext"]["compileCommandsArtifactId"] = "artifact-compile-commands"
    try:
        ingest_resp = client.post("/v1/source-code-kg/ingest", json=payload, headers=_HEADERS)
        assert ingest_resp.status_code == 200, ingest_resp.text
        ingest_body = ingest_resp.json()

        resp = client.post(
            "/v1/source-code-kg/context",
            json={
                "schemaVersion": "s5-source-code-kg-context-request-v1",
                "buildContextId": ingest_body["buildContextId"],
            },
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-compile-artifact-context"},
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        artifact = body["sourceArtifacts"][0]
        assert artifact["sourceRepositoryArtifactId"] == "artifact-compile-commands"
        assert artifact["artifactUri"] == (
            "https://***:***@artifacts.example.com/compile_commands.json?api_key=***"
        )
        assert artifact["checksumSha256"] == payload["sourceArtifacts"][0]["checksumSha256"]
        assert body["buildContext"]["compileCommandsArtifactId"] == "artifact-compile-commands"
        assert body["contextResolution"]["sourceArtifacts"] == {
            "requestedIds": ["artifact-compile-commands"],
            "resolvedIds": ["artifact-compile-commands"],
            "missingIds": [],
        }
        assert "artifact_user" not in resp.text
        assert "artifact_password" not in resp.text
        assert "artifact-secret" not in resp.text
        assert repo.fetch_all("source_repository_artifact")[0]["artifact_uri"] == artifact_uri
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_context_api_error_taxonomy_covers_uninitialized_ledger_and_deadline(tmp_path, monkeypatch):
    old = source_kg_api._ledger_repository
    request = {"schemaVersion": "s5-source-code-kg-context-request-v1", "graphNodeIds": ["missing-node"]}
    try:
        source_kg_api.set_ledger_repository(None)
        uninitialized = client.post(
            "/v1/source-code-kg/context",
            json=request,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-context-no-ledger"},
        )
        assert uninitialized.status_code == 503
        assert uninitialized.json()["errorDetail"]["reason"] == "ledger_not_initialized"

        repo = _repo(tmp_path)
        source_kg_api.set_ledger_repository(repo)

        def _slow_context(*args, **kwargs):
            time.sleep(0.05)
            return {}

        monkeypatch.setattr(source_kg_api, "_context_sync", _slow_context)
        deadline = client.post(
            "/v1/source-code-kg/context",
            json=request,
            headers={"X-Timeout-Ms": "1", "X-Request-Id": "req-source-kg-context-timeout"},
        )
        assert deadline.status_code == 408
        assert deadline.json()["errorDetail"]["reason"] == "deadline_exceeded_before_context_resolution_completed"
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_context_api_rejects_over_limit_explicit_selectors(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        over_limit_requests = [
            {"graphNodeIds": [f"node-{index}" for index in range(257)]},
            {"evidenceSnippetIds": [f"snippet-{index}" for index in range(257)]},
            {"richIrArtifactIds": [f"rich-ir-{index}" for index in range(129)]},
        ]
        for request in over_limit_requests:
            resp = client.post(
                "/v1/source-code-kg/context",
                json={"schemaVersion": "s5-source-code-kg-context-request-v1", **request},
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-over-limit-selector"},
            )
            assert resp.status_code == 422
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "explicit_selector_limit_exceeded"
            assert body["errorDetail"]["requestId"] == "req-source-kg-over-limit-selector"
            assert "missingIds" not in body["error"]
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_context_api_rejects_oversized_selector_values_without_echo(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    oversized_id = "node-" + ("x" * 100_000)
    try:
        oversized_requests = [
            {"repositorySnapshotId": oversized_id},
            {"graphNodeIds": [oversized_id]},
        ]
        for request in oversized_requests:
            resp = client.post(
                "/v1/source-code-kg/context",
                json={"schemaVersion": "s5-source-code-kg-context-request-v1", **request},
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-oversized-selector"},
            )

            assert resp.status_code == 422
            body_text = resp.text
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "selector_value_too_long"
            assert len(body_text) < 4096
            assert oversized_id not in body_text
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_api_rejects_over_limit_collection_without_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    payload = _payload()
    payload["graphNodes"] = [
        {
            "sourceGraphNodeId": f"node-{index}",
            "nodeKind": "function",
            "stableId": f"func:{index}",
            "evidenceSnippetId": "snippet-1",
        }
        for index in range(8193)
    ]
    payload["graphEdges"] = []
    payload["richIrArtifacts"] = []
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-over-limit-ingest"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["reason"] == "ingest_collection_limit_exceeded"
        assert repo.count_rows("source_graph_node") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_api_rejects_oversized_values_without_echo_or_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    huge = "secret-tail-" + ("x" * 300_000)
    payloads = []
    snippet_payload = _payload()
    snippet_payload["evidenceSnippets"][0]["snippetText"] = huge
    payloads.append(snippet_payload)
    rich_ir_payload = _payload()
    rich_ir_payload["richIrArtifacts"][0]["payload"] = {"huge": huge}
    payloads.append(rich_ir_payload)
    try:
        for payload in payloads:
            resp = client.post(
                "/v1/source-code-kg/ingest",
                json=payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-oversized-ingest-value"},
            )

            assert resp.status_code == 422
            body_text = resp.text
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "ingest_value_too_large"
            assert len(body_text) < 4096
            assert huge not in body_text
            assert repo.count_rows("source_evidence_snippet") == 0
            assert repo.count_rows("source_rich_ir_artifact") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


@pytest.mark.parametrize(
    ("field_path", "request_id_suffix"),
    [
        (("repositorySnapshot", "submoduleHashes"), "repo-submodule-hashes"),
        (("repositorySnapshot", "metadata"), "repo-metadata"),
        (("repositorySnapshot", "provenance"), "repo-provenance"),
        (("sourceArtifacts", 0, "metadata"), "artifact-metadata"),
        (("sourceArtifacts", 0, "provenance"), "artifact-provenance"),
        (("buildContext", "toolchain"), "build-toolchain"),
        (("buildContext", "dependencyGraph"), "build-dependency-graph"),
        (("buildContext", "buildMetadata"), "build-metadata"),
        (("buildContext", "provenance"), "build-provenance"),
        (("analysisArtifactSet", "analysisConfig"), "analysis-config"),
        (("analysisArtifactSet", "artifactHashes"), "analysis-artifact-hashes"),
        (("analysisArtifactSet", "provenance"), "analysis-provenance"),
        (("evidenceSnippets", 0, "provenance"), "snippet-provenance"),
        (("graphNodes", 0, "symbol"), "node-symbol"),
        (("graphNodes", 0, "metadata"), "node-metadata"),
        (("graphEdges", 0, "evidence"), "edge-evidence"),
        (("graphEdges", 0, "metadata"), "edge-metadata"),
        (("richIrArtifacts", 0, "provenance"), "rich-ir-provenance"),
    ],
)
def test_source_code_kg_ingest_rejects_oversized_nested_objects_without_echo_or_ledger_write(
    tmp_path, field_path, request_id_suffix
):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    huge = "secret-nested-budget-" + ("x" * 300_000)
    payload = _payload()
    target = payload
    for part in field_path[:-1]:
        target = target[part]
    target[field_path[-1]] = {"huge": huge}
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-source-kg-oversized-{request_id_suffix}"},
        )

        assert resp.status_code == 422
        body_text = resp.text
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["reason"] == "ingest_value_too_large"
        assert len(body_text) < 4096
        assert huge not in body_text
        assert repo.count_rows("source_repository_snapshot") == 0
        assert repo.count_rows("source_repository_artifact") == 0
        assert repo.count_rows("source_build_context") == 0
        assert repo.count_rows("source_analysis_artifact_set") == 0
        assert repo.count_rows("source_evidence_snippet") == 0
        assert repo.count_rows("source_graph_node") == 0
        assert repo.count_rows("source_graph_edge") == 0
        assert repo.count_rows("source_rich_ir_artifact") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_aggregate_nested_object_budget_without_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    payload = _payload()
    near_limit = "secret-aggregate-budget-" + ("x" * 60_000)
    payload["graphNodes"].extend(
        {
            "nodeKind": "function",
            "stableId": f"func:aggregate_budget_{index}",
            "displayName": f"aggregate_budget_{index}",
            "filePath": f"src/aggregate_{index}.c",
            "lineStart": 1,
            "lineEnd": 2,
            "symbol": {"name": f"aggregate_budget_{index}"},
            "metadata": {"nearLimit": near_limit},
        }
        for index in range(20)
    )
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-aggregate-nested-budget"},
        )

        assert resp.status_code == 422
        body_text = resp.text
        body = resp.json()
        assert body["errorDetail"]["reason"] == "ingest_value_too_large"
        assert len(body_text) < 4096
        assert near_limit not in body_text
        assert repo.count_rows("source_repository_snapshot") == 0
        assert repo.count_rows("source_graph_node") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_oversized_reference_ids_without_echo_or_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    oversized_id = "secret-node-" + ("x" * 300_000)
    payload = _payload()
    payload["graphEdges"][0].pop("sourceStableId", None)
    payload["graphEdges"][0]["sourceGraphNodeId"] = oversized_id
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-oversized-reference-id"},
        )

        assert resp.status_code == 422
        body_text = resp.text
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["reason"] == "ingest_value_too_large"
        assert len(body_text) < 4096
        assert oversized_id not in body_text
        assert repo.count_rows("source_repository_snapshot") == 0
        assert repo.count_rows("source_graph_edge") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_mismatched_evidence_snippet_checksum_without_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    payload = _payload()
    payload["evidenceSnippets"][0]["checksumSha256"] = "sha256:" + hashlib.sha256(
        b"different snippet"
    ).hexdigest()
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-checksum-mismatch"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["errorDetail"]["reason"] == "source_kg_checksum_invalid"
        assert repo.count_rows("source_evidence_snippet") == 0
        assert repo.count_rows("source_repository_snapshot") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_non_sha256_checksum_format_without_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    payload = _payload()
    payload["sourceArtifacts"][0]["checksumSha256"] = "sha256:not-a-real-digest"
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-checksum-format"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["errorDetail"]["reason"] == "source_kg_checksum_invalid"
        assert repo.count_rows("source_repository_snapshot") == 0
        assert repo.count_rows("source_repository_artifact") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_invalid_line_spans_without_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    cases = []

    negative_snippet = _payload()
    negative_snippet["evidenceSnippets"][0]["lineStart"] = -1
    cases.append(("negative-snippet", negative_snippet))

    inverted_snippet = _payload()
    inverted_snippet["evidenceSnippets"][0]["lineStart"] = 20
    inverted_snippet["evidenceSnippets"][0]["lineEnd"] = 10
    cases.append(("inverted-snippet", inverted_snippet))

    negative_node = _payload()
    negative_node["graphNodes"][0]["lineStart"] = 0
    cases.append(("negative-node", negative_node))

    inverted_node = _payload()
    inverted_node["graphNodes"][0]["lineStart"] = 30
    inverted_node["graphNodes"][0]["lineEnd"] = 29
    cases.append(("inverted-node", inverted_node))

    try:
        for case_name, payload in cases:
            repo = _repo(tmp_path / case_name)
            source_kg_api.set_ledger_repository(repo)
            resp = client.post(
                "/v1/source-code-kg/ingest",
                json=payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-source-kg-invalid-span-{case_name}"},
            )

            assert resp.status_code == 422, resp.text
            body = resp.json()
            assert body["errorDetail"]["reason"] == "source_kg_line_span_invalid"
            assert repo.count_rows("source_repository_snapshot") == 0
            assert repo.count_rows("source_evidence_snippet") == 0
            assert repo.count_rows("source_graph_node") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_context_api_rejects_missing_context_selector(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        resp = client.post(
            "/v1/source-code-kg/context",
            json={"schemaVersion": "s5-source-code-kg-context-request-v1"},
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-context-no-selector"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "INVALID_INPUT"
        assert body["errorDetail"]["reason"] == "no_context_selector"
        assert body["errorDetail"]["requestId"] == "req-source-kg-context-no-selector"
        assert "at least one context identifier" in body["errorDetail"]["message"]
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
        assert body["errorDetail"]["reason"] == "request_schema_invalid"
        assert body["errorDetail"]["requestId"] == "req-invalid-source-kg"
        assert body["errorDetail"]["retryable"] is False
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_api_rejects_dangling_edge_with_s5_error_envelope(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        invalid = _payload()
        invalid["graphEdges"][0]["sourceStableId"] = "func:missing-source"
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=invalid,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-dangling-edge"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "INVALID_INPUT"
        assert body["errorDetail"]["reason"] == "graph_edge_references_unknown_node"
        assert body["errorDetail"]["requestId"] == "req-dangling-edge"
        assert "unknown source stable id: func:missing-source" in body["errorDetail"]["message"]
        assert repo.count_rows("source_graph_edge") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_api_rejects_dangling_node_evidence_snippet_with_s5_error_envelope(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        invalid = _payload()
        invalid["graphNodes"][1]["evidenceSnippetId"] = "missing-snippet"
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=invalid,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-dangling-snippet"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "INVALID_INPUT"
        assert body["errorDetail"]["reason"] == "graph_node_references_unknown_evidence_snippet"
        assert body["errorDetail"]["requestId"] == "req-dangling-snippet"
        assert "unknown evidence snippet id: missing-snippet" in body["errorDetail"]["message"]
        assert repo.count_rows("source_graph_node") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_explicit_node_id_reuse_across_analysis_sets(tmp_path):
    repo = _repo(tmp_path)
    first_payload = _payload()
    first_payload["evidenceSnippets"] = []
    first_payload["graphNodes"][1].pop("evidenceSnippetId", None)
    first_payload["graphNodes"][0]["sourceGraphNodeId"] = "node-reused"
    ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(first_payload))

    second_payload = _payload()
    second_payload["evidenceSnippets"] = []
    second_payload["graphNodes"][1].pop("evidenceSnippetId", None)
    second_payload["repositorySnapshot"]["commitHash"] = "fedcba0987654321"
    second_payload["repositorySnapshot"]["treeHash"] = "tree-2222"
    second_payload["graphNodes"][0]["sourceGraphNodeId"] = "node-reused"
    req = SourceCodeKgIngestRequest.model_validate(second_payload)

    try:
        ingest_source_kg(repo, req)
    except ValueError as exc:
        assert "source graph node id reused across analysis artifact sets: node-reused" in str(exc)
    else:  # pragma: no cover - explicit TDD guard
        raise AssertionError("cross-lineage Source KG node id reuse was accepted")


def test_source_code_kg_ingest_rejects_duplicate_graph_node_stable_ids_before_ledger_write(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["graphNodes"][1]["stableId"] = payload["graphNodes"][0]["stableId"]
    payload["graphEdges"] = []
    req = SourceCodeKgIngestRequest.model_validate(payload)

    try:
        ingest_source_kg(repo, req)
    except ValueError as exc:
        assert "duplicate source graph node stable id in request: func:ssl3_read_bytes" in str(exc)
    else:  # pragma: no cover - explicit TDD guard
        raise AssertionError("duplicate Source KG graph node stable id was accepted")

    assert repo.count_rows("source_graph_node") == 0


def test_source_code_kg_ingest_api_rejects_duplicate_explicit_graph_node_ids_before_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        payload = _payload()
        payload["graphNodes"][0]["sourceGraphNodeId"] = "node-duplicate"
        payload["graphNodes"][1]["sourceGraphNodeId"] = "node-duplicate"
        payload["graphEdges"] = []
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-duplicate-source-kg-node"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["reason"] == "duplicate_source_graph_node_identity"
        assert "duplicate source graph node id in request: node-duplicate" in body["errorDetail"]["message"]
        assert repo.count_rows("source_graph_node") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_api_rejects_unknown_compile_commands_artifact_without_partial_rows(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    try:
        payload = _payload()
        payload["buildContext"]["compileCommandsArtifactId"] = "missing-compile-commands-artifact"
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-missing-compile-artifact"},
        )

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["reason"] == "build_context_references_unknown_source_artifact"
        assert "unknown compile commands artifact id: missing-compile-commands-artifact" in body["errorDetail"]["message"]
        assert repo.count_rows("source_repository_snapshot") == 0
        assert repo.count_rows("source_repository_artifact") == 0
        assert repo.count_rows("source_build_context") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rolls_back_partial_rows_when_late_write_fails(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    req = SourceCodeKgIngestRequest.model_validate(_payload())

    def _fail_graph_node_write(*args, **kwargs):
        raise RuntimeError("late graph node write failed")

    monkeypatch.setattr(repo, "upsert_source_graph_node", _fail_graph_node_write)

    with pytest.raises(RuntimeError, match="late graph node write failed"):
        ingest_source_kg(repo, req)

    assert repo.count_rows("source_repository_snapshot") == 0
    assert repo.count_rows("source_repository_artifact") == 0
    assert repo.count_rows("source_build_context") == 0
    assert repo.count_rows("source_analysis_artifact_set") == 0
    assert repo.count_rows("source_evidence_snippet") == 0
    assert repo.count_rows("source_graph_node") == 0


def test_source_code_kg_ingest_api_rejects_duplicate_non_node_producer_ids_before_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    cases = []

    source_artifact_payload = _payload()
    source_artifact_payload["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-duplicate"
    duplicated_artifact = dict(source_artifact_payload["sourceArtifacts"][0])
    duplicated_artifact["artifactUri"] = "file:///fixtures/other-source.tar.zst"
    duplicated_artifact["checksumSha256"] = "sha256:" + "d" * 64
    source_artifact_payload["sourceArtifacts"].append(duplicated_artifact)
    cases.append(("source-artifact", source_artifact_payload, "duplicate source repository artifact id in request: artifact-duplicate"))

    snippet_payload = _payload()
    duplicated_snippet = dict(snippet_payload["evidenceSnippets"][0])
    duplicated_snippet["filePath"] = "ssl/other.c"
    duplicated_snippet["snippetText"] = "different snippet"
    snippet_payload["evidenceSnippets"].append(duplicated_snippet)
    cases.append(("evidence-snippet", snippet_payload, "duplicate evidence snippet id in request: snippet-heartbeat-read"))

    edge_payload = _payload()
    edge_payload["graphEdges"][0]["sourceGraphEdgeId"] = "edge-duplicate"
    duplicated_edge = dict(edge_payload["graphEdges"][0])
    duplicated_edge["metadata"] = {"confidence": 0.5}
    edge_payload["graphEdges"].append(duplicated_edge)
    cases.append(("graph-edge", edge_payload, "duplicate source graph edge id in request: edge-duplicate"))

    rich_ir_payload = _payload()
    rich_ir_payload["richIrArtifacts"][0]["richIrArtifactId"] = "rich-ir-duplicate"
    duplicated_rich_ir = dict(rich_ir_payload["richIrArtifacts"][0])
    duplicated_rich_ir["payload"] = {"source": "different"}
    rich_ir_payload["richIrArtifacts"].append(duplicated_rich_ir)
    cases.append(("rich-ir", rich_ir_payload, "duplicate rich IR artifact id in request: rich-ir-duplicate"))

    try:
        for case_name, payload, expected_message in cases:
            repo = _repo(tmp_path / case_name)
            source_kg_api.set_ledger_repository(repo)
            resp = client.post(
                "/v1/source-code-kg/ingest",
                json=payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-duplicate-source-kg-{case_name}"},
            )

            assert resp.status_code == 422, resp.text
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "duplicate_source_kg_identity"
            assert expected_message in body["errorDetail"]["message"]
            assert repo.count_rows("source_repository_snapshot") == 0
            assert repo.count_rows("source_repository_artifact") == 0
            assert repo.count_rows("source_evidence_snippet") == 0
            assert repo.count_rows("source_graph_edge") == 0
            assert repo.count_rows("source_rich_ir_artifact") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_duplicate_generated_non_node_identities_before_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    payload = _payload()
    payload["sourceArtifacts"].append(dict(payload["sourceArtifacts"][0]))
    try:
        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-duplicate-generated-source-kg"},
        )

        assert resp.status_code == 422, resp.text
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["reason"] == "duplicate_source_kg_identity"
        assert "duplicate generated source repository artifact id in request" in body["errorDetail"]["message"]
        assert repo.count_rows("source_repository_snapshot") == 0
        assert repo.count_rows("source_repository_artifact") == 0
        assert repo.count_rows("source_graph_edge") == 0
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_api_rejects_explicit_container_id_lineage_rebind_before_ledger_write(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)

    def _container_only_payload():
        payload = _payload()
        payload["evidenceSnippets"] = []
        payload["graphNodes"] = []
        payload["graphEdges"] = []
        payload["richIrArtifacts"] = []
        return payload

    def _row(table: str, key: str, value: str):
        return next(row for row in repo.fetch_all(table) if row[key] == value)

    def _counts():
        return {
            "source_repository_snapshot": repo.count_rows("source_repository_snapshot"),
            "source_repository_artifact": repo.count_rows("source_repository_artifact"),
            "source_build_context": repo.count_rows("source_build_context"),
            "source_analysis_artifact_set": repo.count_rows("source_analysis_artifact_set"),
        }

    first_payload = _container_only_payload()
    first_payload["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-reused-container"
    first_payload["buildContext"]["buildContextId"] = "build-reused-container"
    first_payload["analysisArtifactSet"]["analysisArtifactSetId"] = "analysis-reused-container"

    try:
        source_kg_api.set_ledger_repository(repo)
        first = client.post("/v1/source-code-kg/ingest", json=first_payload, headers=_HEADERS)
        assert first.status_code == 200, first.text
        first_body = first.json()
        counts_before = _counts()

        cases = []
        artifact_reuse = _container_only_payload()
        artifact_reuse["repositorySnapshot"]["commitHash"] = "commit-artifact-rebind"
        artifact_reuse["repositorySnapshot"]["treeHash"] = "tree-artifact-rebind"
        artifact_reuse["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-reused-container"
        artifact_reuse["buildContext"]["buildContextId"] = "build-artifact-rebind"
        artifact_reuse["analysisArtifactSet"]["analysisArtifactSetId"] = "analysis-artifact-rebind"
        cases.append(("artifact", artifact_reuse, "source repository artifact id reused across repository snapshots: artifact-reused-container"))

        build_reuse = _container_only_payload()
        build_reuse["repositorySnapshot"]["commitHash"] = "commit-build-rebind"
        build_reuse["repositorySnapshot"]["treeHash"] = "tree-build-rebind"
        build_reuse["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-build-rebind"
        build_reuse["buildContext"]["buildContextId"] = "build-reused-container"
        build_reuse["analysisArtifactSet"]["analysisArtifactSetId"] = "analysis-build-rebind"
        cases.append(("build", build_reuse, "build context id reused across repository snapshots: build-reused-container"))

        analysis_reuse = _container_only_payload()
        analysis_reuse["repositorySnapshot"]["commitHash"] = "commit-analysis-rebind"
        analysis_reuse["repositorySnapshot"]["treeHash"] = "tree-analysis-rebind"
        analysis_reuse["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-analysis-rebind"
        analysis_reuse["buildContext"]["buildContextId"] = "build-analysis-rebind"
        analysis_reuse["analysisArtifactSet"]["analysisArtifactSetId"] = "analysis-reused-container"
        cases.append(("analysis", analysis_reuse, "analysis artifact set id reused across build contexts: analysis-reused-container"))

        for case_name, payload, expected_message in cases:
            resp = client.post(
                "/v1/source-code-kg/ingest",
                json=payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-source-kg-container-rebind-{case_name}"},
            )

            assert resp.status_code == 422, resp.text
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "source_kg_lineage_rebind_forbidden"
            assert expected_message in body["errorDetail"]["message"]
            assert _counts() == counts_before
            assert (
                _row("source_repository_artifact", "source_repository_artifact_id", "artifact-reused-container")[
                    "repository_snapshot_id"
                ]
                == first_body["repositorySnapshotId"]
            )
            assert (
                _row("source_build_context", "build_context_id", "build-reused-container")["repository_snapshot_id"]
                == first_body["repositorySnapshotId"]
            )
            assert (
                _row("source_analysis_artifact_set", "analysis_artifact_set_id", "analysis-reused-container")[
                    "build_context_id"
                ]
                == first_body["buildContextId"]
            )
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_repository_snapshot_id_rebind_without_mutating_root(tmp_path):
    old = source_kg_api._ledger_repository
    repo = _repo(tmp_path)
    source_kg_api.set_ledger_repository(repo)
    first_payload = _payload()
    first_payload["repositorySnapshot"]["repositorySnapshotId"] = "repo-root-reused"
    second_payload = _payload()
    second_payload["repositorySnapshot"]["repositorySnapshotId"] = "repo-root-reused"
    second_payload["repositorySnapshot"]["commitHash"] = "different-commit"
    second_payload["repositorySnapshot"]["treeHash"] = "different-tree"
    second_payload["sourceArtifacts"][0]["sourceRepositoryArtifactId"] = "artifact-root-rebind"
    second_payload["buildContext"]["buildContextId"] = "build-root-rebind"
    second_payload["analysisArtifactSet"]["analysisArtifactSetId"] = "analysis-root-rebind"
    second_payload["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-root-rebind"
    second_payload["graphNodes"][1]["evidenceSnippetId"] = "snippet-root-rebind"
    try:
        first = client.post("/v1/source-code-kg/ingest", json=first_payload, headers=_HEADERS)
        assert first.status_code == 200, first.text

        resp = client.post(
            "/v1/source-code-kg/ingest",
            json=second_payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-source-kg-root-rebind"},
        )

        assert resp.status_code == 422, resp.text
        body = resp.json()
        assert body["errorDetail"]["reason"] == "source_kg_lineage_rebind_forbidden"
        assert "repository snapshot id reused across repository versions: repo-root-reused" in body["errorDetail"]["message"]
        row = next(
            row for row in repo.fetch_all("source_repository_snapshot") if row["repository_snapshot_id"] == "repo-root-reused"
        )
        assert row["commit_hash"] == "abcdef1234567890"
        assert row["tree_hash"] == "tree-1111"
        assert repo.count_rows("source_repository_snapshot") == 1
        assert repo.count_rows("source_repository_artifact") == 1
        assert repo.count_rows("source_build_context") == 1
        assert repo.count_rows("source_analysis_artifact_set") == 1
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_same_lineage_explicit_id_content_conflicts_without_mutation(tmp_path):
    old = source_kg_api._ledger_repository

    def row(repo: SQLiteLedgerRepository, table: str, key: str, value: str) -> dict:
        return dict(next(item for item in repo.fetch_all(table) if item[key] == value))

    cases = [
        {
            "name": "source-artifact",
            "id": "artifact-content-conflict",
            "table": "source_repository_artifact",
            "key": "source_repository_artifact_id",
            "prepare": lambda payload: payload["sourceArtifacts"][0].update(
                {"sourceRepositoryArtifactId": "artifact-content-conflict"}
            ),
            "mutate": lambda payload: payload["sourceArtifacts"][0].update(
                {"artifactUri": "file:///fixtures/openssl-vuln-mutated.tar.zst"}
            ),
        },
        {
            "name": "build-context",
            "id": "build-content-conflict",
            "table": "source_build_context",
            "key": "build_context_id",
            "prepare": lambda payload: payload["buildContext"].update({"buildContextId": "build-content-conflict"}),
            "mutate": lambda payload: payload["buildContext"]["toolchain"].update({"compiler": "clang"}),
        },
        {
            "name": "analysis-artifact-set",
            "id": "analysis-content-conflict",
            "table": "source_analysis_artifact_set",
            "key": "analysis_artifact_set_id",
            "prepare": lambda payload: payload["analysisArtifactSet"].update(
                {"analysisArtifactSetId": "analysis-content-conflict"}
            ),
            "mutate": lambda payload: payload["analysisArtifactSet"].update({"analyzerVersion": "2.0"}),
        },
        {
            "name": "evidence-snippet",
            "id": "snippet-content-conflict",
            "table": "source_evidence_snippet",
            "key": "evidence_snippet_id",
            "prepare": lambda payload: (
                payload["evidenceSnippets"][0].update({"evidenceSnippetId": "snippet-content-conflict"}),
                payload["graphNodes"][1].update({"evidenceSnippetId": "snippet-content-conflict"}),
            ),
            "mutate": lambda payload: payload["evidenceSnippets"][0].update(
                {"snippetText": "memcpy(bp, pl, payload + 1);"}
            ),
        },
        {
            "name": "graph-node",
            "id": "node-content-conflict",
            "table": "source_graph_node",
            "key": "source_graph_node_id",
            "prepare": lambda payload: payload["graphNodes"][0].update(
                {"sourceGraphNodeId": "node-content-conflict"}
            ),
            "mutate": lambda payload: payload["graphNodes"][0].update({"displayName": "ssl3_read_bytes_mutated"}),
        },
        {
            "name": "graph-edge",
            "id": "edge-content-conflict",
            "table": "source_graph_edge",
            "key": "source_graph_edge_id",
            "prepare": lambda payload: payload["graphEdges"][0].update(
                {"sourceGraphEdgeId": "edge-content-conflict"}
            ),
            "mutate": lambda payload: payload["graphEdges"][0].update({"edgeKind": "taint_flow"}),
        },
        {
            "name": "rich-ir",
            "id": "rich-ir-content-conflict",
            "table": "source_rich_ir_artifact",
            "key": "rich_ir_artifact_id",
            "prepare": lambda payload: payload["richIrArtifacts"][0].update(
                {"richIrArtifactId": "rich-ir-content-conflict"}
            ),
            "mutate": lambda payload: payload["richIrArtifacts"][0].update(
                {"checksumSha256": "sha256:" + "c" * 64, "payload": {"source": "payload", "sink": "strcpy"}}
            ),
        },
    ]

    try:
        for case in cases:
            case_dir = tmp_path / case["name"]
            case_dir.mkdir()
            repo = _repo(case_dir)
            source_kg_api.set_ledger_repository(repo)
            first_payload = _payload()
            second_payload = _payload()
            case["prepare"](first_payload)
            case["prepare"](second_payload)
            case["mutate"](second_payload)

            first = client.post(
                "/v1/source-code-kg/ingest",
                json=first_payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-source-kg-content-conflict-first-{case['name']}"},
            )
            assert first.status_code == 200, first.text
            before = row(repo, case["table"], case["key"], case["id"])

            resp = client.post(
                "/v1/source-code-kg/ingest",
                json=second_payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-source-kg-content-conflict-{case['name']}"},
            )

            assert resp.status_code == 422, f"{case['name']}: {resp.text}"
            body = resp.json()
            assert body["errorDetail"]["reason"] == "source_kg_identity_content_conflict"
            assert f"source KG explicit ID content conflict: {case['id']}" in body["errorDetail"]["message"]
            assert row(repo, case["table"], case["key"], case["id"]) == before
    finally:
        source_kg_api.set_ledger_repository(old)


def test_source_code_kg_ingest_rejects_explicit_snippet_id_reuse_across_repository_snapshots(tmp_path):
    repo = _repo(tmp_path)
    first_payload = _payload()
    first_payload["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-reused"
    first_payload["graphNodes"][1]["evidenceSnippetId"] = "snippet-reused"
    ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(first_payload))

    second_payload = _payload()
    second_payload["repositorySnapshot"]["commitHash"] = "fedcba0987654321"
    second_payload["repositorySnapshot"]["treeHash"] = "tree-2222"
    second_payload["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-reused"
    second_payload["graphNodes"][1]["evidenceSnippetId"] = "snippet-reused"
    req = SourceCodeKgIngestRequest.model_validate(second_payload)

    try:
        ingest_source_kg(repo, req)
    except ValueError as exc:
        assert "evidence snippet id reused across repository snapshots: snippet-reused" in str(exc)
    else:  # pragma: no cover - explicit TDD guard
        raise AssertionError("cross-lineage Source KG snippet id reuse was accepted")


def test_source_code_kg_ingest_rejects_explicit_rich_ir_id_reuse_across_analysis_sets(tmp_path):
    repo = _repo(tmp_path)
    first_payload = _payload()
    first_payload["richIrArtifacts"][0]["richIrArtifactId"] = "rich-ir-reused"
    ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(first_payload))

    second_payload = _payload()
    second_payload["repositorySnapshot"]["commitHash"] = "fedcba0987654321"
    second_payload["repositorySnapshot"]["treeHash"] = "tree-2222"
    second_payload["evidenceSnippets"][0]["evidenceSnippetId"] = "snippet-second"
    second_payload["graphNodes"][1]["evidenceSnippetId"] = "snippet-second"
    second_payload["richIrArtifacts"][0]["richIrArtifactId"] = "rich-ir-reused"
    req = SourceCodeKgIngestRequest.model_validate(second_payload)

    try:
        ingest_source_kg(repo, req)
    except ValueError as exc:
        assert "rich IR artifact id reused across analysis artifact sets: rich-ir-reused" in str(exc)
    else:  # pragma: no cover - explicit TDD guard
        raise AssertionError("cross-lineage Source KG rich IR id reuse was accepted")


def test_source_code_kg_ingest_rejects_unknown_edge_node_ids_before_ledger_write(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["graphEdges"][0] = {
        "edgeKind": "calls",
        "sourceGraphNodeId": "src-node-does-not-exist",
        "targetStableId": "func:tls1_process_heartbeat",
        "evidence": {"pathKind": "call"},
    }
    req = SourceCodeKgIngestRequest.model_validate(payload)

    try:
        ingest_source_kg(repo, req)
    except ValueError as exc:
        assert "unknown source graph node id: src-node-does-not-exist" in str(exc)
    else:  # pragma: no cover - explicit TDD guard
        raise AssertionError("dangling Source Code KG edge was accepted")

    assert repo.count_rows("source_graph_edge") == 0


def test_source_code_kg_ingest_rejects_unknown_node_snippet_ids_before_ledger_write(tmp_path):
    repo = _repo(tmp_path)
    payload = _payload()
    payload["graphNodes"][0]["evidenceSnippetId"] = "snippet-does-not-exist"
    req = SourceCodeKgIngestRequest.model_validate(payload)

    try:
        ingest_source_kg(repo, req)
    except ValueError as exc:
        assert "unknown evidence snippet id: snippet-does-not-exist" in str(exc)
    else:  # pragma: no cover - explicit TDD guard
        raise AssertionError("dangling Source Code KG node snippet was accepted")

    assert repo.count_rows("source_graph_node") == 0
