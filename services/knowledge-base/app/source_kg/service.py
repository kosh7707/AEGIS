"""Ledger-backed Source Code KG ingestion service."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.ledger.repository import SQLiteLedgerRepository

from .models import SourceCodeKgIngestRequest, SourceCodeKgIngestResult


def _canonical(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = "\0".join(_canonical(part) if isinstance(part, (dict, list)) else str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def _text_checksum(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def ingest_source_kg(repo: SQLiteLedgerRepository, request: SourceCodeKgIngestRequest) -> SourceCodeKgIngestResult:
    """Persist a Source Code KG ingest bundle into the durable S5 ledger.

    The service is intentionally ledger-only.  It does not invoke Neo4j or
    Qdrant projection writers; projections are separate quality-gated steps.
    """

    repo.initialize()

    snapshot = request.repository_snapshot
    repository_snapshot_id = snapshot.repository_snapshot_id or _stable_id(
        "src-snapshot",
        snapshot.repository_url or "",
        snapshot.repository_id or "",
        snapshot.commit_hash,
        snapshot.tree_hash or "",
        snapshot.submodule_hashes,
    )
    repo.upsert_source_repository_snapshot(
        repository_snapshot_id=repository_snapshot_id,
        repository_url=snapshot.repository_url,
        repository_id=snapshot.repository_id,
        commit_hash=snapshot.commit_hash,
        tree_hash=snapshot.tree_hash,
        submodule_hashes=snapshot.submodule_hashes,
        metadata=snapshot.metadata,
        provenance=snapshot.provenance,
    )

    source_artifact_ids: list[str] = []
    for artifact in request.source_artifacts:
        artifact_id = artifact.source_repository_artifact_id or _stable_id(
            "src-artifact",
            repository_snapshot_id,
            artifact.artifact_uri,
            artifact.checksum_sha256,
            artifact.storage_mode,
        )
        repo.upsert_source_repository_artifact(
            source_repository_artifact_id=artifact_id,
            repository_snapshot_id=repository_snapshot_id,
            artifact_uri=artifact.artifact_uri,
            media_type=artifact.media_type,
            checksum_sha256=artifact.checksum_sha256,
            storage_mode=artifact.storage_mode,
            metadata=artifact.metadata,
            provenance=artifact.provenance,
        )
        source_artifact_ids.append(artifact_id)

    build = request.build_context
    build_context_id = build.build_context_id or _stable_id(
        "src-build",
        repository_snapshot_id,
        build.project_id or "",
        build.target_id or "",
        build.build_target or "",
        build.toolchain,
        build.compile_commands_artifact_id or "",
        build.dependency_graph,
        build.build_metadata,
    )
    repo.upsert_source_build_context(
        build_context_id=build_context_id,
        repository_snapshot_id=repository_snapshot_id,
        project_id=build.project_id,
        target_id=build.target_id,
        build_target=build.build_target,
        toolchain=build.toolchain,
        compile_commands_artifact_id=build.compile_commands_artifact_id,
        dependency_graph=build.dependency_graph,
        build_metadata=build.build_metadata,
        provenance=build.provenance,
    )

    analysis = request.analysis_artifact_set
    analysis_artifact_set_id = analysis.analysis_artifact_set_id or _stable_id(
        "src-analysis",
        build_context_id,
        analysis.analyzer_name,
        analysis.analyzer_version or "",
        analysis.analysis_config,
        analysis.artifact_hashes,
    )
    repo.upsert_source_analysis_artifact_set(
        analysis_artifact_set_id=analysis_artifact_set_id,
        build_context_id=build_context_id,
        analyzer_name=analysis.analyzer_name,
        analyzer_version=analysis.analyzer_version,
        analysis_config=analysis.analysis_config,
        artifact_hashes=analysis.artifact_hashes,
        produced_at=analysis.produced_at,
        provenance=analysis.provenance,
    )

    evidence_snippet_ids: list[str] = []
    for snippet in request.evidence_snippets:
        checksum = snippet.checksum_sha256 or _text_checksum(snippet.snippet_text)
        snippet_id = snippet.evidence_snippet_id or _stable_id(
            "src-snippet",
            repository_snapshot_id,
            snippet.file_path,
            snippet.line_start or "",
            snippet.line_end or "",
            checksum,
        )
        repo.upsert_source_evidence_snippet(
            evidence_snippet_id=snippet_id,
            repository_snapshot_id=repository_snapshot_id,
            file_path=snippet.file_path,
            line_start=snippet.line_start,
            line_end=snippet.line_end,
            language=snippet.language,
            snippet_text=snippet.snippet_text,
            checksum_sha256=checksum,
            provenance=snippet.provenance,
        )
        evidence_snippet_ids.append(snippet_id)

    graph_node_ids: list[str] = []
    stable_to_node_id: dict[str, str] = {}
    for node in request.graph_nodes:
        node_id = node.source_graph_node_id or _stable_id(
            "src-node",
            analysis_artifact_set_id,
            node.node_kind,
            node.stable_id,
        )
        repo.upsert_source_graph_node(
            source_graph_node_id=node_id,
            analysis_artifact_set_id=analysis_artifact_set_id,
            node_kind=node.node_kind,
            stable_id=node.stable_id,
            display_name=node.display_name,
            file_path=node.file_path,
            line_start=node.line_start,
            line_end=node.line_end,
            symbol=node.symbol,
            metadata=node.metadata,
            evidence_snippet_id=node.evidence_snippet_id,
        )
        graph_node_ids.append(node_id)
        stable_to_node_id[node.stable_id] = node_id

    graph_edge_ids: list[str] = []
    for edge in request.graph_edges:
        source_id = edge.source_graph_node_id or stable_to_node_id.get(str(edge.source_stable_id or ""))
        target_id = edge.target_graph_node_id or stable_to_node_id.get(str(edge.target_stable_id or ""))
        if not source_id or not target_id:
            raise ValueError("graph edge references unknown source/target node")
        edge_id = edge.source_graph_edge_id or _stable_id(
            "src-edge",
            analysis_artifact_set_id,
            edge.edge_kind,
            source_id,
            target_id,
            edge.evidence,
        )
        repo.upsert_source_graph_edge(
            source_graph_edge_id=edge_id,
            analysis_artifact_set_id=analysis_artifact_set_id,
            edge_kind=edge.edge_kind,
            source_graph_node_id=source_id,
            target_graph_node_id=target_id,
            evidence=edge.evidence,
            metadata=edge.metadata,
        )
        graph_edge_ids.append(edge_id)

    rich_ir_artifact_ids: list[str] = []
    for artifact in request.rich_ir_artifacts:
        rich_id = artifact.rich_ir_artifact_id or _stable_id(
            "src-rich-ir",
            analysis_artifact_set_id,
            artifact.artifact_kind,
            artifact.uri or "",
            artifact.checksum_sha256,
        )
        repo.upsert_source_rich_ir_artifact(
            rich_ir_artifact_id=rich_id,
            analysis_artifact_set_id=analysis_artifact_set_id,
            artifact_kind=artifact.artifact_kind,
            media_type=artifact.media_type,
            uri=artifact.uri,
            checksum_sha256=artifact.checksum_sha256,
            payload=artifact.payload,
            provenance=artifact.provenance,
        )
        rich_ir_artifact_ids.append(rich_id)

    return SourceCodeKgIngestResult(
        repositorySnapshotId=repository_snapshot_id,
        buildContextId=build_context_id,
        analysisArtifactSetId=analysis_artifact_set_id,
        counts={
            "sourceArtifacts": len(source_artifact_ids),
            "evidenceSnippets": len(evidence_snippet_ids),
            "graphNodes": len(graph_node_ids),
            "graphEdges": len(graph_edge_ids),
            "richIrArtifacts": len(rich_ir_artifact_ids),
        },
        ids={
            "sourceArtifactIds": source_artifact_ids,
            "evidenceSnippetIds": evidence_snippet_ids,
            "sourceGraphNodeIds": graph_node_ids,
            "sourceGraphEdgeIds": graph_edge_ids,
            "richIrArtifactIds": rich_ir_artifact_ids,
        },
    )
