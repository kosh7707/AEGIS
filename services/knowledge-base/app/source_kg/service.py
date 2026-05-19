"""Ledger-backed Source Code KG ingestion service."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.ledger.repository import SQLiteLedgerRepository

from .models import SourceCodeKgIngestRequest, SourceCodeKgIngestResult

SHA256_CHECKSUM_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _canonical(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = "\0".join(_canonical(part) if isinstance(part, (dict, list)) else str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def _text_checksum(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_sha256_checksum(value: str | None, *, field: str) -> None:
    if value is None:
        return
    if not SHA256_CHECKSUM_RE.fullmatch(value):
        raise ValueError(f"invalid source KG checksum format: {field}")


def _validate_checksum_matches(value: str | None, expected: str, *, field: str) -> None:
    _validate_sha256_checksum(value, field=field)
    if value is not None and value != expected:
        raise ValueError(f"source KG checksum mismatch: {field}")


def _validate_line_span(line_start: int | None, line_end: int | None, *, field: str) -> None:
    if line_start is not None and line_start < 1:
        raise ValueError(f"invalid source KG line span: {field}")
    if line_end is not None and line_end < 1:
        raise ValueError(f"invalid source KG line span: {field}")
    if line_start is not None and line_end is not None and line_end < line_start:
        raise ValueError(f"invalid source KG line span: {field}")


def _first_duplicate(values: list[str]) -> str | None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            return value
        seen.add(value)
    return None


def _reject_duplicate_generated_id(label: str, values: list[str]) -> None:
    duplicate = _first_duplicate(values)
    if duplicate:
        raise ValueError(f"duplicate generated {label} in request: {duplicate}")


def _validate_internal_references(request: SourceCodeKgIngestRequest) -> None:
    """Reject dangling Source Code KG references before writing ledger rows."""

    for artifact in request.source_artifacts:
        _validate_sha256_checksum(artifact.checksum_sha256, field="sourceArtifacts[].checksumSha256")
    for artifact in request.rich_ir_artifacts:
        _validate_sha256_checksum(artifact.checksum_sha256, field="richIrArtifacts[].checksumSha256")
    for snippet in request.evidence_snippets:
        _validate_line_span(snippet.line_start, snippet.line_end, field="evidenceSnippets[]")
    for node in request.graph_nodes:
        _validate_line_span(node.line_start, node.line_end, field="graphNodes[]")

    duplicate_artifact_id = _first_duplicate(
        [
            str(artifact.source_repository_artifact_id)
            for artifact in request.source_artifacts
            if artifact.source_repository_artifact_id
        ]
    )
    if duplicate_artifact_id:
        raise ValueError(f"duplicate source repository artifact id in request: {duplicate_artifact_id}")

    duplicate_snippet_id = _first_duplicate(
        [
            str(snippet.evidence_snippet_id)
            for snippet in request.evidence_snippets
            if snippet.evidence_snippet_id
        ]
    )
    if duplicate_snippet_id:
        raise ValueError(f"duplicate evidence snippet id in request: {duplicate_snippet_id}")

    duplicate_node_id = _first_duplicate(
        [
            str(node.source_graph_node_id)
            for node in request.graph_nodes
            if node.source_graph_node_id
        ]
    )
    if duplicate_node_id:
        raise ValueError(f"duplicate source graph node id in request: {duplicate_node_id}")

    duplicate_stable_id = _first_duplicate([node.stable_id for node in request.graph_nodes])
    if duplicate_stable_id:
        raise ValueError(f"duplicate source graph node stable id in request: {duplicate_stable_id}")

    duplicate_edge_id = _first_duplicate(
        [
            str(edge.source_graph_edge_id)
            for edge in request.graph_edges
            if edge.source_graph_edge_id
        ]
    )
    if duplicate_edge_id:
        raise ValueError(f"duplicate source graph edge id in request: {duplicate_edge_id}")

    duplicate_rich_ir_id = _first_duplicate(
        [
            str(artifact.rich_ir_artifact_id)
            for artifact in request.rich_ir_artifacts
            if artifact.rich_ir_artifact_id
        ]
    )
    if duplicate_rich_ir_id:
        raise ValueError(f"duplicate rich IR artifact id in request: {duplicate_rich_ir_id}")

    explicit_snippet_ids = {
        snippet.evidence_snippet_id
        for snippet in request.evidence_snippets
        if snippet.evidence_snippet_id
    }
    for node in request.graph_nodes:
        if node.evidence_snippet_id and node.evidence_snippet_id not in explicit_snippet_ids:
            raise ValueError(f"unknown evidence snippet id: {node.evidence_snippet_id}")

    explicit_node_ids = {
        node.source_graph_node_id
        for node in request.graph_nodes
        if node.source_graph_node_id
    }
    stable_node_ids = {node.stable_id for node in request.graph_nodes}
    for edge in request.graph_edges:
        if edge.source_graph_node_id and edge.source_graph_node_id not in explicit_node_ids:
            raise ValueError(f"unknown source graph node id: {edge.source_graph_node_id}")
        if edge.target_graph_node_id and edge.target_graph_node_id not in explicit_node_ids:
            raise ValueError(f"unknown target graph node id: {edge.target_graph_node_id}")
        if edge.source_stable_id and edge.source_stable_id not in stable_node_ids:
            raise ValueError(f"unknown source stable id: {edge.source_stable_id}")
        if edge.target_stable_id and edge.target_stable_id not in stable_node_ids:
            raise ValueError(f"unknown target stable id: {edge.target_stable_id}")


def _table_by_id(repo: SQLiteLedgerRepository, table: str, key: str) -> dict[str, dict[str, Any]]:
    return {str(row[key]): row for row in repo.fetch_all(table)}


def _repository_snapshot_version_identity_from_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "repositoryUrl": row["repository_url"],
        "repositoryId": row["repository_id"],
        "commitHash": row["commit_hash"],
        "treeHash": row["tree_hash"],
        "submoduleHashes": json.loads(row["submodule_hashes_json"] or "{}"),
    }


def _repository_snapshot_version_identity(request: SourceCodeKgIngestRequest) -> dict[str, Any]:
    snapshot = request.repository_snapshot
    return {
        "repositoryUrl": snapshot.repository_url,
        "repositoryId": snapshot.repository_id,
        "commitHash": snapshot.commit_hash,
        "treeHash": snapshot.tree_hash,
        "submoduleHashes": snapshot.submodule_hashes,
    }


def _row_json(row: dict[str, Any], key: str) -> dict[str, Any]:
    return json.loads(row[key] or "{}")


def _reject_content_conflict(entity_id: str, *, existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    if _canonical(existing) != _canonical(incoming):
        raise ValueError(f"source KG explicit ID content conflict: {entity_id}")


def _reject_cross_lineage_id_reuse(
    repo: SQLiteLedgerRepository,
    request: SourceCodeKgIngestRequest,
    *,
    repository_snapshot_id: str,
    source_artifact_ids: list[str],
    build_context_id: str,
    analysis_artifact_set_id: str,
) -> None:
    """Reject producer-supplied IDs that would rebind facts across source lineage."""

    repository_snapshots = _table_by_id(repo, "source_repository_snapshot", "repository_snapshot_id")
    if repository_snapshot_id in repository_snapshots and _canonical(
        _repository_snapshot_version_identity_from_row(repository_snapshots[repository_snapshot_id])
    ) != _canonical(_repository_snapshot_version_identity(request)):
        raise ValueError(f"repository snapshot id reused across repository versions: {repository_snapshot_id}")

    source_artifacts = _table_by_id(repo, "source_repository_artifact", "source_repository_artifact_id")
    for artifact_id in source_artifact_ids:
        if artifact_id not in source_artifacts:
            continue
        if source_artifacts[artifact_id]["repository_snapshot_id"] != repository_snapshot_id:
            raise ValueError(f"source repository artifact id reused across repository snapshots: {artifact_id}")

    build_contexts = _table_by_id(repo, "source_build_context", "build_context_id")
    if build_context_id in build_contexts and build_contexts[build_context_id]["repository_snapshot_id"] != repository_snapshot_id:
        raise ValueError(f"build context id reused across repository snapshots: {build_context_id}")

    analysis_artifact_sets = _table_by_id(repo, "source_analysis_artifact_set", "analysis_artifact_set_id")
    if (
        analysis_artifact_set_id in analysis_artifact_sets
        and analysis_artifact_sets[analysis_artifact_set_id]["build_context_id"] != build_context_id
    ):
        raise ValueError(f"analysis artifact set id reused across build contexts: {analysis_artifact_set_id}")

    snippets = _table_by_id(repo, "source_evidence_snippet", "evidence_snippet_id")
    for snippet in request.evidence_snippets:
        snippet_id = snippet.evidence_snippet_id
        if not snippet_id or snippet_id not in snippets:
            continue
        if snippets[snippet_id]["repository_snapshot_id"] != repository_snapshot_id:
            raise ValueError(f"evidence snippet id reused across repository snapshots: {snippet_id}")

    nodes = _table_by_id(repo, "source_graph_node", "source_graph_node_id")
    for node in request.graph_nodes:
        node_id = node.source_graph_node_id
        if not node_id or node_id not in nodes:
            continue
        if nodes[node_id]["analysis_artifact_set_id"] != analysis_artifact_set_id:
            raise ValueError(f"source graph node id reused across analysis artifact sets: {node_id}")

    edges = _table_by_id(repo, "source_graph_edge", "source_graph_edge_id")
    for edge in request.graph_edges:
        edge_id = edge.source_graph_edge_id
        if not edge_id or edge_id not in edges:
            continue
        if edges[edge_id]["analysis_artifact_set_id"] != analysis_artifact_set_id:
            raise ValueError(f"source graph edge id reused across analysis artifact sets: {edge_id}")

    rich_ir_artifacts = _table_by_id(repo, "source_rich_ir_artifact", "rich_ir_artifact_id")
    for artifact in request.rich_ir_artifacts:
        rich_id = artifact.rich_ir_artifact_id
        if not rich_id or rich_id not in rich_ir_artifacts:
            continue
        if rich_ir_artifacts[rich_id]["analysis_artifact_set_id"] != analysis_artifact_set_id:
            raise ValueError(f"rich IR artifact id reused across analysis artifact sets: {rich_id}")


def _reject_explicit_id_content_conflicts(
    repo: SQLiteLedgerRepository,
    request: SourceCodeKgIngestRequest,
    *,
    repository_snapshot_id: str,
    source_artifact_ids: list[str],
    build_context_id: str,
    analysis_artifact_set_id: str,
    evidence_snippet_rows: list[tuple[Any, str, str]],
    graph_node_ids: list[str],
    graph_edge_rows: list[tuple[Any, str, str, str]],
    rich_ir_artifact_rows: list[tuple[Any, str]],
) -> None:
    """Reject explicit/resolved Source KG IDs that would mutate stored facts."""

    source_artifacts = _table_by_id(repo, "source_repository_artifact", "source_repository_artifact_id")
    for artifact, artifact_id in zip(request.source_artifacts, source_artifact_ids, strict=True):
        if artifact_id not in source_artifacts:
            continue
        row = source_artifacts[artifact_id]
        _reject_content_conflict(
            artifact_id,
            existing={
                "repositorySnapshotId": row["repository_snapshot_id"],
                "artifactUri": row["artifact_uri"],
                "mediaType": row["media_type"],
                "checksumSha256": row["checksum_sha256"],
                "storageMode": row["storage_mode"],
                "metadata": _row_json(row, "metadata_json"),
                "provenance": _row_json(row, "provenance_json"),
            },
            incoming={
                "repositorySnapshotId": repository_snapshot_id,
                "artifactUri": artifact.artifact_uri,
                "mediaType": artifact.media_type,
                "checksumSha256": artifact.checksum_sha256,
                "storageMode": artifact.storage_mode,
                "metadata": artifact.metadata,
                "provenance": artifact.provenance,
            },
        )

    build_contexts = _table_by_id(repo, "source_build_context", "build_context_id")
    if build_context_id in build_contexts:
        build = request.build_context
        row = build_contexts[build_context_id]
        _reject_content_conflict(
            build_context_id,
            existing={
                "repositorySnapshotId": row["repository_snapshot_id"],
                "projectId": row["project_id"],
                "targetId": row["target_id"],
                "buildTarget": row["build_target"],
                "toolchain": _row_json(row, "toolchain_json"),
                "compileCommandsArtifactId": row["compile_commands_artifact_id"],
                "dependencyGraph": _row_json(row, "dependency_graph_json"),
                "buildMetadata": _row_json(row, "build_metadata_json"),
                "provenance": _row_json(row, "provenance_json"),
            },
            incoming={
                "repositorySnapshotId": repository_snapshot_id,
                "projectId": build.project_id,
                "targetId": build.target_id,
                "buildTarget": build.build_target,
                "toolchain": build.toolchain,
                "compileCommandsArtifactId": build.compile_commands_artifact_id,
                "dependencyGraph": build.dependency_graph,
                "buildMetadata": build.build_metadata,
                "provenance": build.provenance,
            },
        )

    analysis_artifact_sets = _table_by_id(repo, "source_analysis_artifact_set", "analysis_artifact_set_id")
    if analysis_artifact_set_id in analysis_artifact_sets:
        analysis = request.analysis_artifact_set
        row = analysis_artifact_sets[analysis_artifact_set_id]
        _reject_content_conflict(
            analysis_artifact_set_id,
            existing={
                "buildContextId": row["build_context_id"],
                "analyzerName": row["analyzer_name"],
                "analyzerVersion": row["analyzer_version"],
                "analysisConfig": _row_json(row, "analysis_config_json"),
                "artifactHashes": _row_json(row, "artifact_hashes_json"),
                "producedAt": row["produced_at"],
                "provenance": _row_json(row, "provenance_json"),
            },
            incoming={
                "buildContextId": build_context_id,
                "analyzerName": analysis.analyzer_name,
                "analyzerVersion": analysis.analyzer_version,
                "analysisConfig": analysis.analysis_config,
                "artifactHashes": analysis.artifact_hashes,
                "producedAt": analysis.produced_at,
                "provenance": analysis.provenance,
            },
        )

    snippets = _table_by_id(repo, "source_evidence_snippet", "evidence_snippet_id")
    for snippet, checksum, snippet_id in evidence_snippet_rows:
        if snippet_id not in snippets:
            continue
        row = snippets[snippet_id]
        _reject_content_conflict(
            snippet_id,
            existing={
                "repositorySnapshotId": row["repository_snapshot_id"],
                "filePath": row["file_path"],
                "lineStart": row["line_start"],
                "lineEnd": row["line_end"],
                "language": row["language"],
                "snippetText": row["snippet_text"],
                "checksumSha256": row["checksum_sha256"],
                "provenance": _row_json(row, "provenance_json"),
            },
            incoming={
                "repositorySnapshotId": repository_snapshot_id,
                "filePath": snippet.file_path,
                "lineStart": snippet.line_start,
                "lineEnd": snippet.line_end,
                "language": snippet.language,
                "snippetText": snippet.snippet_text,
                "checksumSha256": checksum,
                "provenance": snippet.provenance,
            },
        )

    nodes = _table_by_id(repo, "source_graph_node", "source_graph_node_id")
    for node, node_id in zip(request.graph_nodes, graph_node_ids, strict=True):
        if node_id not in nodes:
            continue
        row = nodes[node_id]
        _reject_content_conflict(
            node_id,
            existing={
                "analysisArtifactSetId": row["analysis_artifact_set_id"],
                "nodeKind": row["node_kind"],
                "stableId": row["stable_id"],
                "displayName": row["display_name"],
                "filePath": row["file_path"],
                "lineStart": row["line_start"],
                "lineEnd": row["line_end"],
                "symbol": _row_json(row, "symbol_json"),
                "metadata": _row_json(row, "metadata_json"),
                "evidenceSnippetId": row["evidence_snippet_id"],
            },
            incoming={
                "analysisArtifactSetId": analysis_artifact_set_id,
                "nodeKind": node.node_kind,
                "stableId": node.stable_id,
                "displayName": node.display_name,
                "filePath": node.file_path,
                "lineStart": node.line_start,
                "lineEnd": node.line_end,
                "symbol": node.symbol,
                "metadata": node.metadata,
                "evidenceSnippetId": node.evidence_snippet_id,
            },
        )

    edges = _table_by_id(repo, "source_graph_edge", "source_graph_edge_id")
    for edge, source_id, target_id, edge_id in graph_edge_rows:
        if edge_id not in edges:
            continue
        row = edges[edge_id]
        _reject_content_conflict(
            edge_id,
            existing={
                "analysisArtifactSetId": row["analysis_artifact_set_id"],
                "edgeKind": row["edge_kind"],
                "sourceGraphNodeId": row["source_graph_node_id"],
                "targetGraphNodeId": row["target_graph_node_id"],
                "evidence": _row_json(row, "evidence_json"),
                "metadata": _row_json(row, "metadata_json"),
            },
            incoming={
                "analysisArtifactSetId": analysis_artifact_set_id,
                "edgeKind": edge.edge_kind,
                "sourceGraphNodeId": source_id,
                "targetGraphNodeId": target_id,
                "evidence": edge.evidence,
                "metadata": edge.metadata,
            },
        )

    rich_ir_artifacts = _table_by_id(repo, "source_rich_ir_artifact", "rich_ir_artifact_id")
    for artifact, rich_id in rich_ir_artifact_rows:
        if rich_id not in rich_ir_artifacts:
            continue
        row = rich_ir_artifacts[rich_id]
        _reject_content_conflict(
            rich_id,
            existing={
                "analysisArtifactSetId": row["analysis_artifact_set_id"],
                "artifactKind": row["artifact_kind"],
                "mediaType": row["media_type"],
                "uri": row["uri"],
                "checksumSha256": row["checksum_sha256"],
                "payload": _row_json(row, "payload_json"),
                "provenance": _row_json(row, "provenance_json"),
            },
            incoming={
                "analysisArtifactSetId": analysis_artifact_set_id,
                "artifactKind": artifact.artifact_kind,
                "mediaType": artifact.media_type,
                "uri": artifact.uri,
                "checksumSha256": artifact.checksum_sha256,
                "payload": artifact.payload,
                "provenance": artifact.provenance,
            },
        )


def _validate_build_context_artifact_reference(
    repo: SQLiteLedgerRepository,
    request: SourceCodeKgIngestRequest,
    *,
    repository_snapshot_id: str,
    source_artifact_ids: list[str],
) -> None:
    compile_commands_artifact_id = request.build_context.compile_commands_artifact_id
    if not compile_commands_artifact_id:
        return
    if compile_commands_artifact_id in set(source_artifact_ids):
        return
    existing = _table_by_id(repo, "source_repository_artifact", "source_repository_artifact_id")
    row = existing.get(compile_commands_artifact_id)
    if row is None or row["repository_snapshot_id"] != repository_snapshot_id:
        raise ValueError(f"unknown compile commands artifact id: {compile_commands_artifact_id}")


def ingest_source_kg(repo: SQLiteLedgerRepository, request: SourceCodeKgIngestRequest) -> SourceCodeKgIngestResult:
    """Persist a Source Code KG ingest bundle into the durable S5 ledger.

    The service is intentionally ledger-only.  It does not invoke Neo4j or
    Qdrant projection writers; projections are separate quality-gated steps.
    """

    _validate_internal_references(request)
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

    source_artifact_ids: list[str] = []
    for artifact in request.source_artifacts:
        artifact_id = artifact.source_repository_artifact_id or _stable_id(
            "src-artifact",
            repository_snapshot_id,
            artifact.artifact_uri,
            artifact.checksum_sha256,
            artifact.storage_mode,
        )
        source_artifact_ids.append(artifact_id)
    _reject_duplicate_generated_id("source repository artifact id", source_artifact_ids)

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

    analysis = request.analysis_artifact_set
    analysis_artifact_set_id = analysis.analysis_artifact_set_id or _stable_id(
        "src-analysis",
        build_context_id,
        analysis.analyzer_name,
        analysis.analyzer_version or "",
        analysis.analysis_config,
        analysis.artifact_hashes,
    )
    _reject_cross_lineage_id_reuse(
        repo,
        request,
        repository_snapshot_id=repository_snapshot_id,
        source_artifact_ids=source_artifact_ids,
        build_context_id=build_context_id,
        analysis_artifact_set_id=analysis_artifact_set_id,
    )
    _validate_build_context_artifact_reference(
        repo,
        request,
        repository_snapshot_id=repository_snapshot_id,
        source_artifact_ids=source_artifact_ids,
    )

    evidence_snippet_rows = []
    evidence_snippet_ids: list[str] = []
    for snippet in request.evidence_snippets:
        checksum = snippet.checksum_sha256 or _text_checksum(snippet.snippet_text)
        _validate_checksum_matches(
            snippet.checksum_sha256,
            _text_checksum(snippet.snippet_text),
            field="evidenceSnippets[].checksumSha256",
        )
        snippet_id = snippet.evidence_snippet_id or _stable_id(
            "src-snippet",
            repository_snapshot_id,
            snippet.file_path,
            snippet.line_start or "",
            snippet.line_end or "",
            checksum,
        )
        evidence_snippet_rows.append((snippet, checksum, snippet_id))
        evidence_snippet_ids.append(snippet_id)
    _reject_duplicate_generated_id("evidence snippet id", evidence_snippet_ids)

    graph_node_ids: list[str] = []
    stable_to_node_id: dict[str, str] = {}
    for node in request.graph_nodes:
        node_id = node.source_graph_node_id or _stable_id(
            "src-node",
            analysis_artifact_set_id,
            node.node_kind,
            node.stable_id,
        )
        graph_node_ids.append(node_id)
        stable_to_node_id[node.stable_id] = node_id
    _reject_duplicate_generated_id("source graph node id", graph_node_ids)

    graph_edge_rows = []
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
        graph_edge_rows.append((edge, source_id, target_id, edge_id))
        graph_edge_ids.append(edge_id)
    _reject_duplicate_generated_id("source graph edge id", graph_edge_ids)

    rich_ir_artifact_rows = []
    rich_ir_artifact_ids: list[str] = []
    for artifact in request.rich_ir_artifacts:
        rich_id = artifact.rich_ir_artifact_id or _stable_id(
            "src-rich-ir",
            analysis_artifact_set_id,
            artifact.artifact_kind,
            artifact.uri or "",
            artifact.checksum_sha256,
        )
        rich_ir_artifact_rows.append((artifact, rich_id))
        rich_ir_artifact_ids.append(rich_id)
    _reject_duplicate_generated_id("rich IR artifact id", rich_ir_artifact_ids)
    _reject_explicit_id_content_conflicts(
        repo,
        request,
        repository_snapshot_id=repository_snapshot_id,
        source_artifact_ids=source_artifact_ids,
        build_context_id=build_context_id,
        analysis_artifact_set_id=analysis_artifact_set_id,
        evidence_snippet_rows=evidence_snippet_rows,
        graph_node_ids=graph_node_ids,
        graph_edge_rows=graph_edge_rows,
        rich_ir_artifact_rows=rich_ir_artifact_rows,
    )

    with repo.transaction():
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
        for artifact, artifact_id in zip(request.source_artifacts, source_artifact_ids, strict=True):
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

        for snippet, checksum, snippet_id in evidence_snippet_rows:
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

        for node, node_id in zip(request.graph_nodes, graph_node_ids, strict=True):
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

        for edge, source_id, target_id, edge_id in graph_edge_rows:
            repo.upsert_source_graph_edge(
                source_graph_edge_id=edge_id,
                analysis_artifact_set_id=analysis_artifact_set_id,
                edge_kind=edge.edge_kind,
                source_graph_node_id=source_id,
                target_graph_node_id=target_id,
                evidence=edge.evidence,
                metadata=edge.metadata,
            )

        for artifact, rich_id in rich_ir_artifact_rows:
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
