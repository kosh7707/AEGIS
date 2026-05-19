"""Source Code KG ingestion contract models.

The Source Code KG is a durable S5-owned ledger layer.  It stores source/build
facts and rich analysis IR without writing production Neo4j/Qdrant projections.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

MAX_INGEST_SOURCE_ARTIFACTS = 1024
MAX_INGEST_EVIDENCE_SNIPPETS = 4096
MAX_INGEST_GRAPH_NODES = 8192
MAX_INGEST_GRAPH_EDGES = 16384
MAX_INGEST_RICH_IR_ARTIFACTS = 2048
MAX_INGEST_ID_LENGTH = 512
MAX_INGEST_SNIPPET_TEXT_CHARS = 65536
MAX_INGEST_NESTED_OBJECT_BYTES = 65536
MAX_INGEST_TOTAL_NESTED_OBJECT_BYTES = 1048576
MAX_INGEST_RICH_IR_PAYLOAD_BYTES = 262144
MAX_CONTEXT_GRAPH_NODE_IDS = 256
MAX_CONTEXT_EVIDENCE_SNIPPET_IDS = 256
MAX_CONTEXT_RICH_IR_ARTIFACT_IDS = 128
MAX_CONTEXT_SELECTOR_ID_LENGTH = 512
SourceKgSelectorId = Annotated[str, Field(max_length=MAX_CONTEXT_SELECTOR_ID_LENGTH)]
SourceKgIngestId = Annotated[str, Field(max_length=MAX_INGEST_ID_LENGTH)]


class _ContractModel(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}


def _json_byte_length(value: Any) -> int:
    return len(
        json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    )


def _validate_nested_object_bytes(value: dict[str, Any], *, field: str) -> None:
    byte_length = _json_byte_length(value)
    if byte_length > MAX_INGEST_NESTED_OBJECT_BYTES:
        raise ValueError(
            f"source KG nested JSON object byte length exceeds max bytes: {field} {byte_length}>{MAX_INGEST_NESTED_OBJECT_BYTES}"
        )


def _validate_nested_object_fields(instance: Any, fields: tuple[str, ...]) -> None:
    for field in fields:
        _validate_nested_object_bytes(getattr(instance, field), field=field)


class SourceRepositorySnapshot(_ContractModel):
    repository_snapshot_id: SourceKgIngestId | None = Field(default=None, alias="repositorySnapshotId")
    repository_url: str | None = Field(default=None, alias="repositoryUrl")
    repository_id: SourceKgIngestId | None = Field(default=None, alias="repositoryId")
    commit_hash: str = Field(..., alias="commitHash")
    tree_hash: str | None = Field(default=None, alias="treeHash")
    submodule_hashes: dict[str, Any] = Field(default_factory=dict, alias="submoduleHashes")
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_repository_identity(self) -> "SourceRepositorySnapshot":
        if not (self.repository_url or self.repository_id):
            raise ValueError("repositorySnapshot requires repositoryUrl or repositoryId")
        _validate_nested_object_fields(self, ("submodule_hashes", "metadata", "provenance"))
        return self


class SourceRepositoryArtifact(_ContractModel):
    source_repository_artifact_id: SourceKgIngestId | None = Field(default=None, alias="sourceRepositoryArtifactId")
    artifact_uri: str = Field(..., alias="artifactUri")
    media_type: str = Field(default="application/octet-stream", alias="mediaType")
    checksum_sha256: str = Field(..., alias="checksumSha256")
    storage_mode: Literal["embedded", "content_addressed", "external_uri"] = Field(default="external_uri", alias="storageMode")
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _nested_objects_are_bounded(self) -> "SourceRepositoryArtifact":
        _validate_nested_object_fields(self, ("metadata", "provenance"))
        return self


class SourceBuildContext(_ContractModel):
    build_context_id: SourceKgIngestId | None = Field(default=None, alias="buildContextId")
    project_id: SourceKgIngestId | None = Field(default=None, alias="projectId")
    target_id: SourceKgIngestId | None = Field(default=None, alias="targetId")
    build_target: str | None = Field(default=None, alias="buildTarget")
    toolchain: dict[str, Any] = Field(default_factory=dict)
    compile_commands_artifact_id: SourceKgIngestId | None = Field(default=None, alias="compileCommandsArtifactId")
    dependency_graph: dict[str, Any] = Field(default_factory=dict, alias="dependencyGraph")
    build_metadata: dict[str, Any] = Field(default_factory=dict, alias="buildMetadata")
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _nested_objects_are_bounded(self) -> "SourceBuildContext":
        _validate_nested_object_fields(self, ("toolchain", "dependency_graph", "build_metadata", "provenance"))
        return self


class SourceAnalysisArtifactSet(_ContractModel):
    analysis_artifact_set_id: SourceKgIngestId | None = Field(default=None, alias="analysisArtifactSetId")
    analyzer_name: str = Field(..., alias="analyzerName")
    analyzer_version: str | None = Field(default=None, alias="analyzerVersion")
    analysis_config: dict[str, Any] = Field(default_factory=dict, alias="analysisConfig")
    artifact_hashes: dict[str, Any] = Field(default_factory=dict, alias="artifactHashes")
    produced_at: str | None = Field(default=None, alias="producedAt")
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _nested_objects_are_bounded(self) -> "SourceAnalysisArtifactSet":
        _validate_nested_object_fields(self, ("analysis_config", "artifact_hashes", "provenance"))
        return self


class SourceEvidenceSnippet(_ContractModel):
    evidence_snippet_id: SourceKgIngestId | None = Field(default=None, alias="evidenceSnippetId")
    file_path: str = Field(..., alias="filePath")
    line_start: int | None = Field(default=None, alias="lineStart")
    line_end: int | None = Field(default=None, alias="lineEnd")
    language: str | None = None
    snippet_text: str = Field(..., alias="snippetText", max_length=MAX_INGEST_SNIPPET_TEXT_CHARS)
    checksum_sha256: str | None = Field(default=None, alias="checksumSha256")
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _nested_objects_are_bounded(self) -> "SourceEvidenceSnippet":
        _validate_nested_object_fields(self, ("provenance",))
        return self


class SourceGraphNode(_ContractModel):
    source_graph_node_id: SourceKgIngestId | None = Field(default=None, alias="sourceGraphNodeId")
    node_kind: str = Field(..., alias="nodeKind")
    stable_id: SourceKgIngestId = Field(..., alias="stableId")
    display_name: str | None = Field(default=None, alias="displayName")
    file_path: str | None = Field(default=None, alias="filePath")
    line_start: int | None = Field(default=None, alias="lineStart")
    line_end: int | None = Field(default=None, alias="lineEnd")
    symbol: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_snippet_id: SourceKgIngestId | None = Field(default=None, alias="evidenceSnippetId")

    @model_validator(mode="after")
    def _nested_objects_are_bounded(self) -> "SourceGraphNode":
        _validate_nested_object_fields(self, ("symbol", "metadata"))
        return self


class SourceGraphEdge(_ContractModel):
    source_graph_edge_id: SourceKgIngestId | None = Field(default=None, alias="sourceGraphEdgeId")
    edge_kind: str = Field(..., alias="edgeKind")
    source_graph_node_id: SourceKgIngestId | None = Field(default=None, alias="sourceGraphNodeId")
    target_graph_node_id: SourceKgIngestId | None = Field(default=None, alias="targetGraphNodeId")
    source_stable_id: SourceKgIngestId | None = Field(default=None, alias="sourceStableId")
    target_stable_id: SourceKgIngestId | None = Field(default=None, alias="targetStableId")
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_edge_endpoints(self) -> "SourceGraphEdge":
        if not (self.source_graph_node_id or self.source_stable_id):
            raise ValueError("source graph edge requires sourceGraphNodeId or sourceStableId")
        if not (self.target_graph_node_id or self.target_stable_id):
            raise ValueError("source graph edge requires targetGraphNodeId or targetStableId")
        _validate_nested_object_fields(self, ("evidence", "metadata"))
        return self


class SourceRichIrArtifact(_ContractModel):
    rich_ir_artifact_id: SourceKgIngestId | None = Field(default=None, alias="richIrArtifactId")
    artifact_kind: str = Field(..., alias="artifactKind")
    media_type: str = Field(default="application/json", alias="mediaType")
    uri: str | None = None
    checksum_sha256: str = Field(..., alias="checksumSha256")
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _payload_is_bounded(self) -> "SourceRichIrArtifact":
        payload_bytes = _json_byte_length(self.payload)
        if payload_bytes > MAX_INGEST_RICH_IR_PAYLOAD_BYTES:
            raise ValueError(
                f"richIrArtifact payload byte length exceeds max bytes: {payload_bytes}>{MAX_INGEST_RICH_IR_PAYLOAD_BYTES}"
            )
        _validate_nested_object_fields(self, ("provenance",))
        return self


class SourceCodeKgIngestRequest(_ContractModel):
    schema_version: Literal["s5-source-code-kg-ingest-request-v1"] = Field(
        default="s5-source-code-kg-ingest-request-v1", alias="schemaVersion"
    )
    repository_snapshot: SourceRepositorySnapshot = Field(..., alias="repositorySnapshot")
    source_artifacts: list[SourceRepositoryArtifact] = Field(
        default_factory=list, alias="sourceArtifacts", max_length=MAX_INGEST_SOURCE_ARTIFACTS
    )
    build_context: SourceBuildContext = Field(..., alias="buildContext")
    analysis_artifact_set: SourceAnalysisArtifactSet = Field(..., alias="analysisArtifactSet")
    evidence_snippets: list[SourceEvidenceSnippet] = Field(
        default_factory=list, alias="evidenceSnippets", max_length=MAX_INGEST_EVIDENCE_SNIPPETS
    )
    graph_nodes: list[SourceGraphNode] = Field(
        default_factory=list, alias="graphNodes", max_length=MAX_INGEST_GRAPH_NODES
    )
    graph_edges: list[SourceGraphEdge] = Field(
        default_factory=list, alias="graphEdges", max_length=MAX_INGEST_GRAPH_EDGES
    )
    rich_ir_artifacts: list[SourceRichIrArtifact] = Field(
        default_factory=list, alias="richIrArtifacts", max_length=MAX_INGEST_RICH_IR_ARTIFACTS
    )

    @model_validator(mode="after")
    def _nested_object_aggregate_is_bounded(self) -> "SourceCodeKgIngestRequest":
        nested_object_bytes = (
            _json_byte_length(self.repository_snapshot.submodule_hashes)
            + _json_byte_length(self.repository_snapshot.metadata)
            + _json_byte_length(self.repository_snapshot.provenance)
            + sum(_json_byte_length(artifact.metadata) + _json_byte_length(artifact.provenance) for artifact in self.source_artifacts)
            + _json_byte_length(self.build_context.toolchain)
            + _json_byte_length(self.build_context.dependency_graph)
            + _json_byte_length(self.build_context.build_metadata)
            + _json_byte_length(self.build_context.provenance)
            + _json_byte_length(self.analysis_artifact_set.analysis_config)
            + _json_byte_length(self.analysis_artifact_set.artifact_hashes)
            + _json_byte_length(self.analysis_artifact_set.provenance)
            + sum(_json_byte_length(snippet.provenance) for snippet in self.evidence_snippets)
            + sum(_json_byte_length(node.symbol) + _json_byte_length(node.metadata) for node in self.graph_nodes)
            + sum(_json_byte_length(edge.evidence) + _json_byte_length(edge.metadata) for edge in self.graph_edges)
            + sum(_json_byte_length(artifact.provenance) for artifact in self.rich_ir_artifacts)
        )
        if nested_object_bytes > MAX_INGEST_TOTAL_NESTED_OBJECT_BYTES:
            raise ValueError(
                "source KG nested JSON object byte length exceeds max bytes: "
                f"aggregate {nested_object_bytes}>{MAX_INGEST_TOTAL_NESTED_OBJECT_BYTES}"
            )
        return self


class SourceCodeKgIngestResult(_ContractModel):
    schema_version: Literal["s5-source-code-kg-ingest-result-v1"] = Field(
        default="s5-source-code-kg-ingest-result-v1", alias="schemaVersion"
    )
    ledger_only: bool = Field(default=True, alias="ledgerOnly")
    production_writes: dict[str, bool] = Field(default_factory=lambda: {"neo4j": False, "qdrant": False}, alias="productionWrites")
    repository_snapshot_id: str = Field(..., alias="repositorySnapshotId")
    build_context_id: str = Field(..., alias="buildContextId")
    analysis_artifact_set_id: str = Field(..., alias="analysisArtifactSetId")
    counts: dict[str, int]
    ids: dict[str, Any]


class SourceCodeKgContextRequest(_ContractModel):
    schema_version: Literal["s5-source-code-kg-context-request-v1"] = Field(
        default="s5-source-code-kg-context-request-v1", alias="schemaVersion"
    )
    repository_snapshot_id: SourceKgSelectorId | None = Field(default=None, alias="repositorySnapshotId")
    build_context_id: SourceKgSelectorId | None = Field(default=None, alias="buildContextId")
    analysis_artifact_set_id: SourceKgSelectorId | None = Field(default=None, alias="analysisArtifactSetId")
    graph_node_ids: list[SourceKgSelectorId] = Field(
        default_factory=list,
        alias="graphNodeIds",
        max_length=MAX_CONTEXT_GRAPH_NODE_IDS,
    )
    evidence_snippet_ids: list[SourceKgSelectorId] = Field(
        default_factory=list,
        alias="evidenceSnippetIds",
        max_length=MAX_CONTEXT_EVIDENCE_SNIPPET_IDS,
    )
    rich_ir_artifact_ids: list[SourceKgSelectorId] = Field(
        default_factory=list,
        alias="richIrArtifactIds",
        max_length=MAX_CONTEXT_RICH_IR_ARTIFACT_IDS,
    )

    @model_validator(mode="after")
    def _has_context_selector(self) -> "SourceCodeKgContextRequest":
        if not any(
            [
                self.repository_snapshot_id,
                self.build_context_id,
                self.analysis_artifact_set_id,
                self.graph_node_ids,
                self.evidence_snippet_ids,
                self.rich_ir_artifact_ids,
            ]
        ):
            raise ValueError("Source Code KG context request requires at least one context identifier")
        return self


class SourceCodeKgContextResult(_ContractModel):
    schema_version: Literal["s5-source-code-kg-context-result-v1"] = Field(
        default="s5-source-code-kg-context-result-v1", alias="schemaVersion"
    )
    repository_snapshot: dict[str, Any] | None = Field(default=None, alias="repositorySnapshot")
    build_context: dict[str, Any] | None = Field(default=None, alias="buildContext")
    analysis_artifact_set: dict[str, Any] | None = Field(default=None, alias="analysisArtifactSet")
    source_artifacts: list[dict[str, Any]] = Field(default_factory=list, alias="sourceArtifacts")
    graph_nodes: list[dict[str, Any]] = Field(default_factory=list, alias="graphNodes")
    graph_edges: list[dict[str, Any]] = Field(default_factory=list, alias="graphEdges")
    evidence_snippets: list[dict[str, Any]] = Field(default_factory=list, alias="evidenceSnippets")
    rich_ir_artifacts: list[dict[str, Any]] = Field(default_factory=list, alias="richIrArtifacts")
    context_resolution: dict[str, Any] = Field(default_factory=dict, alias="contextResolution")
    resolved: bool = False
