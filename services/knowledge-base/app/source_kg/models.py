"""Source Code KG ingestion contract models.

The Source Code KG is a durable S5-owned ledger layer.  It stores source/build
facts and rich analysis IR without writing production Neo4j/Qdrant projections.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class _ContractModel(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}


class SourceRepositorySnapshot(_ContractModel):
    repository_snapshot_id: str | None = Field(default=None, alias="repositorySnapshotId")
    repository_url: str | None = Field(default=None, alias="repositoryUrl")
    repository_id: str | None = Field(default=None, alias="repositoryId")
    commit_hash: str = Field(..., alias="commitHash")
    tree_hash: str | None = Field(default=None, alias="treeHash")
    submodule_hashes: dict[str, Any] = Field(default_factory=dict, alias="submoduleHashes")
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_repository_identity(self) -> "SourceRepositorySnapshot":
        if not (self.repository_url or self.repository_id):
            raise ValueError("repositorySnapshot requires repositoryUrl or repositoryId")
        return self


class SourceRepositoryArtifact(_ContractModel):
    source_repository_artifact_id: str | None = Field(default=None, alias="sourceRepositoryArtifactId")
    artifact_uri: str = Field(..., alias="artifactUri")
    media_type: str = Field(default="application/octet-stream", alias="mediaType")
    checksum_sha256: str = Field(..., alias="checksumSha256")
    storage_mode: Literal["embedded", "content_addressed", "external_uri"] = Field(default="external_uri", alias="storageMode")
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class SourceBuildContext(_ContractModel):
    build_context_id: str | None = Field(default=None, alias="buildContextId")
    project_id: str | None = Field(default=None, alias="projectId")
    target_id: str | None = Field(default=None, alias="targetId")
    build_target: str | None = Field(default=None, alias="buildTarget")
    toolchain: dict[str, Any] = Field(default_factory=dict)
    compile_commands_artifact_id: str | None = Field(default=None, alias="compileCommandsArtifactId")
    dependency_graph: dict[str, Any] = Field(default_factory=dict, alias="dependencyGraph")
    build_metadata: dict[str, Any] = Field(default_factory=dict, alias="buildMetadata")
    provenance: dict[str, Any] = Field(default_factory=dict)


class SourceAnalysisArtifactSet(_ContractModel):
    analysis_artifact_set_id: str | None = Field(default=None, alias="analysisArtifactSetId")
    analyzer_name: str = Field(..., alias="analyzerName")
    analyzer_version: str | None = Field(default=None, alias="analyzerVersion")
    analysis_config: dict[str, Any] = Field(default_factory=dict, alias="analysisConfig")
    artifact_hashes: dict[str, Any] = Field(default_factory=dict, alias="artifactHashes")
    produced_at: str | None = Field(default=None, alias="producedAt")
    provenance: dict[str, Any] = Field(default_factory=dict)


class SourceEvidenceSnippet(_ContractModel):
    evidence_snippet_id: str | None = Field(default=None, alias="evidenceSnippetId")
    file_path: str = Field(..., alias="filePath")
    line_start: int | None = Field(default=None, alias="lineStart")
    line_end: int | None = Field(default=None, alias="lineEnd")
    language: str | None = None
    snippet_text: str = Field(..., alias="snippetText")
    checksum_sha256: str | None = Field(default=None, alias="checksumSha256")
    provenance: dict[str, Any] = Field(default_factory=dict)


class SourceGraphNode(_ContractModel):
    source_graph_node_id: str | None = Field(default=None, alias="sourceGraphNodeId")
    node_kind: str = Field(..., alias="nodeKind")
    stable_id: str = Field(..., alias="stableId")
    display_name: str | None = Field(default=None, alias="displayName")
    file_path: str | None = Field(default=None, alias="filePath")
    line_start: int | None = Field(default=None, alias="lineStart")
    line_end: int | None = Field(default=None, alias="lineEnd")
    symbol: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_snippet_id: str | None = Field(default=None, alias="evidenceSnippetId")


class SourceGraphEdge(_ContractModel):
    source_graph_edge_id: str | None = Field(default=None, alias="sourceGraphEdgeId")
    edge_kind: str = Field(..., alias="edgeKind")
    source_graph_node_id: str | None = Field(default=None, alias="sourceGraphNodeId")
    target_graph_node_id: str | None = Field(default=None, alias="targetGraphNodeId")
    source_stable_id: str | None = Field(default=None, alias="sourceStableId")
    target_stable_id: str | None = Field(default=None, alias="targetStableId")
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _has_edge_endpoints(self) -> "SourceGraphEdge":
        if not (self.source_graph_node_id or self.source_stable_id):
            raise ValueError("source graph edge requires sourceGraphNodeId or sourceStableId")
        if not (self.target_graph_node_id or self.target_stable_id):
            raise ValueError("source graph edge requires targetGraphNodeId or targetStableId")
        return self


class SourceRichIrArtifact(_ContractModel):
    rich_ir_artifact_id: str | None = Field(default=None, alias="richIrArtifactId")
    artifact_kind: str = Field(..., alias="artifactKind")
    media_type: str = Field(default="application/json", alias="mediaType")
    uri: str | None = None
    checksum_sha256: str = Field(..., alias="checksumSha256")
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class SourceCodeKgIngestRequest(_ContractModel):
    schema_version: Literal["s5-source-code-kg-ingest-request-v1"] = Field(
        default="s5-source-code-kg-ingest-request-v1", alias="schemaVersion"
    )
    repository_snapshot: SourceRepositorySnapshot = Field(..., alias="repositorySnapshot")
    source_artifacts: list[SourceRepositoryArtifact] = Field(default_factory=list, alias="sourceArtifacts")
    build_context: SourceBuildContext = Field(..., alias="buildContext")
    analysis_artifact_set: SourceAnalysisArtifactSet = Field(..., alias="analysisArtifactSet")
    evidence_snippets: list[SourceEvidenceSnippet] = Field(default_factory=list, alias="evidenceSnippets")
    graph_nodes: list[SourceGraphNode] = Field(default_factory=list, alias="graphNodes")
    graph_edges: list[SourceGraphEdge] = Field(default_factory=list, alias="graphEdges")
    rich_ir_artifacts: list[SourceRichIrArtifact] = Field(default_factory=list, alias="richIrArtifacts")


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
