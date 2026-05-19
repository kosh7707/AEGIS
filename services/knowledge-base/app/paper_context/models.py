"""Pydantic models for S5 paper-context API requests.

The models intentionally keep the paper-facing surface narrow.  Backing S5
internals may contain verdict/advisory vocabulary; those fields are projected by
``service.py`` before anything becomes S3-visible.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.source_kg.models import SourceCodeKgIngestRequest


class _ContractModel(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}


class ProducerInputRefs(_ContractModel):
    source_root_ref: str = Field(..., alias="sourceRootRef")
    compile_context_ref: str = Field(..., alias="compileContextRef")
    build_snapshot_id: str | None = Field(default=None, alias="buildSnapshotId")
    build_unit_id: str | None = Field(default=None, alias="buildUnitId")


class SourceKgSelectors(_ContractModel):
    repository_snapshot_id: str | None = Field(default=None, alias="repositorySnapshotId")
    build_context_id: str | None = Field(default=None, alias="buildContextId")
    analysis_artifact_set_id: str | None = Field(default=None, alias="analysisArtifactSetId")
    graph_node_ids: list[str] = Field(default_factory=list, alias="graphNodeIds")
    evidence_snippet_ids: list[str] = Field(default_factory=list, alias="evidenceSnippetIds")
    rich_ir_artifact_ids: list[str] = Field(default_factory=list, alias="richIrArtifactIds")

    def has_any(self) -> bool:
        return any(
            [
                self.repository_snapshot_id,
                self.build_context_id,
                self.analysis_artifact_set_id,
                self.graph_node_ids,
                self.evidence_snippet_ids,
                self.rich_ir_artifact_ids,
            ]
        )

    def as_context_kwargs(self) -> dict[str, Any]:
        return {
            "repository_snapshot_id": self.repository_snapshot_id,
            "build_context_id": self.build_context_id,
            "analysis_artifact_set_id": self.analysis_artifact_set_id,
            "graph_node_ids": self.graph_node_ids or None,
            "evidence_snippet_ids": self.evidence_snippet_ids or None,
            "rich_ir_artifact_ids": self.rich_ir_artifact_ids or None,
        }

    def as_paper_dict(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True, exclude_none=True)


class SourceContext(_ContractModel):
    source_root: str | None = Field(default=None, alias="sourceRoot")
    compile_commands_path: str | None = Field(default=None, alias="compileCommandsPath")
    language: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    source_kg_ingest_request: SourceCodeKgIngestRequest | None = Field(default=None, alias="sourceKgIngestRequest")
    source_kg_selectors: SourceKgSelectors | None = Field(default=None, alias="sourceKgSelectors")


class BasePaperRequest(_ContractModel):
    schema_version: str = Field(..., alias="schemaVersion")
    case_id: str = Field(..., alias="caseId")
    build_target_id: str = Field(..., alias="buildTargetId")
    paper_run_id: str = Field(..., alias="paperRunId")
    request_id: str = Field(..., alias="requestId")
    idempotency_key: str = Field(..., alias="idempotencyKey")
    visibility_mode: str = Field(..., alias="visibilityMode")
    forbidden_leakage_classes: list[str] = Field(..., alias="forbiddenLeakageClasses")


class PrepareCodeKbRequest(BasePaperRequest):
    schema_version: Literal["s5-prepare-code-kb-request-v1"] = Field(..., alias="schemaVersion")
    producer_input_refs: ProducerInputRefs = Field(..., alias="producerInputRefs")
    source_context: SourceContext = Field(..., alias="sourceContext")
    source_root_ref: str | None = Field(default=None, alias="sourceRootRef")
    compile_context_ref: str | None = Field(default=None, alias="compileContextRef")
    build_snapshot_id: str | None = Field(default=None, alias="buildSnapshotId")
    build_unit_id: str | None = Field(default=None, alias="buildUnitId")
    implementation_mode: Literal["live", "file_backed"] | None = Field(default=None, alias="implementationMode")
    file_backed_artifact_ref: str | None = Field(default=None, alias="fileBackedArtifactRef")


class SourceAnchor(_ContractModel):
    file_ref: str | None = Field(default=None, alias="fileRef")
    display_path: str | None = Field(default=None, alias="displayPath")
    function_ref: str | None = Field(default=None, alias="functionRef")
    symbol_name: str | None = Field(default=None, alias="symbolName")
    line_start: int | None = Field(default=None, alias="lineStart")
    line_end: int | None = Field(default=None, alias="lineEnd")


class LibraryIdentity(_ContractModel):
    name: str | None = None
    version: str | None = None
    confidence: str | None = None
    purl: str | None = None
    cpe: str | None = None
    package_identity_id: str | None = Field(default=None, alias="packageIdentityId")
    repo_url: str | None = Field(default=None, alias="repoUrl")


class FindingPayload(_ContractModel):
    finding_id: str = Field(..., alias="findingId")
    s3_evidence_refs: list[str] = Field(default_factory=list, alias="s3EvidenceRefs")
    source_anchors: list[SourceAnchor] = Field(default_factory=list, alias="sourceAnchors")
    rule_id: str | None = Field(default=None, alias="ruleId")
    cwe_candidates: list[str] = Field(default_factory=list, alias="cweCandidates")
    tool_message: str | None = Field(default=None, alias="toolMessage")
    library_identity: LibraryIdentity | None = Field(default=None, alias="libraryIdentity")


class RetrieveFindingContextRequest(BasePaperRequest):
    schema_version: Literal["s5-retrieve-finding-context-request-v1"] = Field(..., alias="schemaVersion")
    finding_id: str = Field(..., alias="findingId")
    code_kb_ref: str = Field(..., alias="codeKbRef")
    source_kg_ref: str = Field(..., alias="sourceKgRef")
    finding: FindingPayload
    query_intent: Literal["finding_local_context"] = Field(..., alias="queryIntent")
    retrieval_profile: str = Field(..., alias="retrievalProfile")
    top_k: int = Field(..., alias="topK", gt=0)
    producer_input_refs: ProducerInputRefs | None = Field(default=None, alias="producerInputRefs")
    source_kg_selectors: SourceKgSelectors | None = Field(default=None, alias="sourceKgSelectors")
    max_snippet_chars: int | None = Field(default=None, alias="maxSnippetChars")
    include_neighbor_symbols: bool | None = Field(default=None, alias="includeNeighborSymbols")


class RetrieveGenericThreatContextRequest(BasePaperRequest):
    schema_version: Literal["s5-retrieve-generic-threat-context-request-v1"] = Field(..., alias="schemaVersion")
    finding_id: str = Field(..., alias="findingId")
    s3_evidence_refs: list[str] = Field(default_factory=list, alias="s3EvidenceRefs")
    cwe_candidates: list[str] = Field(default_factory=list, alias="cweCandidates")
    capec_candidates: list[str] = Field(default_factory=list, alias="capecCandidates")
    api_names: list[str] = Field(default_factory=list, alias="apiNames")
    library_identity: LibraryIdentity | None = Field(default=None, alias="libraryIdentity")
    query_intent: Literal["generic_threat_context"] = Field(..., alias="queryIntent")
    retrieval_profile: str = Field(..., alias="retrievalProfile")
    top_k: int = Field(..., alias="topK", gt=0)
