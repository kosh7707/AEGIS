"""Evidence-Grounded Judge contract models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class _ContractModel(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}


class JudgeSourceContext(_ContractModel):
    repository_snapshot_id: str | None = Field(default=None, alias="repositorySnapshotId")
    build_context_id: str | None = Field(default=None, alias="buildContextId")
    analysis_artifact_set_id: str | None = Field(default=None, alias="analysisArtifactSetId")
    graph_node_ids: list[str] = Field(default_factory=list, alias="graphNodeIds")
    evidence_snippet_ids: list[str] = Field(default_factory=list, alias="evidenceSnippetIds")
    rich_ir_artifact_ids: list[str] = Field(default_factory=list, alias="richIrArtifactIds")


class JudgeControls(_ContractModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    exclude: list[str] = Field(default_factory=list)
    prefer: list[str] = Field(default_factory=list)
    force_context: dict[str, Any] = Field(default_factory=dict, alias="forceContext")
    answer_mode: str | None = Field(default=None, alias="answerMode")


class JudgeQueryRequest(_ContractModel):
    schema_version: Literal["s5-judge-query-v1"] = Field(default="s5-judge-query-v1", alias="schemaVersion")
    question: str | None = None
    component: dict[str, Any] = Field(default_factory=dict)
    source_context: JudgeSourceContext | None = Field(default=None, alias="sourceContext")
    controls: JudgeControls = Field(default_factory=JudgeControls)
