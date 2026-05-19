"""Evidence-Grounded Judge contract models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, SkipValidation, field_validator

from app.serving.query_planner import (
    CONTROL_OBJECT_TOO_LARGE_REASON,
    MAX_CONTROL_LIST_ITEMS,
    MAX_FORCE_CONTEXT_ROOT_KEYS,
    force_context_budget_too_large,
)
from app.source_kg.models import (
    MAX_CONTEXT_EVIDENCE_SNIPPET_IDS,
    MAX_CONTEXT_GRAPH_NODE_IDS,
    MAX_CONTEXT_RICH_IR_ARTIFACT_IDS,
    SourceKgSelectorId,
)


class _ContractModel(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}


class JudgeSourceContext(_ContractModel):
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


class JudgeControls(_ContractModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    exclude: list[str] = Field(default_factory=list, max_length=MAX_CONTROL_LIST_ITEMS)
    prefer: list[str] = Field(default_factory=list, max_length=MAX_CONTROL_LIST_ITEMS)
    force_context: dict[str, Any] = Field(
        default_factory=dict,
        alias="forceContext",
        max_length=MAX_FORCE_CONTEXT_ROOT_KEYS,
    )
    answer_mode: str | None = Field(default=None, alias="answerMode")
    top_k: SkipValidation[int | None] = Field(
        default=None,
        alias="topK",
        description="Final Threat Retrieval candidateEvidence count. Clamped by the S5 top-k policy and never affects affectedness authority.",
        json_schema_extra={"type": "integer", "minimum": 1},
    )

    @field_validator("force_context")
    @classmethod
    def _force_context_fits_budget(cls, value: dict[str, Any]) -> dict[str, Any]:
        if force_context_budget_too_large(value):
            raise ValueError(CONTROL_OBJECT_TOO_LARGE_REASON)
        return value


class JudgeQueryRequest(_ContractModel):
    schema_version: Literal["s5-judge-query-v1"] = Field(default="s5-judge-query-v1", alias="schemaVersion")
    question: str | None = None
    component: dict[str, Any] = Field(default_factory=dict)
    source_context: JudgeSourceContext | None = Field(default=None, alias="sourceContext")
    controls: JudgeControls = Field(default_factory=JudgeControls)
