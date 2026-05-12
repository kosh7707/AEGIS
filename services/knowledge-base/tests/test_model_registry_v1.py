from __future__ import annotations

from app.graphrag.model_registry import (
    CURRENT_DEFAULT_EMBEDDING_MODEL,
    candidate_models_by_role,
    default_model_policy,
    model_registry_snapshot,
)


def test_model_registry_keeps_current_default_dependency_stable():
    policy = default_model_policy()

    assert policy["embeddingModel"] == CURRENT_DEFAULT_EMBEDDING_MODEL
    assert policy["mandatoryNewDependency"] is False
    assert policy["requiresReindex"] is False
    assert policy["rerankerModelBacked"] is False
    assert policy["negativeEvidenceAllowedFromEmbeddingOnly"] is False


def test_model_registry_records_embedding_and_reranker_candidates_with_sources():
    snapshot = model_registry_snapshot()
    candidates = snapshot["candidates"]

    assert candidate_models_by_role("embedding")
    assert candidate_models_by_role("reranker")
    assert any("Qwen3" in candidate["modelId"] for candidate in candidates)
    assert any("bge" in candidate["modelId"].lower() for candidate in candidates)
    assert any("codestral" in candidate["modelId"].lower() for candidate in candidates)
    for candidate in candidates:
        assert candidate["sourceRefs"], candidate
        if candidate["modelId"] != CURRENT_DEFAULT_EMBEDDING_MODEL:
            assert candidate["mandatoryDefault"] is False
