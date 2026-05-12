"""Dated embedding/reranker model registry for S5 GraphRAG policy.

The registry is a transparent contract surface, not a dynamic model loader.  It
records what S5 considered and why the current runtime remains dependency-stable
until an explicit re-index/model-migration goal is run.
"""

from __future__ import annotations

from typing import Any

REGISTRY_VERSION = "s5-model-registry-2026-05-11"
CURRENT_DEFAULT_EMBEDDING_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

MODEL_CANDIDATES: list[dict[str, Any]] = [
    {
        "modelId": CURRENT_DEFAULT_EMBEDDING_MODEL,
        "role": "embedding",
        "deployment": "local-fastembed",
        "mandatoryDefault": True,
        "modelBackedRuntime": True,
        "dependencyImpact": "existing_dependency",
        "recommendedFor": ["current_threat_knowledge", "current_code_functions"],
        "sourceRefs": ["services/knowledge-base/app/rag/threat_search.py"],
        "decision": "Keep for this goal to avoid dimension/re-index churn.",
    },
    {
        "modelId": "Qwen/Qwen3-Embedding",
        "role": "embedding",
        "deployment": "local_or_hosted",
        "mandatoryDefault": False,
        "dependencyImpact": "large_model_download_and_reindex_required",
        "recommendedFor": ["future_multilingual_retrieval", "future_code_text_experiment"],
        "sourceRefs": ["https://qwenlm.github.io/blog/qwen3-embedding/"],
        "decision": "Candidate only; requires explicit model migration.",
    },
    {
        "modelId": "Qwen/Qwen3-Reranker",
        "role": "reranker",
        "deployment": "local_or_hosted",
        "mandatoryDefault": False,
        "dependencyImpact": "large_model_download_or_api_required",
        "recommendedFor": ["future_model_backed_rerank"],
        "sourceRefs": ["https://qwenlm.github.io/blog/qwen3-embedding/"],
        "decision": "Candidate only; deterministic reranker is runtime default now.",
    },
    {
        "modelId": "BAAI/bge-m3",
        "role": "embedding",
        "deployment": "local",
        "mandatoryDefault": False,
        "dependencyImpact": "model_download_and_reindex_required",
        "recommendedFor": ["future_hybrid_dense_sparse_retrieval"],
        "sourceRefs": ["https://huggingface.co/BAAI/bge-m3"],
        "decision": "Candidate only; useful for hybrid experiments.",
    },
    {
        "modelId": "BAAI/bge-reranker-v2-m3",
        "role": "reranker",
        "deployment": "local",
        "mandatoryDefault": False,
        "dependencyImpact": "transformers_model_download_required",
        "recommendedFor": ["future_local_cross_encoder_rerank"],
        "sourceRefs": ["https://huggingface.co/BAAI/bge-reranker-v2-m3"],
        "decision": "Candidate only; no mandatory new dependency in this goal.",
    },
    {
        "modelId": "jinaai/jina-embeddings-v4",
        "role": "embedding",
        "deployment": "local_or_hosted",
        "mandatoryDefault": False,
        "dependencyImpact": "large_model_download_remote_code_and_reindex_required",
        "recommendedFor": ["future_code_text_multilingual_retrieval"],
        "sourceRefs": ["https://huggingface.co/jinaai/jina-embeddings-v4"],
        "decision": "Candidate only; heavyweight for current deterministic tests.",
    },
    {
        "modelId": "mistral/codestral-embed-2505",
        "role": "embedding",
        "deployment": "hosted_api",
        "mandatoryDefault": False,
        "dependencyImpact": "api_key_network_and_reindex_required",
        "recommendedFor": ["future_code_graph_embedding_ab_test"],
        "sourceRefs": ["https://docs.mistral.ai/models/codestral-embed-25-05", "https://docs.mistral.ai/capabilities/embeddings/code_embeddings"],
        "decision": "Hosted code candidate only.",
    },
    {
        "modelId": "voyage-code-3",
        "role": "embedding",
        "deployment": "hosted_api",
        "mandatoryDefault": False,
        "dependencyImpact": "api_key_network_and_reindex_required",
        "recommendedFor": ["future_code_graph_embedding_ab_test"],
        "sourceRefs": ["https://docs.voyageai.com/docs/embeddings"],
        "decision": "Hosted code candidate only.",
    },
    {
        "modelId": "cohere/embed-v4.0",
        "role": "embedding",
        "deployment": "hosted_api",
        "mandatoryDefault": False,
        "dependencyImpact": "api_key_network_and_reindex_required",
        "recommendedFor": ["future_multimodal_document_retrieval"],
        "sourceRefs": ["https://docs.cohere.com/docs/cohere-embed"],
        "decision": "Hosted candidate only.",
    },
    {
        "modelId": "cohere/rerank-v4.0",
        "role": "reranker",
        "deployment": "hosted_api",
        "mandatoryDefault": False,
        "dependencyImpact": "api_key_network_required",
        "recommendedFor": ["future_hosted_rerank"],
        "sourceRefs": ["https://docs.cohere.com/docs/rerank-2"],
        "decision": "Hosted candidate only.",
    },
    {
        "modelId": "openai/text-embedding-3-large",
        "role": "embedding",
        "deployment": "hosted_api",
        "mandatoryDefault": False,
        "dependencyImpact": "api_key_network_and_reindex_required",
        "recommendedFor": ["future_general_text_retrieval_baseline"],
        "sourceRefs": ["https://platform.openai.com/docs/models/text-embedding-3-large"],
        "decision": "Hosted general embedding candidate only.",
    },
]


def model_registry_snapshot() -> dict[str, Any]:
    return {
        "schemaVersion": REGISTRY_VERSION,
        "datedAsOf": "2026-05-11",
        "runtimeDefault": default_model_policy(),
        "candidates": list(MODEL_CANDIDATES),
    }


def default_model_policy() -> dict[str, Any]:
    return {
        "name": "s5-default-model-policy-v1",
        "embeddingModel": CURRENT_DEFAULT_EMBEDDING_MODEL,
        "embeddingModelBacked": True,
        "reranker": "s5-deterministic-method-aware-reranker",
        "rerankerModelBacked": False,
        "mandatoryNewDependency": False,
        "requiresReindex": False,
        "negativeEvidenceAllowedFromEmbeddingOnly": False,
        "registryVersion": REGISTRY_VERSION,
    }


def candidate_models_by_role(role: str) -> list[dict[str, Any]]:
    return [candidate for candidate in MODEL_CANDIDATES if candidate.get("role") == role]
