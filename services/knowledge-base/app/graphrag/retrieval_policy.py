"""Deterministic S5 retrieval sizing and reranking policy.

This module deliberately avoids model downloads/API calls.  It makes the
runtime GraphRAG policy visible so consumers can distinguish final ``top_k``
from the broader internal candidate pool and can see when ranking was a local
method-aware policy rather than a model-backed reranker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MIN_FINAL_TOP_K = 1
MAX_FINAL_TOP_K = 50
MAX_CANDIDATE_POOL_K = 120
DEFAULT_FINAL_TOP_K = 5

METHOD_RANK_WEIGHTS: dict[str, int] = {
    "affectedness_evidence": 110,
    "exact_id_match": 100,
    "curated_mapping": 95,
    "direct_source_relation": 90,
    "provider_range_eval": 90,
    "package_identity_context": 80,
    "graph_expansion": 70,
    "constrained_embedding_rerank": 60,
    "embedding_similarity": 45,
    "keyword_match": 35,
    "profile_signal": 30,
    "global_embedding_search": 10,
}

INTENT_POOL_FLOORS: dict[str, int] = {
    "judge_threat_context": 24,
    "code_context": 24,
    "package_identity_resolution": 24,
    "candidate_cve_evaluation": 24,
    "cve_discovery": 24,
    "profile_context": 20,
    "project_memory_context": 20,
    "attack_pattern_context": 18,
    "weakness_context": 16,
    "mitigation_context": 16,
    "tool_rule_mapping": 16,
    "consumer_policy_example": 12,
}

INTENT_POOL_MULTIPLIERS: dict[str, int] = {
    "judge_threat_context": 5,
    "code_context": 5,
    "package_identity_resolution": 5,
    "candidate_cve_evaluation": 5,
    "cve_discovery": 5,
    "profile_context": 4,
    "project_memory_context": 4,
    "attack_pattern_context": 4,
    "weakness_context": 3,
    "mitigation_context": 3,
    "tool_rule_mapping": 3,
    "consumer_policy_example": 2,
}


@dataclass(frozen=True)
class RetrievalPolicyDecision:
    """Sizing decision for a single retrieval request."""

    requested_top_k: int
    final_top_k: int
    candidate_pool_k: int
    min_final_top_k: int = MIN_FINAL_TOP_K
    max_final_top_k: int = MAX_FINAL_TOP_K
    max_candidate_pool_k: int = MAX_CANDIDATE_POOL_K
    reasons: tuple[str, ...] = ()

    def top_k_policy(self) -> dict[str, Any]:
        return {
            "name": "s5-top-k-policy-v1",
            "requestedTopK": self.requested_top_k,
            "finalTopK": self.final_top_k,
            "acceptedControlTopK": self.final_top_k,
            "minFinalTopK": self.min_final_top_k,
            "maxFinalTopK": self.max_final_top_k,
            "topKMeans": "final_returned_count",
        }

    def candidate_pool_policy(self) -> dict[str, Any]:
        return {
            "name": "s5-candidate-pool-policy-v1",
            "candidatePoolK": self.candidate_pool_k,
            "candidatePoolMeans": "internal_exact_vector_graph_rerank_pool",
            "maxCandidatePoolK": self.max_candidate_pool_k,
            "reasons": list(self.reasons),
        }


def clamp_top_k(value: int | None) -> int:
    try:
        requested = int(value if value is not None else DEFAULT_FINAL_TOP_K)
    except (TypeError, ValueError):
        requested = DEFAULT_FINAL_TOP_K
    return max(MIN_FINAL_TOP_K, min(MAX_FINAL_TOP_K, requested))


def build_retrieval_policy(
    *,
    query_intent: str,
    requested_top_k: int | None,
    matched_terms: list[str] | None = None,
    lexical_signals: list[dict[str, Any]] | None = None,
    graph_depth: int = 2,
) -> RetrievalPolicyDecision:
    """Return final-top-k and internal-candidate-pool sizing.

    ``top_k`` is the final response count.  The candidate pool is intentionally
    larger so S5 can fuse exact, graph, lexical, and embedding candidates before
    truncating the final answer.
    """

    requested = int(requested_top_k if requested_top_k is not None else DEFAULT_FINAL_TOP_K)
    final_top_k = clamp_top_k(requested)
    reasons: list[str] = [f"intent:{query_intent}"]

    multiplier = INTENT_POOL_MULTIPLIERS.get(query_intent, 3)
    floor = INTENT_POOL_FLOORS.get(query_intent, 16)
    pool = max(final_top_k * multiplier, floor, final_top_k + 8)

    id_terms = list(matched_terms or [])
    if id_terms:
        pool = max(pool, final_top_k * 2 + len(id_terms) * 4)
        reasons.append("id_terms_present")

    signal_count = len(lexical_signals or [])
    if signal_count:
        pool += min(16, signal_count * 2)
        reasons.append("lexical_signals_present")

    if graph_depth > 1:
        pool += min(12, max(0, graph_depth - 1) * 4)
        reasons.append("graph_depth_expansion")

    candidate_pool_k = max(final_top_k, min(MAX_CANDIDATE_POOL_K, pool))
    return RetrievalPolicyDecision(
        requested_top_k=requested,
        final_top_k=final_top_k,
        candidate_pool_k=candidate_pool_k,
        reasons=tuple(reasons),
    )


def deterministic_reranker_policy() -> dict[str, Any]:
    return {
        "name": "s5-deterministic-method-aware-reranker",
        "version": "v1",
        "deterministic": True,
        "modelBacked": False,
        "negativeEvidenceAllowed": False,
        "methodWeights": dict(METHOD_RANK_WEIGHTS),
        "ordering": [
            "affectedness_evidence",
            "exact_id_match",
            "curated_mapping",
            "direct_source_relation",
            "provider_range_eval",
            "package_identity_context",
            "graph_expansion",
            "constrained_embedding_rerank",
            "embedding_similarity",
            "keyword_match",
            "profile_signal",
            "global_embedding_search",
        ],
    }


def method_rank_weight(method: str) -> int:
    return METHOD_RANK_WEIGHTS.get(method, 0)


def lexical_boost_for_hit(hit: dict[str, Any], lexical_signals: list[dict[str, Any]] | None) -> float:
    """Small deterministic boost when a hit visibly aligns with lexical signals."""

    signals = lexical_signals or []
    if not signals:
        return 0.0
    haystack = " ".join(
        str(hit.get(field, ""))
        for field in ("id", "name", "title", "source", "threat_category", "file")
    ).lower()
    matched = 0
    for signal in signals:
        terms = [str(signal.get("term", "")), str(signal.get("canonical", ""))]
        aliases = signal.get("aliases") or []
        terms.extend(str(alias) for alias in aliases)
        if any(term and term.lower() in haystack for term in terms):
            matched += 1
    return min(5.0, matched * 0.75)


def build_score_breakdown(
    *,
    base_score: float,
    method: str,
    lexical_boost: float = 0.0,
    profile_boost: float = 0.0,
) -> dict[str, Any]:
    method_weight = method_rank_weight(method)
    final_score = method_weight + base_score + lexical_boost + profile_boost
    return {
        "baseScore": base_score,
        "methodWeight": method_weight,
        "lexicalBoost": round(lexical_boost, 6),
        "profileBoost": round(profile_boost, 6),
        "finalRerankScore": round(final_score, 6),
    }
