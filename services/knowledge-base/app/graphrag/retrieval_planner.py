"""Typed GraphRAG retrieval planning and trace helpers.

G009 keeps runtime retrieval language candidate/readiness oriented.  Offline
quality metrics stay in the Golden Set harness, not in retrieval traces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.graphrag.lexical_signals import lexical_signals_for_query, matched_terms_from_signals
from app.graphrag.model_registry import default_model_policy
from app.graphrag.retrieval_policy import (
    build_retrieval_policy,
    build_score_breakdown,
    deterministic_reranker_policy,
    method_rank_weight as policy_method_rank_weight,
)

QUERY_INTENTS = {
    "weakness_context",
    "attack_pattern_context",
    "mitigation_context",
    "tool_rule_mapping",
    "package_identity_resolution",
    "candidate_cve_evaluation",
    "cve_discovery",
    "profile_context",
    "code_context",
    "project_memory_context",
    "consumer_policy_example",
}

QUERY_INTENT_ALIASES = {
    "domain_profile_context": "profile_context",
    "profile": "profile_context",
    "public_vulnerability_context": "cve_discovery",
    "cve_context": "cve_discovery",
    "code": "code_context",
}

CORPUS_PARTITION_ALIASES = {
    "weakness": "weakness_taxonomy",
    "weakness_taxonomy": "weakness_taxonomy",
    "attack": "attack_pattern",
    "capec_attack": "attack_pattern",
    "attack_pattern": "attack_pattern",
    "mitigation": "mitigation_knowledge",
    "mitigation_knowledge": "mitigation_knowledge",
    "tool_rule_mapping": "tool_rule",
    "tool_rule": "tool_rule",
    "package": "package_identity",
    "package_identity": "package_identity",
    "public_vulnerability_knowledge": "public_vulnerability",
    "public_vulnerability": "public_vulnerability",
    "cve": "public_vulnerability",
    "domain_profile_context": "specialization_profile",
    "profile": "specialization_profile",
    "specialization_profile": "specialization_profile",
    "code_graph": "code_graph",
    "structural_code_projection": "code_graph",
    "contract_policy": "contract_policy",
    "evidence_policy": "contract_policy",
}

DEFAULT_PARTITIONS_BY_INTENT = {
    "weakness_context": ["weakness_taxonomy"],
    "attack_pattern_context": ["attack_pattern"],
    "mitigation_context": ["mitigation_knowledge"],
    "tool_rule_mapping": ["tool_rule"],
    "package_identity_resolution": ["package_identity"],
    "candidate_cve_evaluation": ["public_vulnerability"],
    "cve_discovery": ["public_vulnerability"],
    "profile_context": ["specialization_profile"],
    "code_context": ["code_graph"],
    "project_memory_context": [],
    "consumer_policy_example": ["contract_policy"],
}

SOURCE_FALLBACK_BY_PARTITION = {
    "weakness_taxonomy": ["CWE"],
    "attack_pattern": ["CAPEC", "ATT&CK", "ATTACK"],
    "public_vulnerability": ["CVE"],
}

CANONICAL_METHODS = {
    "exact_id_match",
    "curated_mapping",
    "direct_source_relation",
    "provider_range_eval",
    "graph_expansion",
    "keyword_match",
    "embedding_similarity",
    "constrained_embedding_rerank",
    "global_embedding_search",
    "profile_signal",
}

METHOD_ALIASES = {
    "id_exact": "exact_id_match",
    "name_exact": "exact_id_match",
    "graph_neighbor": "graph_expansion",
    "callsite_traversal": "graph_expansion",
    "vector_semantic": "constrained_embedding_rerank",
    "semantic_vector": "constrained_embedding_rerank",
}

METHOD_TRUST = {
    "exact_id_match": "high",
    "curated_mapping": "high",
    "direct_source_relation": "high",
    "provider_range_eval": "high",
    "graph_expansion": "medium",
    "profile_signal": "context_only",
    "keyword_match": "weak",
    "embedding_similarity": "weak",
    "constrained_embedding_rerank": "medium",
    "global_embedding_search": "low",
}

METHOD_RANK_WEIGHT = {
    "exact_id_match": 100,
    "curated_mapping": 95,
    "direct_source_relation": 90,
    "provider_range_eval": 90,
    "graph_expansion": 70,
    "constrained_embedding_rerank": 60,
    "embedding_similarity": 45,
    "keyword_match": 35,
    "profile_signal": 30,
    "global_embedding_search": 10,
}

_ID_RE = re.compile(r"\b(?:CWE-\d+|CVE-\d{4}-\d+|CAPEC-\d+|T\d{4}(?:\.\d+)?)\b", re.IGNORECASE)


@dataclass(frozen=True)
class RetrievalPlan:
    query: str
    query_intent: str
    corpus_partitions: list[str]
    source_filter: list[str] | None
    profiles: list[str] = field(default_factory=list)
    allow_global_embedding: bool = False
    embedding_scope: str = "constrained"
    filters_applied: list[dict[str, Any]] = field(default_factory=list)
    fallback_trace: list[dict[str, Any]] = field(default_factory=list)
    matched_terms: list[str] = field(default_factory=list)
    lexical_signals: list[dict[str, Any]] = field(default_factory=list)
    candidate_pool_k: int = 5
    final_top_k: int = 5
    candidate_pool_policy: dict[str, Any] = field(default_factory=dict)
    top_k_policy: dict[str, Any] = field(default_factory=dict)
    reranker_policy: dict[str, Any] = field(default_factory=dict)
    model_policy: dict[str, Any] = field(default_factory=dict)


def normalize_query_intent(query_intent: str | None, *, default: str = "weakness_context") -> str:
    raw = (query_intent or default or "weakness_context").strip()
    normalized = QUERY_INTENT_ALIASES.get(raw, raw)
    return normalized if normalized in QUERY_INTENTS else default


def normalize_corpus_partitions(values: list[str] | None) -> list[str]:
    normalized: list[str] = []
    for value in values or []:
        key = str(value).strip()
        if not key:
            continue
        item = CORPUS_PARTITION_ALIASES.get(key, key)
        if item not in normalized:
            normalized.append(item)
    return normalized


def source_fallback_for_partitions(partitions: list[str]) -> list[str]:
    source_filter: list[str] = []
    for partition in partitions:
        for source in SOURCE_FALLBACK_BY_PARTITION.get(partition, []):
            if source not in source_filter:
                source_filter.append(source)
    return source_filter


def canonical_method(method: str, *, embedding_scope: str = "constrained") -> str:
    mapped = METHOD_ALIASES.get(method, method)
    if mapped == "constrained_embedding_rerank" and embedding_scope == "global":
        return "global_embedding_search"
    return mapped if mapped in CANONICAL_METHODS else method


def method_trust(method: str) -> str:
    return METHOD_TRUST.get(method, "unknown")


def method_rank_weight(method: str) -> int:
    return policy_method_rank_weight(method)


def plan_retrieval(
    query: str,
    *,
    query_intent: str | None = None,
    corpus_partitions: list[str] | None = None,
    source_filter: list[str] | None = None,
    profiles: list[str] | None = None,
    allow_global_embedding: bool | None = None,
    default_intent: str = "weakness_context",
    top_k: int | None = None,
    graph_depth: int = 2,
) -> RetrievalPlan:
    intent = normalize_query_intent(query_intent, default=default_intent)
    explicit_partitions = normalize_corpus_partitions(corpus_partitions)
    partitions = explicit_partitions or list(DEFAULT_PARTITIONS_BY_INTENT.get(intent, []))
    fallback_sources = source_fallback_for_partitions(partitions)
    effective_source_filter = source_filter if source_filter is not None else (fallback_sources or None)

    typed_or_filtered = bool(query_intent or corpus_partitions or source_filter or partitions)
    if allow_global_embedding is None:
        allow_global_embedding = not typed_or_filtered
    embedding_scope = "global" if allow_global_embedding and not partitions and not source_filter else "constrained"

    filters: list[dict[str, Any]] = []
    fallback_trace: list[dict[str, Any]] = []
    if partitions:
        filters.append({"field": "corpusPartition", "values": partitions})
        if fallback_sources:
            fallback_trace.append({
                "from": "corpusPartition",
                "to": "source_filter",
                "reason": "legacy_payload_may_lack_corpusPartition",
                "values": fallback_sources,
            })
    if effective_source_filter:
        filters.append({"field": "source", "values": effective_source_filter})
    if profiles:
        filters.append({"field": "profiles", "values": list(profiles)})

    id_terms = []
    for match in _ID_RE.finditer(query or ""):
        term = match.group(0).upper()
        if term not in id_terms:
            id_terms.append(term)

    lexical_signals = lexical_signals_for_query(query or "", profiles=profiles)
    matched_terms = list(id_terms)
    for term in matched_terms_from_signals(lexical_signals):
        if term not in matched_terms:
            matched_terms.append(term)

    sizing = build_retrieval_policy(
        query_intent=intent,
        requested_top_k=top_k,
        matched_terms=id_terms,
        lexical_signals=lexical_signals,
        graph_depth=graph_depth,
    )

    return RetrievalPlan(
        query=query or "",
        query_intent=intent,
        corpus_partitions=partitions,
        source_filter=effective_source_filter,
        profiles=list(profiles or []),
        allow_global_embedding=bool(allow_global_embedding),
        embedding_scope=embedding_scope,
        filters_applied=filters,
        fallback_trace=fallback_trace,
        matched_terms=matched_terms,
        lexical_signals=lexical_signals,
        candidate_pool_k=sizing.candidate_pool_k,
        final_top_k=sizing.final_top_k,
        candidate_pool_policy=sizing.candidate_pool_policy(),
        top_k_policy=sizing.top_k_policy(),
        reranker_policy=deterministic_reranker_policy(),
        model_policy=default_model_policy(),
    )


def methods_from_match_types(match_types: list[str], *, embedding_scope: str = "constrained") -> list[str]:
    methods: list[str] = []
    for match_type in match_types:
        method = canonical_method(match_type, embedding_scope=embedding_scope)
        if method not in methods:
            methods.append(method)
    return methods


def annotate_hit(
    hit: dict[str, Any],
    *,
    rank: int,
    embedding_scope: str,
    rerank_score: float | None = None,
    score_breakdown: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out = dict(hit)
    match_type = str(out.get("match_type") or out.get("matchType") or "")
    method = canonical_method(match_type, embedding_scope=embedding_scope)
    relation_methods = [method] if method else []
    out["relationMethods"] = relation_methods
    out["methodTrust"] = method_trust(method) if method else "unknown"
    base_score = float(out.get("score", 0) or 0)
    score_breakdown = score_breakdown or build_score_breakdown(base_score=base_score, method=method)
    out["scoreBreakdown"] = score_breakdown
    out["ranking"] = {
        "rank": rank,
        "rerankScore": rerank_score if rerank_score is not None else score_breakdown["finalRerankScore"],
        "methodWeight": method_rank_weight(method) if method else 0,
        "scoreBreakdown": score_breakdown,
    }
    return out


def build_retrieval_trace(
    *,
    plan: RetrievalPlan,
    hits: list[dict[str, Any]],
    methods_attempted: list[str],
    methods_succeeded: list[str] | None = None,
    relation_methods: list[str] | None = None,
    rerankers_applied: list[str] | None = None,
    top_k: int,
    min_score: float,
    graph_depth: int,
    projection_state: dict[str, Any] | None = None,
    provider_state: dict[str, Any] | None = None,
    extra_fallback_trace: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    relation_methods = relation_methods or methods_from_match_types(
        [str(hit.get("match_type", "")) for hit in hits],
        embedding_scope=plan.embedding_scope,
    )
    methods_used = [m for m in relation_methods if m]
    if methods_succeeded is None:
        methods_succeeded = list(methods_used)
    return {
        "queryIntent": plan.query_intent,
        "corpusPartitionsSearched": list(plan.corpus_partitions),
        "candidateSetSize": len(hits),
        "candidatePoolSize": plan.candidate_pool_k,
        "returnedCount": len(hits),
        "candidatePoolPolicy": dict(plan.candidate_pool_policy),
        "topKPolicy": dict(plan.top_k_policy),
        "rerankerPolicy": dict(plan.reranker_policy),
        "modelPolicy": dict(plan.model_policy),
        "methodsUsed": methods_used,
        "methodsAttempted": list(methods_attempted),
        "methodsSucceeded": list(methods_succeeded),
        "filtersApplied": list(plan.filters_applied),
        "rerankersApplied": list(rerankers_applied or []),
        "embeddingUsed": any(m in methods_attempted for m in {"constrained_embedding_rerank", "global_embedding_search", "embedding_similarity"}),
        "embeddingScope": plan.embedding_scope,
        "keywordUsed": "keyword_match" in methods_attempted or bool(plan.lexical_signals),
        "matchedTerms": list(plan.matched_terms),
        "lexicalSignals": list(plan.lexical_signals),
        "relationMethods": list(relation_methods),
        "profileBoostsApplied": list(plan.profiles),
        "projectionState": projection_state or {"state": "not_applicable"},
        "providerState": provider_state or {"state": "not_applicable"},
        "fallbackTrace": [*plan.fallback_trace, *(extra_fallback_trace or [])],
        "topK": top_k,
        "minScore": min_score,
        "graphDepth": graph_depth,
        "thresholds": {"minScore": min_score, "topK": top_k, "candidatePoolK": plan.candidate_pool_k},
        "globalEmbeddingPolicy": {
            "allowed": bool(plan.allow_global_embedding),
            "trust": "low",
            "negativeEvidenceAllowed": False,
        },
    }


def unsafe_no_hit_basis_from_trace(trace: dict[str, Any]) -> str:
    methods = set(trace.get("methodsUsed") or trace.get("methodsSucceeded") or trace.get("methodsAttempted") or [])
    if methods and methods <= {"keyword_match"}:
        return "keyword_only_no_result"
    if methods and methods <= {"embedding_similarity", "constrained_embedding_rerank"}:
        return "embedding_only_no_result"
    if methods and methods <= {"global_embedding_search"}:
        return "global_embedding_only_no_result"
    if trace.get("embeddingScope") == "global" and not trace.get("returnedCount"):
        return "global_embedding_only_no_result"
    return "completed_required_methods"
