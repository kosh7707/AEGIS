from __future__ import annotations

from app.contracts.acquisition import evaluate_no_hit_eligibility
from app.graphrag.retrieval_planner import (
    annotate_hit,
    build_retrieval_trace,
    canonical_method,
    method_trust,
    normalize_corpus_partitions,
    normalize_query_intent,
    plan_retrieval,
    unsafe_no_hit_basis_from_trace,
)


def test_query_intent_partition_and_method_aliases_are_canonicalized():
    assert normalize_query_intent("domain_profile_context") == "profile_context"
    assert normalize_corpus_partitions(["public_vulnerability_knowledge", "cve", "weakness"]) == [
        "public_vulnerability",
        "weakness_taxonomy",
    ]
    assert canonical_method("name_exact") == "exact_id_match"
    assert canonical_method("callsite_traversal") == "graph_expansion"
    assert canonical_method("vector_semantic", embedding_scope="global") == "global_embedding_search"
    assert method_trust("global_embedding_search") == "low"


def test_plan_retrieval_defaults_cve_discovery_to_public_vulnerability_partition():
    plan = plan_retrieval("OpenSSL CVE candidates", query_intent="cve_discovery")

    assert plan.query_intent == "cve_discovery"
    assert plan.corpus_partitions == ["public_vulnerability"]
    assert {"field": "corpusPartition", "values": ["public_vulnerability"]} in plan.filters_applied
    assert {"field": "source", "values": ["CVE"]} in plan.filters_applied
    assert plan.embedding_scope == "constrained"


def test_retrieval_trace_exposes_topk_threshold_partition_and_global_embedding_policy():
    plan = plan_retrieval(
        "legacy broad context",
        allow_global_embedding=True,
        corpus_partitions=[],
        default_intent="project_memory_context",
        top_k=7,
    )
    hit = annotate_hit(
        {"id": "doc-1", "match_type": "vector_semantic", "score": 0.42},
        rank=1,
        embedding_scope=plan.embedding_scope,
    )
    trace = build_retrieval_trace(
        plan=plan,
        hits=[hit],
        methods_attempted=["global_embedding_search"],
        methods_succeeded=["global_embedding_search"],
        relation_methods=["global_embedding_search"],
        rerankers_applied=["method_trust"],
        top_k=7,
        min_score=0.21,
        graph_depth=0,
    )

    assert trace["queryIntent"] == "project_memory_context"
    assert trace["embeddingScope"] == "global"
    assert trace["topK"] == 7
    assert trace["minScore"] == 0.21
    assert trace["thresholds"] == {"minScore": 0.21, "topK": 7, "candidatePoolK": trace["candidatePoolSize"]}
    assert trace["candidatePoolSize"] > trace["topK"]
    assert trace["topKPolicy"]["topKMeans"] == "final_returned_count"
    assert trace["candidatePoolPolicy"]["candidatePoolMeans"] == "internal_exact_vector_graph_rerank_pool"
    assert trace["rerankerPolicy"]["modelBacked"] is False
    assert trace["modelPolicy"]["mandatoryNewDependency"] is False
    assert trace["globalEmbeddingPolicy"] == {
        "allowed": True,
        "trust": "low",
        "negativeEvidenceAllowed": False,
    }
    assert hit["relationMethods"] == ["global_embedding_search"]
    assert hit["methodTrust"] == "low"


def test_global_embedding_only_no_hit_is_unsafe_for_runtime_no_hit():
    trace = {
        "embeddingScope": "global",
        "returnedCount": 0,
        "methodsAttempted": ["global_embedding_search"],
        "methodsSucceeded": ["global_embedding_search"],
    }

    assert unsafe_no_hit_basis_from_trace(trace) == "global_embedding_only_no_result"
    eligible, reasons = evaluate_no_hit_eligibility({
        "acquisitionStatus": "completed_no_hit",
        "consumerPolicy": "scoped_no_hit_record_only",
        "methodsAttempted": ["global_embedding_search"],
        "methodsSucceeded": ["global_embedding_search"],
        "providerState": {"state": "not_applicable"},
        "projectionState": {"state": "not_applicable"},
        "scope": {
            "methodsRequiredForNoHit": ["global_embedding_search"],
            "noHitBasis": "global_embedding_only_no_result",
        },
    })

    assert eligible is False
    assert "NO_HIT_BASIS_UNSAFE:global_embedding_only_no_result" in reasons


def test_plan_retrieval_extracts_cpp_lexical_signals_and_separates_candidate_pool():
    plan = plan_retrieval(
        "Gateway::runCommand uses popen after parsing CAN frame",
        query_intent="code_context",
        top_k=4,
        graph_depth=3,
        profiles=["embedded-system-specialization"],
    )

    assert plan.final_top_k == 4
    assert plan.candidate_pool_k > plan.final_top_k
    assert any(signal["canonical"] == "command_execution" for signal in plan.lexical_signals)
    assert any(signal["canonical"] == "embedded_ics_profile" for signal in plan.lexical_signals)
    assert "keyword_match" not in ["constrained_embedding_rerank"]
    assert plan.reranker_policy["negativeEvidenceAllowed"] is False
