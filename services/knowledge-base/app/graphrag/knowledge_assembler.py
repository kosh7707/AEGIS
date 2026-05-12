"""KnowledgeAssembler — 하이브리드 검색 (ID 직접조회 + 벡터 + 그래프 보강 + RRF)."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Protocol

from app.graphrag.retrieval_planner import (
    RetrievalPlan,
    annotate_hit,
    build_retrieval_trace,
    canonical_method,
    method_rank_weight,
    methods_from_match_types,
    plan_retrieval,
)
from app.graphrag.retrieval_policy import build_score_breakdown, lexical_boost_for_hit
from app.graphrag.vector_search import VectorSearch

if TYPE_CHECKING:
    from app.rag.threat_search import ThreatHit

logger = logging.getLogger(__name__)

# 쿼리에서 CWE/CVE/ATT&CK/CAPEC ID를 추출하는 패턴
_ID_PATTERNS = [
    re.compile(r"\b(CWE-\d+)\b", re.IGNORECASE),
    re.compile(r"\b(CVE-\d{4}-\d+)\b", re.IGNORECASE),
    re.compile(r"\b(CAPEC-\d+)\b", re.IGNORECASE),
    re.compile(r"\b(T\d{4}(?:\.\d+)?)\b"),  # ATT&CK technique IDs
]


def _extract_ids(query: str) -> list[str]:
    """쿼리에서 위협 DB ID를 추출한다."""
    ids = []
    for pattern in _ID_PATTERNS:
        for match in pattern.finditer(query):
            raw = match.group(1)
            if raw.upper().startswith(("CWE", "CVE", "CAPEC")):
                raw = raw.upper()
            if raw not in ids:
                ids.append(raw)
    return ids


class GraphLike(Protocol):
    """Neo4jGraph 공통 인터페이스."""

    def get_related(self, node_id: str) -> dict[str, list[str]]: ...
    def get_node_info(self, node_id: str) -> dict | None: ...
    def neighbors(self, node_id: str, depth: int = 2) -> list[str]: ...


class KnowledgeAssembler:
    """하이브리드 검색: ID 직접조회 + 벡터 유사도 + 그래프 보강 + RRF."""

    def __init__(
        self,
        vector_search: VectorSearch,
        relation_graph: GraphLike,
        *,
        neighbor_score: float = 0.8,
        rrf_k: int = 60,
    ) -> None:
        self._vector = vector_search
        self._graph = relation_graph
        self._neighbor_score = neighbor_score
        self._rrf_k = rrf_k

    def _enrich_with_graph(
        self, node_id: str, hit_dict: dict,
    ) -> tuple[set[str], set[str], set[str]]:
        """그래프 관계를 hit에 추가하고 관련 ID 집합을 반환한다."""
        cwe: set[str] = set()
        cve: set[str] = set()
        attack: set[str] = set()
        related = self._graph.get_related(node_id)
        if related:
            hit_dict["graph_relations"] = related
            cwe.update(related.get("cwe", []))
            cve.update(related.get("cve", []))
            attack.update(related.get("attack", []))
        return cwe, cve, attack

    def _path_id_exact(
        self,
        extracted_ids: list[str],
        seen_ids: set[str],
        graph_depth: int,
        top_k: int,
        source_filter: list[str] | None = None,
    ) -> tuple[list[dict], set[str], set[str], set[str]]:
        """경로 1: ID 직접 조회 + 그래프 이웃."""
        enriched_hits: list[dict] = []
        graph_neighbor_hits: list[dict] = []
        all_cwe: set[str] = set()
        all_cve: set[str] = set()
        all_attack: set[str] = set()

        for eid in extracted_ids:
            if eid in seen_ids:
                continue

            node_info = self._graph.get_node_info(eid)
            if node_info is None:
                continue

            # 소스 필터링
            if source_filter and node_info.get("source", "") not in source_filter:
                continue

            hit_dict = {
                "id": node_info.get("id", eid),
                "source": node_info.get("source", ""),
                "title": node_info.get("title", ""),
                "score": 1.0,
                "threat_category": node_info.get("threat_category", ""),
                "match_type": "id_exact",
            }

            cwe, cve, att = self._enrich_with_graph(eid, hit_dict)
            all_cwe |= cwe
            all_cve |= cve
            all_attack |= att

            # 이웃 노드 수집
            neighbor_ids = self._graph.neighbors(eid, depth=min(graph_depth, 2))
            for nid in neighbor_ids[:10]:
                if nid in seen_ids:
                    continue
                ninfo = self._graph.get_node_info(nid)
                if not ninfo:
                    continue
                if source_filter and ninfo.get("source", "") not in source_filter:
                    continue
                neighbor_dict = {
                    "id": ninfo.get("id", nid),
                    "source": ninfo.get("source", ""),
                    "title": ninfo.get("title", ""),
                    "score": self._neighbor_score,
                    "threat_category": ninfo.get("threat_category", ""),
                    "match_type": "graph_neighbor",
                }
                n_cwe, n_cve, n_att = self._enrich_with_graph(nid, neighbor_dict)
                all_cwe |= n_cwe
                all_cve |= n_cve
                all_attack |= n_att
                graph_neighbor_hits.append(neighbor_dict)
                seen_ids.add(nid)

            enriched_hits.append(hit_dict)
            seen_ids.add(eid)

        # 이웃 hits를 top_k 범위 내에서 추가
        remaining = max(0, top_k - len(enriched_hits))
        enriched_hits.extend(graph_neighbor_hits[:remaining])

        return enriched_hits, all_cwe, all_cve, all_attack

    def _path_vector_semantic(
        self,
        query: str,
        seen_ids: set[str],
        top_k: int,
        min_score: float,
        plan: RetrievalPlan,
        source_filter: list[str] | None = None,
        strict_source_filter: bool = False,
    ) -> tuple[list[dict], set[str], set[str], set[str], list[dict[str, object]]]:
        """경로 2: 벡터 시맨틱 검색 + 그래프 보강."""
        enriched_hits: list[dict] = []
        all_cwe: set[str] = set()
        all_cve: set[str] = set()
        all_attack: set[str] = set()
        fallback_trace: list[dict[str, object]] = []

        if plan.corpus_partitions:
            vector_hits = self._vector.search(
                query,
                top_k=top_k,
                min_score=min_score,
                corpus_partitions=plan.corpus_partitions,
            )
            if not vector_hits and source_filter:
                fallback_trace.append({
                    "from": "corpusPartition",
                    "to": "source_filter",
                    "reason": "no_vector_hits_with_corpus_partition_filter",
                    "values": source_filter,
                })
                vector_hits = self._vector.search(
                    query, top_k=top_k, min_score=min_score, source_filter=source_filter,
                )
        else:
            vector_hits = self._vector.search(
                query, top_k=top_k, min_score=min_score, source_filter=source_filter,
            )

        for hit in vector_hits:
            if hit.id in seen_ids:
                continue
            if (
                (strict_source_filter or not plan.corpus_partitions)
                and source_filter
                and hit.source not in source_filter
            ):
                continue
            if len(enriched_hits) >= top_k:
                break

            hit_dict = {
                "id": hit.id,
                "source": hit.source,
                "title": hit.title,
                "score": hit.score,
                "threat_category": hit.threat_category,
                "match_type": "vector_semantic",
                "corpusPartition": getattr(hit, "corpus_partition", ""),
            }

            cwe, cve, att = self._enrich_with_graph(hit.id, hit_dict)
            all_cwe |= cwe
            all_cve |= cve
            all_attack |= att

            all_cwe.update(hit.related_cwe)
            all_cve.update(hit.related_cve)
            all_attack.update(hit.related_attack)

            enriched_hits.append(hit_dict)
            seen_ids.add(hit.id)

        return enriched_hits, all_cwe, all_cve, all_attack, fallback_trace

    @staticmethod
    def _apply_rrf(result_lists: list[list[dict]], k: int = 60) -> list[dict]:
        """Reciprocal Rank Fusion — 여러 검색 결과 리스트를 융합한다."""
        rrf_scores: dict[str, float] = {}
        hit_map: dict[str, dict] = {}

        for result_list in result_lists:
            for rank, hit in enumerate(result_list):
                doc_id = hit["id"]
                rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + 1.0 / (k + rank + 1)
                if doc_id not in hit_map:
                    hit_map[doc_id] = hit

        merged = []
        for doc_id, rrf_score in rrf_scores.items():
            hit = hit_map[doc_id].copy()
            hit["score"] = round(rrf_score, 6)
            merged.append(hit)

        merged.sort(key=lambda h: h["score"], reverse=True)
        return merged

    @staticmethod
    def _rerank_hits(hits: list[dict], *, plan: RetrievalPlan) -> list[dict]:
        scored: list[tuple[float, dict, dict]] = []
        for hit in hits:
            method = canonical_method(str(hit.get("match_type", "")), embedding_scope=plan.embedding_scope)
            score = float(hit.get("score", 0) or 0)
            lexical_boost = lexical_boost_for_hit(hit, plan.lexical_signals)
            profile_boost = 0.25 if plan.profiles and hit.get("match_type") == "graph_neighbor" else 0.0
            breakdown = build_score_breakdown(
                base_score=score,
                method=method,
                lexical_boost=lexical_boost,
                profile_boost=profile_boost,
            )
            scored.append((breakdown["finalRerankScore"], hit, breakdown))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            annotate_hit(
                hit,
                rank=rank,
                embedding_scope=plan.embedding_scope,
                rerank_score=round(score, 6),
                score_breakdown=breakdown,
            )
            for rank, (score, hit, breakdown) in enumerate(scored, start=1)
        ]

    def assemble(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float = 0.35,
        graph_depth: int = 2,
        exclude_ids: list[str] | None = None,
        source_filter: list[str] | None = None,
        query_intent: str | None = None,
        corpus_partitions: list[str] | None = None,
        profiles: list[str] | None = None,
        allow_global_embedding: bool | None = None,
    ) -> dict:
        """3경로 하이브리드 검색 → 병합 → 그래프 보강."""
        plan = plan_retrieval(
            query or "",
            query_intent=query_intent,
            corpus_partitions=corpus_partitions,
            source_filter=source_filter,
            profiles=profiles,
            allow_global_embedding=allow_global_embedding,
            default_intent="weakness_context",
            top_k=top_k,
            graph_depth=graph_depth,
        )
        final_top_k = plan.final_top_k
        candidate_pool_k = plan.candidate_pool_k
        if not query or not query.strip():
            trace = build_retrieval_trace(
                plan=plan,
                hits=[],
                methods_attempted=[],
                methods_succeeded=[],
                relation_methods=[],
                rerankers_applied=[],
                top_k=final_top_k,
                min_score=min_score,
                graph_depth=graph_depth,
            )
            return {
                "query": query or "",
                "hits": [],
                "total": 0,
                "extracted_ids": [],
                "related_cwe": [],
                "related_cve": [],
                "related_attack": [],
                "match_type_counts": {"id_exact": 0, "graph_neighbor": 0, "vector_semantic": 0},
                "retrievalTrace": trace,
            }

        seen_ids: set[str] = set(exclude_ids) if exclude_ids else set()
        extracted_ids = _extract_ids(query)
        effective_source_filter = plan.source_filter

        exact_hits, cwe1, cve1, att1 = self._path_id_exact(
            extracted_ids, seen_ids, graph_depth, candidate_pool_k, source_filter=source_filter,
        )
        vector_hits, cwe2, cve2, att2, vector_fallback = self._path_vector_semantic(
            query,
            seen_ids,
            candidate_pool_k,
            min_score,
            plan=plan,
            source_filter=effective_source_filter,
            strict_source_filter=source_filter is not None,
        )

        # RRF 또는 단순 정렬
        if self._rrf_k > 0:
            id_exact_list = [h for h in exact_hits if h.get("match_type") == "id_exact"]
            neighbor_list = [h for h in exact_hits if h.get("match_type") == "graph_neighbor"]
            all_hits = self._apply_rrf(
                [id_exact_list, neighbor_list, vector_hits], k=self._rrf_k,
            )
        else:
            all_hits = exact_hits + vector_hits
            all_hits.sort(key=lambda h: h.get("score", 0), reverse=True)
        all_hits = self._rerank_hits(all_hits[:candidate_pool_k], plan=plan)
        all_hits = all_hits[:final_top_k]
        relation_methods = methods_from_match_types(
            [str(hit.get("match_type", "")) for hit in all_hits],
            embedding_scope=plan.embedding_scope,
        )
        methods_attempted = []
        if extracted_ids:
            methods_attempted.extend(["exact_id_match", "graph_expansion"])
        if plan.lexical_signals:
            methods_attempted.append("keyword_match")
        methods_attempted.append("global_embedding_search" if plan.embedding_scope == "global" else "constrained_embedding_rerank")
        methods_attempted = list(dict.fromkeys(methods_attempted))
        methods_succeeded = list(dict.fromkeys(relation_methods))
        trace = build_retrieval_trace(
            plan=plan,
            hits=all_hits,
            methods_attempted=methods_attempted,
            methods_succeeded=methods_succeeded,
            relation_methods=relation_methods,
            rerankers_applied=["rrf" if self._rrf_k > 0 else "score_sort", "method_trust", "lexical_signal_policy"],
            top_k=final_top_k,
            min_score=min_score,
            graph_depth=graph_depth,
            projection_state={"state": "ready"},
            provider_state={"state": "not_applicable"},
            extra_fallback_trace=vector_fallback,
        )

        return {
            "query": query,
            "hits": all_hits,
            "total": len(all_hits),
            "extracted_ids": extracted_ids,
            "related_cwe": sorted(cwe1 | cwe2),
            "related_cve": sorted(cve1 | cve2),
            "related_attack": sorted(att1 | att2),
            "match_type_counts": {
                "id_exact": sum(1 for h in all_hits if h.get("match_type") == "id_exact"),
                "graph_neighbor": sum(1 for h in all_hits if h.get("match_type") == "graph_neighbor"),
                "vector_semantic": sum(1 for h in all_hits if h.get("match_type") == "vector_semantic"),
            },
            "retrievalTrace": trace,
        }

    def batch_assemble(self, queries: list[dict]) -> dict:
        """여러 쿼리를 순차 실행하며 교차 중복을 제거한다."""
        global_seen_ids: set[str] = set()
        results = []

        for q in queries:
            exclude = list(global_seen_ids)
            if q.get("exclude_ids"):
                exclude.extend(q["exclude_ids"])

            result = self.assemble(
                q["query"],
                top_k=q.get("top_k", 5),
                min_score=q.get("min_score", 0.35),
                graph_depth=q.get("graph_depth", 2),
                exclude_ids=exclude,
                source_filter=q.get("source_filter"),
                query_intent=q.get("query_intent") or q.get("queryIntent"),
                corpus_partitions=q.get("corpus_partitions") or q.get("corpusPartitions"),
                profiles=q.get("profiles"),
                allow_global_embedding=q.get("allow_global_embedding")
                if "allow_global_embedding" in q
                else q.get("allowGlobalEmbedding"),
            )

            for hit in result.get("hits", []):
                global_seen_ids.add(hit["id"])

            results.append(result)

        total_hits = sum(r.get("total", 0) for r in results)

        return {
            "results": results,
            "global_stats": {
                "total_queries": len(queries),
                "total_hits": total_hits,
                "unique_ids": len(global_seen_ids),
            },
        }
