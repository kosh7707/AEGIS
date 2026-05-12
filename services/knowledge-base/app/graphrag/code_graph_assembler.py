"""CodeGraphAssembler — 코드 그래프 하이브리드 검색 (Neo4j + Qdrant + RRF)."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from app.graphrag.code_graph_service import CodeGraphService
    from app.graphrag.code_vector_search import CodeVectorSearch

logger = logging.getLogger(__name__)

_FUNC_NAME_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\b")

_SKIP_WORDS = frozenset({
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "not",
    "function", "file", "calls", "line", "code", "handler", "network",
    "system", "command", "execute", "dangerous", "buffer", "overflow",
    "injection", "memory", "input", "output", "read", "write", "open",
    "close", "send", "recv", "connect", "include", "return", "void",
    "int", "char", "float", "double", "const", "static", "struct",
    "class", "public", "private", "using", "namespace", "string",
    "true", "false", "null", "none", "bool", "size", "type", "auto",
})


class CodeGraphAssembler:
    """코드 그래프 하이브리드 검색: 함수명 정확 매칭 + 벡터 시맨틱 + 그래프 확장."""

    def __init__(
        self,
        code_graph_service: CodeGraphService,
        code_vector_search: CodeVectorSearch,
        *,
        rrf_k: int = 60,
    ) -> None:
        self._graph = code_graph_service
        self._vector = code_vector_search
        self._rrf_k = rrf_k

    def _path_name_exact(
        self,
        project_id: str,
        query: str,
        seen: set[str],
        top_k: int,
        build_snapshot_id: str | None,
    ) -> list[dict]:
        """경로 1: 쿼리에서 함수명 후보를 추출하고 Neo4j에서 정확 매칭."""
        hits: list[dict] = []
        candidates = _FUNC_NAME_RE.findall(query)

        for name in candidates:
            if name.lower() in _SKIP_WORDS or name in seen:
                continue

            func_info = self._graph.get_function(
                project_id, name, build_snapshot_id=build_snapshot_id,
            )
            if func_info is None:
                continue

            callees = self._graph.get_callees(
                project_id, name, build_snapshot_id=build_snapshot_id,
            )
            func_info["calls"] = [c["name"] for c in callees]
            func_info["score"] = 1.0
            func_info["match_type"] = "name_exact"
            hits.append(func_info)
            seen.add(name)

            if len(hits) >= top_k:
                break

        return hits

    def _path_vector_semantic(
        self,
        project_id: str,
        query: str,
        seen: set[str],
        top_k: int,
        min_score: float,
        build_snapshot_id: str | None,
    ) -> list[dict]:
        """경로 2: Qdrant 벡터 시맨틱 검색."""
        vector_hits = self._vector.search(
            query,
            project_id=project_id,
            top_k=top_k,
            min_score=min_score,
            build_snapshot_id=build_snapshot_id,
        )

        hits: list[dict] = []
        for h in vector_hits:
            if h.name in seen:
                continue
            if len(hits) >= top_k:
                break

            item = {
                "name": h.name,
                "file": h.file,
                "line": h.line,
                "calls": h.calls,
                "origin": h.origin,
                "original_lib": h.original_lib,
                "original_version": h.original_version,
                "score": h.score,
                "match_type": "vector_semantic",
            }
            if any([
                h.build_snapshot_id,
                h.build_unit_id,
                h.source_build_attempt_id,
            ]):
                item["provenance"] = {
                    "buildSnapshotId": h.build_snapshot_id,
                    "buildUnitId": h.build_unit_id,
                    "sourceBuildAttemptId": h.source_build_attempt_id,
                }
            hits.append(item)
            seen.add(h.name)

        return hits

    def _enrich_with_call_chain(
        self,
        project_id: str,
        hits: list[dict],
        graph_depth: int,
        seen: set[str],
        build_snapshot_id: str | None,
    ) -> list[dict]:
        """매칭된 함수의 callers/callees 체인을 보강하고 neighbor hit을 반환한다."""
        neighbor_hits: list[dict] = []

        for hit in hits:
            func_name = hit["name"]
            callers = self._graph.get_callers(
                project_id, func_name, depth=graph_depth, build_snapshot_id=build_snapshot_id,
            )
            callees = self._graph.get_callees(
                project_id, func_name, build_snapshot_id=build_snapshot_id,
            )

            hit["call_chain"] = {
                "callers": callers[:10],
                "callees": [dict(c) for c in callees[:10]],
            }

            for caller in callers[:5]:
                if caller["name"] in seen:
                    continue
                neighbor_hits.append({
                    **caller,
                    "calls": [],
                    "score": 0.8 * hit["score"],
                    "match_type": "graph_neighbor",
                })
                seen.add(caller["name"])

        return neighbor_hits

    @staticmethod
    def _apply_rrf(result_lists: list[list[dict]], k: int = 60) -> list[dict]:
        """Reciprocal Rank Fusion — 여러 검색 결과 리스트를 융합한다."""
        rrf_scores: dict[str, float] = {}
        hit_map: dict[str, dict] = {}

        for result_list in result_lists:
            for rank, hit in enumerate(result_list):
                doc_id = hit["name"]
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

    def search(
        self,
        project_id: str,
        query: str,
        *,
        top_k: int = 10,
        min_score: float = 0.3,
        graph_depth: int = 2,
        include_call_chain: bool = True,
        build_snapshot_id: str | None = None,
        query_intent: str | None = None,
        corpus_partitions: list[str] | None = None,
        profiles: list[str] | None = None,
        allow_global_embedding: bool | None = None,
    ) -> dict:
        """하이브리드 코드 그래프 검색."""
        plan = plan_retrieval(
            query or "",
            query_intent=query_intent,
            corpus_partitions=corpus_partitions,
            profiles=profiles,
            allow_global_embedding=allow_global_embedding,
            default_intent="code_context",
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
                projection_state={
                    "state": "target_scoped" if build_snapshot_id is not None else "project_scoped",
                    "projectId": project_id,
                    **({"buildSnapshotId": build_snapshot_id} if build_snapshot_id is not None else {}),
                },
            )
            return {
                "query": "",
                "hits": [],
                "total": 0,
                "match_type_counts": {
                    "name_exact": 0, "vector_semantic": 0, "graph_neighbor": 0,
                },
                "retrievalTrace": trace,
            }

        seen: set[str] = set()

        exact_hits = self._path_name_exact(
            project_id, query, seen, candidate_pool_k, build_snapshot_id,
        )
        vector_hits = self._path_vector_semantic(
            project_id, query, seen, candidate_pool_k, min_score, build_snapshot_id,
        )

        if self._rrf_k > 0:
            all_hits = self._apply_rrf([exact_hits, vector_hits], k=self._rrf_k)
        else:
            all_hits = exact_hits + vector_hits
            all_hits.sort(key=lambda h: h.get("score", 0), reverse=True)

        all_hits = self._rerank_hits(all_hits[:candidate_pool_k], plan=plan)
        all_hits = all_hits[:final_top_k]

        if include_call_chain and all_hits:
            neighbor_hits = self._enrich_with_call_chain(
                project_id, all_hits, graph_depth, seen, build_snapshot_id,
            )
            remaining = max(0, final_top_k - len(all_hits))
            start_rank = len(all_hits) + 1
            all_hits.extend(
                annotate_hit(
                    hit,
                    rank=start_rank + offset,
                    embedding_scope=plan.embedding_scope,
                    rerank_score=float(hit.get("score", 0) or 0),
                )
                for offset, hit in enumerate(neighbor_hits[:remaining])
            )

        all_hits = all_hits[:final_top_k]
        relation_methods = methods_from_match_types(
            [str(hit.get("match_type", "")) for hit in all_hits],
            embedding_scope=plan.embedding_scope,
        )
        methods_attempted = ["exact_id_match"]
        if plan.lexical_signals:
            methods_attempted.append("keyword_match")
        methods_attempted.append("global_embedding_search" if plan.embedding_scope == "global" else "constrained_embedding_rerank")
        if include_call_chain and graph_depth > 0:
            methods_attempted.append("graph_expansion")
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
            projection_state={
                "state": "target_scoped" if build_snapshot_id is not None else "project_scoped",
                "projectId": project_id,
                **({"buildSnapshotId": build_snapshot_id} if build_snapshot_id is not None else {}),
            },
        )
        result = {
            "query": query,
            "hits": all_hits,
            "total": len(all_hits),
            "match_type_counts": {
                "name_exact": sum(
                    1 for h in all_hits if h.get("match_type") == "name_exact"
                ),
                "vector_semantic": sum(
                    1 for h in all_hits if h.get("match_type") == "vector_semantic"
                ),
                "graph_neighbor": sum(
                    1 for h in all_hits if h.get("match_type") == "graph_neighbor"
                ),
            },
            "retrievalTrace": trace,
        }
        if build_snapshot_id is not None:
            result["provenance"] = {"buildSnapshotId": build_snapshot_id}
        return result
