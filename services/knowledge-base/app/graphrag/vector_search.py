"""VectorSearch — 기존 ThreatSearch의 얇은 래퍼 + 소스 필터링."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.rag.threat_search import ThreatHit, ThreatSearch


class VectorSearch:
    """Qdrant 벡터 유사도 검색을 위임한다."""

    def __init__(self, threat_search: ThreatSearch) -> None:
        self._search = threat_search

    def search(
        self,
        query: str,
        top_k: int = 5,
        min_score: float = 0.35,
        source_filter: list[str] | None = None,
        corpus_partitions: list[str] | None = None,
    ) -> list[ThreatHit]:
        query_filter = None
        must = []
        if corpus_partitions:
            from qdrant_client.models import FieldCondition, MatchAny
            must.append(FieldCondition(key="corpusPartition", match=MatchAny(any=corpus_partitions)))
        if source_filter:
            from qdrant_client.models import FieldCondition, MatchAny
            must.append(FieldCondition(key="source", match=MatchAny(any=source_filter)))
        if must:
            from qdrant_client.models import Filter
            query_filter = Filter(must=must)
        return self._search.search(
            query, top_k=top_k, min_score=min_score, query_filter=query_filter,
        )
