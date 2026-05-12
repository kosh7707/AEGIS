"""KnowledgeAssembler 단위 테스트 — ThreatSearch와 Graph를 mock하여 검증."""

from dataclasses import dataclass
from unittest.mock import MagicMock

from app.graphrag.knowledge_assembler import KnowledgeAssembler
from app.graphrag.vector_search import VectorSearch


@dataclass
class FakeHit:
    id: str = "CWE-78"
    source: str = "CWE"
    title: str = "OS Command Injection"
    threat_category: str = "Injection"
    severity: float | None = None
    attack_surfaces: list = None
    related_cwe: list = None
    related_cve: list = None
    related_attack: list = None
    score: float = 0.85
    corpus_partition: str = ""

    def __post_init__(self):
        self.attack_surfaces = self.attack_surfaces or []
        self.related_cwe = self.related_cwe or []
        self.related_cve = self.related_cve or ["CVE-2021-28372"]
        self.related_attack = self.related_attack or []


class FakeGraph:
    """Neo4jGraph 인터페이스의 경량 mock."""

    def __init__(self, records: list[dict]):
        self._nodes = {r["id"]: r for r in records}
        self._edges: dict[str, dict[str, list[str]]] = {}
        for rec in records:
            related: dict[str, list[str]] = {}
            for field, key in [("related_capec", "capec"), ("related_cwe", "cwe"),
                               ("related_cve", "cve"), ("related_attack", "attack")]:
                ids = rec.get(field, [])
                if ids:
                    related[key] = ids
            if related:
                self._edges[rec["id"]] = related

    def get_related(self, node_id: str) -> dict[str, list[str]]:
        return self._edges.get(node_id, {})

    def get_node_info(self, node_id: str) -> dict | None:
        return self._nodes.get(node_id)

    def neighbors(self, node_id: str, depth: int = 2) -> list[str]:
        related = self._edges.get(node_id, {})
        result = []
        for ids in related.values():
            result.extend(ids)
        return result


def _make_assembler(hits: list | None = None) -> KnowledgeAssembler:
    mock_search = MagicMock()
    mock_search.search.return_value = hits if hits is not None else [FakeHit()]
    vs = VectorSearch.__new__(VectorSearch)
    vs._search = mock_search

    graph = FakeGraph([
        {"id": "CWE-78", "source": "CWE", "title": "OS CI", "related_capec": ["CAPEC-88"], "related_cve": [], "related_cwe": [], "related_attack": []},
        {"id": "CAPEC-88", "source": "CAPEC", "title": "OS CI Attack", "related_cwe": ["CWE-78"], "related_cve": [], "related_attack": [], "related_capec": []},
    ])

    return KnowledgeAssembler(vs, graph, rrf_k=0)


def test_assemble_combines_vector_and_graph():
    assembler = _make_assembler()
    result = assembler.assemble("command injection")
    assert result["total"] >= 1
    # graph enrichment should add CAPEC-88
    assert "CAPEC-88" in str(result)


def test_assemble_no_hits():
    assembler = _make_assembler(hits=[])
    result = assembler.assemble("unknown query")
    assert result["total"] == 0
    assert result["hits"] == []
    assert result["retrievalTrace"]["methodsSucceeded"] == []
    assert result["retrievalTrace"]["methodsAttempted"] == ["constrained_embedding_rerank"]


def test_assemble_collects_cross_references():
    assembler = _make_assembler()
    result = assembler.assemble("CWE-78")
    # ID 직접 조회로 CWE-78이 잡히고, 그래프 이웃(CAPEC-88)이 related_capec에 포함
    assert "CAPEC-88" in str(result)


def test_assemble_returns_sorted_references():
    hit1 = FakeHit(id="CWE-78", related_cve=["CVE-2023-001", "CVE-2021-002"])
    assembler = _make_assembler(hits=[hit1])
    result = assembler.assemble("injection")
    assert result["related_cve"] == sorted(result["related_cve"])


def test_hybrid_id_exact_match():
    """쿼리에 CWE-78이 명시되면 ID 직접 조회로 score=1.0 hit이 나와야 한다."""
    assembler = _make_assembler(hits=[])  # 벡터 검색 0건
    result = assembler.assemble("CWE-78 command injection")

    assert result["total"] >= 1
    assert result["extracted_ids"] == ["CWE-78"]

    # 첫 번째 hit이 CWE-78 (ID 정확 매칭, score=1.0)
    top = result["hits"][0]
    assert top["id"] == "CWE-78"
    assert top["score"] == 1.0
    assert top["match_type"] == "id_exact"

    # 그래프 이웃(CAPEC-88)도 포함
    all_ids = {h["id"] for h in result["hits"]}
    assert "CAPEC-88" in all_ids


def test_hybrid_deduplication():
    """벡터 검색과 ID 조회가 같은 노드를 반환하면 중복 제거."""
    hit = FakeHit(id="CWE-78")
    assembler = _make_assembler(hits=[hit])
    result = assembler.assemble("CWE-78 injection")

    cwe78_hits = [h for h in result["hits"] if h["id"] == "CWE-78"]
    assert len(cwe78_hits) == 1  # 중복 없음


# ── 소스 필터링 ──


def _make_assembler_multi_source(hits=None, rrf_k=0):
    """CWE + CAPEC + ATT&CK 노드가 있는 assembler 생성."""
    mock_search = MagicMock()

    default_hits = [
        FakeHit(id="CWE-79", source="CWE", title="XSS"),
        FakeHit(id="CAPEC-86", source="CAPEC", title="XSS via HTTP"),
    ] if hits is None else hits

    mock_search.search.return_value = default_hits
    vs = VectorSearch.__new__(VectorSearch)
    vs._search = mock_search

    graph = FakeGraph([
        {"id": "CWE-78", "source": "CWE", "title": "OS CI", "related_capec": ["CAPEC-88"], "related_cwe": [], "related_cve": [], "related_attack": []},
        {"id": "CAPEC-88", "source": "CAPEC", "title": "OS CI Attack", "related_cwe": ["CWE-78"], "related_cve": [], "related_attack": [], "related_capec": []},
        {"id": "CWE-79", "source": "CWE", "title": "XSS", "related_capec": [], "related_cwe": [], "related_cve": [], "related_attack": []},
        {"id": "CAPEC-86", "source": "CAPEC", "title": "XSS via HTTP", "related_cwe": [], "related_cve": [], "related_attack": [], "related_capec": []},
    ])

    return KnowledgeAssembler(vs, graph, rrf_k=rrf_k)


def test_source_filter_cwe_only():
    """source_filter=["CWE"] → CWE만 반환, CAPEC 제외."""
    assembler = _make_assembler_multi_source()
    result = assembler.assemble("CWE-78 injection", source_filter=["CWE"])

    for hit in result["hits"]:
        assert hit["source"] == "CWE", f"Non-CWE hit found: {hit['id']}"


def test_source_filter_none_returns_all():
    """source_filter=None → 전체 소스 반환."""
    assembler = _make_assembler_multi_source()
    result = assembler.assemble("CWE-78 injection", source_filter=None)

    sources = {h["source"] for h in result["hits"]}
    assert len(sources) >= 1  # 최소 1개 소스


def test_source_filter_in_id_exact():
    """ID exact path에서도 소스 필터가 동작하는지 확인."""
    assembler = _make_assembler_multi_source(hits=[])  # 벡터 검색 0건
    result = assembler.assemble("CWE-78", source_filter=["CWE"])

    # CWE-78은 CWE이므로 통과, CAPEC-88은 이웃이지만 CAPEC이므로 필터링
    for hit in result["hits"]:
        assert hit["source"] == "CWE"


# ── 배치 검색 ──


def test_batch_assemble_dedup():
    """쿼리 간 중복 제거: 첫 쿼리에 나온 ID는 두 번째 쿼리에서 제외."""
    assembler = _make_assembler()

    result = assembler.batch_assemble([
        {"query": "CWE-78"},
        {"query": "CWE-78"},  # 동일 쿼리
    ])

    # 첫 쿼리에서 CWE-78이 반환되면 두 번째에서는 중복 제거됨
    assert result["results"][0]["total"] >= 1
    second_ids = {h["id"] for h in result["results"][1]["hits"]}
    first_ids = {h["id"] for h in result["results"][0]["hits"]}
    assert second_ids.isdisjoint(first_ids)


def test_batch_assemble_stats():
    """global_stats 정확성 확인."""
    assembler = _make_assembler(hits=[])

    result = assembler.batch_assemble([
        {"query": "CWE-78"},
    ])

    assert result["global_stats"]["total_queries"] == 1
    assert "total_hits" in result["global_stats"]
    assert "unique_ids" in result["global_stats"]


def test_batch_assemble_empty():
    """빈 queries 리스트는 빈 results."""
    assembler = _make_assembler()

    result = assembler.batch_assemble([])

    assert result["results"] == []
    assert result["global_stats"]["total_queries"] == 0


# ── RRF ──


def test_rrf_basic():
    """3-list RRF 점수 계산+정렬 검증."""
    list1 = [{"id": "A", "match_type": "id_exact", "source": "CWE", "title": "a", "score": 1.0}]
    list2 = [{"id": "B", "match_type": "graph_neighbor", "source": "CWE", "title": "b", "score": 0.8}]
    list3 = [
        {"id": "A", "match_type": "vector_semantic", "source": "CWE", "title": "a", "score": 0.9},
        {"id": "C", "match_type": "vector_semantic", "source": "CWE", "title": "c", "score": 0.7},
    ]

    merged = KnowledgeAssembler._apply_rrf([list1, list2, list3], k=60)

    # A는 list1과 list3에 모두 등장 → RRF 점수 더 높음
    assert merged[0]["id"] == "A"
    assert len(merged) == 3


def test_rrf_disabled():
    """rrf_k=0이면 기존 단순 정렬 동작."""
    assembler = _make_assembler_multi_source(hits=[], rrf_k=0)
    result = assembler.assemble("CWE-78")

    # rrf_k=0이면 id_exact는 score=1.0 고정
    exact_hits = [h for h in result["hits"] if h["match_type"] == "id_exact"]
    for h in exact_hits:
        assert h["score"] == 1.0


def test_rrf_single_list():
    """리스트 1개만 있을 때도 정상 동작."""
    single = [
        {"id": "X", "match_type": "id_exact", "source": "CWE", "title": "x", "score": 1.0},
        {"id": "Y", "match_type": "id_exact", "source": "CWE", "title": "y", "score": 1.0},
    ]
    merged = KnowledgeAssembler._apply_rrf([single], k=60)
    assert len(merged) == 2
    # 첫 번째가 rank 1 → 1/(60+1), 두 번째가 rank 2 → 1/(60+2)
    assert merged[0]["id"] == "X"
    assert merged[0]["score"] > merged[1]["score"]


def test_assemble_caps_total_hits_to_final_top_k_and_exposes_candidate_pool():
    mock_search = MagicMock()
    mock_search.search.return_value = [
        FakeHit(id=f"CWE-{i + 100}", source="CWE", title=f"hit-{i}")
        for i in range(5)
    ]
    vs = VectorSearch.__new__(VectorSearch)
    vs._search = mock_search

    graph = FakeGraph([
        {"id": "CWE-1", "source": "CWE", "title": "one", "related_capec": [], "related_cwe": [], "related_cve": [], "related_attack": []},
        {"id": "CWE-2", "source": "CWE", "title": "two", "related_capec": [], "related_cwe": [], "related_cve": [], "related_attack": []},
        {"id": "CWE-3", "source": "CWE", "title": "three", "related_capec": [], "related_cwe": [], "related_cve": [], "related_attack": []},
    ])

    assembler = KnowledgeAssembler(vs, graph, rrf_k=60)
    result = assembler.assemble("CWE-1 CWE-2 CWE-3", top_k=2)

    assert result["total"] <= 2
    assert result["retrievalTrace"]["topK"] == 2
    assert result["retrievalTrace"]["candidatePoolSize"] > 2
    assert result["retrievalTrace"]["topKPolicy"]["topKMeans"] == "final_returned_count"


def test_typed_threat_search_returns_constrained_retrieval_trace_and_rank_metadata():
    hit = FakeHit(
        id="CVE-2026-0001",
        source="OSV",
        title="fixture CVE",
        corpus_partition="public_vulnerability",
    )
    assembler = _make_assembler(hits=[hit])

    result = assembler.assemble(
        "OpenSSL CVE candidates",
        query_intent="cve_discovery",
        corpus_partitions=["public_vulnerability_knowledge"],
        top_k=3,
        min_score=0.2,
    )

    trace = result["retrievalTrace"]
    assert trace["queryIntent"] == "cve_discovery"
    assert trace["corpusPartitionsSearched"] == ["public_vulnerability"]
    assert trace["embeddingScope"] == "constrained"
    assert trace["topK"] == 3
    assert trace["minScore"] == 0.2
    assert trace["methodsAttempted"] == ["keyword_match", "constrained_embedding_rerank"]
    assert trace["keywordUsed"] is True
    assert trace["lexicalSignals"]
    assert trace["candidatePoolSize"] > trace["topK"]
    assert trace["modelPolicy"]["mandatoryNewDependency"] is False
    assert trace["methodsSucceeded"] == ["constrained_embedding_rerank"]
    assert result["hits"][0]["corpusPartition"] == "public_vulnerability"
    assert result["hits"][0]["relationMethods"] == ["constrained_embedding_rerank"]
    assert result["hits"][0]["methodTrust"] == "medium"
    assert "ranking" in result["hits"][0]
    assert "scoreBreakdown" in result["hits"][0]["ranking"]


def test_typed_threat_search_records_corpus_partition_to_source_fallback():
    mock_search = MagicMock()
    mock_search.search.side_effect = [
        [],
        [FakeHit(id="CWE-79", source="CWE", title="XSS")],
    ]
    vs = VectorSearch.__new__(VectorSearch)
    vs._search = mock_search
    graph = FakeGraph([
        {"id": "CWE-79", "source": "CWE", "title": "XSS", "related_capec": [], "related_cwe": [], "related_cve": [], "related_attack": []},
    ])
    assembler = KnowledgeAssembler(vs, graph, rrf_k=0)

    result = assembler.assemble("cross-site scripting", query_intent="weakness_context")

    first_filter = mock_search.search.call_args_list[0].kwargs["query_filter"]
    second_filter = mock_search.search.call_args_list[1].kwargs["query_filter"]
    assert first_filter.must[0].key == "corpusPartition"
    assert first_filter.must[0].match.any == ["weakness_taxonomy"]
    assert second_filter.must[0].key == "source"
    assert second_filter.must[0].match.any == ["CWE"]
    fallback_trace = result["retrievalTrace"]["fallbackTrace"]
    assert any(item["reason"] == "legacy_payload_may_lack_corpusPartition" for item in fallback_trace)
    assert any(item["reason"] == "no_vector_hits_with_corpus_partition_filter" for item in fallback_trace)


def test_global_embedding_search_is_visible_and_low_trust():
    assembler = _make_assembler(hits=[FakeHit(id="DOC-1", source="misc", title="broad hit")])

    result = assembler.assemble(
        "broad unconstrained query",
        query_intent="project_memory_context",
        allow_global_embedding=True,
    )

    trace = result["retrievalTrace"]
    assert trace["embeddingScope"] == "global"
    assert trace["methodsAttempted"] == ["global_embedding_search"]
    assert trace["globalEmbeddingPolicy"]["trust"] == "low"
    assert trace["globalEmbeddingPolicy"]["negativeEvidenceAllowed"] is False
    assert result["hits"][0]["relationMethods"] == ["global_embedding_search"]
    assert result["hits"][0]["methodTrust"] == "low"
