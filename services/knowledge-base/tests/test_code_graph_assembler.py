"""CodeGraphAssembler 단위 테스트 — CodeGraphService + CodeVectorSearch를 mock하여 검증."""

from unittest.mock import MagicMock

from app.graphrag.code_graph_assembler import CodeGraphAssembler
from app.graphrag.code_vector_search import CodeFunctionHit


def _make_assembler():
    graph_svc = MagicMock()
    vector_search = MagicMock()
    asm = CodeGraphAssembler(graph_svc, vector_search, rrf_k=60)
    return asm, graph_svc, vector_search


# ── 기본 동작 ──


def test_search_empty_query():
    asm, _, _ = _make_assembler()
    result = asm.search("proj-1", "")
    assert result["total"] == 0
    assert result["hits"] == []
    assert result["retrievalTrace"]["queryIntent"] == "code_context"
    assert result["retrievalTrace"]["corpusPartitionsSearched"] == ["code_graph"]


def test_search_whitespace_query():
    asm, _, _ = _make_assembler()
    result = asm.search("proj-1", "   ")
    assert result["total"] == 0


def test_search_no_hits_does_not_mark_methods_succeeded():
    asm, graph_svc, vector_search = _make_assembler()
    graph_svc.get_function.return_value = None
    vector_search.search.return_value = []

    result = asm.search("proj-1", "missing_function", include_call_chain=True)

    assert result["total"] == 0
    assert result["retrievalTrace"]["methodsAttempted"] == [
        "exact_id_match",
        "constrained_embedding_rerank",
        "graph_expansion",
    ]
    assert result["retrievalTrace"]["methodsSucceeded"] == []


# ── 함수명 정확 매칭 ──


def test_name_exact_match():
    asm, graph_svc, vector_search = _make_assembler()

    graph_svc.get_function.return_value = {
        "name": "postJson", "file": "src/http_client.cpp", "line": 8,
        "origin": None, "original_lib": None, "original_version": None,
    }
    graph_svc.get_callees.return_value = [
        {"name": "popen", "file": None, "line": None},
    ]
    graph_svc.get_callers.return_value = []
    vector_search.search.return_value = []

    result = asm.search("proj-1", "postJson 함수 분석", include_call_chain=False)
    assert result["total"] >= 1
    exact_hits = [h for h in result["hits"] if h.get("match_type") == "name_exact"]
    assert len(exact_hits) == 1
    assert exact_hits[0]["name"] == "postJson"
    assert exact_hits[0]["calls"] == ["popen"]


def test_name_exact_skip_common_words():
    """일반 영단어는 함수명 후보에서 제외."""
    asm, graph_svc, vector_search = _make_assembler()
    graph_svc.get_function.return_value = None
    vector_search.search.return_value = []

    result = asm.search("proj-1", "function that handles network input", include_call_chain=False)
    # "function", "handles", "network", "input"은 _SKIP_WORDS이므로 get_function 호출되지 않거나 매칭 안 됨
    assert result["match_type_counts"]["name_exact"] == 0


# ── 벡터 시맨틱 검색 ──


def test_vector_semantic_search():
    asm, graph_svc, vector_search = _make_assembler()

    graph_svc.get_function.return_value = None
    vector_search.search.return_value = [
        CodeFunctionHit(
            name="postJson", file="src/http_client.cpp", line=8,
            calls=["popen", "fgets"], score=0.75,
        ),
        CodeFunctionHit(
            name="sendData", file="src/net.cpp", line=20,
            calls=["send"], score=0.60,
        ),
    ]
    graph_svc.get_callers.return_value = []
    graph_svc.get_callees.return_value = []

    result = asm.search("proj-1", "시스템 명령 실행 핸들러", include_call_chain=False)
    assert result["total"] == 2
    assert result["match_type_counts"]["vector_semantic"] == 2


# ── 하이브리드 RRF ──


def test_hybrid_rrf_dedup():
    """같은 함수가 exact + vector 양쪽에서 발견되면 RRF 점수가 합산되고 중복 제거."""
    asm, graph_svc, vector_search = _make_assembler()

    graph_svc.get_function.return_value = {
        "name": "postJson", "file": "src/http_client.cpp", "line": 8,
        "origin": None, "original_lib": None, "original_version": None,
    }
    graph_svc.get_callees.side_effect = lambda pid, name, **kwargs: (
        [{"name": "popen"}] if name == "postJson" else []
    )
    graph_svc.get_callers.return_value = []

    # vector에서도 postJson 반환 → seen에 의해 제외됨
    vector_search.search.return_value = [
        CodeFunctionHit(
            name="sendData", file="src/net.cpp", line=20,
            calls=["send"], score=0.60,
        ),
    ]

    result = asm.search("proj-1", "postJson network", include_call_chain=False)
    names = [h["name"] for h in result["hits"]]
    assert names.count("postJson") == 1  # 중복 없음


# ── 그래프 확장 (call chain) ──


def test_enrich_with_call_chain():
    asm, graph_svc, vector_search = _make_assembler()

    graph_svc.get_function.return_value = None
    vector_search.search.return_value = [
        CodeFunctionHit(
            name="postJson", file="src/http_client.cpp", line=8,
            calls=["popen"], score=0.80,
        ),
    ]
    graph_svc.get_callers.return_value = [
        {"name": "main", "file": "src/main.cpp", "line": 1,
         "origin": None, "original_lib": None, "original_version": None},
    ]
    graph_svc.get_callees.return_value = [
        {"name": "popen", "file": None, "line": None,
         "origin": None, "original_lib": None, "original_version": None},
    ]

    result = asm.search("proj-1", "HTTP 클라이언트", top_k=10, include_call_chain=True)

    # postJson hit에 call_chain이 붙어야 함
    main_hit = result["hits"][0]
    assert "call_chain" in main_hit
    assert len(main_hit["call_chain"]["callers"]) == 1
    assert main_hit["call_chain"]["callers"][0]["name"] == "main"


def test_no_call_chain_when_disabled():
    asm, graph_svc, vector_search = _make_assembler()

    graph_svc.get_function.return_value = None
    vector_search.search.return_value = [
        CodeFunctionHit(name="postJson", file="x.cpp", line=1, calls=[], score=0.7),
    ]

    result = asm.search("proj-1", "test", include_call_chain=False)
    assert "call_chain" not in result["hits"][0]


# ── RRF 알고리즘 ──


def test_apply_rrf():
    list1 = [{"name": "a", "score": 1.0}, {"name": "b", "score": 0.9}]
    list2 = [{"name": "b", "score": 0.8}, {"name": "c", "score": 0.7}]

    merged = CodeGraphAssembler._apply_rrf([list1, list2], k=60)

    names = [h["name"] for h in merged]
    # "b"가 양쪽에 나타나므로 RRF 점수가 가장 높아야 함
    assert names[0] == "b"
    assert len(merged) == 3


def test_search_passes_build_snapshot_filter():
    asm, graph_svc, vector_search = _make_assembler()
    graph_svc.get_function.return_value = None
    vector_search.search.return_value = []

    asm.search(
        "proj-1",
        "postJson",
        include_call_chain=False,
        build_snapshot_id="snap-1",
    )

    assert graph_svc.get_function.call_args.kwargs["build_snapshot_id"] == "snap-1"
    assert vector_search.search.call_args.kwargs["build_snapshot_id"] == "snap-1"


def test_code_graph_search_returns_target_scoped_retrieval_trace_and_rank_metadata():
    asm, graph_svc, vector_search = _make_assembler()
    graph_svc.get_function.return_value = None
    graph_svc.get_callers.return_value = []
    graph_svc.get_callees.return_value = []
    vector_search.search.return_value = [
        CodeFunctionHit(
            name="postJson",
            file="src/http_client.cpp",
            line=8,
            calls=["popen"],
            score=0.75,
            build_snapshot_id="snap-1",
        ),
    ]

    result = asm.search(
        "proj-1",
        "network command execution",
        query_intent="code_context",
        corpus_partitions=["structural_code_projection"],
        include_call_chain=False,
        build_snapshot_id="snap-1",
    )

    trace = result["retrievalTrace"]
    assert trace["queryIntent"] == "code_context"
    assert trace["corpusPartitionsSearched"] == ["code_graph"]
    assert trace["embeddingScope"] == "constrained"
    assert trace["projectionState"]["projectId"] == "proj-1"
    assert trace["projectionState"]["buildSnapshotId"] == "snap-1"
    assert trace["methodsAttempted"] == ["exact_id_match", "keyword_match", "constrained_embedding_rerank"]
    assert trace["keywordUsed"] is True
    assert trace["lexicalSignals"]
    assert trace["candidatePoolSize"] > trace["topK"]
    assert trace["methodsSucceeded"] == ["constrained_embedding_rerank"]
    assert result["hits"][0]["relationMethods"] == ["constrained_embedding_rerank"]
    assert result["hits"][0]["methodTrust"] == "medium"
    assert "ranking" in result["hits"][0]
    assert "scoreBreakdown" in result["hits"][0]["ranking"]
