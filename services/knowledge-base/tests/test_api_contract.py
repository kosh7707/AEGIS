"""API 계약서 대비 HTTP 레벨 응답 shape 검증 테스트.

계약서: wiki/canon/api/knowledge-base-api.md
기존 test_api_error_responses.py는 에러 경로 위주.
이 파일은 **성공 경로의 응답 shape**이 계약서와 일치하는지 검증한다.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import api, code_graph_api, cve_api, judge_api, project_memory_api, source_kg_api

# ---------------------------------------------------------------------------
# Mock 서비스
# ---------------------------------------------------------------------------

_TIMEOUT = {"X-Timeout-Ms": "30000"}
_REQ_ID = "req-contract-test-001"
_HEADERS = {**_TIMEOUT, "X-Request-Id": _REQ_ID}


class FakeNeo4jGraph:
    node_count = 2196
    edge_count = 9298

    def get_stats(self):
        return {
            "nodeCount": self.node_count,
            "edgeCount": self.edge_count,
            "sources": {"CWE": 944, "CVE": 0, "Attack": 694, "CAPEC": 558},
            "edgeTypes": {"RELATED_CAPEC": 3210, "RELATED_ATTACK": 2845, "RELATED_CWE": 3243},
            "topConnected": [
                {"id": "CWE-119", "title": "Buffer Overflow", "label": "CWE", "degree": 142},
            ],
        }

    def get_node_info(self, node_id):
        if node_id == "CWE-78":
            return {
                "id": "CWE-78",
                "title": "OS Command Injection",
                "source": "CWE",
                "threat_category": "Injection",
            }
        return None

    def neighbors(self, node_id, depth=2):
        if node_id == "CWE-78":
            return ["CAPEC-88"]
        return []

    def get_related(self, node_id):
        if node_id == "CWE-78":
            return {"capec": ["CAPEC-88"], "attack": ["T0807"]}
        if node_id == "CAPEC-88":
            return {"cwe": ["CWE-78"]}
        return {}

    def get_kb_meta(self):
        return {
            "cwe_version": "4.19.1",
            "attack_enterprise_version": "18.1",
            "attack_ics_version": "18.1",
            "capec_version": "3.9",
            "total_records": 2011,
        }


class FakeAssembler:
    def assemble(self, query, **kwargs):
        if not query or not query.strip():
            return {
                "query": query or "",
                "hits": [],
                "total": 0,
                "extracted_ids": [],
                "related_cwe": [],
                "related_cve": [],
                "related_attack": [],
                "match_type_counts": {"id_exact": 0, "graph_neighbor": 0, "vector_semantic": 0},
            }
        return {
            "query": query,
            "hits": [
                {
                    "id": "CWE-78",
                    "source": "CWE",
                    "title": "OS Command Injection",
                    "score": 1.0,
                    "threat_category": "Injection",
                    "match_type": "id_exact",
                    "graph_relations": {"capec": ["CAPEC-88"], "attack": ["T0807"]},
                },
                {
                    "id": "CWE-77",
                    "source": "CWE",
                    "title": "Command Injection",
                    "score": 0.72,
                    "threat_category": "Injection",
                    "match_type": "vector_semantic",
                },
            ],
            "total": 2,
            "extracted_ids": ["CWE-78"],
            "related_cwe": ["CWE-77", "CWE-78"],
            "related_cve": [],
            "related_attack": ["T0807"],
            "match_type_counts": {"id_exact": 1, "graph_neighbor": 0, "vector_semantic": 1},
        }

    def batch_assemble(self, queries):
        results = []
        for q in queries:
            results.append(self.assemble(q["query"]))
        total_hits = sum(r["total"] for r in results)
        return {
            "results": results,
            "global_stats": {
                "total_queries": len(queries),
                "total_hits": total_hits,
                "unique_ids": total_hits,
            },
        }


class FakeCodeGraphService:
    def export_project(self, project_id):
        if project_id == "existing-project":
            return [{"name": "legacy", "file": "legacy.cpp", "line": 1, "calls": []}]
        return []

    def ingest(self, project_id, functions, *, provenance=None):
        result = {
            "project_id": project_id,
            "replaceMode": "replace_project_graph",
            "replacedExistingGraph": project_id == "existing-project",
            "nodeCount": len(functions),
            "edgeCount": sum(len(f.get("calls", [])) for f in functions),
            "files": list({f.get("file") for f in functions if f.get("file")}),
        }
        if provenance:
            from app.graphrag.code_graph_service import CodeGraphService
            np = CodeGraphService._normalize_provenance(provenance)
            if any(np.values()):
                result["provenance"] = {
                    "buildSnapshotId": np.get("build_snapshot_id"),
                    "buildUnitId": np.get("build_unit_id"),
                    "sourceBuildAttemptId": np.get("source_build_attempt_id"),
                }
        return result

    def activate_staging(self, staging_project_id, project_id):
        return self.get_stats(project_id)

    def get_stats(self, project_id, *, build_snapshot_id=None):
        result = {"nodeCount": 3, "edgeCount": 2, "files": ["main.cpp", "http.cpp"]}
        if build_snapshot_id:
            result["provenance"] = {"buildSnapshotId": build_snapshot_id}
        return result

    def get_callers(self, project_id, function_name, depth=2, *, build_snapshot_id=None):
        return [
            {
                "name": "main", "file": "main.cpp", "line": 1,
                "origin": None, "original_lib": None, "original_version": None,
                "build_snapshot_id": None, "build_unit_id": None,
                "source_build_attempt_id": None,
            },
        ]

    def get_function(self, project_id, function_name, *, build_snapshot_id=None):
        if function_name == "postJson":
            return {
                "name": "postJson", "file": "http.cpp", "line": 8,
                "origin": None, "original_lib": None, "original_version": None,
                "build_snapshot_id": None, "build_unit_id": None,
                "source_build_attempt_id": None,
            }
        return None

    def get_callees(self, project_id, function_name, *, build_snapshot_id=None):
        if function_name == "postJson":
            return [
                {
                    "name": "popen", "file": None, "line": None,
                    "origin": None, "original_lib": None, "original_version": None,
                    "build_snapshot_id": None, "build_unit_id": None,
                    "source_build_attempt_id": None,
                },
            ]
        return []

    def find_dangerous_callers(self, project_id, dangerous_functions, *, build_snapshot_id=None):
        return [
            {
                "name": "postJson", "file": "http.cpp", "line": 8,
                "dangerous_calls": ["popen"],
                "origin": None, "original_lib": None, "original_version": None,
                "build_snapshot_id": None, "build_unit_id": None,
                "source_build_attempt_id": None,
            },
        ]

    def delete_project(self, project_id):
        return project_id == "re100"

    def list_projects(self):
        return ["re100", "sample-ecu"]


class FakeCodeVectorSearch:
    def ingest(self, project_id, functions, *, provenance=None):
        return len(functions)

    def activate_staging(self, staging_project_id, project_id):
        return None

    def delete_project(self, project_id):
        pass


class FakeCodeAssembler:
    def search(self, project_id, query, *, top_k=10, min_score=0.3,
               graph_depth=2, include_call_chain=True, build_snapshot_id=None):
        result = {
            "query": query,
            "hits": [
                {
                    "name": "postJson", "file": "http.cpp", "line": 8,
                    "calls": ["popen", "fgets"],
                    "origin": None, "original_lib": None, "original_version": None,
                    "score": 0.032787,
                    "match_type": "vector_semantic",
                    "call_chain": {
                        "callers": [{"name": "main", "file": "main.cpp", "line": 1}],
                        "callees": [{"name": "popen", "file": None, "line": None}],
                    },
                },
            ],
            "total": 1,
            "match_type_counts": {"name_exact": 0, "vector_semantic": 1, "graph_neighbor": 0},
        }
        if build_snapshot_id:
            result["provenance"] = {"buildSnapshotId": build_snapshot_id}
        return result


class FakeNvdClient:
    async def batch_lookup(self, libraries):
        return [
            {
                "library": lib["name"],
                "version": lib["version"],
                "cves": [
                    {
                        "id": "CVE-2021-28825",
                        "title": "Test vulnerability",
                        "description": "Test description",
                        "severity": 8.8,
                        "attack_vector": "NETWORK",
                        "affected_versions": "<= 1.3.0",
                        "version_match": False,
                        "risk_score": 0.582,
                        "epss_score": 0.42,
                        "epss_percentile": 0.78,
                        "kev": False,
                        "related_cwe": ["CWE-863"],
                        "related_attack": [],
                        "kb_context": {
                            "threat_categories": ["Authentication/Authorization"],
                            "attack_surfaces": [],
                            "max_automotive_relevance": 0.35,
                        },
                        "source": "nvd",
                    },
                ],
                "total": 1,
                "cached": False,
            }
            for lib in libraries
        ]


class FakeMemoryService:
    def __init__(self):
        self._store = {}

    def list_memories(self, project_id, memory_type=None, provenance_filters=None):
        return [
            {
                "id": "mem-a1b2c3d4",
                "type": "analysis_history",
                "data": {"claimCount": 4},
                "createdAt": "2026-03-23T15:00:00+00:00",
            },
        ]

    def create_memory(self, project_id, memory_type, data, *, ttl_seconds=None, provenance=None):
        if memory_type not in {"analysis_history", "false_positive", "resolved", "preference"}:
            raise ValueError(f"Invalid memory type: {memory_type}")
        result = {
            "id": "mem-new12345",
            "type": memory_type,
            "createdAt": "2026-04-08T10:00:00+00:00",
        }
        if provenance:
            from app.graphrag.project_memory_service import ProjectMemoryService
            np = ProjectMemoryService._normalize_provenance(provenance)
            if any(np.values()):
                result["provenance"] = {
                    "buildSnapshotId": np.get("build_snapshot_id"),
                    "buildUnitId": np.get("build_unit_id"),
                    "sourceBuildAttemptId": np.get("source_build_attempt_id"),
                }
        return result

    def delete_memory(self, project_id, memory_id):
        return memory_id == "mem-a1b2c3d4"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_state():
    """테스트 전후 글로벌 상태 초기화."""
    old = {
        "assembler": api._assembler,
        "neo4j": api._neo4j_graph,
        "qdrant": api._qdrant_ready,
        "code_svc": code_graph_api._service,
        "code_vec": code_graph_api._code_vector_search,
        "code_asm": code_graph_api._code_assembler,
        "nvd": cve_api._nvd_client,
        "mem": project_memory_api._service,
        "source_kg_repo": source_kg_api._ledger_repository,
        "judge_repo": judge_api._ledger_repository,
    }
    yield
    api.set_assembler(old["assembler"])
    api.set_neo4j_graph(old["neo4j"])
    api.set_qdrant_ready(old["qdrant"])
    code_graph_api.set_service(old["code_svc"])
    code_graph_api.set_code_vector_search(old["code_vec"])
    code_graph_api.set_code_assembler(old["code_asm"])
    cve_api.set_nvd_client(old["nvd"])
    project_memory_api.set_service(old["mem"])
    source_kg_api.set_ledger_repository(old["source_kg_repo"])
    judge_api.set_ledger_repository(old["judge_repo"])


@pytest.fixture()
def _init_threat_search():
    """위협 검색 엔드포인트용 초기화."""
    api.set_assembler(FakeAssembler())
    api.set_neo4j_graph(FakeNeo4jGraph())
    api.set_qdrant_ready(True)
    source_kg_api.set_ledger_repository(object())
    judge_api.set_ledger_repository(object())


@pytest.fixture()
def _init_code_graph():
    """코드 그래프 엔드포인트용 초기화."""
    code_graph_api.set_service(FakeCodeGraphService())
    code_graph_api.set_code_vector_search(FakeCodeVectorSearch())
    code_graph_api.set_code_assembler(FakeCodeAssembler())


@pytest.fixture()
def _init_cve():
    """CVE 엔드포인트용 초기화."""
    cve_api.set_nvd_client(FakeNvdClient())


@pytest.fixture()
def _init_memory():
    """프로젝트 메모리 엔드포인트용 초기화."""
    project_memory_api.set_service(FakeMemoryService())


client = TestClient(app, raise_server_exceptions=False)


# ===========================================================================
# 1. 위협 지식 검색
# ===========================================================================


class TestSearchContract:
    """POST /v1/search 성공 응답 shape."""

    def test_response_shape(self, _init_threat_search):
        resp = client.post("/v1/search", json={"query": "CWE-78"}, headers=_HEADERS)
        assert resp.status_code == 200
        body = resp.json()

        # 최상위 필드 존재
        assert "query" in body
        assert "hits" in body
        assert "total" in body
        assert "extracted_ids" in body
        assert "related_cwe" in body
        assert "related_cve" in body
        assert "related_attack" in body
        assert "match_type_counts" in body

        # 타입 검증
        assert isinstance(body["query"], str)
        assert isinstance(body["hits"], list)
        assert isinstance(body["total"], int)
        assert isinstance(body["extracted_ids"], list)
        assert isinstance(body["related_cwe"], list)
        assert isinstance(body["related_cve"], list)
        assert isinstance(body["related_attack"], list)
        assert isinstance(body["match_type_counts"], dict)

    def test_hit_shape(self, _init_threat_search):
        resp = client.post("/v1/search", json={"query": "CWE-78"}, headers=_HEADERS)
        body = resp.json()
        assert body["total"] > 0

        hit = body["hits"][0]
        # 필수 필드
        for key in ("id", "source", "title", "score", "threat_category", "match_type"):
            assert key in hit, f"hit에 '{key}' 필드 누락"

        # match_type 값 범위
        assert hit["match_type"] in ("id_exact", "graph_neighbor", "vector_semantic")

    def test_match_type_counts_keys(self, _init_threat_search):
        resp = client.post("/v1/search", json={"query": "CWE-78"}, headers=_HEADERS)
        counts = resp.json()["match_type_counts"]
        for key in ("id_exact", "graph_neighbor", "vector_semantic"):
            assert key in counts
            assert isinstance(counts[key], int)

    def test_graph_relations_on_exact_hit(self, _init_threat_search):
        """id_exact hit에는 graph_relations가 포함되어야 한다."""
        resp = client.post("/v1/search", json={"query": "CWE-78"}, headers=_HEADERS)
        exact_hits = [h for h in resp.json()["hits"] if h["match_type"] == "id_exact"]
        assert len(exact_hits) >= 1
        hit = exact_hits[0]
        assert "graph_relations" in hit
        assert isinstance(hit["graph_relations"], dict)

    def test_extracted_ids_populated(self, _init_threat_search):
        resp = client.post("/v1/search", json={"query": "CWE-78 command injection"}, headers=_HEADERS)
        body = resp.json()
        assert "CWE-78" in body["extracted_ids"]

    def test_empty_query_returns_empty(self, _init_threat_search):
        resp = client.post("/v1/search", json={"query": ""}, headers=_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["hits"] == []
        assert body["total"] == 0

    def test_no_degraded_key(self, _init_threat_search):
        """계약서에 degraded 필드는 없다."""
        resp = client.post("/v1/search", json={"query": "test"}, headers=_HEADERS)
        assert "degraded" not in resp.json()


class TestSearchBatchContract:
    """POST /v1/search/batch 성공 응답 shape."""

    def test_response_shape(self, _init_threat_search):
        resp = client.post(
            "/v1/search/batch",
            json={"queries": [{"query": "CWE-78"}, {"query": "CWE-120"}]},
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()

        assert "results" in body
        assert "global_stats" in body
        assert "latency_ms" in body

        assert isinstance(body["results"], list)
        assert isinstance(body["latency_ms"], int)

    def test_global_stats_shape(self, _init_threat_search):
        resp = client.post(
            "/v1/search/batch",
            json={"queries": [{"query": "CWE-78"}]},
            headers=_HEADERS,
        )
        gs = resp.json()["global_stats"]
        for key in ("total_queries", "total_hits", "unique_ids"):
            assert key in gs
            assert isinstance(gs[key], int)

    def test_each_result_matches_single_search_shape(self, _init_threat_search):
        resp = client.post(
            "/v1/search/batch",
            json={"queries": [{"query": "CWE-78"}]},
            headers=_HEADERS,
        )
        result = resp.json()["results"][0]
        for key in ("query", "hits", "total", "extracted_ids",
                     "related_cwe", "related_cve", "related_attack", "match_type_counts"):
            assert key in result, f"batch result에 '{key}' 필드 누락"


class TestGraphStatsContract:
    """GET /v1/graph/stats 성공 응답 shape."""

    def test_response_shape(self, _init_threat_search):
        resp = client.get("/v1/graph/stats", headers={"X-Request-Id": _REQ_ID})
        assert resp.status_code == 200
        body = resp.json()

        for key in ("nodeCount", "edgeCount", "sources", "edgeTypes", "topConnected"):
            assert key in body, f"graph/stats에 '{key}' 필드 누락"

        assert isinstance(body["nodeCount"], int)
        assert isinstance(body["edgeCount"], int)
        assert isinstance(body["sources"], dict)
        assert isinstance(body["edgeTypes"], dict)
        assert isinstance(body["topConnected"], list)

    def test_sources_keys(self, _init_threat_search):
        resp = client.get("/v1/graph/stats")
        sources = resp.json()["sources"]
        for key in ("CWE", "CVE", "Attack", "CAPEC"):
            assert key in sources

    def test_top_connected_item_shape(self, _init_threat_search):
        resp = client.get("/v1/graph/stats")
        items = resp.json()["topConnected"]
        assert len(items) >= 1
        item = items[0]
        for key in ("id", "title", "label", "degree"):
            assert key in item


class TestGraphNeighborsContract:
    """GET /v1/graph/neighbors/{node_id} 성공 응답 shape."""

    def test_response_shape(self, _init_threat_search):
        resp = client.get("/v1/graph/neighbors/CWE-78")
        assert resp.status_code == 200
        body = resp.json()

        for key in ("nodeId", "nodeInfo", "neighbors", "related"):
            assert key in body, f"graph/neighbors에 '{key}' 필드 누락"

        assert body["nodeId"] == "CWE-78"
        assert isinstance(body["nodeInfo"], dict)
        assert isinstance(body["neighbors"], list)
        assert isinstance(body["related"], dict)

    def test_node_not_found_404(self, _init_threat_search):
        resp = client.get("/v1/graph/neighbors/NONEXISTENT")
        assert resp.status_code == 404
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "NOT_FOUND"


# ===========================================================================
# 2. 코드 그래프
# ===========================================================================


class TestCodeGraphIngestContract:
    """POST /v1/code-graph/{project_id}/ingest 성공 응답 shape."""

    _FUNCTIONS = [
        {"name": "postJson", "file": "http.cpp", "line": 8, "calls": ["popen", "fgets"]},
        {"name": "main", "file": "main.cpp", "line": 1, "calls": ["postJson"]},
    ]

    def test_response_shape(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": self._FUNCTIONS},
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()

        for key in (
            "project_id",
            "nodeCount",
            "edgeCount",
            "files",
            "vectorCount",
            "operation",
            "readiness",
            "status",
        ):
            assert key in body, f"ingest 응답에 '{key}' 필드 누락"

        assert isinstance(body["nodeCount"], int)
        assert isinstance(body["edgeCount"], int)
        assert isinstance(body["files"], list)
        assert isinstance(body["vectorCount"], int)
        assert body["operation"] == {
            "mode": "replace_project_graph",
            "repeatable": True,
            "replacedExistingGraph": False,
        }
        assert body["readiness"] == {
            "neo4jGraph": True,
            "vectorIndex": True,
            "graphRag": True,
        }
        assert body["status"] == "ready"

    def test_ingest_completion_is_structured_logged(self, _init_code_graph, caplog):
        caplog.set_level(logging.INFO, logger="app.routers.code_graph_api")

        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": self._FUNCTIONS},
            headers=_HEADERS,
        )

        assert resp.status_code == 200
        records = [
            rec for rec in caplog.records
            if rec.name == "app.routers.code_graph_api"
            and rec.getMessage() == "코드 그래프 ingest 완료"
        ]
        assert records
        extra = records[-1]._extra
        assert extra["projectId"] == "re100"
        assert extra["status"] == "ready"
        assert extra["expectedVectorCount"] == len(self._FUNCTIONS)
        assert extra["readinessGraphRag"] is True
        assert isinstance(extra["elapsedMs"], int)

    def test_ingest_ready_when_graph_has_more_nodes_than_vectorized_functions(self):
        class GraphWithExternalCallees(FakeCodeGraphService):
            def ingest(self, project_id, functions, *, provenance=None):
                return {
                    "project_id": project_id,
                    "replaceMode": "replace_project_graph",
                    "replacedExistingGraph": False,
                    "nodeCount": 24,
                    "edgeCount": 41,
                    "files": ["main.cpp", "http.cpp"],
                }

        code_graph_api.set_service(GraphWithExternalCallees())
        code_graph_api.set_code_vector_search(FakeCodeVectorSearch())
        code_graph_api.set_code_assembler(FakeCodeAssembler())

        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": self._FUNCTIONS},
            headers=_HEADERS,
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["nodeCount"] == 24
        assert body["vectorCount"] == len(self._FUNCTIONS)
        assert body["status"] == "ready"
        assert body["readiness"] == {
            "neo4jGraph": True,
            "vectorIndex": True,
            "graphRag": True,
        }
        assert "warnings" not in body

    def test_provenance_passthrough(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={
                "functions": self._FUNCTIONS,
                "provenance": {
                    "buildSnapshotId": "snap-001",
                    "buildUnitId": "unit-gw",
                    "sourceBuildAttemptId": "attempt-1",
                },
            },
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "provenance" in body
        prov = body["provenance"]
        assert prov["buildSnapshotId"] == "snap-001"
        assert prov["buildUnitId"] == "unit-gw"
        assert prov["sourceBuildAttemptId"] == "attempt-1"

    def test_ingest_without_provenance_omits_key(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": self._FUNCTIONS},
            headers=_HEADERS,
        )
        body = resp.json()
        assert "provenance" not in body

    def test_ingest_marks_repeat_replacement(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/existing-project/ingest",
            json={"functions": self._FUNCTIONS},
            headers=_HEADERS,
        )
        body = resp.json()
        assert body["operation"]["replacedExistingGraph"] is True

    def test_ingest_partial_when_vector_stage_unavailable(self):
        code_graph_api.set_service(FakeCodeGraphService())
        code_graph_api.set_code_vector_search(None)
        code_graph_api.set_code_assembler(FakeCodeAssembler())

        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": self._FUNCTIONS},
            headers=_HEADERS,
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["vectorCount"] == 0
        assert body["status"] == "partial"
        assert body["readiness"] == {
            "neo4jGraph": True,
            "vectorIndex": False,
            "graphRag": False,
        }
        assert body["warnings"] == ["VECTOR_INDEX_INCOMPLETE"]

    def test_ingest_empty_graph_reports_not_ready(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": []},
            headers=_HEADERS,
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "empty"
        assert body["readiness"] == {
            "neo4jGraph": False,
            "vectorIndex": False,
            "graphRag": False,
        }

    def test_503_when_not_initialized(self):
        code_graph_api.set_service(None)
        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": [{"name": "f", "file": "f.c", "line": 1, "calls": []}]},
            headers=_HEADERS,
        )
        assert resp.status_code == 503


class TestCodeGraphSearchContract:
    """POST /v1/code-graph/{project_id}/search 성공 응답 shape."""

    def test_response_shape(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/search",
            json={"query": "network handler"},
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()

        for key in ("query", "hits", "total", "match_type_counts", "latency_ms"):
            assert key in body, f"code-graph search에 '{key}' 필드 누락"

        assert isinstance(body["latency_ms"], int)

    def test_hit_shape(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/search",
            json={"query": "network handler"},
            headers=_HEADERS,
        )
        hit = resp.json()["hits"][0]
        for key in ("name", "file", "score", "match_type"):
            assert key in hit, f"code search hit에 '{key}' 누락"
        assert hit["match_type"] in ("name_exact", "vector_semantic", "graph_neighbor")

    def test_match_type_counts_keys(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/search",
            json={"query": "test"},
            headers=_HEADERS,
        )
        counts = resp.json()["match_type_counts"]
        for key in ("name_exact", "vector_semantic", "graph_neighbor"):
            assert key in counts

    def test_provenance_filter(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/search",
            json={"query": "test", "buildSnapshotId": "snap-001"},
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("provenance", {}).get("buildSnapshotId") == "snap-001"

    def test_503_when_assembler_not_initialized(self):
        code_graph_api.set_service(FakeCodeGraphService())
        code_graph_api.set_code_assembler(None)
        resp = client.post(
            "/v1/code-graph/re100/search",
            json={"query": "test"},
            headers=_HEADERS,
        )
        assert resp.status_code == 503


class TestCodeGraphStatsContract:
    """GET /v1/code-graph/{project_id}/stats 응답 shape."""

    def test_response_shape(self, _init_code_graph):
        resp = client.get("/v1/code-graph/re100/stats")
        assert resp.status_code == 200
        body = resp.json()

        for key in ("nodeCount", "edgeCount", "files"):
            assert key in body

    def test_stats_is_structured_logged(self, _init_code_graph, caplog):
        caplog.set_level(logging.INFO, logger="app.routers.code_graph_api")

        resp = client.get("/v1/code-graph/re100/stats", headers={"X-Request-Id": _REQ_ID})

        assert resp.status_code == 200
        records = [
            rec for rec in caplog.records
            if rec.name == "app.routers.code_graph_api"
            and rec.getMessage() == "코드 그래프 stats 조회"
        ]
        assert records
        extra = records[-1]._extra
        assert extra["projectId"] == "re100"
        assert extra["nodeCount"] == 3
        assert extra["edgeCount"] == 2
        assert extra["fileCount"] == 2

    def test_provenance_filter(self, _init_code_graph):
        resp = client.get("/v1/code-graph/re100/stats?buildSnapshotId=snap-001")
        body = resp.json()
        assert body.get("provenance", {}).get("buildSnapshotId") == "snap-001"


class TestCodeGraphCallersContract:
    """GET /v1/code-graph/{project_id}/callers/{function_name} 응답 shape."""

    def test_response_shape(self, _init_code_graph):
        resp = client.get("/v1/code-graph/re100/callers/popen")
        assert resp.status_code == 200
        body = resp.json()

        assert "function" in body
        assert "depth" in body
        assert "callers" in body
        assert body["function"] == "popen"
        assert isinstance(body["callers"], list)

    def test_caller_item_shape(self, _init_code_graph):
        resp = client.get("/v1/code-graph/re100/callers/popen")
        callers = resp.json()["callers"]
        assert len(callers) >= 1
        caller = callers[0]
        for key in ("name", "file", "line"):
            assert key in caller


class TestCodeGraphCalleesContract:
    """GET /v1/code-graph/{project_id}/callees/{function_name} 응답 shape."""

    def test_response_shape(self, _init_code_graph):
        resp = client.get("/v1/code-graph/re100/callees/postJson")
        assert resp.status_code == 200
        body = resp.json()

        assert "function" in body
        assert "callees" in body
        assert body["function"] == "postJson"
        assert isinstance(body["callees"], list)


class TestCodeGraphDangerousCallersContract:
    """POST /v1/code-graph/{project_id}/dangerous-callers 응답 shape."""

    def test_response_shape(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/dangerous-callers",
            json={"dangerous_functions": ["popen", "system"]},
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()

        assert "results" in body
        assert isinstance(body["results"], list)

    def test_result_item_shape(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/dangerous-callers",
            json={"dangerous_functions": ["popen"]},
            headers=_HEADERS,
        )
        item = resp.json()["results"][0]
        for key in ("name", "file", "line", "dangerous_calls"):
            assert key in item
        assert isinstance(item["dangerous_calls"], list)

    def test_dangerous_callers_is_structured_logged(self, _init_code_graph, caplog):
        caplog.set_level(logging.INFO, logger="app.routers.code_graph_api")

        resp = client.post(
            "/v1/code-graph/re100/dangerous-callers",
            json={"dangerous_functions": ["popen", "system"]},
            headers=_HEADERS,
        )

        assert resp.status_code == 200
        records = [
            rec for rec in caplog.records
            if rec.name == "app.routers.code_graph_api"
            and rec.getMessage() == "코드 그래프 dangerous-callers 조회"
        ]
        assert records
        extra = records[-1]._extra
        assert extra["projectId"] == "re100"
        assert extra["dangerousFunctionCount"] == 2
        assert extra["resultCount"] == 1
        assert extra["timeoutMs"] == int(_TIMEOUT["X-Timeout-Ms"])


class TestCodeGraphDeleteContract:
    """DELETE /v1/code-graph/{project_id} 응답 shape."""

    def test_success_response(self, _init_code_graph):
        resp = client.delete("/v1/code-graph/re100")
        assert resp.status_code == 200
        body = resp.json()
        assert body["deleted"] is True
        assert body["project_id"] == "re100"

    def test_not_found_404(self, _init_code_graph):
        resp = client.delete("/v1/code-graph/nonexistent")
        assert resp.status_code == 404
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "NOT_FOUND"


class TestCodeGraphListProjectsContract:
    """GET /v1/code-graph 응답 shape."""

    def test_response_shape(self, _init_code_graph):
        resp = client.get("/v1/code-graph")
        assert resp.status_code == 200
        body = resp.json()
        assert "projects" in body
        assert isinstance(body["projects"], list)
        assert "re100" in body["projects"]


# ===========================================================================
# 3. CVE batch-lookup
# ===========================================================================


class TestCveBatchLookupContract:
    """POST /v1/cve/batch-lookup 성공 응답 shape."""

    _LIBRARIES = [
        {"name": "mosquitto", "version": "2.0.22"},
    ]

    def test_response_shape(self, _init_cve):
        resp = client.post(
            "/v1/cve/batch-lookup",
            json={"libraries": self._LIBRARIES},
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()

        assert "results" in body
        assert "latency_ms" in body
        assert isinstance(body["results"], list)
        assert isinstance(body["latency_ms"], int)

    def test_result_item_shape(self, _init_cve):
        resp = client.post(
            "/v1/cve/batch-lookup",
            json={"libraries": self._LIBRARIES},
            headers=_HEADERS,
        )
        item = resp.json()["results"][0]
        for key in ("library", "version", "cves", "total", "cached"):
            assert key in item, f"CVE result에 '{key}' 필드 누락"

    def test_cve_entry_shape(self, _init_cve):
        resp = client.post(
            "/v1/cve/batch-lookup",
            json={"libraries": self._LIBRARIES},
            headers=_HEADERS,
        )
        cve = resp.json()["results"][0]["cves"][0]
        for key in ("id", "title", "description", "severity", "attack_vector",
                     "affected_versions", "version_match", "risk_score",
                     "epss_score", "epss_percentile", "kev",
                     "related_cwe", "related_attack", "kb_context", "source"):
            assert key in cve, f"CVE entry에 '{key}' 필드 누락"

    def test_kb_context_shape(self, _init_cve):
        resp = client.post(
            "/v1/cve/batch-lookup",
            json={"libraries": self._LIBRARIES},
            headers=_HEADERS,
        )
        ctx = resp.json()["results"][0]["cves"][0]["kb_context"]
        for key in ("threat_categories", "attack_surfaces", "max_automotive_relevance"):
            assert key in ctx, f"kb_context에 '{key}' 필드 누락"
        assert isinstance(ctx["threat_categories"], list)
        assert isinstance(ctx["attack_surfaces"], list)
        assert isinstance(ctx["max_automotive_relevance"], (int, float))

    def test_503_when_not_initialized(self):
        cve_api.set_nvd_client(None)
        resp = client.post(
            "/v1/cve/batch-lookup",
            json={"libraries": [{"name": "test", "version": "1.0"}]},
            headers=_HEADERS,
        )
        assert resp.status_code == 503

    def test_camel_case_repo_url_accepted(self, _init_cve):
        """계약서: repoUrl camelCase도 수용."""
        resp = client.post(
            "/v1/cve/batch-lookup",
            json={"libraries": [
                {"name": "curl", "version": "7.68.0", "repoUrl": "https://github.com/curl/curl.git"},
            ]},
            headers=_HEADERS,
        )
        assert resp.status_code == 200


# ===========================================================================
# 4. 프로젝트 메모리
# ===========================================================================


class TestProjectMemoryListContract:
    """GET /v1/project-memory/{project_id} 성공 응답 shape."""

    def test_response_shape(self, _init_memory):
        resp = client.get("/v1/project-memory/re100")
        assert resp.status_code == 200
        body = resp.json()

        assert "projectId" in body
        assert "memories" in body
        assert body["projectId"] == "re100"
        assert isinstance(body["memories"], list)

    def test_memory_item_shape(self, _init_memory):
        resp = client.get("/v1/project-memory/re100")
        mem = resp.json()["memories"][0]
        for key in ("id", "type", "data", "createdAt"):
            assert key in mem, f"memory에 '{key}' 필드 누락"
        assert isinstance(mem["data"], dict)

    def test_503_when_not_initialized(self):
        project_memory_api.set_service(None)
        resp = client.get("/v1/project-memory/re100")
        assert resp.status_code == 503

    def test_type_filter_accepted(self, _init_memory):
        resp = client.get("/v1/project-memory/re100?type=false_positive")
        assert resp.status_code == 200

    def test_provenance_filter_accepted(self, _init_memory):
        resp = client.get("/v1/project-memory/re100?buildSnapshotId=snap-001")
        assert resp.status_code == 200

    def test_list_memories_is_structured_logged(self, _init_memory, caplog):
        caplog.set_level(logging.INFO, logger="app.routers.project_memory_api")

        resp = client.get(
            "/v1/project-memory/re100?type=analysis_history",
            headers={"X-Request-Id": _REQ_ID},
        )

        assert resp.status_code == 200
        records = [
            rec for rec in caplog.records
            if rec.name == "app.routers.project_memory_api"
            and rec.getMessage() == "프로젝트 메모리 조회"
        ]
        assert records
        extra = records[-1]._extra
        assert extra["projectId"] == "re100"
        assert extra["type"] == "analysis_history"
        assert extra["resultCount"] == 1


class TestProjectMemoryCreateContract:
    """POST /v1/project-memory/{project_id} 성공 응답 shape."""

    def test_response_shape(self, _init_memory):
        resp = client.post(
            "/v1/project-memory/re100",
            json={"type": "false_positive", "data": {"pattern": "test"}},
        )
        assert resp.status_code == 200
        body = resp.json()
        for key in ("id", "type", "createdAt"):
            assert key in body, f"create memory 응답에 '{key}' 필드 누락"

    def test_create_memory_is_structured_logged(self, _init_memory, caplog):
        caplog.set_level(logging.INFO, logger="app.routers.project_memory_api")

        resp = client.post(
            "/v1/project-memory/re100",
            json={"type": "false_positive", "data": {"pattern": "test"}},
            headers={"X-Request-Id": _REQ_ID},
        )

        assert resp.status_code == 200
        records = [
            rec for rec in caplog.records
            if rec.name == "app.routers.project_memory_api"
            and rec.getMessage() == "프로젝트 메모리 생성 요청 완료"
        ]
        assert records
        extra = records[-1]._extra
        assert extra["projectId"] == "re100"
        assert extra["type"] == "false_positive"
        assert extra["memoryId"] == "mem-new12345"

    def test_provenance_passthrough(self, _init_memory):
        resp = client.post(
            "/v1/project-memory/re100",
            json={
                "type": "preference",
                "data": {"key": "value"},
                "provenance": {
                    "buildSnapshotId": "snap-001",
                    "buildUnitId": "unit-gw",
                },
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "provenance" in body
        assert body["provenance"]["buildSnapshotId"] == "snap-001"
        assert body["provenance"]["buildUnitId"] == "unit-gw"

    def test_invalid_type_returns_422(self, _init_memory):
        resp = client.post(
            "/v1/project-memory/re100",
            json={"type": "invalid_type", "data": {}},
        )
        assert resp.status_code == 422

    def test_503_when_not_initialized(self):
        project_memory_api.set_service(None)
        resp = client.post(
            "/v1/project-memory/re100",
            json={"type": "preference", "data": {}},
        )
        assert resp.status_code == 503


class TestProjectMemoryDeleteContract:
    """DELETE /v1/project-memory/{project_id}/{memory_id} 응답 shape."""

    def test_success_response(self, _init_memory):
        resp = client.delete("/v1/project-memory/re100/mem-a1b2c3d4")
        assert resp.status_code == 200
        body = resp.json()
        assert body["deleted"] is True
        assert body["projectId"] == "re100"
        assert body["memoryId"] == "mem-a1b2c3d4"

    def test_delete_memory_is_structured_logged(self, _init_memory, caplog):
        caplog.set_level(logging.INFO, logger="app.routers.project_memory_api")

        resp = client.delete(
            "/v1/project-memory/re100/mem-a1b2c3d4",
            headers={"X-Request-Id": _REQ_ID},
        )

        assert resp.status_code == 200
        records = [
            rec for rec in caplog.records
            if rec.name == "app.routers.project_memory_api"
            and rec.getMessage() == "프로젝트 메모리 삭제"
        ]
        assert records
        extra = records[-1]._extra
        assert extra["projectId"] == "re100"
        assert extra["memoryId"] == "mem-a1b2c3d4"
        assert extra["deleted"] is True

    def test_not_found_404(self, _init_memory):
        resp = client.delete("/v1/project-memory/re100/mem-nonexistent")
        assert resp.status_code == 404
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "NOT_FOUND"

    def test_503_when_not_initialized(self):
        project_memory_api.set_service(None)
        resp = client.delete("/v1/project-memory/re100/mem-x")
        assert resp.status_code == 503


# ===========================================================================
# 5. 헬스체크
# ===========================================================================


class TestHealthContract:
    """GET /v1/health 계약 검증."""

    def test_response_shape(self):
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["service"] == "aegis-knowledge-base"
        assert body["status"] == "ok"
        assert "version" in body

    def test_no_extra_legacy_fields(self):
        resp = client.get("/v1/health")
        body = resp.json()
        assert "initialized" not in body
        assert "graph" not in body


class TestReadyContract:
    """GET /v1/ready 계약 검증."""

    def test_success_shape(self, _init_threat_search):
        resp = client.get("/v1/ready")
        assert resp.status_code == 200
        body = resp.json()

        assert body["service"] == "aegis-knowledge-base"
        assert body["ready"] is True
        assert "components" in body

        qdrant = body["components"]["qdrant"]
        assert "initialized" in qdrant

        neo4j = body["components"]["neo4j"]
        assert "connected" in neo4j
        assert "nodeCount" in neo4j
        assert "edgeCount" in neo4j

    def test_ontology_included_when_kb_meta_present(self, _init_threat_search):
        resp = client.get("/v1/ready")
        body = resp.json()
        assert "ontology" in body
        ontology = body["ontology"]
        for key in ("cwe_version", "attack_enterprise_version", "capec_version", "total_records"):
            assert key in ontology


# ===========================================================================
# 6. 공통 헤더
# ===========================================================================


class TestRequestIdEcho:
    """X-Request-Id 응답 헤더 echo 검증."""

    def test_success_path_echoes_request_id(self, _init_threat_search):
        resp = client.post(
            "/v1/search",
            json={"query": "CWE-78"},
            headers=_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.headers.get("X-Request-Id") == _REQ_ID

    def test_health_echoes_request_id(self):
        """health는 X-Request-Id 미지원이면 헤더 없음 — 확인용."""
        resp = client.get("/v1/health", headers={"X-Request-Id": _REQ_ID})
        # health는 set_request_id를 호출하지 않으므로 미들웨어에서 echo
        assert resp.headers.get("X-Request-Id") == _REQ_ID

    def test_no_request_id_means_no_header(self, _init_threat_search):
        resp = client.post("/v1/search", json={"query": "test"}, headers=_TIMEOUT)
        assert "X-Request-Id" not in resp.headers

    def test_error_path_echoes_request_id(self):
        resp = client.post(
            "/v1/search",
            json={"query": "test"},
            headers={"X-Request-Id": _REQ_ID, "X-Timeout-Ms": "10000"},
        )
        # 503 에러에서도 X-Request-Id 헤더 echo
        assert resp.headers.get("X-Request-Id") == _REQ_ID


class TestTimeoutHeaderEnforcement:
    """X-Timeout-Ms 헤더 누락 시 400 — 모든 POST 엔드포인트."""

    def test_search_requires_timeout(self, _init_threat_search):
        resp = client.post("/v1/search", json={"query": "test"})
        assert resp.status_code == 400

    def test_search_batch_requires_timeout(self, _init_threat_search):
        resp = client.post("/v1/search/batch", json={"queries": [{"query": "t"}]})
        assert resp.status_code == 400

    def test_code_graph_ingest_requires_timeout(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/ingest",
            json={"functions": [{"name": "f", "file": "f.c", "line": 1, "calls": []}]},
        )
        assert resp.status_code == 400

    def test_code_graph_search_requires_timeout(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/search",
            json={"query": "test"},
        )
        assert resp.status_code == 400

    def test_dangerous_callers_requires_timeout(self, _init_code_graph):
        resp = client.post(
            "/v1/code-graph/re100/dangerous-callers",
            json={"dangerous_functions": ["popen"]},
        )
        assert resp.status_code == 400

    def test_cve_batch_lookup_requires_timeout(self, _init_cve):
        resp = client.post(
            "/v1/cve/batch-lookup",
            json={"libraries": [{"name": "test", "version": "1.0"}]},
        )
        assert resp.status_code == 400
