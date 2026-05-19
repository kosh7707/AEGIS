"""Phase 1+2: HTTP 에러 시맨틱 + Health/Readiness 분리 테스트."""

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import api, code_graph_api, cve_api, judge_api, project_memory_api, source_kg_api


@pytest.fixture(autouse=True)
def _reset_state():
    """테스트 전후 글로벌 상태 초기화."""
    old_assembler = api._assembler
    old_graph = api._neo4j_graph
    old_qdrant_ready = api._qdrant_ready
    old_code_service = code_graph_api._service
    old_code_vector = code_graph_api._code_vector_search
    old_code_assembler = code_graph_api._code_assembler
    old_nvd_client = cve_api._nvd_client
    old_memory_service = project_memory_api._service
    old_source_kg_repo = source_kg_api._ledger_repository
    old_judge_repo = judge_api._ledger_repository
    api.set_assembler(None)
    api.set_neo4j_graph(None)
    api.set_qdrant_ready(False)
    code_graph_api.set_service(None)
    code_graph_api.set_code_vector_search(None)
    code_graph_api.set_code_assembler(None)
    cve_api.set_nvd_client(None)
    project_memory_api.set_service(None)
    source_kg_api.set_ledger_repository(None)
    judge_api.set_ledger_repository(None)
    yield
    api.set_assembler(old_assembler)
    api.set_neo4j_graph(old_graph)
    api.set_qdrant_ready(old_qdrant_ready)
    code_graph_api.set_service(old_code_service)
    code_graph_api.set_code_vector_search(old_code_vector)
    code_graph_api.set_code_assembler(old_code_assembler)
    cve_api.set_nvd_client(old_nvd_client)
    project_memory_api.set_service(old_memory_service)
    source_kg_api.set_ledger_repository(old_source_kg_repo)
    judge_api.set_ledger_repository(old_judge_repo)


client = TestClient(app, raise_server_exceptions=False)


def _assert_503_format(resp, expected_code="KB_NOT_READY"):
    """503 응답이 observability.md 에러 포맷을 따르는지 검증."""
    assert resp.status_code == 503
    body = resp.json()
    assert body["success"] is False
    assert "error" in body
    assert body["errorDetail"]["code"] == expected_code
    assert body["errorDetail"]["retryable"] is True


# ── Phase 1: 미초기화 시 503 반환 ──


_TIMEOUT_HEADER = {"X-Timeout-Ms": "10000"}


def test_search_uninitialized_returns_503():
    resp = client.post("/v1/search", json={"query": "CWE-78"}, headers=_TIMEOUT_HEADER)
    _assert_503_format(resp)


def test_search_batch_uninitialized_returns_503():
    resp = client.post(
        "/v1/search/batch",
        json={"queries": [{"query": "test"}]},
        headers=_TIMEOUT_HEADER,
    )
    _assert_503_format(resp)


def test_graph_stats_uninitialized_returns_503():
    resp = client.get("/v1/graph/stats")
    _assert_503_format(resp)


def test_graph_neighbors_uninitialized_returns_503():
    resp = client.get("/v1/graph/neighbors/CWE-78")
    _assert_503_format(resp)


def test_error_includes_request_id():
    resp = client.post(
        "/v1/search",
        json={"query": "test"},
        headers={"X-Request-Id": "req-test-123", "X-Timeout-Ms": "10000"},
    )
    _assert_503_format(resp)
    assert resp.json()["errorDetail"]["requestId"] == "req-test-123"


def test_search_missing_timeout_returns_400():
    """X-Timeout-Ms 헤더 누락 시 400 반환."""
    resp = client.post("/v1/search", json={"query": "test"})
    assert resp.status_code == 400
    assert "X-Timeout-Ms" in resp.json()["error"]


# ── Phase 2: Health / Readiness ──


def test_health_always_200():
    resp = client.get("/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "aegis-knowledge-base"
    assert "initialized" not in body  # 이전 필드 제거됨
    assert "graph" not in body


def test_ready_returns_503_when_not_initialized():
    resp = client.get("/v1/ready")
    _assert_503_format(resp)


def test_ready_returns_200_when_initialized():
    class FakeGraph:
        node_count = 100
        edge_count = 200

    class FakeAssembler:
        pass

    api.set_assembler(FakeAssembler())
    api.set_neo4j_graph(FakeGraph())
    api.set_qdrant_ready(True)
    source_kg_api.set_ledger_repository(object())
    judge_api.set_ledger_repository(object())

    resp = client.get("/v1/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True
    assert body["components"]["qdrant"]["initialized"] is True
    assert body["components"]["neo4j"]["connected"] is True
    assert body["components"]["neo4j"]["nodeCount"] == 100


def test_ready_returns_503_when_source_kg_judge_ledger_unavailable():
    class FakeGraph:
        node_count = 100
        edge_count = 200

    class FakeAssembler:
        pass

    api.set_assembler(FakeAssembler())
    api.set_neo4j_graph(FakeGraph())
    api.set_qdrant_ready(True)
    source_kg_api.set_ledger_repository(None)
    judge_api.set_ledger_repository(None)

    resp = client.get("/v1/ready", headers={"X-Request-Id": "req-ready-no-ledger"})

    _assert_503_format(resp)
    body = resp.json()
    assert body["errorDetail"]["requestId"] == "req-ready-no-ledger"


# ── 전역 HTTPException 핸들러 ──


# ── Search readiness semantics ──


class _ReadyAssembler:
    """search 성공 응답 테스트용 — 최소한의 assemble/batch_assemble 구현."""

    def assemble(self, query, **kwargs):
        return {
            "query": query, "hits": [], "total": 0,
            "extracted_ids": [], "related_cwe": [], "related_cve": [],
            "related_attack": [],
            "match_type_counts": {"id_exact": 0, "graph_neighbor": 0, "vector_semantic": 0},
        }

    def batch_assemble(self, queries):
        results = [self.assemble(q["query"]) for q in queries]
        return {"results": results, "global_stats": {"total_queries": len(queries), "total_hits": 0, "unique_ids": 0}}


def test_search_returns_503_when_neo4j_down_even_if_qdrant_ready():
    api.set_assembler(_ReadyAssembler())
    api.set_qdrant_ready(True)

    resp = client.post("/v1/search", json={"query": "CWE-78"}, headers=_TIMEOUT_HEADER)
    _assert_503_format(resp)


def test_batch_search_returns_503_when_neo4j_down_even_if_qdrant_ready():
    api.set_assembler(_ReadyAssembler())
    api.set_qdrant_ready(True)

    resp = client.post(
        "/v1/search/batch",
        json={"queries": [{"query": "test"}]},
        headers=_TIMEOUT_HEADER,
    )
    _assert_503_format(resp)


def test_search_success_payload_has_no_degraded_key():
    class FakeGraph:
        node_count = 10
        edge_count = 5

    api.set_assembler(_ReadyAssembler())
    api.set_neo4j_graph(FakeGraph())
    api.set_qdrant_ready(True)

    resp = client.post("/v1/search", json={"query": "test"}, headers=_TIMEOUT_HEADER)
    assert resp.status_code == 200
    assert "degraded" not in resp.json()


def test_project_memory_limit_error_uses_specific_code():
    from app.graphrag.project_memory_service import MemoryLimitError

    class FakeMemoryService:
        def create_memory(self, *args, **kwargs):
            raise MemoryLimitError("limit reached")

    project_memory_api.set_service(FakeMemoryService())

    resp = client.post(
        "/v1/project-memory/re100",
        json={"type": "preference", "data": {"key": "value"}},
    )
    assert resp.status_code == 409
    body = resp.json()
    assert body["errorDetail"]["code"] == "MEMORY_LIMIT_EXCEEDED"


def test_code_graph_503_uses_kb_not_ready_code():
    resp = client.post(
        "/v1/code-graph/re100/ingest",
        json={"functions": [{"name": "main", "file": "main.cpp", "line": 1, "calls": []}]},
        headers=_TIMEOUT_HEADER,
    )
    _assert_503_format(resp)


def test_project_memory_503_uses_kb_not_ready_code():
    resp = client.get("/v1/project-memory/re100")
    _assert_503_format(resp)


def test_cve_batch_503_uses_kb_not_ready_code():
    resp = client.post(
        "/v1/cve/batch-lookup",
        json={"libraries": [{"name": "test", "version": "1.0"}]},
        headers=_TIMEOUT_HEADER,
    )
    _assert_503_format(resp)


def test_code_graph_ingest_defaults_vector_count_to_zero_when_vector_unavailable():
    class FakeCodeGraphService:
        def export_project(self, project_id):
            return []

        def ingest(self, project_id, functions, provenance=None):
            return {"project_id": project_id, "nodeCount": 1, "edgeCount": 0, "files": ["main.cpp"]}

        def activate_staging(self, staging_project_id, project_id):
            return {"project_id": project_id, "nodeCount": 1, "edgeCount": 0, "files": ["main.cpp"]}

        def delete_project(self, project_id):
            return True

    code_graph_api.set_service(FakeCodeGraphService())
    code_graph_api.set_code_vector_search(None)

    resp = client.post(
        "/v1/code-graph/re100/ingest",
        json={"functions": [{"name": "main", "file": "main.cpp", "line": 1, "calls": []}]},
        headers=_TIMEOUT_HEADER,
    )
    assert resp.status_code == 200
    assert resp.json()["vectorCount"] == 0


# ── 전역 HTTPException 핸들러 ──


def test_http_exception_uses_observability_format():
    """기존 HTTPException(404)도 observability 포맷으로 변환되는지 확인."""

    class FakeGraph:
        node_count = 10
        edge_count = 5

        def get_node_info(self, node_id):
            return None

    api.set_neo4j_graph(FakeGraph())
    api.set_assembler(object())  # assembler만 truthy면 됨

    resp = client.get("/v1/graph/neighbors/NONEXISTENT")
    assert resp.status_code == 404
    body = resp.json()
    assert body["success"] is False
    assert body["errorDetail"]["code"] == "NOT_FOUND"


class _SlowAssembler:
    def assemble(self, query, **kwargs):
        time.sleep(0.05)
        return {
            "query": query,
            "hits": [],
            "total": 0,
            "extracted_ids": [],
            "related_cwe": [],
            "related_cve": [],
            "related_attack": [],
            "match_type_counts": {"id_exact": 0, "graph_neighbor": 0, "vector_semantic": 0},
        }

    def batch_assemble(self, queries):
        time.sleep(0.05)
        return {
            "results": [],
            "global_stats": {"total_queries": len(queries), "total_hits": 0, "unique_ids": 0},
        }


class _SlowCodeAssembler:
    def search(self, *args, **kwargs):
        time.sleep(0.05)
        return {
            "query": kwargs.get("query", ""),
            "hits": [],
            "total": 0,
            "match_type_counts": {"name_exact": 0, "vector_semantic": 0, "graph_neighbor": 0},
        }


class _SlowNvdClient:
    async def batch_lookup(self, libraries):
        await asyncio.sleep(0.05)
        return [{"library": lib["name"], "version": lib["version"], "cves": [], "total": 0, "cached": False} for lib in libraries]


class _FastGraph:
    node_count = 10
    edge_count = 5


def test_search_timeout_returns_408():
    api.set_assembler(_SlowAssembler())
    api.set_neo4j_graph(_FastGraph())
    api.set_qdrant_ready(True)

    resp = client.post("/v1/search", json={"query": "test"}, headers={"X-Timeout-Ms": "1"})
    assert resp.status_code == 408
    assert resp.json()["errorDetail"]["code"] == "TIMEOUT"


def test_search_batch_timeout_returns_408():
    api.set_assembler(_SlowAssembler())
    api.set_neo4j_graph(_FastGraph())
    api.set_qdrant_ready(True)

    resp = client.post(
        "/v1/search/batch",
        json={"queries": [{"query": "test"}]},
        headers={"X-Timeout-Ms": "1"},
    )
    assert resp.status_code == 408
    assert resp.json()["errorDetail"]["code"] == "TIMEOUT"


def test_code_graph_search_timeout_returns_408():
    code_graph_api.set_code_assembler(_SlowCodeAssembler())

    resp = client.post(
        "/v1/code-graph/re100/search",
        json={"query": "test"},
        headers={"X-Timeout-Ms": "1"},
    )
    assert resp.status_code == 408
    assert resp.json()["errorDetail"]["code"] == "TIMEOUT"


def test_cve_batch_timeout_returns_408():
    cve_api.set_nvd_client(_SlowNvdClient())

    resp = client.post(
        "/v1/cve/batch-lookup",
        json={"libraries": [{"name": "test", "version": "1.0"}]},
        headers={"X-Timeout-Ms": "1"},
    )
    assert resp.status_code == 408
    assert resp.json()["errorDetail"]["code"] == "TIMEOUT"


def test_code_graph_ingest_timeout_after_vector_stage_returns_408():
    class _FastCodeGraphService:
        def export_project(self, project_id):
            return []

        def ingest(self, project_id, functions, provenance=None):
            return {"project_id": project_id, "nodeCount": 1, "edgeCount": 0, "files": ["main.cpp"]}

        def activate_staging(self, staging_project_id, project_id):
            return {"project_id": project_id, "nodeCount": 1, "edgeCount": 0, "files": ["main.cpp"]}

        def delete_project(self, project_id):
            return True

    class _SlowCodeVectorSearch:
        def ingest(self, project_id, functions, provenance=None):
            time.sleep(0.05)
            return 1

    code_graph_api.set_service(_FastCodeGraphService())
    code_graph_api.set_code_vector_search(_SlowCodeVectorSearch())

    resp = client.post(
        "/v1/code-graph/re100/ingest",
        json={"functions": [{"name": "main", "file": "main.cpp", "line": 1, "calls": []}]},
        headers={"X-Timeout-Ms": "1"},
    )
    assert resp.status_code == 408
    assert resp.json()["errorDetail"]["code"] == "TIMEOUT"


def test_code_graph_ingest_timeout_rolls_back_previous_state():
    class _StatefulCodeGraphService:
        def __init__(self):
            self.current = [{"name": "old", "file": "old.cpp", "line": 1, "calls": ["legacy"]}]
            self.deleted = False

        def export_project(self, project_id):
            return [dict(item) for item in self.current]

        def ingest(self, project_id, functions, provenance=None):
            self.current = [dict(item) for item in functions]
            self.deleted = False
            return {"project_id": project_id, "nodeCount": len(functions), "edgeCount": 0, "files": ["main.cpp"]}

        def activate_staging(self, staging_project_id, project_id):
            self.current = [dict(item) for item in self.current]
            return {"project_id": project_id, "nodeCount": len(self.current), "edgeCount": 0, "files": ["main.cpp"]}

        def delete_project(self, project_id):
            self.current = []
            self.deleted = True

    class _StatefulVectorSearch:
        def __init__(self):
            self.current = [{"name": "old", "file": "old.cpp", "line": 1, "calls": ["legacy"]}]
            self.deleted = False

        def ingest(self, project_id, functions, provenance=None):
            self.current = [dict(item) for item in functions]
            self.deleted = False
            time.sleep(0.05)
            return len(functions)

        def activate_staging(self, staging_project_id, project_id):
            return None

        def delete_project(self, project_id):
            self.current = []
            self.deleted = True

    svc = _StatefulCodeGraphService()
    vec = _StatefulVectorSearch()
    code_graph_api.set_service(svc)
    code_graph_api.set_code_vector_search(vec)

    resp = client.post(
        "/v1/code-graph/re100/ingest",
        json={"functions": [{"name": "new", "file": "new.cpp", "line": 10, "calls": []}]},
        headers={"X-Timeout-Ms": "1"},
    )

    assert resp.status_code == 408
    assert svc.current == [{"name": "old", "file": "old.cpp", "line": 1, "calls": ["legacy"]}]
    assert vec.current == [{"name": "old", "file": "old.cpp", "line": 1, "calls": ["legacy"]}]
    assert svc.deleted is False
    assert vec.deleted is False


def test_code_graph_ingest_timeout_rolls_back_to_empty_when_no_previous_state():
    class _EmptyCodeGraphService:
        def __init__(self):
            self.current = []
            self.deleted = False

        def export_project(self, project_id):
            return []

        def ingest(self, project_id, functions, provenance=None):
            self.current = [dict(item) for item in functions]
            self.deleted = False
            return {"project_id": project_id, "nodeCount": len(functions), "edgeCount": 0, "files": ["main.cpp"]}

        def activate_staging(self, staging_project_id, project_id):
            self.current = [dict(item) for item in self.current]
            return {"project_id": project_id, "nodeCount": len(self.current), "edgeCount": 0, "files": ["main.cpp"]}

        def delete_project(self, project_id):
            self.current = []
            self.deleted = True

    class _SlowVectorSearch:
        def __init__(self):
            self.current = []
            self.deleted = False

        def ingest(self, project_id, functions, provenance=None):
            self.current = [dict(item) for item in functions]
            self.deleted = False
            time.sleep(0.05)
            return len(functions)

        def activate_staging(self, staging_project_id, project_id):
            return None

        def delete_project(self, project_id):
            self.current = []
            self.deleted = True

    svc = _EmptyCodeGraphService()
    vec = _SlowVectorSearch()
    code_graph_api.set_service(svc)
    code_graph_api.set_code_vector_search(vec)

    resp = client.post(
        "/v1/code-graph/re100/ingest",
        json={"functions": [{"name": "new", "file": "new.cpp", "line": 10, "calls": []}]},
        headers={"X-Timeout-Ms": "1"},
    )

    assert resp.status_code == 408
    assert svc.current == []
    assert vec.current == []
    assert svc.deleted is True
    assert vec.deleted is True
