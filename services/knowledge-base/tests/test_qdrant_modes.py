"""ThreatSearch 듀얼 모드(file/server) 초기화 테스트."""

import logging
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def _mock_qdrant():
    """QdrantClient를 mock하여 실제 Qdrant 없이 테스트."""
    with patch("app.rag.threat_search.QdrantClient") as MockClient:
        instance = MagicMock()
        # get_collections → threat_knowledge 컬렉션 존재
        coll = MagicMock()
        coll.name = "threat_knowledge"
        instance.get_collections.return_value.collections = [coll]
        MockClient.return_value = instance
        yield MockClient, instance


def test_file_mode_init(_mock_qdrant):
    """qdrant_path만 지정 → file 모드."""
    MockClient, _ = _mock_qdrant
    from app.rag.threat_search import ThreatSearch

    ts = ThreatSearch(qdrant_path="/tmp/qdrant")
    MockClient.assert_called_once_with(path="/tmp/qdrant")
    assert ts.mode == "file"


def test_server_mode_init(_mock_qdrant):
    """qdrant_url만 지정 → server 모드."""
    MockClient, _ = _mock_qdrant
    from app.rag.threat_search import ThreatSearch

    ts = ThreatSearch(qdrant_url="http://localhost:6333")
    MockClient.assert_called_once_with(url="http://localhost:6333", api_key=None)
    assert ts.mode == "server"


def test_server_mode_with_api_key(_mock_qdrant):
    """api_key가 전달되는지 확인."""
    MockClient, _ = _mock_qdrant
    from app.rag.threat_search import ThreatSearch

    ts = ThreatSearch(qdrant_url="http://localhost:6333", qdrant_api_key="secret")
    MockClient.assert_called_once_with(url="http://localhost:6333", api_key="secret")
    assert ts.mode == "server"


def test_server_mode_log_redacts_qdrant_url_userinfo(_mock_qdrant, caplog):
    """서버 모드 startup log는 Qdrant URL userinfo credential을 노출하지 않는다."""

    MockClient, _ = _mock_qdrant
    from app.rag.threat_search import ThreatSearch

    raw_url = "https://q_user:q_password@qdrant.internal:6333"

    caplog.set_level(logging.INFO, logger="app.rag.threat_search")
    ts = ThreatSearch(qdrant_url=raw_url, qdrant_api_key="api-secret")

    MockClient.assert_called_once_with(url=raw_url, api_key="api-secret")
    assert ts.mode == "server"
    assert raw_url not in caplog.text
    assert "q_user" not in caplog.text
    assert "q_password" not in caplog.text
    assert "api-secret" not in caplog.text
    assert "https://***:***@qdrant.internal:6333" in caplog.text


def test_no_path_no_url_raises():
    """둘 다 없으면 ValueError."""
    from app.rag.threat_search import ThreatSearch

    with pytest.raises(ValueError, match="qdrant_path 또는 qdrant_url"):
        ThreatSearch()


def test_mode_property_values(_mock_qdrant):
    """mode 프로퍼티가 정확한 문자열을 반환."""
    MockClient, _ = _mock_qdrant
    from app.rag.threat_search import ThreatSearch

    ts_file = ThreatSearch(qdrant_path="/tmp/q")
    assert ts_file.mode == "file"

    MockClient.reset_mock()
    ts_server = ThreatSearch(qdrant_url="http://host:6333")
    assert ts_server.mode == "server"


def test_missing_collection_raises_by_default():
    with patch("app.rag.threat_search.QdrantClient") as MockClient:
        instance = MagicMock()
        instance.get_collections.return_value.collections = []
        MockClient.return_value = instance

        from app.rag.threat_search import ThreatSearch

        with pytest.raises(RuntimeError, match="threat_knowledge"):
            ThreatSearch(qdrant_path="/tmp/qdrant")


def test_missing_collection_allowed_when_not_required():
    with patch("app.rag.threat_search.QdrantClient") as MockClient:
        instance = MagicMock()
        instance.get_collections.return_value.collections = []
        MockClient.return_value = instance

        from app.rag.threat_search import ThreatSearch

        ts = ThreatSearch(qdrant_path="/tmp/qdrant", require_collection=False)
        assert ts.mode == "file"
