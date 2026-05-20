import json
import logging

from app.agent_runtime.context import get_request_id, reset_request_id, set_request_id
from app.agent_runtime.observability import _JsonFormatter


def test_json_formatter_emits_aegis_numeric_log_levels():
    formatter = _JsonFormatter("s3-agent")
    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="watch this",
        args=(),
        exc_info=None,
    )

    data = json.loads(formatter.format(record))

    assert data["level"] == 40
    assert data["service"] == "s3-agent"
    assert data["msg"] == "watch this"


def test_json_formatter_merges_structured_extra_fields():
    formatter = _JsonFormatter("s3-agent")
    token = set_request_id("req-extra")
    try:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="paper http call completed",
            args=(),
            exc_info=None,
        )
        record._extra = {
            "target": "s4-sast",
            "method": "POST",
            "path": "/v1/paper/static-evidence",
            "status": 200,
            "elapsedMs": 123,
        }

        data = json.loads(formatter.format(record))
    finally:
        reset_request_id(token)

    assert data["level"] == 30
    assert data["requestId"] == "req-extra"
    assert data["target"] == "s4-sast"
    assert data["method"] == "POST"
    assert data["path"] == "/v1/paper/static-evidence"
    assert data["status"] == 200
    assert data["elapsedMs"] == 123


def test_request_id_context_resets_with_token():
    outer = set_request_id("req-outer")
    try:
        inner = set_request_id("req-inner")
        assert get_request_id() == "req-inner"
        reset_request_id(inner)
        assert get_request_id() == "req-outer"
    finally:
        reset_request_id(outer)
    assert get_request_id() is None
