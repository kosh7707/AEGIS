from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_paper_context_api_contract import (  # noqa: E402
    _prepare_with_ingest_payload,
    client,
    paper_repo,
)


def _paper_log_records(caplog, message: str):
    return [
        rec
        for rec in caplog.records
        if rec.name == "app.routers.paper_context_api" and rec.getMessage() == message
    ]


def _main_log_records(caplog, message: str):
    return [rec for rec in caplog.records if rec.name == "app.main" and rec.getMessage() == message]


def _contract_log_records(caplog, message: str):
    return [
        rec
        for rec in caplog.records
        if rec.name == "app.routers.contracts_api" and rec.getMessage() == message
    ]


def test_paper_contract_generates_and_returns_request_id_when_header_missing():
    resp = client.get("/v1/contracts/paper-context")

    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Request-Id"].startswith("req-")


def test_paper_contract_logs_request_lifecycle_with_generated_request_id(caplog):
    caplog.set_level(logging.INFO, logger="app.routers.contracts_api")

    resp = client.get("/v1/contracts/paper-context")

    assert resp.status_code == 200, resp.text
    generated = resp.headers["X-Request-Id"]
    starts = _contract_log_records(caplog, "S5 paper endpoint start")
    ends = _contract_log_records(caplog, "S5 paper endpoint end")
    assert starts and ends
    start_extra = starts[-1]._extra
    end_extra = ends[-1]._extra
    assert start_extra["service"] == "s5-kb"
    assert start_extra["requestId"] == generated
    assert start_extra["method"] == "GET"
    assert start_extra["path"] == "/v1/contracts/paper-context"
    assert end_extra["requestId"] == generated
    assert end_extra["status"] == 200
    assert isinstance(end_extra["elapsedMs"], int)


def test_paper_post_missing_header_uses_body_request_id_in_response_and_logs_lifecycle(paper_repo, caplog):
    caplog.set_level(logging.INFO, logger="app.routers.paper_context_api")
    payload = _prepare_with_ingest_payload(
        requestId="s3-s5-observability-prepare-001",
        idempotencyKey="case-001:target-001:s5:prepare-code-kb:observability",
    )

    resp = client.post("/v1/paper/code-kb/prepare", json=payload)

    assert resp.status_code == 200, resp.text
    assert resp.headers["X-Request-Id"] == payload["requestId"]
    starts = _paper_log_records(caplog, "S5 paper endpoint start")
    ends = _paper_log_records(caplog, "S5 paper endpoint end")
    assert starts and ends
    start_extra = starts[-1]._extra
    end_extra = ends[-1]._extra
    assert start_extra["requestId"] == payload["requestId"]
    assert start_extra["method"] == "POST"
    assert start_extra["path"] == "/v1/paper/code-kb/prepare"
    assert start_extra["caseId"] == "case-001"
    assert start_extra["buildTargetId"] == "target-001"
    assert start_extra["paperRunId"] == "paper-run-001"
    assert end_extra["requestId"] == payload["requestId"]
    assert end_extra["status"] == 200
    assert isinstance(end_extra["elapsedMs"], int)
    assert end_extra["s5ProducerRunId"].startswith("s5-producer-run-code-kb-")
    assert end_extra["surfaceStatus"] == "produced"


def test_paper_post_error_response_and_lifecycle_error_log_include_request_id(paper_repo, caplog):
    caplog.set_level(logging.INFO, logger="app.routers.paper_context_api")
    payload = _prepare_with_ingest_payload(
        requestId="s3-s5-observability-error-001",
        idempotencyKey="case-001:target-001:s5:prepare-code-kb:observability-error",
        visibilityMode="appendix_registered",
    )

    resp = client.post(
        "/v1/paper/code-kb/prepare",
        json=payload,
        headers={"X-Request-Id": payload["requestId"]},
    )

    assert resp.status_code == 422, resp.text
    assert resp.headers["X-Request-Id"] == payload["requestId"]
    body = resp.json()
    assert body["success"] is False
    assert body["errorDetail"]["code"] == "S5_PAPER_VISIBILITY_MODE_UNSUPPORTED"
    assert body["errorDetail"]["message"] == "S5 paper-context v1 supports only generic visibility mode."
    assert body["errorDetail"]["requestId"] == payload["requestId"]
    assert body["errorDetail"]["retryable"] is False
    errors = _paper_log_records(caplog, "S5 paper endpoint error")
    assert errors
    extra = errors[-1]._extra
    assert extra["requestId"] == payload["requestId"]
    assert extra["status"] == 422
    assert extra["errorCode"] == "S5_PAPER_VISIBILITY_MODE_UNSUPPORTED"
    assert isinstance(extra["elapsedMs"], int)


def test_paper_validation_error_without_header_gets_generated_request_id_and_sanitized_log(caplog):
    caplog.set_level(logging.INFO, logger="app.main")
    payload: dict[str, Any] = _prepare_with_ingest_payload(
        requestId="s3-s5-validation-secret-001",
        idempotencyKey="case-001:target-001:s5:prepare-code-kb:validation-secret",
    )
    payload.pop("sourceContext")
    payload["sourceRoot"] = "https://user:password@example.invalid/source?api_key=secret"

    resp = client.post("/v1/paper/code-kb/prepare", json=payload)

    assert resp.status_code == 422, resp.text
    generated = resp.headers["X-Request-Id"]
    assert generated.startswith("req-")
    body = resp.json()
    assert body["success"] is False
    assert body["errorDetail"]["code"] == "S5_PAPER_SCHEMA_INVALID"
    assert body["errorDetail"]["requestId"] == generated
    rendered = str(body)
    assert "password" not in rendered
    assert "api_key" not in rendered
    errors = _main_log_records(caplog, "S5 paper endpoint validation error")
    assert errors
    extra = errors[-1]._extra
    assert extra["requestId"] == generated
    assert extra["service"] == "s5-kb"
    assert extra["method"] == "POST"
    assert extra["path"] == "/v1/paper/code-kb/prepare"
    assert extra["status"] == 422
    assert extra["errorCode"] == "S5_PAPER_SCHEMA_INVALID"
    assert isinstance(extra["elapsedMs"], int)
