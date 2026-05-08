from __future__ import annotations

import pytest

from app.runtime.request_summary import request_summary_tracker


@pytest.fixture(autouse=True)
def _reset_request_summary_tracker():
    request_summary_tracker.reset()
    yield
    request_summary_tracker.reset()


def test_health_endpoint_includes_idle_request_summary(client_live):
    resp = client_live.get("/v1/health")
    assert resp.status_code == 200

    data = resp.json()
    assert data["activePromptVersions"]["deep-analyze"] == "agent-v1"
    assert data["activeResponseSchemas"]["deep-analyze"] == "agent-v1.1"
    assert data["agentConfig"]["taskDeadlineMs"] == 1_800_000
    assert data["agentConfig"]["partialEnvelopeDeadlineMs"] == 1_740_000
    assert data["agentConfig"]["llmAsyncPollIntervalSeconds"] == 1.0
    assert data["activeRequestCount"] == 0
    assert data["requestSummary"]["requestId"] is None
    assert data["requestSummary"]["state"] == "idle"
    assert data["requestSummary"]["localAckState"] is None
    assert data["requestSummary"]["blockedReason"] is None


def test_health_endpoint_reports_running_request_summary(client_live):
    request_summary_tracker.register("health-running", endpoint="tasks")
    request_summary_tracker.mark_phase_advancing(
        "health-running",
        source="phase-one-complete",
        degraded=True,
        degrade_reasons=["phase1-partial-tools"],
    )

    resp = client_live.get("/v1/health", params={"requestId": "health-running"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["activeRequestCount"] == 1
    assert data["requestSummary"]["requestId"] == "health-running"
    assert data["requestSummary"]["state"] == "running"
    assert data["requestSummary"]["localAckState"] == "phase-advancing"
    assert data["requestSummary"]["degraded"] is True
    assert "phase1-partial-tools" in data["requestSummary"]["degradeReasons"]
    assert data["requestSummary"]["lastAckSource"] == "phase-one-complete"


def test_health_endpoint_reports_transport_only_wait_state(client_live):
    request_summary_tracker.register("health-transport", endpoint="tasks")
    request_summary_tracker.mark_transport_only("health-transport", source="llm-inference")

    resp = client_live.get("/v1/health", params={"requestId": "health-transport"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["activeRequestCount"] == 1
    assert data["requestSummary"]["requestId"] == "health-transport"
    assert data["requestSummary"]["state"] == "running"
    assert data["requestSummary"]["localAckState"] == "transport-only"
    assert data["requestSummary"]["blockedReason"] is None
    assert data["requestSummary"]["lastAckSource"] == "llm-inference"


def test_health_endpoint_reports_ack_break(client_live):
    request_summary_tracker.register("health-failed", endpoint="tasks")
    request_summary_tracker.mark_failed("health-failed", "MODEL_UNAVAILABLE")

    resp = client_live.get("/v1/health", params={"requestId": "health-failed"})
    assert resp.status_code == 200

    data = resp.json()
    assert data["requestSummary"]["requestId"] == "health-failed"
    assert data["requestSummary"]["state"] == "failed"
    assert data["requestSummary"]["localAckState"] == "ack-break"
    assert data["requestSummary"]["blockedReason"] == "MODEL_UNAVAILABLE"
    assert data["requestSummary"]["lastAckSource"] == "ack-break"


def test_health_endpoint_returns_idle_summary_when_only_completed_requests_exist(client_live):
    request_summary_tracker.register("health-completed", endpoint="tasks")
    request_summary_tracker.mark_completed("health-completed")

    resp = client_live.get("/v1/health")
    assert resp.status_code == 200

    data = resp.json()
    assert data["activeRequestCount"] == 0
    assert data["requestSummary"]["requestId"] is None
    assert data["requestSummary"]["state"] == "idle"
    assert data["requestSummary"]["localAckState"] is None
