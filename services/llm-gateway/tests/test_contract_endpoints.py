"""엔드포인트 계약 테스트 (/v1/health, /v1/models, /v1/prompts, /v1/chat)."""
import asyncio
import json
import logging
import time
from threading import Event
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.config import settings
from app.main import app
from tests.conftest import ALL_TASK_TYPES, make_chat_body


class _ListLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _capture_exchange_logs():
    logger = logging.getLogger("llm_exchange")
    handler = _ListLogHandler()
    logger.addHandler(handler)
    return logger, handler


def _release_exchange_logs(logger, handler):
    logger.removeHandler(handler)


# ---------------------------------------------------------------------------
# GET /v1/health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def _clear_llm_backend_cache(self):
        for attr in ("llm_backend_health_cache", "llm_backend_health_cache_lock"):
            if hasattr(app.state, attr):
                delattr(app.state, attr)

    def test_health_required_fields(self, client_live):
        resp = client_live.get("/v1/health")
        assert resp.status_code == 200
        assert resp.headers["x-request-id"].startswith("gw-")
        data = resp.json()
        for field in ("service", "status", "version", "llmMode",
                      "modelProfiles", "activePromptVersions", "rag",
                      "activeRequestCount", "requestSummary"):
            assert field in data, f"missing field: {field}"

    def test_health_service_name(self, client_live):
        data = client_live.get("/v1/health").json()
        assert data["service"] == "s7-gateway"

    def test_health_status_ok(self, client_live):
        data = client_live.get("/v1/health").json()
        assert data["status"] == "ok"

    def test_health_model_profiles_is_list(self, client_live):
        data = client_live.get("/v1/health").json()
        assert isinstance(data["modelProfiles"], list)
        assert len(data["modelProfiles"]) >= 1

    def test_health_active_prompt_versions_has_all_types(self, client_live):
        data = client_live.get("/v1/health").json()
        versions = data["activePromptVersions"]
        for task_type in ALL_TASK_TYPES:
            assert task_type in versions, f"missing prompt version for: {task_type}"

    def test_health_rag_field_structure(self, client_live):
        data = client_live.get("/v1/health").json()
        rag = data["rag"]
        assert isinstance(rag["enabled"], bool)
        assert isinstance(rag["kbEndpoint"], str)
        assert isinstance(rag["topK"], int)
        assert isinstance(rag["minScore"], float)
        assert rag["policy"] == "task-pipeline-context-enrichment"
        assert isinstance(rag["status"], str)

    def test_health_mock_mode_no_llm_backend(self, client_live):
        data = client_live.get("/v1/health").json()
        assert data["llmMode"] == "mock"
        assert "llmBackend" not in data

    def test_health_circuit_breaker_field(self, client_live):
        data = client_live.get("/v1/health").json()
        cb = data.get("circuitBreaker")
        assert cb is not None
        assert cb["state"] == "closed"
        assert cb["consecutiveFailures"] == 0
        assert "threshold" in cb
        assert "recoverySeconds" in cb

    def test_health_mock_mode_reports_ready_without_llm_backend(self, client_live):
        data = client_live.get("/v1/health").json()
        assert data["status"] == "ok"
        assert data["ready"] is True
        assert data["llmReady"] is True
        assert data["degraded"] is False
        assert data["degradeReasons"] == []
        assert data["blockedReason"] is None
        assert data["dependencyStatus"]["llmBackend"]["status"] == "mock"
        assert data["dependencyStatus"]["rag"]["status"] == data["rag"]["status"]

    def test_health_real_backend_reachable_reports_llm_ready(self, client_live):
        original_mode = settings.llm_mode
        original_ttl = settings.llm_health_cache_ttl_seconds
        object.__setattr__(settings, "llm_mode", "real")
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.0)
        self._clear_llm_backend_cache()
        original_get = app.state.proxy_client.get
        app.state.proxy_client.get = AsyncMock(
            return_value=httpx.Response(
                200,
                request=httpx.Request("GET", "http://llm.test/health"),
            )
        )
        try:
            data = client_live.get("/v1/health").json()
        finally:
            app.state.proxy_client.get = original_get
            object.__setattr__(settings, "llm_mode", original_mode)
            object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
            self._clear_llm_backend_cache()

        assert data["status"] == "ok"
        assert data["llmBackend"]["status"] == "ok"
        assert data["ready"] is True
        assert data["llmReady"] is True
        assert data["degraded"] is False
        assert data["degradeReasons"] == []
        assert data["blockedReason"] is None
        assert data["dependencyStatus"]["llmBackend"]["status"] == "ok"

    def test_health_real_backend_unreachable_reports_not_ready(self, client_live):
        original_mode = settings.llm_mode
        original_ttl = settings.llm_health_cache_ttl_seconds
        object.__setattr__(settings, "llm_mode", "real")
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.0)
        self._clear_llm_backend_cache()
        original_get = app.state.proxy_client.get
        app.state.proxy_client.get = AsyncMock(side_effect=httpx.ConnectError("vpn down"))
        try:
            data = client_live.get("/v1/health").json()
        finally:
            app.state.proxy_client.get = original_get
            object.__setattr__(settings, "llm_mode", original_mode)
            object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
            self._clear_llm_backend_cache()

        assert data["status"] == "ok"
        assert data["llmBackend"]["status"] == "unreachable"
        assert data["ready"] is False
        assert data["llmReady"] is False
        assert data["degraded"] is True
        assert data["degradeReasons"] == ["llm_backend_unreachable"]
        assert data["blockedReason"] == "backend_unreachable"
        assert data["dependencyStatus"]["llmBackend"]["status"] == "unreachable"

    def test_health_real_backend_reachable_but_circuit_open_reports_not_ready(
        self,
        client_live,
    ):
        original_mode = settings.llm_mode
        original_ttl = settings.llm_health_cache_ttl_seconds
        object.__setattr__(settings, "llm_mode", "real")
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.0)
        self._clear_llm_backend_cache()
        original_get = app.state.proxy_client.get
        app.state.proxy_client.get = AsyncMock(
            return_value=httpx.Response(
                200,
                request=httpx.Request("GET", "http://llm.test/health"),
            )
        )
        with patch.object(
            app.state.circuit_breaker,
            "snapshot",
            return_value={
                "state": "open",
                "consecutiveFailures": 3,
                "threshold": 3,
                "recoverySeconds": 30.0,
            },
        ):
            try:
                data = client_live.get("/v1/health").json()
            finally:
                app.state.proxy_client.get = original_get
                object.__setattr__(settings, "llm_mode", original_mode)
                object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
                self._clear_llm_backend_cache()

        assert data["status"] == "ok"
        assert data["llmBackend"]["status"] == "ok"
        assert data["ready"] is False
        assert data["llmReady"] is False
        assert data["degraded"] is True
        assert data["degradeReasons"] == ["llm_circuit_open"]
        assert data["blockedReason"] == "circuit_open"
        assert data["dependencyStatus"]["circuitBreaker"]["state"] == "open"

    def test_health_real_backend_reachable_but_circuit_half_open_reports_not_ready(
        self,
        client_live,
    ):
        original_mode = settings.llm_mode
        original_ttl = settings.llm_health_cache_ttl_seconds
        object.__setattr__(settings, "llm_mode", "real")
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.0)
        self._clear_llm_backend_cache()
        original_get = app.state.proxy_client.get
        app.state.proxy_client.get = AsyncMock(
            return_value=httpx.Response(
                200,
                request=httpx.Request("GET", "http://llm.test/health"),
            )
        )
        with patch.object(
            app.state.circuit_breaker,
            "snapshot",
            return_value={
                "state": "half_open",
                "consecutiveFailures": 3,
                "threshold": 3,
                "recoverySeconds": 30.0,
            },
        ):
            try:
                data = client_live.get("/v1/health").json()
            finally:
                app.state.proxy_client.get = original_get
                object.__setattr__(settings, "llm_mode", original_mode)
                object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
                self._clear_llm_backend_cache()

        assert data["status"] == "ok"
        assert data["llmBackend"]["status"] == "ok"
        assert data["ready"] is False
        assert data["llmReady"] is False
        assert data["degraded"] is True
        assert data["degradeReasons"] == ["llm_circuit_half_open"]
        assert data["blockedReason"] == "circuit_half_open"
        assert data["dependencyStatus"]["circuitBreaker"]["state"] == "half_open"

    def test_health_real_backend_probe_uses_short_ttl_cache(self, client_live):
        original_mode = settings.llm_mode
        original_ttl = settings.llm_health_cache_ttl_seconds
        object.__setattr__(settings, "llm_mode", "real")
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", 10.0)
        self._clear_llm_backend_cache()
        original_get = app.state.proxy_client.get
        mock_get = AsyncMock(
            return_value=httpx.Response(
                200,
                request=httpx.Request("GET", "http://llm.test/health"),
            )
        )
        app.state.proxy_client.get = mock_get
        try:
            first = client_live.get("/v1/health").json()
            second = client_live.get("/v1/health").json()
        finally:
            app.state.proxy_client.get = original_get
            object.__setattr__(settings, "llm_mode", original_mode)
            object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
            self._clear_llm_backend_cache()

        assert mock_get.await_count == 1
        assert first["llmBackend"]["cached"] is False
        assert second["llmBackend"]["cached"] is True
        assert second["ready"] is True
        assert second["llmReady"] is True

    def test_health_real_backend_cache_expires_and_refreshes(self, client_live):
        original_mode = settings.llm_mode
        original_ttl = settings.llm_health_cache_ttl_seconds
        object.__setattr__(settings, "llm_mode", "real")
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.01)
        self._clear_llm_backend_cache()
        original_get = app.state.proxy_client.get
        mock_get = AsyncMock(
            return_value=httpx.Response(
                200,
                request=httpx.Request("GET", "http://llm.test/health"),
            )
        )
        app.state.proxy_client.get = mock_get
        try:
            first = client_live.get("/v1/health").json()
            time.sleep(0.02)
            second = client_live.get("/v1/health").json()
        finally:
            app.state.proxy_client.get = original_get
            object.__setattr__(settings, "llm_mode", original_mode)
            object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
            self._clear_llm_backend_cache()

        assert mock_get.await_count == 2
        assert first["llmBackend"]["cached"] is False
        assert second["llmBackend"]["cached"] is False
        assert second["ready"] is True

    def test_health_real_backend_cache_does_not_hide_unreachable_after_ttl(
        self,
        client_live,
    ):
        original_mode = settings.llm_mode
        original_ttl = settings.llm_health_cache_ttl_seconds
        object.__setattr__(settings, "llm_mode", "real")
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.01)
        self._clear_llm_backend_cache()
        original_get = app.state.proxy_client.get
        mock_get = AsyncMock(
            side_effect=[
                httpx.Response(
                    200,
                    request=httpx.Request("GET", "http://llm.test/health"),
                ),
                httpx.ConnectError("vpn down"),
            ]
        )
        app.state.proxy_client.get = mock_get
        try:
            first = client_live.get("/v1/health").json()
            time.sleep(0.02)
            second = client_live.get("/v1/health").json()
        finally:
            app.state.proxy_client.get = original_get
            object.__setattr__(settings, "llm_mode", original_mode)
            object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
            self._clear_llm_backend_cache()

        assert mock_get.await_count == 2
        assert first["llmBackend"]["status"] == "ok"
        assert second["llmBackend"]["status"] == "unreachable"
        assert second["ready"] is False
        assert second["llmReady"] is False
        assert second["blockedReason"] == "backend_unreachable"

    def test_health_idle_request_summary_shape(self, client_live):
        data = client_live.get("/v1/health").json()
        summary = data["requestSummary"]
        assert data["activeRequestCount"] == 0
        assert summary["requestId"] is None
        assert summary["state"] == "idle"
        assert summary["localAckState"] is None
        assert summary["degraded"] is False
        assert summary["degradeReasons"] == []
        assert summary["blockedReason"] is None
        assert summary["phase"] is None

    def test_health_request_id_query_prefers_matching_active_request(self, client_live):
        tracker = app.state.request_tracker
        tracker.register("gw-health-001", endpoint="chat")
        tracker.mark_phase(
            "gw-health-001",
            phase="llm-inference",
            state="running",
            ack_source="queue-exit",
        )
        tracker.mark_transport_only("gw-health-001", phase="llm-inference")

        try:
            resp = client_live.get("/v1/health", params={"requestId": "gw-health-001"})
        finally:
            tracker.clear("gw-health-001")

        data = resp.json()
        summary = data["requestSummary"]
        assert data["activeRequestCount"] == 1
        assert summary["requestId"] == "gw-health-001"
        assert summary["endpoint"] == "chat"
        assert summary["state"] == "running"
        assert summary["localAckState"] == "transport-only"
        assert summary["phase"] == "llm-inference"
        assert summary["elapsedMs"] >= 0

    def test_health_unknown_request_id_returns_idle_summary(self, client_live):
        tracker = app.state.request_tracker
        tracker.register("gw-health-002", endpoint="tasks", task_type="static-explain")
        tracker.mark_phase(
            "gw-health-002",
            phase="prompt-build",
            state="running",
            ack_source="prompt-build",
        )

        try:
            resp = client_live.get("/v1/health", params={"requestId": "gw-missing"})
        finally:
            tracker.clear("gw-health-002")

        data = resp.json()
        assert data["activeRequestCount"] == 1
        assert data["requestSummary"]["requestId"] is None
        assert data["requestSummary"]["state"] == "idle"


# ---------------------------------------------------------------------------
# GET /v1/models
# ---------------------------------------------------------------------------

class TestModelsEndpoint:
    def test_models_response_structure(self, client_live):
        resp = client_live.get("/v1/models")
        assert resp.status_code == 200
        data = resp.json()
        assert "profiles" in data
        assert isinstance(data["profiles"], list)
        assert len(data["profiles"]) >= 1
        profile = data["profiles"][0]
        for field in ("profileId", "modelName", "contextLimit",
                      "allowedTaskTypes", "status"):
            assert field in profile, f"missing field in profile: {field}"

    def test_models_allowed_task_types_are_strings(self, client_live):
        data = client_live.get("/v1/models").json()
        for profile in data["profiles"]:
            assert isinstance(profile["allowedTaskTypes"], list)
            for t in profile["allowedTaskTypes"]:
                assert isinstance(t, str)

    def test_models_includes_request_id_header(self, client_live):
        resp = client_live.get("/v1/models", headers={"X-Request-Id": "rid-models-001"})
        assert resp.headers["x-request-id"] == "rid-models-001"


# ---------------------------------------------------------------------------
# GET /v1/prompts
# ---------------------------------------------------------------------------

class TestPromptsEndpoint:
    def test_prompts_response_structure(self, client_live):
        resp = client_live.get("/v1/prompts")
        assert resp.status_code == 200
        data = resp.json()
        assert "prompts" in data
        assert isinstance(data["prompts"], list)
        assert len(data["prompts"]) >= 1
        prompt = data["prompts"][0]
        for field in ("promptId", "version", "taskType", "description"):
            assert field in prompt, f"missing field in prompt: {field}"

    def test_prompts_covers_all_task_types(self, client_live):
        data = client_live.get("/v1/prompts").json()
        registered_types = {p["taskType"] for p in data["prompts"]}
        for task_type in ALL_TASK_TYPES:
            assert task_type in registered_types, f"missing prompt for: {task_type}"


# ---------------------------------------------------------------------------
# POST /v1/chat — LLM Engine 프록시
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# GET /v1/usage
# ---------------------------------------------------------------------------

class TestUsageEndpoint:
    def test_usage_response_structure(self, client_live):
        resp = client_live.get("/v1/usage")
        assert resp.status_code == 200
        data = resp.json()
        assert "startedAt" in data
        assert "totalRequests" in data
        assert "totalErrors" in data
        assert "tokens" in data
        assert data["tokens"]["total"] == data["tokens"]["prompt"] + data["tokens"]["completion"]

    def test_usage_initial_zeros(self, client_live):
        data = client_live.get("/v1/usage").json()
        assert data["totalRequests"] >= 0
        assert data["totalErrors"] >= 0


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    def test_metrics_returns_prometheus_format(self, client_live):
        resp = client_live.get("/metrics")
        assert resp.status_code == 200
        body = resp.text
        assert "aegis_llm_requests_total" in body
        assert "aegis_llm_tokens_total" in body
        assert "aegis_llm_circuit_breaker_state" in body
        assert "aegis_llm_temperature" in body
        assert "aegis_llm_top_p" in body
        assert "aegis_llm_top_k" in body
        assert "aegis_llm_min_p" in body
        assert "aegis_llm_presence_penalty" in body
        assert "aegis_llm_repetition_penalty" in body
        assert "aegis_llm_thinking_requests_total" in body
        assert "aegis_llm_thinking_token_count" in body
        assert "aegis_llm_finish_reason_total" in body
        assert "aegis_llm_tool_call_empty_total" in body
        assert "aegis_llm_tool_choice_total" in body
        assert "aegis_llm_response_contract_violation_total" in body

    def test_metrics_content_type(self, client_live):
        resp = client_live.get("/metrics")
        assert "text/plain" in resp.headers["content-type"] or "text/openmetrics" in resp.headers.get("content-type", "")

    def test_generation_controls_are_recorded_as_metrics(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 3,
                "completion_tokens": 2,
                "completion_tokens_details": {"reasoning_tokens": 1},
            },
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)
            resp = client_live.post(
                "/v1/chat",
                json={
                    "model": "ignored-by-gateway",
                    "messages": [{"role": "user", "content": "metrics"}],
                    "max_tokens": 100,
                    "temperature": 1.0,
                    "top_p": 0.95,
                    "top_k": 20,
                    "min_p": 0.0,
                    "presence_penalty": 0.0,
                    "repetition_penalty": 1.0,
                    "chat_template_kwargs": {"enable_thinking": True},
                    "tool_choice": "auto",
                },
            )

        assert resp.status_code == 200
        metrics = client_live.get("/metrics").text
        assert 'aegis_llm_temperature_count{endpoint="chat_proxy",task_type="none"}' in metrics
        assert 'aegis_llm_top_p_count{endpoint="chat_proxy",task_type="none"}' in metrics
        assert 'aegis_llm_top_k_count{endpoint="chat_proxy",task_type="none"}' in metrics
        assert 'aegis_llm_thinking_requests_total{enabled="true",endpoint="chat_proxy",task_type="none"}' in metrics
        assert 'aegis_llm_thinking_token_count_count{endpoint="chat_proxy",task_type="none"}' in metrics
        assert 'aegis_llm_finish_reason_total{endpoint="chat_proxy",reason="stop",task_type="none"}' in metrics
        assert 'aegis_llm_tool_choice_total{choice="auto",endpoint="chat_proxy"}' in metrics

    def test_named_tool_choice_is_rejected_before_metrics_or_backend(self, client_live):
        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock()
            body = make_chat_body()
            body.update({
                "messages": [{"role": "user", "content": "tool choice"}],
                "max_tokens": 16,
                "tool_choice": {"type": "function", "function": {"name": "lookup_vin"}},
            })
            resp = client_live.post(
                "/v1/chat",
                json=body,
            )

        assert resp.status_code == 422
        data = resp.json()
        assert data["errorDetail"]["code"] == "INVALID_TOOL_CHOICE"
        assert data["retryable"] is False
        mock_client.post.assert_not_called()

    def test_chat_payload_task_type_does_not_become_metric_label(self, client_live):
        mock_resp = httpx.Response(200, json={
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        })

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)
            body = make_chat_body()
            body.update({
                "messages": [{"role": "user", "content": "cardinality"}],
                "max_tokens": 16,
                "temperature": 1.0,
                "top_p": 0.95,
                "top_k": 20,
                "task_type": "user-controlled-cardinality",
            })
            resp = client_live.post(
                "/v1/chat",
                json=body,
            )

        assert resp.status_code == 200
        metrics = client_live.get("/metrics").text
        assert 'task_type="user-controlled-cardinality"' not in metrics
        assert 'aegis_llm_temperature_count{endpoint="chat_proxy",task_type="none"}' in metrics


# ---------------------------------------------------------------------------
# POST /v1/chat — LLM Engine 프록시
# ---------------------------------------------------------------------------

class TestChatProxy:
    """POST /v1/chat 프록시 엔드포인트 계약 테스트."""

    def test_chat_proxy_forwards_request(self, client_live):
        """프록시가 요청을 LLM Engine에 전달하고 응답을 반환한다."""
        mock_llm_response = {
            "choices": [{"message": {"content": '{"test": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 100,
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 200
        data = resp.json()
        assert "choices" in data
        assert data["choices"][0]["message"]["content"] == '{"test": true}'
        assert data["usage"]["prompt_tokens"] == 10
        assert resp.headers["X-AEGIS-Effective-Thinking"] == "true"

        call_kwargs = mock_client.post.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["chat_template_kwargs"]["enable_thinking"] is True

    def test_chat_proxy_exchange_log_contains_full_request_and_response(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": "hello back"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)
        logger, handler = _capture_exchange_logs()
        try:
            with patch.object(app.state, "proxy_client") as mock_client:
                mock_client.post = AsyncMock(return_value=mock_resp)

                resp = client_live.post(
                    "/v1/chat",
                    json={
                        "model": "ignored-by-gateway",
                        "messages": [{"role": "user", "content": "full prompt evidence"}],
                        "max_tokens": 100,
                        "temperature": 1.0,
                        "top_p": 0.95,
                        "top_k": 20,
                        "min_p": 0.0,
                        "presence_penalty": 0.0,
                        "repetition_penalty": 1.0,
                        "chat_template_kwargs": {"enable_thinking": True},
                    },
                    headers={"X-Request-Id": "rid-chat-exchange-001"},
                )
        finally:
            _release_exchange_logs(logger, handler)

        assert resp.status_code == 200
        entries = [json.loads(m) for m in handler.messages]
        entry = next(e for e in entries if e.get("requestId") == "rid-chat-exchange-001")
        assert entry["type"] == "chat_proxy"
        assert entry["request"]["messages"][0]["content"] == "full prompt evidence"
        assert entry["request"]["chat_template_kwargs"]["enable_thinking"] is True
        assert entry["effectiveThinking"] is True
        assert entry["generation"] == {
            "maxTokens": 100,
            "temperature": 1.0,
            "topP": 0.95,
            "topK": 20,
            "minP": 0.0,
            "presencePenalty": 0.0,
            "repetitionPenalty": 1.0,
            "enableThinking": True,
            "taskType": None,
        }
        assert entry["response"]["choices"][0]["message"]["content"] == "hello back"

    def test_chat_proxy_preserves_snake_case_generation_controls(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        body = {
            "model": "ignored-by-gateway",
            "messages": [{"role": "user", "content": "generation controls"}],
            "max_tokens": 321,
            "temperature": 0.6,
            "top_p": 0.9,
            "top_k": 30,
            "min_p": 0.01,
            "presence_penalty": 0.2,
            "repetition_penalty": 1.1,
            "chat_template_kwargs": {"enable_thinking": True},
        }
        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 200
        call_kwargs = mock_client.post.call_args
        forwarded = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        for key in (
            "max_tokens",
            "temperature",
            "top_p",
            "top_k",
            "min_p",
            "presence_penalty",
            "repetition_penalty",
        ):
            assert forwarded[key] == body[key]
        assert forwarded["chat_template_kwargs"]["enable_thinking"] is True

    def test_chat_proxy_preserves_explicit_thinking_false(self, client_live):
        """명시적 mechanical off 요청은 S7 기본값 없이 그대로 보존한다."""
        mock_llm_response = {
            "choices": [{"message": {"content": "mechanical final"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({
                "messages": [{"role": "user", "content": "no reasoning needed"}],
                "chat_template_kwargs": {"enable_thinking": False},
            })
            resp = client_live.post(
                "/v1/chat",
                json=body,
            )

        assert resp.status_code == 200
        assert resp.headers["X-AEGIS-Effective-Thinking"] == "false"
        call_kwargs = mock_client.post.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["chat_template_kwargs"]["enable_thinking"] is False

    def test_chat_proxy_auto_request_id(self, client_live):
        """requestId가 없으면 Gateway가 gw- 접두사로 자동 생성한다."""
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "test"}],
            })
            resp = client_live.post("/v1/chat", json=body)
            # X-Request-Id 헤더 없이 요청

        assert resp.status_code == 200
        rid = resp.headers.get("x-request-id", "")
        assert rid.startswith("gw-"), f"expected gw- prefix, got: {rid}"

    def test_chat_proxy_caller_timeout_header(self, client_live):
        """X-Timeout-Seconds 헤더로 per-request 타임아웃을 전달한다."""
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({"model": "test", "messages": [{"role": "user", "content": "x"}]})
            resp = client_live.post(
                "/v1/chat",
                json=body,
                headers={"X-Timeout-Seconds": "300"},
            )

        assert resp.status_code == 200
        # post() 호출 시 timeout 인자가 전달되었는지 확인
        call_kwargs = mock_client.post.call_args
        req_timeout = call_kwargs.kwargs.get("timeout") or call_kwargs[1].get("timeout")
        assert req_timeout is not None
        assert req_timeout.read == 300.0

    def test_chat_proxy_503_on_connect_error(self, client_live):
        """LLM Engine 연결 실패 시 503 반환."""
        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 503
        data = resp.json()
        assert data["success"] is False
        assert data["retryable"] is True
        assert data["errorDetail"]["code"] == "LLM_UNAVAILABLE"
        assert resp.headers["x-request-id"].startswith("gw-")

    def test_chat_proxy_504_on_timeout(self, client_live):
        """LLM Engine 타임아웃 시 504 반환."""
        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 504
        data = resp.json()
        assert data["success"] is False
        assert data["retryable"] is True
        assert data["errorDetail"]["code"] == "LLM_TIMEOUT"

    def test_chat_proxy_passes_tool_calls(self, client_live):
        """tool_calls가 포함된 응답을 그대로 전달한다."""
        mock_llm_response = {
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "tc-1",
                        "type": "function",
                        "function": {"name": "knowledge.search", "arguments": '{"query":"CWE-78"}'},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 15},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "analyze"}],
                "tools": [{"type": "function", "function": {"name": "knowledge.search"}}],
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 200
        data = resp.json()
        assert data["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "knowledge.search"

    def test_chat_proxy_rejects_required_tool_choice_before_backend(self, client_live):
        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock()

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "analyze"}],
                "tools": [{"type": "function", "function": {"name": "knowledge.search"}}],
                "tool_choice": "required",
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 422
        data = resp.json()
        assert data["success"] is False
        assert data["retryable"] is False
        assert data["errorDetail"]["code"] == "INVALID_TOOL_CHOICE"
        assert "required" in data["errorDetail"]["detail"]
        mock_client.post.assert_not_called()

    def test_chat_proxy_contract_violation_empty_tool_calls_is_retryable_503(self, client_live):
        mock_llm_response = {
            "choices": [{
                "message": {
                    "content": "",
                    "tool_calls": [],
                    "reasoning": "I should call a tool.\n",
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 15},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "analyze"}],
                "tools": [{"type": "function", "function": {"name": "knowledge.search"}}],
                "tool_choice": "auto",
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 503
        data = resp.json()
        assert data["success"] is False
        assert data["retryable"] is True
        assert data["errorDetail"]["code"] == "LLM_PARSE_RETRY"
        assert data["errorDetail"]["violationReason"] == "finish_reason_tool_calls_with_empty_array"
        assert data["violationReason"] == "finish_reason_tool_calls_with_empty_array"
        metrics = client_live.get("/metrics").text
        assert 'aegis_llm_response_contract_violation_total{endpoint="chat_proxy",reason="finish_reason_tool_calls_with_empty_array"}' in metrics
        assert 'aegis_llm_tool_call_empty_total{endpoint="chat_proxy",reason="tool_calls",task_type="none",tool_calls_empty="true"}' in metrics

    def test_chat_proxy_contract_violation_reasoning_only_is_retryable_503(self, client_live):
        mock_llm_response = {
            "choices": [{
                "message": {
                    "content": "",
                    "tool_calls": [],
                    "reasoning": "Final answer was swallowed by the reasoning parser.\n",
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 15},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)
            resp = client_live.post("/v1/chat", json=make_chat_body())

        assert resp.status_code == 503
        data = resp.json()
        assert data["errorDetail"]["code"] == "LLM_PARSE_RETRY"
        assert data["errorDetail"]["violationReason"] == "all_output_absorbed_into_reasoning"

    def test_chat_proxy_records_cb_failure_on_500(self, client_live):
        """LLM Engine 500 응답 시 circuit breaker에 failure 기록."""
        mock_resp = httpx.Response(500, json={"error": "internal"})

        cb = app.state.circuit_breaker
        before = cb.consecutive_failures

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 500
        assert cb.consecutive_failures == before + 1

    def test_chat_proxy_no_cb_failure_on_400(self, client_live):
        """LLM Engine 400 응답 시 circuit breaker에 failure 미기록."""
        mock_resp = httpx.Response(400, json={"error": "bad request"})

        cb = app.state.circuit_breaker
        before = cb.consecutive_failures

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            })
            resp = client_live.post("/v1/chat", json=body)

        assert resp.status_code == 400
        assert cb.consecutive_failures == before

    def test_chat_proxy_invalid_timeout_header_uses_default(self, client_live):
        """비숫자 X-Timeout-Seconds 헤더는 기본값(1800초)으로 대체된다."""
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({"model": "test", "messages": [{"role": "user", "content": "x"}]})
            resp = client_live.post(
                "/v1/chat",
                json=body,
                headers={"X-Timeout-Seconds": "not-a-number"},
            )

        assert resp.status_code == 200
        call_kwargs = mock_client.post.call_args
        req_timeout = call_kwargs.kwargs.get("timeout") or call_kwargs[1].get("timeout")
        assert req_timeout.read == 1800.0

    def test_chat_proxy_strict_json_mode_injects_only_json_response_format(self, client_live):
        """strict JSON은 JSON 제어만 주입하고 caller-owned thinking 값을 보존한다."""
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok":true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({"model": "test", "messages": [{"role": "user", "content": "x"}]})
            resp = client_live.post(
                "/v1/chat",
                json=body,
                headers={"X-AEGIS-Strict-JSON": "true"},
            )

        assert resp.status_code == 200
        call_kwargs = mock_client.post.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["response_format"] == {"type": "json_object"}
        assert body["chat_template_kwargs"]["enable_thinking"] is True
        assert resp.headers["X-AEGIS-Effective-Thinking"] == "true"
        assert resp.headers["X-AEGIS-Strict-JSON"] == "applied"

    def test_chat_proxy_strict_json_mode_preserves_thinking_false(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok":true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body["chat_template_kwargs"] = {"enable_thinking": False}
            resp = client_live.post(
                "/v1/chat",
                json=body,
                headers={"X-AEGIS-Strict-JSON": "true"},
            )

        assert resp.status_code == 200
        call_kwargs = mock_client.post.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["response_format"] == {"type": "json_object"}
        assert body["chat_template_kwargs"]["enable_thinking"] is False
        assert resp.headers["X-AEGIS-Effective-Thinking"] == "false"
        assert resp.headers["X-AEGIS-Strict-JSON"] == "applied"

    def test_chat_proxy_strict_json_mode_scrubs_reasoning_and_normalizes_content(self, client_live):
        """strict JSON 모드에서는 reasoning을 scrub하고 content를 compact JSON으로 정규화한다."""
        mock_llm_response = {
            "choices": [{
                "message": {
                    "content": '{\n  "ok": true\n}',
                    "reasoning": "internal chain",
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({"model": "test", "messages": [{"role": "user", "content": "x"}]})
            resp = client_live.post(
                "/v1/chat",
                json=body,
                headers={"X-AEGIS-Strict-JSON": "true"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == '{"ok":true}'
        assert data["choices"][0]["message"]["reasoning"] is None

    def test_chat_proxy_strict_json_mode_rejects_invalid_json_response(self, client_live):
        """strict JSON 모드에서 JSON object가 아니면 502로 명확히 실패한다."""
        mock_llm_response = {
            "choices": [{
                "message": {
                    "content": None,
                    "reasoning": "Thinking...",
                },
                "finish_reason": "length",
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 64},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            body = make_chat_body()
            body.update({"model": "test", "messages": [{"role": "user", "content": "x"}]})
            resp = client_live.post(
                "/v1/chat",
                json=body,
                headers={"X-AEGIS-Strict-JSON": "true"},
            )

        assert resp.status_code == 502
        data = resp.json()
        assert data["error"] == "Strict JSON contract violated"
        assert data["success"] is False
        assert data["retryable"] is True
        assert data["strictJson"] is True
        assert data["errorDetail"]["code"] == "LLM_PARSE_ERROR"


class TestAsyncChatOwnershipSurface:
    def test_async_submit_returns_accepted_shape(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            resp = client_live.post(
                "/v1/async-chat-requests",
                json=make_chat_body(),
                headers={"X-Request-Id": "trace-async-001"},
            )

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["requestId"].startswith("acr_")
        assert data["traceRequestId"] == "trace-async-001"
        assert data["statusUrl"].endswith(data["requestId"])
        assert data["resultUrl"].endswith(f'{data["requestId"]}/result')
        assert data["cancelUrl"].endswith(data["requestId"])
        assert "acceptedAt" in data
        assert "expiresAt" in data

    def test_async_submit_rejects_required_tool_choice_before_backend(self, client_live):
        body = make_chat_body()
        body.update({
            "tools": [{"type": "function", "function": {"name": "knowledge.search"}}],
            "tool_choice": "required",
        })

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock()
            resp = client_live.post(
                "/v1/async-chat-requests",
                json=body,
                headers={"X-Request-Id": "trace-async-toolchoice-001"},
            )

        assert resp.status_code == 422
        data = resp.json()
        assert data["success"] is False
        assert data["retryable"] is False
        assert data["errorDetail"]["code"] == "INVALID_TOOL_CHOICE"
        mock_client.post.assert_not_called()

    def test_async_status_and_result_wrap_chat_response(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            submit = client_live.post(
                "/v1/async-chat-requests",
                json=make_chat_body(),
                headers={"X-Request-Id": "trace-async-002"},
            )
            request_id = submit.json()["requestId"]

            deadline = time.time() + 1.0
            status_data = None
            while time.time() < deadline:
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                status_data = status_resp.json()
                if status_data["state"] == "completed":
                    break
                time.sleep(0.01)

            assert status_data is not None
            assert status_data["state"] == "completed"
            assert status_data["resultReady"] is True
            assert status_data["traceRequestId"] == "trace-async-002"

            result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")

        assert result_resp.status_code == 200
        result_data = result_resp.json()
        assert result_data["requestId"] == request_id
        assert result_data["state"] == "completed"
        assert result_data["traceRequestId"] == "trace-async-002"
        assert result_data["response"]["choices"][0]["message"]["content"] == '{"ok": true}'
        assert result_data["response"]["usage"]["prompt_tokens"] == 8

    def test_async_exchange_log_contains_full_request_and_response(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": "async answer"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)
        logger, handler = _capture_exchange_logs()
        try:
            with patch.object(app.state, "proxy_client") as mock_client:
                mock_client.post = AsyncMock(return_value=mock_resp)

                submit = client_live.post(
                    "/v1/async-chat-requests",
                    json={
                        "model": "ignored",
                        "messages": [{"role": "user", "content": "async full prompt"}],
                        "max_tokens": 100,
                        "temperature": 1.0,
                        "top_p": 0.95,
                        "top_k": 20,
                        "min_p": 0.0,
                        "presence_penalty": 0.0,
                        "repetition_penalty": 1.0,
                        "chat_template_kwargs": {"enable_thinking": True},
                    },
                    headers={"X-Request-Id": "trace-async-exchange-001"},
                )
                request_id = submit.json()["requestId"]
                deadline = time.time() + 1.0
                while time.time() < deadline:
                    status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                    if status_resp.json()["state"] == "completed":
                        break
                    time.sleep(0.01)
        finally:
            _release_exchange_logs(logger, handler)

        entries = [json.loads(m) for m in handler.messages]
        entry = next(e for e in entries if e.get("asyncRequestId") == request_id)
        assert entry["type"] == "async_chat"
        assert entry["request"]["messages"][0]["content"] == "async full prompt"
        assert entry["request"]["chat_template_kwargs"]["enable_thinking"] is True
        assert entry["effectiveThinking"] is True
        assert entry["generation"] == {
            "maxTokens": 100,
            "temperature": 1.0,
            "topP": 0.95,
            "topK": 20,
            "minP": 0.0,
            "presencePenalty": 0.0,
            "repetitionPenalty": 1.0,
            "enableThinking": True,
            "taskType": None,
        }
        assert entry["response"]["choices"][0]["message"]["content"] == "async answer"

    def test_async_submit_preserves_snake_case_generation_controls(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": "async answer"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)
        body = make_chat_body()
        body.update({
            "max_tokens": 321,
            "temperature": 0.6,
            "top_p": 0.9,
            "top_k": 30,
            "min_p": 0.01,
            "presence_penalty": 0.2,
            "repetition_penalty": 1.1,
            "chat_template_kwargs": {"enable_thinking": False},
        })

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)
            submit = client_live.post("/v1/async-chat-requests", json=body)
            request_id = submit.json()["requestId"]
            deadline = time.time() + 1.0
            while time.time() < deadline:
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                if status_resp.json()["state"] == "completed":
                    break
                time.sleep(0.01)

        call_kwargs = mock_client.post.call_args
        forwarded = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        for key in (
            "max_tokens",
            "temperature",
            "top_p",
            "top_k",
            "min_p",
            "presence_penalty",
            "repetition_penalty",
        ):
            assert forwarded[key] == body[key]
        assert forwarded["chat_template_kwargs"]["enable_thinking"] is False

    def test_async_backend_read_timeout_is_unbounded_for_wait_while_alive(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": "async answer"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)
            submit = client_live.post("/v1/async-chat-requests", json=make_chat_body())
            request_id = submit.json()["requestId"]
            deadline = time.time() + 1.0
            while time.time() < deadline:
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                if status_resp.json()["state"] == "completed":
                    break
                time.sleep(0.01)

        call_kwargs = mock_client.post.call_args
        req_timeout = call_kwargs.kwargs.get("timeout") or call_kwargs[1].get("timeout")
        assert req_timeout is not None
        assert req_timeout.connect == 10.0
        assert req_timeout.read is None
        assert req_timeout.write == 10.0
        assert req_timeout.pool == 10.0

    def test_async_result_not_ready_is_explicit(self, client_live):
        async def delayed_response(*args, **kwargs):
            await asyncio.sleep(0.05)
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 4},
                },
            )

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(side_effect=delayed_response)

            submit = client_live.post("/v1/async-chat-requests", json=make_chat_body())
            request_id = submit.json()["requestId"]
            result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")

        assert result_resp.status_code == 409
        result_data = result_resp.json()
        assert result_data["requestId"] == request_id
        assert result_data["success"] is False
        assert result_data["error"] == "Async result not ready"
        assert result_data["errorDetail"]["code"] == "CONFLICT"
        assert result_data["state"] in {"queued", "running"}

    def test_async_wait_while_alive_status_health_and_late_result(self, client_live):
        started = Event()
        release = Event()

        async def delayed_response(*args, **kwargs):
            started.set()
            while not release.is_set():
                await asyncio.sleep(0.01)
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 4},
                },
            )

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(side_effect=delayed_response)

            submit = client_live.post(
                "/v1/async-chat-requests",
                json=make_chat_body(),
                headers={"X-Request-Id": "trace-async-wait-v2"},
            )
            request_id = submit.json()["requestId"]

            deadline = time.time() + 1.0
            while not started.is_set() and time.time() < deadline:
                time.sleep(0.01)
            assert started.is_set()

            record = app.state.async_chat_manager._requests[request_id]
            record.accepted_at_ms = 0
            record.started_at_ms = 0
            record.expires_at_ms = 0
            tracked = app.state.request_tracker._requests[request_id]
            tracked.started_at = 0

            for _ in range(3):
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                status_data = status_resp.json()
                assert status_data["state"] == "running"
                assert status_data["localAckState"] == "transport-only"
                assert status_data["blockedReason"] is None
                assert status_data["resultReady"] is False

                result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")
                assert result_resp.status_code == 409
                result_data = result_resp.json()
                assert result_data["state"] == "running"
                assert result_data["retryable"] is True
                assert result_data["blockedReason"] is None

            health = client_live.get(f"/v1/health?requestId={request_id}").json()
            summary = health["requestSummary"]
            assert summary["requestId"] == request_id
            assert summary["endpoint"] == "async-chat"
            assert summary["state"] == "running"
            assert summary["localAckState"] == "transport-only"
            assert summary["blockedReason"] is None
            assert summary["elapsedMs"] > 1_800_000

            release.set()
            deadline = time.time() + 1.0
            completed = None
            while time.time() < deadline:
                completed = client_live.get(f"/v1/async-chat-requests/{request_id}").json()
                if completed["state"] == "completed":
                    break
                time.sleep(0.01)

            assert completed is not None
            assert completed["state"] == "completed"
            assert completed["resultReady"] is True

            result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")

        assert result_resp.status_code == 200
        result_data = result_resp.json()
        assert result_data["state"] == "completed"
        assert result_data["response"]["choices"][0]["message"]["content"] == '{"ok": true}'

    def test_async_cancel_returns_cancelled_state(self, client_live):
        started = Event()

        async def delayed_response(*args, **kwargs):
            started.set()
            await asyncio.sleep(60)
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 4},
                },
            )

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(side_effect=delayed_response)

            submit = client_live.post("/v1/async-chat-requests", json=make_chat_body())
            request_id = submit.json()["requestId"]

            deadline = time.time() + 1.0
            while not started.is_set() and time.time() < deadline:
                time.sleep(0.01)

            cancel_resp = client_live.delete(f"/v1/async-chat-requests/{request_id}")

        assert cancel_resp.status_code == 200
        cancel_data = cancel_resp.json()
        assert cancel_data["requestId"] == request_id
        assert cancel_data["state"] == "cancelled"
        assert cancel_data["localAckState"] == "ack-break"

    def test_async_result_expired_is_explicit(self, client_live):
        mock_llm_response = {
            "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            submit = client_live.post("/v1/async-chat-requests", json=make_chat_body())
            request_id = submit.json()["requestId"]

            deadline = time.time() + 1.0
            while time.time() < deadline:
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                if status_resp.json()["state"] == "completed":
                    break
                time.sleep(0.01)

            record = app.state.async_chat_manager._requests[request_id]
            record.expires_at_ms = 0

            result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")

        assert result_resp.status_code == 410
        result_data = result_resp.json()
        assert result_data["requestId"] == request_id
        assert result_data["state"] == "expired"
        assert result_data["error"] == "Async result expired"

    def test_async_backend_transport_timeout_is_terminal_failure(self, client_live):
        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(side_effect=httpx.PoolTimeout("pool timeout"))

            submit = client_live.post("/v1/async-chat-requests", json=make_chat_body())
            request_id = submit.json()["requestId"]

            deadline = time.time() + 1.0
            status_data = None
            while time.time() < deadline:
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                status_data = status_resp.json()
                if status_data["state"] == "failed":
                    break
                time.sleep(0.01)

            result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")

        assert status_data is not None
        assert status_data["state"] == "failed"
        assert status_data["localAckState"] == "ack-break"
        assert status_data["blockedReason"] == "backend_timeout"
        assert "elapsed read ceiling" in status_data["errorDetail"]
        assert status_data["retryable"] is True

        assert result_resp.status_code == 409
        result_data = result_resp.json()
        assert result_data["state"] == "failed"
        assert result_data["blockedReason"] == "backend_timeout"
        assert "elapsed read ceiling" in result_data["errorDetail"]["detail"]

    def test_async_strict_json_failure_is_explicit_retryable(self, client_live):
        """S3 structured finalizer용 async strict JSON 실패는 retryable terminal failure로 노출한다."""
        mock_llm_response = {
            "choices": [{
                "message": {
                    "content": "not json",
                    "reasoning": "internal chain",
                },
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            submit = client_live.post(
                "/v1/async-chat-requests",
                json=make_chat_body(),
                headers={
                    "X-Request-Id": "trace-async-strict-001",
                    "X-AEGIS-Strict-JSON": "true",
                },
            )
            request_id = submit.json()["requestId"]

            deadline = time.time() + 1.0
            status_data = None
            while time.time() < deadline:
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                status_data = status_resp.json()
                if status_data["state"] == "failed":
                    break
                time.sleep(0.01)

            result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")

        assert status_data is not None
        assert status_data["state"] == "failed"
        assert status_data["blockedReason"] == "strict_json_contract_violation"
        assert status_data["error"] == "Strict JSON contract violated"
        assert status_data["retryable"] is True

        result_data = result_resp.json()
        assert result_resp.status_code == 409
        assert result_data["requestId"] == request_id
        assert result_data["state"] == "failed"
        assert result_data["error"] == "Strict JSON contract violated"
        assert "valid JSON" in result_data["errorDetail"]["detail"]
        assert result_data["retryable"] is True
        assert result_data["blockedReason"] == "strict_json_contract_violation"

    def test_async_response_contract_violation_is_failed_retryable(self, client_live):
        mock_llm_response = {
            "choices": [{
                "message": {
                    "content": "",
                    "tool_calls": [],
                    "reasoning": "I should call a tool.\n",
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4},
        }
        mock_resp = httpx.Response(200, json=mock_llm_response)
        body = make_chat_body()
        body.update({
            "tools": [{"type": "function", "function": {"name": "knowledge.search"}}],
            "tool_choice": "auto",
        })

        with patch.object(app.state, "proxy_client") as mock_client:
            mock_client.post = AsyncMock(return_value=mock_resp)

            submit = client_live.post(
                "/v1/async-chat-requests",
                json=body,
                headers={"X-Request-Id": "trace-async-contract-001"},
            )
            request_id = submit.json()["requestId"]

            deadline = time.time() + 1.0
            status_data = None
            while time.time() < deadline:
                status_resp = client_live.get(f"/v1/async-chat-requests/{request_id}")
                status_data = status_resp.json()
                if status_data["state"] == "failed":
                    break
                time.sleep(0.01)

            result_resp = client_live.get(f"/v1/async-chat-requests/{request_id}/result")

        assert status_data is not None
        assert status_data["state"] == "failed"
        assert status_data["blockedReason"] == "response_contract_violation"
        assert status_data["error"] == "LLM response contract violated"
        assert status_data["errorDetail"] == "finish_reason_tool_calls_with_empty_array"
        assert status_data["retryable"] is True

        assert result_resp.status_code == 409
        result_data = result_resp.json()
        assert result_data["state"] == "failed"
        assert result_data["error"] == "LLM response contract violated"
        assert result_data["blockedReason"] == "response_contract_violation"
        assert result_data["errorDetail"]["detail"] == "finish_reason_tool_calls_with_empty_array"
        assert result_data["retryable"] is True

        metrics = client_live.get("/metrics").text
        assert 'aegis_llm_response_contract_violation_total{endpoint="async_chat",reason="finish_reason_tool_calls_with_empty_array"}' in metrics
