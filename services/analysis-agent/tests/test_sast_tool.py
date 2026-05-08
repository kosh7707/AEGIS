"""SastScanTool 단위 테스트 — NDJSON 스트리밍 + 동기 fallback."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.agent_runtime.context import set_request_id
from app.tools.implementations.sast_tool import SastScanTool


def _make_ndjson_response(events: list[dict]) -> str:
    """NDJSON 이벤트 목록을 줄 단위 문자열로 변환."""
    return "\n".join(json.dumps(e) for e in events) + "\n"


class _MockStreamResponse:
    """httpx 스트리밍 응답 mock."""

    def __init__(self, lines: list[str], content_type: str = "application/x-ndjson", status_code: int = 200):
        self.headers = {"content-type": content_type}
        self.status_code = status_code
        self._lines = lines

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=MagicMock(), response=self)

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    async def aread(self):
        return "\n".join(self._lines).encode()

    async def aclose(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


@pytest.mark.asyncio
async def test_ndjson_streaming_success():
    """progress → heartbeat → result 정상 파싱."""
    events = [
        {"type": "progress", "tool": "semgrep", "status": "completed", "findingsCount": 5, "elapsedMs": 3000},
        {"type": "heartbeat", "timestamp": 1711900030000},
        {"type": "progress", "tool": "cppcheck", "status": "completed", "findingsCount": 3, "elapsedMs": 8000},
        {"type": "result", "data": {
            "success": True,
            "findings": [
                {"toolId": "semgrep", "ruleId": "cmd-injection", "severity": "error",
                 "message": "command injection", "location": {"file": "main.c", "line": 10}},
            ],
            "stats": {"findingsTotal": 1},
        }},
    ]
    lines = [json.dumps(e) for e in events]
    mock_resp = _MockStreamResponse(lines)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is True
    data = json.loads(result.content)
    assert data["success"] is True
    assert len(data["findings"]) == 1
    assert "eref-sast-cmd-injection" in result.new_evidence_refs


@pytest.mark.asyncio
async def test_ndjson_error_event():
    """error 이벤트 처리."""
    events = [
        {"type": "progress", "tool": "semgrep", "status": "completed", "findingsCount": 0, "elapsedMs": 100},
        {"type": "error", "code": "SCAN_TIMEOUT", "message": "Scan timed out", "retryable": True},
    ]
    lines = [json.dumps(e) for e in events]
    mock_resp = _MockStreamResponse(lines)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is False
    assert "SCAN_TIMEOUT" in result.content


@pytest.mark.asyncio
async def test_ndjson_http_503_error_event_preserved():
    """NDJSON 응답이 HTTP 503이어도 final error 이벤트를 소비한다."""
    events = [
        {
            "type": "error",
            "code": "DISALLOWED_TOOL_OMISSION",
            "message": "tool omission policy violation",
            "retryable": False,
            "execution": {"toolResults": {"semgrep": {"status": "skipped", "skipReason": "environment-drift"}}},
        },
    ]
    mock_resp = _MockStreamResponse([json.dumps(e) for e in events], status_code=503)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is False
    assert "DISALLOWED_TOOL_OMISSION" in result.content


@pytest.mark.asyncio
async def test_sync_503_json_error_preserved():
    """동기 JSON 503도 generic unavailable이 아니라 S4 payload를 보존한다."""
    payload = {
        "success": False,
        "status": "failed",
        "error": "policy violation",
        "errorDetail": {"code": "DISALLOWED_TOOL_OMISSION", "message": "tool omission policy violation"},
    }
    mock_resp = _MockStreamResponse([json.dumps(payload)], content_type="application/json", status_code=503)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is False
    assert "DISALLOWED_TOOL_OMISSION" in result.content
    assert "tool omission policy violation" in (result.error or "")


@pytest.mark.asyncio
async def test_sync_fallback():
    """Content-Type이 ndjson이 아니면 동기 fallback."""
    data = {
        "success": True,
        "findings": [
            {"toolId": "flawfinder", "ruleId": "buffer-overflow", "severity": "warning",
             "message": "buffer overflow", "location": {"file": "buf.c", "line": 5}},
        ],
        "stats": {"findingsTotal": 1},
    }
    mock_resp = _MockStreamResponse(
        [json.dumps(data)],
        content_type="application/json",
    )

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is True
    assert "eref-sast-buffer-overflow" in result.new_evidence_refs


@pytest.mark.asyncio
async def test_stream_no_result():
    """result 없이 스트림 종료 시 실패 반환."""
    events = [
        {"type": "progress", "tool": "semgrep", "status": "completed", "findingsCount": 0, "elapsedMs": 100},
        {"type": "heartbeat", "timestamp": 1711900030000},
    ]
    lines = [json.dumps(e) for e in events]
    mock_resp = _MockStreamResponse(lines)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is False
    assert "no_result" in (result.error or "")


@pytest.mark.asyncio
async def test_connection_error():
    """연결 실패 시 graceful 에러."""
    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(side_effect=httpx.ConnectError("refused"))

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is False
    assert "unavailable" in result.content.lower() or "error" in result.content.lower()


@pytest.mark.asyncio
async def test_accept_header_sent():
    """Accept: application/x-ndjson 헤더 전송 확인."""
    events = [{"type": "result", "data": {"success": True, "findings": [], "stats": {}}}]
    mock_resp = _MockStreamResponse([json.dumps(e) for e in events])

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    await tool.execute({"scanId": "test", "projectId": "p1"})

    call_kwargs = tool._client.stream.call_args
    headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
    assert headers.get("Accept") == "application/x-ndjson"


@pytest.mark.asyncio
async def test_queued_heartbeat_no_stall():
    """queued 상태 heartbeat는 stall 감지를 트리거하지 않는다."""
    events = [
        {"type": "heartbeat", "timestamp": 1, "status": "queued"},
        {"type": "heartbeat", "timestamp": 2, "status": "queued"},
        {"type": "heartbeat", "timestamp": 3, "status": "queued"},
        {"type": "heartbeat", "timestamp": 4, "status": "running", "progress": {
            "activeTools": ["semgrep"], "completedTools": [], "findingsCount": 0,
            "filesCompleted": 0, "filesTotal": 10, "currentFile": None,
        }},
        {"type": "result", "data": {"success": True, "findings": [], "stats": {}}},
    ]
    lines = [json.dumps(e) for e in events]
    mock_resp = _MockStreamResponse(lines)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is True
    data = json.loads(result.content)
    assert "_sast_caveats" not in data


@pytest.mark.asyncio
async def test_stall_detection():
    """filesCompleted가 3회 연속 동일하면 stall 감지."""
    events = [
        {"type": "heartbeat", "timestamp": 1, "status": "running", "progress": {
            "activeTools": ["gcc-fanalyzer"], "completedTools": ["semgrep"],
            "findingsCount": 5, "filesCompleted": 3, "filesTotal": 50,
            "currentFile": "big_file.c",
        }},
        {"type": "heartbeat", "timestamp": 2, "status": "running", "progress": {
            "activeTools": ["gcc-fanalyzer"], "completedTools": ["semgrep"],
            "findingsCount": 5, "filesCompleted": 3, "filesTotal": 50,
            "currentFile": "big_file.c",
        }},
        {"type": "heartbeat", "timestamp": 3, "status": "running", "progress": {
            "activeTools": ["gcc-fanalyzer"], "completedTools": ["semgrep"],
            "findingsCount": 5, "filesCompleted": 3, "filesTotal": 50,
            "currentFile": "big_file.c",
        }},
        {"type": "heartbeat", "timestamp": 4, "status": "running", "progress": {
            "activeTools": ["gcc-fanalyzer"], "completedTools": ["semgrep"],
            "findingsCount": 5, "filesCompleted": 3, "filesTotal": 50,
            "currentFile": "big_file.c",
        }},
        {"type": "result", "data": {"success": True, "findings": [
            {"toolId": "semgrep", "ruleId": "xss", "severity": "warning",
             "message": "xss", "location": {"file": "a.c", "line": 1}},
        ], "stats": {}}},
    ]
    lines = [json.dumps(e) for e in events]
    mock_resp = _MockStreamResponse(lines)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is True
    data = json.loads(result.content)
    assert data.get("_sast_caveats", {}).get("stallDetected") is True


@pytest.mark.asyncio
async def test_no_stall_when_progress_advances():
    """filesCompleted가 계속 증가하면 stall이 아님."""
    events = [
        {"type": "heartbeat", "timestamp": 1, "status": "running", "progress": {
            "activeTools": ["gcc-fanalyzer"], "completedTools": [],
            "findingsCount": 0, "filesCompleted": 1, "filesTotal": 10,
        }},
        {"type": "heartbeat", "timestamp": 2, "status": "running", "progress": {
            "activeTools": ["gcc-fanalyzer"], "completedTools": [],
            "findingsCount": 2, "filesCompleted": 2, "filesTotal": 10,
        }},
        {"type": "heartbeat", "timestamp": 3, "status": "running", "progress": {
            "activeTools": ["gcc-fanalyzer"], "completedTools": [],
            "findingsCount": 3, "filesCompleted": 3, "filesTotal": 10,
        }},
        {"type": "result", "data": {"success": True, "findings": [], "stats": {}}},
    ]
    lines = [json.dumps(e) for e in events]
    mock_resp = _MockStreamResponse(lines)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is True
    data = json.loads(result.content)
    assert "_sast_caveats" not in data


@pytest.mark.asyncio
async def test_failed_tool_caveats():
    """toolResults에 failed 도구가 있으면 _sast_caveats에 포함."""
    events = [
        {"type": "result", "data": {
            "success": True,
            "findings": [
                {"toolId": "semgrep", "ruleId": "sqli", "severity": "error",
                 "message": "sql injection", "location": {"file": "db.c", "line": 42}},
            ],
            "stats": {},
            "execution": {
                "toolResults": {
                    "semgrep": {"status": "ok", "findingsCount": 1},
                    "gcc-fanalyzer": {"status": "failed", "findingsCount": 0, "skipReason": "OOM killed"},
                    "scan-build": {"status": "partial", "findingsCount": 2, "timedOutFiles": 3},
                }
            },
        }},
    ]
    lines = [json.dumps(e) for e in events]
    mock_resp = _MockStreamResponse(lines)

    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=mock_resp)

    result = await tool.execute({"scanId": "test", "projectId": "p1"})
    assert result.success is True
    data = json.loads(result.content)
    caveats = data.get("_sast_caveats", {})
    assert len(caveats.get("incompleteTools", [])) == 2
    assert any("gcc-fanalyzer" in t for t in caveats["incompleteTools"])
    assert any("scan-build" in t for t in caveats["incompleteTools"])


@pytest.mark.asyncio
async def test_sast_scan_uses_durable_ownership_and_continues_transport_only(monkeypatch):
    submit = MagicMock(status_code=202)
    submit.json.return_value = {
        "requestId": "req-scan-owned",
        "statusUrl": "/v1/requests/req-scan-owned",
        "resultUrl": "/v1/requests/req-scan-owned/result",
    }
    running = MagicMock(status_code=200)
    running.json.return_value = {
        "requestId": "req-scan-owned",
        "state": "running",
        "localAckState": "transport-only",
        "blockedReason": None,
        "resultReady": False,
    }
    completed = MagicMock(status_code=200)
    completed.json.return_value = {"requestId": "req-scan-owned", "state": "completed", "resultReady": True}
    final = MagicMock(status_code=200)
    final.json.return_value = {
        "requestId": "req-scan-owned",
        "state": "completed",
        "result": {
            "success": True,
            "findings": [{
                "toolId": "semgrep",
                "ruleId": "CWE-78",
                "severity": "error",
                "message": "cmd injection",
                "location": {"file": "main.c", "line": 1},
            }],
            "stats": {},
        },
    }
    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=submit)
    tool._client.get = AsyncMock(side_effect=[running, completed, final])
    monkeypatch.setattr("asyncio.sleep", AsyncMock())

    result = await tool.execute({"scanId": "scan", "projectId": "p"})

    assert result.success is True
    assert "eref-sast-CWE-78" in result.new_evidence_refs
    headers = tool._client.post.await_args.kwargs["headers"]
    assert headers["Prefer"] == "respond-async"
    assert headers["X-Request-Id"].startswith("s3-request:s4:v1-scan:sast_scan:")
    assert tool._client.get.await_count == 3


@pytest.mark.asyncio
async def test_sast_scan_durable_failed_result_returns_tool_failure(monkeypatch):
    submit = MagicMock(status_code=202)
    submit.json.return_value = {
        "requestId": "req-scan-failed",
        "statusUrl": "/v1/requests/req-scan-failed",
        "resultUrl": "/v1/requests/req-scan-failed/result",
    }
    completed = MagicMock(status_code=200)
    completed.json.return_value = {
        "requestId": "req-scan-failed",
        "state": "completed",
        "resultReady": True,
    }
    final = MagicMock(status_code=200)
    final.json.return_value = {
        "requestId": "req-scan-failed",
        "state": "completed",
        "result": {
            "success": False,
            "failureDetail": {
                "code": "SDK_NOT_FOUND",
                "message": "SDK profile not registered",
            },
            "findings": [],
            "stats": {},
        },
    }
    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=submit)
    tool._client.get = AsyncMock(side_effect=[completed, final])
    monkeypatch.setattr("asyncio.sleep", AsyncMock())

    result = await tool.execute({"scanId": "scan", "projectId": "p"})

    assert result.success is False
    assert "SDK_NOT_FOUND" in result.content
    assert "SDK profile not registered" in (result.error or "")
    assert result.new_evidence_refs == []


@pytest.mark.asyncio
async def test_sast_scan_durable_ownership_error_preserves_status_code(monkeypatch):
    from app.clients.s4_ownership import S4OwnershipError

    async def fake_post_and_wait(*args, **kwargs):
        raise S4OwnershipError(
            "S4 submit failed with HTTP 400",
            status_code=400,
            payload={
                "success": False,
                "failureDetail": {
                    "code": "SDK_PROFILE_INVALID",
                    "message": "invalid sdk profile",
                },
            },
        )

    monkeypatch.setattr(
        "app.tools.implementations.sast_tool.post_and_wait_s4_ownership",
        fake_post_and_wait,
    )
    tool = SastScanTool()

    result = await tool.execute({"scanId": "scan", "projectId": "p"})

    assert result.success is False
    data = json.loads(result.content)
    assert data["statusCode"] == 400
    assert data["detail"]["failureDetail"]["code"] == "SDK_PROFILE_INVALID"


@pytest.mark.asyncio
async def test_sast_scan_durable_ack_break_returns_tool_failure():
    submit = MagicMock(status_code=202)
    submit.json.return_value = {
        "requestId": "req-scan-blocked",
        "statusUrl": "/v1/requests/req-scan-blocked",
        "resultUrl": "/v1/requests/req-scan-blocked/result",
    }
    blocked = MagicMock(status_code=200)
    blocked.json.return_value = {
        "requestId": "req-scan-blocked",
        "state": "failed",
        "localAckState": "ack-break",
        "blockedReason": "tool_policy_failed",
        "resultReady": False,
    }
    tool = SastScanTool()
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=submit)
    tool._client.get = AsyncMock(return_value=blocked)

    result = await tool.execute({"scanId": "scan", "projectId": "p"})

    assert result.success is False
    assert "tool_policy_failed" in (result.error or result.content)


@pytest.mark.asyncio
async def test_ndjson_inactivity_polls_health_and_continues_when_alive(monkeypatch):
    set_request_id("req-stream")
    async def delayed_lines():
        yield json.dumps({"type": "heartbeat", "status": "running", "progress": {"filesCompleted": 1}})
        await asyncio.sleep(0.01)
        yield json.dumps({"type": "result", "data": {"success": True, "findings": [], "stats": {}}})

    class _DelayedStream:
        headers = {"content-type": "application/x-ndjson"}
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *args): return False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def aiter_lines(self):
            async for line in delayed_lines():
                yield line

    tool = SastScanTool(prefer_durable_ownership=False)
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=_DelayedStream())
    health = MagicMock(status_code=200)
    health.json.return_value = {
        "requestSummary": {
            "requestId": "req-stream",
            "state": "running",
            "localAckState": "transport-only",
            "blockedReason": None,
        }
    }
    tool._client.get = AsyncMock(return_value=health)

    original_wait_for = asyncio.wait_for
    calls = 0

    async def fake_wait_for(awaitable, timeout):
        nonlocal calls
        calls += 1
        if calls == 2:
            awaitable.close()
            raise asyncio.TimeoutError()
        return await original_wait_for(awaitable, timeout=1.0)

    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    result = await tool.execute({"scanId": "scan", "projectId": "p"})

    assert result.success is True
    tool._client.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_ndjson_inactivity_health_ack_break_stops_wait(monkeypatch):
    set_request_id("req-stream")
    class _NeverStream:
        headers = {"content-type": "application/x-ndjson"}
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *args): return False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def aiter_lines(self):
            if False:
                yield ""

    tool = SastScanTool(prefer_durable_ownership=False)
    tool._client = MagicMock()
    tool._client.stream = MagicMock(return_value=_NeverStream())
    health = MagicMock(status_code=200)
    health.json.return_value = {
        "requestSummary": {
            "requestId": "req-stream",
            "state": "failed",
            "localAckState": "ack-break",
            "blockedReason": "tool_policy_failed",
        }
    }
    tool._client.get = AsyncMock(return_value=health)

    async def fake_wait_for(awaitable, timeout):
        awaitable.close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    result = await tool.execute({"scanId": "scan", "projectId": "p"})

    assert result.success is False
    assert result.error == "no_result"
    tool._client.get.assert_awaited_once()
