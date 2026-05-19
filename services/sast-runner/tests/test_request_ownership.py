from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.runtime.request_ownership import request_ownership_store
from app.runtime.request_summary import request_summary_tracker
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    ScanResponse,
    ScanStats,
    SdkResolutionInfo,
)


@pytest.fixture(autouse=True)
async def reset_ownership_state():
    await request_ownership_store.reset()
    request_summary_tracker.reset()
    old_retention = request_ownership_store.retention_seconds
    yield
    request_ownership_store.retention_seconds = old_retention
    await request_ownership_store.reset()
    request_summary_tracker.reset()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _build_result(*, success: bool = True) -> dict:
    return {
        "success": success,
        "buildEvidence": {
            "requestedBuildCommand": "make",
            "effectiveBuildCommand": "make",
            "buildDir": "/tmp/project",
            "compileCommandsPath": "/tmp/project/compile_commands.json" if success else None,
            "entries": 1 if success else None,
            "userEntries": 1 if success else None,
            "exitCode": 0 if success else 127,
            "buildOutput": "ok" if success else "command not found",
            "wrapWithBear": True,
            "timeoutSeconds": 1,
            "timeoutMode": "async-ownership-no-caller-deadline",
            "timeoutEnforced": False,
            "environmentKeys": None,
            "elapsedMs": 25,
        },
        "readiness": {
            "status": "ready" if success else "not-ready",
            "compileCommandsReady": success,
            "quickEligible": success,
            "summary": "ready" if success else "not ready",
        },
        "failureDetail": None if success else {
            "category": "command-not-found",
            "summary": "The supplied build command referenced an unavailable executable or script (exit code 127).",
            "matchedExcerpt": "command not found",
            "hint": "provide valid command",
            "retryable": False,
        },
    }


def _scan_response(scan_id: str = "scan-owned") -> ScanResponse:
    return ScanResponse(
        success=True,
        scanId=scan_id,
        status="completed",
        findings=[],
        stats=ScanStats(filesScanned=1, rulesRun=0, findingsTotal=0, elapsedMs=5),
        execution=ExecutionReport(
            toolsRun=[],
            toolResults={},
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        ),
    )


async def _wait_for_result(client: AsyncClient, request_id: str) -> dict:
    for _ in range(20):
        resp = await client.get(f"/v1/requests/{request_id}/result")
        if resp.status_code == 200:
            return resp.json()
        await asyncio.sleep(0.02)
    raise AssertionError(f"result was not ready for {request_id}")


@pytest.mark.asyncio
async def test_async_build_result_recovery_after_submit_response(client: AsyncClient) -> None:
    gate = asyncio.Event()
    seen_kwargs = {}

    async def _slow_build(*args, on_runtime_state=None, **kwargs):
        seen_kwargs.update(kwargs)
        if on_runtime_state:
            await on_runtime_state({"localAckState": "transport-only", "lastAckSource": "build-subprocess-alive"})
        await gate.wait()
        return _build_result(success=True)

    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(side_effect=_slow_build),
    ):
        submit = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "owned-build", "Prefer": "respond-async", "X-Timeout-Ms": "1"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        assert submit.status_code == 202
        assert submit.headers["Preference-Applied"] == "respond-async"
        assert submit.json()["resultReady"] is False

        await asyncio.sleep(0.05)
        health = await client.get("/v1/health", params={"requestId": "owned-build"})
        summary = health.json()["requestSummary"]
        assert summary["state"] == "running"
        assert summary["localAckState"] == "transport-only"
        assert summary["lastAckSource"] == "build-subprocess-alive"

        pending = await client.get("/v1/requests/owned-build/result")
        assert pending.status_code == 202

        gate.set()
        result = await _wait_for_result(client, "owned-build")

    assert seen_kwargs["timeout"] is None
    assert seen_kwargs["timeout_seconds_for_evidence"] == 1
    assert seen_kwargs["timeout_enforced"] is False
    assert result["state"] == "completed"
    evidence = result["result"]["buildEvidence"]
    assert evidence["timeoutSeconds"] == 1
    assert evidence["timeoutMode"] == "async-ownership-no-caller-deadline"
    assert evidence["timeoutEnforced"] is False


@pytest.mark.asyncio
async def test_async_build_failure_is_ack_break_and_retrievable(client: AsyncClient) -> None:
    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(return_value=_build_result(success=False)),
    ):
        submit = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "owned-build-fail", "Prefer": "respond-async"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        assert submit.status_code == 202
        result = await _wait_for_result(client, "owned-build-fail")

    assert result["state"] == "failed"
    assert result["result"]["success"] is False
    health = await client.get("/v1/health", params={"requestId": "owned-build-fail"})
    summary = health.json()["requestSummary"]
    assert summary["state"] == "failed"
    assert summary["localAckState"] == "ack-break"
    assert "unavailable executable" in summary["blockedReason"]


@pytest.mark.asyncio
async def test_async_duplicate_submit_reuses_existing_request(client: AsyncClient) -> None:
    gate = asyncio.Event()
    calls = 0

    async def _slow_build(*args, on_runtime_state=None, **kwargs):
        nonlocal calls
        calls += 1
        await gate.wait()
        return _build_result(success=True)

    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(side_effect=_slow_build),
    ):
        first = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "owned-build-dupe", "Prefer": "respond-async"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        second = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "owned-build-dupe", "Prefer": "respond-async"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        assert first.status_code == 202
        assert second.status_code == 202
        assert second.json()["reused"] is True
        await asyncio.sleep(0.05)
        assert calls == 1
        gate.set()
        await _wait_for_result(client, "owned-build-dupe")


@pytest.mark.asyncio
async def test_async_scan_prefer_overrides_ndjson_accept(client: AsyncClient) -> None:
    with patch("app.routers.scan._run_scan_core", AsyncMock(return_value=_scan_response("scan-prefer"))):
        submit = await client.post(
            "/v1/scan",
            headers={
                "X-Request-Id": "owned-scan",
                "Prefer": "respond-async",
                "Accept": "application/x-ndjson",
            },
            json={
                "scanId": "scan-prefer",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        )
        assert submit.status_code == 202
        assert submit.headers["content-type"].startswith("application/json")
        result = await _wait_for_result(client, "owned-scan")

    assert result["state"] == "completed"
    assert result["result"]["scanId"] == "scan-prefer"


@pytest.mark.asyncio
async def test_async_scan_internal_error_result_summary_and_logs_do_not_echo_exception(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SECRET_ASYNC_SCAN_INTERNAL_EXCEPTION_SHOULD_NOT_LEAK"
    caplog.set_level("ERROR", logger="aegis-sast-runner")

    with patch(
        "app.routers.scan._run_scan_core",
        AsyncMock(side_effect=RuntimeError(secret)),
    ):
        submit = await client.post(
            "/v1/scan",
            headers={
                "X-Request-Id": "owned-scan-internal-sanitized",
                "Prefer": "respond-async",
            },
            json={
                "scanId": "owned-scan-internal-sanitized",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        )
        assert submit.status_code == 202
        result = await _wait_for_result(client, "owned-scan-internal-sanitized")

    assert result["state"] == "failed"
    payload = result["result"]
    assert payload["error"] == "internal error"
    assert payload["errorDetail"]["code"] == "INTERNAL_ERROR"
    assert payload["errorDetail"]["message"] == "internal error"
    assert secret not in str(result)

    health = await client.get(
        "/v1/health",
        params={"requestId": "owned-scan-internal-sanitized"},
    )
    summary = health.json()["requestSummary"]
    assert summary["state"] == "failed"
    assert summary["blockedReason"] == "internal error"
    assert secret not in str(summary)
    assert secret not in caplog.text


@pytest.mark.asyncio
async def test_async_build_and_analyze_result_recovery(client: AsyncClient) -> None:
    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(return_value=_build_result(success=True)),
    ), patch(
        "app.routers.scan._run_scan_core",
        AsyncMock(return_value=_scan_response("build-analyze-owned")),
    ), patch(
        "app.routers.scan.metadata_extractor.extract",
        AsyncMock(return_value={"compiler": "gcc"}),
    ):
        submit = await client.post(
            "/v1/build-and-analyze",
            headers={"X-Request-Id": "owned-build-analyze", "Prefer": "respond-async"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        assert submit.status_code == 202
        result = await _wait_for_result(client, "owned-build-analyze")

    assert result["state"] == "completed"
    assert result["result"]["success"] is True
    assert result["result"]["build"]["success"] is True
    assert result["result"]["scan"]["scanId"] == "build-analyze-owned"


@pytest.mark.asyncio
async def test_async_build_cancel_marks_terminal_cancelled_and_stops_active_count(client: AsyncClient) -> None:
    gate = asyncio.Event()

    async def _slow_build(*args, on_runtime_state=None, **kwargs):
        if on_runtime_state:
            await on_runtime_state({"localAckState": "transport-only", "lastAckSource": "build-subprocess-alive"})
        await gate.wait()
        return _build_result(success=True)

    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(side_effect=_slow_build),
    ):
        submit = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "owned-build-cancel", "Prefer": "respond-async"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        assert submit.status_code == 202
        await asyncio.sleep(0.05)

        cancel = await client.delete("/v1/requests/owned-build-cancel")
        duplicate_cancel = await client.delete("/v1/requests/owned-build-cancel")
        result = await client.get("/v1/requests/owned-build-cancel/result")
        health = await client.get("/v1/health", params={"requestId": "owned-build-cancel"})

    assert cancel.status_code == 202
    cancel_payload = cancel.json()
    assert cancel_payload["state"] == "cancelled"
    assert cancel_payload["resultReady"] is True
    assert cancel_payload["result"]["success"] is False
    assert cancel_payload["result"]["errorDetail"]["code"] == "REQUEST_CANCELLED"
    assert duplicate_cancel.status_code == 200
    assert duplicate_cancel.json()["state"] == "cancelled"
    assert result.status_code == 200
    assert result.json()["state"] == "cancelled"
    assert result.json()["result"]["errorDetail"]["code"] == "REQUEST_CANCELLED"
    health_payload = health.json()
    assert health_payload["activeRequestCount"] == 0
    summary = health_payload["requestSummary"]
    assert summary["state"] == "cancelled"
    assert summary["ackStatus"] == "broken"
    assert summary["localAckState"] == "ack-break"
    assert summary["blockedReason"] == "request cancelled"
    assert summary["lastAckSource"] == "request-cancelled"


@pytest.mark.asyncio
async def test_unknown_request_status_and_result_are_404(client: AsyncClient) -> None:
    status = await client.get("/v1/requests/missing")
    result = await client.get("/v1/requests/missing/result")
    cancel = await client.delete("/v1/requests/missing")
    for response in (status, result, cancel):
        assert response.status_code == 404
        payload = response.json()
        assert payload["success"] is False
        assert payload["error"] == "REQUEST_NOT_FOUND"
        assert payload["requestId"] == "missing"
        assert payload["errorDetail"]["code"] == "REQUEST_NOT_FOUND"
        assert payload["errorDetail"]["message"] == "request not found"
        assert payload["errorDetail"]["requestId"] == "missing"
        assert payload["errorDetail"]["retryable"] is False


@pytest.mark.asyncio
async def test_expired_terminal_result_returns_410(client: AsyncClient) -> None:
    request_ownership_store.retention_seconds = -1
    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(return_value=_build_result(success=True)),
    ):
        submit = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "owned-expired", "Prefer": "respond-async"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        assert submit.status_code == 202
        for _ in range(20):
            status = await client.get("/v1/requests/owned-expired")
            if status.status_code == 410:
                break
            await asyncio.sleep(0.02)
        else:
            raise AssertionError("request did not expire")

    result = await client.get("/v1/requests/owned-expired/result")
    assert result.status_code == 410
    payload = result.json()
    assert payload["success"] is False
    assert payload["error"] == "REQUEST_EXPIRED"
    assert payload["requestId"] == "owned-expired"
    assert payload["errorDetail"]["code"] == "REQUEST_EXPIRED"
    assert payload["errorDetail"]["message"] == "request expired"
    assert payload["errorDetail"]["requestId"] == "owned-expired"
    assert payload["errorDetail"]["retryable"] is False

@pytest.mark.asyncio
async def test_same_request_id_different_endpoint_returns_conflict(client: AsyncClient) -> None:
    gate = asyncio.Event()

    async def _slow_build(*args, on_runtime_state=None, **kwargs):
        await gate.wait()
        return _build_result(success=True)

    scan_mock = AsyncMock(return_value=_scan_response("conflicting-scan"))

    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(side_effect=_slow_build),
    ), patch("app.routers.scan._run_scan_core", scan_mock):
        build_submit = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "shared-trace-id", "Prefer": "respond-async"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )
        scan_submit = await client.post(
            "/v1/scan",
            headers={"X-Request-Id": "shared-trace-id", "Prefer": "respond-async"},
            json={
                "scanId": "conflicting-scan",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        )
        gate.set()
        await _wait_for_result(client, "shared-trace-id")

    assert build_submit.status_code == 202
    assert scan_submit.status_code == 409
    payload = scan_submit.json()
    assert payload["success"] is False
    assert payload["error"] == "REQUEST_ID_CONFLICT"
    assert payload["requestId"] == "shared-trace-id"
    assert payload["errorDetail"]["code"] == "REQUEST_ID_CONFLICT"
    assert payload["errorDetail"]["message"] == "request id already belongs to another endpoint"
    assert payload["errorDetail"]["requestId"] == "shared-trace-id"
    assert payload["errorDetail"]["retryable"] is False
    assert payload["existingEndpoint"] == "build"
    assert payload["requestedEndpoint"] == "scan"
    assert payload["statusUrl"] == "/v1/requests/shared-trace-id"
    assert payload["resultUrl"] == "/v1/requests/shared-trace-id/result"
    scan_mock.assert_not_called()
