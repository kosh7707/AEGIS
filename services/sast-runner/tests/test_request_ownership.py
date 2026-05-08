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
async def test_unknown_request_status_and_result_are_404(client: AsyncClient) -> None:
    status = await client.get("/v1/requests/missing")
    result = await client.get("/v1/requests/missing/result")
    assert status.status_code == 404
    assert status.json()["error"] == "REQUEST_NOT_FOUND"
    assert result.status_code == 404
    assert result.json()["error"] == "REQUEST_NOT_FOUND"


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
    assert result.json()["error"] == "REQUEST_EXPIRED"

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
    assert payload["error"] == "REQUEST_ID_CONFLICT"
    assert payload["existingEndpoint"] == "build"
    assert payload["requestedEndpoint"] == "scan"
    scan_mock.assert_not_called()
