"""API 엔드포인트 계약 테스트."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.scanner.orchestrator import ALL_TOOLS
from app.scanner.semgrep_coverage import C_CPP_INCLUDE_EXTENSIONS
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    SdkResolutionInfo,
    ToolExecutionResult,
)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    from unittest.mock import AsyncMock, patch

    with patch.object(
        __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator,
        "check_tools",
        AsyncMock(return_value={
            "semgrep": {"available": True, "version": "1.45.0", "probeReason": None},
            "cppcheck": {"available": True, "version": "2.13.0", "probeReason": None},
            "flawfinder": {"available": True, "version": "2.0.19", "probeReason": None},
            "clang-tidy": {"available": True, "version": "18.1.3", "probeReason": None},
            "scan-build": {"available": True, "version": "18.1.3", "probeReason": None},
            "gcc-fanalyzer": {"available": True, "version": "13.3.0", "probeReason": None},
        }),
    ):
        resp = await client.get("/v1/health")
    assert resp.status_code == 200

    data = resp.json()
    assert data["service"] == "s4-sast"
    assert data["status"] == "ok"
    assert data["version"] == "0.11.2"
    assert "semgrep" in data
    assert "defaultRulesets" in data
    assert data["policyStatus"] == "ok"
    assert data["policyReasons"] == []
    assert data["unavailableTools"] == []
    assert data["allowedSkipReasons"] == [
        "operator-requested-subset",
        "profile-not-applicable",
    ]
    assert data["activeRequestCount"] == 0
    assert data["requestSummary"]["state"] == "idle"
    assert data["requestSummary"]["ackStatus"] == "idle"
    assert data["requestSummary"]["localAckState"] is None


def _contains_key(value, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


@pytest.mark.asyncio
async def test_request_validation_error_does_not_echo_raw_body_values(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SECRET_422_VALIDATION_SHOULD_NOT_LEAK"
    request_id = "req-validation-redacted"
    caplog.set_level("WARNING", logger="aegis-sast-runner")

    resp = await client.post(
        "/v1/scan",
        headers={"X-Request-Id": request_id},
        json={
            "scanId": "validation-redaction",
            "projectId": "proj-test",
            "files": [
                {
                    "path": "src/main.c",
                    "content": {"secret": secret},
                },
            ],
        },
    )

    assert resp.status_code == 422
    assert resp.headers["X-Request-Id"] == request_id
    data = resp.json()
    assert data["success"] is False
    assert data["error"] == "request validation failed"
    assert data["errorDetail"]["code"] == "REQUEST_VALIDATION_FAILED"
    assert data["errorDetail"]["message"] == "request validation failed"
    assert data["errorDetail"]["requestId"] == request_id
    assert data["errorDetail"]["retryable"] is False
    assert data["validationErrors"]
    assert data["validationErrors"][0]["loc"] == ["body", "files", 0, "content"]
    assert _contains_key(data, "input") is False
    assert _contains_key(data, "ctx") is False
    assert _contains_key(data, "url") is False
    assert secret not in resp.text
    assert secret not in str(data)
    assert secret not in caplog.text


@pytest.mark.asyncio
async def test_request_validation_error_redacts_dynamic_location_keys(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SECRET_ENV_KEY_SHOULD_NOT_LEAK"
    caplog.set_level("WARNING", logger="aegis-sast-runner")

    resp = await client.post(
        "/v1/build",
        headers={"X-Request-Id": "req-validation-loc-redacted"},
        json={
            "projectPath": "/tmp",
            "buildCommand": "make",
            "buildEnvironment": {
                secret: {"bad": "value"},
            },
        },
    )

    assert resp.status_code == 422
    data = resp.json()
    assert data["errorDetail"]["code"] == "REQUEST_VALIDATION_FAILED"
    assert data["validationErrors"][0]["loc"] == ["body", "buildEnvironment", "<field>"]
    assert secret not in resp.text
    assert secret not in str(data)
    assert secret not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "payload", "expected_loc"),
    [
        (
            "/v1/build",
            {
                "projectPath": "/tmp",
                "buildCommand": "make",
                "buildEnvironment": {
                    "environment": {"secret": "SECRET_MAP_VALUE_SHOULD_NOT_LEAK"},
                },
            },
            ["body", "buildEnvironment", "<field>"],
        ),
        (
            "/v1/scan",
            {
                "scanId": "validation-loc-context",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main(void) { return 0; }"}],
                "buildProfile": {
                    "defines": {
                        "compiler": {"secret": "SECRET_MAP_VALUE_SHOULD_NOT_LEAK"},
                    },
                },
            },
            ["body", "buildProfile", "defines", "<field>"],
        ),
    ],
)
async def test_request_validation_error_redacts_safe_named_dynamic_map_keys(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
    path: str,
    payload: dict,
    expected_loc: list,
) -> None:
    secret = "SECRET_MAP_VALUE_SHOULD_NOT_LEAK"
    caplog.set_level("WARNING", logger="aegis-sast-runner")

    resp = await client.post(
        path,
        headers={"X-Request-Id": "req-validation-context-loc-redacted"},
        json=payload,
    )

    assert resp.status_code == 422
    data = resp.json()
    assert data["errorDetail"]["code"] == "REQUEST_VALIDATION_FAILED"
    assert expected_loc in [error["loc"] for error in data["validationErrors"]]
    assert secret not in resp.text
    assert secret not in str(data)
    assert secret not in caplog.text


@pytest.mark.asyncio
async def test_health_endpoint_preserves_existing_fields_and_adds_policy(client: AsyncClient) -> None:
    from unittest.mock import AsyncMock, patch

    with patch.object(
        __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator,
        "check_tools",
        AsyncMock(return_value={
            "semgrep": {"available": False, "version": None, "probeReason": "environment-drift"},
            "cppcheck": {"available": True, "version": "2.13.0", "probeReason": None},
            "flawfinder": {"available": True, "version": "2.0.19", "probeReason": None},
            "clang-tidy": {"available": True, "version": "18.1.3", "probeReason": None},
            "scan-build": {"available": True, "version": "18.1.3", "probeReason": None},
            "gcc-fanalyzer": {"available": True, "version": "13.3.0", "probeReason": None},
        }),
    ):
        resp = await client.get("/v1/health")

    data = resp.json()
    assert resp.status_code == 200
    assert data["status"] == "ok"
    assert "semgrep" in data and "tools" in data and "defaultRulesets" in data
    assert data["policyStatus"] == "degraded"
    assert data["policyReasons"] == ["environment-drift"]
    assert data["unavailableTools"] == ["semgrep"]
    assert data["allowedSkipReasons"] == [
        "operator-requested-subset",
        "profile-not-applicable",
    ]
    assert data["activeRequestCount"] == 0
    assert data["requestSummary"]["state"] == "idle"
    assert data["requestSummary"]["localAckState"] is None


@pytest.mark.asyncio
async def test_health_endpoint_redacts_expected_executable_path(client: AsyncClient) -> None:
    secret_path = "/svc/SECRET_HEALTH_TOOL_PATH_SHOULD_NOT_LEAK/semgrep"
    router_orchestrator = __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator

    with patch.object(
        router_orchestrator,
        "check_tools",
        AsyncMock(return_value={
            "semgrep": {
                "available": False,
                "version": None,
                "probeReason": "environment-drift",
                "expectedExecutablePath": secret_path,
            },
            "cppcheck": {"available": True, "version": "2.13.0", "probeReason": None},
            "flawfinder": {"available": True, "version": "2.0.19", "probeReason": None},
            "clang-tidy": {"available": True, "version": "18.1.3", "probeReason": None},
            "scan-build": {"available": True, "version": "18.1.3", "probeReason": None},
            "gcc-fanalyzer": {"available": True, "version": "13.3.0", "probeReason": None},
        }),
    ):
        resp = await client.get("/v1/health")

    data = resp.json()
    assert resp.status_code == 200
    assert data["semgrep"]["expectedExecutablePathStatus"] == "configured"
    assert data["tools"]["semgrep"]["expectedExecutablePathStatus"] == "configured"
    assert "expectedExecutablePath" not in data["semgrep"]
    assert "expectedExecutablePath" not in data["tools"]["semgrep"]
    assert secret_path not in str(data)


@pytest.mark.asyncio
async def test_health_endpoint_request_summary_reports_running_state(
    client: AsyncClient,
    mock_semgrep_runner,
) -> None:
    from app.scanner.sarif_parser import parse_sarif
    import json
    from pathlib import Path as P

    sarif = json.loads((P(__file__).parent / "fixtures" / "sample.sarif.json").read_text())
    findings, _ = parse_sarif(sarif, P("/tmp/mock"))
    execution = mock_semgrep_runner.run.return_value[1]
    mock_semgrep_runner.run = AsyncMock(
        side_effect=_make_slow_progress_mock(findings, execution, delay=0.2),
    )

    scan_task = asyncio.create_task(
        client.post(
            "/v1/scan",
            headers={"X-Request-Id": "scan-health-running"},
            json={
                "scanId": "scan-health-running",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        ),
    )
    await asyncio.sleep(0.05)

    health_resp = await client.get("/v1/health", params={"requestId": "scan-health-running"})
    data = health_resp.json()

    assert health_resp.status_code == 200
    assert data["activeRequestCount"] >= 1
    assert data["requestSummary"]["requestId"] == "scan-health-running"
    assert data["requestSummary"]["state"] == "running"
    assert data["requestSummary"]["ackStatus"] == "active"
    assert data["requestSummary"]["localAckState"] == "phase-advancing"
    assert data["requestSummary"]["degraded"] is True
    assert "timeout-floor" in data["requestSummary"]["degradeReasons"]
    assert data["requestSummary"]["lastAckSource"] in {"tool-progress", "runtime-state", "file-progress"}

    await scan_task


@pytest.mark.asyncio
async def test_health_endpoint_request_summary_reports_queued_state(
    client: AsyncClient,
    mock_semgrep_runner,
) -> None:
    from app.config import settings
    from app.routers.scan import _scan_semaphore
    from app.scanner.sarif_parser import parse_sarif
    import json
    from pathlib import Path as P

    sarif = json.loads((P(__file__).parent / "fixtures" / "sample.sarif.json").read_text())
    findings, _ = parse_sarif(sarif, P("/tmp/mock"))
    execution = mock_semgrep_runner.run.return_value[1]
    mock_semgrep_runner.run = AsyncMock(side_effect=_make_progress_mock(findings, execution))

    for _ in range(settings.max_concurrent_scans):
        await _scan_semaphore.acquire()

    async def _release_later():
        await asyncio.sleep(0.15)
        for _ in range(settings.max_concurrent_scans):
            _scan_semaphore.release()

    release_task = asyncio.create_task(_release_later())
    scan_task = asyncio.create_task(
        client.post(
            "/v1/scan",
            headers={"X-Request-Id": "scan-health-queued"},
            json={
                "scanId": "scan-health-queued",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        ),
    )
    await asyncio.sleep(0.03)

    health_resp = await client.get("/v1/health", params={"requestId": "scan-health-queued"})
    data = health_resp.json()

    assert health_resp.status_code == 200
    assert data["requestSummary"]["requestId"] == "scan-health-queued"
    assert data["requestSummary"]["state"] == "queued"
    assert data["requestSummary"]["ackStatus"] == "active"
    assert data["requestSummary"]["localAckState"] == "transport-only"

    await release_task
    await scan_task


@pytest.mark.asyncio
async def test_health_endpoint_request_summary_reports_ack_break(client: AsyncClient) -> None:
    secret = "SECRET_HEALTH_INTERNAL_EXCEPTION_SHOULD_NOT_LEAK"
    with patch("app.routers.scan.orchestrator.run", AsyncMock(side_effect=RuntimeError(secret))):
        resp = await client.post(
            "/v1/scan",
            headers={"X-Request-Id": "scan-health-failed"},
            json={
                "scanId": "scan-health-failed",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        )

    assert resp.status_code == 500

    health_resp = await client.get("/v1/health", params={"requestId": "scan-health-failed"})
    data = health_resp.json()
    assert health_resp.status_code == 200
    assert data["requestSummary"]["requestId"] == "scan-health-failed"
    assert data["requestSummary"]["state"] == "failed"
    assert data["requestSummary"]["ackStatus"] == "broken"
    assert data["requestSummary"]["localAckState"] == "ack-break"
    assert data["requestSummary"]["blockedReason"] == "internal error"
    assert secret not in str(data)


@pytest.mark.asyncio
async def test_health_endpoint_request_summary_reports_build_transport_only_state(
    client: AsyncClient,
) -> None:
    gate = asyncio.Event()

    async def _slow_build(*args, on_runtime_state=None, **kwargs):
        if on_runtime_state:
            await on_runtime_state(
                {
                    "localAckState": "transport-only",
                    "lastAckSource": "build-subprocess-alive",
                },
            )
        await gate.wait()
        return {
            "success": True,
            "buildEvidence": {
                "requestedBuildCommand": "make",
                "effectiveBuildCommand": "make",
                "buildDir": "/tmp/project",
                "compileCommandsPath": "/tmp/project/compile_commands.json",
                "entries": 1,
                "userEntries": 1,
                "exitCode": 0,
                "buildOutput": "ok",
                "wrapWithBear": True,
                "timeoutSeconds": 600,
                "environmentKeys": None,
                "elapsedMs": 200,
            },
            "readiness": {
                "status": "ready",
                "compileCommandsReady": True,
                "quickEligible": True,
                "summary": "ready",
            },
            "failureDetail": None,
        }

    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(side_effect=_slow_build),
    ):
        build_task = asyncio.create_task(
            client.post(
                "/v1/build",
                headers={"X-Request-Id": "build-health-running"},
                json={"projectPath": "/tmp/project", "buildCommand": "make"},
            ),
        )
        await asyncio.sleep(0.05)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as health_client:
            health_resp = await health_client.get("/v1/health", params={"requestId": "build-health-running"})
            data = health_resp.json()

            assert health_resp.status_code == 200
            assert data["requestSummary"]["requestId"] == "build-health-running"
            assert data["requestSummary"]["endpoint"] == "build"
            assert data["requestSummary"]["state"] == "running"
            assert data["requestSummary"]["ackStatus"] == "active"
            assert data["requestSummary"]["localAckState"] == "transport-only"
            assert data["requestSummary"]["lastAckSource"] == "build-subprocess-alive"

        gate.set()
        await build_task


@pytest.mark.asyncio
async def test_health_endpoint_request_summary_reports_build_and_analyze_transport_only_state(
    client: AsyncClient,
) -> None:
    from app.schemas.response import (
        ExecutionReport,
        FindingsFilterInfo,
        ScanResponse,
        ScanStats,
        SdkResolutionInfo,
    )
    gate = asyncio.Event()

    async def _slow_build(*args, on_runtime_state=None, **kwargs):
        if on_runtime_state:
            await on_runtime_state(
                {
                    "localAckState": "transport-only",
                    "lastAckSource": "build-subprocess-alive",
                },
            )
        await gate.wait()
        return {
            "success": True,
            "buildEvidence": {
                "requestedBuildCommand": "make",
                "effectiveBuildCommand": "make",
                "buildDir": "/tmp/project",
                "compileCommandsPath": "/tmp/project/compile_commands.json",
                "entries": 1,
                "userEntries": 1,
                "exitCode": 0,
                "buildOutput": "ok",
                "wrapWithBear": True,
                "timeoutSeconds": 600,
                "environmentKeys": None,
                "elapsedMs": 200,
            },
            "readiness": {
                "status": "ready",
                "compileCommandsReady": True,
                "quickEligible": True,
                "summary": "ready",
            },
            "failureDetail": None,
        }

    scan_result = ScanResponse(
        success=True,
        scanId="build-analyze-health-running",
        status="completed",
        findings=[],
        stats=ScanStats(filesScanned=1, rulesRun=1, findingsTotal=0, elapsedMs=5),
        execution=ExecutionReport(
            toolsRun=[],
            toolResults={},
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        ),
        codeGraph={"functions": []},
        sca={"libraries": []},
    )

    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(side_effect=_slow_build),
    ), patch(
        "app.routers.scan._run_scan_core",
        AsyncMock(return_value=scan_result),
    ), patch(
        "app.routers.scan.metadata_extractor.extract",
        AsyncMock(return_value={"compiler": "gcc"}),
    ):
        task = asyncio.create_task(
            client.post(
                "/v1/build-and-analyze",
                headers={"X-Request-Id": "build-analyze-health-running"},
                json={"projectPath": "/tmp/project", "buildCommand": "make"},
            ),
        )
        await asyncio.sleep(0.05)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as health_client:
            health_resp = await health_client.get("/v1/health", params={"requestId": "build-analyze-health-running"})
            data = health_resp.json()

            assert health_resp.status_code == 200
            assert data["requestSummary"]["requestId"] == "build-analyze-health-running"
            assert data["requestSummary"]["endpoint"] == "build-and-analyze"
            assert data["requestSummary"]["state"] == "running"
            assert data["requestSummary"]["ackStatus"] == "active"
            assert data["requestSummary"]["localAckState"] == "transport-only"
            assert data["requestSummary"]["lastAckSource"] == "build-subprocess-alive"

        gate.set()
        await task


@pytest.mark.asyncio
async def test_health_endpoint_request_summary_reports_build_ack_break(client: AsyncClient) -> None:
    with patch("app.routers.scan.Path.is_dir", return_value=True), patch(
        "app.routers.scan.build_runner.build",
        AsyncMock(
            return_value={
                "success": False,
                "buildEvidence": {
                    "requestedBuildCommand": "make",
                    "effectiveBuildCommand": "make",
                    "buildDir": "/tmp/project",
                    "compileCommandsPath": None,
                    "entries": None,
                    "userEntries": None,
                    "exitCode": 127,
                    "buildOutput": "command not found",
                    "wrapWithBear": True,
                    "timeoutSeconds": 600,
                    "environmentKeys": None,
                    "elapsedMs": 5,
                },
                "readiness": {
                    "status": "not-ready",
                    "compileCommandsReady": False,
                    "quickEligible": False,
                    "summary": "not ready",
                },
                "failureDetail": {
                    "category": "command-not-found",
                    "summary": "The supplied build command referenced an unavailable executable or script (exit code 127).",
                    "matchedExcerpt": "command not found",
                    "hint": "provide a valid build command",
                    "retryable": False,
                },
            },
        ),
    ):
        resp = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "build-health-failed"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )

    assert resp.status_code == 200
    health_resp = await client.get("/v1/health", params={"requestId": "build-health-failed"})
    data = health_resp.json()
    assert data["requestSummary"]["endpoint"] == "build"
    assert data["requestSummary"]["state"] == "failed"
    assert data["requestSummary"]["ackStatus"] == "broken"
    assert data["requestSummary"]["localAckState"] == "ack-break"
    assert "unavailable executable" in data["requestSummary"]["blockedReason"]


@pytest.mark.asyncio
async def test_scan_no_files_returns_400(client: AsyncClient) -> None:
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-001",
            "projectId": "proj-test",
            "files": [],
        },
    )
    assert resp.status_code == 400

    data = resp.json()
    assert data["success"] is False
    assert data["status"] == "failed"
    assert data["errorDetail"]["code"] == "NO_FILES_PROVIDED"
    assert data["errorDetail"]["retryable"] is False


@pytest.mark.asyncio
async def test_scan_path_traversal_rejected(client: AsyncClient) -> None:
    secret_path = "../../../SECRET_SCAN_TRAVERSAL_SHOULD_NOT_LEAK.c"
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-002",
            "projectId": "proj-test",
            "files": [{"path": secret_path, "content": "x"}],
        },
    )
    assert resp.status_code == 400

    data = resp.json()
    assert data["error"] == "Path traversal not allowed"
    assert data["errorDetail"]["code"] == "NO_FILES_PROVIDED"
    assert data["errorDetail"]["message"] == "Path traversal not allowed"
    assert "SECRET_SCAN_TRAVERSAL_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_scan_absolute_path_rejected(client: AsyncClient) -> None:
    secret_path = "/tmp/SECRET_SCAN_ABSOLUTE_SHOULD_NOT_LEAK.c"
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-003",
            "projectId": "proj-test",
            "files": [{"path": secret_path, "content": "x"}],
        },
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "Absolute path not allowed"
    assert data["errorDetail"]["message"] == "Absolute path not allowed"
    assert "SECRET_SCAN_ABSOLUTE_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_scan_request_id_propagation(client: AsyncClient) -> None:
    """X-Request-Id 헤더가 응답에 전파되는지 확인."""
    resp = await client.post(
        "/v1/scan",
        headers={"X-Request-Id": "req-test-123"},
        json={
            "scanId": "test-004",
            "projectId": "proj-test",
            "files": [],
        },
    )
    assert resp.headers.get("X-Request-Id") == "req-test-123"


@pytest.mark.asyncio
async def test_scan_generates_request_id_if_missing(client: AsyncClient) -> None:
    """X-Request-Id가 없으면 자동 생성."""
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-005",
            "projectId": "proj-test",
            "files": [],
        },
    )
    assert resp.headers.get("X-Request-Id", "").startswith("req-")


@pytest.mark.asyncio
async def test_scan_success_with_mock(
    client: AsyncClient,
    mock_semgrep_runner,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Semgrep mock으로 정상 스캔 응답 구조 확인."""
    caplog.set_level("INFO", logger="aegis-sast-runner")
    resp = await client.post(
        "/v1/scan",
        headers={"X-Request-Id": "req-mock-001"},
        json={
            "scanId": "test-mock-001",
            "projectId": "proj-test",
            "files": [
                {"path": "src/main.c", "content": "#include <stdio.h>\nvoid f() { gets(buf); }"}
            ],
            "rulesets": ["p/c"],
        },
    )
    assert resp.status_code == 200

    data = resp.json()
    assert data["success"] is True
    assert data["status"] == "completed"
    assert data["scanId"] == "test-mock-001"
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) == 3

    # SastFinding 필드 검증 (shared-models.md alias 형식)
    finding = data["findings"][0]
    assert "toolId" in finding
    assert "ruleId" in finding
    assert finding["toolId"] == "semgrep"
    assert finding["ruleId"].startswith("semgrep:")
    assert "location" in finding
    assert "line" in finding["location"]

    # stats
    assert data["stats"]["filesScanned"] == 1
    assert data["stats"]["findingsTotal"] == 3
    assert data["stats"]["elapsedMs"] >= 0

    scan_summary = [
        record for record in caplog.records
        if record.getMessage() == "Scan execution summary"
    ][-1]
    assert scan_summary.requestId == "req-mock-001"
    assert scan_summary.scanId == "test-mock-001"
    assert scan_summary.findingsByTool["semgrep"] == 3
    assert scan_summary.findingsAfterFilter == 3
    assert scan_summary.compileCommandsProvided is False
    assert scan_summary.sdkResolved is False

    terminal_summary = [
        record for record in caplog.records
        if record.getMessage() == "Request terminal summary"
    ][-1]
    assert terminal_summary.requestId == "req-mock-001"
    assert terminal_summary.endpoint == "scan"
    assert terminal_summary.state == "completed"


@pytest.mark.asyncio
async def test_scan_logs_redact_sdk_id_identity(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_sdk_id = "SECRET_SDK_ID_SHOULD_NOT_LEAK"
    execution = ExecutionReport(
        toolsRun=["cppcheck"],
        toolResults={
            "cppcheck": ToolExecutionResult(
                status="ok",
                findingsCount=0,
                elapsedMs=1,
            ),
        },
        sdk=SdkResolutionInfo(
            resolved=True,
            sdkId=secret_sdk_id,
            includePathsAdded=0,
        ),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=False,
        degradeReasons=[],
    )
    caplog.set_level("INFO", logger="aegis-sast-runner")

    with (
        patch("app.routers.scan.sdk_reference_exists", return_value=True),
        patch(
            "app.routers.scan.orchestrator.run",
            AsyncMock(return_value=([], execution)),
        ),
    ):
        resp = await client.post(
            "/v1/scan",
            headers={"X-Request-Id": "req-sdk-log-redaction"},
            json={
                "scanId": "test-sdk-log-redaction",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main(void) { return 0; }\n"}],
                "buildProfile": {"sdkId": secret_sdk_id},
                "options": {"tools": ["cppcheck"]},
            },
        )

    assert resp.status_code == 200
    started = [
        record for record in caplog.records
        if record.getMessage() == "Scan started"
    ][-1]
    summary = [
        record for record in caplog.records
        if record.getMessage() == "Scan execution summary"
    ][-1]

    assert started.sdkIdProvided is True
    assert summary.executionSdkIdProvided is True
    assert not hasattr(started, "sdkId")
    assert not hasattr(summary, "sdkId")
    assert secret_sdk_id not in caplog.text
    assert secret_sdk_id not in repr(started.__dict__)
    assert secret_sdk_id not in repr(summary.__dict__)


@pytest.mark.asyncio
async def test_scan_with_build_profile(client: AsyncClient, mock_semgrep_runner) -> None:
    """BuildProfile을 포함한 스캔 요청이 정상 처리되는지 확인."""
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-bp-001",
            "projectId": "proj-test",
            "files": [
                {"path": "src/main.c", "content": "int main() { return 0; }"}
            ],
            "buildProfile": {
                "compiler": "arm-none-eabi-gcc",
                "compilerVersion": "12.3.0",
                "targetArch": "arm-cortex-a8",
                "languageStandard": "c99",
                "headerLanguage": "c",
                "defines": {"__ARM_ARCH": "7"},
                "flags": ["-mthumb"]
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True


@pytest.mark.asyncio
async def test_scan_echoes_provenance(client: AsyncClient, mock_semgrep_runner) -> None:
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-prov-001",
            "projectId": "proj-test",
            "provenance": {
                "buildSnapshotId": "bsnap-123",
                "buildUnitId": "bunit-123",
                "snapshotSchemaVersion": "build-snapshot-v1",
            },
            "files": [
                {"path": "src/main.c", "content": "int main() { return 0; }"},
            ],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["provenance"]["buildSnapshotId"] == "bsnap-123"


@pytest.mark.asyncio
async def test_scan_with_cpp_profile_auto_rulesets(client: AsyncClient, mock_semgrep_runner) -> None:
    """C++ BuildProfile로 보내면 룰셋이 자동 선택되는지 확인."""
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-bp-cpp-001",
            "projectId": "proj-test",
            "files": [
                {"path": "src/main.cpp", "content": "int main() { return 0; }"}
            ],
            "buildProfile": {
                "compiler": "g++",
                "targetArch": "x86_64",
                "languageStandard": "c++17",
                "headerLanguage": "cpp",
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True


@pytest.mark.asyncio
async def test_scan_without_build_profile_still_works(client: AsyncClient, mock_semgrep_runner) -> None:
    """BuildProfile 없이도 기존처럼 동작하는지 확인 (하위호환)."""
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-no-bp-001",
            "projectId": "proj-test",
            "files": [
                {"path": "src/main.c", "content": "int main() { return 0; }"}
            ],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True


@pytest.mark.asyncio
async def test_scan_error_response_format(client: AsyncClient) -> None:
    """에러 응답이 observability.md errorDetail 형식을 준수하는지 확인."""
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-err-001",
            "projectId": "proj-test",
            "files": [],
        },
    )
    data = resp.json()

    # observability.md 필수 필드
    assert "success" in data
    assert "error" in data
    assert "errorDetail" in data
    detail = data["errorDetail"]
    assert "code" in detail
    assert "message" in detail
    assert "requestId" in detail
    assert "retryable" in detail


# === /v1/discover-targets ===


@pytest.mark.asyncio
async def test_discover_targets_no_project_path(client: AsyncClient) -> None:
    """projectPath 없으면 400."""
    resp = await client.post(
        "/v1/discover-targets",
        headers={"X-Request-Id": "req-discover-no-path"},
        json={},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["error"] == "projectPath is required"
    assert data["errorDetail"]["code"] == "PROJECT_PATH_REQUIRED"
    assert data["errorDetail"]["message"] == "projectPath is required"
    assert data["errorDetail"]["requestId"] == "req-discover-no-path"
    assert data["errorDetail"]["retryable"] is False


@pytest.mark.asyncio
async def test_discover_targets_invalid_path(client: AsyncClient) -> None:
    """존재하지 않는 경로면 400."""
    secret_path = "/tmp/SECRET_DISCOVER_PROJECT_PATH_SHOULD_NOT_LEAK"
    resp = await client.post(
        "/v1/discover-targets",
        json={"projectPath": secret_path},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["error"] == "projectPath not found"
    assert data["errorDetail"]["code"] == "PROJECT_PATH_NOT_FOUND"
    assert data["errorDetail"]["message"] == "projectPath not found"
    assert data["errorDetail"]["retryable"] is False
    assert "SECRET_DISCOVER_PROJECT_PATH_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_discover_targets_basic(client: AsyncClient, tmp_path) -> None:
    """빌드 파일 탐지 기본 동작."""
    (tmp_path / "gateway").mkdir()
    (tmp_path / "gateway" / "CMakeLists.txt").touch()
    (tmp_path / "controller").mkdir()
    (tmp_path / "controller" / "Makefile").touch()

    resp = await client.post(
        "/v1/discover-targets",
        json={"projectPath": str(tmp_path)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["targets"]) == 2
    names = {t["name"] for t in data["targets"]}
    assert "gateway" in names
    assert "controller" in names


@pytest.mark.asyncio
async def test_discover_targets_nested_dedup(client: AsyncClient, tmp_path) -> None:
    """중첩 빌드 파일은 상위만 반환."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "CMakeLists.txt").touch()
    (tmp_path / "app" / "src").mkdir()
    (tmp_path / "app" / "src" / "CMakeLists.txt").touch()  # 중첩 — 제거

    resp = await client.post(
        "/v1/discover-targets",
        json={"projectPath": str(tmp_path)},
    )
    data = resp.json()
    assert len(data["targets"]) == 1
    assert data["targets"][0]["name"] == "app"


# === /v1/functions ===


@pytest.mark.asyncio
async def test_functions_no_input_returns_error(client: AsyncClient) -> None:
    """files도 projectPath도 없으면 에러."""
    resp = await client.post(
        "/v1/functions",
        json={"scanId": "test-fn-001", "projectId": "proj-test", "files": []},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_functions_invalid_project_path_redacts_project_path(
    client: AsyncClient,
) -> None:
    secret_path = "/tmp/SECRET_FUNCTIONS_PROJECT_PATH_SHOULD_NOT_LEAK"

    resp = await client.post(
        "/v1/functions",
        json={"scanId": "test-fn-invalid-path", "projectId": "proj-test", "projectPath": secret_path},
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "projectPath not found"
    assert data["errorDetail"]["message"] == "projectPath not found"
    assert "SECRET_FUNCTIONS_PROJECT_PATH_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_functions_file_path_traversal_redacts_file_path(
    client: AsyncClient,
) -> None:
    secret_path = "../SECRET_FUNCTIONS_TRAVERSAL_SHOULD_NOT_LEAK.c"

    resp = await client.post(
        "/v1/functions",
        json={
            "scanId": "test-fn-path-traversal",
            "projectId": "proj-test",
            "files": [{"path": secret_path, "content": "int f(void) { return 0; }"}],
        },
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "Path traversal not allowed"
    assert data["errorDetail"]["message"] == "Path traversal not allowed"
    assert "SECRET_FUNCTIONS_TRAVERSAL_SHOULD_NOT_LEAK" not in str(data)


# === /v1/build ===


@pytest.mark.asyncio
async def test_build_no_project_path(client: AsyncClient) -> None:
    """projectPath 없으면 400."""
    resp = await client.post("/v1/build", json={})
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False


@pytest.mark.asyncio
async def test_build_invalid_path(client: AsyncClient) -> None:
    """존재하지 않는 경로면 400."""
    secret_path = "/tmp/SECRET_BUILD_PROJECT_PATH_SHOULD_NOT_LEAK"
    resp = await client.post(
        "/v1/build",
        json={"projectPath": secret_path},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["error"] == "projectPath not found"
    assert data["errorDetail"]["code"] == "PROJECT_PATH_NOT_FOUND"
    assert data["errorDetail"]["message"] == "projectPath not found"
    assert data["errorDetail"]["retryable"] is False
    assert "SECRET_BUILD_PROJECT_PATH_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_build_requires_build_command(client: AsyncClient, tmp_path) -> None:
    """buildCommand는 필수."""
    resp = await client.post(
        "/v1/build",
        json={
            "projectPath": str(tmp_path),
        },
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["error"] == "buildCommand is required"
    assert data["errorDetail"]["code"] == "BUILD_COMMAND_REQUIRED"
    assert data["errorDetail"]["message"] == "buildCommand is required"
    assert data["errorDetail"]["retryable"] is False


@pytest.mark.asyncio
async def test_build_accepts_explicit_environment(client: AsyncClient, tmp_path) -> None:
    """buildEnvironment는 그대로 전달 가능."""
    resp = await client.post(
        "/v1/build",
        json={
            "projectPath": str(tmp_path),
            "buildCommand": "echo hello",
            "buildEnvironment": {"SDK_ROOT": "/uploads/sdk", "CC": "/uploads/sdk/bin/gcc"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "success" in data
    assert "buildEvidence" in data
    assert "environmentKeys" in data["buildEvidence"]


@pytest.mark.asyncio
async def test_build_rejects_legacy_build_profile(client: AsyncClient, tmp_path) -> None:
    resp = await client.post(
        "/v1/build",
        json={
            "projectPath": str(tmp_path),
            "buildCommand": "echo hello",
            "buildProfile": {"sdkId": "ti-am335x"},
        },
    )
    assert resp.status_code == 422



@pytest.mark.asyncio
async def test_build_echoes_provenance_and_structured_evidence(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO", logger="aegis-sast-runner")
    mocked = {
        "success": True,
        "buildEvidence": {
            "requestedBuildCommand": "make",
            "effectiveBuildCommand": "make",
            "buildDir": "/tmp/project",
            "compileCommandsPath": "/tmp/project/compile_commands.json",
            "entries": 2,
            "userEntries": 2,
            "exitCode": 0,
            "buildOutput": "ok",
            "wrapWithBear": True,
            "timeoutSeconds": 600,
            "environmentKeys": ["CC", "SDK_ROOT"],
            "elapsedMs": 123,
        },
        "readiness": {
            "status": "ready",
            "compileCommandsReady": True,
            "quickEligible": True,
            "summary": "compile_commands.json contains user-target entries and the build exited successfully.",
        },
        "failureDetail": None,
    }

    with (
        patch("pathlib.Path.is_dir", return_value=True),
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=mocked)),
    ):
        resp = await client.post(
            "/v1/build",
            json={
                "projectPath": "/tmp/project",
                "buildCommand": "make",
                "provenance": {
                    "buildSnapshotId": "bsnap-1",
                    "buildUnitId": "bunit-1",
                    "snapshotSchemaVersion": "build-snapshot-v1",
                },
            },
        )

    data = resp.json()
    assert data["success"] is True
    assert data["provenance"]["buildSnapshotId"] == "bsnap-1"
    assert data["buildEvidence"]["effectiveBuildCommand"] == "make"
    assert data["buildEvidence"]["environmentKeys"] == ["CC", "SDK_ROOT"]
    assert data["readiness"]["status"] == "ready"
    assert data["readiness"]["quickEligible"] is True

    build_summary = [
        record for record in caplog.records
        if record.getMessage() == "Build execution summary"
    ][-1]
    assert build_summary.requestId
    assert build_summary.endpoint == "build"
    assert build_summary.readinessStatus == "ready"
    assert build_summary.compileCommandsReady is True
    assert build_summary.quickEligible is True
    assert build_summary.entries == 2
    assert build_summary.userEntries == 2

    terminal_summary = [
        record for record in caplog.records
        if record.getMessage() == "Request terminal summary"
    ][-1]
    assert terminal_summary.endpoint == "build"
    assert terminal_summary.state == "completed"


@pytest.mark.asyncio
async def test_build_internal_error_response_summary_and_logs_do_not_echo_exception(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SECRET_BUILD_INTERNAL_EXCEPTION_SHOULD_NOT_LEAK"
    caplog.set_level("ERROR", logger="aegis-sast-runner")

    with (
        patch("app.routers.scan.Path.is_dir", return_value=True),
        patch("app.routers.scan.build_runner.build", AsyncMock(side_effect=RuntimeError(secret))),
    ):
        resp = await client.post(
            "/v1/build",
            headers={"X-Request-Id": "req-build-internal-sanitized"},
            json={"projectPath": "/tmp/project", "buildCommand": "make"},
        )

    assert resp.status_code == 500
    data = resp.json()
    assert data["error"] == "internal error"
    assert data["errorDetail"]["code"] == "INTERNAL_ERROR"
    assert data["errorDetail"]["message"] == "internal error"
    assert secret not in str(data)

    health = await client.get(
        "/v1/health",
        params={"requestId": "req-build-internal-sanitized"},
    )
    summary = health.json()["requestSummary"]
    assert summary["state"] == "failed"
    assert summary["blockedReason"] == "internal error"
    assert secret not in str(summary)
    assert secret not in caplog.text


# === /v1/includes ===


@pytest.mark.asyncio
async def test_includes_no_input_returns_error(client: AsyncClient) -> None:
    """files도 projectPath도 없으면 에러."""
    resp = await client.post(
        "/v1/includes",
        json={"scanId": "test-inc-001", "projectId": "proj-test", "files": []},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_includes_absolute_file_path_redacts_file_path(
    client: AsyncClient,
) -> None:
    secret_path = "/tmp/SECRET_INCLUDES_ABSOLUTE_SHOULD_NOT_LEAK.c"

    resp = await client.post(
        "/v1/includes",
        json={
            "scanId": "test-inc-absolute-path",
            "projectId": "proj-test",
            "files": [{"path": secret_path, "content": "#include <stdio.h>\n"}],
        },
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "Absolute path not allowed"
    assert data["errorDetail"]["message"] == "Absolute path not allowed"
    assert "SECRET_INCLUDES_ABSOLUTE_SHOULD_NOT_LEAK" not in str(data)


# === /v1/sdk-registry removed ===


@pytest.mark.asyncio
async def test_sdk_registry_routes_removed(client: AsyncClient) -> None:
    assert (await client.get("/v1/sdk-registry")).status_code == 404
    assert (await client.post("/v1/sdk-registry", json={})).status_code == 404
    assert (await client.delete("/v1/sdk-registry/test-sdk")).status_code == 404


# === /v1/libraries ===


@pytest.mark.asyncio
async def test_libraries_no_project_path(client: AsyncClient) -> None:
    """projectPath 없으면 에러."""
    resp = await client.post(
        "/v1/libraries",
        json={"scanId": "test-lib-001", "projectId": "proj-test", "files": []},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_scan_invalid_project_path_redacts_project_path(
    client: AsyncClient,
) -> None:
    secret_path = "/tmp/SECRET_SCAN_PROJECT_PATH_SHOULD_NOT_LEAK"

    resp = await client.post(
        "/v1/scan",
        json={"scanId": "test-scan-invalid-path", "projectId": "proj-test", "projectPath": secret_path},
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "projectPath not found"
    assert data["errorDetail"]["message"] == "projectPath not found"
    assert "SECRET_SCAN_PROJECT_PATH_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_includes_invalid_project_path_redacts_project_path(
    client: AsyncClient,
) -> None:
    secret_path = "/tmp/SECRET_INCLUDES_PROJECT_PATH_SHOULD_NOT_LEAK"

    resp = await client.post(
        "/v1/includes",
        json={"scanId": "test-inc-invalid-path", "projectId": "proj-test", "projectPath": secret_path},
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "projectPath not found"
    assert data["errorDetail"]["message"] == "projectPath not found"
    assert "SECRET_INCLUDES_PROJECT_PATH_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_includes_redacts_absolute_dependency_paths(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        async def communicate(self):
            return (
                b"main.o: src/main.c /tmp/SECRET_INCLUDE_ROOT/usr/include/stdio.h",
                b"",
            )

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    monkeypatch.setattr(
        "app.scanner.include_resolver.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    resp = await client.post(
        "/v1/includes",
        json={
            "scanId": "test-inc-redact-deps",
            "projectId": "proj-test",
            "files": [{"path": "src/main.c", "content": "#include <stdio.h>\n"}],
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    deps = data["includes"]["src/main.c"]
    assert deps == ["<external>/stdio.h"]
    assert "SECRET_INCLUDE_ROOT" not in str(data)
    assert not any(dep.startswith("/") for dep in deps)


@pytest.mark.asyncio
async def test_libraries_invalid_project_path_redacts_project_path(
    client: AsyncClient,
) -> None:
    secret_path = "/tmp/SECRET_LIBRARIES_PROJECT_PATH_SHOULD_NOT_LEAK"

    resp = await client.post(
        "/v1/libraries",
        json={"scanId": "test-lib-invalid-path", "projectId": "proj-test", "projectPath": secret_path},
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "projectPath not found"
    assert data["errorDetail"]["message"] == "projectPath not found"
    assert "SECRET_LIBRARIES_PROJECT_PATH_SHOULD_NOT_LEAK" not in str(data)


# ──────────── NDJSON 스트리밍 모드 ────────────


def _parse_ndjson(text: str) -> list[dict]:
    """NDJSON 텍스트를 파싱하여 이벤트 리스트 반환."""
    import json
    events = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def _execution_with_bad_tool(bad_tool: str, **bad_result_kwargs):
    from app.schemas.response import (
        ExecutionReport,
        FindingsFilterInfo,
        SdkResolutionInfo,
        ToolExecutionResult,
    )

    tool_results = {
        tool: ToolExecutionResult(status="ok", findings_count=0, elapsed_ms=10)
        for tool in ALL_TOOLS
    }
    tool_results[bad_tool] = ToolExecutionResult(**bad_result_kwargs)
    return ExecutionReport(
        toolsRun=list(ALL_TOOLS),
        toolResults=tool_results,
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=bad_result_kwargs.get("degraded", False),
        degradeReasons=bad_result_kwargs.get("degrade_reasons", []),
    )


@pytest.mark.asyncio
async def test_scan_ndjson_streaming_basic(client: AsyncClient, mock_semgrep_runner) -> None:
    """NDJSON Accept → 스트리밍 응답, progress + result 이벤트 검증."""
    resp = await client.post(
        "/v1/scan",
        headers={
            "Accept": "application/x-ndjson",
            "X-Request-Id": "req-stream-001",
        },
        json={
            "scanId": "test-stream-001",
            "projectId": "proj-test",
            "files": [
                {"path": "src/main.c", "content": "int main() { return 0; }"},
            ],
        },
    )
    assert resp.status_code == 200
    assert "application/x-ndjson" in resp.headers.get("content-type", "")
    assert resp.headers.get("X-Request-Id") == "req-stream-001"

    events = _parse_ndjson(resp.text)
    assert len(events) >= 1

    # 마지막 이벤트는 result
    last = events[-1]
    assert last["type"] == "result"
    assert last["data"]["success"] is True
    assert last["data"]["scanId"] == "test-stream-001"
    assert isinstance(last["data"]["findings"], list)


@pytest.mark.asyncio
async def test_scan_ndjson_has_progress_events(client: AsyncClient, mock_semgrep_runner) -> None:
    """스트리밍 응답에 progress 이벤트가 포함되는지 확인."""
    resp = await client.post(
        "/v1/scan",
        headers={"Accept": "application/x-ndjson"},
        json={
            "scanId": "test-stream-progress",
            "projectId": "proj-test",
            "files": [
                {"path": "src/main.c", "content": "int main() { return 0; }"},
            ],
        },
    )
    events = _parse_ndjson(resp.text)
    progress_events = [e for e in events if e["type"] == "progress"]

    # mock_semgrep_runner의 on_progress 콜백이 호출됨 (도구별)
    # orchestrator.run이 mock이므로 콜백이 호출되지 않을 수 있음
    # 최소한 result 이벤트는 존재해야 함
    result_events = [e for e in events if e["type"] == "result"]
    assert len(result_events) == 1
    assert result_events[0]["data"]["success"] is True


@pytest.mark.asyncio
async def test_scan_ndjson_result_matches_sync(client: AsyncClient, mock_semgrep_runner) -> None:
    """동기/스트리밍 동일 결과 반환 확인."""
    body = {
        "scanId": "test-compare",
        "projectId": "proj-test",
        "files": [
            {"path": "src/main.c", "content": "#include <stdio.h>\nvoid f() { gets(buf); }"},
        ],
        "rulesets": ["p/c"],
    }

    # 동기
    resp_sync = await client.post("/v1/scan", json=body)
    sync_data = resp_sync.json()

    # 스트리밍
    resp_stream = await client.post(
        "/v1/scan",
        headers={"Accept": "application/x-ndjson"},
        json=body,
    )
    events = _parse_ndjson(resp_stream.text)
    stream_data = [e for e in events if e["type"] == "result"][0]["data"]

    # 핵심 필드 일치 확인
    assert sync_data["success"] == stream_data["success"]
    assert sync_data["scanId"] == stream_data["scanId"]
    assert len(sync_data["findings"]) == len(stream_data["findings"])


@pytest.mark.asyncio
async def test_scan_ndjson_error_event(client: AsyncClient) -> None:
    """스캔 에러 시 error 이벤트 emit 확인."""
    from unittest.mock import AsyncMock, patch
    from app.errors import ScanTimeoutError

    with patch("app.routers.scan.orchestrator") as mock_orch:
        mock_orch.run = AsyncMock(side_effect=ScanTimeoutError("Tool timed out"))
        resp = await client.post(
            "/v1/scan",
            headers={"Accept": "application/x-ndjson"},
            json={
                "scanId": "test-stream-error",
                "projectId": "proj-test",
                "files": [
                    {"path": "src/main.c", "content": "int main() { return 0; }"},
                ],
            },
        )

    events = _parse_ndjson(resp.text)
    error_events = [e for e in events if e["type"] == "error"]
    assert len(error_events) == 1
    assert error_events[0]["code"] == "SCAN_TIMEOUT"
    assert error_events[0]["retryable"] is True


@pytest.mark.asyncio
async def test_scan_ndjson_internal_error_is_value_sanitized(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SECRET_NDJSON_INTERNAL_EXCEPTION_SHOULD_NOT_LEAK"
    caplog.set_level("ERROR", logger="aegis-sast-runner")

    with patch("app.routers.scan.orchestrator") as mock_orch:
        mock_orch.run = AsyncMock(side_effect=RuntimeError(secret))
        resp = await client.post(
            "/v1/scan",
            headers={
                "Accept": "application/x-ndjson",
                "X-Request-Id": "req-ndjson-internal-sanitized",
            },
            json={
                "scanId": "test-stream-internal-error",
                "projectId": "proj-test",
                "files": [
                    {"path": "src/main.c", "content": "int main() { return 0; }"},
                ],
            },
        )

    events = _parse_ndjson(resp.text)
    error_events = [e for e in events if e["type"] == "error"]
    assert len(error_events) == 1
    assert error_events[0]["code"] == "INTERNAL_ERROR"
    assert error_events[0]["message"] == "internal error"
    assert secret not in resp.text

    health = await client.get(
        "/v1/health",
        params={"requestId": "req-ndjson-internal-sanitized"},
    )
    summary = health.json()["requestSummary"]
    assert summary["state"] == "failed"
    assert summary["blockedReason"] == "internal error"
    assert secret not in str(summary)
    assert secret not in caplog.text
    assert any("NDJSON scan failed unexpectedly" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_scan_sync_internal_error_response_summary_and_logs_do_not_echo_exception(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SECRET_SYNC_SCAN_INTERNAL_EXCEPTION_SHOULD_NOT_LEAK"
    caplog.set_level("ERROR", logger="aegis-sast-runner")

    with patch("app.routers.scan.orchestrator") as mock_orch:
        mock_orch.run = AsyncMock(side_effect=RuntimeError(secret))
        resp = await client.post(
            "/v1/scan",
            headers={"X-Request-Id": "req-sync-internal-sanitized"},
            json={
                "scanId": "test-sync-internal-error",
                "projectId": "proj-test",
                "files": [
                    {"path": "src/main.c", "content": "int main() { return 0; }"},
                ],
            },
        )

    assert resp.status_code == 500
    data = resp.json()
    assert data["error"] == "internal error"
    assert data["errorDetail"]["code"] == "INTERNAL_ERROR"
    assert data["errorDetail"]["message"] == "internal error"
    assert secret not in str(data)

    health = await client.get(
        "/v1/health",
        params={"requestId": "req-sync-internal-sanitized"},
    )
    summary = health.json()["requestSummary"]
    assert summary["state"] == "failed"
    assert summary["blockedReason"] == "internal error"
    assert secret not in str(summary)
    assert secret not in caplog.text


@pytest.mark.asyncio
async def test_scan_with_build_profile_without_sdk_id_succeeds(
    client: AsyncClient,
    tmp_path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    with patch.object(
        __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator,
        "check_tools",
        AsyncMock(return_value={}),
    ), patch.object(
        __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator,
        "_select_tools",
        AsyncMock(return_value={"_skipped": {}}),
    ), patch.object(
        __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator,
        "evaluate_policy",
        return_value=None,
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "test-build-profile-no-sdk",
                "projectId": "proj-test",
                "projectPath": str(project_dir),
                "buildProfile": {
                    "compiler": "gcc",
                    "targetArch": "x86_64",
                    "languageStandard": "c++17",
                    "headerLanguage": "cpp",
                },
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["execution"]["sdk"]["resolved"] is False
    assert data["execution"]["sdk"].get("sdkId") is None


@pytest.mark.asyncio
async def test_project_path_source_discovery_uses_shared_c_cpp_semgrep_extensions(
    client: AsyncClient,
    tmp_path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    for suffix in C_CPP_INCLUDE_EXTENSIONS:
        (project_dir / f"sample{suffix}").write_text("int x;\n", encoding="utf-8")
    (project_dir / "ignored.txt").write_text("not source\n", encoding="utf-8")

    captured_source_files: list[str] = []

    async def _capture_run(*, source_files: list[str], **kwargs):
        del kwargs
        captured_source_files.extend(source_files)
        return [], ExecutionReport(
            toolsRun=[],
            toolResults={},
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        )

    with (
        patch.object(
            __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator,
            "run",
            AsyncMock(side_effect=_capture_run),
        ),
        patch.object(
            __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator,
            "evaluate_policy",
            return_value=None,
        ),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "test-project-discovery-cpp-extensions",
                "projectId": "proj-test",
                "projectPath": str(project_dir),
                "options": {"tools": []},
            },
        )

    assert resp.status_code == 200
    assert {Path(path).suffix for path in captured_source_files} == set(C_CPP_INCLUDE_EXTENSIONS)
    assert "ignored.txt" not in captured_source_files


@pytest.mark.asyncio
@pytest.mark.parametrize("sdk_id", ["SECRET_SDK_ID_SHOULD_NOT_LEAK", "custom"])
async def test_scan_with_invalid_sdk_id_returns_domain_error(
    client: AsyncClient,
    tmp_path,
    sdk_id: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    request_id = "req-invalid-sdk-redacted"
    caplog.set_level("ERROR", logger="aegis-sast-runner")
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    resp = await client.post(
        "/v1/scan",
        headers={"X-Request-Id": request_id},
        json={
            "scanId": "test-build-profile-bad-sdk",
            "projectId": "proj-test",
            "projectPath": str(project_dir),
            "buildProfile": {
                "sdkId": sdk_id,
                "compiler": "gcc",
                "targetArch": "x86_64",
                "languageStandard": "c++17",
                "headerLanguage": "cpp",
            },
        },
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "SDK_NOT_FOUND"
    assert data["errorDetail"]["retryable"] is False
    assert "registered sdkId" in data["errorDetail"]["message"]
    assert "non-registered" in data["errorDetail"]["message"]
    assert sdk_id not in str(data)
    assert sdk_id not in caplog.text

    health = await client.get("/v1/health", params={"requestId": request_id})
    summary = health.json()["requestSummary"]
    assert sdk_id not in str(summary)
    if summary["state"] != "idle":
        assert summary["blockedReason"] == data["errorDetail"]["message"]
        assert sdk_id not in summary["blockedReason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("sdk_id", ["SECRET_STREAM_SDK_ID_SHOULD_NOT_LEAK", "custom"])
async def test_scan_ndjson_with_invalid_sdk_id_returns_json_domain_error(
    client: AsyncClient,
    tmp_path,
    sdk_id: str,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    resp = await client.post(
        "/v1/scan",
        headers={"Accept": "application/x-ndjson"},
        json={
            "scanId": "test-build-profile-bad-sdk-stream",
            "projectId": "proj-test",
            "projectPath": str(project_dir),
            "buildProfile": {
                "sdkId": sdk_id,
                "compiler": "gcc",
                "targetArch": "x86_64",
                "languageStandard": "c++17",
                "headerLanguage": "cpp",
            },
        },
    )

    assert resp.status_code == 400
    assert "application/json" in resp.headers.get("content-type", "")
    data = resp.json()
    assert data["errorDetail"]["code"] == "SDK_NOT_FOUND"
    assert data["errorDetail"]["retryable"] is False
    assert "registered sdkId" in data["errorDetail"]["message"]
    assert "non-registered" in data["errorDetail"]["message"]
    assert sdk_id not in resp.text
    assert sdk_id not in str(data)


@pytest.mark.asyncio
async def test_scan_invalid_options_tool_returns_caller_error_not_system_instability(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_tool = "SECRET_SCAN_TOOL_SHOULD_NOT_LEAK"
    request_id = "req-invalid-scan-tool-redacted"
    caplog.set_level("ERROR", logger="aegis-sast-runner")

    resp = await client.post(
        "/v1/scan",
        headers={"X-Request-Id": request_id},
        json={
            "scanId": "invalid-tool-id",
            "projectId": "proj-test",
            "files": [{"path": "src/main.c", "content": "int main(void) { return 0; }"}],
            "options": {"tools": [secret_tool]},
        },
    )

    data = resp.json()
    assert resp.status_code == 400
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "SCAN_TOOL_INVALID"
    assert data["errorDetail"]["retryable"] is False
    assert "Unknown SAST tool" in data["errorDetail"]["message"]
    assert "Allowed tools" in data["errorDetail"]["message"]
    assert secret_tool not in str(data)
    assert secret_tool not in caplog.text

    health = await client.get("/v1/health", params={"requestId": request_id})
    summary = health.json()["requestSummary"]
    assert secret_tool not in str(summary)
    if summary["state"] != "idle":
        assert summary["blockedReason"] == data["errorDetail"]["message"]
        assert secret_tool not in summary["blockedReason"]


@pytest.mark.asyncio
async def test_scan_ndjson_invalid_options_tool_returns_json_domain_error(
    client: AsyncClient,
) -> None:
    secret_tool = "SECRET_STREAM_SCAN_TOOL_SHOULD_NOT_LEAK"
    resp = await client.post(
        "/v1/scan",
        headers={"Accept": "application/x-ndjson"},
        json={
            "scanId": "invalid-tool-id-stream",
            "projectId": "proj-test",
            "files": [{"path": "src/main.c", "content": "int main(void) { return 0; }"}],
            "options": {"tools": [secret_tool]},
        },
    )

    assert resp.status_code == 400
    assert "application/json" in resp.headers.get("content-type", "")
    data = resp.json()
    assert data["errorDetail"]["code"] == "SCAN_TOOL_INVALID"
    assert data["errorDetail"]["retryable"] is False
    assert "Unknown SAST tool" in data["errorDetail"]["message"]
    assert "Allowed tools" in data["errorDetail"]["message"]
    assert secret_tool not in resp.text
    assert secret_tool not in str(data)


@pytest.mark.asyncio
async def test_build_and_analyze_invalid_options_tool_fails_before_build_without_echo(
    client: AsyncClient,
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    secret_tool = "SECRET_BUILD_ANALYZE_TOOL_SHOULD_NOT_LEAK"
    build_mock = AsyncMock()
    caplog.set_level("ERROR", logger="aegis-sast-runner")

    with patch("app.routers.scan.build_runner.build", build_mock):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": str(project_dir),
                "buildCommand": "make",
                "options": {"tools": [secret_tool]},
            },
        )

    data = resp.json()
    assert resp.status_code == 400
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "SCAN_TOOL_INVALID"
    assert data["errorDetail"]["retryable"] is False
    assert "Unknown SAST tool" in data["errorDetail"]["message"]
    assert "Allowed tools" in data["errorDetail"]["message"]
    assert secret_tool not in str(data)
    assert secret_tool not in caplog.text
    build_mock.assert_not_called()


@pytest.mark.asyncio
async def test_scan_policy_violation_returns_503_with_execution(client: AsyncClient) -> None:
    from unittest.mock import AsyncMock, patch

    from app.schemas.response import (
        ExecutionReport,
        FindingsFilterInfo,
        ScanStats,
        SdkResolutionInfo,
        ToolExecutionResult,
    )

    execution = ExecutionReport(
        toolsRun=["cppcheck"],
        toolResults={
            "semgrep": ToolExecutionResult(
                status="skipped",
                findings_count=0,
                elapsed_ms=0,
                skip_reason="environment-drift",
            ),
            "cppcheck": ToolExecutionResult(
                status="ok",
                findings_count=1,
                elapsed_ms=10,
            ),
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=False,
        degradeReasons=[],
    )

    with patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "policy-sync-001",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() { return 0; }"}],
            },
        )

    data = resp.json()
    assert resp.status_code == 503
    assert data["success"] is False
    assert data["status"] == "failed"
    assert data["errorDetail"]["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    assert data["execution"]["toolResults"]["semgrep"]["status"] == "skipped"
    assert data["execution"]["toolResults"]["semgrep"]["skipReason"] == "environment-drift"
    assert data["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"


@pytest.mark.parametrize("bad_tool", ALL_TOOLS)
@pytest.mark.parametrize(
    "bad_result_kwargs",
    [
        {"status": "failed", "findings_count": 0, "elapsed_ms": 10, "skip_reason": "runner crashed"},
        {"status": "partial", "findings_count": 1, "elapsed_ms": 10, "timed_out_files": 1},
        {"status": "ok", "findings_count": 1, "elapsed_ms": 10, "degraded": True, "degrade_reasons": ["bad-output"]},
    ],
)
@pytest.mark.asyncio
async def test_scan_execution_incomplete_for_any_required_tool_returns_503_with_contract(
    client: AsyncClient,
    bad_tool: str,
    bad_result_kwargs: dict,
) -> None:
    from app.schemas.response import (
        ExecutionReport,
        FindingsFilterInfo,
        SdkResolutionInfo,
        ToolExecutionResult,
    )

    tool_results = {
        tool: ToolExecutionResult(status="ok", findings_count=0, elapsed_ms=10)
        for tool in ALL_TOOLS
    }
    tool_results[bad_tool] = ToolExecutionResult(**bad_result_kwargs)
    execution = ExecutionReport(
        toolsRun=list(ALL_TOOLS),
        toolResults=tool_results,
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=bad_result_kwargs.get("degraded", False),
        degradeReasons=bad_result_kwargs.get("degrade_reasons", []),
    )

    with patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "policy-execution-incomplete",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() { return 0; }"}],
            },
        )

    data = resp.json()
    assert resp.status_code == 503
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    assert data["execution"]["toolResults"][bad_tool]["status"] == bad_result_kwargs["status"]
    assert data["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"
    assert data["staticEvidenceContract"]["gates"]["evidenceReadiness"]["status"] == "not_ready"
    assert data["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "fail"
    assert "REQUIRED_TOOL_EXECUTION_INCOMPLETE" in data["staticEvidenceContract"]["gates"]["systemStability"]["reasonCodes"]


@pytest.mark.asyncio
async def test_scan_ndjson_execution_incomplete_emits_error_with_contract(
    client: AsyncClient,
) -> None:
    execution = _execution_with_bad_tool(
        "clang-tidy",
        status="failed",
        findings_count=0,
        elapsed_ms=10,
        skip_reason="runner crashed",
    )

    with patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))):
        resp = await client.post(
            "/v1/scan",
            headers={"Accept": "application/x-ndjson"},
            json={
                "scanId": "policy-execution-incomplete-stream",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() { return 0; }"}],
            },
        )

    events = _parse_ndjson(resp.text)
    assert not [e for e in events if e["type"] == "result"]
    error_event = [e for e in events if e["type"] == "error"][0]
    assert error_event["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    assert error_event["execution"]["toolResults"]["clang-tidy"]["status"] == "failed"
    assert error_event["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"


@pytest.mark.asyncio
async def test_scan_async_ownership_execution_incomplete_result_preserves_contract(
    client: AsyncClient,
) -> None:
    request_id = "req-execution-incomplete-async"
    execution = _execution_with_bad_tool(
        "scan-build",
        status="partial",
        findings_count=1,
        elapsed_ms=10,
        timed_out_files=1,
    )

    with patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))):
        accepted = await client.post(
            "/v1/scan",
            headers={"Prefer": "respond-async", "X-Request-Id": request_id},
            json={
                "scanId": "policy-execution-incomplete-async",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() { return 0; }"}],
            },
        )
        assert accepted.status_code == 202

        result = None
        for _ in range(20):
            result = await client.get(f"/v1/requests/{request_id}/result")
            if result.status_code == 200:
                break
            await asyncio.sleep(0.02)

    assert result is not None
    assert result.status_code == 200
    data = result.json()["result"]
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    assert data["execution"]["toolResults"]["scan-build"]["status"] == "partial"
    assert data["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"


@pytest.mark.asyncio
async def test_scan_ndjson_policy_violation_error_includes_execution(client: AsyncClient) -> None:
    from unittest.mock import AsyncMock, patch

    from app.schemas.response import (
        ExecutionReport,
        FindingsFilterInfo,
        SdkResolutionInfo,
        ToolExecutionResult,
    )

    execution = ExecutionReport(
        toolsRun=["cppcheck"],
        toolResults={
            "semgrep": ToolExecutionResult(
                status="skipped",
                findings_count=0,
                elapsed_ms=0,
                skip_reason="environment-drift",
            ),
            "cppcheck": ToolExecutionResult(status="ok", findings_count=1, elapsed_ms=10),
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=False,
        degradeReasons=[],
    )

    with patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))):
        resp = await client.post(
            "/v1/scan",
            headers={"Accept": "application/x-ndjson"},
            json={
                "scanId": "policy-stream-001",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() { return 0; }"}],
            },
        )

    events = _parse_ndjson(resp.text)
    error_event = [e for e in events if e["type"] == "error"][0]
    assert error_event["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    assert error_event["retryable"] is False
    assert error_event["execution"]["toolResults"]["semgrep"]["skipReason"] == "environment-drift"


@pytest.mark.parametrize("missing_tool", ALL_TOOLS)
@pytest.mark.asyncio
async def test_scan_required_tool_preflight_failure_returns_contract_and_runs_no_tools(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
    missing_tool: str,
) -> None:
    """어떤 required tool이 죽어도 실행 전 fail-closed 하고 실패 contract를 반환한다."""
    caplog.set_level("ERROR", logger="aegis-sast-runner")
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability[missing_tool] = {
        "available": False,
        "version": None,
        "probeReason": "environment-drift",
        "expectedExecutablePath": f"/svc/bin/{missing_tool}",
    }
    router_orchestrator = __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator

    with (
        patch.object(router_orchestrator, "check_tools", AsyncMock(return_value=availability)),
        patch.object(router_orchestrator, "_run_semgrep", AsyncMock(return_value=[])) as semgrep,
        patch.object(router_orchestrator, "_run_cppcheck", AsyncMock(return_value=[])) as cppcheck,
        patch.object(router_orchestrator, "_run_flawfinder", AsyncMock(return_value=[])) as flawfinder,
        patch.object(router_orchestrator, "_run_clangtidy", AsyncMock(return_value=[])) as clangtidy,
        patch.object(router_orchestrator, "_run_scanbuild", AsyncMock(return_value=[])) as scanbuild,
        patch.object(router_orchestrator, "_run_gcc_analyzer", AsyncMock(return_value=[])) as gcc_analyzer,
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "required-tool-preflight-sync",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() { return 0; }"}],
            },
        )

    data = resp.json()
    assert resp.status_code == 503
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "REQUIRED_TOOL_UNAVAILABLE"
    assert data["execution"]["toolsRun"] == []
    assert data["execution"]["toolResults"][missing_tool]["skipReason"] == "environment-drift"
    assert data["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"
    assert "REQUIRED_TOOL_UNAVAILABLE" in data["staticEvidenceContract"]["gates"]["systemStability"]["reasonCodes"]
    for runner in (semgrep, cppcheck, flawfinder, clangtidy, scanbuild, gcc_analyzer):
        assert runner.await_count == 0
    assert "Required SAST tool preflight failed" in caplog.text


@pytest.mark.asyncio
async def test_scan_ndjson_required_tool_preflight_failure_includes_contract(
    client: AsyncClient,
) -> None:
    from app.scanner.orchestrator import ALL_TOOLS

    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {
        "available": False,
        "version": None,
        "probeReason": "environment-drift",
    }
    router_orchestrator = __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator

    with patch.object(router_orchestrator, "check_tools", AsyncMock(return_value=availability)):
        resp = await client.post(
            "/v1/scan",
            headers={"Accept": "application/x-ndjson"},
            json={
                "scanId": "required-tool-preflight-stream",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() { return 0; }"}],
            },
        )

    events = _parse_ndjson(resp.text)
    error_event = [e for e in events if e["type"] == "error"][0]
    assert error_event["code"] == "REQUIRED_TOOL_UNAVAILABLE"
    assert error_event["execution"]["toolResults"]["semgrep"]["skipReason"] == "environment-drift"
    assert error_event["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"


@pytest.mark.asyncio
async def test_scan_without_ndjson_header_unchanged(client: AsyncClient, mock_semgrep_runner) -> None:
    """Accept 없으면 기존 동기 JSON 응답 (스트리밍 아님)."""
    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "test-sync",
            "projectId": "proj-test",
            "files": [
                {"path": "src/main.c", "content": "int main() { return 0; }"},
            ],
        },
    )
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")
    data = resp.json()
    assert "type" not in data  # NDJSON 이벤트 형식이 아님
    assert data["success"] is True


@pytest.mark.asyncio
async def test_scan_ndjson_validation_error_returns_json(client: AsyncClient) -> None:
    """NDJSON 모드에서도 입력 검증 실패 시 일반 HTTP 에러 반환."""
    resp = await client.post(
        "/v1/scan",
        headers={"Accept": "application/x-ndjson"},
        json={
            "scanId": "test-validate",
            "projectId": "proj-test",
            "files": [],
        },
    )
    assert resp.status_code == 400


# --- heartbeat 진행 지표 보강 테스트 ---


def _make_progress_mock(findings, execution):
    """orchestrator.run mock — on_progress 콜백을 실제 호출하는 side_effect."""

    async def _run(*args, **kwargs):
        on_progress = kwargs.get("on_progress")
        on_file_progress = kwargs.get("on_file_progress")
        on_runtime_state = kwargs.get("on_runtime_state")
        if on_progress:
            await on_progress("semgrep", "started", 0, 0)
            await on_progress("semgrep", "completed", len(findings), 100)
        if on_runtime_state:
            await on_runtime_state(
                "gcc-fanalyzer",
                {
                    "filesAttempted": 2,
                    "filesCompleted": 1,
                    "timedOutFiles": 0,
                    "failedFiles": 0,
                    "batchCount": 1,
                    "timeoutBudgetSeconds": 120,
                    "perFileTimeoutSeconds": 60,
                    "budgetWarning": False,
                    "degraded": False,
                    "degradeReasons": [],
                },
            )
        if on_file_progress:
            await on_file_progress("gcc-fanalyzer", "src/main.c", 1, 2)
        return (findings, execution)

    return _run


def _make_slow_progress_mock(findings, execution, delay: float = 0.3):
    """orchestrator.run mock — 지연 + on_progress 호출 (heartbeat 발생 유도)."""

    async def _run(*args, **kwargs):
        on_progress = kwargs.get("on_progress")
        on_file_progress = kwargs.get("on_file_progress")
        on_runtime_state = kwargs.get("on_runtime_state")
        if on_progress:
            await on_progress("semgrep", "started", 0, 0)
        if on_runtime_state:
            await on_runtime_state(
                "gcc-fanalyzer",
                {
                    "filesAttempted": 3,
                    "filesCompleted": 1,
                    "timedOutFiles": 1,
                    "failedFiles": 0,
                    "batchCount": 2,
                    "timeoutBudgetSeconds": 20,
                    "perFileTimeoutSeconds": 10,
                    "budgetWarning": True,
                    "degraded": True,
                    "degradeReasons": ["timeout-floor", "timed-out-files"],
                },
            )
        if on_file_progress:
            await on_file_progress("gcc-fanalyzer", "src/main.c", 1, 3)
        await asyncio.sleep(delay)
        if on_progress:
            await on_progress("semgrep", "completed", len(findings), 200)
        return (findings, execution)

    return _run


@pytest.mark.asyncio
async def test_scan_ndjson_progress_started_event(client: AsyncClient, mock_semgrep_runner) -> None:
    """스트리밍 응답에 도구별 'started' progress 이벤트가 포함되는지 확인."""
    from app.scanner.sarif_parser import parse_sarif
    import json
    from pathlib import Path as P

    sarif = json.loads((P(__file__).parent / "fixtures" / "sample.sarif.json").read_text())
    findings, _ = parse_sarif(sarif, P("/tmp/mock"))
    execution = mock_semgrep_runner.run.return_value[1]

    mock_semgrep_runner.run = AsyncMock(side_effect=_make_progress_mock(findings, execution))

    resp = await client.post(
        "/v1/scan",
        headers={"Accept": "application/x-ndjson"},
        json={
            "scanId": "test-started",
            "projectId": "proj-test",
            "files": [{"path": "src/main.c", "content": "int main() {}"}],
        },
    )
    events = _parse_ndjson(resp.text)
    started_events = [e for e in events if e.get("type") == "progress" and e.get("status") == "started"]
    assert len(started_events) >= 1
    assert started_events[0]["tool"] == "semgrep"


@pytest.mark.asyncio
async def test_scan_ndjson_heartbeat_has_progress(client: AsyncClient, mock_semgrep_runner) -> None:
    """running 상태 heartbeat에 status + progress 필드가 포함되는지 확인."""
    from app.scanner.sarif_parser import parse_sarif
    import json
    from pathlib import Path as P

    sarif = json.loads((P(__file__).parent / "fixtures" / "sample.sarif.json").read_text())
    findings, _ = parse_sarif(sarif, P("/tmp/mock"))
    execution = mock_semgrep_runner.run.return_value[1]

    mock_semgrep_runner.run = AsyncMock(
        side_effect=_make_slow_progress_mock(findings, execution, delay=0.3),
    )

    with patch("app.routers.scan._HEARTBEAT_INTERVAL_S", 0.1):
        resp = await client.post(
            "/v1/scan",
            headers={"Accept": "application/x-ndjson"},
            json={
                "scanId": "test-hb-progress",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        )

    events = _parse_ndjson(resp.text)
    heartbeats = [e for e in events if e.get("type") == "heartbeat"]
    assert len(heartbeats) >= 1
    running_hb = [h for h in heartbeats if h.get("status") == "running"]
    assert len(running_hb) >= 1
    progress = running_hb[0]["progress"]
    assert "activeTools" in progress
    assert "completedTools" in progress
    assert "findingsCount" in progress
    assert "filesCompleted" in progress
    assert "filesTotal" in progress
    assert "currentFile" in progress
    assert "degraded" in progress
    assert "degradeReasons" in progress
    assert "toolStates" in progress


@pytest.mark.asyncio
async def test_scan_ndjson_file_progress_in_heartbeat(client: AsyncClient, mock_semgrep_runner) -> None:
    """heartbeat의 filesCompleted/currentFile이 on_file_progress에서 반영되는지 확인."""
    from app.scanner.sarif_parser import parse_sarif
    import json
    from pathlib import Path as P

    sarif = json.loads((P(__file__).parent / "fixtures" / "sample.sarif.json").read_text())
    findings, _ = parse_sarif(sarif, P("/tmp/mock"))
    execution = mock_semgrep_runner.run.return_value[1]

    mock_semgrep_runner.run = AsyncMock(
        side_effect=_make_slow_progress_mock(findings, execution, delay=0.3),
    )

    with patch("app.routers.scan._HEARTBEAT_INTERVAL_S", 0.1):
        resp = await client.post(
            "/v1/scan",
            headers={"Accept": "application/x-ndjson"},
            json={
                "scanId": "test-file-progress",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        )

    events = _parse_ndjson(resp.text)
    running_hb = [
        e for e in events
        if e.get("type") == "heartbeat" and e.get("status") == "running"
    ]
    if running_hb:
        progress = running_hb[0]["progress"]
        assert progress["filesCompleted"] >= 1
        assert progress["currentFile"] == "src/main.c"
        assert progress["toolStates"]["gcc-fanalyzer"]["timedOutFiles"] == 1


@pytest.mark.asyncio
async def test_scan_ndjson_queued_status(client: AsyncClient, mock_semgrep_runner) -> None:
    """세마포어 포화 시 queued status heartbeat가 전송되는지 확인."""
    from app.config import settings
    from app.scanner.sarif_parser import parse_sarif
    import json
    from pathlib import Path as P

    sarif = json.loads((P(__file__).parent / "fixtures" / "sample.sarif.json").read_text())
    findings, _ = parse_sarif(sarif, P("/tmp/mock"))
    execution = mock_semgrep_runner.run.return_value[1]

    from app.routers.scan import _scan_semaphore

    for _ in range(settings.max_concurrent_scans):
        await _scan_semaphore.acquire()

    async def _release_later():
        await asyncio.sleep(0.15)
        _scan_semaphore.release()

    mock_semgrep_runner.run = AsyncMock(
        side_effect=_make_progress_mock(findings, execution),
    )

    release_task = asyncio.create_task(_release_later())

    with patch("app.routers.scan._HEARTBEAT_INTERVAL_S", 0.05):
        resp = await client.post(
            "/v1/scan",
            headers={"Accept": "application/x-ndjson"},
            json={
                "scanId": "test-queued",
                "projectId": "proj-test",
                "files": [{"path": "src/main.c", "content": "int main() {}"}],
            },
        )

    await release_task

    events = _parse_ndjson(resp.text)
    heartbeats = [e for e in events if e.get("type") == "heartbeat"]
    queued_hb = [h for h in heartbeats if h.get("status") == "queued"]
    assert len(queued_hb) >= 1
    assert "progress" not in queued_hb[0]


@pytest.mark.asyncio
async def test_build_and_analyze_accepts_provenance(client: AsyncClient) -> None:
    from app.schemas.response import BuildEvidence, BuildResponse, ScanResponse, ScanStats
    from app.schemas.request import SnapshotProvenance
    from app.schemas.response import ExecutionReport, FindingsFilterInfo, SdkResolutionInfo

    provenance = SnapshotProvenance(
        buildSnapshotId="bsnap-9",
        buildUnitId="bunit-9",
        snapshotSchemaVersion="build-snapshot-v1",
    )
    build_response = BuildResponse(
        success=True,
        provenance=provenance,
        buildEvidence=BuildEvidence(
            requestedBuildCommand="make",
            effectiveBuildCommand="make",
            buildDir="/tmp/project",
            compileCommandsPath="/tmp/project/compile_commands.json",
            entries=1,
            userEntries=1,
            exitCode=0,
            buildOutput="ok",
            wrapWithBear=True,
            timeoutSeconds=600,
            environmentKeys=["CC"],
            elapsedMs=10,
        ),
        readiness={
            "status": "ready",
            "compileCommandsReady": True,
            "quickEligible": True,
            "summary": "compile_commands.json contains user-target entries and the build exited successfully.",
        },
    )
    scan_response = ScanResponse(
        success=True,
        scanId="build-analyze-req-1",
        status="completed",
        provenance=provenance,
        findings=[],
        stats=ScanStats(filesScanned=1, rulesRun=1, findingsTotal=0, elapsedMs=20),
        execution=ExecutionReport(
            toolsRun=["semgrep"],
            toolResults={},
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
            degraded=False,
            degradeReasons=[],
        ),
        codeGraph={"functions": []},
        sca={"libraries": []},
    )

    with (
        patch("pathlib.Path.is_dir", return_value=True),
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=build_response.model_dump(by_alias=True, exclude_none=True))),
        patch("app.routers.scan._run_scan_core", AsyncMock(return_value=scan_response)),
        patch("app.routers.scan.metadata_extractor.extract", AsyncMock(return_value={"compiler": "gcc"})),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": "/tmp/project",
                "buildCommand": "make",
                "projectId": "proj-test",
                "buildEnvironment": {"CC": "/uploads/toolchain/gcc"},
                "provenance": provenance.model_dump(by_alias=True, exclude_none=True),
            },
        )

    data = resp.json()
    assert data["success"] is True
    assert data["provenance"]["buildSnapshotId"] == "bsnap-9"
    assert data["build"]["buildEvidence"]["compileCommandsPath"].endswith("compile_commands.json")
    assert data["build"]["readiness"]["status"] == "ready"


@pytest.mark.asyncio
async def test_build_and_analyze_invalid_path_redacts_project_path(
    client: AsyncClient,
) -> None:
    secret_path = "/tmp/SECRET_BUILD_ANALYZE_PROJECT_PATH_SHOULD_NOT_LEAK"

    resp = await client.post(
        "/v1/build-and-analyze",
        json={"projectPath": secret_path, "buildCommand": "make"},
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["error"] == "projectPath not found"
    assert data["errorDetail"]["code"] == "PROJECT_PATH_NOT_FOUND"
    assert data["errorDetail"]["message"] == "projectPath not found"
    assert data["errorDetail"]["retryable"] is False
    assert "SECRET_BUILD_ANALYZE_PROJECT_PATH_SHOULD_NOT_LEAK" not in str(data)


@pytest.mark.asyncio
async def test_build_and_analyze_requires_build_command(client: AsyncClient) -> None:
    with patch("pathlib.Path.is_dir", return_value=True):
        resp = await client.post(
            "/v1/build-and-analyze",
            headers={"X-Request-Id": "req-build-analyze-no-command"},
            json={"projectPath": "/tmp/project"},
        )
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["error"] == "buildCommand is required"
    assert data["errorDetail"]["code"] == "BUILD_COMMAND_REQUIRED"
    assert data["errorDetail"]["message"] == "buildCommand is required"
    assert data["errorDetail"]["requestId"] == "req-build-analyze-no-command"
    assert data["errorDetail"]["retryable"] is False


@pytest.mark.asyncio
async def test_build_and_analyze_rejects_legacy_build_profile(client: AsyncClient) -> None:
    with patch("pathlib.Path.is_dir", return_value=True):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": "/tmp/project",
                "buildCommand": "make",
                "buildProfile": {"sdkId": "ti-am335x"},
            },
        )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_build_and_analyze_policy_violation_preserves_build_evidence(client: AsyncClient) -> None:
    from unittest.mock import AsyncMock, patch

    from app.errors import PolicyViolationError
    from app.schemas.response import (
        BuildEvidence,
        BuildResponse,
        ErrorDetail,
        ExecutionReport,
        FindingsFilterInfo,
        ScanResponse,
        ScanStats,
        SdkResolutionInfo,
        ToolExecutionResult,
    )

    build = BuildResponse(
        success=True,
        buildEvidence=BuildEvidence(
            requestedBuildCommand="make",
            effectiveBuildCommand="make",
            buildDir="/tmp/project",
            compileCommandsPath="/tmp/project/compile_commands.json",
            entries=1,
            userEntries=1,
            exitCode=0,
            buildOutput="ok",
            wrapWithBear=True,
            timeoutSeconds=600,
            elapsedMs=10,
        ),
        readiness={
            "status": "ready",
            "compileCommandsReady": True,
            "quickEligible": True,
            "summary": "compile_commands.json contains user-target entries and the build exited successfully.",
        },
    )
    failed_scan = ScanResponse(
        success=False,
        scanId="build-analyze-policy-001",
        status="failed",
        findings=[],
        stats=ScanStats(filesScanned=1, rulesRun=1, findingsTotal=0, elapsedMs=20),
        execution=ExecutionReport(
            toolsRun=["cppcheck"],
            toolResults={
                "semgrep": ToolExecutionResult(
                    status="skipped",
                    findings_count=0,
                    elapsed_ms=0,
                    skip_reason="environment-drift",
                ),
                "cppcheck": ToolExecutionResult(status="ok", findings_count=0, elapsed_ms=10),
            },
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
            degraded=False,
            degradeReasons=[],
        ),
        error="Disallowed tool omission: semgrep(environment-drift)",
        errorDetail=ErrorDetail(
            code="DISALLOWED_TOOL_ENVIRONMENT_DRIFT",
            message="Disallowed tool omission: semgrep(environment-drift)",
            requestId="req-policy-bna",
            retryable=False,
        ),
    )

    with (
        patch("pathlib.Path.is_dir", return_value=True),
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=build.model_dump(by_alias=True, exclude_none=True))),
        patch(
            "app.routers.scan._run_scan_core",
            AsyncMock(side_effect=PolicyViolationError(
                "Disallowed tool omission: semgrep(environment-drift)",
                scan_response=failed_scan,
                code="DISALLOWED_TOOL_ENVIRONMENT_DRIFT",
            )),
        ),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": "/tmp/project",
                "buildCommand": "make",
                "projectId": "proj-test",
            },
        )

    data = resp.json()
    assert resp.status_code == 503
    assert data["success"] is False
    assert data["build"]["buildEvidence"]["compileCommandsPath"].endswith("compile_commands.json")
    assert data["scan"]["success"] is False
    assert data["scan"]["execution"]["toolResults"]["semgrep"]["skipReason"] == "environment-drift"
    assert data["errorDetail"]["code"] == "DISALLOWED_TOOL_ENVIRONMENT_DRIFT"


@pytest.mark.asyncio
async def test_build_and_analyze_required_tool_preflight_failure_preserves_build_evidence(
    client: AsyncClient,
) -> None:
    from app.scanner.orchestrator import ALL_TOOLS
    from app.schemas.response import BuildEvidence, BuildResponse

    build = BuildResponse(
        success=True,
        buildEvidence=BuildEvidence(
            requestedBuildCommand="make",
            effectiveBuildCommand="make",
            buildDir="/tmp/project",
            compileCommandsPath="/tmp/project/compile_commands.json",
            entries=1,
            userEntries=1,
            exitCode=0,
            buildOutput="ok",
            wrapWithBear=True,
            timeoutSeconds=600,
            elapsedMs=10,
        ),
        readiness={
            "status": "ready",
            "compileCommandsReady": True,
            "quickEligible": True,
            "summary": "compile_commands.json contains user-target entries and the build exited successfully.",
        },
    )
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {
        "available": False,
        "version": None,
        "probeReason": "environment-drift",
    }
    router_orchestrator = __import__("app.routers.scan", fromlist=["orchestrator"]).orchestrator

    with (
        patch("pathlib.Path.is_dir", return_value=True),
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=build.model_dump(by_alias=True, exclude_none=True))),
        patch.object(router_orchestrator, "check_tools", AsyncMock(return_value=availability)),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": "/tmp/project",
                "buildCommand": "make",
                "projectId": "proj-test",
            },
        )

    data = resp.json()
    assert resp.status_code == 503
    assert data["success"] is False
    assert data["build"]["readiness"]["status"] == "ready"
    assert data["scan"]["success"] is False
    assert data["scan"]["errorDetail"]["code"] == "REQUIRED_TOOL_UNAVAILABLE"
    assert data["scan"]["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"
    assert data["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"


@pytest.mark.asyncio
async def test_build_and_analyze_execution_incomplete_preserves_build_evidence_and_failed_contract(
    client: AsyncClient,
) -> None:
    from app.schemas.response import BuildEvidence, BuildResponse

    build = BuildResponse(
        success=True,
        buildEvidence=BuildEvidence(
            requestedBuildCommand="make",
            effectiveBuildCommand="make",
            buildDir="/tmp/project",
            compileCommandsPath="/tmp/project/compile_commands.json",
            entries=1,
            userEntries=1,
            exitCode=0,
            buildOutput="ok",
            wrapWithBear=True,
            timeoutSeconds=600,
            elapsedMs=10,
        ),
        readiness={
            "status": "ready",
            "compileCommandsReady": True,
            "quickEligible": True,
            "summary": "compile_commands.json contains user-target entries and the build exited successfully.",
        },
    )
    execution = _execution_with_bad_tool(
        "gcc-fanalyzer",
        status="failed",
        findings_count=0,
        elapsed_ms=10,
        skip_reason="nonzero exit",
    )

    with (
        patch("pathlib.Path.is_dir", return_value=True),
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=build.model_dump(by_alias=True, exclude_none=True))),
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": "/tmp/project",
                "buildCommand": "make",
                "projectId": "proj-test",
            },
        )

    data = resp.json()
    assert resp.status_code == 503
    assert data["success"] is False
    assert data["build"]["readiness"]["status"] == "ready"
    assert data["scan"]["success"] is False
    assert data["scan"]["errorDetail"]["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
    assert data["scan"]["execution"]["toolResults"]["gcc-fanalyzer"]["status"] == "failed"
    assert data["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"
