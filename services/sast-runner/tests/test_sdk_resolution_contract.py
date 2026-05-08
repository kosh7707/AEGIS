from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.runtime.request_summary import request_summary_tracker


@pytest.fixture(autouse=True)
def reset_request_summary() -> None:
    request_summary_tracker.reset()
    yield
    request_summary_tracker.reset()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _write_popen_project(project_dir: Path) -> None:
    src = project_dir / "src"
    src.mkdir(parents=True)
    (src / "http_client.cpp").write_text(
        """
        #include <cstdio>
        #include <string>

        void run_remote_command(const std::string& cmd) {
            FILE* pipe = popen(cmd.c_str(), "r");
            if (pipe != nullptr) {
                pclose(pipe);
            }
        }
        """,
        encoding="utf-8",
    )


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("flawfinder") is None, reason="flawfinder not installed")
async def test_non_registered_sdk_descriptor_does_not_suppress_flawfinder_popen_evidence(
    client: AsyncClient,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_popen_project(project_dir)

    sdk_root = tmp_path / "sdk"
    include_dir = sdk_root / "sysroot" / "usr" / "include"
    include_dir.mkdir(parents=True)

    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "non-registered-popen",
            "projectId": "proj-contract",
            "projectPath": str(project_dir),
            "buildProfile": {
                "sdkResolutionMode": "non-registered",
                "sdkDescriptor": {
                    "sdkRootPath": str(sdk_root),
                    "sysroot": "sysroot",
                    "toolchainTriplet": "arm-linux-gnueabihf",
                    "includePaths": [str(include_dir)],
                },
            },
            "options": {"tools": ["flawfinder"]},
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert any(
        "CWE-78" in (finding.get("metadata") or {}).get("cwe", [])
        or "popen" in finding.get("ruleId", "").lower()
        for finding in data.get("findings", [])
    )
    sdk = data["execution"]["sdk"]
    assert sdk["resolutionMode"] == "non-registered"
    assert sdk["resolvedFrom"] == "sdkDescriptor"
    assert sdk["sdkRootPath"] == str(sdk_root)


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("flawfinder") is None, reason="flawfinder not installed")
async def test_sdk_resolution_mode_none_never_touches_registry(
    client: AsyncClient,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_popen_project(project_dir)

    with patch(
        "app.scanner.sdk_resolver._get_registry",
        side_effect=AssertionError("registry should not be touched for sdkResolutionMode='none'"),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "none-no-registry",
                "projectId": "proj-contract",
                "projectPath": str(project_dir),
                "buildProfile": {"sdkResolutionMode": "none"},
                "options": {"tools": ["flawfinder"]},
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["execution"]["sdk"]["resolutionMode"] == "none"
    assert data["execution"]["sdk"]["resolved"] is False


@pytest.mark.asyncio
async def test_unknown_bare_sdkid_fails_build_and_analyze_before_build(
    client: AsyncClient,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    build_mock = AsyncMock()

    with patch("app.routers.scan.build_runner.build", build_mock):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": str(project_dir),
                "buildCommand": "make",
                "scanProfile": {"sdkId": "definitely-unknown-sdk-20260508"},
                "options": {"tools": ["flawfinder"]},
            },
        )

    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "SDK_NOT_FOUND"
    assert "non-registered" in data["errorDetail"]["message"]
    build_mock.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("build_profile", "expected_message"),
    [
        ({"sdkResolutionMode": "none", "sdkId": "ti-am335x"}, "must omit sdkId"),
        ({"sdkResolutionMode": "non-registered"}, "requires sdkDescriptor.sdkRootPath"),
        ({"sdkDescriptor": {"sdkRootPath": "/tmp/sdk"}}, "requires sdkResolutionMode"),
    ],
)
async def test_invalid_sdk_resolution_profile_fails_explicitly(
    client: AsyncClient,
    tmp_path: Path,
    build_profile: dict,
    expected_message: str,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    resp = await client.post(
        "/v1/scan",
        json={
            "scanId": "invalid-sdk-profile",
            "projectId": "proj-contract",
            "projectPath": str(project_dir),
            "buildProfile": build_profile,
            "options": {"tools": ["flawfinder"]},
        },
    )

    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert data["errorDetail"]["code"] == "SDK_PROFILE_INVALID"
    assert expected_message in data["errorDetail"]["message"]
