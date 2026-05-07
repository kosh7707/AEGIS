from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config import settings
from app.agent_runtime.schemas.agent import ToolResult
from app.routers.build_resolve_handler import _request_scoped_build_subdir, handle_build_resolve
from app.schemas.request import Context, TaskRequest
from app.types import TaskType


@pytest.mark.asyncio
async def test_build_resolve_requests_async_ownership_on_toolless_turn(monkeypatch, tmp_path: Path):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")

    (tmp_path / "README.md").write_text("test project")

    request = TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="build-async-001",
        contractVersion="build-resolve-v1",
        strictMode=True,
        context=Context(trusted={
            "projectPath": str(tmp_path),
            "buildTargetPath": ".",
                "buildTargetName": "test-project",
                "build": {"mode": "native"},
                "expectedArtifacts": [
                    {"kind": "file-set", "path": "build-aegis-default/aegis-build.sh"},
                ],
            }),
    )

    seen: dict[str, object] = {}

    async def fake_call(self, *args, **kwargs):
        seen["prefer_async_ownership"] = kwargs.get("prefer_async_ownership")
        from app.agent_runtime.schemas.agent import LlmResponse
        return LlmResponse(
            content=json.dumps({
                "summary": "빌드 완료",
                "buildResult": {
                    "success": True,
                    "buildCommand": "bash build-aegis-default/aegis-build.sh",
                    "buildScript": "build-aegis-default/aegis-build.sh",
                    "buildDir": "build-aegis-default",
                    "declaredMode": "native",
                    "sdkId": None,
                    "producedArtifacts": ["build-aegis-default/aegis-build.sh"],
                },
                "claims": [{"statement": "Mock 빌드 완료", "supportingEvidenceRefs": []}],
                "caveats": [],
                "usedEvidenceRefs": [],
                "needsHumanReview": False,
                "recommendedNextSteps": [],
                "policyFlags": [],
            }),
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def fake_aclose(self):
        return None

    monkeypatch.setattr(
        "app.budget.manager.BudgetManager.no_callable_tools_remaining",
        lambda self: True,
    )
    monkeypatch.setattr(
        "app.core.result_assembler.ResultAssembler._has_build_success_evidence",
        lambda self, session: True,
    )
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fake_call)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.aclose", fake_aclose)

    try:
        result = await handle_build_resolve(request)
        assert result.status == "completed"
        assert seen["prefer_async_ownership"] is True
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)


def test_request_scoped_build_subdir_hashes_untrusted_request_id():
    build_dir = _request_scoped_build_subdir("../evil/request-id-with-shared-prefix")

    assert build_dir.startswith("build-aegis-")
    assert "/" not in build_dir
    assert ".." not in build_dir
    assert build_dir != _request_scoped_build_subdir("../evil/request-id-with-shared-prefix-2")
    assert len(build_dir.removeprefix("build-aegis-")) == 16


@pytest.mark.asyncio
async def test_build_script_hint_path_is_reference_only_not_directly_executed(monkeypatch, tmp_path: Path):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "mock")
    (tmp_path / "README.md").write_text("no deterministic build files")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "build.sh").write_text("#!/bin/bash\necho should-not-run\n")
    calls: list[dict] = []

    async def reject_if_direct_hint_executed(self, arguments):
        calls.append(arguments)
        assert arguments["build_command"].startswith("bash build-aegis-")
        assert "scripts/build.sh" not in arguments["build_command"]
        return ToolResult(
            tool_call_id="",
            name="try_build",
            success=False,
            content='{"error":"unit deterministic build intentionally failed"}',
            error="unit deterministic build intentionally failed",
        )

    monkeypatch.setattr(
        "app.tools.implementations.try_build.TryBuildTool.execute",
        reject_if_direct_hint_executed,
    )

    request = TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="hint-direct-exec-check",
        contractVersion="build-resolve-v1",
        strictMode=True,
        context=Context(trusted={
            "projectPath": str(tmp_path),
            "buildTargetPath": ".",
            "buildTargetName": "hinted",
            "build": {
                "mode": "native",
                "scriptHintPath": "scripts/build.sh",
            },
            "expectedArtifacts": [{"kind": "file-set", "path": "hinted"}],
        }),
    )

    try:
        await handle_build_resolve(request)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)

    assert len(calls) == 1


@pytest.mark.asyncio
async def test_build_resolve_configures_try_build_with_request_scoped_build_dir(monkeypatch, tmp_path: Path):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "mock")
    (tmp_path / "README.md").write_text("test project")
    seen: dict[str, object] = {}

    from app.tools.implementations.try_build import TryBuildTool

    original_init = TryBuildTool.__init__

    def spy_init(self, *args, **kwargs):
        seen["build_dir"] = kwargs.get("build_dir")
        return original_init(self, *args, **kwargs)

    monkeypatch.setattr(TryBuildTool, "__init__", spy_init)

    request = TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="build-dir-guard-check",
        contractVersion="build-resolve-v1",
        strictMode=True,
        context=Context(trusted={
            "projectPath": str(tmp_path),
            "buildTargetPath": ".",
            "buildTargetName": "guarded",
            "build": {"mode": "native"},
            "expectedArtifacts": [{"kind": "file-set", "path": "guarded"}],
        }),
    )

    try:
        await handle_build_resolve(request)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)

    assert isinstance(seen["build_dir"], str)
    assert seen["build_dir"].startswith("build-aegis-")


@pytest.mark.asyncio
async def test_build_resolve_configures_try_build_with_sdk_descriptor_environment(monkeypatch, tmp_path: Path):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "mock")
    (tmp_path / "README.md").write_text("test project")
    sdk_root = tmp_path / "sdk"
    env_script = sdk_root / "linux-devkit" / "environment-setup-arm"
    sysroot = sdk_root / "linux-devkit" / "sysroots" / "arm"
    env_script.parent.mkdir(parents=True)
    sysroot.mkdir(parents=True)
    env_script.write_text("export CC=arm-gcc\n")
    seen: dict[str, object] = {}

    from app.tools.implementations.try_build import TryBuildTool

    original_init = TryBuildTool.__init__

    def spy_init(self, *args, **kwargs):
        seen["default_build_environment"] = kwargs.get("default_build_environment")
        return original_init(self, *args, **kwargs)

    monkeypatch.setattr(TryBuildTool, "__init__", spy_init)

    request = TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="sdk-env-check",
        contractVersion="build-resolve-v1",
        strictMode=True,
        context=Context(trusted={
            "projectPath": str(tmp_path),
            "buildTargetPath": ".",
            "buildTargetName": "sdk-env",
            "build": {
                "mode": "sdk",
                "sdkId": "sdk-1",
                "sdkRootPath": str(sdk_root),
                "setupScript": "linux-devkit/environment-setup-arm",
                "sysroot": "linux-devkit/sysroots/arm",
                "toolchainTriplet": "arm-none-linux-gnueabihf",
                "environment": {"AEGIS_SDK_ROOT": "/evil", "CUSTOM_FLAG": "1"},
            },
            "expectedArtifacts": [{"kind": "file-set", "path": "sdk-env"}],
        }),
    )

    try:
        await handle_build_resolve(request)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)

    env = seen["default_build_environment"]
    assert isinstance(env, dict)
    assert env["CUSTOM_FLAG"] == "1"
    assert env["AEGIS_SDK_ROOT"] == str(sdk_root.resolve())
    assert env["SDK_DIR"] == str(sdk_root.resolve())
    assert env["AEGIS_SDK_SETUP_SCRIPT"] == str(env_script.resolve())
    assert env["AEGIS_SDK_SYSROOT"] == str(sysroot.resolve())
    assert env["SDKTARGETSYSROOT"] == str(sysroot.resolve())
    assert env["AEGIS_TOOLCHAIN_TRIPLET"] == "arm-none-linux-gnueabihf"


@pytest.mark.asyncio
async def test_phase0_initial_script_exports_sdk_descriptor_environment(monkeypatch, tmp_path: Path):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "mock")
    (tmp_path / "Makefile").write_text("all:\n\t@echo ok\n")
    sdk_root = tmp_path / "sdk root"
    env_script = sdk_root / "linux-devkit" / "environment-setup-arm"
    sysroot = sdk_root / "linux-devkit" / "sysroots" / "arm"
    env_script.parent.mkdir(parents=True)
    sysroot.mkdir(parents=True)
    env_script.write_text("export CC=arm-gcc\n")

    request = TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="sdk-initial-script-check",
        contractVersion="build-resolve-v1",
        strictMode=True,
        context=Context(trusted={
            "projectPath": str(tmp_path),
            "buildTargetPath": ".",
            "buildTargetName": "sdk-initial",
            "build": {
                "mode": "sdk",
                "sdkId": "sdk-1",
                "sdkRootPath": str(sdk_root),
                "setupScript": "linux-devkit/environment-setup-arm",
                "sysroot": "linux-devkit/sysroots/arm",
            },
            "expectedArtifacts": [{"kind": "file-set", "path": "sdk-initial"}],
        }),
    )

    try:
        await handle_build_resolve(request)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)

    build_dir = _request_scoped_build_subdir("sdk-initial-script-check")
    generated = tmp_path / build_dir / "aegis-build.sh"
    script = generated.read_text()
    assert f"export AEGIS_SDK_ROOT='{sdk_root.resolve()}'" in script
    assert f"export SDK_DIR='{sdk_root.resolve()}'" in script
    assert f"source '{env_script.resolve()}'" in script
    assert f"export SDKTARGETSYSROOT='{sysroot.resolve()}'" in script


@pytest.mark.asyncio
async def test_shell_script_hint_gets_request_scoped_descriptor_wrapper(monkeypatch, tmp_path: Path):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "mock")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "cross_build.sh").write_text("#!/bin/bash\necho hinted\n")
    sdk_root = tmp_path / "sdk root"
    env_script = sdk_root / "linux-devkit" / "environment-setup-arm"
    env_script.parent.mkdir(parents=True)
    env_script.write_text("export CC=arm-gcc\n")

    request = TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="sdk-shell-wrapper-check",
        contractVersion="build-resolve-v1",
        strictMode=True,
        context=Context(trusted={
            "projectPath": str(tmp_path),
            "buildTargetPath": ".",
            "buildTargetName": "sdk-shell",
            "build": {
                "mode": "sdk",
                "sdkId": "sdk-1",
                "sdkRootPath": str(sdk_root),
                "setupScript": "linux-devkit/environment-setup-arm",
                "scriptHintPath": "scripts/cross_build.sh",
            },
            "expectedArtifacts": [{"kind": "file-set", "path": "sdk-shell"}],
        }),
    )

    try:
        await handle_build_resolve(request)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)

    build_dir = _request_scoped_build_subdir("sdk-shell-wrapper-check")
    script = (tmp_path / build_dir / "aegis-build.sh").read_text()
    assert f"export AEGIS_SDK_ROOT='{sdk_root.resolve()}'" in script
    assert f"source '{env_script.resolve()}'" in script
    assert "bash scripts/cross_build.sh" in script


@pytest.mark.asyncio
async def test_deterministic_phase0_wrapper_success_short_circuits_agent_loop(monkeypatch, tmp_path: Path):
    original_mode = settings.llm_mode
    object.__setattr__(settings, "llm_mode", "real")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "build.sh").write_text("#!/bin/bash\necho build\n")

    async def fake_execute(self, arguments):
        assert arguments["build_command"].endswith("/aegis-build.sh")
        (tmp_path / "out.bin").write_text("built\n")
        return ToolResult(
            tool_call_id="",
            name="try_build",
            success=True,
            content='{"buildEvidence":{"exitCode":0}}',
            new_evidence_refs=["eref-build-success"],
        )

    async def fail_llm_call(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("deterministic success should return before LLM")

    monkeypatch.setattr("app.tools.implementations.try_build.TryBuildTool.execute", fake_execute)
    monkeypatch.setattr("app.agent_runtime.llm.caller.LlmCaller.call", fail_llm_call)

    request = TaskRequest(
        taskType=TaskType.BUILD_RESOLVE,
        taskId="deterministic-short-circuit",
        contractVersion="build-resolve-v1",
        strictMode=True,
        context=Context(trusted={
            "projectPath": str(tmp_path),
            "buildTargetPath": ".",
            "buildTargetName": "deterministic",
            "build": {"mode": "native", "scriptHintPath": "scripts/build.sh"},
            "expectedArtifacts": [{"kind": "file-set", "path": "out.bin"}],
        }),
    )

    try:
        result = await handle_build_resolve(request)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)

    assert result.status == "completed"
    assert result.modelProfile == "deterministic-phase0"
    assert result.result.cleanPass is True
    assert result.result.buildOutcome.outcome == "built"
    assert result.result.buildResult.buildCommand.startswith("bash build-aegis-")
