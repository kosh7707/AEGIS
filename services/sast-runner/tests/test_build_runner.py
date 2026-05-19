"""BuildRunner 단위 테스트 — explicit build execution, discover_targets."""

import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.scanner.build_runner import BuildRunner


@pytest.fixture
def runner():
    return BuildRunner()


class TestDiscoverTargets:
    def test_single_makefile(self, runner, tmp_path):
        (tmp_path / "Makefile").write_text("all:\n")
        targets = runner.discover_targets(tmp_path)
        assert len(targets) == 1
        assert targets[0]["buildSystem"] == "make"
        assert "detectedBuildCommand" not in targets[0]

    def test_nested_cmake(self, runner, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("project(root)\n")
        sub = tmp_path / "lib"
        sub.mkdir()
        (sub / "CMakeLists.txt").write_text("project(sub)\n")
        targets = runner.discover_targets(tmp_path)
        assert len(targets) >= 1

    def test_multiple_independent_targets(self, runner, tmp_path):
        app1 = tmp_path / "app1"
        app1.mkdir()
        (app1 / "Makefile").write_text("all:\n")
        app2 = tmp_path / "app2"
        app2.mkdir()
        (app2 / "CMakeLists.txt").write_text("project(app2)\n")
        targets = runner.discover_targets(tmp_path)
        assert len(targets) == 2

    def test_empty_project(self, runner, tmp_path):
        targets = runner.discover_targets(tmp_path)
        assert targets == []

    def test_discover_targets_log_does_not_echo_project_path(self, runner, tmp_path, caplog):
        secret_project = tmp_path / "SECRET_DISCOVER_PROJECT_PATH_SHOULD_NOT_LEAK"
        secret_project.mkdir()
        (secret_project / "Makefile").write_text("all:\n")
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        targets = runner.discover_targets(secret_project)

        assert len(targets) == 1
        assert "Discovered" in caplog.text
        assert "SECRET_DISCOVER_PROJECT_PATH_SHOULD_NOT_LEAK" not in caplog.text


def _make_proc_mock(returncode: int, stdout: bytes = b"", stderr: bytes = b""):
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    return proc


class TestBuild:
    @pytest.mark.asyncio
    async def test_success_when_exit_zero(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(0, b"Build OK\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "make")

        assert result["success"] is True
        assert result["buildEvidence"]["exitCode"] == 0
        assert result["buildEvidence"]["entries"] == 1
        assert result["buildEvidence"]["userEntries"] == 1
        assert result["failureDetail"] is None

    @pytest.mark.asyncio
    async def test_build_output_does_not_echo_success_stdout_or_stderr(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(
            0,
            b"SECRET_BUILD_STDOUT_SHOULD_NOT_LEAK\n",
            b"SECRET_BUILD_STDERR_SHOULD_NOT_LEAK\n",
        )
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "make")

        assert result["success"] is True
        assert result["buildEvidence"]["buildOutput"] == "build output omitted"
        assert "SECRET_BUILD_STDOUT_SHOULD_NOT_LEAK" not in str(result)
        assert "SECRET_BUILD_STDERR_SHOULD_NOT_LEAK" not in str(result)

    @pytest.mark.asyncio
    async def test_build_start_log_does_not_echo_command_or_project_path(self, runner, tmp_path, caplog):
        secret_project = tmp_path / "SECRET_BUILD_PROJECT_PATH_SHOULD_NOT_LEAK"
        secret_project.mkdir()
        secret_command = "echo SECRET_BUILD_COMMAND_SHOULD_NOT_LEAK"
        proc = _make_proc_mock(0, b"", b"")
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(secret_project, secret_command, wrap_with_bear=False)

        assert result["success"] is False
        assert "Build started" in caplog.text
        assert "SECRET_BUILD_PROJECT_PATH_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_BUILD_COMMAND_SHOULD_NOT_LEAK" not in caplog.text

    @pytest.mark.asyncio
    async def test_environment_keys_echoed_without_mutation(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(0, b"OK\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            result = await runner.build(
                tmp_path,
                "./toolchains/build.sh",
                environment={"SDK_ROOT": "/uploads/sdk", "CC": "/uploads/sdk/bin/gcc"},
            )

        assert result["success"] is True
        assert result["buildEvidence"]["effectiveBuildCommand"] == "./toolchains/build.sh"
        assert result["buildEvidence"]["environmentKeys"] == ["CC", "SDK_ROOT"]
        assert mock_exec.call_args.kwargs["env"]["SDK_ROOT"] == "/uploads/sdk"

    @pytest.mark.asyncio
    async def test_failure_with_partial_entries(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(1, b"", b"ld returned 1 exit status\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "make")

        assert result["success"] is False
        assert result["buildEvidence"]["exitCode"] == 1
        assert result["buildEvidence"]["entries"] == 1
        assert result["buildEvidence"]["userEntries"] == 1
        assert result["failureDetail"]["category"] == "build-process"

    @pytest.mark.asyncio
    async def test_failure_cmake_temp_only(self, runner, tmp_path):
        cc = [
            {"file": "/tmp/build/CMakeFiles/CMakeCCompilerId.c", "command": "gcc -c CMakeCCompilerId.c", "directory": "/tmp"},
            {"file": "/tmp/build/CMakeFiles/CMakeCXXCompilerId.cpp", "command": "g++ -c CMakeCXXCompilerId.cpp", "directory": "/tmp"},
        ]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(1, b"", b"CMake will not be able to correctly generate this project\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "cmake -S . -B build && cmake --build build")

        assert result["success"] is False
        assert result["buildEvidence"]["userEntries"] == 0
        assert "CMake temporary" in result["failureDetail"]["summary"]

    @pytest.mark.asyncio
    async def test_failure_no_compile_commands(self, runner, tmp_path):
        proc = _make_proc_mock(2, b"", b"bear: error\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "make")

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "compile-commands-missing"

    @pytest.mark.asyncio
    async def test_build_output_and_matched_excerpt_do_not_echo_failure_output(self, runner, tmp_path):
        proc = _make_proc_mock(
            2,
            b"SECRET_BUILD_FAILURE_STDOUT_SHOULD_NOT_LEAK\n",
            b"SECRET_BUILD_FAILURE_STDERR_SHOULD_NOT_LEAK\n",
        )
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "make")

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "compile-commands-missing"
        assert result["buildEvidence"]["buildOutput"] == "build output omitted"
        assert result["failureDetail"]["matchedExcerpt"] is None
        assert "SECRET_BUILD_FAILURE_STDOUT_SHOULD_NOT_LEAK" not in str(result)
        assert "SECRET_BUILD_FAILURE_STDERR_SHOULD_NOT_LEAK" not in str(result)

    @pytest.mark.asyncio
    async def test_failure_empty_compile_commands(self, runner, tmp_path):
        (tmp_path / "compile_commands.json").write_text("[]")

        proc = _make_proc_mock(0)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "make")

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "compile-commands-empty"

    @pytest.mark.asyncio
    async def test_timeout(self, runner, tmp_path):
        import asyncio

        proc = AsyncMock()
        proc.returncode = -9
        proc.kill = AsyncMock()

        call_count = 0

        async def side_effect_fn():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.TimeoutError()
            return (b"", b"")

        proc.communicate = AsyncMock(side_effect=side_effect_fn)

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "make", timeout=1)

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "timeout"

    @pytest.mark.asyncio
    async def test_shared_library_load_classified_generically(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(
            127,
            b"",
            b"error while loading shared libraries: libfoo.so: cannot open shared object file\n",
        )
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "./build.sh", environment={"LD_LIBRARY_PATH": "/uploads/sdk"})

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "shared-library-load"
        assert result["buildEvidence"]["environmentKeys"] == ["LD_LIBRARY_PATH"]

    @pytest.mark.asyncio
    async def test_shared_library_failure_detail_does_not_echo_raw_loader_line(self, runner, tmp_path):
        proc = _make_proc_mock(
            127,
            b"",
            b"error while loading shared libraries: SECRET_LIB_SHOULD_NOT_LEAK.so: cannot open shared object file\n",
        )
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(
                tmp_path,
                "./build.sh",
                environment={"LD_LIBRARY_PATH": "/uploads/sdk"},
            )

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "shared-library-load"
        assert result["failureDetail"]["matchedExcerpt"] is None
        assert result["buildEvidence"]["buildOutput"] == "build output omitted"
        assert "SECRET_LIB_SHOULD_NOT_LEAK" not in str(result)

    @pytest.mark.asyncio
    async def test_exit127_classified_as_command_not_found(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(127, b"", b"bash: missing-tool: command not found\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "missing-tool")

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "command-not-found"

    @pytest.mark.asyncio
    async def test_exit127_failure_detail_does_not_echo_raw_command_line(self, runner, tmp_path):
        proc = _make_proc_mock(
            127,
            b"",
            b"bash: SECRET_MISSING_TOOL_SHOULD_NOT_LEAK: command not found\n",
        )
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.build(tmp_path, "missing-tool")

        assert result["success"] is False
        assert result["failureDetail"]["category"] == "command-not-found"
        assert result["failureDetail"]["matchedExcerpt"] is None
        assert result["buildEvidence"]["buildOutput"] == "build output omitted"
        assert "SECRET_MISSING_TOOL_SHOULD_NOT_LEAK" not in str(result)

    @pytest.mark.asyncio
    async def test_wrap_with_bear_true(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(0, b"OK\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await runner.build(tmp_path, "make", wrap_with_bear=True)

        cmd_args = mock_exec.call_args[0]
        assert cmd_args[0] == "bear"
        assert "--" in cmd_args

    @pytest.mark.asyncio
    async def test_wrap_with_bear_false(self, runner, tmp_path):
        cc = [{"file": "src/main.c", "command": "gcc -c src/main.c", "directory": str(tmp_path)}]
        (tmp_path / "compile_commands.json").write_text(json.dumps(cc))

        proc = _make_proc_mock(0, b"OK\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await runner.build(tmp_path, "make", wrap_with_bear=False)

        cmd_args = mock_exec.call_args[0]
        assert cmd_args[0] == "bash"
        assert "bear" not in cmd_args
