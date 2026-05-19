"""SemgrepRunner 단위 테스트 — check_available, run, _build_command."""

import asyncio
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.errors import ScanTimeoutError, SemgrepNotAvailableError, ToolOutputInvalidError
from app.scanner.semgrep_runner import SemgrepRunner


@pytest.fixture
def runner():
    return SemgrepRunner()


def _make_proc_mock(returncode: int, stdout: bytes = b"", stderr: bytes = b""):
    """asyncio.create_subprocess_exec 결과를 모킹."""
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = AsyncMock()
    return proc


# ---------------------------------------------------------------------------
# _build_command
# ---------------------------------------------------------------------------

class TestBuildCommand:
    def test_uses_service_toolchain_executable_for_scan_command(self, runner, tmp_path):
        """PATH drift가 있어도 S4 venv의 canonical semgrep 실행 파일을 사용한다."""
        semgrep_bin = tmp_path / "semgrep"
        semgrep_bin.write_text("#!/bin/sh\n", encoding="utf-8")

        with (
            patch("app.scanner.semgrep_runner.service_toolchain_executable", return_value=semgrep_bin),
            patch("app.config.settings") as mock_settings,
        ):
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path, ["p/c"])

        assert cmd[0] == str(semgrep_bin)

    def test_basic_command_structure(self, runner, tmp_path):
        """기본 rulesets로 올바른 CLI 인자를 조립하는지 확인."""
        with patch("app.config.settings") as mock_settings:
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path, ["p/c", "p/security-audit"])

        assert Path(cmd[0]).name == "semgrep"
        assert cmd[1] == "scan"
        assert "--config" in cmd
        assert "p/c" in cmd
        assert "p/security-audit" in cmd
        assert "--sarif" in cmd
        assert str(tmp_path) == cmd[-1]

    def test_falls_back_to_path_when_service_toolchain_executable_is_absent(self, runner, tmp_path):
        """canonical executable이 없을 때만 PATH의 semgrep 이름으로 fallback한다."""
        with (
            patch("app.scanner.semgrep_runner.service_toolchain_executable", return_value=None),
            patch("app.config.settings") as mock_settings,
        ):
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path, ["p/c"])

        assert cmd[0] == "semgrep"

    def test_custom_rules_dir_absolute_exists(self, runner, tmp_path):
        """절대 경로의 커스텀 룰 디렉토리가 추가되는지 확인."""
        rules_dir = tmp_path / "custom_rules"
        rules_dir.mkdir()

        with patch("app.config.settings") as mock_settings:
            mock_settings.custom_rules_dir = str(rules_dir)
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path / "src", ["p/c"])

        # custom rules dir should appear as an extra --config
        config_indices = [i for i, v in enumerate(cmd) if v == "--config"]
        config_values = [cmd[i + 1] for i in config_indices]
        assert str(rules_dir) in config_values

    def test_custom_rules_dir_none(self, runner, tmp_path):
        """custom_rules_dir가 None이면 커스텀 룰 경로가 추가되지 않는다."""
        with patch("app.config.settings") as mock_settings:
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path, ["p/c"])

        config_indices = [i for i, v in enumerate(cmd) if v == "--config"]
        # Only one --config for p/c
        assert len(config_indices) == 1

    def test_timeout_and_max_bytes_from_settings(self, runner, tmp_path):
        """settings의 semgrep_per_rule_timeout, semgrep_max_target_bytes가 반영되는지."""
        with patch("app.config.settings") as mock_settings:
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 30
            mock_settings.semgrep_max_target_bytes = 5_000_000

            cmd = runner._build_command(tmp_path, ["p/c"])

        timeout_idx = cmd.index("--timeout")
        assert cmd[timeout_idx + 1] == "30"
        max_bytes_idx = cmd.index("--max-target-bytes")
        assert cmd[max_bytes_idx + 1] == "5000000"

    def test_metrics_off_and_no_git_ignore(self, runner, tmp_path):
        """--metrics off, --no-git-ignore 플래그가 항상 포함되는지."""
        with patch("app.config.settings") as mock_settings:
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path, ["p/c"])

        assert "--no-git-ignore" in cmd
        metrics_idx = cmd.index("--metrics")
        assert cmd[metrics_idx + 1] == "off"

    def test_include_extensions(self, runner, tmp_path):
        """include_extensions가 지정되면 --include 플래그가 추가된다."""
        with patch("app.config.settings") as mock_settings:
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path, ["p/c"], include_extensions=[".c", ".h"])

        assert "--include" in cmd
        include_indices = [i for i, v in enumerate(cmd) if v == "--include"]
        include_values = [cmd[i + 1] for i in include_indices]
        assert "*.c" in include_values
        assert "*.h" in include_values
        # scan_dir should still be the last argument
        assert cmd[-1] == str(tmp_path)

    def test_no_include_extensions(self, runner, tmp_path):
        """include_extensions가 None이면 --include 플래그가 없다."""
        with patch("app.config.settings") as mock_settings:
            mock_settings.custom_rules_dir = None
            mock_settings.semgrep_per_rule_timeout = 5
            mock_settings.semgrep_max_target_bytes = 1_000_000

            cmd = runner._build_command(tmp_path, ["p/c"], include_extensions=None)

        assert "--include" not in cmd


# ---------------------------------------------------------------------------
# check_available
# ---------------------------------------------------------------------------

class TestCheckAvailable:
    @pytest.mark.asyncio
    async def test_check_available_uses_service_toolchain_executable(self, runner, tmp_path):
        """가용성 probe도 PATH의 semgrep이 아니라 canonical executable을 직접 실행한다."""
        semgrep_bin = tmp_path / "semgrep"
        semgrep_bin.write_text("#!/bin/sh\n", encoding="utf-8")
        proc = _make_proc_mock(0, stdout=b"1.156.0\n")

        with (
            patch("app.scanner.semgrep_runner.service_toolchain_executable", return_value=semgrep_bin),
            patch("asyncio.create_subprocess_exec", return_value=proc) as exec_mock,
        ):
            available, version = await runner.check_available()

        assert available is True
        assert version == "1.156.0"
        assert exec_mock.call_args.args[0] == str(semgrep_bin)

    @pytest.mark.asyncio
    async def test_available(self, runner):
        """semgrep --version이 정상이면 (True, version) 반환."""
        proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            available, version = await runner.check_available()

        assert available is True
        assert version == "1.45.0"

    @pytest.mark.asyncio
    async def test_not_available_nonzero_exit(self, runner):
        """비정상 exit code → (False, None)."""
        proc = _make_proc_mock(1)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            available, version = await runner.check_available()

        assert available is False
        assert version is None

    @pytest.mark.asyncio
    async def test_not_available_file_not_found(self, runner):
        """FileNotFoundError → (False, None)."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("semgrep not found"),
        ):
            available, version = await runner.check_available()

        assert available is False
        assert version is None

    @pytest.mark.asyncio
    async def test_not_available_timeout(self, runner):
        """asyncio.TimeoutError → (False, None)."""
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            available, version = await runner.check_available()

        assert available is False
        assert version is None


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

SAMPLE_SARIF = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [{"id": "test-rule"}],
                }
            },
            "results": [
                {
                    "ruleId": "test-rule",
                    "message": {"text": "Test finding"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main.c"},
                                "region": {"startLine": 10},
                            }
                        }
                    ],
                }
            ],
        }
    ]
}

EMPTY_SARIF = {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}


class TestRun:
    @pytest.mark.asyncio
    async def test_normal_sarif_output(self, runner, tmp_path):
        """정상 SARIF JSON 출력 → 파싱된 dict 반환."""
        sarif_bytes = json.dumps(SAMPLE_SARIF).encode()
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = _make_proc_mock(0, stdout=sarif_bytes)

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                result = await runner.run(tmp_path, ["p/c"])

        assert result == SAMPLE_SARIF
        assert len(result["runs"][0]["results"]) == 1

    @pytest.mark.asyncio
    async def test_command_start_log_does_not_echo_raw_command(self, runner, tmp_path, caplog):
        """Semgrep 실행 시작 로그는 joined command, scan_dir, rules path를 남기지 않는다."""
        scan_dir = tmp_path / "SECRET_SEMGREP_SCAN_DIR_SHOULD_NOT_LEAK"
        scan_dir.mkdir()
        secret_rules = str(tmp_path / "SECRET_SEMGREP_RULES_SHOULD_NOT_LEAK.yml")
        sarif_bytes = json.dumps(EMPTY_SARIF).encode()
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = _make_proc_mock(0, stdout=sarif_bytes)
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                result = await runner.run(scan_dir, [secret_rules])

        assert result == EMPTY_SARIF
        assert "Running Semgrep" in caplog.text
        assert "SECRET_SEMGREP_SCAN_DIR_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_SEMGREP_RULES_SHOULD_NOT_LEAK" not in caplog.text
        assert "--sarif" not in caplog.text
        assert "--config" not in caplog.text

    @pytest.mark.asyncio
    async def test_empty_stdout(self, runner, tmp_path):
        """stdout가 빈 경우 → 빈 SARIF 구조 반환."""
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = _make_proc_mock(0, stdout=b"", stderr=b"some warning")

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                result = await runner.run(tmp_path, ["p/c"])

        assert result == EMPTY_SARIF

    @pytest.mark.asyncio
    async def test_empty_stdout_stderr_log_does_not_echo_raw_stderr(self, runner, tmp_path, caplog):
        """stdout가 비고 stderr가 있어도 raw stderr 내용을 로그에 남기지 않는다."""
        secret_stderr = "SECRET_SEMGREP_STDERR_SHOULD_NOT_LEAK"
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = _make_proc_mock(0, stdout=b"", stderr=secret_stderr.encode())
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                result = await runner.run(tmp_path, ["p/c"])

        assert result == EMPTY_SARIF
        assert "Semgrep stderr was non-empty" in caplog.text
        assert secret_stderr not in caplog.text

    @pytest.mark.asyncio
    async def test_json_decode_error_is_system_stability_failure(self, runner, tmp_path):
        """stdout가 유효하지 않은 JSON이면 정상 응답으로 취급하지 않고 실패한다."""
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = _make_proc_mock(1, stdout=b"ERROR: invalid config\n", stderr=b"err")

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                with pytest.raises(ToolOutputInvalidError):
                    await runner.run(tmp_path, ["p/c"])

    @pytest.mark.asyncio
    async def test_json_decode_error_log_does_not_echo_raw_stdout_or_stderr(self, runner, tmp_path, caplog):
        """Semgrep non-JSON stdout/stderr 내용을 로그에 남기지 않는다."""
        secret_stdout = "SECRET_SEMGREP_STDOUT_SHOULD_NOT_LEAK"
        secret_stderr = "SECRET_SEMGREP_NON_JSON_STDERR_SHOULD_NOT_LEAK"
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = _make_proc_mock(1, stdout=secret_stdout.encode(), stderr=secret_stderr.encode())
        caplog.set_level(logging.ERROR, logger="aegis-sast-runner")

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                with pytest.raises(ToolOutputInvalidError):
                    await runner.run(tmp_path, ["p/c"])

        assert "Semgrep produced non-JSON SARIF output" in caplog.text
        assert secret_stdout not in caplog.text
        assert secret_stderr not in caplog.text

    @pytest.mark.asyncio
    async def test_timeout_raises_scan_timeout_error(self, runner, tmp_path):
        """타임아웃 초과 시 ScanTimeoutError 발생."""
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = AsyncMock()
        run_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        run_proc.kill = MagicMock()

        # kill 후 communicate 재호출 모킹
        comm_call_count = 0

        async def communicate_side_effect():
            nonlocal comm_call_count
            comm_call_count += 1
            if comm_call_count == 1:
                raise asyncio.TimeoutError()
            return (b"", b"")

        run_proc.communicate = AsyncMock(side_effect=communicate_side_effect)

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                with pytest.raises(ScanTimeoutError, match="timeout"):
                    await runner.run(tmp_path, ["p/c"], timeout=30)

        run_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_semgrep_not_available_raises(self, runner, tmp_path):
        """semgrep이 없으면 SemgrepNotAvailableError 발생."""
        proc = _make_proc_mock(127)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            with pytest.raises(SemgrepNotAvailableError):
                await runner.run(tmp_path, ["p/c"])

    @pytest.mark.asyncio
    async def test_findings_with_exit_code_one(self, runner, tmp_path):
        """semgrep은 findings가 있으면 exit code 1을 반환하지만 SARIF는 정상."""
        sarif_bytes = json.dumps(SAMPLE_SARIF).encode()
        check_proc = _make_proc_mock(0, stdout=b"1.45.0\n")
        run_proc = _make_proc_mock(1, stdout=sarif_bytes, stderr=b"")

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return check_proc
            return run_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            with patch("app.config.settings") as mock_settings:
                mock_settings.custom_rules_dir = None
                mock_settings.semgrep_per_rule_timeout = 5
                mock_settings.semgrep_max_target_bytes = 1_000_000

                result = await runner.run(tmp_path, ["p/c"])

        assert result == SAMPLE_SARIF
