from __future__ import annotations

import logging
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from app.config import settings
from benchmark.juliet_manifest import JulietCWESuite, JulietTestCase
from benchmark.juliet_manifest import discover_cwe_suites
from benchmark.juliet_runner import _benchmark_cwe, run_benchmark
from benchmark.metrics import BenchmarkResult


def _assert_juliet_cli_error_payload(
    stderr: str,
    *,
    error: str,
    reason_code: str,
    stage: str,
) -> dict[str, str]:
    payload = json.loads(stderr)
    assert payload == {
        "error": error,
        "reasonCode": reason_code,
        "stage": stage,
    }
    return payload


class _FailingOrchestrator:
    async def run(self, **kwargs: Any) -> tuple[list[Any], Any]:
        del kwargs
        raise RuntimeError("SECRET_JULIET_SCAN_ERROR_SHOULD_NOT_LEAK")


class _ExecutionStub:
    tools_run: list[str] = []


class _EmptyOrchestrator:
    async def run(self, **kwargs: Any) -> tuple[list[Any], _ExecutionStub]:
        del kwargs
        return [], _ExecutionStub()


@pytest.mark.asyncio
async def test_juliet_benchmark_scan_failure_log_does_not_echo_exception_text(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    suite = JulietCWESuite(
        cwe_num=121,
        cwe_name="Stack_Based_Buffer_Overflow",
        directory=tmp_path,
        test_cases=[
            JulietTestCase(
                file_path=tmp_path / "CWE121_case_01.c",
                cwe_num=121,
                variant_id="01",
                relative_path="CWE121_case_01.c",
            ),
            JulietTestCase(
                file_path=tmp_path / "CWE121_case_02.c",
                cwe_num=121,
                variant_id="02",
                relative_path="CWE121_case_02.c",
            ),
        ],
    )

    caplog.set_level(logging.ERROR, logger="benchmark")

    metrics = await _benchmark_cwe(
        _FailingOrchestrator(),
        suite,
        support_path=None,
        cwe_key="CWE-121",
        timeout=1,
    )

    assert metrics.combined_fn == suite.count
    assert "Scan failed for CWE-121" in caplog.text
    assert "SECRET_JULIET_SCAN_ERROR_SHOULD_NOT_LEAK" not in caplog.text


def test_juliet_manifest_missing_testcases_error_does_not_echo_root_path(tmp_path: Path) -> None:
    juliet_root = tmp_path / "SECRET_JULIET_ROOT_SHOULD_NOT_LEAK"

    with pytest.raises(FileNotFoundError) as excinfo:
        discover_cwe_suites(juliet_root, target_cwes=[121], variant_filter="01")

    message = str(excinfo.value)
    assert "Juliet testcases directory not found" in message
    assert str(juliet_root) not in message
    assert "SECRET_JULIET_ROOT_SHOULD_NOT_LEAK" not in message


@pytest.mark.asyncio
async def test_juliet_benchmark_no_suites_log_does_not_echo_root_path(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    juliet_root = tmp_path / "SECRET_JULIET_EMPTY_SELECTION_ROOT_SHOULD_NOT_LEAK"
    (juliet_root / "testcases" / "CWE999_Unrelated").mkdir(parents=True)

    caplog.set_level(logging.ERROR, logger="benchmark")

    result = await run_benchmark(
        juliet_root,
        target_cwes=[121],
        variant_filter="01",
        timeout=1,
    )

    assert result.cwe_results == {}
    assert "No Juliet test suites found" in caplog.text
    assert str(juliet_root) not in caplog.text
    assert "SECRET_JULIET_EMPTY_SELECTION_ROOT_SHOULD_NOT_LEAK" not in caplog.text
    for record in caplog.records:
        assert str(juliet_root) not in record.getMessage()
        assert "SECRET_JULIET_EMPTY_SELECTION_ROOT_SHOULD_NOT_LEAK" not in str(record.__dict__)


@pytest.mark.asyncio
async def test_juliet_benchmark_restores_custom_rules_on_no_suite_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel_rules_dir = "rules/SECRET_CUSTOM_RULES_DIR_SHOULD_BE_RESTORED"
    monkeypatch.setattr(settings, "custom_rules_dir", sentinel_rules_dir)
    juliet_root = tmp_path / "juliet-root"
    (juliet_root / "testcases" / "CWE999_Unrelated").mkdir(parents=True)

    result = await run_benchmark(
        juliet_root,
        target_cwes=[121],
        variant_filter="01",
        timeout=1,
        custom_rules=False,
    )

    assert result.cwe_results == {}
    assert settings.custom_rules_dir == sentinel_rules_dir


@pytest.mark.asyncio
async def test_juliet_benchmark_suite_progress_log_does_not_echo_cwe_name(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_suffix = "SECRET_CWE_DIR_SUFFIX_SHOULD_NOT_LEAK"
    juliet_root = tmp_path / "juliet-root"
    cwe_dir = juliet_root / "testcases" / f"CWE121_{secret_suffix}"
    cwe_dir.mkdir(parents=True)
    (cwe_dir / "CWE121_case_01.c").write_text("int main(void) { return 0; }\n")
    monkeypatch.setattr("benchmark.juliet_runner.ScanOrchestrator", lambda: _EmptyOrchestrator())

    caplog.set_level(logging.INFO, logger="benchmark")

    result = await run_benchmark(
        juliet_root,
        target_cwes=[121],
        variant_filter="01",
        timeout=1,
    )

    assert list(result.cwe_results) == ["CWE-121"]
    assert "--- CWE-121" in caplog.text
    assert secret_suffix not in caplog.text
    for record in caplog.records:
        assert secret_suffix not in record.getMessage()
        assert secret_suffix not in str(record.__dict__)


@pytest.mark.asyncio
async def test_juliet_benchmark_start_log_does_not_echo_tool_list(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_tool = "SECRET_TOOL_SELECTOR_SHOULD_NOT_LEAK"
    juliet_root = tmp_path / "juliet-root"
    cwe_dir = juliet_root / "testcases" / "CWE121_Buffer"
    cwe_dir.mkdir(parents=True)
    (cwe_dir / "CWE121_case_01.c").write_text("int main(void) { return 0; }\n")
    monkeypatch.setattr("benchmark.juliet_runner.ScanOrchestrator", lambda: _EmptyOrchestrator())

    caplog.set_level(logging.INFO, logger="benchmark")

    result = await run_benchmark(
        juliet_root,
        target_cwes=[121],
        variant_filter="01",
        timeout=1,
        tools=["semgrep", secret_tool],
    )

    assert list(result.cwe_results) == ["CWE-121"]
    assert "Benchmark started" in caplog.text
    assert "toolSelection=custom" in caplog.text
    assert "toolCount=2" in caplog.text
    assert secret_tool not in caplog.text
    for record in caplog.records:
        assert secret_tool not in record.getMessage()
        assert secret_tool not in str(record.__dict__)


@pytest.mark.asyncio
async def test_juliet_benchmark_start_log_does_not_echo_variant_filter(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_variant = "SECRET_VARIANT_FILTER_SHOULD_NOT_LEAK"
    suite = JulietCWESuite(
        cwe_num=121,
        cwe_name="Buffer",
        directory=tmp_path,
        test_cases=[
            JulietTestCase(
                file_path=tmp_path / "CWE121_case_01.c",
                cwe_num=121,
                variant_id="01",
                relative_path="CWE121_case_01.c",
            )
        ],
    )
    monkeypatch.setattr("benchmark.juliet_runner.discover_cwe_suites", lambda *args: [suite])
    monkeypatch.setattr("benchmark.juliet_runner.ScanOrchestrator", lambda: _EmptyOrchestrator())

    caplog.set_level(logging.INFO, logger="benchmark")

    result = await run_benchmark(
        tmp_path,
        target_cwes=[121],
        variant_filter=secret_variant,
        timeout=1,
    )

    assert list(result.cwe_results) == ["CWE-121"]
    assert "Benchmark started" in caplog.text
    assert "variantSelection=filtered" in caplog.text
    assert secret_variant not in caplog.text
    for record in caplog.records:
        assert secret_variant not in record.getMessage()
        assert secret_variant not in str(record.__dict__)


@pytest.mark.asyncio
async def test_juliet_benchmark_restores_custom_rules_on_discovery_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel_rules_dir = "rules/SECRET_CUSTOM_RULES_DIR_SHOULD_BE_RESTORED"
    monkeypatch.setattr(settings, "custom_rules_dir", sentinel_rules_dir)
    juliet_root = tmp_path / "juliet-root-without-testcases"

    with pytest.raises(FileNotFoundError):
        await run_benchmark(
            juliet_root,
            target_cwes=[121],
            variant_filter="01",
            timeout=1,
            custom_rules=False,
        )

    assert settings.custom_rules_dir == sentinel_rules_dir


def test_juliet_cli_stdout_json_redacts_juliet_path_but_uses_real_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_root = tmp_path / "SECRET_JULIET_CLI_ROOT_SHOULD_NOT_LEAK" / "C"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(secret_root),
            "--cwes",
            "121",
        ],
    )

    juliet_runner.main()

    assert captured["juliet_root"] == secret_root
    stdout = capsys.readouterr().out
    assert "SECRET_JULIET_CLI_ROOT_SHOULD_NOT_LEAK" not in stdout
    assert str(secret_root) not in stdout

    payload_start = stdout.index('{\n  "timestamp"')
    payload = json.loads(stdout[payload_start:])
    assert payload["julietPath"] == "<JULIET_ROOT>/C"
    assert payload["targetCWEs"] == ["CWE-121"]


def test_juliet_cli_missing_required_args_fails_without_argparse_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    def fail_if_run(*args: Any, **kwargs: Any) -> BenchmarkResult:
        pytest.fail(f"_run_cli_benchmark should not run after parse failure: {args} {kwargs}")

    monkeypatch.setattr(juliet_runner, "_run_cli_benchmark", fail_if_run)
    monkeypatch.setattr(sys, "argv", ["juliet_runner"])

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    captured_io = capsys.readouterr()
    assert captured_io.out == ""
    _assert_juliet_cli_error_payload(
        captured_io.err,
        error="invalid Juliet arguments",
        reason_code="JULIET_CLI_ARGUMENTS_INVALID",
        stage="input",
    )
    assert "invalid Juliet arguments" in captured_io.err
    assert "usage:" not in captured_io.err
    assert "required" not in captured_io.err
    assert "--juliet-path" not in captured_io.err
    assert "SystemExit" not in captured_io.err


def test_juliet_cli_timeout_failure_exits_two_when_stderr_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmark.juliet_runner as juliet_runner

    class BrokenStderr:
        def write(self, text: str) -> int:
            del text
            raise ValueError("SECRET_BROKEN_JULIET_STDERR_SHOULD_NOT_LEAK")

        def flush(self) -> None:
            return None

    monkeypatch.setattr(sys, "stderr", BrokenStderr())
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--timeout",
            "SECRET_TIMEOUT_SHOULD_NOT_LEAK",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2


def test_juliet_cli_unknown_arg_fails_without_argparse_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_root = tmp_path / "SECRET_JULIET_ARG_ROOT_SHOULD_NOT_LEAK" / "C"
    secret_flag = "--SECRET_JULIET_FLAG_SHOULD_NOT_LEAK"

    def fail_if_run(*args: Any, **kwargs: Any) -> BenchmarkResult:
        pytest.fail(f"_run_cli_benchmark should not run after parse failure: {args} {kwargs}")

    monkeypatch.setattr(juliet_runner, "_run_cli_benchmark", fail_if_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(secret_root),
            secret_flag,
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    captured_io = capsys.readouterr()
    assert captured_io.out == ""
    assert "invalid Juliet arguments" in captured_io.err
    assert "usage:" not in captured_io.err
    assert "unrecognized arguments" not in captured_io.err
    assert secret_flag not in captured_io.err
    assert "SECRET_JULIET_ARG_ROOT_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(secret_root) not in captured_io.err
    assert "SystemExit" not in captured_io.err


def test_juliet_cli_missing_cwes_value_fails_without_argparse_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_root = tmp_path / "SECRET_JULIET_CWES_ROOT_SHOULD_NOT_LEAK" / "C"

    def fail_if_run(*args: Any, **kwargs: Any) -> BenchmarkResult:
        pytest.fail(f"_run_cli_benchmark should not run after parse failure: {args} {kwargs}")

    monkeypatch.setattr(juliet_runner, "_run_cli_benchmark", fail_if_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(secret_root),
            "--cwes",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    captured_io = capsys.readouterr()
    assert captured_io.out == ""
    assert "invalid Juliet arguments" in captured_io.err
    assert "usage:" not in captured_io.err
    assert "expected one argument" not in captured_io.err
    assert "SECRET_JULIET_CWES_ROOT_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(secret_root) not in captured_io.err
    assert "SystemExit" not in captured_io.err


def test_juliet_cli_output_json_and_save_log_redact_paths_but_write_requested_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_root = tmp_path / "SECRET_JULIET_OUTPUT_ROOT_SHOULD_NOT_LEAK" / "C"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(secret_root),
            "--output",
            str(output_path),
        ],
    )
    caplog.set_level(logging.INFO, logger="benchmark")

    juliet_runner.main()

    assert captured["juliet_root"] == secret_root
    assert output_path.exists()
    output_payload = output_path.read_text()
    assert "SECRET_JULIET_OUTPUT_ROOT_SHOULD_NOT_LEAK" not in output_payload
    assert str(secret_root) not in output_payload
    assert json.loads(output_payload)["julietPath"] == "<JULIET_ROOT>/C"

    stdout = capsys.readouterr().out
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stdout
    assert str(output_path) not in stdout
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in caplog.text
    assert str(output_path) not in caplog.text
    assert "Results saved" in caplog.text
    for record in caplog.records:
        assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in record.getMessage()
        assert str(output_path) not in record.getMessage()
        assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in str(record.__dict__)
        assert str(output_path) not in str(record.__dict__)


def test_juliet_cli_unknown_tool_selector_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_tool = "SECRET_TOOL_SELECTOR_SHOULD_NOT_LEAK"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--tools",
            f"semgrep,{secret_tool}",
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    _assert_juliet_cli_error_payload(
        stderr,
        error="invalid tool selection",
        reason_code="JULIET_TOOL_SELECTION_INVALID",
        stage="input",
    )
    assert "invalid tool selection" in stderr
    assert secret_tool not in stderr
    assert f"semgrep,{secret_tool}" not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_blank_tool_selector_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--tools",
            "semgrep,",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    stderr = capsys.readouterr().err
    assert "invalid tool selection" in stderr
    assert "semgrep," not in stderr


def test_juliet_cli_duplicate_tool_selector_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    duplicate_selector = "semgrep,semgrep"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--tools",
            duplicate_selector,
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid tool selection" in stderr
    assert duplicate_selector not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_valid_tool_subset_preserves_execution_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--tools",
            "flawfinder,cppcheck",
        ],
    )

    juliet_runner.main()

    assert captured["tools"] == ["flawfinder", "cppcheck"]
    stdout = capsys.readouterr().out
    payload_start = stdout.index('{\n  "timestamp"')
    payload = json.loads(stdout[payload_start:])
    assert payload["tools"] == ["flawfinder", "cppcheck"]


def test_juliet_cli_invalid_cwe_selector_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_cwe = "SECRET_CWE_SELECTOR_SHOULD_NOT_LEAK"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--cwes",
            f"121,{secret_cwe}",
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid CWE selection" in stderr
    assert secret_cwe not in stderr
    assert f"121,{secret_cwe}" not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_blank_cwe_selector_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--cwes",
            "121,",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    stderr = capsys.readouterr().err
    assert "invalid CWE selection" in stderr
    assert "121," not in stderr


def test_juliet_cli_oversized_cwe_selector_fails_without_traceback_or_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    oversized_cwe = "9" * 5000
    output_path = tmp_path / "SECRET_OUTPUT_OVERSIZED_CWE_PATH_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--cwes",
            oversized_cwe,
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid CWE selection" in stderr
    assert "Traceback" not in stderr
    assert "ValueError" not in stderr
    assert oversized_cwe not in stderr
    assert "SECRET_OUTPUT_OVERSIZED_CWE_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_valid_cwe_subset_preserves_execution_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--cwes",
            "121,476",
        ],
    )

    juliet_runner.main()

    assert captured["target_cwes"] == [121, 476]
    stdout = capsys.readouterr().out
    payload_start = stdout.index('{\n  "timestamp"')
    payload = json.loads(stdout[payload_start:])
    assert payload["targetCWEs"] == ["CWE-121", "CWE-476"]


def test_juliet_cli_invalid_variant_selector_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_variant = "SECRET_VARIANT_SELECTOR_SHOULD_NOT_LEAK"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--variant-filter",
            secret_variant,
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid variant selection" in stderr
    assert secret_variant not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_blank_variant_selector_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--variant-filter",
            "",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    stderr = capsys.readouterr().err
    assert "invalid variant selection" in stderr


def test_juliet_cli_oversized_variant_selector_fails_without_traceback_or_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    oversized_variant = "9" * 5000
    output_path = tmp_path / "SECRET_OUTPUT_OVERSIZED_VARIANT_PATH_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--variant-filter",
            oversized_variant,
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid variant selection" in stderr
    assert "Traceback" not in stderr
    assert "ValueError" not in stderr
    assert oversized_variant not in stderr
    assert "SECRET_OUTPUT_OVERSIZED_VARIANT_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_valid_numeric_variant_preserves_execution_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--variant-filter",
            " 02 ",
        ],
    )

    juliet_runner.main()

    assert captured["variant_filter"] == "02"
    stdout = capsys.readouterr().out
    payload_start = stdout.index('{\n  "timestamp"')
    payload = json.loads(stdout[payload_start:])
    assert payload["variantFilter"] == "02"


def test_juliet_cli_all_variant_preserves_execution_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--variant-filter",
            " all ",
        ],
    )

    juliet_runner.main()

    assert captured["variant_filter"] is None
    stdout = capsys.readouterr().out
    payload_start = stdout.index('{\n  "timestamp"')
    payload = json.loads(stdout[payload_start:])
    assert payload["variantFilter"] == "all"


def test_juliet_cli_invalid_timeout_selector_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_timeout = "SECRET_TIMEOUT_SELECTOR_SHOULD_NOT_LEAK"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--timeout",
            secret_timeout,
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid timeout selection" in stderr
    assert secret_timeout not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_non_positive_timeout_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--timeout",
            "0",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    stderr = capsys.readouterr().err
    assert "invalid timeout selection" in stderr


def test_juliet_cli_oversized_timeout_selector_fails_without_traceback_or_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    oversized_timeout = "9" * 5000
    output_path = tmp_path / "SECRET_OUTPUT_OVERSIZED_TIMEOUT_PATH_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--timeout",
            oversized_timeout,
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid timeout selection" in stderr
    assert "Traceback" not in stderr
    assert "ValueError" not in stderr
    assert oversized_timeout not in stderr
    assert "SECRET_OUTPUT_OVERSIZED_TIMEOUT_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_valid_timeout_preserves_execution_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--timeout",
            "45",
        ],
    )

    juliet_runner.main()

    assert captured["timeout"] == 45


def test_juliet_cli_default_timeout_preserves_execution_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmark.juliet_runner as juliet_runner

    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
        ],
    )

    juliet_runner.main()

    assert captured["timeout"] == 300


def test_juliet_cli_missing_baseline_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_DIR_SHOULD_NOT_LEAK" / "missing.json"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid baseline artifact" in stderr
    assert "SECRET_BASELINE_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_directory_baseline_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_DIR_SHOULD_NOT_LEAK"
    baseline_path.mkdir()
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid baseline artifact" in stderr
    assert "SECRET_BASELINE_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_baseline_artifact_stat_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_STAT_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_BASELINE_STAT_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_error = "SECRET_BASELINE_STAT_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    original_is_file = Path.is_file

    def failing_is_file(self: Path) -> bool:
        if self == baseline_path:
            raise OSError(secret_error)
        return original_is_file(self)

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(Path, "is_file", failing_is_file)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" not in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    assert "invalid baseline artifact" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "OSError" not in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_BASELINE_STAT_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(baseline_path) not in captured_io.err
    assert "SECRET_OUTPUT_BASELINE_STAT_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_valid_baseline_preserves_compare_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    run_captured: dict[str, Any] = {}
    compare_captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        run_captured.update(kwargs)
        return BenchmarkResult()

    def fake_compare_from_files(baseline: Path, current: Any) -> None:
        compare_captured["baseline"] = baseline
        compare_captured["current"] = current

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fake_compare_from_files)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
        ],
    )

    juliet_runner.main()

    assert run_captured["juliet_root"] == tmp_path / "juliet-root"
    assert compare_captured["baseline"] == baseline_path
    assert isinstance(compare_captured["current"], dict)
    assert compare_captured["current"]["julietPath"] == "<JULIET_ROOT>/C"


def test_juliet_cli_malformed_baseline_payload_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_PAYLOAD_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_content = "SECRET_BASELINE_PAYLOAD_CONTENT_SHOULD_NOT_LEAK"
    baseline_path.write_text(f'{{"secret": "{secret_content}"')
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    _assert_juliet_cli_error_payload(
        stderr,
        error="invalid baseline artifact payload",
        reason_code="JULIET_BASELINE_PAYLOAD_INVALID",
        stage="input",
    )
    assert "invalid baseline artifact payload" in stderr
    assert secret_content not in stderr
    assert "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_non_object_baseline_payload_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_PAYLOAD_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_content = "SECRET_BASELINE_PAYLOAD_CONTENT_SHOULD_NOT_LEAK"
    baseline_path.write_text(json.dumps([secret_content]))
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid baseline artifact payload" in stderr
    assert secret_content not in stderr
    assert "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_baseline_missing_required_schema_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_EMPTY_PAYLOAD_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_EMPTY_PAYLOAD_PATH_SHOULD_NOT_LEAK" / "result.json"
    baseline_path.write_text(json.dumps({}))
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid baseline artifact payload" in stderr
    assert "SECRET_BASELINE_EMPTY_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_EMPTY_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_baseline_out_of_range_metric_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_RANGE_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_RANGE_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_content = "SECRET_BASELINE_RANGE_PAYLOAD_SHOULD_NOT_LEAK"
    baseline_path.write_text(json.dumps({
        "results": {},
        "summary": {"overallRecall": 2.0, "secret": secret_content},
    }))
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid baseline artifact payload" in stderr
    assert secret_content not in stderr
    assert "SECRET_BASELINE_RANGE_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_RANGE_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_baseline_noncanonical_cwe_key_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_CWE_KEY_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_CWE_KEY_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_key = "SECRET_BASELINE_CWE_KEY_SHOULD_NOT_LEAK"
    baseline_path.write_text(json.dumps({
        "results": {
            secret_key: {"combined": {"recall": 0.8}},
        },
        "summary": {"overallRecall": 0.8},
    }))
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid baseline artifact payload" in stderr
    assert secret_key not in stderr
    assert "SECRET_BASELINE_CWE_KEY_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_CWE_KEY_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_nested_baseline_payload_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_NESTED_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_NESTED_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_content = "SECRET_BASELINE_NESTED_CONTENT_SHOULD_NOT_LEAK"
    baseline_path.write_text(json.dumps({"summary": [secret_content], "results": {}}))
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not output_path.exists()
    stderr = capsys.readouterr().err
    assert "invalid baseline artifact payload" in stderr
    assert secret_content not in stderr
    assert "SECRET_BASELINE_NESTED_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_NESTED_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_invalid_output_fails_before_baseline_payload_read_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK.json"
    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK"
    output_path.mkdir()
    secret_content = "SECRET_BASELINE_PAYLOAD_CONTENT_SHOULD_NOT_LEAK"
    baseline_path.write_text(f'{{"secret": "{secret_content}"')
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    stderr = capsys.readouterr().err
    assert "invalid output artifact" in stderr
    assert "invalid baseline artifact payload" not in stderr
    assert secret_content not in stderr
    assert "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
    assert str(baseline_path) not in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_output_parent_create_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    output_path = tmp_path / "SECRET_OUTPUT_MKDIR_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_error = "SECRET_OUTPUT_MKDIR_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"calls": 0}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return BenchmarkResult()

    def fail_if_compared(*args: Any, **kwargs: Any) -> None:
        pytest.fail(f"compare_from_files should not run after output write failure: {args} {kwargs}")

    original_mkdir = Path.mkdir

    def failing_mkdir(self: Path, *args: Any, **kwargs: Any) -> None:
        if self == output_path.parent:
            raise OSError(secret_error)
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fail_if_compared)
    monkeypatch.setattr(Path, "mkdir", failing_mkdir)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert not output_path.exists()
    captured_io = capsys.readouterr()
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    _assert_juliet_cli_error_payload(
        captured_io.err,
        error="output artifact write failed",
        reason_code="JULIET_OUTPUT_ARTIFACT_WRITE_FAILED",
        stage="output",
    )
    assert "output artifact write failed" in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_OUTPUT_MKDIR_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_output_write_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    output_path = tmp_path / "SECRET_OUTPUT_WRITE_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_error = "SECRET_OUTPUT_WRITE_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"calls": 0}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return BenchmarkResult()

    def fail_if_compared(*args: Any, **kwargs: Any) -> None:
        pytest.fail(f"compare_from_files should not run after output write failure: {args} {kwargs}")

    original_write_text = Path.write_text

    def failing_write_text(self: Path, data: str, *args: Any, **kwargs: Any) -> int:
        if self == output_path:
            raise OSError(secret_error)
        return original_write_text(self, data, *args, **kwargs)

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fail_if_compared)
    monkeypatch.setattr(Path, "write_text", failing_write_text)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert not output_path.exists()
    captured_io = capsys.readouterr()
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    _assert_juliet_cli_error_payload(
        captured_io.err,
        error="output artifact write failed",
        reason_code="JULIET_OUTPUT_ARTIFACT_WRITE_FAILED",
        stage="output",
    )
    assert "output artifact write failed" in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_OUTPUT_WRITE_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_compare_handoff_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    baseline_path = tmp_path / "SECRET_BASELINE_COMPARE_PATH_SHOULD_NOT_LEAK.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    output_path = tmp_path / "SECRET_OUTPUT_COMPARE_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_error = "SECRET_COMPARE_HANDOFF_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"calls": 0}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return BenchmarkResult()

    def failing_compare_from_files(*args: Any, **kwargs: Any) -> None:
        raise OSError(secret_error)

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", failing_compare_from_files)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert json.loads(output_path.read_text())["julietPath"] == "<JULIET_ROOT>/C"
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" in captured_io.out
    _assert_juliet_cli_error_payload(
        captured_io.err,
        error="comparison handoff failed",
        reason_code="JULIET_COMPARISON_HANDOFF_FAILED",
        stage="handoff",
    )
    assert "comparison handoff failed" in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_BASELINE_COMPARE_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(baseline_path) not in captured_io.err
    assert "SECRET_OUTPUT_COMPARE_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_missing_testcases_fails_without_traceback_or_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    secret_root = tmp_path / "SECRET_JULIET_ROOT_SHOULD_NOT_LEAK"
    output_path = tmp_path / "SECRET_OUTPUT_BENCHMARK_PATH_SHOULD_NOT_LEAK" / "result.json"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(secret_root),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert not output_path.exists()
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" not in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    _assert_juliet_cli_error_payload(
        captured_io.err,
        error="benchmark execution failed",
        reason_code="JULIET_BENCHMARK_EXECUTION_FAILED",
        stage="run",
    )
    assert "benchmark execution failed" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "FileNotFoundError" not in captured_io.err
    assert "Juliet testcases directory not found" not in captured_io.err
    assert "SECRET_JULIET_ROOT_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(secret_root) not in captured_io.err
    assert "SECRET_OUTPUT_BENCHMARK_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_benchmark_exception_fails_without_echo_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    output_path = tmp_path / "SECRET_OUTPUT_BENCHMARK_EXCEPTION_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_error = "SECRET_BENCHMARK_EXECUTION_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"calls": 0}

    async def failing_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        raise ValueError(secret_error)

    monkeypatch.setattr(juliet_runner, "run_benchmark", failing_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert not output_path.exists()
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" not in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    assert "benchmark execution failed" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "ValueError" not in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_OUTPUT_BENCHMARK_EXCEPTION_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_markdown_report_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    class FakeBenchmarkResult:
        def to_dict(self) -> dict[str, Any]:
            return {"results": {}, "summary": {"overallRecall": 0}}

        def to_markdown(self, show_rules: bool = False) -> str:
            del show_rules
            raise ValueError("SECRET_MARKDOWN_REPORT_ERROR_SHOULD_NOT_LEAK")

    baseline_path = tmp_path / "SECRET_BASELINE_MARKDOWN_PATH_SHOULD_NOT_LEAK.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    output_path = tmp_path / "SECRET_OUTPUT_MARKDOWN_PATH_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {"calls": 0}

    async def fake_run_benchmark(**kwargs: Any) -> FakeBenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return FakeBenchmarkResult()

    def fail_if_compared(*args: Any, **kwargs: Any) -> None:
        pytest.fail(f"compare_from_files should not run after markdown failure: {args} {kwargs}")

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fail_if_compared)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert json.loads(output_path.read_text())["julietPath"] == "<JULIET_ROOT>/C"
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" not in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    assert "markdown report failed" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "ValueError" not in captured_io.err
    assert "SECRET_MARKDOWN_REPORT_ERROR_SHOULD_NOT_LEAK" not in captured_io.err
    assert "SECRET_BASELINE_MARKDOWN_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(baseline_path) not in captured_io.err
    assert "SECRET_OUTPUT_MARKDOWN_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_output_data_build_failure_without_echo_or_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    class FakeBenchmarkResult:
        def to_dict(self) -> dict[str, Any]:
            raise ValueError("SECRET_OUTPUT_DATA_BUILD_ERROR_SHOULD_NOT_LEAK")

        def to_markdown(self, show_rules: bool = False) -> str:
            del show_rules
            pytest.fail("to_markdown should not run after output-data build failure")

    baseline_path = tmp_path / "SECRET_BASELINE_OUTPUT_DATA_PATH_SHOULD_NOT_LEAK.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    output_path = tmp_path / "SECRET_OUTPUT_DATA_PATH_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {"calls": 0}

    async def fake_run_benchmark(**kwargs: Any) -> FakeBenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return FakeBenchmarkResult()

    def fail_if_compared(*args: Any, **kwargs: Any) -> None:
        pytest.fail(f"compare_from_files should not run after output-data build failure: {args} {kwargs}")

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fail_if_compared)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert not output_path.exists()
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" not in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    assert "benchmark report build failed" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "ValueError" not in captured_io.err
    assert "SECRET_OUTPUT_DATA_BUILD_ERROR_SHOULD_NOT_LEAK" not in captured_io.err
    assert "SECRET_BASELINE_OUTPUT_DATA_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(baseline_path) not in captured_io.err
    assert "SECRET_OUTPUT_DATA_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_output_data_non_mapping_failure_without_echo_or_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    class FakeBenchmarkResult:
        def to_dict(self) -> list[str]:
            return ["SECRET_OUTPUT_DATA_NON_MAPPING_SHOULD_NOT_LEAK"]

        def to_markdown(self, show_rules: bool = False) -> str:
            del show_rules
            pytest.fail("to_markdown should not run after non-mapping output-data failure")

    baseline_path = tmp_path / "SECRET_BASELINE_OUTPUT_DATA_SHAPE_PATH_SHOULD_NOT_LEAK.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    output_path = tmp_path / "SECRET_OUTPUT_DATA_SHAPE_PATH_SHOULD_NOT_LEAK" / "result.json"
    captured: dict[str, Any] = {"calls": 0}

    async def fake_run_benchmark(**kwargs: Any) -> FakeBenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return FakeBenchmarkResult()

    def fail_if_compared(*args: Any, **kwargs: Any) -> None:
        pytest.fail(f"compare_from_files should not run after output-data shape failure: {args} {kwargs}")

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fail_if_compared)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert not output_path.exists()
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" not in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    assert "benchmark report build failed" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "TypeError" not in captured_io.err
    assert "SECRET_OUTPUT_DATA_NON_MAPPING_SHOULD_NOT_LEAK" not in captured_io.err
    assert "SECRET_BASELINE_OUTPUT_DATA_SHAPE_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(baseline_path) not in captured_io.err
    assert "SECRET_OUTPUT_DATA_SHAPE_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_stdout_json_serialization_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    class SECRET_STDOUT_JSON_ERROR_SHOULD_NOT_LEAK:
        pass

    class FakeBenchmarkResult:
        def to_dict(self) -> dict[str, Any]:
            return {"nonSerializable": SECRET_STDOUT_JSON_ERROR_SHOULD_NOT_LEAK()}

        def to_markdown(self, show_rules: bool = False) -> str:
            del show_rules
            return "# SAST Runner Benchmark Results\n\nsynthetic markdown"

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    captured: dict[str, Any] = {"calls": 0}

    async def fake_run_benchmark(**kwargs: Any) -> FakeBenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return FakeBenchmarkResult()

    def fail_if_compared(*args: Any, **kwargs: Any) -> None:
        pytest.fail(f"compare_from_files should not run after stdout JSON failure: {args} {kwargs}")

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fail_if_compared)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    _assert_juliet_cli_error_payload(
        captured_io.err,
        error="stdout JSON write failed",
        reason_code="JULIET_STDOUT_JSON_WRITE_FAILED",
        stage="output",
    )
    assert "stdout JSON write failed" in captured_io.err
    assert "SECRET_STDOUT_JSON_ERROR_SHOULD_NOT_LEAK" not in captured_io.err


def test_juliet_cli_stdout_json_separator_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import builtins
    import benchmark.compare as compare_module
    import benchmark.juliet_runner as juliet_runner

    class FakeBenchmarkResult:
        def to_dict(self) -> dict[str, Any]:
            return {"results": {}, "summary": {"overallRecall": 0}}

        def to_markdown(self, show_rules: bool = False) -> str:
            del show_rules
            return "# SAST Runner Benchmark Results\n\nsynthetic markdown"

    baseline_path = tmp_path / "SECRET_BASELINE_STDOUT_SEPARATOR_PATH_SHOULD_NOT_LEAK.json"
    baseline_path.write_text('{"results": {}, "summary": {"overallRecall": 0}}')
    secret_error = "SECRET_STDOUT_SEPARATOR_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"calls": 0}
    print_calls = {"count": 0}

    async def fake_run_benchmark(**kwargs: Any) -> FakeBenchmarkResult:
        captured["calls"] += 1
        captured["kwargs"] = kwargs
        return FakeBenchmarkResult()

    def fail_if_compared(*args: Any, **kwargs: Any) -> None:
        pytest.fail(f"compare_from_files should not run after stdout separator failure: {args} {kwargs}")

    original_print = builtins.print

    def failing_print(*args: Any, **kwargs: Any) -> None:
        print_calls["count"] += 1
        if print_calls["count"] == 3:
            raise OSError(secret_error)
        return original_print(*args, **kwargs)

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(compare_module, "compare_from_files", fail_if_compared)
    monkeypatch.setattr(builtins, "print", failing_print)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--baseline",
            str(baseline_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured["calls"] == 1
    assert print_calls["count"] == 3
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    assert "stdout JSON write failed" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "OSError" not in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_BASELINE_STDOUT_SEPARATOR_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(baseline_path) not in captured_io.err


def test_juliet_cli_directory_output_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    output_path = tmp_path / "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK"
    output_path.mkdir()
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    stderr = capsys.readouterr().err
    assert "invalid output artifact" in stderr
    assert "SECRET_OUTPUT_DIR_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


def test_juliet_cli_output_parent_file_fails_before_execution_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    parent_path = tmp_path / "SECRET_OUTPUT_PARENT_SHOULD_NOT_LEAK"
    parent_path.write_text("not a directory")
    output_path = parent_path / "result.json"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    stderr = capsys.readouterr().err
    assert "invalid output artifact" in stderr
    assert "SECRET_OUTPUT_PARENT_SHOULD_NOT_LEAK" not in stderr
    assert str(output_path) not in stderr


@pytest.mark.parametrize("probe", ["output_exists", "parent_exists"])
def test_juliet_cli_output_artifact_probe_failure_without_echo(
    probe: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.juliet_runner as juliet_runner

    output_path = tmp_path / "SECRET_OUTPUT_PROBE_PATH_SHOULD_NOT_LEAK" / "result.json"
    secret_error = "SECRET_OUTPUT_PROBE_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    original_exists = Path.exists

    def failing_exists(self: Path) -> bool:
        if probe == "output_exists" and self == output_path:
            raise OSError(secret_error)
        if probe == "parent_exists" and self == output_path.parent:
            raise OSError(secret_error)
        return original_exists(self)

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(Path, "exists", failing_exists)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        juliet_runner.main()

    assert excinfo.value.code == 2
    assert captured == {}
    assert not original_exists(output_path)
    captured_io = capsys.readouterr()
    assert "# SAST Runner Benchmark Results" not in captured_io.out
    assert '"timestamp"' not in captured_io.out
    assert '"julietPath"' not in captured_io.out
    assert "invalid output artifact" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "OSError" not in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_OUTPUT_PROBE_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_juliet_cli_existing_output_file_remains_overwritable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmark.juliet_runner as juliet_runner

    output_path = tmp_path / "result.json"
    output_path.write_text("stale")
    captured: dict[str, Any] = {}

    async def fake_run_benchmark(**kwargs: Any) -> BenchmarkResult:
        captured.update(kwargs)
        return BenchmarkResult()

    monkeypatch.setattr(juliet_runner, "run_benchmark", fake_run_benchmark)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "juliet_runner",
            "--juliet-path",
            str(tmp_path / "juliet-root"),
            "--output",
            str(output_path),
        ],
    )

    juliet_runner.main()

    assert captured["juliet_root"] == tmp_path / "juliet-root"
    assert output_path.is_file()
    payload = json.loads(output_path.read_text())
    assert payload["julietPath"] == "<JULIET_ROOT>/C"
