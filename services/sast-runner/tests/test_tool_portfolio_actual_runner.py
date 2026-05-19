from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from app.errors import RequiredToolUnavailableError
from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.response import ExecutionReport, FindingsFilterInfo, SdkResolutionInfo, ToolExecutionResult
from benchmark.tool_portfolio_acquisition_manifest import ACQUISITION_SCHEMA_VERSION, manifest_checksum
from benchmark.tool_portfolio_actual_runner import (
    _load_json_object,
    build_actual_tool_portfolio_report,
    main as actual_runner_main,
    stage_case_only_corpus,
)
from benchmark.tool_portfolio_experiment_manifest import CORPUS_SCHEMA_VERSION, required_current_six_configs


def _sha256_text(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stderr_payload(stderr: str) -> dict[str, Any]:
    payload = json.loads(stderr.strip())
    assert set(payload) == {"error", "reasonCode", "stage"}
    return payload


def _acquisition(root: Path, *, acquisition_id: str = "juliet-c-cpp-1.3") -> dict[str, Any]:
    return {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "acquisitionId": acquisition_id,
        "sourceName": acquisition_id,
        "sourceUrl": f"local://{acquisition_id}",
        "sourceVersion": "test",
        "licenseOrRedistributionNote": "test fixture",
        "downloadedAt": "2026-05-13",
        "archiveChecksum": "sha256:" + "a" * 64,
        "extractionRootChecksum": "sha256:" + "b" * 64,
        "localPath": str(root),
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }


def _case(case_id: str, *, source_path: str, split: str, acquisition: dict[str, Any]) -> dict[str, Any]:
    return {
        "caseId": case_id,
        "targetId": f"{case_id}-target",
        "lineageId": case_id,
        "sliceKind": "juliet-controlled-positive",
        "split": split,
        "language": "c",
        "sourceArtifact": "Juliet C/C++ 1.3",
        "acquisitionId": acquisition["acquisitionId"],
        "acquisitionManifestChecksum": manifest_checksum(acquisition),
        "sourceRef": f"{acquisition['acquisitionId']}:{source_path}",
        "sourcePath": source_path,
        "checksum": _sha256_text(f"int {case_id}(void) {{ return 0; }}\n"),
        "expected": {
            "targetId": f"{case_id}-target",
            "granularity": "sink-line",
            "cweId": "CWE-121",
            "polarity": "positive",
            "locations": [{"file": source_path, "line": 1, "role": "sink"}],
            "functionRegion": {"function": case_id, "startLine": 1, "endLine": 1},
            "allowedMatchWindows": {"lineDelta": 5, "functionFallback": False},
        },
        "buildContext": {"requiresCompileCommands": False, "compileCommandsFixture": None, "defines": [], "includePaths": []},
        "notes": [],
    }


def _fixture_bundle(tmp_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source_root = tmp_path / "source" / "juliet"
    (source_root / "src").mkdir(parents=True)
    files = {
        "src/validation.c": "int validation_case(void) { return 0; }\n",
        "src/test.c": "int test_case(void) { return 0; }\n",
        "src/not-in-manifest.c": "int should_not_be_scanned(void) { return 0; }\n",
    }
    for relative, body in files.items():
        (source_root / relative).write_text(body, encoding="utf-8")

    acquisition = _acquisition(source_root)
    validation = _case("validation_case", source_path="src/validation.c", split="validation", acquisition=acquisition)
    test = _case("test_case", source_path="src/test.c", split="test", acquisition=acquisition)
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [validation, test],
    }
    return corpus, [acquisition]


def test_actual_runner_json_loader_rejects_missing_file_without_raw_path_echo(tmp_path: Path) -> None:
    missing_path = tmp_path / "SECRET_ACTUAL_JSON_PATH_SHOULD_NOT_LEAK.json"

    with pytest.raises(ValueError) as excinfo:
        _load_json_object(missing_path)

    message = str(excinfo.value)
    assert "JSON input could not be read" in message
    assert str(missing_path) not in message
    assert "SECRET_ACTUAL_JSON_PATH_SHOULD_NOT_LEAK" not in message
    assert excinfo.value.__cause__ is None


def test_actual_runner_json_loader_rejects_malformed_json_without_raw_content_echo(tmp_path: Path) -> None:
    malformed_path = tmp_path / "malformed.json"
    secret_content = "SECRET_ACTUAL_JSON_CONTENT_SHOULD_NOT_LEAK"
    malformed_path.write_text("{ " + secret_content, encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        _load_json_object(malformed_path)

    message = str(excinfo.value)
    assert "JSON input is malformed" in message
    assert secret_content not in message
    assert excinfo.value.__cause__ is None


def test_actual_runner_json_loader_rejects_non_object_without_raw_path_echo(tmp_path: Path) -> None:
    json_path = tmp_path / "SECRET_ACTUAL_NON_OBJECT_PATH_SHOULD_NOT_LEAK.json"
    json_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        _load_json_object(json_path)

    message = str(excinfo.value)
    assert "JSON input must be an object" in message
    assert str(json_path) not in message
    assert "SECRET_ACTUAL_NON_OBJECT_PATH_SHOULD_NOT_LEAK" not in message


def test_actual_runner_cli_input_failure_does_not_raise_or_echo_missing_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_path = tmp_path / "SECRET_ACTUAL_CLI_PATH_SHOULD_NOT_LEAK.json"
    acquisition_path = tmp_path / "acquisition.json"
    acquisition_path.write_text("{}", encoding="utf-8")
    output_path = tmp_path / "report.json"
    work_dir = tmp_path / "work"

    exit_code = actual_runner_main([
        "--corpus-manifest",
        str(missing_path),
        "--acquisition-manifest",
        str(acquisition_path),
        "--output",
        str(output_path),
        "--work-dir",
        str(work_dir),
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "input validation failed" in captured.err
    assert "SECRET_ACTUAL_CLI_PATH_SHOULD_NOT_LEAK" not in captured.err
    assert str(missing_path) not in captured.err


def test_actual_runner_cli_input_failure_does_not_raise_or_echo_malformed_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_content = "SECRET_ACTUAL_CLI_CONTENT_SHOULD_NOT_LEAK"
    corpus_path = tmp_path / "corpus.json"
    acquisition_path = tmp_path / "acquisition.json"
    corpus_path.write_text("{ " + secret_content, encoding="utf-8")
    acquisition_path.write_text("{}", encoding="utf-8")
    output_path = tmp_path / "report.json"
    work_dir = tmp_path / "work"

    exit_code = actual_runner_main([
        "--corpus-manifest",
        str(corpus_path),
        "--acquisition-manifest",
        str(acquisition_path),
        "--output",
        str(output_path),
        "--work-dir",
        str(work_dir),
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "input validation failed" in captured.err
    assert secret_content not in captured.err


def test_actual_runner_cli_invalid_timeout_fails_before_file_reads_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    secret_timeout = "SECRET_ACTUAL_TIMEOUT_SHOULD_NOT_LEAK"
    output_path = tmp_path / "SECRET_ACTUAL_TIMEOUT_OUTPUT_SHOULD_NOT_LEAK.json"

    def fail_if_loaded(path: Path) -> dict[str, Any]:
        pytest.fail(f"_load_json_object should not be called for invalid timeout: {path}")

    monkeypatch.setattr(actual_module, "_load_json_object", fail_if_loaded)

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "SECRET_CORPUS_PATH_SHOULD_NOT_LEAK.json"),
        "--acquisition-manifest",
        str(tmp_path / "SECRET_ACQUISITION_PATH_SHOULD_NOT_LEAK.json"),
        "--output",
        str(output_path),
        "--work-dir",
        str(tmp_path / "SECRET_WORK_DIR_SHOULD_NOT_LEAK"),
        "--timeout",
        secret_timeout,
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert not output_path.exists()
    assert captured.out == ""
    assert "input validation failed" in captured.err
    assert _stderr_payload(captured.err) == {
        "error": "input validation failed",
        "reasonCode": "ACTUAL_RUN_CLI_INPUT_INVALID",
        "stage": "input",
    }
    assert "usage:" not in captured.err
    assert "invalid int value" not in captured.err
    assert "SystemExit" not in captured.err
    assert secret_timeout not in captured.err
    assert "SECRET_CORPUS_PATH_SHOULD_NOT_LEAK" not in captured.err
    assert "SECRET_ACQUISITION_PATH_SHOULD_NOT_LEAK" not in captured.err
    assert "SECRET_ACTUAL_TIMEOUT_OUTPUT_SHOULD_NOT_LEAK" not in captured.err
    assert "SECRET_WORK_DIR_SHOULD_NOT_LEAK" not in captured.err
    assert str(output_path) not in captured.err


def test_actual_runner_cli_invalid_phase_fails_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    secret_phase = "SECRET_ACTUAL_PHASE_SHOULD_NOT_LEAK"

    def fail_if_loaded(path: Path) -> dict[str, Any]:
        pytest.fail(f"_load_json_object should not be called for invalid phase: {path}")

    monkeypatch.setattr(actual_module, "_load_json_object", fail_if_loaded)

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--acquisition-manifest",
        str(tmp_path / "acquisition.json"),
        "--output",
        str(tmp_path / "report.json"),
        "--work-dir",
        str(tmp_path / "work"),
        "--phase",
        secret_phase,
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "input validation failed" in captured.err
    assert _stderr_payload(captured.err) == {
        "error": "input validation failed",
        "reasonCode": "ACTUAL_RUN_CLI_INPUT_INVALID",
        "stage": "input",
    }
    assert "usage:" not in captured.err
    assert "invalid choice" not in captured.err
    assert "SystemExit" not in captured.err
    assert secret_phase not in captured.err


def test_actual_runner_cli_valid_timeout_preserves_execution_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    captured: dict[str, Any] = {}

    def fake_load_json_object(path: Path) -> dict[str, Any]:
        return {"loadedFrom": path.name}

    async def fake_build_actual_tool_portfolio_report(**kwargs: Any) -> dict[str, Any]:
        captured["kwargs"] = kwargs
        return {"qualityGate": {"status": "not_decision_grade"}}

    def fake_write_experiment_report(report: dict[str, Any], output: str) -> None:
        captured["report"] = report
        captured["output"] = output

    monkeypatch.setattr(actual_module, "_load_json_object", fake_load_json_object)
    monkeypatch.setattr(actual_module, "build_actual_tool_portfolio_report", fake_build_actual_tool_portfolio_report)
    monkeypatch.setattr(actual_module, "write_experiment_report", fake_write_experiment_report)

    output_path = tmp_path / "report.json"

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--acquisition-manifest",
        str(tmp_path / "acquisition.json"),
        "--output",
        str(output_path),
        "--work-dir",
        str(tmp_path / "work"),
        "--timeout",
        "45",
    ])

    assert exit_code == 2
    assert captured["kwargs"]["timeout"] == 45
    assert captured["output"] == str(output_path)
    assert captured["report"] == {"qualityGate": {"status": "not_decision_grade"}}


def test_actual_runner_cli_output_write_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    report = {"qualityGate": {"status": "pass"}}
    output_path = tmp_path / "SECRET_ACTUAL_OUTPUT_PATH_SHOULD_NOT_LEAK" / "report.json"
    secret_error = "SECRET_ACTUAL_OUTPUT_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"build_calls": 0, "writer_calls": 0}

    def fake_load_json_object(path: Path) -> dict[str, Any]:
        return {"loadedFrom": path.name}

    async def fake_build_actual_tool_portfolio_report(**kwargs: Any) -> dict[str, Any]:
        captured["build_calls"] += 1
        captured["kwargs"] = kwargs
        return report

    def failing_write_experiment_report(payload: dict[str, Any], output: str) -> None:
        captured["writer_calls"] += 1
        captured["report"] = payload
        captured["output"] = output
        raise OSError(secret_error)

    monkeypatch.setattr(actual_module, "_load_json_object", fake_load_json_object)
    monkeypatch.setattr(actual_module, "build_actual_tool_portfolio_report", fake_build_actual_tool_portfolio_report)
    monkeypatch.setattr(actual_module, "write_experiment_report", failing_write_experiment_report)

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--acquisition-manifest",
        str(tmp_path / "acquisition.json"),
        "--output",
        str(output_path),
        "--work-dir",
        str(tmp_path / "work"),
    ])

    assert exit_code == 1
    assert captured["build_calls"] == 1
    assert captured["writer_calls"] == 1
    assert captured["report"] == report
    assert captured["output"] == str(output_path)
    captured_io = capsys.readouterr()
    assert captured_io.out == ""
    assert "output write failed" in captured_io.err
    assert _stderr_payload(captured_io.err) == {
        "error": "output write failed",
        "reasonCode": "ACTUAL_RUN_OUTPUT_WRITE_FAILED",
        "stage": "output",
    }
    assert "Traceback" not in captured_io.err
    assert "OSError" not in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_ACTUAL_OUTPUT_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_actual_runner_cli_output_serialization_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    report = {"qualityGate": {"status": "pass"}}
    output_path = tmp_path / "SECRET_ACTUAL_SERIALIZATION_OUTPUT_PATH_SHOULD_NOT_LEAK" / "report.json"
    secret_error = "SECRET_ACTUAL_OUTPUT_OBJECT_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"build_calls": 0, "writer_calls": 0}

    def fake_load_json_object(path: Path) -> dict[str, Any]:
        return {"loadedFrom": path.name}

    async def fake_build_actual_tool_portfolio_report(**kwargs: Any) -> dict[str, Any]:
        captured["build_calls"] += 1
        captured["kwargs"] = kwargs
        return report

    def failing_write_experiment_report(payload: dict[str, Any], output: str) -> None:
        captured["writer_calls"] += 1
        captured["report"] = payload
        captured["output"] = output
        raise TypeError(secret_error)

    monkeypatch.setattr(actual_module, "_load_json_object", fake_load_json_object)
    monkeypatch.setattr(actual_module, "build_actual_tool_portfolio_report", fake_build_actual_tool_portfolio_report)
    monkeypatch.setattr(actual_module, "write_experiment_report", failing_write_experiment_report)

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--acquisition-manifest",
        str(tmp_path / "acquisition.json"),
        "--output",
        str(output_path),
        "--work-dir",
        str(tmp_path / "work"),
    ])

    assert exit_code == 1
    assert captured["build_calls"] == 1
    assert captured["writer_calls"] == 1
    assert captured["report"] == report
    assert captured["output"] == str(output_path)
    captured_io = capsys.readouterr()
    assert captured_io.out == ""
    assert "output write failed" in captured_io.err
    assert "Traceback" not in captured_io.err
    assert "TypeError" not in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_ACTUAL_SERIALIZATION_OUTPUT_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_actual_runner_cli_broken_stderr_after_output_failure_without_raw_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    secret_write_error = "SECRET_ACTUAL_OUTPUT_FAILURE_SHOULD_NOT_LEAK"
    secret_stderr_error = "SECRET_ACTUAL_STDERR_FAILURE_SHOULD_NOT_LEAK"

    class FailingStderr:
        def write(self, text: str) -> int:
            del text
            raise OSError(secret_stderr_error)

        def flush(self) -> None:
            return None

    def fake_load_json_object(path: Path) -> dict[str, Any]:
        return {"loadedFrom": path.name}

    async def fake_build_actual_tool_portfolio_report(**kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {"qualityGate": {"status": "pass"}}

    def failing_write_experiment_report(payload: dict[str, Any], output: str) -> None:
        del payload, output
        raise TypeError(secret_write_error)

    monkeypatch.setattr(actual_module, "_load_json_object", fake_load_json_object)
    monkeypatch.setattr(actual_module, "build_actual_tool_portfolio_report", fake_build_actual_tool_portfolio_report)
    monkeypatch.setattr(actual_module, "write_experiment_report", failing_write_experiment_report)
    monkeypatch.setattr(actual_module.sys, "stderr", FailingStderr())

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--acquisition-manifest",
        str(tmp_path / "acquisition.json"),
        "--output",
        str(tmp_path / "report.json"),
        "--work-dir",
        str(tmp_path / "work"),
    ])

    captured_io = capsys.readouterr()
    assert exit_code == 1
    assert captured_io.out == ""
    assert secret_write_error not in captured_io.err
    assert secret_stderr_error not in captured_io.err


def test_actual_runner_cli_report_build_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    output_path = tmp_path / "SECRET_ACTUAL_BUILD_OUTPUT_PATH_SHOULD_NOT_LEAK" / "report.json"
    secret_error = "SECRET_ACTUAL_BUILD_ERROR_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"build_calls": 0, "writer_calls": 0}

    def fake_load_json_object(path: Path) -> dict[str, Any]:
        return {"loadedFrom": path.name}

    async def failing_build_actual_tool_portfolio_report(**kwargs: Any) -> dict[str, Any]:
        captured["build_calls"] += 1
        captured["kwargs"] = kwargs
        raise ValueError(secret_error)

    def fail_if_written(*args: Any, **kwargs: Any) -> None:
        captured["writer_calls"] += 1
        pytest.fail(f"write_experiment_report should not run after report-build failure: {args} {kwargs}")

    monkeypatch.setattr(actual_module, "_load_json_object", fake_load_json_object)
    monkeypatch.setattr(actual_module, "build_actual_tool_portfolio_report", failing_build_actual_tool_portfolio_report)
    monkeypatch.setattr(actual_module, "write_experiment_report", fail_if_written)

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--acquisition-manifest",
        str(tmp_path / "acquisition.json"),
        "--output",
        str(output_path),
        "--work-dir",
        str(tmp_path / "work"),
    ])

    assert exit_code == 1
    assert captured["build_calls"] == 1
    assert captured["writer_calls"] == 0
    captured_io = capsys.readouterr()
    assert captured_io.out == ""
    assert "actual run failed" in captured_io.err
    assert _stderr_payload(captured_io.err) == {
        "error": "actual run failed",
        "reasonCode": "ACTUAL_RUN_FAILED",
        "stage": "run",
    }
    assert "Traceback" not in captured_io.err
    assert "ValueError" not in captured_io.err
    assert secret_error not in captured_io.err
    assert "SECRET_ACTUAL_BUILD_OUTPUT_PATH_SHOULD_NOT_LEAK" not in captured_io.err
    assert str(output_path) not in captured_io.err


def test_actual_runner_cli_broken_stderr_after_report_build_failure_without_raw_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import benchmark.tool_portfolio_actual_runner as actual_module

    secret_build_error = "SECRET_ACTUAL_BUILD_FAILURE_SHOULD_NOT_LEAK"
    secret_stderr_error = "SECRET_ACTUAL_BUILD_STDERR_FAILURE_SHOULD_NOT_LEAK"
    captured: dict[str, Any] = {"writer_calls": 0}

    class FailingStderr:
        def write(self, text: str) -> int:
            del text
            raise OSError(secret_stderr_error)

        def flush(self) -> None:
            return None

    def fake_load_json_object(path: Path) -> dict[str, Any]:
        return {"loadedFrom": path.name}

    async def failing_build_actual_tool_portfolio_report(**kwargs: Any) -> dict[str, Any]:
        del kwargs
        raise RuntimeError(secret_build_error)

    def fail_if_written(*args: Any, **kwargs: Any) -> None:
        captured["writer_calls"] += 1
        pytest.fail(f"write_experiment_report should not run after report-build failure: {args} {kwargs}")

    monkeypatch.setattr(actual_module, "_load_json_object", fake_load_json_object)
    monkeypatch.setattr(actual_module, "build_actual_tool_portfolio_report", failing_build_actual_tool_portfolio_report)
    monkeypatch.setattr(actual_module, "write_experiment_report", fail_if_written)
    monkeypatch.setattr(actual_module.sys, "stderr", FailingStderr())

    exit_code = actual_module.main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--acquisition-manifest",
        str(tmp_path / "acquisition.json"),
        "--output",
        str(tmp_path / "report.json"),
        "--work-dir",
        str(tmp_path / "work"),
    ])

    captured_io = capsys.readouterr()
    assert exit_code == 1
    assert captured["writer_calls"] == 0
    assert captured_io.out == ""
    assert secret_build_error not in captured_io.err
    assert secret_stderr_error not in captured_io.err


def _execution(tools: list[str], *, status: str = "ok", degraded: bool = False) -> ExecutionReport:
    return ExecutionReport(
        toolsRun=list(tools),
        toolResults={
            tool: ToolExecutionResult(
                status=status,
                findingsCount=0,
                elapsedMs=1,
                degraded=degraded,
                degradeReasons=(["test-degraded"] if degraded else None),
                version="1.0.0",
            )
            for tool in tools
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=degraded,
        degradeReasons=(["test-degraded"] if degraded else []),
    )


class FakeOrchestrator:
    def __init__(
        self,
        *,
        raise_required_unavailable: bool = False,
        subset_skips: bool = False,
        degrade_single_tool: str | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.raise_required_unavailable = raise_required_unavailable
        self.subset_skips = subset_skips
        self.degrade_single_tool = degrade_single_tool

    async def check_tools(self, *, force: bool = False) -> dict[str, dict[str, Any]]:
        return {tool: {"available": True, "version": "1.0.0", "probeReason": None} for tool in ALL_TOOLS}

    async def run(self, *, scan_dir: Path, source_files: list[str], tools: list[str], **kwargs: Any) -> tuple[list[Any], ExecutionReport]:
        self.calls.append({
            "scan_dir": scan_dir,
            "source_files": list(source_files),
            "tools": list(tools),
            "profile": kwargs.get("profile"),
        })
        if self.raise_required_unavailable:
            raise RequiredToolUnavailableError(
                "required tool unavailable",
                execution=_execution(list(ALL_TOOLS), status="skipped", degraded=True),
                tool_failures=[{"toolId": "semgrep", "reasonCode": "runtime-tool-missing"}],
            )
        execution = _execution(list(tools))
        if self.degrade_single_tool is not None and list(tools) == [self.degrade_single_tool]:
            execution.tool_results[self.degrade_single_tool] = ToolExecutionResult(
                status="partial",
                findingsCount=0,
                elapsedMs=1,
                degraded=True,
                degradeReasons=["comparative-fixture-degraded"],
                version="1.0.0",
            )
            execution.degraded = True
            execution.degrade_reasons = ["comparative-fixture-degraded"]
        if self.subset_skips and set(tools) != set(ALL_TOOLS):
            for tool in ALL_TOOLS:
                if tool not in tools:
                    execution.tool_results[tool] = ToolExecutionResult(
                        status="skipped",
                        findingsCount=0,
                        elapsedMs=0,
                        skipReason="operator-requested-subset",
                        version="1.0.0",
                    )
        return [], execution


def test_stage_case_only_corpus_copies_only_manifest_sources_and_repins_checksums(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)

    staged = stage_case_only_corpus(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=tmp_path / "stage",
    )

    staged_acquisition = staged["acquisitionManifests"][0]
    staged_root = Path(staged_acquisition["localPath"])
    assert (staged_root / "src" / "validation.c").is_file()
    assert (staged_root / "src" / "test.c").is_file()
    assert not (staged_root / "src" / "not-in-manifest.c").exists()
    assert staged["corpusManifest"]["cases"][0]["sourcePath"] == "src/validation.c"
    assert staged["corpusManifest"]["cases"][0]["acquisitionManifestChecksum"] == manifest_checksum(staged_acquisition)


def test_stage_case_only_corpus_removes_stale_files_when_reusing_work_dir(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    work_dir = tmp_path / "stage"
    stage_case_only_corpus(corpus_manifest=corpus, acquisition_manifests=acquisitions, work_dir=work_dir)
    stale = work_dir / "staged-cases" / "juliet-c-cpp-1.3" / "src" / "stale.c"
    stale.write_text("int stale(void) { return 0; }\n", encoding="utf-8")

    stage_case_only_corpus(corpus_manifest=corpus, acquisition_manifests=acquisitions, work_dir=work_dir)

    assert not stale.exists()


def test_stage_case_only_corpus_emits_absolute_staged_local_paths_for_relative_work_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    monkeypatch.chdir(tmp_path)

    staged = stage_case_only_corpus(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=Path("relative-stage"),
    )

    staged_path = Path(staged["acquisitionManifests"][0]["localPath"])
    assert staged_path.is_absolute()
    assert staged_path == (tmp_path / "relative-stage" / "staged-cases" / acquisitions[0]["acquisitionId"]).resolve()
    assert staged_path.is_dir()


def test_actual_runner_supports_relative_local_path_with_explicit_base_path(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    (base_support := tmp_path / "source" / "juliet" / "C" / "testcasesupport").mkdir(parents=True)
    base = tmp_path / "source"
    relative_acquisition = {
        **acquisitions[0],
        "localPath": "juliet",
    }
    relative_checksum = manifest_checksum(relative_acquisition)
    relative_corpus = {
        **corpus,
        "cases": [
            {**case, "acquisitionManifestChecksum": relative_checksum}
            for case in corpus["cases"]
        ],
    }
    orchestrator = FakeOrchestrator()

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=relative_corpus,
        acquisition_manifests=[relative_acquisition],
        corpus_readiness_base_path=base,
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    assert report["corpusReadinessGate"]["status"] == "available"
    assert orchestrator.calls
    assert all(
        call["profile"] is not None and str(base_support) in call["profile"].include_paths
        for call in orchestrator.calls
        if call["tools"]
    )
    assert all(
        call["profile"].sdk_resolution_mode == "none" and call["profile"].sdk_id is None
        for call in orchestrator.calls
        if call["profile"] is not None
    )


def test_stage_case_only_corpus_rejects_relative_local_path_without_explicit_base_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    monkeypatch.chdir(tmp_path / "source")
    relative_acquisition = {
        **acquisitions[0],
        "localPath": "juliet",
    }
    relative_checksum = manifest_checksum(relative_acquisition)
    relative_corpus = {
        **corpus,
        "cases": [
            {**case, "acquisitionManifestChecksum": relative_checksum}
            for case in corpus["cases"]
        ],
    }

    with pytest.raises(ValueError) as excinfo:
        stage_case_only_corpus(
            corpus_manifest=relative_corpus,
            acquisition_manifests=[relative_acquisition],
            work_dir=tmp_path / "stage",
        )

    message = str(excinfo.value)
    assert "explicit base path" in message
    assert "juliet" not in message
    assert str(tmp_path) not in message


def test_stage_case_only_corpus_rejects_relative_local_path_escape_without_exception_chain(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    secret_path = "SECRET_ACTUAL_BASE_ESCAPE_SHOULD_NOT_LEAK"
    base = tmp_path / "source"
    relative_acquisition = {
        **acquisitions[0],
        "localPath": f"../{secret_path}",
    }
    relative_checksum = manifest_checksum(relative_acquisition)
    relative_corpus = {
        **corpus,
        "cases": [
            {**case, "acquisitionManifestChecksum": relative_checksum}
            for case in corpus["cases"]
        ],
    }

    with pytest.raises(ValueError) as excinfo:
        stage_case_only_corpus(
            corpus_manifest=relative_corpus,
            acquisition_manifests=[relative_acquisition],
            work_dir=tmp_path / "stage",
            base_path=base,
        )

    message = str(excinfo.value)
    assert "relative acquisition localPath escapes base path" in message
    assert secret_path not in message
    assert str(tmp_path) not in message
    assert excinfo.value.__cause__ is None


def test_stage_case_only_corpus_rejects_symlink_source_escape_without_exception_chain(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    source_root = Path(acquisitions[0]["localPath"])
    secret_outside_root = tmp_path / "SECRET_ACTUAL_SOURCE_ESCAPE_SHOULD_NOT_LEAK"
    secret_outside_root.mkdir()
    (secret_outside_root / "outside.c").write_text("int outside(void) { return 0; }\n", encoding="utf-8")
    symlink_path = source_root / "link-outside"
    try:
        symlink_path.symlink_to(secret_outside_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unsupported in this environment: {exc}")
    escaped_case = {
        **corpus["cases"][0],
        "sourcePath": "link-outside/outside.c",
        "sourceRef": f"{acquisitions[0]['acquisitionId']}:link-outside/outside.c",
    }
    escaped_corpus = {
        **corpus,
        "cases": [escaped_case, corpus["cases"][1]],
    }

    with pytest.raises(ValueError) as excinfo:
        stage_case_only_corpus(
            corpus_manifest=escaped_corpus,
            acquisition_manifests=acquisitions,
            work_dir=tmp_path / "stage",
        )

    message = str(excinfo.value)
    assert "case sourcePath escapes acquisition root" in message
    assert "SECRET_ACTUAL_SOURCE_ESCAPE_SHOULD_NOT_LEAK" not in message
    assert str(secret_outside_root) not in message
    assert excinfo.value.__cause__ is None


def test_actual_runner_blocks_relative_local_path_without_base_before_scanning(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    relative_acquisition = {
        **acquisitions[0],
        "localPath": "juliet",
    }
    relative_checksum = manifest_checksum(relative_acquisition)
    relative_corpus = {
        **corpus,
        "cases": [
            {**case, "acquisitionManifestChecksum": relative_checksum}
            for case in corpus["cases"]
        ],
    }
    orchestrator = FakeOrchestrator()

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=relative_corpus,
        acquisition_manifests=[relative_acquisition],
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    assert orchestrator.calls == []
    assert report["corpusReadinessGate"]["status"] == "blocked"
    assert "LOCAL_CORPUS_BASE_PATH_REQUIRED" in report["corpusReadinessGate"]["reasonCodes"]
    assert report["qualityGate"]["status"] != "pass"


def test_actual_runner_relative_work_dir_keeps_staged_readiness_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    orchestrator = FakeOrchestrator()
    monkeypatch.chdir(tmp_path)

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=Path("relative-stage"),
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    assert orchestrator.calls
    assert report["corpusReadinessGate"]["status"] == "available"
    assert "LOCAL_CORPUS_BASE_PATH_REQUIRED" not in report["corpusReadinessGate"]["reasonCodes"]
    acquisition_status = report["corpusReadinessGate"]["acquisitionStatuses"]["juliet-c-cpp-1.3"]
    assert "localPath" not in acquisition_status
    assert "resolvedLocalPath" not in acquisition_status
    assert acquisition_status["localPathStatus"] == "available"
    assert acquisition_status["resolvedLocalPathStatus"] == "available"
    assert report["systemStabilityGate"]["status"] == "pass"
    assert report["qualityGate"]["status"] == "not_decision_grade"


def test_actual_runner_does_not_scan_when_readiness_is_blocked(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    acquisitions[0] = {**acquisitions[0], "localPath": str(tmp_path / "missing")}
    missing_checksum = manifest_checksum(acquisitions[0])
    corpus["cases"] = [
        {**case, "acquisitionManifestChecksum": missing_checksum}
        for case in corpus["cases"]
    ]
    orchestrator = FakeOrchestrator()

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    assert orchestrator.calls == []
    assert report["corpusReadinessGate"]["status"] == "blocked"
    assert report["qualityGate"]["status"] != "pass"


def test_actual_runner_emits_all_required_config_keys(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    orchestrator = FakeOrchestrator()

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    expected_configs = set(required_current_six_configs())
    assert set(report["toolSetConfigs"]) == expected_configs
    assert set(report["validationMetrics"]["byConfig"]) == expected_configs
    assert set(report["testMetrics"]["byConfig"]) == expected_configs


def test_actual_runner_top_level_system_gate_ignores_intentional_subset_skips(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    orchestrator = FakeOrchestrator(subset_skips=True)

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    assert report["systemStabilityGate"]["status"] == "pass"
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLDS_NON_DISCRIMINATING"]
    assert report["qualityGate"]["localQualityAssessment"]["thresholdProfile"]["intent"] == "runner-integrity-only"


def test_actual_runner_low_threshold_profile_with_no_findings_is_not_decision_grade(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    orchestrator = FakeOrchestrator(subset_skips=True)

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={
            "minimumTargetRecall": 0.0,
            "minimumFindingPrecision": 0.0,
            "maximumNegativeTargetFpr": 1.0,
            "requiredSplits": ["validation", "test"],
        },
    ))

    assert report["systemStabilityGate"]["status"] == "pass"
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLDS_NON_DISCRIMINATING"]
    assert report["qualityGate"]["localQualityAssessment"]["thresholdProfile"] == {
        "status": "not_decision_grade",
        "intent": "runner-integrity-only",
        "reasonCodes": ["QUALITY_THRESHOLDS_NON_DISCRIMINATING"],
        "nonDiscriminatingThresholdFields": [
            "minimumTargetRecall",
            "minimumFindingPrecision",
            "maximumNegativeTargetFpr",
        ],
    }


def test_actual_runner_captures_required_tool_unavailable_as_blocked_report(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    orchestrator = FakeOrchestrator(raise_required_unavailable=True)

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    assert report["systemStabilityGate"]["status"] == "fail"
    assert "REQUIRED_TOOL_INCOMPLETE" in report["systemStabilityGate"]["reasonCodes"]
    assert report["qualityGate"]["status"] == "blocked"


def test_actual_runner_marks_tool_contribution_not_run_when_comparative_config_degrades(tmp_path: Path) -> None:
    corpus, acquisitions = _fixture_bundle(tmp_path)
    orchestrator = FakeOrchestrator(degrade_single_tool="semgrep")

    report = asyncio.run(build_actual_tool_portfolio_report(
        corpus_manifest=corpus,
        acquisition_manifests=acquisitions,
        work_dir=tmp_path / "stage",
        orchestrator=orchestrator,
        thresholds={"minimumTargetRecall": 0.0, "requiredSplits": ["validation", "test"]},
    ))

    assert report["systemStabilityGate"]["status"] == "pass"
    assert report["actualRunCompleteness"]["status"] == "fail"
    assert report["actualRunCompleteness"]["failures"][0]["toolSetConfig"] == "single-tool:semgrep"
    contribution = report["toolContributionDiagnostics"]
    assert contribution["status"] == "not_run"
    assert contribution["reasonCodes"] == ["TOOL_CONTRIBUTION_COMPARATIVE_CONFIG_INCOMPLETE"]
    assert contribution["tools"] == []
