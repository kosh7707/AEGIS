"""벤치마크 인프라 단위 테스트 — metrics, compare."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from benchmark.metrics import BenchmarkResult, CWEMetrics, RuleMetrics, ToolMetrics
from benchmark.compare import compare


def _assert_compare_cli_error_payload(
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


# ──────────────────── ToolMetrics ────────────────────


class TestToolMetrics:
    def test_recall(self):
        tm = ToolMetrics(tool_name="cppcheck", tp=8, fn=2)
        assert tm.recall == pytest.approx(0.8)

    def test_noise_tracking(self):
        tm = ToolMetrics(tool_name="cppcheck", tp=8, fn=2, targeted_noise=10, portfolio_noise=5)
        assert tm.noise_findings == 15
        assert tm.targeted_noise == 10
        assert tm.portfolio_noise == 5

    def test_zero_division(self):
        tm = ToolMetrics(tool_name="x")
        assert tm.recall == 0.0

    def test_to_dict(self):
        d = ToolMetrics(tool_name="t", tp=5, fn=5, targeted_noise=7, portfolio_noise=3).to_dict()
        assert d["recall"] == 0.5
        assert d["noise"] == 10
        assert d["targetedNoise"] == 7
        assert d["portfolioNoise"] == 3
        assert "tp" in d


# ──────────────────── CWEMetrics ────────────────────


class TestCWEMetrics:
    def test_combined_recall(self):
        m = CWEMetrics(cwe="CWE-78", cwe_name="Cmd", total_files=10,
                       combined_tp=8, combined_fn=2, targeted_noise=20, portfolio_noise=10)
        assert m.combined_recall == pytest.approx(0.8)

    def test_noise_per_file(self):
        m = CWEMetrics(cwe="CWE-78", cwe_name="test", total_files=10,
                       targeted_noise=30, portfolio_noise=20)
        assert m.noise_per_file == pytest.approx(5.0)

    def test_noise_per_file_zero_files(self):
        m = CWEMetrics(cwe="CWE-78", cwe_name="test", total_files=0, targeted_noise=5)
        assert m.noise_per_file == 0.0

    def test_to_dict_includes_noise(self):
        m = CWEMetrics(cwe="CWE-78", cwe_name="test", total_files=10,
                       targeted_noise=30, portfolio_noise=20)
        d = m.to_dict()
        assert d["combined"]["noise"] == 50
        assert d["combined"]["targetedNoise"] == 30
        assert d["combined"]["portfolioNoise"] == 20
        assert d["combined"]["noisePerFile"] == 5.0
        assert d["combined"]["targetedNoisePerFile"] == 3.0

    def test_to_dict_does_not_echo_corpus_derived_cwe_name(self):
        m = CWEMetrics(
            cwe="CWE-121",
            cwe_name="SECRET_CWE_DIR_SUFFIX_SHOULD_NOT_LEAK",
            total_files=1,
        )
        d = m.to_dict()
        assert d["cweName"] == "Stack_Based_Buffer_Overflow"
        assert "SECRET_CWE_DIR_SUFFIX_SHOULD_NOT_LEAK" not in str(d)

    def test_to_dict_unknown_cwe_name_falls_back_to_cwe_id(self):
        m = CWEMetrics(
            cwe="CWE-999",
            cwe_name="SECRET_UNKNOWN_CWE_NAME_SHOULD_NOT_LEAK",
            total_files=1,
        )
        d = m.to_dict()
        assert d["cweName"] == "CWE-999"
        assert "SECRET_UNKNOWN_CWE_NAME_SHOULD_NOT_LEAK" not in str(d)

    def test_backward_compat_combined_noise(self):
        m = CWEMetrics(cwe="CWE-78", cwe_name="test", targeted_noise=15, portfolio_noise=5)
        assert m.combined_noise == 20

    def test_targeted_noise_per_file(self):
        m = CWEMetrics(cwe="CWE-78", cwe_name="test", total_files=10,
                       targeted_noise=30, portfolio_noise=20)
        assert m.targeted_noise_per_file == pytest.approx(3.0)

    def test_by_rule_in_dict(self):
        m = CWEMetrics(cwe="CWE-78", cwe_name="test")
        m.by_rule["flawfinder:gets"] = RuleMetrics(rule_id="flawfinder:gets", tool="flawfinder", tp=3, noise=0)
        d = m.to_dict()
        assert "byRule" in d
        assert d["byRule"]["flawfinder:gets"]["tp"] == 3


# ──────────────────── BenchmarkResult ────────────────────


class TestBenchmarkResult:
    def _make_result(self) -> BenchmarkResult:
        r = BenchmarkResult()
        r.cwe_results["CWE-78"] = CWEMetrics(
            cwe="CWE-78", cwe_name="Cmd", total_files=10,
            combined_tp=8, combined_fn=2, targeted_noise=20, portfolio_noise=10,
        )
        r.cwe_results["CWE-476"] = CWEMetrics(
            cwe="CWE-476", cwe_name="Null", total_files=5,
            combined_tp=5, combined_fn=0, targeted_noise=7, portfolio_noise=3,
        )
        return r

    def test_overall_recall(self):
        r = self._make_result()
        assert r.overall_recall == pytest.approx(13 / 15)

    def test_overall_noise_per_file(self):
        r = self._make_result()
        assert r.overall_noise_per_file == pytest.approx(40 / 15)

    def test_to_dict_summary(self):
        d = self._make_result().to_dict()
        s = d["summary"]
        assert s["totalTP"] == 13
        assert s["totalFN"] == 2
        assert s["totalNoise"] == 40
        assert s["totalTargetedNoise"] == 27
        assert s["totalPortfolioNoise"] == 13
        assert "overallNoisePerFile" in s

    def test_to_markdown(self):
        md = self._make_result().to_markdown()
        assert "Recall:" in md
        assert "Noise/File:" in md

    def test_to_markdown_with_rules(self):
        r = self._make_result()
        r.cwe_results["CWE-78"].by_rule["semgrep:cmd"] = RuleMetrics(
            rule_id="semgrep:cmd", tool="semgrep", tp=3, noise=1,
        )
        md = r.to_markdown(show_rules=True)
        assert "Per-Rule" in md
        assert "semgrep:cmd" in md


# ──────────────────── compare ────────────────────


class TestCompare:
    def _make_data(self, recall_78: float, recall_476: float) -> dict:
        return {
            "results": {
                "CWE-78": {"combined": {"recall": recall_78, "noisePerFile": 3.0}},
                "CWE-476": {"combined": {"recall": recall_476, "noisePerFile": 1.0}},
            },
            "summary": {
                "overallRecall": (recall_78 + recall_476) / 2,
            },
        }

    def test_no_change(self):
        data = self._make_data(0.8, 1.0)
        report = compare(data, data, "a", "b")
        assert len(report.regressions) == 0
        assert len(report.improvements) == 0

    def test_regression_detected(self):
        baseline = self._make_data(0.8, 1.0)
        current = self._make_data(0.5, 1.0)
        report = compare(baseline, current, "a", "b")
        assert len(report.regressions) == 1
        assert report.regressions[0].cwe == "CWE-78"
        assert report.has_regression(threshold=0.05)

    def test_improvement_detected(self):
        baseline = self._make_data(0.5, 0.8)
        current = self._make_data(0.8, 0.9)
        report = compare(baseline, current, "a", "b")
        assert len(report.improvements) == 2

    def test_to_markdown(self):
        baseline = self._make_data(0.8, 1.0)
        current = self._make_data(0.6, 1.0)
        report = compare(baseline, current, "base.json", "curr.json")
        md = report.to_markdown()
        assert "Regressions" in md

    def test_to_markdown_does_not_echo_comparison_paths(self):
        baseline = self._make_data(0.8, 1.0)
        current = self._make_data(0.6, 1.0)
        baseline_path = "/tmp/SECRET_BASELINE_PATH_SHOULD_NOT_LEAK.json"
        current_path = "/tmp/SECRET_CURRENT_PATH_SHOULD_NOT_LEAK.json"

        report = compare(baseline, current, baseline_path, current_path)
        md = report.to_markdown()

        assert "Baseline:" in md
        assert "Current:" in md
        assert baseline_path not in md
        assert current_path not in md
        assert "SECRET_BASELINE_PATH_SHOULD_NOT_LEAK" not in md
        assert "SECRET_CURRENT_PATH_SHOULD_NOT_LEAK" not in md

    def test_new_cwe_in_current(self):
        baseline = {"results": {}, "summary": {"overallRecall": 0}}
        current = self._make_data(0.8, 1.0)
        report = compare(baseline, current, "a", "b")
        assert len(report.improvements) == 2

    def test_threshold(self):
        baseline = self._make_data(0.8, 1.0)
        current = self._make_data(0.78, 1.0)
        report = compare(baseline, current, "a", "b")
        assert not report.has_regression(threshold=0.05)
        assert report.has_regression(threshold=0.01)

    def test_cli_missing_required_args_fails_without_argparse_echo(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        def fail_if_loaded(path_or_data):
            pytest.fail(f"_load_result should not be called for parser failure: {path_or_data}")

        monkeypatch.setattr(compare_module, "_load_result", fail_if_loaded)
        monkeypatch.setattr(sys, "argv", ["compare"])

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        captured_io = capsys.readouterr()
        assert excinfo.value.code == 2
        assert captured_io.out == ""
        _assert_compare_cli_error_payload(
            captured_io.err,
            error="invalid comparison arguments",
            reason_code="BENCHMARK_COMPARE_CLI_ARGUMENTS_INVALID",
            stage="input",
        )
        assert "invalid comparison arguments" in captured_io.err
        assert "usage:" not in captured_io.err
        assert "required" not in captured_io.err
        assert "--baseline" not in captured_io.err
        assert "--current" not in captured_io.err
        assert "SystemExit" not in captured_io.err

    def test_cli_unknown_arg_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_ARG_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "SECRET_CURRENT_ARG_PATH_SHOULD_NOT_LEAK.json"
        secret_flag = "--SECRET_COMPARE_FLAG_SHOULD_NOT_LEAK"

        def fail_if_loaded(path_or_data):
            pytest.fail(f"_load_result should not be called for parser failure: {path_or_data}")

        monkeypatch.setattr(compare_module, "_load_result", fail_if_loaded)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                secret_flag,
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        captured_io = capsys.readouterr()
        assert excinfo.value.code == 2
        assert captured_io.out == ""
        assert "invalid comparison arguments" in captured_io.err
        assert "usage:" not in captured_io.err
        assert "unrecognized arguments" not in captured_io.err
        assert secret_flag not in captured_io.err
        assert "SECRET_COMPARE_FLAG_SHOULD_NOT_LEAK" not in captured_io.err
        assert str(baseline_path) not in captured_io.err
        assert str(current_path) not in captured_io.err
        assert "SECRET_BASELINE_ARG_PATH_SHOULD_NOT_LEAK" not in captured_io.err
        assert "SECRET_CURRENT_ARG_PATH_SHOULD_NOT_LEAK" not in captured_io.err
        assert "SystemExit" not in captured_io.err

    def test_cli_missing_threshold_value_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_THRESHOLD_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "SECRET_CURRENT_THRESHOLD_PATH_SHOULD_NOT_LEAK.json"

        def fail_if_loaded(path_or_data):
            pytest.fail(f"_load_result should not be called for parser failure: {path_or_data}")

        monkeypatch.setattr(compare_module, "_load_result", fail_if_loaded)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        captured_io = capsys.readouterr()
        assert excinfo.value.code == 2
        assert captured_io.out == ""
        assert "invalid comparison arguments" in captured_io.err
        assert "usage:" not in captured_io.err
        assert "expected one argument" not in captured_io.err
        assert str(baseline_path) not in captured_io.err
        assert str(current_path) not in captured_io.err
        assert "SECRET_BASELINE_THRESHOLD_PATH_SHOULD_NOT_LEAK" not in captured_io.err
        assert "SECRET_CURRENT_THRESHOLD_PATH_SHOULD_NOT_LEAK" not in captured_io.err
        assert "SystemExit" not in captured_io.err

    def test_cli_missing_baseline_fails_before_read_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_DIR_SHOULD_NOT_LEAK" / "missing.json"
        current_path = tmp_path / "current.json"
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        _assert_compare_cli_error_payload(
            stderr,
            error="invalid comparison artifact",
            reason_code="BENCHMARK_COMPARE_ARTIFACT_INVALID",
            stage="input",
        )
        assert "invalid comparison artifact" in stderr
        assert "SECRET_BASELINE_DIR_SHOULD_NOT_LEAK" not in stderr
        assert str(baseline_path) not in stderr

    def test_cli_directory_current_fails_before_read_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path = tmp_path / "SECRET_CURRENT_DIR_SHOULD_NOT_LEAK"
        current_path.mkdir()

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact" in stderr
        assert "SECRET_CURRENT_DIR_SHOULD_NOT_LEAK" not in stderr
        assert str(current_path) not in stderr

    def test_cli_comparison_artifact_stat_failure_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_STAT_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "current.json"
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        secret_error = "SECRET_COMPARE_STAT_ERROR_SHOULD_NOT_LEAK"
        original_is_file = Path.is_file

        def failing_is_file(self: Path) -> bool:
            if self == baseline_path:
                raise OSError(secret_error)
            return original_is_file(self)

        monkeypatch.setattr(Path, "is_file", failing_is_file)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        captured_io = capsys.readouterr()
        stderr = captured_io.err
        assert "# Benchmark Comparison" not in captured_io.out
        assert "invalid comparison artifact" in stderr
        assert "Traceback" not in stderr
        assert "OSError" not in stderr
        assert secret_error not in stderr
        assert "SECRET_BASELINE_STAT_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(baseline_path) not in stderr

    def test_cli_valid_comparison_omits_raw_paths(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "SECRET_CURRENT_PATH_SHOULD_NOT_LEAK.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
                "0.5",
            ],
        )

        compare_module.main()

        stdout = capsys.readouterr().out
        assert "# Benchmark Comparison" in stdout
        assert str(baseline_path) not in stdout
        assert str(current_path) not in stdout
        assert "SECRET_BASELINE_PATH_SHOULD_NOT_LEAK" not in stdout
        assert "SECRET_CURRENT_PATH_SHOULD_NOT_LEAK" not in stdout

    def test_cli_markdown_report_failure_without_echo_or_regression_check(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        class FakeReport:
            def to_markdown(self) -> str:
                raise ValueError("SECRET_COMPARISON_MARKDOWN_ERROR_SHOULD_NOT_LEAK")

            def has_regression(self, threshold: float = 0.05) -> bool:
                del threshold
                pytest.fail("has_regression should not run after markdown emission failure")

        baseline_path = tmp_path / "SECRET_BASELINE_MARKDOWN_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "SECRET_CURRENT_MARKDOWN_PATH_SHOULD_NOT_LEAK.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(compare_module, "compare", lambda *args, **kwargs: FakeReport())
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        captured_io = capsys.readouterr()
        assert "# Benchmark Comparison" not in captured_io.out
        _assert_compare_cli_error_payload(
            captured_io.err,
            error="comparison report failed",
            reason_code="BENCHMARK_COMPARE_REPORT_FAILED",
            stage="output",
        )
        assert "comparison report failed" in captured_io.err
        assert "Traceback" not in captured_io.err
        assert "ValueError" not in captured_io.err
        assert "SECRET_COMPARISON_MARKDOWN_ERROR_SHOULD_NOT_LEAK" not in captured_io.err
        assert "SECRET_BASELINE_MARKDOWN_PATH_SHOULD_NOT_LEAK" not in captured_io.err
        assert str(baseline_path) not in captured_io.err
        assert "SECRET_CURRENT_MARKDOWN_PATH_SHOULD_NOT_LEAK" not in captured_io.err
        assert str(current_path) not in captured_io.err

    def test_cli_empty_results_payload_preserves_valid_comparison(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        empty_result = {"results": {}, "summary": {"overallRecall": 0}}
        baseline_path.write_text(json.dumps(empty_result))
        current_path.write_text(json.dumps(empty_result))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        compare_module.main()

        stdout = capsys.readouterr().out
        assert "# Benchmark Comparison" in stdout
        assert "No significant changes detected." in stdout

    def test_cli_metric_boundary_values_remain_valid(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        boundary_result = {
            "results": {
                "CWE-78": {
                    "combined": {
                        "recall": 1.0,
                        "noisePerFile": 0.0,
                        "targetedNoisePerFile": 0.0,
                    }
                }
            },
            "summary": {"overallRecall": 0.0},
        }
        baseline_path.write_text(json.dumps(boundary_result))
        current_path.write_text(json.dumps(boundary_result))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        compare_module.main()

        stdout = capsys.readouterr().out
        assert "# Benchmark Comparison" in stdout
        assert "No significant changes detected." in stdout

    def test_cli_canonical_cwe_key_payload_remains_valid(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        canonical_result = {
            "results": {
                "CWE-1": {"combined": {"recall": 0.0}},
            },
            "summary": {"overallRecall": 0.0},
        }
        baseline_path.write_text(json.dumps(canonical_result))
        current_path.write_text(json.dumps(canonical_result))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        compare_module.main()

        stdout = capsys.readouterr().out
        assert "# Benchmark Comparison" in stdout
        assert "No significant changes detected." in stdout

    def test_cli_secret_threshold_fails_before_read_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        secret_threshold = "SECRET_THRESHOLD_SHOULD_NOT_LEAK"

        def fail_if_loaded(path_or_data):
            pytest.fail(f"_load_result should not be called for invalid threshold: {path_or_data}")

        monkeypatch.setattr(compare_module, "_load_result", fail_if_loaded)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
                secret_threshold,
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        _assert_compare_cli_error_payload(
            stderr,
            error="invalid threshold selection",
            reason_code="BENCHMARK_COMPARE_THRESHOLD_INVALID",
            stage="input",
        )
        assert "invalid threshold selection" in stderr
        assert secret_threshold not in stderr

    def test_cli_threshold_failure_exits_two_when_stderr_write_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        import benchmark.compare as compare_module

        class BrokenStderr:
            def write(self, text: str) -> int:
                del text
                raise ValueError("SECRET_BROKEN_STDERR_SHOULD_NOT_LEAK")

            def flush(self) -> None:
                return None

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(sys, "stderr", BrokenStderr())
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
                "SECRET_THRESHOLD_SHOULD_NOT_LEAK",
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2

    def test_cli_non_finite_threshold_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        raw_threshold = "NaN"

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
                raw_threshold,
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid threshold selection" in stderr
        assert raw_threshold not in stderr

    @pytest.mark.parametrize("raw_threshold", ["0", "-0.1", "1.1"])
    def test_cli_out_of_range_threshold_fails_without_echo(
        self,
        raw_threshold: str,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
                raw_threshold,
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid threshold selection" in stderr
        assert raw_threshold not in stderr

    def test_cli_valid_threshold_preserves_regression_exit(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "current.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps(self._make_data(0.78, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
                "0.01",
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 1
        capsys.readouterr()

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
                "--threshold",
                "0.05",
            ],
        )

        compare_module.main()
        stdout = capsys.readouterr().out
        assert "# Benchmark Comparison" in stdout

    def test_cli_malformed_baseline_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "current.json"
        secret_content = "SECRET_BASELINE_PAYLOAD_CONTENT_SHOULD_NOT_LEAK"
        baseline_path.write_text(f'{{\"secret\": \"{secret_content}\"')
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        _assert_compare_cli_error_payload(
            stderr,
            error="invalid comparison artifact payload",
            reason_code="BENCHMARK_COMPARE_PAYLOAD_INVALID",
            stage="input",
        )
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_BASELINE_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(baseline_path) not in stderr

    def test_cli_non_object_current_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "SECRET_CURRENT_PAYLOAD_PATH_SHOULD_NOT_LEAK.json"
        secret_content = "SECRET_CURRENT_PAYLOAD_CONTENT_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps([secret_content]))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_CURRENT_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(current_path) not in stderr

    def test_cli_missing_required_top_level_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_EMPTY_PAYLOAD_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "current.json"
        baseline_path.write_text(json.dumps({}))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert "SECRET_BASELINE_EMPTY_PAYLOAD_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(baseline_path) not in stderr

    def test_cli_out_of_range_summary_recall_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_RANGE_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "current.json"
        secret_content = "SECRET_SUMMARY_RANGE_PAYLOAD_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps({
            "results": {},
            "summary": {"overallRecall": 1.5, "secret": secret_content},
        }))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_BASELINE_RANGE_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(baseline_path) not in stderr

    def test_cli_noncanonical_cwe_key_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "SECRET_CURRENT_CWE_KEY_PATH_SHOULD_NOT_LEAK.json"
        secret_key = "SECRET_CWE_KEY_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps({
            "results": {
                secret_key: {"combined": {"recall": 0.8}},
            },
            "summary": {"overallRecall": 0.8},
        }))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_key not in stderr
        assert "SECRET_CURRENT_CWE_KEY_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(current_path) not in stderr

    def test_cli_nested_summary_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "SECRET_BASELINE_NESTED_PATH_SHOULD_NOT_LEAK.json"
        current_path = tmp_path / "current.json"
        secret_content = "SECRET_COMPARE_SUMMARY_PAYLOAD_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps({"summary": [secret_content], "results": {}}))
        current_path.write_text(json.dumps(self._make_data(0.8, 1.0)))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_BASELINE_NESTED_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(baseline_path) not in stderr

    def test_cli_non_numeric_recall_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "SECRET_CURRENT_RECALL_PATH_SHOULD_NOT_LEAK.json"
        secret_content = "SECRET_COMPARE_RECALL_PAYLOAD_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps({
            "results": {
                "CWE-78": {"combined": {"recall": secret_content}},
            },
            "summary": {"overallRecall": 0.8},
        }))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_CURRENT_RECALL_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(current_path) not in stderr

    def test_cli_missing_combined_recall_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "SECRET_CURRENT_MISSING_RECALL_PATH_SHOULD_NOT_LEAK.json"
        secret_content = "SECRET_COMPARE_MISSING_RECALL_PAYLOAD_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps({
            "results": {
                "CWE-78": {
                    "combined": {"noisePerFile": 0.0},
                    "detectedFiles": [secret_content],
                },
            },
            "summary": {"overallRecall": 0.8},
        }))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_CURRENT_MISSING_RECALL_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(current_path) not in stderr

    def test_cli_negative_combined_recall_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "SECRET_CURRENT_NEGATIVE_RECALL_PATH_SHOULD_NOT_LEAK.json"
        secret_content = "SECRET_NEGATIVE_RECALL_PAYLOAD_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps({
            "results": {
                "CWE-78": {
                    "combined": {"recall": -0.1},
                    "detectedFiles": [secret_content],
                },
            },
            "summary": {"overallRecall": 0.8},
        }))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_CURRENT_NEGATIVE_RECALL_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(current_path) not in stderr

    @pytest.mark.parametrize("noise_field", ["noisePerFile", "targetedNoisePerFile"])
    def test_cli_negative_noise_payload_fails_without_echo(
        self,
        noise_field: str,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / f"SECRET_CURRENT_NEGATIVE_{noise_field.upper()}_PATH_SHOULD_NOT_LEAK.json"
        secret_content = f"SECRET_NEGATIVE_{noise_field.upper()}_PAYLOAD_SHOULD_NOT_LEAK"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(json.dumps({
            "results": {
                "CWE-78": {
                    "combined": {"recall": 0.8, noise_field: -1.0},
                    "missedFiles": [secret_content],
                },
            },
            "summary": {"overallRecall": 0.8},
        }))

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert secret_content not in stderr
        assert "SECRET_CURRENT_NEGATIVE_" not in stderr
        assert str(current_path) not in stderr

    def test_cli_non_finite_nested_payload_fails_without_echo(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        import benchmark.compare as compare_module

        baseline_path = tmp_path / "baseline.json"
        current_path = tmp_path / "SECRET_CURRENT_NONFINITE_PATH_SHOULD_NOT_LEAK.json"
        baseline_path.write_text(json.dumps(self._make_data(0.8, 1.0)))
        current_path.write_text(
            '{"results": {"CWE-78": {"combined": {"recall": NaN}}}, "summary": {"overallRecall": 0.8}}'
        )

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--current",
                str(current_path),
            ],
        )

        with pytest.raises(SystemExit) as excinfo:
            compare_module.main()

        assert excinfo.value.code == 2
        stderr = capsys.readouterr().err
        assert "invalid comparison artifact payload" in stderr
        assert "NaN" not in stderr
        assert "SECRET_CURRENT_NONFINITE_PATH_SHOULD_NOT_LEAK" not in stderr
        assert str(current_path) not in stderr
