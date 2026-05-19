"""벤치마크 회귀 감지 — 두 결과를 비교하여 Recall/Precision 변화를 분석."""

from __future__ import annotations

import argparse
import json
import logging
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn, Sequence

logger = logging.getLogger("benchmark")

_CWE_KEY_RE = re.compile(r"^CWE-[1-9][0-9]*$")
_CLI_PARSE_ERROR = "invalid comparison arguments"
_CLI_ERROR_DETAILS = {
    _CLI_PARSE_ERROR: ("BENCHMARK_COMPARE_CLI_ARGUMENTS_INVALID", "input"),
    "invalid threshold selection": ("BENCHMARK_COMPARE_THRESHOLD_INVALID", "input"),
    "invalid comparison artifact": ("BENCHMARK_COMPARE_ARTIFACT_INVALID", "input"),
    "invalid comparison artifact payload": ("BENCHMARK_COMPARE_PAYLOAD_INVALID", "input"),
    "comparison report failed": ("BENCHMARK_COMPARE_REPORT_FAILED", "output"),
}


def _emit_cli_error(error: str, *, reason_code: str, stage: str) -> None:
    payload = {
        "error": error,
        "reasonCode": reason_code,
        "stage": stage,
    }
    try:
        sys.stderr.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    except (OSError, TypeError, ValueError, UnicodeError):
        return


def _exit_cli_error(error: str) -> NoReturn:
    safe_error = error if error in _CLI_ERROR_DETAILS else _CLI_PARSE_ERROR
    reason_code, stage = _CLI_ERROR_DETAILS[safe_error]
    _emit_cli_error(safe_error, reason_code=reason_code, stage=stage)
    raise SystemExit(2)


class _FixedDiagnosticArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _exit_cli_error(message)


def _comparison_display_label(label: str, role: str) -> str:
    if role == "current" and label == "(current run)":
        return label
    if label == role:
        return role
    return f"{role} artifact"


@dataclass
class CWEDelta:
    """하나의 CWE에 대한 변화."""
    cwe: str
    baseline_recall: float
    current_recall: float
    recall_delta: float
    baseline_noise_per_file: float = 0.0
    current_noise_per_file: float = 0.0
    baseline_targeted_noise_pf: float = 0.0
    current_targeted_noise_pf: float = 0.0

    @property
    def is_regression(self) -> bool:
        return self.recall_delta < -0.001  # 0.1% 이상 하락

    @property
    def is_improvement(self) -> bool:
        return self.recall_delta > 0.001


@dataclass
class ComparisonReport:
    """비교 결과 보고서."""
    baseline_path: str
    current_path: str
    overall_recall_delta: float = 0.0
    cwe_deltas: list[CWEDelta] = field(default_factory=list)

    @property
    def regressions(self) -> list[CWEDelta]:
        return [d for d in self.cwe_deltas if d.is_regression]

    @property
    def improvements(self) -> list[CWEDelta]:
        return [d for d in self.cwe_deltas if d.is_improvement]

    def has_regression(self, threshold: float = 0.05) -> bool:
        """recall이 threshold 이상 하락한 CWE가 있으면 True."""
        return any(d.recall_delta <= -threshold for d in self.cwe_deltas)

    def to_markdown(self) -> str:
        lines = ["# Benchmark Comparison", ""]
        baseline_label = _comparison_display_label(self.baseline_path, "baseline")
        current_label = _comparison_display_label(self.current_path, "current")
        lines.append(f"Baseline: `{baseline_label}`")
        lines.append(f"Current:  `{current_label}`")
        lines.append("")

        lines.append(
            f"**Overall Recall: {self.overall_recall_delta:+.1%}**"
        )
        lines.append("")

        if self.regressions:
            lines.append("## Regressions")
            lines.append("| CWE | Recall | Delta |")
            lines.append("|-----|--------|-------|")
            for d in sorted(self.regressions, key=lambda x: x.recall_delta):
                lines.append(
                    f"| {d.cwe} | {d.baseline_recall:.1%} → {d.current_recall:.1%} "
                    f"| **{d.recall_delta:+.1%}** |"
                )
            lines.append("")

        if self.improvements:
            lines.append("## Improvements")
            lines.append("| CWE | Recall | Delta |")
            lines.append("|-----|--------|-------|")
            for d in sorted(self.improvements, key=lambda x: -x.recall_delta):
                lines.append(
                    f"| {d.cwe} | {d.baseline_recall:.1%} → {d.current_recall:.1%} "
                    f"| {d.recall_delta:+.1%} |"
                )
            lines.append("")

        if not self.regressions and not self.improvements:
            lines.append("No significant changes detected.")

        return "\n".join(lines)


def _load_result(path_or_data: Path | dict | str) -> dict:
    """JSON 파일 또는 dict를 로드."""
    if isinstance(path_or_data, dict):
        return path_or_data
    path = Path(path_or_data)
    return json.loads(path.read_text())


def _is_finite_json_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _is_probability_metric(value: Any) -> bool:
    return _is_finite_json_number(value) and 0.0 <= value <= 1.0


def _is_non_negative_json_number(value: Any) -> bool:
    return _is_finite_json_number(value) and value >= 0.0


def _is_canonical_cwe_key(value: Any) -> bool:
    return isinstance(value, str) and _CWE_KEY_RE.fullmatch(value) is not None


def is_comparison_payload_shape(data: Any) -> bool:
    if not isinstance(data, dict):
        return False

    if "summary" not in data or "results" not in data:
        return False

    summary = data["summary"]
    if not isinstance(summary, dict):
        return False
    if "overallRecall" not in summary or not _is_probability_metric(summary["overallRecall"]):
        return False

    results = data["results"]
    if not isinstance(results, dict):
        return False

    for cwe, cwe_data in results.items():
        if not _is_canonical_cwe_key(cwe) or not isinstance(cwe_data, dict):
            return False
        if "combined" not in cwe_data:
            return False
        combined = cwe_data["combined"]
        if not isinstance(combined, dict):
            return False
        if "recall" not in combined or not _is_probability_metric(combined["recall"]):
            return False
        for field in ("noisePerFile", "targetedNoisePerFile"):
            if field in combined and not _is_non_negative_json_number(combined[field]):
                return False

    return True


def _validate_cli_comparison_artifact(path: Path, parser: argparse.ArgumentParser) -> Path:
    try:
        is_file = path.is_file()
    except (OSError, ValueError):
        parser.error("invalid comparison artifact")
    if not is_file:
        parser.error("invalid comparison artifact")
    return path


def _parse_cli_threshold(raw_threshold: str, parser: argparse.ArgumentParser) -> float:
    text = raw_threshold.strip()
    if not text:
        parser.error("invalid threshold selection")
    try:
        threshold = float(text)
    except (OverflowError, ValueError):
        parser.error("invalid threshold selection")
    if not math.isfinite(threshold) or threshold <= 0.0 or threshold > 1.0:
        parser.error("invalid threshold selection")
    return threshold


def _load_cli_result(path: Path, parser: argparse.ArgumentParser) -> dict:
    invalid_payload = False
    data: Any = None
    try:
        data = _load_result(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        invalid_payload = True

    if invalid_payload or not is_comparison_payload_shape(data):
        parser.error("invalid comparison artifact payload")
    return data


def _get_cwe_metrics(data: dict, cwe: str) -> dict:
    """결과 JSON에서 CWE별 combined 메트릭을 추출."""
    results = data.get("results", {})
    cwe_data = results.get(cwe, {})
    combined = cwe_data.get("combined", {})
    return combined


def compare(
    baseline_data: dict,
    current_data: dict,
    baseline_label: str = "baseline",
    current_label: str = "current",
) -> ComparisonReport:
    """두 벤치마크 결과를 비교."""
    report = ComparisonReport(
        baseline_path=baseline_label,
        current_path=current_label,
    )

    b_summary = baseline_data.get("summary", {})
    c_summary = current_data.get("summary", {})
    report.overall_recall_delta = (
        c_summary.get("overallRecall", 0) - b_summary.get("overallRecall", 0)
    )

    # 모든 CWE를 합집합으로
    all_cwes = set(baseline_data.get("results", {}).keys()) | set(current_data.get("results", {}).keys())

    for cwe in sorted(all_cwes):
        b_combined = _get_cwe_metrics(baseline_data, cwe)
        c_combined = _get_cwe_metrics(current_data, cwe)

        b_recall = b_combined.get("recall", 0.0)
        c_recall = c_combined.get("recall", 0.0)
        b_noise = b_combined.get("noisePerFile", 0.0)
        c_noise = c_combined.get("noisePerFile", 0.0)
        b_targeted = b_combined.get("targetedNoisePerFile", b_noise)
        c_targeted = c_combined.get("targetedNoisePerFile", c_noise)

        report.cwe_deltas.append(CWEDelta(
            cwe=cwe,
            baseline_recall=b_recall,
            current_recall=c_recall,
            recall_delta=c_recall - b_recall,
            baseline_noise_per_file=b_noise,
            current_noise_per_file=c_noise,
            baseline_targeted_noise_pf=b_targeted,
            current_targeted_noise_pf=c_targeted,
        ))

    return report


def compare_from_files(
    baseline_path: Path,
    current_path_or_data: Path | dict,
) -> ComparisonReport:
    """파일에서 로드하여 비교하고 결과를 출력."""
    baseline = _load_result(baseline_path)
    current = _load_result(current_path_or_data)

    bl = str(baseline_path)
    cl = str(current_path_or_data) if isinstance(current_path_or_data, Path) else "(current run)"

    report = compare(baseline, current, bl, cl)

    print()
    print(report.to_markdown())

    if report.has_regression():
        logger.warning("REGRESSION DETECTED — recall dropped >5%% on some CWEs")

    return report


def _emit_cli_comparison_markdown(
    report: ComparisonReport,
    parser: argparse.ArgumentParser,
) -> None:
    try:
        print(report.to_markdown())
    except (OSError, TypeError, ValueError, AttributeError, UnicodeError):
        parser.error("comparison report failed")


def main(argv: Sequence[str] | None = None) -> None:
    parser = _FixedDiagnosticArgumentParser(description="Benchmark Comparison Tool")
    parser.add_argument(
        "--baseline", type=Path, required=True,
        help="Baseline JSON 파일",
    )
    parser.add_argument(
        "--current", type=Path, required=True,
        help="현재 결과 JSON 파일",
    )
    parser.add_argument(
        "--threshold", type=str, default="0.05",
        help="회귀 판정 임계값 (기본: 0.05 = 5%%)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    threshold = _parse_cli_threshold(args.threshold, parser)
    baseline_path = _validate_cli_comparison_artifact(args.baseline, parser)
    current_path = _validate_cli_comparison_artifact(args.current, parser)

    baseline = _load_cli_result(baseline_path, parser)
    current = _load_cli_result(current_path, parser)

    report = compare(baseline, current, str(baseline_path), str(current_path))

    _emit_cli_comparison_markdown(report, parser)

    if report.has_regression(threshold):
        logger.warning("REGRESSION DETECTED (threshold=%.1f%%)", threshold * 100)
        sys.exit(1)
    else:
        logger.info("No regression detected (threshold=%.1f%%)", threshold * 100)


if __name__ == "__main__":
    main()
