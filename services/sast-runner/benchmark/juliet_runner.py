"""Juliet 벤치마크 러너 — 6도구 CWE별 Recall/Precision/F1 측정."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Sequence

# 프로젝트 루트를 path에 추가
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scanner.orchestrator import ScanOrchestrator
from app.schemas.request import BuildProfile
from app.schemas.response import SastFinding
from benchmark.cwe_matcher import classify_findings, extract_cwes, matches_cwe
from benchmark.juliet_manifest import (
    JulietCWESuite,
    JulietTestCase,
    discover_cwe_suites,
    get_testcasesupport_path,
)
from benchmark.metrics import BenchmarkResult, CWEMetrics, RuleMetrics, ToolMetrics

logger = logging.getLogger("benchmark")

# 자동차 임베디드 우선 CWE
PRIORITY_CWES = [78, 121, 122, 190, 416, 476]

ALL_TOOLS = ["semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"]

PUBLIC_JULIET_PATH_LABEL = "<JULIET_ROOT>/C"
_CLI_PARSE_ERROR = "invalid Juliet arguments"
_CLI_ERROR_DETAILS = {
    _CLI_PARSE_ERROR: ("JULIET_CLI_ARGUMENTS_INVALID", "input"),
    "invalid tool selection": ("JULIET_TOOL_SELECTION_INVALID", "input"),
    "invalid CWE selection": ("JULIET_CWE_SELECTION_INVALID", "input"),
    "invalid variant selection": ("JULIET_VARIANT_SELECTION_INVALID", "input"),
    "invalid timeout selection": ("JULIET_TIMEOUT_SELECTION_INVALID", "input"),
    "invalid baseline artifact": ("JULIET_BASELINE_ARTIFACT_INVALID", "input"),
    "invalid output artifact": ("JULIET_OUTPUT_ARTIFACT_INVALID", "input"),
    "invalid baseline artifact payload": ("JULIET_BASELINE_PAYLOAD_INVALID", "input"),
    "output artifact write failed": ("JULIET_OUTPUT_ARTIFACT_WRITE_FAILED", "output"),
    "markdown report failed": ("JULIET_MARKDOWN_REPORT_FAILED", "output"),
    "stdout JSON write failed": ("JULIET_STDOUT_JSON_WRITE_FAILED", "output"),
    "comparison handoff failed": ("JULIET_COMPARISON_HANDOFF_FAILED", "handoff"),
    "benchmark execution failed": ("JULIET_BENCHMARK_EXECUTION_FAILED", "run"),
    "benchmark report build failed": ("JULIET_BENCHMARK_REPORT_BUILD_FAILED", "output"),
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


def _parse_cli_tools(raw_tools: str | None, parser: argparse.ArgumentParser) -> list[str] | None:
    if raw_tools is None:
        return None

    tools = [tool.strip() for tool in raw_tools.split(",")]
    if not tools or any(not tool or tool not in ALL_TOOLS for tool in tools):
        parser.error("invalid tool selection")
    if len(set(tools)) != len(tools):
        parser.error("invalid tool selection")
    return tools


def _parse_positive_decimal(value: str, parser: argparse.ArgumentParser, error_message: str) -> int:
    if not value or not value.isdecimal():
        parser.error(error_message)
    try:
        parsed = int(value)
    except (OverflowError, ValueError):
        parser.error(error_message)
    if parsed <= 0:
        parser.error(error_message)
    return parsed


def _parse_cli_cwes(raw_cwes: str | None, parser: argparse.ArgumentParser) -> list[int] | None:
    if raw_cwes is None:
        return None

    values = [value.strip() for value in raw_cwes.split(",")]
    if not values:
        parser.error("invalid CWE selection")
    return [_parse_positive_decimal(value, parser, "invalid CWE selection") for value in values]


def _parse_cli_variant_filter(raw_variant: str, parser: argparse.ArgumentParser) -> tuple[str, str | None]:
    value = raw_variant.strip()
    if value == "all":
        return "all", None
    _parse_positive_decimal(value, parser, "invalid variant selection")
    return value, value


def _parse_cli_timeout(raw_timeout: str, parser: argparse.ArgumentParser) -> int:
    value = raw_timeout.strip()
    return _parse_positive_decimal(value, parser, "invalid timeout selection")


def _validate_cli_baseline_artifact(
    baseline_path: Path | None,
    parser: argparse.ArgumentParser,
) -> Path | None:
    if baseline_path is None:
        return None
    try:
        is_file = baseline_path.is_file()
    except (OSError, ValueError):
        parser.error("invalid baseline artifact")
    if not is_file:
        parser.error("invalid baseline artifact")
    return baseline_path


def _validate_cli_output_artifact(
    output_path: Path | None,
    parser: argparse.ArgumentParser,
) -> Path | None:
    if output_path is None:
        return None
    try:
        output_exists = output_path.exists()
        output_is_file = output_path.is_file() if output_exists else False
        parent = output_path.parent
        parent_exists = parent.exists()
        parent_is_dir = parent.is_dir() if parent_exists else False
    except (OSError, ValueError):
        parser.error("invalid output artifact")
    if output_exists and not output_is_file:
        parser.error("invalid output artifact")
    if parent_exists and not parent_is_dir:
        parser.error("invalid output artifact")
    return output_path


def _validate_cli_baseline_payload(
    baseline_path: Path | None,
    parser: argparse.ArgumentParser,
) -> Path | None:
    if baseline_path is None:
        return None

    invalid_payload = False
    data: Any = None
    try:
        data = json.loads(baseline_path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        invalid_payload = True

    if not invalid_payload:
        from benchmark.compare import is_comparison_payload_shape
        invalid_payload = not is_comparison_payload_shape(data)

    if invalid_payload:
        parser.error("invalid baseline artifact payload")
    return baseline_path


def _write_cli_output_artifact(
    output_path: Path | None,
    output_data: dict[str, Any],
    parser: argparse.ArgumentParser,
) -> None:
    if output_path is None:
        return

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(output_data, indent=2, ensure_ascii=False))
    except (OSError, TypeError, UnicodeError):
        parser.error("output artifact write failed")
    logger.info("Results saved to output file")


def _emit_cli_markdown_report(
    result: BenchmarkResult,
    show_rules: bool,
    parser: argparse.ArgumentParser,
) -> None:
    try:
        print()
        print(result.to_markdown(show_rules=show_rules))
    except (OSError, TypeError, ValueError, AttributeError, UnicodeError):
        parser.error("markdown report failed")


def _emit_cli_stdout_json(output_data: dict[str, Any], parser: argparse.ArgumentParser) -> None:
    try:
        print()
        print(json.dumps(output_data, indent=2, ensure_ascii=False))
    except (OSError, TypeError, UnicodeError):
        parser.error("stdout JSON write failed")


def _run_cli_compare_handoff(
    baseline_path: Path | None,
    current: Path | dict[str, Any],
    parser: argparse.ArgumentParser,
) -> None:
    if baseline_path is None:
        return

    try:
        from benchmark.compare import compare_from_files
        compare_from_files(baseline_path, current)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        AttributeError,
    ):
        parser.error("comparison handoff failed")


async def run_benchmark(
    juliet_root: Path,
    target_cwes: list[int] | None = None,
    variant_filter: str | None = "01",
    timeout: int = 300,
    custom_rules: bool = True,
    tools: list[str] | None = None,
) -> BenchmarkResult:
    """Juliet 벤치마크를 실행하고 결과를 반환.

    Args:
        juliet_root: Juliet C/ 디렉토리 경로
        target_cwes: 대상 CWE 번호. None이면 PRIORITY_CWES 사용
        variant_filter: "01"이면 _01.c만. None이면 전부
        timeout: 도구 타임아웃 (초)
        custom_rules: False이면 커스텀 Semgrep 룰 비활성화 (delta 측정용)
        tools: 실행할 도구 목록. None이면 전부
    """
    # 커스텀 룰 비활성화 (delta 측정용)
    from app.config import settings
    _orig_rules_dir = settings.custom_rules_dir
    if not custom_rules:
        settings.custom_rules_dir = None
        logger.info("Custom Semgrep rules DISABLED for this benchmark run")
    try:
        if target_cwes is None:
            target_cwes = PRIORITY_CWES

        suites = discover_cwe_suites(juliet_root, target_cwes, variant_filter)
        if not suites:
            logger.error("No Juliet test suites found for benchmark selection")
            return BenchmarkResult()

        support_path = get_testcasesupport_path(juliet_root)
        variant_selection = "filtered" if variant_filter else "all"
        tool_selection = "custom" if tools else "all"
        tool_count = len(tools) if tools else 0

        logger.info(
            "Benchmark started: %d CWEs, %d total files, variantSelection=%s, toolSelection=%s, toolCount=%d",
            len(suites),
            sum(s.count for s in suites),
            variant_selection,
            tool_selection,
            tool_count,
        )

        orchestrator = ScanOrchestrator()
        result = BenchmarkResult()

        for suite in suites:
            cwe_key = f"CWE-{suite.cwe_num}"
            logger.info("--- %s: %d files ---", cwe_key, suite.count)

            cwe_metrics = await _benchmark_cwe(
                orchestrator, suite, support_path, cwe_key, timeout, tools,
            )
            result.cwe_results[cwe_key] = cwe_metrics

            logger.info(
                "%s: recall=%.1f%% (%d/%d, noise/file=%.1f)",
                cwe_key,
                cwe_metrics.combined_recall * 100,
                cwe_metrics.combined_tp,
                cwe_metrics.total_files,
                cwe_metrics.noise_per_file,
            )

        logger.info(
            "=== Overall — Recall: %.1f%%  Noise/File: %.1f ===",
            result.overall_recall * 100,
            result.overall_noise_per_file,
        )

        return result

    finally:
        # 커스텀 룰 복원
        if not custom_rules:
            settings.custom_rules_dir = _orig_rules_dir


def _run_cli_benchmark(
    parser: argparse.ArgumentParser,
    *,
    juliet_root: Path,
    target_cwes: list[int] | None,
    variant_filter: str | None,
    timeout: int,
    custom_rules: bool,
    tools: list[str] | None,
) -> BenchmarkResult:
    try:
        return asyncio.run(run_benchmark(
            juliet_root=juliet_root,
            target_cwes=target_cwes,
            variant_filter=variant_filter,
            timeout=timeout,
            custom_rules=custom_rules,
            tools=tools,
        ))
    except (OSError, ValueError, TypeError, AttributeError):
        parser.error("benchmark execution failed")


def _build_cli_output_data(
    result: BenchmarkResult,
    variant_label: str,
    target_cwes: list[int] | None,
    tools: list[str] | None,
    parser: argparse.ArgumentParser,
) -> dict[str, Any]:
    try:
        result_data = result.to_dict()
        if not isinstance(result_data, dict):
            parser.error("benchmark report build failed")
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "julietPath": PUBLIC_JULIET_PATH_LABEL,
            "variantFilter": variant_label,
            "targetCWEs": [f"CWE-{c}" for c in (target_cwes or PRIORITY_CWES)],
            "tools": tools,
            **result_data,
        }
    except (TypeError, ValueError, AttributeError, UnicodeError):
        parser.error("benchmark report build failed")


async def _benchmark_cwe(
    orchestrator: ScanOrchestrator,
    suite: JulietCWESuite,
    support_path: Path | None,
    cwe_key: str,
    timeout: int,
    tools: list[str] | None = None,
) -> CWEMetrics:
    """하나의 CWE 스위트를 벤치마크.

    최적화: CWE 디렉토리를 1회만 스캔하고 파일별로 findings를 분류.
    """
    metrics = CWEMetrics(
        cwe=cwe_key,
        cwe_name=suite.cwe_name,
        total_files=suite.count,
    )

    # 전체 소스 파일 목록
    all_source_files = [tc.relative_path for tc in suite.test_cases]

    # Juliet testcasesupport/ 헤더 경로를 BuildProfile로 전달
    # 이것 없으면 clang-tidy, scan-build, gcc-fanalyzer가 컴파일 실패 → 0건
    profile = None
    if support_path:
        profile = BuildProfile(
            sdkId="juliet-bench",
            compiler="gcc",
            targetArch="x86_64",
            languageStandard="c11",
            headerLanguage="c",
            includePaths=[str(support_path)],
        )

    try:
        findings, execution = await orchestrator.run(
            scan_dir=suite.directory,
            source_files=all_source_files,
            profile=profile,
            rulesets=["p/c", "p/security-audit"],
            tools=tools,
            timeout=timeout,
        )
    except Exception:
        logger.error("Scan failed for %s", cwe_key)
        metrics.combined_fn = suite.count
        return metrics

    logger.info(
        "%s: scan complete — %d findings from %d tools",
        cwe_key, len(findings), len(execution.tools_run),
    )

    # 파일별 findings 인덱스 구축
    findings_by_file: dict[str, list[SastFinding]] = {}
    for f in findings:
        loc_file = f.location.file
        findings_by_file.setdefault(loc_file, []).append(f)

    # 파일별 TP/FN 판정 + FP(noise) 추적
    for tc in suite.test_cases:
        # finding의 location.file은 상대 경로 — tc.relative_path와 매칭
        file_findings = findings_by_file.get(tc.relative_path, [])

        # 매칭: 이 파일의 findings 중 target CWE와 매칭되는 게 있는지
        classification = classify_findings(file_findings, cwe_key)
        matched = classification["matched"]
        unmatched = classification["unmatched"]
        is_detected = len(matched) > 0

        if is_detected:
            metrics.combined_tp += 1
            metrics.detected_files.append(tc.file_path.name)
        else:
            metrics.combined_fn += 1
            metrics.missed_files.append(tc.file_path.name)

        # Targeted noise: target 파일 내 wrong-CWE findings
        metrics.targeted_noise += len(unmatched)

        # 도구별 TP/FN/Noise
        tools_run = execution.tools_run
        for tool in tools_run:
            if tool not in metrics.by_tool:
                metrics.by_tool[tool] = ToolMetrics(tool_name=tool)

            tool_findings = [f for f in file_findings if f.tool_id == tool]
            tool_matched = [f for f in tool_findings if matches_cwe(f, cwe_key)]
            tool_unmatched = [f for f in tool_findings if not matches_cwe(f, cwe_key)]

            if tool_matched:
                metrics.by_tool[tool].tp += 1
            else:
                metrics.by_tool[tool].fn += 1
            metrics.by_tool[tool].targeted_noise += len(tool_unmatched)

        # Per-rule 메트릭
        for f in matched:
            rid = f.rule_id or f"{f.tool_id}:unknown"
            if rid not in metrics.by_rule:
                metrics.by_rule[rid] = RuleMetrics(rule_id=rid, tool=f.tool_id)
            metrics.by_rule[rid].tp += 1
        for f in unmatched:
            rid = f.rule_id or f"{f.tool_id}:unknown"
            if rid not in metrics.by_rule:
                metrics.by_rule[rid] = RuleMetrics(rule_id=rid, tool=f.tool_id)
            metrics.by_rule[rid].noise += 1

    # Portfolio noise: non-target 파일(지원 파일 등)의 findings
    target_files = {tc.relative_path for tc in suite.test_cases}
    for file_path, file_findings in findings_by_file.items():
        if file_path not in target_files:
            metrics.portfolio_noise += len(file_findings)
            for f in file_findings:
                tool = f.tool_id
                if tool in metrics.by_tool:
                    metrics.by_tool[tool].portfolio_noise += 1

    return metrics


def main(argv: Sequence[str] | None = None) -> None:
    parser = _FixedDiagnosticArgumentParser(description="Juliet Benchmark Runner")
    parser.add_argument(
        "--juliet-path", type=Path, required=True,
        help="Juliet C/ 디렉토리 경로",
    )
    parser.add_argument(
        "--cwes", type=str, default=None,
        help="대상 CWE 번호 (쉼표 구분, 예: 78,121,476). 기본: priority subset",
    )
    parser.add_argument(
        "--variant-filter", type=str, default="01",
        help="variant 필터 (예: 01). 'all'이면 전부",
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="결과 JSON 출력 경로",
    )
    parser.add_argument(
        "--timeout", type=str, default="300",
        help="도구 타임아웃 (초, 기본: 300)",
    )
    parser.add_argument(
        "--no-custom-rules", action="store_true",
        help="커스텀 Semgrep 룰 비활성화 (delta 측정용)",
    )
    parser.add_argument(
        "--tools", type=str, default=None,
        help="실행할 도구 (쉼표 구분, 예: flawfinder,cppcheck). 기본: 전부",
    )
    parser.add_argument(
        "--baseline", type=Path, default=None,
        help="비교 baseline JSON 파일. 지정하면 실행 후 회귀 감지",
    )
    parser.add_argument(
        "--show-rules", action="store_true",
        help="마크다운에 per-rule 메트릭 포함",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    target_cwes = _parse_cli_cwes(args.cwes, parser)

    variant_label, variant = _parse_cli_variant_filter(args.variant_filter, parser)
    tools = _parse_cli_tools(args.tools, parser)
    timeout = _parse_cli_timeout(args.timeout, parser)
    baseline = _validate_cli_baseline_artifact(args.baseline, parser)
    output_path = _validate_cli_output_artifact(args.output, parser)
    baseline = _validate_cli_baseline_payload(baseline, parser)

    result = _run_cli_benchmark(
        parser,
        juliet_root=args.juliet_path,
        target_cwes=target_cwes,
        variant_filter=variant,
        timeout=timeout,
        custom_rules=not args.no_custom_rules,
        tools=tools,
    )

    # JSON 출력
    output_data = _build_cli_output_data(result, variant_label, target_cwes, tools, parser)

    if output_path:
        _write_cli_output_artifact(output_path, output_data, parser)

    # Markdown 출력
    _emit_cli_markdown_report(result, args.show_rules, parser)

    # JSON도 stdout에 (output 없을 때)
    if not output_path:
        _emit_cli_stdout_json(output_data, parser)

    # 회귀 감지
    _run_cli_compare_handoff(baseline, output_path or output_data, parser)


if __name__ == "__main__":
    main()
