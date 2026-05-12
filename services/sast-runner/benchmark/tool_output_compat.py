from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.scanner.clangtidy_runner import ClangTidyRunner
from app.scanner.cppcheck_runner import CppcheckRunner
from app.scanner.flawfinder_runner import FlawfinderRunner
from app.scanner.gcc_analyzer_runner import GccAnalyzerRunner
from app.scanner.sarif_parser import parse_sarif
from app.scanner.scanbuild_runner import ScanbuildRunner
from app.schemas.response import SastFinding

REPORT_SCHEMA_VERSION = "s4-tool-output-compat-report-v1"


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_manifest_cases(manifest_path: Path) -> list[dict[str, Any]]:
    manifest = load_manifest(manifest_path)
    fixture_root = manifest_path.parent
    return [_parse_case(case, fixture_root) for case in manifest.get("cases", [])]


def build_compat_report(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = parse_manifest_cases(manifest_path)
    all_passed = all(case["status"] == "pass" for case in cases)
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "manifestSchemaVersion": manifest.get("schemaVersion"),
        "toolOrder": list(manifest.get("toolOrder", [])),
        "gates": {
            "parserCompatibility": {
                "status": "pass" if all_passed else "fail",
                "reasonCodes": [] if all_passed else ["TOOL_OUTPUT_COMPAT_MISMATCH"],
                "consumerPolicy": "tool_change_prerequisite_only",
            }
        },
        "toolSetChangePolicy": "do_not_change_tool_set_from_this_report_alone",
        "cases": cases,
    }


def _parse_case(case: Mapping[str, Any], fixture_root: Path) -> dict[str, Any]:
    findings = _parse_findings(case, fixture_root)
    normalized = [_dump_finding(finding) for finding in findings]
    expected = case.get("expectedFindings") if isinstance(case.get("expectedFindings"), list) else []
    mismatches = _expected_mismatches(normalized, expected)
    return {
        "caseId": case.get("caseId"),
        "toolId": case.get("toolId"),
        "parserKind": case.get("parserKind"),
        "status": "pass" if not mismatches else "fail",
        "reasonCodes": [] if not mismatches else ["EXPECTED_FINDING_MISMATCH"],
        "inputFixture": case.get("inputFixture"),
        "expectedCount": len(expected),
        "actualCount": len(normalized),
        "mismatches": mismatches,
        "findings": normalized,
    }


def _parse_findings(case: Mapping[str, Any], fixture_root: Path) -> list[SastFinding]:
    parser_kind = case.get("parserKind")
    base_dir = Path(str(case.get("baseDir", "/tmp/scan")))
    input_fixture = fixture_root / str(case.get("inputFixture"))

    if parser_kind == "semgrep-sarif":
        findings, _rules_run = parse_sarif(json.loads(input_fixture.read_text(encoding="utf-8")), base_dir)
        return findings
    if parser_kind == "cppcheck-xml":
        return CppcheckRunner()._parse_xml(input_fixture.read_text(encoding="utf-8"), base_dir)
    if parser_kind == "flawfinder-csv":
        return FlawfinderRunner()._parse_csv(input_fixture.read_text(encoding="utf-8"), base_dir)
    if parser_kind == "clang-tidy-text":
        return ClangTidyRunner()._parse_output(input_fixture.read_text(encoding="utf-8"), base_dir)
    if parser_kind == "scan-build-plist":
        return ScanbuildRunner()._parse_plist_results(input_fixture, base_dir)
    if parser_kind == "gcc-fanalyzer-text":
        return GccAnalyzerRunner()._parse_output(input_fixture.read_text(encoding="utf-8"), base_dir)

    raise ValueError(f"unsupported parserKind: {parser_kind!r}")


def _dump_finding(finding: SastFinding) -> dict[str, Any]:
    return finding.model_dump(by_alias=True, exclude_none=True)


def _expected_mismatches(actual: list[dict[str, Any]], expected: list[Any]) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    if len(actual) != len(expected):
        mismatches.append({"path": "$", "expectedCount": len(expected), "actualCount": len(actual)})
    for index, expected_item in enumerate(expected):
        if index >= len(actual) or not isinstance(expected_item, Mapping):
            continue
        mismatches.extend(_subset_mismatches(actual[index], expected_item, f"findings[{index}]"))
    return mismatches


def _subset_mismatches(actual: Any, expected: Any, path: str) -> list[dict[str, Any]]:
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping):
            return [{"path": path, "expected": expected, "actual": actual}]
        mismatches: list[dict[str, Any]] = []
        for key, expected_value in expected.items():
            if key not in actual:
                mismatches.append({"path": f"{path}.{key}", "expected": expected_value, "actual": None})
                continue
            mismatches.extend(_subset_mismatches(actual[key], expected_value, f"{path}.{key}"))
        return mismatches
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) < len(expected):
            return [{"path": path, "expected": expected, "actual": actual}]
        mismatches: list[dict[str, Any]] = []
        for index, expected_value in enumerate(expected):
            mismatches.extend(_subset_mismatches(actual[index], expected_value, f"{path}[{index}]"))
        return mismatches
    if actual != expected:
        return [{"path": path, "expected": expected, "actual": actual}]
    return []
