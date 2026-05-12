from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.scanner.orchestrator import ALL_TOOLS
from benchmark.tool_output_compat import build_compat_report, load_manifest, parse_manifest_cases

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tool_output_compat_v1"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
FORBIDDEN_KEYS = {
    "vulnerable",
    "safe",
    "affected",
    "clean",
    "riskScore",
    "securityVerdict",
    "verdict",
    "shouldCallS5",
    "routeTo",
    "nextService",
    "agentDecision",
}


def _collect_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for nested in value.values():
            keys.update(_collect_keys(nested))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for item in value:
            keys.update(_collect_keys(item))
        return keys
    return set()


def test_tool_output_compat_manifest_declares_current_six_tool_order() -> None:
    manifest = load_manifest(MANIFEST_PATH)

    assert manifest["schemaVersion"] == "s4-tool-output-compat-v1"
    assert manifest["toolOrder"] == ALL_TOOLS
    assert [case["toolId"] for case in manifest["cases"]] == ALL_TOOLS
    assert {case["parserKind"] for case in manifest["cases"]} == {
        "semgrep-sarif",
        "cppcheck-xml",
        "flawfinder-csv",
        "clang-tidy-text",
        "scan-build-plist",
        "gcc-fanalyzer-text",
    }


def test_tool_output_compat_report_passes_all_fixture_cases() -> None:
    report = build_compat_report(MANIFEST_PATH)

    assert report["schemaVersion"] == "s4-tool-output-compat-report-v1"
    assert report["manifestSchemaVersion"] == "s4-tool-output-compat-v1"
    assert report["gates"]["parserCompatibility"]["status"] == "pass"
    assert report["toolOrder"] == ALL_TOOLS
    assert [case["toolId"] for case in report["cases"]] == ALL_TOOLS
    assert all(case["status"] == "pass" for case in report["cases"])


def test_tool_output_compat_expected_fields_match_normalized_findings() -> None:
    cases = parse_manifest_cases(MANIFEST_PATH)

    by_tool = {case["toolId"]: case for case in cases}
    assert by_tool["semgrep"]["findings"][0]["metadata"]["cweId"] == "CWE-120"
    assert by_tool["semgrep"]["findings"][0]["dataFlow"][0]["file"] == "src/main.c"
    assert by_tool["cppcheck"]["findings"][0]["metadata"]["cweId"] == "CWE-476"
    assert by_tool["flawfinder"]["findings"][0]["ruleId"] == "flawfinder:buffer/gets"
    assert by_tool["clang-tidy"]["findings"][0]["metadata"]["cweId"] == "CWE-476"
    assert by_tool["scan-build"]["findings"][0]["metadata"]["checkName"] == "core.NullDereference"
    assert by_tool["gcc-fanalyzer"]["findings"][0]["metadata"]["cweId"] == "CWE-401"
    assert by_tool["gcc-fanalyzer"]["findings"][0]["dataFlow"][0]["file"] == "src/main.c"


def test_tool_output_compat_report_contains_no_verdict_or_orchestration_keys() -> None:
    report = build_compat_report(MANIFEST_PATH)

    forbidden = _collect_keys(report).intersection(FORBIDDEN_KEYS)
    assert not forbidden, f"tool output compatibility report contains forbidden keys: {sorted(forbidden)}"
    serialized = json.dumps(report, sort_keys=True)
    for token in ["shouldCallS5", "routeTo", "nextService", "securityVerdict", "riskScore"]:
        assert token not in serialized


def test_tool_output_compat_helper_has_no_execution_network_or_server_side_effects() -> None:
    helper = Path(__file__).parents[1] / "benchmark" / "tool_output_compat.py"
    text = helper.read_text(encoding="utf-8")

    forbidden_tokens = [
        "create_subprocess",
        "subprocess",
        "check_output",
        "Popen",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "socket",
        "grpc",
        "uvicorn",
        "FastAPI",
        "app.routers",
        "app.main",
        "openai",
        "anthropic",
        "shouldCallS5",
        "routeTo",
        "nextService",
    ]
    for token in forbidden_tokens:
        assert token not in text, f"tool output compat helper must not reference {token!r}"
