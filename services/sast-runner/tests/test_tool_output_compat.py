from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

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


def test_tool_output_compat_manifest_rejects_missing_file_without_raw_path_echo(tmp_path: Path) -> None:
    missing_path = tmp_path / "SECRET_TOOL_OUTPUT_MANIFEST_PATH_SHOULD_NOT_LEAK.json"

    with pytest.raises(ValueError) as excinfo:
        load_manifest(missing_path)

    message = str(excinfo.value)
    assert "tool-output compatibility manifest could not be read" in message
    assert str(missing_path) not in message
    assert "SECRET_TOOL_OUTPUT_MANIFEST_PATH_SHOULD_NOT_LEAK" not in message
    assert excinfo.value.__cause__ is None


def test_tool_output_compat_manifest_rejects_malformed_json_without_raw_content_echo(tmp_path: Path) -> None:
    secret_content = "SECRET_TOOL_OUTPUT_MANIFEST_CONTENT_SHOULD_NOT_LEAK"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{ " + secret_content, encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_manifest(manifest_path)

    message = str(excinfo.value)
    assert "tool-output compatibility manifest is malformed JSON" in message
    assert secret_content not in message
    assert excinfo.value.__cause__ is None


def test_tool_output_compat_manifest_rejects_non_object_json_without_raw_path_echo(tmp_path: Path) -> None:
    manifest_path = tmp_path / "SECRET_TOOL_OUTPUT_NON_OBJECT_PATH_SHOULD_NOT_LEAK.json"
    manifest_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_manifest(manifest_path)

    message = str(excinfo.value)
    assert "tool-output compatibility manifest must be an object" in message
    assert str(manifest_path) not in message
    assert "SECRET_TOOL_OUTPUT_NON_OBJECT_PATH_SHOULD_NOT_LEAK" not in message


def test_tool_output_compat_rejects_unsupported_parser_kind_without_raw_value_echo(tmp_path: Path) -> None:
    secret_parser_kind = "SECRET_TOOL_OUTPUT_PARSER_KIND_SHOULD_NOT_LEAK"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "schemaVersion": "s4-tool-output-compat-v1",
            "toolOrder": [],
            "cases": [
                {
                    "caseId": "unsupported-parser",
                    "toolId": "semgrep",
                    "parserKind": secret_parser_kind,
                    "inputFixture": "unused.txt",
                    "expectedFindings": [],
                }
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        parse_manifest_cases(manifest_path)

    message = str(excinfo.value)
    assert "unsupported parserKind" in message
    assert secret_parser_kind not in message


def test_tool_output_compat_rejects_missing_fixture_without_raw_path_echo(tmp_path: Path) -> None:
    secret_fixture = "SECRET_TOOL_OUTPUT_FIXTURE_PATH_SHOULD_NOT_LEAK.xml"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "schemaVersion": "s4-tool-output-compat-v1",
            "toolOrder": [],
            "cases": [
                {
                    "caseId": "missing-fixture",
                    "toolId": "cppcheck",
                    "parserKind": "cppcheck-xml",
                    "inputFixture": secret_fixture,
                    "expectedFindings": [],
                }
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        parse_manifest_cases(manifest_path)

    message = str(excinfo.value)
    assert "tool-output compatibility fixture could not be read" in message
    assert secret_fixture not in message
    assert str(tmp_path) not in message
    assert excinfo.value.__cause__ is None


def test_tool_output_compat_rejects_malformed_sarif_fixture_without_raw_content_echo(tmp_path: Path) -> None:
    secret_content = "SECRET_TOOL_OUTPUT_FIXTURE_CONTENT_SHOULD_NOT_LEAK"
    fixture_path = tmp_path / "semgrep.sarif"
    fixture_path.write_text("{ " + secret_content, encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "schemaVersion": "s4-tool-output-compat-v1",
            "toolOrder": [],
            "cases": [
                {
                    "caseId": "malformed-sarif-fixture",
                    "toolId": "semgrep",
                    "parserKind": "semgrep-sarif",
                    "inputFixture": fixture_path.name,
                    "expectedFindings": [],
                }
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        parse_manifest_cases(manifest_path)

    message = str(excinfo.value)
    assert "tool-output compatibility fixture is malformed JSON" in message
    assert secret_content not in message
    assert excinfo.value.__cause__ is None


def test_tool_output_compat_rejects_fixture_path_escape_without_raw_value_echo(tmp_path: Path) -> None:
    secret_fixture = "SECRET_TOOL_OUTPUT_FIXTURE_ESCAPE_SHOULD_NOT_LEAK.txt"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "schemaVersion": "s4-tool-output-compat-v1",
            "toolOrder": [],
            "cases": [
                {
                    "caseId": "fixture-path-escape",
                    "toolId": "cppcheck",
                    "parserKind": "cppcheck-xml",
                    "inputFixture": f"../{secret_fixture}",
                    "expectedFindings": [],
                }
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        parse_manifest_cases(manifest_path)

    message = str(excinfo.value)
    assert "tool-output compatibility fixture path is unsafe" in message
    assert secret_fixture not in message
    assert str(tmp_path) not in message


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
