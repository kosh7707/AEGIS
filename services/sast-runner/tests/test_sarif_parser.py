"""SARIF 파싱 단위 테스트."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from app.errors import SarifParseError
from app.scanner.sarif_parser import parse_sarif

BASE_DIR = Path("/tmp/sast-scan-test")


class TestParseSarif:
    """SARIF → SastFinding 변환 테스트."""

    def test_basic_conversion(self, sample_sarif: dict) -> None:
        findings, rules_run = parse_sarif(sample_sarif, BASE_DIR)

        assert len(findings) == 3
        assert rules_run == 3

    def test_finding_fields(self, sample_sarif: dict) -> None:
        findings, _ = parse_sarif(sample_sarif, BASE_DIR)
        f = findings[0]

        assert f.tool_id == "semgrep"
        assert f.rule_id == "semgrep:c.lang.security.insecure-use-gets-fn"
        assert f.severity == "error"
        assert "gets()" in f.message
        assert f.location.file == "src/main.c"
        assert f.location.line == 4
        assert f.location.column == 5
        assert f.location.end_line == 4
        assert f.location.end_column == 14

    def test_severity_mapping(self, sample_sarif: dict) -> None:
        findings, _ = parse_sarif(sample_sarif, BASE_DIR)

        assert findings[0].severity == "error"
        assert findings[1].severity == "warning"
        assert findings[2].severity == "warning"

    def test_data_flow_extraction(self, sample_sarif: dict) -> None:
        findings, _ = parse_sarif(sample_sarif, BASE_DIR)
        f = findings[1]  # strcpy finding with codeFlows

        assert f.data_flow is not None
        assert len(f.data_flow) == 2
        assert f.data_flow[0].file == "src/can_handler.c"
        assert f.data_flow[0].line == 18
        assert "get_can_payload" in (f.data_flow[0].content or "")
        assert f.data_flow[1].line == 22

    def test_no_data_flow(self, sample_sarif: dict) -> None:
        findings, _ = parse_sarif(sample_sarif, BASE_DIR)

        assert findings[0].data_flow is None
        assert findings[2].data_flow is None

    def test_metadata_cwe(self, sample_sarif: dict) -> None:
        findings, _ = parse_sarif(sample_sarif, BASE_DIR)

        meta = findings[0].metadata
        assert meta is not None
        assert "CWE-120" in meta["cwe"]
        assert "CWE-242" in meta["cwe"]
        assert meta["semgrepRuleId"] == "c.lang.security.insecure-use-gets-fn"

    def test_metadata_references(self, sample_sarif: dict) -> None:
        findings, _ = parse_sarif(sample_sarif, BASE_DIR)

        meta = findings[0].metadata
        assert meta is not None
        assert "references" in meta
        assert any("cwe.mitre.org" in r for r in meta["references"])

    def test_empty_runs(self) -> None:
        findings, rules = parse_sarif({"runs": []}, BASE_DIR)
        assert findings == []
        assert rules == 0

    def test_empty_results(self, sample_sarif: dict) -> None:
        sarif = copy.deepcopy(sample_sarif)
        sarif["runs"][0]["results"] = []

        findings, rules = parse_sarif(sarif, BASE_DIR)
        assert findings == []
        assert rules == 3  # rules still counted

    def test_no_runs_key(self) -> None:
        findings, rules = parse_sarif({}, BASE_DIR)
        assert findings == []
        assert rules == 0

    def test_result_without_rule_id_skipped(self, sample_sarif: dict) -> None:
        sarif = copy.deepcopy(sample_sarif)
        sarif["runs"][0]["results"].append({"message": {"text": "no rule"}})

        findings, _ = parse_sarif(sarif, BASE_DIR)
        assert len(findings) == 3  # the bad result is skipped

    def test_result_without_location_skipped(self, sample_sarif: dict) -> None:
        sarif = copy.deepcopy(sample_sarif)
        sarif["runs"][0]["results"].append({
            "ruleId": "some.rule",
            "message": {"text": "no location"},
            "locations": [],
        })

        findings, _ = parse_sarif(sarif, BASE_DIR)
        assert len(findings) == 3

    def test_path_normalization_with_base_dir(self) -> None:
        """temp dir prefix가 포함된 URI에서 상대 경로를 복원."""
        sarif = {
            "runs": [{
                "tool": {"driver": {"rules": [
                    {"id": "test.rule", "properties": {"tags": []}}
                ]}},
                "results": [{
                    "ruleId": "test.rule",
                    "level": "warning",
                    "message": {"text": "test"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "/tmp/sast-scan-test/src/main.c"
                            },
                            "region": {"startLine": 1}
                        }
                    }]
                }]
            }]
        }

        findings, _ = parse_sarif(sarif, BASE_DIR)
        assert findings[0].location.file == "src/main.c"

    def test_json_serialization(self, sample_sarif: dict) -> None:
        """SastFinding이 shared-models.md 형식으로 직렬화되는지 확인."""
        findings, _ = parse_sarif(sample_sarif, BASE_DIR)
        data = findings[0].model_dump(by_alias=True, exclude_none=True)

        assert "toolId" in data
        assert "ruleId" in data
        assert "endLine" in data["location"]
        assert "dataFlow" not in data  # None이면 제외

    def test_malformed_rule_shape_raises_sanitized_parse_error_without_exception_chain(self) -> None:
        sarif = {
            "runs": [{
                "tool": {"driver": {"rules": [None]}},
                "results": [],
            }]
        }

        with pytest.raises(SarifParseError) as excinfo:
            parse_sarif(sarif, BASE_DIR)

        assert str(excinfo.value) == "Failed to parse SARIF output"
        assert "NoneType" not in str(excinfo.value)
        assert excinfo.value.__cause__ is None

    def test_non_mapping_run_raises_sanitized_parse_error(self) -> None:
        secret_run = "SECRET_SARIF_RUN_SHOULD_NOT_LEAK"
        sarif = {"runs": [secret_run]}

        with pytest.raises(SarifParseError) as excinfo:
            parse_sarif(sarif, BASE_DIR)

        assert str(excinfo.value) == "Failed to parse SARIF output"
        assert secret_run not in str(excinfo.value)
        assert excinfo.value.__cause__ is None
