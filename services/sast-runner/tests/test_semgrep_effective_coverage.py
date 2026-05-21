from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.scanner.semgrep_coverage import build_semgrep_effective_coverage


def _write_rule(path: Path, *, language: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""
rules:
  - id: test.{language}.popen
    pattern: popen($ARG, ...)
    message: popen with variable argument
    languages: [{language}]
    severity: WARNING
""".lstrip(),
        encoding="utf-8",
    )
    return path


def test_cpp_sources_with_c_only_local_rules_are_quality_degraded(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir / "c-rules.yaml", language="c")

    coverage = build_semgrep_effective_coverage(
        source_files=["src/main.cpp"],
        rulesets=["p/c"],
        custom_rules_dir=rules_dir,
        include_extensions=[".c", ".h"],
    )

    assert coverage["coverageKind"] == "semgrep-effective-coverage-v1"
    assert coverage["coverageStatus"] == "degraded"
    assert coverage["targetLanguageCounts"]["cpp"] == 1
    assert coverage["localRuleLanguageCounts"]["c"] == 1
    assert coverage["localRuleLanguageCounts"]["cpp"] == 0
    assert "SEMGREP_CPP_TARGETS_EXCLUDED_BY_EXTENSION_FILTER" in coverage["coverageReasons"]
    assert "SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN" in coverage["coverageReasons"]


def test_cpp_sources_with_cpp_included_but_c_only_rules_are_coverage_degraded(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir / "c-rules.yaml", language="c")

    coverage = build_semgrep_effective_coverage(
        source_files=["src/main.cpp"],
        rulesets=["p/c"],
        custom_rules_dir=rules_dir,
        include_extensions=[".c", ".h", ".cpp"],
    )

    assert coverage["coverageStatus"] == "degraded"
    assert "SEMGREP_CPP_TARGETS_EXCLUDED_BY_EXTENSION_FILTER" not in coverage["coverageReasons"]
    assert "SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN" in coverage["coverageReasons"]


def test_cpp_sources_with_cpp_local_rules_are_quality_ok(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir / "cpp-rules.yaml", language="cpp")

    coverage = build_semgrep_effective_coverage(
        source_files=["src/main.cpp"],
        rulesets=["p/c"],
        custom_rules_dir=rules_dir,
        include_extensions=[".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"],
    )

    assert coverage["coverageStatus"] == "ok"
    assert coverage["coverageReasons"] == []
    assert coverage["targetLanguageCounts"]["cpp"] == 1
    assert coverage["localRuleLanguageCounts"]["cpp"] == 1


def test_c_sources_with_c_local_rules_are_quality_ok(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir / "c-rules.yaml", language="c")

    coverage = build_semgrep_effective_coverage(
        source_files=["src/main.c"],
        rulesets=["p/c"],
        custom_rules_dir=rules_dir,
        include_extensions=None,
    )

    assert coverage["coverageStatus"] == "ok"
    assert coverage["coverageReasons"] == []
    assert coverage["targetLanguageCounts"]["c"] == 1


def test_canonical_cpp_command_injection_rule_detects_popen_c_str(tmp_path: Path) -> None:
    source = tmp_path / "main.cpp"
    source.write_text(
        """
#include <cstdio>
#include <string>
void run(std::string cmd) {
    popen(cmd.c_str(), "r");
}
""".lstrip(),
        encoding="utf-8",
    )
    semgrep = Path(sys.executable).with_name("semgrep")
    if not semgrep.exists():
        semgrep = Path("semgrep")
    rule_path = Path(__file__).resolve().parents[1] / "rules" / "cpp" / "command-injection.yaml"

    completed = subprocess.run(
        [
            str(semgrep),
            "scan",
            "--config",
            str(rule_path),
            "--json",
            "--metrics",
            "off",
            str(tmp_path),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )

    assert completed.stdout, completed.stderr
    payload = json.loads(completed.stdout)
    rule_ids = {result["check_id"] for result in payload.get("results", [])}
    assert any(rule_id.endswith("aegis.cpp.cwe-78-popen-with-variable") for rule_id in rule_ids)
