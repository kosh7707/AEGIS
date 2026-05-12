from __future__ import annotations

import json
from pathlib import Path

from app.scanner.orchestrator import ALL_TOOLS
from benchmark.golden_corpus_validator import load_manifest
from benchmark.tool_portfolio_governance import GOVERNANCE_GATES, build_governance_report

MANIFEST_PATH = Path(__file__).parent / "fixtures" / "golden_corpus_v1" / "manifest.json"
WIKI_PAGE = Path(__file__).parents[4] / "aegis-static-wiki" / "wiki" / "canon" / "specs" / "sast-runner-tool-portfolio-governance-v1.md"
FORBIDDEN_VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}


def _manifest() -> dict:
    return load_manifest(MANIFEST_PATH)


def test_tool_portfolio_governance_report_keeps_current_six_tools() -> None:
    report = build_governance_report(_manifest(), repo_root=Path(__file__).parents[1])

    assert report["schemaVersion"] == "s4-tool-portfolio-governance-v1"
    assert report["decision"] == "keep-current-six-tools"
    assert report["toolSet"] == ALL_TOOLS
    assert sorted(report["gates"]) == sorted(GOVERNANCE_GATES)
    assert all(gate["status"] == "pass" for gate in report["gates"].values())


def test_governance_records_unique_contribution_overlap_and_limits_for_each_tool() -> None:
    report = build_governance_report(_manifest(), repo_root=Path(__file__).parents[1])
    by_tool = {tool["toolId"]: tool for tool in report["tools"]}

    assert list(by_tool) == ALL_TOOLS
    for tool_id, tool in by_tool.items():
        assert tool["role"]
        assert tool["uniqueContribution"]
        assert tool["overlap"]
        assert tool["limitations"]
        assert tool["capabilityOracle"] == tool_id
        assert tool["deterministic"] is True
        assert tool["requiresNetwork"] is False
        assert tool["requiresExternalKnowledge"] is False
        assert tool["emitsFinalVerdict"] is False


def test_governance_decision_record_rejects_tool_changes_until_corpus_expands() -> None:
    report = build_governance_report(_manifest(), repo_root=Path(__file__).parents[1])
    rejected = {item["alternative"]: item["reason"] for item in report["decisionRecord"]["rejectedAlternatives"]}

    assert "add-tool-now" in rejected
    assert "remove-tool-now" in rejected
    assert "upgrade-tool-now-for-quality-claim" in rejected
    assert report["decisionRecord"]["requiredFollowUps"]
    serialized = json.dumps(report, sort_keys=True)
    for key in FORBIDDEN_VERDICT_KEYS:
        assert key not in serialized


def test_governance_includes_parser_compatibility_prerequisite() -> None:
    report = build_governance_report(_manifest(), repo_root=Path(__file__).parents[1])

    assert report["gates"]["parserCompatibility"]["status"] == "pass"
    compat = report["toolOutputCompatibility"]
    assert compat["schemaVersion"] == "s4-tool-output-compat-report-v1"
    assert compat["manifestSchemaVersion"] == "s4-tool-output-compat-v1"
    assert compat["status"] == "pass"
    assert compat["caseCount"] == len(ALL_TOOLS)
    assert compat["toolOrder"] == ALL_TOOLS


def test_governance_includes_benchmark_slice_evidence_without_changing_decision() -> None:
    report = build_governance_report(_manifest(), repo_root=Path(__file__).parents[1])

    assert report["decision"] == "keep-current-six-tools"
    assert report["gates"]["benchmarkSliceCoverage"]["status"] == "pass"
    evidence = report["benchmarkSliceEvidence"]
    assert evidence["schemaVersion"] == "s4-benchmark-slice-report-v1"
    assert evidence["consumerPolicy"] == "benchmark_quality_evidence_not_runtime_verdict"
    assert evidence["sources"]["variant01"]["artifact"] == "v0.6.0-full.json"
    assert evidence["sources"]["allVariants"]["artifact"] == "v0.7.0-all-variants.json"
    assert evidence["weakestSlices"]["variant01"][0]["cwe"] == "CWE-457"
    assert evidence["weakestSlices"]["allVariants"][0]["cwe"] == "CWE-457"


def test_governance_wiki_page_documents_decision_gates_and_no_tool_change() -> None:
    text = WIKI_PAGE.read_text()

    assert "Decision: **keep-current-six-tools**" in text
    for tool_id in ALL_TOOLS:
        assert tool_id in text
    for gate in [
        "Golden Corpus coverage",
        "Evidence contract compatibility",
        "Parser compatibility",
        "Benchmark slice coverage",
        "Unique contribution / overlap accounting",
        "Runtime and stability budget",
        "Consumer safety",
    ]:
        assert gate in text
    assert "does **not** add a new SAST tool" in text
    assert "does **not** remove or upgrade" in text
