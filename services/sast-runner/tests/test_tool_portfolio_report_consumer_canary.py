from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

from benchmark.tool_portfolio_report_consumer_canary import (
    main as consumer_canary_main,
    summarize_tool_portfolio_report,
)

REPO_ROOT = Path(__file__).parents[1]
REPORT_PATH = REPO_ROOT / "benchmark" / "results" / "tool_portfolio" / "s4-harness-fixture-report-v1.json"
CONSUMER_SUMMARY_RELATIVE_PATH = Path(
    "benchmark/results/tool_portfolio/s4-harness-fixture-consumer-summary-v1.json",
)
CONSUMER_SUMMARY_PATH = (
    REPO_ROOT
    / CONSUMER_SUMMARY_RELATIVE_PATH
)
SUMMARY_SCHEMA_VERSION = "s4-tool-portfolio-report-consumer-summary-v1"
EXPECTED_SUMMARY_KEYS = {
    "summarySchemaVersion",
    "reportPresent",
    "reportLocation",
    "schemaVersion",
    "systemStability",
    "corpusReadiness",
    "corpusDecisionGradeReady",
    "localQualityStatus",
    "thresholdIntent",
    "thresholdProfileStatus",
    "finalQualityStatus",
    "toolPortfolioDecisionGradeUsable",
    "runnerIntegrityOnly",
    "diagnosticSurfaces",
    "reasonCodes",
    "requiredFollowUps",
    "diagnosticCandidateIds",
    "toolContributionClasses",
}
EXPECTED_CURRENT_SIX_TOOL_CONTRIBUTION_CLASSES = {
    "semgrep": "unique-positive-contributor",
    "cppcheck": "overlap-only-positive-contributor",
    "flawfinder": "noise-only-or-no-positive-contribution",
    "clang-tidy": "no-observed-signal",
    "scan-build": "unique-positive-contributor",
    "gcc-fanalyzer": "overlap-only-positive-contributor",
}
FORBIDDEN_OUTPUT_KEYS = {
    "vulnerable",
    "safe",
    "affected",
    "clean",
    "riskScore",
    "securityVerdict",
    "verdict",
    "risk",
    "decision",
    "currentDecision",
    "decisionSupport",
    "addCandidate",
    "removeCandidate",
    "upgradeCandidate",
    "addCandidates",
    "removeCandidates",
    "upgradeCandidates",
    "futureCandidateActionsRequireWr",
    "recommendation",
    "recommendations",
    "recommendedAction",
    "severityScore",
    "shouldCallS5",
    "nextService",
    "routeTo",
    "repairAction",
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


def _collect_string_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        values: set[str] = set()
        for nested in value.values():
            values.update(_collect_string_values(nested))
        return values
    if isinstance(value, list):
        values: set[str] = set()
        for item in value:
            values.update(_collect_string_values(item))
        return values
    return set()


def _assert_no_forbidden_output_keys(summary: dict[str, Any]) -> None:
    keys = _collect_keys(summary)
    forbidden = keys.intersection(FORBIDDEN_OUTPUT_KEYS)
    assert not forbidden, f"Tool Portfolio consumer canary output has forbidden keys: {sorted(forbidden)}"


def _assert_no_forbidden_output_values(summary: dict[str, Any]) -> None:
    values = _collect_string_values(summary)
    forbidden = values.intersection(FORBIDDEN_OUTPUT_KEYS)
    assert not forbidden, f"Tool Portfolio consumer canary output has forbidden values: {sorted(forbidden)}"


def _assert_no_forbidden_output_vocabulary(summary: dict[str, Any]) -> None:
    _assert_summary_contract(summary)
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_values(summary)


def _assert_summary_contract(summary: dict[str, Any]) -> None:
    assert set(summary) == EXPECTED_SUMMARY_KEYS
    assert summary["summarySchemaVersion"] == SUMMARY_SCHEMA_VERSION


def _assert_cli_error_payload(
    stderr: str,
    *,
    error: str,
    reason_code: str,
    stage: str,
) -> dict[str, Any]:
    payload = json.loads(stderr)
    assert payload == {
        "error": error,
        "reasonCode": reason_code,
        "reasonCodes": [reason_code],
        "stage": stage,
        "summaryEmitted": False,
    }
    return payload


def _consumer_summary_artifact_offenders(
    *,
    results_root: Path,
    repo_root: Path,
    expected_summary: dict[str, Any],
) -> list[str]:
    offenders: list[str] = []
    for path in sorted(results_root.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("summarySchemaVersion") != SUMMARY_SCHEMA_VERSION:
            continue
        relative_path = path.relative_to(repo_root)
        if relative_path == CONSUMER_SUMMARY_RELATIVE_PATH and document == expected_summary:
            continue
        offenders.append(str(relative_path))
    return offenders


def _minimal_report(
    *,
    system_status: str = "pass",
    quality_gate_allowed: bool = True,
    corpus_status: str = "available",
    corpus_decision_grade_ready: bool = True,
    local_quality_status: str = "pass",
    final_quality_status: str = "pass",
    threshold_intent: str = "quality-sufficiency",
    threshold_status: str = "decision_grade_candidate",
    reason_codes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schemaVersion": "s4-tool-portfolio-experiment-report-v1",
        "systemStabilityGate": {
            "status": system_status,
            "qualityGateAllowed": quality_gate_allowed,
            "reasonCodes": [],
        },
        "corpusReadinessGate": {
            "status": corpus_status,
            "decisionGradeReady": corpus_decision_grade_ready,
            "reasonCodes": [],
        },
        "qualityGate": {
            "status": final_quality_status,
            "reasonCodes": reason_codes or [],
            "decision": "quality-gate-pass" if final_quality_status == "pass" else "insufficient-evidence-for-tool-change",
            "localQualityAssessment": {
                "status": local_quality_status,
                "reasonCodes": [],
                "thresholdProfile": {
                    "intent": threshold_intent,
                    "status": threshold_status,
                    "reasonCodes": reason_codes or [],
                },
            },
        },
        "qualityDiagnostics": {
            "status": "available",
            "splitDiagnostics": {
                "validation": {
                    "diagnosticTriage": {
                        "candidates": [
                            {"candidateId": "recall-gap-investigation", "nextLocalAction": "do-not-copy"},
                        ],
                    },
                },
            },
        },
        "toolContributionDiagnostics": {
            "status": "available",
            "tools": [
                {"toolId": "semgrep", "evidenceClass": "unique-positive-contributor", "singleTool": {"targetTP": 1}},
                {"toolId": "cppcheck", "evidenceClass": "overlap-only-positive-contributor", "singleTool": {"targetTP": 1}},
                {
                    "toolId": "flawfinder",
                    "evidenceClass": "noise-only-or-no-positive-contribution",
                    "singleTool": {"targetTP": 0},
                },
                {"toolId": "clang-tidy", "evidenceClass": "no-observed-signal", "singleTool": {"targetTP": 0}},
                {"toolId": "scan-build", "evidenceClass": "unique-positive-contributor", "singleTool": {"targetTP": 1}},
                {"toolId": "gcc-fanalyzer", "evidenceClass": "overlap-only-positive-contributor", "singleTool": {"targetTP": 1}},
            ],
        },
        "decisionSupport": {
            "currentDecision": "must-not-leak",
            "addCandidates": ["must-not-leak"],
        },
    }


def test_canonical_harness_report_is_not_decision_grade_but_exposes_neutral_diagnostics() -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["schemaVersion"] == "s4-tool-portfolio-experiment-report-v1"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["systemStability"] == "not_run"
    assert summary["corpusReadiness"] == "blocked"
    assert summary["corpusDecisionGradeReady"] is False
    assert summary["localQualityStatus"] == "fail"
    assert summary["finalQualityStatus"] == "not_decision_grade"
    assert summary["diagnosticSurfaces"] == {
        "qualityDiagnostics": "available",
        "toolContributionDiagnostics": "available",
    }
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in summary["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_NOT_RUN" in summary["reasonCodes"]
    assert set(summary["diagnosticCandidateIds"])
    assert summary["toolContributionClasses"]["scan-build"] == "unique-positive-contributor"
    _assert_no_forbidden_output_vocabulary(summary)


def test_runner_integrity_thresholds_are_not_decision_grade_even_with_diagnostics() -> None:
    report = _minimal_report(
        local_quality_status="not_decision_grade",
        final_quality_status="not_decision_grade",
        threshold_intent="runner-integrity-only",
        threshold_status="not_decision_grade",
        reason_codes=["QUALITY_THRESHOLDS_NON_DISCRIMINATING"],
    )

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["runnerIntegrityOnly"] is True
    assert summary["diagnosticSurfaces"]["qualityDiagnostics"] == "available"
    assert summary["diagnosticSurfaces"]["toolContributionDiagnostics"] == "available"
    assert summary["diagnosticCandidateIds"] == ["recall-gap-investigation"]
    assert summary["toolContributionClasses"] == EXPECTED_CURRENT_SIX_TOOL_CONTRIBUTION_CLASSES
    assert "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION" not in summary["reasonCodes"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_runner_integrity_boolean_fails_closed_on_unsafe_positive_report() -> None:
    report = _minimal_report()
    report["qualityGate"]["localQualityAssessment"]["thresholdProfile"]["reasonCodes"] = [
        "QUALITY_THRESHOLDS_NON_DISCRIMINATING",
    ]

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["thresholdIntent"] == "quality-sufficiency"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["runnerIntegrityOnly"] is False
    assert summary["reasonCodes"] == [
        "QUALITY_THRESHOLDS_NON_DISCRIMINATING",
        "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION",
    ]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_runner_integrity_boolean_fails_closed_on_malformed_runner_report() -> None:
    report = _minimal_report(
        local_quality_status="not_decision_grade",
        final_quality_status="not_decision_grade",
        threshold_intent="runner-integrity-only",
        threshold_status="not_decision_grade",
        reason_codes=["QUALITY_THRESHOLDS_NON_DISCRIMINATING"],
    )
    report["toolContributionDiagnostics"]["tools"].append({
        "toolId": "semgrep",
        "evidenceClass": "unique-positive-contributor",
    })

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["thresholdIntent"] == "runner-integrity-only"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["runnerIntegrityOnly"] is False
    assert summary["toolContributionClasses"] == EXPECTED_CURRENT_SIX_TOOL_CONTRIBUTION_CLASSES
    assert summary["reasonCodes"] == [
        "QUALITY_THRESHOLDS_NON_DISCRIMINATING",
        "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION",
    ]
    _assert_no_forbidden_output_vocabulary(summary)


def test_fully_passing_quality_sufficiency_report_is_decision_grade_usable() -> None:
    summary = summarize_tool_portfolio_report(_minimal_report())

    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is True
    assert summary["runnerIntegrityOnly"] is False
    assert summary["reasonCodes"] == []
    assert summary["toolContributionClasses"] == EXPECTED_CURRENT_SIX_TOOL_CONTRIBUTION_CLASSES
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_requires_quality_diagnostics_surface_for_decision_grade_usable() -> None:
    report = _minimal_report()
    del report["qualityDiagnostics"]

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["diagnosticSurfaces"] == {
        "qualityDiagnostics": "missing",
        "toolContributionDiagnostics": "available",
    }
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_requires_tool_contribution_surface_for_decision_grade_usable() -> None:
    report = _minimal_report()
    del report["toolContributionDiagnostics"]

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["diagnosticSurfaces"] == {
        "qualityDiagnostics": "available",
        "toolContributionDiagnostics": "missing",
    }
    assert summary["toolContributionClasses"] == {}
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_requires_current_six_tool_contribution_rows_for_decision_grade_usable() -> None:
    report = _minimal_report()
    report["toolContributionDiagnostics"]["tools"] = []

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["diagnosticSurfaces"] == {
        "qualityDiagnostics": "available",
        "toolContributionDiagnostics": "available",
    }
    assert summary["toolContributionClasses"] == {}
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_requires_empty_failure_reasons_for_decision_grade_usable() -> None:
    report = _minimal_report()
    report["systemStabilityGate"]["reasonCodes"] = ["SYSTEM_STABILITY_GATE_NOT_RUN"]

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["systemStability"] == "pass"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == [
        "SYSTEM_STABILITY_GATE_NOT_RUN",
        "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION",
    ]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_requires_empty_required_followups_for_decision_grade_usable() -> None:
    valid_followup = "Run Corpus Readiness Gate with explicit required corpora before decision-grade validation/test evidence."
    report = _minimal_report()
    report["decisionSupport"]["requiredFollowUps"] = [valid_followup]

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["requiredFollowUps"] == [valid_followup]
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_does_not_add_completeness_unsafe_for_non_decision_grade_reports() -> None:
    report = _minimal_report(local_quality_status="fail", final_quality_status="fail")
    del report["qualityDiagnostics"]
    del report["toolContributionDiagnostics"]

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["diagnosticSurfaces"] == {
        "qualityDiagnostics": "missing",
        "toolContributionDiagnostics": "missing",
    }
    assert summary["reasonCodes"] == []
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_invalid_required_splits_reason_as_safe_quality_failure() -> None:
    report = _minimal_report(
        local_quality_status="fail",
        final_quality_status="fail",
        reason_codes=["QUALITY_REQUIRED_SPLITS_INVALID"],
    )

    summary = summarize_tool_portfolio_report(report)

    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_INVALID"]
    assert "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION" not in summary["reasonCodes"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_missing_malformed_and_wrong_schema_reports_fail_closed() -> None:
    cases = [
        {"success": True, "qualityGate": {"status": "pass"}},
        "not-a-report",
        {"schemaVersion": "other", "qualityGate": {"status": "pass"}},
    ]

    for payload in cases:
        summary = summarize_tool_portfolio_report(payload)
        assert summary["reportPresent"] is False
        assert summary["toolPortfolioDecisionGradeUsable"] is False
        assert summary["runnerIntegrityOnly"] is False
        assert summary["reasonCodes"]
        _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_does_not_copy_decision_support_or_raw_diagnostic_details() -> None:
    report = _minimal_report()
    poisoned = copy.deepcopy(report)
    poisoned["decisionSupport"]["removeCandidates"] = ["must-not-leak"]
    poisoned["qualityDiagnostics"]["splitDiagnostics"]["validation"]["diagnosticTriage"]["candidates"][0]["evidence"] = {
        "raw": "must-not-leak",
    }
    poisoned["toolContributionDiagnostics"]["tools"][0]["singleTool"] = {
        "targetTP": 999,
        "fpFindings": 999,
        "raw": "must-not-leak",
    }

    summary = summarize_tool_portfolio_report(poisoned)
    serialized = json.dumps(summary, sort_keys=True)

    assert "must-not-leak" not in serialized
    assert "nextLocalAction" not in serialized
    assert "singleTool" not in serialized
    assert summary["diagnosticCandidateIds"] == ["recall-gap-investigation"]
    assert summary["toolContributionClasses"]["semgrep"] == "unique-positive-contributor"
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_allowlists_projected_identifier_fields() -> None:
    report = _minimal_report()
    report["qualityDiagnostics"]["splitDiagnostics"]["validation"]["diagnosticTriage"]["candidates"].append({
        "candidateId": "routeTo",
    })
    report["toolContributionDiagnostics"]["tools"].append({
        "toolId": "shouldCallS5",
        "evidenceClass": "removeCandidate",
    })
    report["toolContributionDiagnostics"]["tools"].append({
        "toolId": "semgrep",
        "evidenceClass": "recommendedAction",
    })

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert "routeTo" not in serialized
    assert "shouldCallS5" not in serialized
    assert "removeCandidate" not in serialized
    assert "recommendedAction" not in serialized
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION" in summary["reasonCodes"]
    assert summary["diagnosticCandidateIds"] == ["recall-gap-investigation"]
    assert summary["toolContributionClasses"] == EXPECTED_CURRENT_SIX_TOOL_CONTRIBUTION_CLASSES
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_fail_closes_malformed_projected_diagnostic_identifiers() -> None:
    report = _minimal_report()
    report["qualityDiagnostics"]["splitDiagnostics"]["validation"]["diagnosticTriage"]["candidates"].append({
        "candidateId": 123,
    })
    report["toolContributionDiagnostics"]["tools"].append({
        "toolId": "semgrep",
    })
    report["toolContributionDiagnostics"]["tools"].append({
        "toolId": "cppcheck",
        "evidenceClass": 456,
    })

    summary = summarize_tool_portfolio_report(report)

    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION" in summary["reasonCodes"]
    assert summary["diagnosticCandidateIds"] == ["recall-gap-investigation"]
    assert summary["toolContributionClasses"] == EXPECTED_CURRENT_SIX_TOOL_CONTRIBUTION_CLASSES
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_duplicate_tool_contribution_rows_as_unsafe() -> None:
    expected_classes = EXPECTED_CURRENT_SIX_TOOL_CONTRIBUTION_CLASSES
    cases = [
        (
            "conflicting_duplicate",
            {
                "toolId": "semgrep",
                "evidenceClass": "noise-only-or-no-positive-contribution",
            },
        ),
        (
            "same_class_duplicate",
            {
                "toolId": "semgrep",
                "evidenceClass": "unique-positive-contributor",
            },
        ),
    ]

    for label, duplicate_row in cases:
        report = _minimal_report()
        report["toolContributionDiagnostics"]["tools"].append(duplicate_row)

        summary = summarize_tool_portfolio_report(report)

        assert summary["reportPresent"] is True, label
        assert summary["toolContributionClasses"] == expected_classes, label
        assert summary["toolPortfolioDecisionGradeUsable"] is False, label
        assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"], label
        _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_allowlists_reason_codes_and_required_followups() -> None:
    report = _minimal_report()
    report["systemStabilityGate"]["reasonCodes"] = ["securityVerdict"]
    report["corpusReadinessGate"]["reasonCodes"] = ["routeTo"]
    report["qualityGate"]["localQualityAssessment"]["reasonCodes"] = ["shouldCallS5"]
    report["qualityGate"]["localQualityAssessment"]["thresholdProfile"]["reasonCodes"] = ["removeCandidate"]
    report["qualityGate"]["reasonCodes"] = ["recommendedAction"]
    report["decisionSupport"]["requiredFollowUps"] = [
        "routeTo",
        "shouldCallS5",
        "removeCandidate",
        "securityVerdict",
    ]

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION" in summary["reasonCodes"]
    assert summary["requiredFollowUps"] == []
    assert "routeTo" not in serialized
    assert "shouldCallS5" not in serialized
    assert "removeCandidate" not in serialized
    assert "securityVerdict" not in serialized
    assert "recommendedAction" not in serialized
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_caller_provided_summary_only_reasons_as_spoofed() -> None:
    report = _minimal_report()
    summary_only_reasons = [
        "TOOL_PORTFOLIO_REPORT_ABSENT",
        "TOOL_PORTFOLIO_REPORT_MALFORMED",
        "TOOL_PORTFOLIO_REPORT_SCHEMA_UNSUPPORTED",
        "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION",
    ]
    report["systemStabilityGate"]["reasonCodes"] = summary_only_reasons
    report["corpusReadinessGate"]["reasonCodes"] = summary_only_reasons
    report["qualityGate"]["localQualityAssessment"]["reasonCodes"] = summary_only_reasons
    report["qualityGate"]["localQualityAssessment"]["thresholdProfile"]["reasonCodes"] = summary_only_reasons
    report["qualityGate"]["reasonCodes"] = summary_only_reasons

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["systemStability"] == "pass"
    assert summary["corpusReadiness"] == "available"
    assert summary["corpusDecisionGradeReady"] is True
    assert summary["localQualityStatus"] == "pass"
    assert summary["thresholdIntent"] == "quality-sufficiency"
    assert summary["thresholdProfileStatus"] == "decision_grade_candidate"
    assert summary["finalQualityStatus"] == "pass"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_non_list_reason_and_followup_containers_as_unsafe() -> None:
    report = _minimal_report()
    report["systemStabilityGate"]["reasonCodes"] = "SYSTEM_STABILITY_GATE_NOT_RUN"
    report["decisionSupport"]["requiredFollowUps"] = (
        "Run Corpus Readiness Gate with explicit required corpora before decision-grade validation/test evidence."
    )

    summary = summarize_tool_portfolio_report(report)

    assert summary["reportPresent"] is True
    assert summary["systemStability"] == "pass"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    assert summary["requiredFollowUps"] == []
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_preserves_valid_list_entries_but_rejects_malformed_items() -> None:
    class SecretValue:
        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_LIST_ITEM_SHOULD_NOT_LEAK"

    valid_followup = "Run Corpus Readiness Gate with explicit required corpora before decision-grade validation/test evidence."
    report = _minimal_report()
    report["systemStabilityGate"]["reasonCodes"] = [
        "SYSTEM_STABILITY_GATE_NOT_RUN",
        SecretValue(),
    ]
    report["decisionSupport"]["requiredFollowUps"] = [
        valid_followup,
        SecretValue(),
    ]

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == [
        "SYSTEM_STABILITY_GATE_NOT_RUN",
        "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION",
    ]
    assert summary["requiredFollowUps"] == [valid_followup]
    assert "SECRET_TOOL_PORTFOLIO_LIST_ITEM_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_malformed_diagnostic_scalar_statuses_as_unsafe() -> None:
    class SecretStatus:
        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_STATUS_SHOULD_NOT_LEAK"

    report = _minimal_report()
    report["qualityDiagnostics"]["status"] = SecretStatus()
    report["toolContributionDiagnostics"]["status"] = ""

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["diagnosticSurfaces"] == {
        "qualityDiagnostics": "missing",
        "toolContributionDiagnostics": "missing",
    }
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    assert "SECRET_TOOL_PORTFOLIO_STATUS_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_malformed_decision_scalar_status_as_unsafe() -> None:
    class SecretStatus:
        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_SYSTEM_STATUS_SHOULD_NOT_LEAK"

    report = _minimal_report()
    report["systemStabilityGate"]["status"] = SecretStatus()

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["reportPresent"] is True
    assert summary["systemStability"] == "unknown"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    assert "SECRET_TOOL_PORTFOLIO_SYSTEM_STATUS_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_malformed_required_gate_container_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_GATE_CONTAINER_SHOULD_NOT_LEAK"

    report = _minimal_report()
    report["systemStabilityGate"] = [SecretContainer()]

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["reportPresent"] is True
    assert summary["systemStability"] == "unknown"
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    assert "SECRET_TOOL_PORTFOLIO_GATE_CONTAINER_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_malformed_nested_quality_containers_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_QUALITY_CONTAINER_SHOULD_NOT_LEAK"

    cases = [
        (
            "local_quality_assessment",
            lambda report: report["qualityGate"].__setitem__("localQualityAssessment", [SecretContainer()]),
            {
                "localQualityStatus": "unknown",
                "thresholdIntent": "unknown",
                "thresholdProfileStatus": "unknown",
            },
        ),
        (
            "threshold_profile",
            lambda report: report["qualityGate"]["localQualityAssessment"].__setitem__(
                "thresholdProfile",
                [SecretContainer()],
            ),
            {
                "localQualityStatus": "pass",
                "thresholdIntent": "unknown",
                "thresholdProfileStatus": "unknown",
            },
        ),
    ]

    for label, mutate, expected_fields in cases:
        report = _minimal_report()
        mutate(report)

        summary = summarize_tool_portfolio_report(report)
        serialized = json.dumps(summary, sort_keys=True)

        assert summary["reportPresent"] is True, label
        for field, expected_value in expected_fields.items():
            assert summary[field] == expected_value, label
        assert summary["toolPortfolioDecisionGradeUsable"] is False, label
        assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"], label
        assert "SECRET_TOOL_PORTFOLIO_QUALITY_CONTAINER_SHOULD_NOT_LEAK" not in serialized, label
        _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_malformed_diagnostic_containers_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_DIAGNOSTIC_CONTAINER_SHOULD_NOT_LEAK"

    cases = [
        (
            "quality_diagnostics",
            lambda report: report.__setitem__("qualityDiagnostics", [SecretContainer()]),
            {"qualityDiagnostics": "missing", "toolContributionDiagnostics": "available"},
        ),
        (
            "split_diagnostics",
            lambda report: report["qualityDiagnostics"].__setitem__("splitDiagnostics", [SecretContainer()]),
            {"qualityDiagnostics": "available", "toolContributionDiagnostics": "available"},
        ),
        (
            "validation_split",
            lambda report: report["qualityDiagnostics"]["splitDiagnostics"].__setitem__(
                "validation",
                [SecretContainer()],
            ),
            {"qualityDiagnostics": "available", "toolContributionDiagnostics": "available"},
        ),
        (
            "diagnostic_triage",
            lambda report: report["qualityDiagnostics"]["splitDiagnostics"]["validation"].__setitem__(
                "diagnosticTriage",
                [SecretContainer()],
            ),
            {"qualityDiagnostics": "available", "toolContributionDiagnostics": "available"},
        ),
        (
            "tool_contribution_diagnostics",
            lambda report: report.__setitem__("toolContributionDiagnostics", [SecretContainer()]),
            {"qualityDiagnostics": "available", "toolContributionDiagnostics": "missing"},
        ),
    ]

    for label, mutate, expected_surfaces in cases:
        report = _minimal_report()
        mutate(report)

        summary = summarize_tool_portfolio_report(report)
        serialized = json.dumps(summary, sort_keys=True)

        assert summary["reportPresent"] is True, label
        assert summary["diagnosticSurfaces"] == expected_surfaces, label
        assert summary["toolPortfolioDecisionGradeUsable"] is False, label
        assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"], label
        assert "SECRET_TOOL_PORTFOLIO_DIAGNOSTIC_CONTAINER_SHOULD_NOT_LEAK" not in serialized, label
        _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_malformed_decision_support_container_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_DECISION_SUPPORT_CONTAINER_SHOULD_NOT_LEAK"

    report = _minimal_report()
    report["decisionSupport"] = [SecretContainer()]

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["requiredFollowUps"] == []
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"]
    assert "SECRET_TOOL_PORTFOLIO_DECISION_SUPPORT_CONTAINER_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_treats_malformed_boolean_decision_fields_as_unsafe() -> None:
    class SecretBool:
        def __bool__(self) -> bool:
            raise AssertionError("malformed boolean projection must not be coerced")

        def __str__(self) -> str:
            return "SECRET_TOOL_PORTFOLIO_BOOL_SHOULD_NOT_LEAK"

    cases = [
        (
            "quality_gate_allowed_object",
            lambda report: report["systemStabilityGate"].__setitem__("qualityGateAllowed", SecretBool()),
            True,
        ),
        (
            "quality_gate_allowed_int",
            lambda report: report["systemStabilityGate"].__setitem__("qualityGateAllowed", 1),
            True,
        ),
        (
            "corpus_decision_ready_object",
            lambda report: report["corpusReadinessGate"].__setitem__("decisionGradeReady", SecretBool()),
            False,
        ),
        (
            "corpus_decision_ready_int",
            lambda report: report["corpusReadinessGate"].__setitem__("decisionGradeReady", 1),
            False,
        ),
    ]

    for label, mutate, expected_corpus_ready in cases:
        report = _minimal_report()
        mutate(report)

        summary = summarize_tool_portfolio_report(report)
        serialized = json.dumps(summary, sort_keys=True)

        assert summary["reportPresent"] is True, label
        assert summary["corpusDecisionGradeReady"] is expected_corpus_ready, label
        assert summary["toolPortfolioDecisionGradeUsable"] is False, label
        assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"], label
        assert "SECRET_TOOL_PORTFOLIO_BOOL_SHOULD_NOT_LEAK" not in serialized, label
        _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_preserves_valid_false_boolean_decision_fields() -> None:
    cases = [
        (
            "quality_gate_allowed_false",
            lambda report: report["systemStabilityGate"].__setitem__("qualityGateAllowed", False),
            True,
        ),
        (
            "corpus_decision_ready_false",
            lambda report: report["corpusReadinessGate"].__setitem__("decisionGradeReady", False),
            False,
        ),
    ]

    for label, mutate, expected_corpus_ready in cases:
        report = _minimal_report()
        mutate(report)

        summary = summarize_tool_portfolio_report(report)

        assert summary["reportPresent"] is True, label
        assert summary["corpusDecisionGradeReady"] is expected_corpus_ready, label
        assert summary["toolPortfolioDecisionGradeUsable"] is False, label
        assert summary["reasonCodes"] == [], label
        _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_allowlists_status_intent_and_surface_scalars() -> None:
    report = _minimal_report()
    report["systemStabilityGate"]["status"] = "routeTo"
    report["corpusReadinessGate"]["status"] = "securityVerdict"
    report["qualityGate"]["localQualityAssessment"]["status"] = "shouldCallS5"
    report["qualityGate"]["localQualityAssessment"]["thresholdProfile"]["intent"] = "recommendedAction"
    report["qualityGate"]["localQualityAssessment"]["thresholdProfile"]["status"] = "agentDecision"
    report["qualityGate"]["status"] = "removeCandidate"
    report["qualityDiagnostics"]["status"] = "nextService"
    report["toolContributionDiagnostics"]["status"] = "repairAction"

    summary = summarize_tool_portfolio_report(report)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["systemStability"] == "unknown"
    assert summary["corpusReadiness"] == "unknown"
    assert summary["localQualityStatus"] == "unknown"
    assert summary["thresholdIntent"] == "unknown"
    assert summary["thresholdProfileStatus"] == "unknown"
    assert summary["finalQualityStatus"] == "unknown"
    assert summary["diagnosticSurfaces"] == {
        "qualityDiagnostics": "missing",
        "toolContributionDiagnostics": "missing",
    }
    assert "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION" in summary["reasonCodes"]
    assert "routeTo" not in serialized
    assert "securityVerdict" not in serialized
    assert "shouldCallS5" not in serialized
    assert "removeCandidate" not in serialized
    assert "recommendedAction" not in serialized
    assert "nextService" not in serialized
    assert "repairAction" not in serialized
    assert "agentDecision" not in serialized
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_cli_emits_summary_for_non_decision_grade_report(capsys) -> None:
    exit_code = consumer_canary_main(["--report", str(REPORT_PATH)])

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert captured.err == ""
    assert exit_code == 0
    assert summary["reportPresent"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["runnerIntegrityOnly"] is False
    _assert_no_forbidden_output_vocabulary(summary)


def test_committed_harness_consumer_summary_matches_canonical_report_summary() -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    committed = json.loads(CONSUMER_SUMMARY_PATH.read_text(encoding="utf-8"))
    generated = summarize_tool_portfolio_report(report)

    assert committed == generated
    assert committed["summarySchemaVersion"] == SUMMARY_SCHEMA_VERSION
    assert committed["schemaVersion"] == "s4-tool-portfolio-experiment-report-v1"
    assert committed["reportPresent"] is True
    assert committed["toolPortfolioDecisionGradeUsable"] is False
    _assert_no_forbidden_output_vocabulary(committed)


def test_consumer_canary_cli_output_matches_committed_harness_consumer_summary(capsys) -> None:
    committed = json.loads(CONSUMER_SUMMARY_PATH.read_text(encoding="utf-8"))

    exit_code = consumer_canary_main(["--report", str(REPORT_PATH)])

    captured = capsys.readouterr()
    assert captured.err == ""
    assert exit_code == 0
    assert json.loads(captured.out) == committed
    _assert_no_forbidden_output_vocabulary(committed)


def test_consumer_summary_artifact_offender_detection_blocks_extra_and_drifted_summaries(
    tmp_path: Path,
) -> None:
    results_root = tmp_path / "benchmark" / "results" / "tool_portfolio"
    results_root.mkdir(parents=True)
    canonical_path = tmp_path / CONSUMER_SUMMARY_RELATIVE_PATH
    expected_summary = summarize_tool_portfolio_report(_minimal_report())
    canonical_path.write_text(json.dumps(expected_summary), encoding="utf-8")

    assert _consumer_summary_artifact_offenders(
        results_root=results_root,
        repo_root=tmp_path,
        expected_summary=expected_summary,
    ) == []

    extra_path = results_root / "stale-consumer-summary.json"
    extra_path.write_text(json.dumps({
        "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
        "reportPresent": False,
    }), encoding="utf-8")
    assert _consumer_summary_artifact_offenders(
        results_root=results_root,
        repo_root=tmp_path,
        expected_summary=expected_summary,
    ) == ["benchmark/results/tool_portfolio/stale-consumer-summary.json"]

    extra_path.unlink()
    drifted_summary = copy.deepcopy(expected_summary)
    drifted_summary["toolPortfolioDecisionGradeUsable"] = False
    canonical_path.write_text(json.dumps(drifted_summary), encoding="utf-8")
    assert _consumer_summary_artifact_offenders(
        results_root=results_root,
        repo_root=tmp_path,
        expected_summary=expected_summary,
    ) == [str(CONSUMER_SUMMARY_RELATIVE_PATH)]


def test_only_canonical_tool_portfolio_consumer_summary_artifact_is_committed() -> None:
    canonical_report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    expected_summary = summarize_tool_portfolio_report(canonical_report)

    assert _consumer_summary_artifact_offenders(
        results_root=REPORT_PATH.parent,
        repo_root=REPO_ROOT,
        expected_summary=expected_summary,
    ) == []


def test_consumer_canary_cli_require_decision_grade_exits_two_when_summary_not_usable(capsys) -> None:
    exit_code = consumer_canary_main(["--report", str(REPORT_PATH), "--require-decision-grade"])

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert captured.err == ""
    assert exit_code == 2
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in summary["reasonCodes"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_cli_require_decision_grade_exits_zero_for_usable_report(tmp_path: Path, capsys) -> None:
    report_path = tmp_path / "decision-grade-report.json"
    report_path.write_text(json.dumps(_minimal_report()), encoding="utf-8")

    exit_code = consumer_canary_main(["--report", str(report_path), "--require-decision-grade"])

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert captured.err == ""
    assert exit_code == 0
    assert summary["toolPortfolioDecisionGradeUsable"] is True
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_cli_wrong_schema_emits_summary_and_exits_two_when_required(
    tmp_path: Path,
    capsys,
) -> None:
    report_path = tmp_path / "wrong-schema.json"
    report_path.write_text(json.dumps({"schemaVersion": "other", "qualityGate": {"status": "pass"}}), encoding="utf-8")

    exit_code = consumer_canary_main(["--report", str(report_path), "--require-decision-grade"])

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert captured.err == ""
    assert exit_code == 2
    assert summary["reportPresent"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_SCHEMA_UNSUPPORTED"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_cli_wrong_schema_exits_two_even_without_decision_grade_requirement(
    tmp_path: Path,
    capsys,
) -> None:
    report_path = tmp_path / "wrong-schema-default.json"
    report_path.write_text(json.dumps({"schemaVersion": "other", "qualityGate": {"status": "pass"}}), encoding="utf-8")

    exit_code = consumer_canary_main(["--report", str(report_path)])

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert captured.err == ""
    assert exit_code == 2
    assert summary["reportPresent"] is False
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_SCHEMA_UNSUPPORTED"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_cli_non_object_json_exits_two_after_sanitized_summary(
    tmp_path: Path,
    capsys,
) -> None:
    report_path = tmp_path / "list-report.json"
    report_path.write_text(json.dumps(["not-a-report"]), encoding="utf-8")

    exit_code = consumer_canary_main(["--report", str(report_path)])

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert captured.err == ""
    assert exit_code == 2
    assert summary["reportPresent"] is False
    assert summary["reportLocation"] == "malformed"
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_MALFORMED"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_cli_empty_object_exits_two_after_absent_summary(
    tmp_path: Path,
    capsys,
) -> None:
    report_path = tmp_path / "empty-report.json"
    report_path.write_text("{}", encoding="utf-8")

    exit_code = consumer_canary_main(["--report", str(report_path)])

    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert captured.err == ""
    assert exit_code == 2
    assert summary["reportPresent"] is False
    assert summary["reportLocation"] == "missing"
    assert summary["reasonCodes"] == ["TOOL_PORTFOLIO_REPORT_ABSENT"]
    _assert_no_forbidden_output_vocabulary(summary)


def test_consumer_canary_cli_json_syntax_failure_exits_one_without_raw_content_echo(
    tmp_path: Path,
    capsys,
) -> None:
    report_path = tmp_path / "bad.json"
    report_path.write_text('{"schemaVersion": "s4-tool-portfolio-experiment-report-v1", "secret": "SECRET_RAW"}', encoding="utf-8")
    report_path.write_text("{not-json: SECRET_RAW}", encoding="utf-8")

    exit_code = consumer_canary_main(["--report", str(report_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    _assert_cli_error_payload(
        captured.err,
        error="input validation failed",
        reason_code="TOOL_PORTFOLIO_REPORT_CLI_INPUT_INVALID",
        stage="input",
    )
    assert "SECRET_RAW" not in captured.err


def test_consumer_canary_cli_argument_error_exits_one(capsys) -> None:
    exit_code = consumer_canary_main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    _assert_cli_error_payload(
        captured.err,
        error="input validation failed",
        reason_code="TOOL_PORTFOLIO_REPORT_CLI_INPUT_INVALID",
        stage="input",
    )


def test_consumer_canary_cli_stdout_write_failure_exits_one_without_echo(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    report_path = tmp_path / "SECRET_CONSUMER_STDOUT_REPORT_PATH_SHOULD_NOT_LEAK.json"
    report_path.write_text(json.dumps(_minimal_report()), encoding="utf-8")
    secret_error = "SECRET_CONSUMER_SUMMARY_STDOUT_ERROR_SHOULD_NOT_LEAK"

    class FailingStdout:
        def write(self, text: str) -> int:
            del text
            raise OSError(secret_error)

        def flush(self) -> None:
            return None

    monkeypatch.setattr(sys, "stdout", FailingStdout())

    exit_code = consumer_canary_main(["--report", str(report_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    _assert_cli_error_payload(
        captured.err,
        error="summary output failed",
        reason_code="TOOL_PORTFOLIO_REPORT_CLI_OUTPUT_FAILED",
        stage="output",
    )
    assert "Traceback" not in captured.err
    assert "OSError" not in captured.err
    assert secret_error not in captured.err
    assert "SECRET_CONSUMER_STDOUT_REPORT_PATH_SHOULD_NOT_LEAK" not in captured.err
    assert str(report_path) not in captured.err


def test_consumer_canary_cli_summary_serialization_failure_exits_one_without_echo(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    import benchmark.tool_portfolio_report_consumer_canary as consumer_module

    class SECRET_CONSUMER_SUMMARY_OBJECT_SHOULD_NOT_LEAK:
        pass

    report_path = tmp_path / "SECRET_CONSUMER_SERIALIZATION_REPORT_PATH_SHOULD_NOT_LEAK.json"
    report_path.write_text(json.dumps(_minimal_report()), encoding="utf-8")

    def non_serializable_summary(payload: Any) -> dict[str, Any]:
        del payload
        return {"bad": SECRET_CONSUMER_SUMMARY_OBJECT_SHOULD_NOT_LEAK()}

    monkeypatch.setattr(consumer_module, "summarize_tool_portfolio_report", non_serializable_summary)

    exit_code = consumer_module.main(["--report", str(report_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    _assert_cli_error_payload(
        captured.err,
        error="summary output failed",
        reason_code="TOOL_PORTFOLIO_REPORT_CLI_OUTPUT_FAILED",
        stage="output",
    )
    assert "Traceback" not in captured.err
    assert "TypeError" not in captured.err
    assert "SECRET_CONSUMER_SUMMARY_OBJECT_SHOULD_NOT_LEAK" not in captured.err
    assert "SECRET_CONSUMER_SERIALIZATION_REPORT_PATH_SHOULD_NOT_LEAK" not in captured.err
    assert str(report_path) not in captured.err


def test_tool_portfolio_consumer_canary_helper_is_json_only_and_side_effect_free() -> None:
    helper = Path(__file__).parents[1] / "benchmark" / "tool_portfolio_report_consumer_canary.py"
    text = helper.read_text(encoding="utf-8")

    forbidden_tokens = [
        "from app.",
        "import app.",
        "toolResults",
        "batch-lookup",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "socket",
        "grpc",
        "openai",
        "anthropic",
        "shouldCallS5",
        "nextService",
        "routeTo",
        "repairAction",
        "agentDecision",
    ]
    for token in forbidden_tokens:
        assert token not in text, f"consumer canary helper must not reference {token!r}"
