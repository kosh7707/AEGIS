from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_EXPECTED_SCHEMA_VERSION = "s4-tool-portfolio-experiment-report-v1"
SUMMARY_SCHEMA_VERSION = "s4-tool-portfolio-report-consumer-summary-v1"
_ABSENT_REASON = "TOOL_PORTFOLIO_REPORT_ABSENT"
_MALFORMED_REASON = "TOOL_PORTFOLIO_REPORT_MALFORMED"
_WRONG_SCHEMA_REASON = "TOOL_PORTFOLIO_REPORT_SCHEMA_UNSUPPORTED"
_UNSAFE_PROJECTION_REASON = "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"
_CLI_INPUT_INVALID_REASON = "TOOL_PORTFOLIO_REPORT_CLI_INPUT_INVALID"
_CLI_OUTPUT_FAILED_REASON = "TOOL_PORTFOLIO_REPORT_CLI_OUTPUT_FAILED"
_CLI_INPUT_INVALID_ERROR = "input validation failed"
_CLI_OUTPUT_FAILED_ERROR = "summary output failed"
_ALLOWED_REASON_CODES = {
    "CORPUS_CASE_CHECKSUM_MISMATCH",
    "CORPUS_CASE_SOURCE_MISSING",
    "CORPUS_CASE_SOURCE_PATH_UNSAFE",
    "CORPUS_READINESS_GATE_INCONSISTENT",
    "CORPUS_READINESS_GATE_INPUT_INVALID",
    "CORPUS_READINESS_GATE_NOT_RUN",
    "CORPUS_READINESS_INPUT_INVALID",
    "CORPUS_REQUIRED_CASES_NOT_DECLARED",
    "CORPUS_REQUIRED_CORPORA_NOT_DECLARED",
    "CORPUS_REQUIRED_CORPUS_ID_INVALID",
    "CORPUS_REQUIRED_SPLITS_MISSING",
    "FINDINGS_BY_CONFIG_INPUT_INVALID",
    "FINDING_PRECISION_BELOW_THRESHOLD",
    "HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS",
    "HISTORICAL_BASELINES_NOT_AVAILABLE",
    "LOCAL_CORPUS_BASE_PATH_REQUIRED",
    "LOCAL_CORPUS_PATH_NOT_FOUND",
    "LOCAL_CORPUS_PATH_OUTSIDE_BASE",
    "LOCAL_EXTERNAL_CORPUS_INCOMPLETE",
    "LOCAL_EXTERNAL_CORPUS_NOT_PRESENT",
    "LOCAL_JULIET_CORPUS_INCOMPLETE",
    "LOCAL_JULIET_CORPUS_NOT_PRESENT",
    "LOCAL_ORACLE_QUALITY_FAILED",
    "LOCAL_ORACLE_QUALITY_PARTIAL",
    "LOCAL_SARD_CORPUS_INCOMPLETE",
    "LOCAL_SARD_CORPUS_NOT_PRESENT",
    "NEGATIVE_REGION_VIOLATION",
    "NEGATIVE_TARGET_FPR_ABOVE_THRESHOLD",
    "NEGATIVE_TARGET_VIOLATIONS_PRESENT",
    "ORACLE_MATCHING_POLICY_INPUT_INVALID",
    "QUALITY_DIAGNOSTICS_PRIMARY_METRICS_NOT_AVAILABLE",
    "QUALITY_PRIMARY_TOOL_SET_CONFIG_INVALID",
    "QUALITY_REQUIRED_SPLITS_INVALID",
    "QUALITY_REQUIRED_SPLITS_NOT_DECLARED",
    "QUALITY_THRESHOLDS_INPUT_INVALID",
    "QUALITY_THRESHOLDS_NON_DISCRIMINATING",
    "QUALITY_THRESHOLDS_NOT_DECLARED",
    "QUALITY_THRESHOLD_VALUE_INVALID",
    "REPORT_IDENTITY_INPUT_INVALID",
    "REQUIRED_TOOL_INCOMPLETE",
    "REQUIRED_TOOL_UNAVAILABLE",
    "REQUIRED_TOOL_UNKNOWN",
    "SPLIT_METRICS_MISSING",
    "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED",
    "SYSTEM_STABILITY_GATE_FAILED",
    "SYSTEM_STABILITY_GATE_INCONSISTENT",
    "SYSTEM_STABILITY_GATE_INPUT_INVALID",
    "SYSTEM_STABILITY_GATE_NOT_RUN",
    "TARGET_RECALL_BELOW_THRESHOLD",
    "TOOL_CONTRIBUTION_COMPARATIVE_CONFIG_INCOMPLETE",
    "TOOL_RESULT_NOT_RECORDED",
}
_ALLOWED_REQUIRED_FOLLOWUPS = {
    "Run Corpus Readiness Gate with explicit required corpora before decision-grade validation/test evidence.",
    "Provide local pinned juliet corpus before decision-grade validation/test evidence.",
    "Provide local pinned sard corpus before decision-grade validation/test evidence.",
    "Provide local pinned external corpus before decision-grade validation/test evidence.",
}
_ALLOWED_SYSTEM_STATUSES = {
    "pass",
    "fail",
    "blocked",
    "not_run",
    "degraded",
    "unknown",
}
_ALLOWED_CORPUS_READINESS_STATUSES = {
    "available",
    "blocked",
    "not_run",
    "unknown",
}
_ALLOWED_QUALITY_STATUSES = {
    "pass",
    "fail",
    "blocked",
    "not_decision_grade",
    "not_run",
    "unknown",
}
_ALLOWED_THRESHOLD_INTENTS = {
    "quality-sufficiency",
    "runner-integrity-only",
    "unknown",
}
_ALLOWED_THRESHOLD_STATUSES = {
    "decision_grade_candidate",
    "not_decision_grade",
    "unknown",
}
_ALLOWED_DIAGNOSTIC_SURFACE_STATUSES = {
    "available",
    "blocked",
    "fail",
    "missing",
    "not_available",
    "not_run",
    "partial",
    "unknown",
}
_ALLOWED_DIAGNOSTIC_CANDIDATE_IDS = {
    "matching-policy-review",
    "cwe-normalization-review",
    "negative-discrimination-review",
    "recall-gap-investigation",
    "noise-pressure-review",
}
_ALLOWED_TOOL_IDS = {
    "semgrep",
    "cppcheck",
    "flawfinder",
    "clang-tidy",
    "scan-build",
    "gcc-fanalyzer",
}
_ALLOWED_TOOL_CONTRIBUTION_CLASSES = {
    "unique-positive-contributor",
    "overlap-only-positive-contributor",
    "noise-only-or-no-positive-contribution",
    "no-observed-signal",
}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(_CLI_INPUT_INVALID_REASON)


def summarize_tool_portfolio_report(payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Summarize offline Tool Portfolio quality evidence for JSON consumers.

    ``toolPortfolioDecisionGradeUsable`` means only that the offline Tool
    Portfolio quality evidence is decision-grade usable. It is not a security
    verdict, not an absence-of-vulnerability claim, and not an S3/S5 routing
    decision.
    """

    report = _mapping(payload)
    if report is None:
        return _absent_summary(location="malformed", reason=_MALFORMED_REASON)
    if not report:
        return _absent_summary(location="missing", reason=_ABSENT_REASON)
    schema_version = report.get("schemaVersion")
    if schema_version != _EXPECTED_SCHEMA_VERSION:
        return _absent_summary(location="wrong_schema", reason=_WRONG_SCHEMA_REASON)

    system_gate, unsafe_system_gate_shape = _mapping_field(report, "systemStabilityGate")
    corpus_gate, unsafe_corpus_gate_shape = _mapping_field(report, "corpusReadinessGate")
    quality_gate, unsafe_quality_gate_shape = _mapping_field(report, "qualityGate")
    local_quality, unsafe_local_quality_shape = _mapping_field(quality_gate, "localQualityAssessment")
    threshold_profile, unsafe_threshold_profile_shape = _mapping_field(local_quality, "thresholdProfile")
    quality_diagnostics, unsafe_quality_diagnostics_shape = _mapping_field(report, "qualityDiagnostics")
    contribution_diagnostics, unsafe_contribution_diagnostics_shape = _mapping_field(
        report,
        "toolContributionDiagnostics",
    )

    system_status, unsafe_system_status = _allowlisted_field(
        system_gate.get("status"),
        default="unknown",
        allowed=_ALLOWED_SYSTEM_STATUSES,
    )
    corpus_status, unsafe_corpus_status = _allowlisted_field(
        corpus_gate.get("status"),
        default="unknown",
        allowed=_ALLOWED_CORPUS_READINESS_STATUSES,
    )
    corpus_ready, unsafe_corpus_ready = _bool_field(corpus_gate, "decisionGradeReady")
    quality_gate_allowed, unsafe_quality_gate_allowed = _bool_field(system_gate, "qualityGateAllowed")
    local_quality_status, unsafe_local_quality_status = _allowlisted_field(
        local_quality.get("status"),
        default="unknown",
        allowed=_ALLOWED_QUALITY_STATUSES,
    )
    final_quality_status, unsafe_final_quality_status = _allowlisted_field(
        quality_gate.get("status"),
        default="unknown",
        allowed=_ALLOWED_QUALITY_STATUSES,
    )
    threshold_intent, unsafe_threshold_intent = _allowlisted_field(
        threshold_profile.get("intent"),
        default="unknown",
        allowed=_ALLOWED_THRESHOLD_INTENTS,
    )
    threshold_status, unsafe_threshold_status = _allowlisted_field(
        threshold_profile.get("status"),
        default="unknown",
        allowed=_ALLOWED_THRESHOLD_STATUSES,
    )
    quality_diagnostics_status, unsafe_quality_diagnostics_status = _allowlisted_field(
        quality_diagnostics.get("status"),
        default="missing",
        allowed=_ALLOWED_DIAGNOSTIC_SURFACE_STATUSES,
    )
    contribution_diagnostics_status, unsafe_contribution_diagnostics_status = _allowlisted_field(
        contribution_diagnostics.get("status"),
        default="missing",
        allowed=_ALLOWED_DIAGNOSTIC_SURFACE_STATUSES,
    )
    system_reason_values, unsafe_system_reason_shape = _string_list(system_gate.get("reasonCodes"))
    corpus_reason_values, unsafe_corpus_reason_shape = _string_list(corpus_gate.get("reasonCodes"))
    local_quality_reason_values, unsafe_local_quality_reason_shape = _string_list(local_quality.get("reasonCodes"))
    threshold_reason_values, unsafe_threshold_reason_shape = _string_list(threshold_profile.get("reasonCodes"))
    final_quality_reason_values, unsafe_final_quality_reason_shape = _string_list(quality_gate.get("reasonCodes"))
    reason_codes, unsafe_reason_projection = _allowlisted_strings([
        *system_reason_values,
        *corpus_reason_values,
        *local_quality_reason_values,
        *threshold_reason_values,
        *final_quality_reason_values,
    ], _ALLOWED_REASON_CODES)
    decision_support, unsafe_decision_support_shape = _mapping_field(report, "decisionSupport")
    required_followup_values, unsafe_followup_shape = _string_list(decision_support.get("requiredFollowUps"))
    required_followups, unsafe_followup_projection = _allowlisted_strings(
        required_followup_values,
        _ALLOWED_REQUIRED_FOLLOWUPS,
    )
    diagnostic_candidate_ids, unsafe_diagnostic_candidate_projection = _diagnostic_candidate_ids(quality_diagnostics)
    tool_contribution_classes, unsafe_tool_contribution_projection = _tool_contribution_classes(contribution_diagnostics)
    unsafe_projection = any([
        unsafe_system_gate_shape,
        unsafe_corpus_gate_shape,
        unsafe_quality_gate_shape,
        unsafe_local_quality_shape,
        unsafe_threshold_profile_shape,
        unsafe_quality_diagnostics_shape,
        unsafe_contribution_diagnostics_shape,
        unsafe_system_status,
        unsafe_quality_gate_allowed,
        unsafe_corpus_status,
        unsafe_corpus_ready,
        unsafe_local_quality_status,
        unsafe_final_quality_status,
        unsafe_threshold_intent,
        unsafe_threshold_status,
        unsafe_quality_diagnostics_status,
        unsafe_contribution_diagnostics_status,
        unsafe_system_reason_shape,
        unsafe_corpus_reason_shape,
        unsafe_local_quality_reason_shape,
        unsafe_threshold_reason_shape,
        unsafe_final_quality_reason_shape,
        unsafe_decision_support_shape,
        unsafe_reason_projection,
        unsafe_followup_shape,
        unsafe_followup_projection,
        unsafe_diagnostic_candidate_projection,
        unsafe_tool_contribution_projection,
    ])
    otherwise_decision_grade_usable = (
        system_status == "pass"
        and quality_gate_allowed
        and corpus_status == "available"
        and corpus_ready
        and local_quality_status == "pass"
        and final_quality_status == "pass"
        and threshold_intent == "quality-sufficiency"
        and threshold_status == "decision_grade_candidate"
        and not unsafe_projection
    )
    decision_grade_projection_complete = _decision_grade_projection_complete(
        quality_diagnostics_status=quality_diagnostics_status,
        contribution_diagnostics_status=contribution_diagnostics_status,
        tool_contribution_classes=tool_contribution_classes,
        reason_codes=reason_codes,
        required_followups=required_followups,
    )
    if otherwise_decision_grade_usable and not decision_grade_projection_complete:
        unsafe_projection = True
    if unsafe_projection:
        reason_codes = _dedupe_strings([*reason_codes, _UNSAFE_PROJECTION_REASON])
    runner_integrity_signal = (
        threshold_intent == "runner-integrity-only"
        or "QUALITY_THRESHOLDS_NON_DISCRIMINATING" in reason_codes
    )
    runner_integrity_only = runner_integrity_signal and not unsafe_projection

    usable = otherwise_decision_grade_usable and decision_grade_projection_complete and not unsafe_projection

    return {
        "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
        "reportPresent": True,
        "reportLocation": "top-level",
        "schemaVersion": _EXPECTED_SCHEMA_VERSION,
        "systemStability": system_status,
        "corpusReadiness": corpus_status,
        "corpusDecisionGradeReady": corpus_ready,
        "localQualityStatus": local_quality_status,
        "thresholdIntent": threshold_intent,
        "thresholdProfileStatus": threshold_status,
        "finalQualityStatus": final_quality_status,
        "toolPortfolioDecisionGradeUsable": usable,
        "runnerIntegrityOnly": runner_integrity_only,
        "diagnosticSurfaces": {
            "qualityDiagnostics": quality_diagnostics_status,
            "toolContributionDiagnostics": contribution_diagnostics_status,
        },
        "reasonCodes": reason_codes,
        "requiredFollowUps": required_followups,
        "diagnosticCandidateIds": diagnostic_candidate_ids,
        "toolContributionClasses": tool_contribution_classes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(
        description="Summarize an offline S4 Tool Portfolio experiment report for consumer canaries.",
        add_help=True,
    )
    parser.add_argument("--report", required=True, help="Path to s4-tool-portfolio-experiment-report-v1 JSON.")
    parser.add_argument(
        "--require-decision-grade",
        action="store_true",
        help="Exit 2 when the sanitized summary is not decision-grade usable.",
    )

    try:
        args = parser.parse_args(argv)
        payload = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except Exception:
        _emit_cli_error()
        return 1

    summary = summarize_tool_portfolio_report(payload)
    if not _emit_summary_stdout(summary):
        _emit_cli_error(_CLI_OUTPUT_FAILED_REASON)
        return 1
    if summary.get("reportPresent") is not True:
        return 2
    if args.require_decision_grade and not summary.get("toolPortfolioDecisionGradeUsable"):
        return 2
    return 0


def _absent_summary(*, location: str, reason: str) -> dict[str, Any]:
    return {
        "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
        "reportPresent": False,
        "reportLocation": location,
        "schemaVersion": "unknown",
        "systemStability": "unknown",
        "corpusReadiness": "unknown",
        "corpusDecisionGradeReady": False,
        "localQualityStatus": "unknown",
        "thresholdIntent": "unknown",
        "thresholdProfileStatus": "unknown",
        "finalQualityStatus": "unknown",
        "toolPortfolioDecisionGradeUsable": False,
        "runnerIntegrityOnly": False,
        "diagnosticSurfaces": {
            "qualityDiagnostics": "missing",
            "toolContributionDiagnostics": "missing",
        },
        "reasonCodes": [reason],
        "requiredFollowUps": [],
        "diagnosticCandidateIds": [],
        "toolContributionClasses": {},
    }


def _diagnostic_candidate_ids(quality_diagnostics: Mapping[str, Any]) -> tuple[list[str], bool]:
    split_diagnostics, unsafe_split_diagnostics_shape = _mapping_field(quality_diagnostics, "splitDiagnostics")
    ids: list[str] = []
    rejected = unsafe_split_diagnostics_shape
    for split in ("validation", "test", "canary"):
        split_entry, unsafe_split_entry_shape = _mapping_field(split_diagnostics, split)
        triage, unsafe_triage_shape = _mapping_field(split_entry, "diagnosticTriage")
        rejected = rejected or unsafe_split_entry_shape or unsafe_triage_shape
        candidates = triage.get("candidates")
        if not isinstance(candidates, list):
            if "candidates" in triage:
                rejected = True
            continue
        for candidate in candidates:
            candidate_map = _mapping(candidate)
            if candidate_map is None:
                rejected = True
                continue
            candidate_id = candidate_map.get("candidateId")
            if not isinstance(candidate_id, str) or candidate_id not in _ALLOWED_DIAGNOSTIC_CANDIDATE_IDS:
                rejected = True
                continue
            if candidate_id not in ids:
                ids.append(candidate_id)
    return ids, rejected


def _tool_contribution_classes(contribution_diagnostics: Mapping[str, Any]) -> tuple[dict[str, str], bool]:
    tools = contribution_diagnostics.get("tools")
    if not isinstance(tools, list):
        return {}, "tools" in contribution_diagnostics
    result: dict[str, str] = {}
    rejected = False
    for entry in tools:
        entry_map = _mapping(entry)
        if entry_map is None:
            rejected = True
            continue
        tool_id = entry_map.get("toolId")
        evidence_class = entry_map.get("evidenceClass")
        if (
            not isinstance(tool_id, str)
            or tool_id not in _ALLOWED_TOOL_IDS
            or not isinstance(evidence_class, str)
            or evidence_class not in _ALLOWED_TOOL_CONTRIBUTION_CLASSES
        ):
            rejected = True
            continue
        if tool_id in result:
            rejected = True
            continue
        result[tool_id] = evidence_class
    return result, rejected


def _decision_grade_projection_complete(
    *,
    quality_diagnostics_status: str,
    contribution_diagnostics_status: str,
    tool_contribution_classes: dict[str, str],
    reason_codes: list[str],
    required_followups: list[str],
) -> bool:
    """Return whether a passing report exposes enough local evidence to be usable.

    Diagnostic candidate identifiers remain advisory: a clean decision-grade
    report may have no triage candidates. For decision-grade usability the
    consumer requires available diagnostic surfaces, all current-six tool
    contribution rows, and no sanitized failure reasons or required follow-ups.
    """

    return (
        quality_diagnostics_status == "available"
        and contribution_diagnostics_status == "available"
        and set(tool_contribution_classes) == _ALLOWED_TOOL_IDS
        and not reason_codes
        and not required_followups
    )


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _mapping_field(parent: Mapping[str, Any], key: str) -> tuple[Mapping[str, Any], bool]:
    if key not in parent or parent.get(key) is None:
        return {}, False
    value = parent[key]
    if isinstance(value, Mapping):
        return value, False
    return {}, True


def _bool_field(parent: Mapping[str, Any], key: str, *, default: bool = False) -> tuple[bool, bool]:
    if key not in parent or parent.get(key) is None:
        return default, False
    value = parent[key]
    if isinstance(value, bool):
        return value, False
    return default, True


def _allowlisted_field(value: Any, *, default: str, allowed: set[str]) -> tuple[str, bool]:
    if value is None:
        return default, False
    if not isinstance(value, str) or not value:
        return default, True
    if value not in allowed:
        return default, True
    return value, False


def _string_list(value: Any) -> tuple[list[str], bool]:
    if value is None:
        return [], False
    if not isinstance(value, list):
        return [], True
    result: list[str] = []
    rejected = False
    for item in value:
        if isinstance(item, str):
            result.append(item)
        else:
            rejected = True
    return result, rejected


def _allowlisted_strings(values: list[str], allowed: set[str]) -> tuple[list[str], bool]:
    result: list[str] = []
    rejected = False
    for value in values:
        if value not in allowed:
            rejected = True
            continue
        if value not in result:
            result.append(value)
    return result, rejected


def _dedupe_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _emit_summary_stdout(summary: dict[str, Any]) -> bool:
    try:
        sys.stdout.write(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, TypeError, UnicodeError):
        return False
    return True


def _emit_cli_error(reason: str = _CLI_INPUT_INVALID_REASON) -> None:
    error = _CLI_OUTPUT_FAILED_ERROR if reason == _CLI_OUTPUT_FAILED_REASON else _CLI_INPUT_INVALID_ERROR
    stage = "output" if reason == _CLI_OUTPUT_FAILED_REASON else "input"
    try:
        sys.stderr.write(json.dumps({
            "error": error,
            "reasonCode": reason,
            "reasonCodes": [reason],
            "stage": stage,
            "summaryEmitted": False,
        }, sort_keys=True, separators=(",", ":")) + "\n")
    except (OSError, TypeError, ValueError, UnicodeError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
