"""S4 Tool Portfolio offline-report consumer helpers.

S3 consumes this artifact only as experiment/readiness metadata. It must never
be promoted into vulnerability absence evidence or final security verdicts.
"""

from __future__ import annotations

from typing import Any


_REPORT_KEYS = (
    "s4ToolPortfolioReport",
    "toolPortfolioReport",
    "s4_tool_portfolio_report",
)
SUMMARY_SCHEMA_VERSION = "s4-tool-portfolio-report-consumer-summary-v1"
UNSAFE_REASON = "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"


def extract_tool_portfolio_report(*payloads: Any) -> dict:
    """Return the first S4 Tool Portfolio report dict from trusted payloads."""
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for key in _REPORT_KEYS:
            report = payload.get(key)
            if isinstance(report, dict) and report:
                return report
        # S4 may already pass the S3-facing consumer summary as the report body.
        if payload.get("summarySchemaVersion") == SUMMARY_SCHEMA_VERSION:
            return payload
    return {}


def summarize_tool_portfolio_report(report: Any) -> dict:
    """Summarize S3 decision-grade readiness for S4 Tool Portfolio artifacts."""
    if isinstance(report, dict) and report.get("summarySchemaVersion") == SUMMARY_SCHEMA_VERSION:
        return _summarize_consumer_summary(report)
    if not isinstance(report, dict) or not report:
        return _base_summary(
            present=False,
            reason_codes=["S4_TOOL_PORTFOLIO_REPORT_MISSING"],
            summary_text="S4 Tool Portfolio report is absent.",
        )

    system_gate = _dict(report.get("systemStabilityGate"))
    corpus_gate = _dict(report.get("corpusReadinessGate"))
    quality_gate = _dict(report.get("qualityGate"))
    local_quality = _dict(quality_gate.get("localQualityAssessment"))
    validation_metrics = _dict(report.get("validationMetrics"))
    test_metrics = _dict(report.get("testMetrics"))
    canary_metrics = _dict(report.get("canaryMetrics"))
    decision_support = _dict(report.get("decisionSupport"))

    system_status = _status(system_gate)
    corpus_status = _status(corpus_gate)
    decision_grade_ready = corpus_gate.get("decisionGradeReady") is True
    quality_gate_status = _status(quality_gate)
    local_quality_status = _status(local_quality)
    validation_status = _status(validation_metrics)
    test_status = _status(test_metrics)
    canary_status = _status(canary_metrics)
    legacy_external = decision_support.get("externalCorpusStatus")
    sard_aggregate = _sard_aggregate_status(corpus_gate, decision_support)

    reason_codes: list[str] = []
    if system_status != "pass":
        reason_codes.append(f"SYSTEM_STABILITY_NOT_PASS:{system_status or 'missing'}")
    if corpus_status != "available":
        reason_codes.append(f"CORPUS_READINESS_NOT_AVAILABLE:{corpus_status or 'missing'}")
    if not decision_grade_ready:
        reason_codes.append("CORPUS_DECISION_GRADE_NOT_READY")
    if quality_gate_status != "pass":
        reason_codes.append(f"QUALITY_GATE_STATUS_NOT_PASS:{quality_gate_status or 'missing'}")
    if local_quality_status != "pass":
        reason_codes.append(f"LOCAL_QUALITY_ASSESSMENT_NOT_PASS:{local_quality_status or 'missing'}")

    for container in (
        system_gate,
        corpus_gate,
        quality_gate,
        local_quality,
        validation_metrics,
        test_metrics,
        canary_metrics,
    ):
        reason_codes.extend(_reason_codes(container))

    quality_candidate = (
        system_status == "pass"
        and corpus_status == "available"
        and decision_grade_ready
        and quality_gate_status == "pass"
        and local_quality_status == "pass"
    )
    if quality_candidate:
        reason_codes.append("S4_TOOL_PORTFOLIO_REPORT_EXPERIMENT_METADATA_ONLY")

    return _base_summary(
        present=True,
        decision_grade_ready=decision_grade_ready,
        reason_codes=reason_codes,
        summary_text=(
            "S4 Tool Portfolio report is decision-grade offline experiment metadata, "
            "not runtime decision-grade evidence."
            if quality_candidate
            else "S4 Tool Portfolio report is not decision-grade quality evidence."
        ),
        system_status=system_status,
        corpus_status=corpus_status,
        quality_gate_status=quality_gate_status,
        local_quality_status=local_quality_status,
        validation_status=validation_status,
        test_status=test_status,
        canary_status=canary_status,
        legacy_external=legacy_external,
        sard_aggregate=sard_aggregate,
    )


def _base_summary(
    *,
    present: bool,
    decision_grade_ready: bool = False,
    reason_codes: list[str] | None = None,
    summary_text: str,
    system_status: str | None = None,
    corpus_status: str | None = None,
    quality_gate_status: str | None = None,
    local_quality_status: str | None = None,
    validation_status: str | None = None,
    test_status: str | None = None,
    canary_status: str | None = None,
    legacy_external: Any = None,
    sard_aggregate: dict | None = None,
    tool_portfolio_usable: bool = False,
    runner_integrity_only: bool = False,
    required_followups: list[str] | None = None,
    tool_contribution_classes: dict | None = None,
) -> dict:
    return {
        "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
        "present": present,
        "qualityReady": False,
        "decisionGradeReady": bool(decision_grade_ready),
        "toolPortfolioDecisionGradeUsable": bool(tool_portfolio_usable),
        "runnerIntegrityOnly": bool(runner_integrity_only),
        "reasonCodes": sorted(set(reason_codes or [])),
        "requiredFollowUps": list(required_followups or []),
        "summary": summary_text,
        "corpusReadinessAuthoritative": True,
        "systemStability": system_status,
        "corpusStatus": corpus_status,
        "qualityGateStatus": quality_gate_status,
        "localQualityStatus": local_quality_status,
        "validationMetricsStatus": validation_status,
        "testMetricsStatus": test_status,
        "canaryMetricsStatus": canary_status,
        "legacyExternalCorpusStatus": legacy_external,
        "sardAggregateStatus": sard_aggregate,
        "toolContributionClasses": dict(tool_contribution_classes or {}),
    }


def _summarize_consumer_summary(report: dict) -> dict:
    reason_codes = _reason_codes(report)
    required_followups = _string_list(report.get("requiredFollowUps"))
    unsafe = UNSAFE_REASON in reason_codes
    usable = bool(report.get("toolPortfolioDecisionGradeUsable")) and not unsafe
    runner_integrity_only = bool(report.get("runnerIntegrityOnly")) and not unsafe
    decision_grade_ready = usable and not required_followups
    if usable:
        reason_codes.append("S4_TOOL_PORTFOLIO_REPORT_EXPERIMENT_METADATA_ONLY")
    tool_classes = report.get("toolContributionClasses")
    if not isinstance(tool_classes, dict):
        tool_classes = {}
    return _base_summary(
        present=bool(report.get("reportPresent", True)),
        decision_grade_ready=decision_grade_ready,
        tool_portfolio_usable=usable,
        runner_integrity_only=runner_integrity_only,
        reason_codes=reason_codes,
        required_followups=required_followups,
        summary_text=(
            "S4 Tool Portfolio consumer summary is decision-grade offline experiment metadata, "
            "not runtime decision-grade evidence."
            if usable
            else "S4 Tool Portfolio consumer summary is not decision-grade usable."
        ),
        system_status=_string_or_none(report.get("systemStability")),
        corpus_status=_string_or_none(report.get("corpusStatus")),
        quality_gate_status=_string_or_none(report.get("qualityGateStatus")),
        local_quality_status=_string_or_none(report.get("localQualityStatus")),
        validation_status=_string_or_none(report.get("validationMetricsStatus")),
        test_status=_string_or_none(report.get("testMetricsStatus")),
        canary_status=_string_or_none(report.get("canaryMetricsStatus")),
        legacy_external=report.get("legacyExternalCorpusStatus"),
        sard_aggregate=report.get("sardAggregateStatus") if isinstance(report.get("sardAggregateStatus"), dict) else None,
        tool_contribution_classes={
            str(key): str(value)
            for key, value in tool_classes.items()
            if isinstance(key, str) and isinstance(value, str)
        },
    )


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _status(value: dict) -> str | None:
    status = value.get("status")
    return status if isinstance(status, str) and status else None


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _reason_codes(value: dict) -> list[str]:
    raw = value.get("reasonCodes")
    if not isinstance(raw, list):
        return []
    result: list[str] = []
    for item in raw:
        if isinstance(item, str) and item:
            result.append(item)
        elif isinstance(item, dict):
            code = item.get("code")
            if isinstance(code, str) and code:
                result.append(code)
    return result


def _sard_aggregate_status(corpus_gate: dict, decision_support: dict) -> dict | None:
    for container in (corpus_gate, decision_support):
        external = container.get("externalCorpusStatus")
        if not isinstance(external, dict):
            continue
        sard = external.get("sard")
        if isinstance(sard, dict):
            return dict(sard)
        aggregate = external.get("sardAggregateStatus")
        if isinstance(aggregate, dict):
            return dict(aggregate)
    return None
