from app.core.s4_tool_portfolio_report import (
    extract_tool_portfolio_report,
    summarize_tool_portfolio_report,
)


def _base_report(**overrides):
    report = {
        "schemaVersion": "s4-tool-portfolio-experiment-report-v1",
        "systemStabilityGate": {"status": "pass"},
        "corpusReadinessGate": {
            "status": "available",
            "decisionGradeReady": True,
            "externalCorpusStatus": {
                "sard": {"vulnerable": "available", "secure": "available"},
            },
        },
        "qualityGate": {
            "status": "pass",
            "localQualityAssessment": {"status": "pass"},
        },
        "validationMetrics": {"status": "pass"},
        "testMetrics": {"status": "pass"},
        "canaryMetrics": {"status": "not_run"},
        "decisionSupport": {"externalCorpusStatus": "available"},
    }
    report.update(overrides)
    return report


def test_extracts_report_from_trusted_or_quick_context():
    report = _base_report()

    assert extract_tool_portfolio_report({"s4ToolPortfolioReport": report}) is report
    assert extract_tool_portfolio_report({}, {"toolPortfolioReport": report}) is report


def test_corpus_readiness_gate_overrides_legacy_external_status():
    report = _base_report(
        corpusReadinessGate={
            "status": "blocked",
            "decisionGradeReady": False,
            "externalCorpusStatus": {
                "sard": {"vulnerable": "available", "secure": "blocked"},
            },
        },
        decisionSupport={"externalCorpusStatus": "available"},
    )

    summary = summarize_tool_portfolio_report(report)

    assert summary["present"] is True
    assert summary["qualityReady"] is False
    assert summary["decisionGradeReady"] is False
    assert summary["corpusStatus"] == "blocked"
    assert summary["legacyExternalCorpusStatus"] == "available"
    assert summary["sardAggregateStatus"] == {"vulnerable": "available", "secure": "blocked"}
    assert "CORPUS_READINESS_NOT_AVAILABLE:blocked" in summary["reasonCodes"]
    assert "CORPUS_DECISION_GRADE_NOT_READY" in summary["reasonCodes"]


def test_metric_pass_buckets_do_not_imply_quality_pass():
    report = _base_report(
        qualityGate={
            "status": "fail",
            "localQualityAssessment": {
                "status": "fail",
                "reasonCodes": ["INVALID_THRESHOLDS"],
            },
        },
        validationMetrics={"status": "pass"},
        testMetrics={"status": "pass"},
    )

    summary = summarize_tool_portfolio_report(report)

    assert summary["validationMetricsStatus"] == "pass"
    assert summary["testMetricsStatus"] == "pass"
    assert summary["localQualityStatus"] == "fail"
    assert summary["qualityReady"] is False
    assert "LOCAL_QUALITY_ASSESSMENT_NOT_PASS:fail" in summary["reasonCodes"]
    assert "INVALID_THRESHOLDS" in summary["reasonCodes"]


def test_system_stability_gate_is_quality_prerequisite():
    report = _base_report(systemStabilityGate={"status": "not_run", "reasonCodes": ["HARNESS_NOT_RUN"]})

    summary = summarize_tool_portfolio_report(report)

    assert summary["qualityReady"] is False
    assert summary["systemStability"] == "not_run"
    assert "SYSTEM_STABILITY_NOT_PASS:not_run" in summary["reasonCodes"]
    assert "HARNESS_NOT_RUN" in summary["reasonCodes"]


def test_sard_aggregate_preserved_from_legacy_decision_support_fallback():
    report = _base_report(
        corpusReadinessGate={"status": "available", "decisionGradeReady": True},
        decisionSupport={
            "externalCorpusStatus": {
                "sard": {
                    "status": "mixed",
                    "acquisitionIds": ["sard-vuln-acq", "sard-secure-acq"],
                }
            }
        },
    )

    summary = summarize_tool_portfolio_report(report)

    assert summary["sardAggregateStatus"] == {
        "status": "mixed",
        "acquisitionIds": ["sard-vuln-acq", "sard-secure-acq"],
    }


def test_absent_tool_portfolio_report_is_never_quality_ready():
    summary = summarize_tool_portfolio_report({})

    assert summary["present"] is False
    assert summary["qualityReady"] is False
    assert summary["decisionGradeReady"] is False
    assert summary["corpusReadinessAuthoritative"] is True
    assert summary["reasonCodes"] == ["S4_TOOL_PORTFOLIO_REPORT_MISSING"]


def test_decision_grade_report_remains_experiment_metadata_not_runtime_quality_ready():
    summary = summarize_tool_portfolio_report(_base_report())

    assert summary["present"] is True
    assert summary["decisionGradeReady"] is True
    assert summary["qualityReady"] is False
    assert "S4_TOOL_PORTFOLIO_REPORT_EXPERIMENT_METADATA_ONLY" in summary["reasonCodes"]
    assert "not runtime decision-grade evidence" in summary["summary"]


def _consumer_summary(**overrides):
    summary = {
        "summarySchemaVersion": "s4-tool-portfolio-report-consumer-summary-v1",
        "reportPresent": True,
        "toolPortfolioDecisionGradeUsable": True,
        "runnerIntegrityOnly": False,
        "reasonCodes": [],
        "requiredFollowUps": [],
        "systemStability": "pass",
        "corpusStatus": "available",
        "decisionGradeReady": True,
        "qualityGateStatus": "pass",
        "localQualityStatus": "pass",
        "thresholdProfileStatus": "quality-sufficiency",
        "toolContributionClasses": {
            "semgrep": "unique",
            "cppcheck": "overlap",
            "flawfinder": "overlap",
            "clang-tidy": "unique",
            "scan-build": "unique",
            "gcc-fanalyzer": "unique",
        },
    }
    summary.update(overrides)
    return summary


def test_consumes_tool_portfolio_consumer_summary_with_exact_schema_but_not_runtime_quality():
    summary = summarize_tool_portfolio_report(_consumer_summary())

    assert summary["present"] is True
    assert summary["summarySchemaVersion"] == "s4-tool-portfolio-report-consumer-summary-v1"
    assert summary["decisionGradeReady"] is True
    assert summary["toolPortfolioDecisionGradeUsable"] is True
    assert summary["qualityReady"] is False
    assert "S4_TOOL_PORTFOLIO_REPORT_EXPERIMENT_METADATA_ONLY" in summary["reasonCodes"]
    assert set(summary) == {
        "summarySchemaVersion",
        "present",
        "qualityReady",
        "decisionGradeReady",
        "toolPortfolioDecisionGradeUsable",
        "runnerIntegrityOnly",
        "reasonCodes",
        "requiredFollowUps",
        "summary",
        "corpusReadinessAuthoritative",
        "systemStability",
        "corpusStatus",
        "qualityGateStatus",
        "localQualityStatus",
        "validationMetricsStatus",
        "testMetricsStatus",
        "canaryMetricsStatus",
        "legacyExternalCorpusStatus",
        "sardAggregateStatus",
        "toolContributionClasses",
    }


def test_tool_portfolio_unsafe_projection_forces_unusable_summary():
    summary = summarize_tool_portfolio_report(_consumer_summary(
        toolPortfolioDecisionGradeUsable=True,
        reasonCodes=["TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION"],
    ))

    assert summary["decisionGradeReady"] is False
    assert summary["toolPortfolioDecisionGradeUsable"] is False
    assert summary["qualityReady"] is False
    assert "TOOL_PORTFOLIO_REPORT_UNSAFE_PROJECTION" in summary["reasonCodes"]


def test_tool_portfolio_runner_integrity_only_is_diagnostic_not_quality_ready():
    summary = summarize_tool_portfolio_report(_consumer_summary(
        toolPortfolioDecisionGradeUsable=False,
        runnerIntegrityOnly=True,
        reasonCodes=["RUNNER_INTEGRITY_ONLY"],
    ))

    assert summary["runnerIntegrityOnly"] is True
    assert summary["decisionGradeReady"] is False
    assert summary["qualityReady"] is False
