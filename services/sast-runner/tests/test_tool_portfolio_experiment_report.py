from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.response import SastFinding
from benchmark.tool_portfolio_acquisition_manifest import ACQUISITION_SCHEMA_VERSION, build_acquisition_index, manifest_checksum
from benchmark.tool_portfolio_corpus_readiness import build_corpus_readiness_gate
from benchmark.tool_portfolio_experiment_manifest import CORPUS_SCHEMA_VERSION, required_current_six_configs
from benchmark.tool_portfolio_experiment_report import (
    EXPERIMENT_REPORT_SCHEMA_VERSION,
    _reject_forbidden_keys,
    build_experiment_report,
    write_experiment_report,
)
from benchmark.tool_portfolio_harness_fixture import build_harness_fixture_report, load_harness_fixture
from benchmark.tool_portfolio_report_consumer_canary import SUMMARY_SCHEMA_VERSION, summarize_tool_portfolio_report
from benchmark.tool_portfolio_system_gate import build_system_stability_gate

FORBIDDEN_VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}
HARNESS_FIXTURE_REPORT_PATH = Path("benchmark/results/tool_portfolio/s4-harness-fixture-report-v1.json")
HARNESS_FIXTURE_CONSUMER_SUMMARY_PATH = Path(
    "benchmark/results/tool_portfolio/s4-harness-fixture-consumer-summary-v1.json",
)
HARNESS_FIXTURE_REGENERATION_COMMAND = (
    "cd services/sast-runner && PYTHONPATH=. .venv/bin/python - <<'PY'\n"
    "from pathlib import Path\n"
    "from benchmark.tool_portfolio_harness_fixture import write_harness_fixture_report\n"
    "write_harness_fixture_report("
    "Path('benchmark/results/tool_portfolio/s4-harness-fixture-report-v1.json'), "
    "repo_root=Path('.').resolve())\n"
    "PY"
)


def _acquisition_manifest() -> dict:
    return {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "acquisitionId": "s4-harness-fixture-v1",
        "sourceName": "S4 harness fixture",
        "sourceUrl": "local://services/sast-runner/tests/fixtures/tool_portfolio_experiment_v1",
        "sourceVersion": "1",
        "licenseOrRedistributionNote": "S4-owned synthetic/precomputed fixture, not Juliet evidence.",
        "downloadedAt": "2026-05-12",
        "archiveChecksum": "sha256:" + "1" * 64,
        "extractionRootChecksum": "sha256:" + "2" * 64,
        "localPath": "tests/fixtures/tool_portfolio_experiment_v1",
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }


def _case(case_id: str, split: str, cwe: str, line: int, *, polarity: str = "positive") -> dict:
    acq = _acquisition_manifest()
    return {
        "caseId": case_id,
        "targetId": f"{case_id}-target",
        "lineageId": case_id,
        "sliceKind": "s4-canary" if split == "canary" else f"s4-harness-fixture-{polarity}",
        "split": split,
        "language": "c",
        "sourceArtifact": "s4-harness-fixture",
        "acquisitionId": acq["acquisitionId"],
        "acquisitionManifestChecksum": manifest_checksum(acq),
        "sourceRef": f"s4-harness-fixture-v1:{case_id}",
        "sourcePath": f"{case_id}.c",
        "checksum": "sha256:" + ("3" if split == "validation" else "4" if split == "test" else "5") * 64,
        "expected": {
            "targetId": f"{case_id}-target",
            "granularity": "sink-line" if polarity == "positive" else "negative-region",
            "cweId": cwe,
            "polarity": polarity,
            "locations": [{"file": f"{case_id}.c", "line": line, "role": "sink"}],
            "functionRegion": {"function": "bad" if polarity == "positive" else "good", "startLine": max(1, line - 5), "endLine": line + 5},
            "allowedMatchWindows": {"lineDelta": 3, "functionFallback": False},
            **({"allowedWarningPolicy": {"mode": "no-findings-in-region", "allowedRuleIds": []}} if polarity == "negative" else {}),
        },
        "buildContext": {"requiresCompileCommands": False, "compileCommandsFixture": None, "defines": [], "includePaths": []},
        "notes": [],
    }


def _corpus_manifest() -> dict:
    return {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [
            _case("validation-semgrep-unique", "validation", "CWE-121", 40),
            _case("validation-overlap", "validation", "CWE-190", 20),
            _case("test-gcc-unique", "test", "CWE-416", 30),
            _case("test-negative", "test", "CWE-121", 80, polarity="negative"),
            _case("canary-buffer-copy", "canary", "CWE-120", 12),
        ],
    }


def _finding(tool: str, case_id: str, line: int, cwe: str) -> SastFinding:
    return SastFinding(
        toolId=tool,
        ruleId=f"{tool}:fixture",
        severity="warning",
        message="fixture finding",
        location={"file": f"{case_id}.c", "line": line, "column": 1},
        metadata={
            "cweId": cwe,
            "cwe": [cwe],
            "evidenceResolution": {"cwe": {"status": "known", "id": cwe, "source": "metadata.cweId"}},
        },
    )


def _findings_by_config() -> dict[str, list[SastFinding]]:
    full = [
        _finding("semgrep", "validation-semgrep-unique", 40, "CWE-121"),
        _finding("semgrep", "validation-overlap", 20, "CWE-190"),
        _finding("cppcheck", "validation-overlap", 20, "CWE-190"),
        _finding("gcc-fanalyzer", "test-gcc-unique", 30, "CWE-416"),
        _finding("flawfinder", "test-negative", 80, "CWE-121"),
        _finding("semgrep", "canary-buffer-copy", 12, "CWE-120"),
    ]
    by_config: dict[str, list[SastFinding]] = {"full-current-six": full}
    by_config.update({f"single-tool:{tool}": [f for f in full if f.tool_id == tool] for tool in ALL_TOOLS})
    by_config.update({f"leave-one-out:{tool}": [f for f in full if f.tool_id != tool] for tool in ALL_TOOLS})
    by_config["parser-only-current-six"] = []
    by_config["contract-canary-current-six"] = [f for f in full if f.location.file == "canary-buffer-copy.c"]
    return by_config


def _passing_system_stability_gate() -> dict:
    availability = {
        tool: {"available": True, "version": f"{idx}.0.0", "probeReason": None}
        for idx, tool in enumerate(ALL_TOOLS, start=1)
    }
    results = {
        tool: {"status": "ok", "findingsCount": 0, "elapsedMs": 10, "version": f"{idx}.0.0"}
        for idx, tool in enumerate(ALL_TOOLS, start=1)
    }
    return build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=results,
    )


def _available_corpus_readiness_gate() -> dict:
    return {
        "schemaVersion": "s4-tool-portfolio-corpus-readiness-gate-v1",
        "status": "available",
        "decisionGradeReady": True,
        "requiredCorpora": ["juliet-c-cpp-1.3"],
        "reasonCodes": [],
        "acquisitionStatuses": {
            "juliet-c-cpp-1.3": {
                "status": "available",
                "acquisitionId": "juliet-c-cpp-1.3",
                "localPathStatus": "available",
                "resolvedLocalPathStatus": "available",
                "reasonCodes": [],
                "splitCounts": {"validation": 1, "test": 1},
            },
        },
        "caseStatuses": [
            {
                "status": "available",
                "acquisitionId": "juliet-c-cpp-1.3",
                "caseId": "validation-clean",
                "sourcePath": "validation-clean.c",
                "resolvedPathStatus": "available",
                "reasonCodes": [],
            },
            {
                "status": "available",
                "acquisitionId": "juliet-c-cpp-1.3",
                "caseId": "test-clean",
                "sourcePath": "test-clean.c",
                "resolvedPathStatus": "available",
                "reasonCodes": [],
            },
        ],
        "externalCorpusStatus": {
            "juliet": {
                "status": "available",
                "reasonCodes": [],
                "acquisitionIds": ["juliet-c-cpp-1.3"],
            },
        },
        "summary": {
            "checkedCaseCount": 2,
            "splitCounts": {"validation": 1, "test": 1},
        },
        "consumerPolicy": "local_filesystem_readiness_only_not_quality_or_security_verdict",
    }


def _clean_quality_corpus_and_findings() -> tuple[dict, dict[str, list[SastFinding]]]:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [
            _case("validation-clean", "validation", "CWE-121", 40),
            _case("test-clean", "test", "CWE-416", 30),
            _case("canary-clean", "canary", "CWE-120", 12),
        ],
    }
    findings = [
        _finding("semgrep", "validation-clean", 40, "CWE-121"),
        _finding("gcc-fanalyzer", "test-clean", 30, "CWE-416"),
        _finding("semgrep", "canary-clean", 12, "CWE-120"),
    ]
    by_config: dict[str, list[SastFinding]] = {"full-current-six": findings}
    by_config.update({f"single-tool:{tool}": [f for f in findings if f.tool_id == tool] for tool in ALL_TOOLS})
    by_config.update({f"leave-one-out:{tool}": [f for f in findings if f.tool_id != tool] for tool in ALL_TOOLS})
    by_config["parser-only-current-six"] = []
    by_config["contract-canary-current-six"] = [findings[-1]]
    return corpus, by_config


def _by_config_for_primary_findings(findings: list[SastFinding]) -> dict[str, list[SastFinding]]:
    by_config: dict[str, list[SastFinding]] = {"full-current-six": findings}
    by_config.update({f"single-tool:{tool}": [f for f in findings if f.tool_id == tool] for tool in ALL_TOOLS})
    by_config.update({f"leave-one-out:{tool}": [f for f in findings if f.tool_id != tool] for tool in ALL_TOOLS})
    by_config["parser-only-current-six"] = []
    by_config["contract-canary-current-six"] = []
    return by_config


def _contribution_report(
    *,
    corpus: dict | None = None,
    by_config: dict[str, list[SastFinding]] | None = None,
    thresholds: dict | None = None,
    **kwargs: object,
) -> dict:
    return build_experiment_report(
        run_id="tool-contribution-diagnostics-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus or _corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config or _findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds=thresholds or {
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
        **kwargs,
    )


def test_file_based_s4_harness_fixture_builds_end_to_end_report() -> None:
    fixture = load_harness_fixture()
    report = build_harness_fixture_report(repo_root=Path(__file__).parents[1])
    committed = json.loads((Path(__file__).parents[1] / HARNESS_FIXTURE_REPORT_PATH).read_text(encoding="utf-8"))
    oracle = json.loads(
        (Path(__file__).parent / "fixtures" / "tool_portfolio_experiment_v1" / "quality_gate_oracle.json")
        .read_text(encoding="utf-8"),
    )

    assert fixture["schemaVersion"] == "s4-tool-portfolio-harness-fixture-v1"
    assert report["schemaVersion"] == EXPERIMENT_REPORT_SCHEMA_VERSION
    assert report["systemStabilityGate"]["status"] == "not_run"
    assert report["systemStabilityGate"]["qualityGateAllowed"] is False
    assert report["corpusReadinessGate"]["status"] == "blocked"
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in report["corpusReadinessGate"]["reasonCodes"]
    assert report["validationMetrics"]["status"] == "pass"
    assert report["testMetrics"]["status"] == "pass"
    assert report["decisionSupport"]["externalCorpusStatus"]["juliet"]["status"] == "blocked"
    assert report["portfolioMetrics"]["uniqueTpContribution"]["scan-build"] >= 1
    for candidate in (report, committed):
        assert candidate["qualityDiagnostics"]["status"] == "available"
        assert candidate["toolContributionDiagnostics"]["status"] == "available"
        assert [
            row["toolId"]
            for row in candidate["toolContributionDiagnostics"]["tools"]
        ] == ALL_TOOLS
        assert candidate["qualityGate"]["status"] == "not_decision_grade"
    assert report["qualityGate"]["status"] == oracle["expected"]["qualityGateStatus"]
    assert report["qualityGate"]["decision"] == oracle["expected"]["decision"]
    local = report["qualityGate"]["localQualityAssessment"]
    expected_local = oracle["expected"]["localQualityAssessment"]
    assert local["status"] == expected_local["status"]
    assert local["primaryToolSetConfig"] == expected_local["primaryToolSetConfig"]
    assert local["failingSplits"] == expected_local["failingSplits"]
    assert local["passingSplits"] == expected_local["passingSplits"]
    for split, reason_codes in expected_local["splitReasonCodes"].items():
        assert local["splitAssessments"][split]["reasonCodes"] == reason_codes
    # Metrics bucket status means "scoring succeeded"; threshold pass/fail lives only in Quality Gate.
    assert report["validationMetrics"]["status"] == "pass"
    assert local["splitAssessments"]["validation"]["status"] == "fail"
    # Splits without negative targets expose negativeTargetFpr=null; max-FPR threshold is not applicable there.
    assert local["splitAssessments"]["validation"]["metrics"]["negativeTargetFpr"] is None
    assert "NEGATIVE_TARGET_FPR_ABOVE_THRESHOLD" not in local["splitAssessments"]["validation"]["reasonCodes"]
    assert local["splitAssessments"]["canary"]["metrics"]["negativeTargetFpr"] is None
    assert "NEGATIVE_TARGET_FPR_ABOVE_THRESHOLD" not in local["splitAssessments"]["canary"]["reasonCodes"]


def test_committed_harness_fixture_report_matches_generated_contract() -> None:
    repo_root = Path(__file__).parents[1]
    committed_path = repo_root / HARNESS_FIXTURE_REPORT_PATH
    committed = json.loads(committed_path.read_text(encoding="utf-8"))
    generated = build_harness_fixture_report(repo_root=repo_root)

    assert committed == generated, (
        "Committed S4 harness fixture report drifted from build_harness_fixture_report(). "
        f"Regenerate with:\n{HARNESS_FIXTURE_REGENERATION_COMMAND}"
    )


def test_only_canonical_tool_portfolio_experiment_report_artifact_is_committed() -> None:
    repo_root = Path(__file__).parents[1]
    results_root = repo_root / "benchmark" / "results" / "tool_portfolio"
    canonical_report = json.loads((repo_root / HARNESS_FIXTURE_REPORT_PATH).read_text(encoding="utf-8"))
    expected_consumer_summary = summarize_tool_portfolio_report(canonical_report)
    offenders: list[str] = []
    for path in sorted(results_root.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schemaVersion") != EXPERIMENT_REPORT_SCHEMA_VERSION:
            continue
        relative_path = path.relative_to(repo_root)
        if relative_path == HARNESS_FIXTURE_REPORT_PATH:
            continue
        if (
            relative_path == HARNESS_FIXTURE_CONSUMER_SUMMARY_PATH
            and document.get("summarySchemaVersion") == SUMMARY_SCHEMA_VERSION
            and document == expected_consumer_summary
        ):
            continue
        offenders.append(str(relative_path))

    assert offenders == [], (
        "Only the canonical S4 harness experiment report artifact may use "
        f"{EXPERIMENT_REPORT_SCHEMA_VERSION}; stale experiment reports: {offenders}"
    )


def test_split_metric_buckets_only_score_findings_for_that_split() -> None:
    report = build_harness_fixture_report(repo_root=Path(__file__).parents[1])

    validation = report["validationMetrics"]["byConfig"]["full-current-six"]
    test = report["testMetrics"]["byConfig"]["full-current-six"]
    canary = report["canaryMetrics"]["byConfig"]["full-current-six"]

    assert validation["targetTP"] == 3
    assert validation["fpFindings"] == 3
    assert test["targetTP"] == 1
    assert test["negativeTargetViolationCount"] == 1
    assert test["fpFindings"] == 1
    assert canary["targetTP"] == 1
    assert canary["fpFindings"] == 0


def test_experiment_report_exercises_current_six_configs_and_keeps_external_juliet_blocked() -> None:
    corpus = _corpus_manifest()
    acquisition = _acquisition_manifest()

    report = build_experiment_report(
        run_id="unit-fixture-run",
        created_at="2026-05-12T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[acquisition],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "blocked", "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]}},
    )

    assert report["schemaVersion"] == EXPERIMENT_REPORT_SCHEMA_VERSION
    assert set(report["toolSetConfigs"]) == set(required_current_six_configs())
    assert report["validationMetrics"]["status"] == "pass"
    assert report["testMetrics"]["status"] == "pass"
    assert report["canaryMetrics"]["status"] == "pass"
    assert report["decisionSupport"]["currentDecision"] == "insufficient-evidence-for-tool-change"
    assert report["decisionSupport"]["futureCandidateActionsRequireWr"] is True
    assert report["decisionSupport"]["addCandidates"] == []
    assert report["decisionSupport"]["externalCorpusStatus"]["juliet"]["status"] == "blocked"
    assert report["benchmarkSliceEvidence"]["consumerPolicy"] == "historical_prerequisite_not_replacement_test_evidence"


def test_experiment_report_treats_not_run_corpus_readiness_as_not_decision_grade() -> None:
    report = build_experiment_report(
        run_id="readiness-not-run-fixture",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
    )

    assert report["corpusReadinessGate"]["status"] == "not_run"
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "CORPUS_READINESS_GATE_NOT_RUN" in report["qualityGate"]["reasonCodes"]
    assert report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]["status"] == "not_run"
    assert report["decisionSupport"]["requiredFollowUps"]


def test_experiment_report_readiness_not_run_overrides_legacy_available_external_status() -> None:
    report = build_experiment_report(
        run_id="readiness-not-run-with-legacy-available",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available", "reasonCodes": []}},
    )

    assert report["corpusReadinessGate"]["status"] == "not_run"
    assert report["decisionSupport"]["externalCorpusStatus"]["juliet"]["status"] == "available"
    assert report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]["status"] == "not_run"
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "CORPUS_READINESS_GATE_NOT_RUN" in report["qualityGate"]["reasonCodes"]


def _assert_inconsistent_corpus_readiness_gate_not_decision_grade(readiness_gate: dict) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="inconsistent-corpus-readiness-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=readiness_gate,
        system_stability=_passing_system_stability_gate(),
    )

    normalized_gate = report["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert normalized_gate["decisionGradeReady"] is False
    assert "CORPUS_READINESS_GATE_INCONSISTENT" in normalized_gate["reasonCodes"]
    assert normalized_gate["acquisitionStatuses"] == readiness_gate["acquisitionStatuses"]
    assert normalized_gate["caseStatuses"] == readiness_gate["caseStatuses"]
    assert normalized_gate["summary"] == readiness_gate["summary"]
    assert normalized_gate["consistencyChecks"]["status"] == "fail"
    projected = report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]
    assert projected["status"] == "blocked"
    assert "CORPUS_READINESS_GATE_INCONSISTENT" in projected["reasonCodes"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "CORPUS_READINESS_GATE_INCONSISTENT" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"
    assert report["decisionSupport"]["currentDecision"] == "insufficient-evidence-for-tool-change"


def test_experiment_report_blocks_decision_grade_when_blocked_readiness_projects_available() -> None:
    gate = _available_corpus_readiness_gate()
    gate["status"] = "blocked"
    gate["decisionGradeReady"] = False
    gate["reasonCodes"] = ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]
    gate["acquisitionStatuses"]["juliet-c-cpp-1.3"]["status"] = "blocked"
    gate["acquisitionStatuses"]["juliet-c-cpp-1.3"]["reasonCodes"] = ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]
    gate["caseStatuses"] = [{"caseId": "preserved-case", "status": "blocked"}]
    gate["summary"] = {"checkedCaseCount": 1, "splitCounts": {"validation": 1}}
    gate["externalCorpusStatus"] = {"juliet": {"status": "available", "reasonCodes": []}}

    _assert_inconsistent_corpus_readiness_gate_not_decision_grade(gate)


def test_experiment_report_blocks_decision_grade_when_available_readiness_is_not_ready() -> None:
    gate = _available_corpus_readiness_gate()
    gate["decisionGradeReady"] = False

    _assert_inconsistent_corpus_readiness_gate_not_decision_grade(gate)


def test_experiment_report_blocks_decision_grade_when_available_readiness_has_reason_codes() -> None:
    gate = _available_corpus_readiness_gate()
    gate["reasonCodes"] = ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]

    _assert_inconsistent_corpus_readiness_gate_not_decision_grade(gate)


def test_experiment_report_blocks_decision_grade_when_not_run_readiness_projects_available() -> None:
    gate = _available_corpus_readiness_gate()
    gate["status"] = "not_run"
    gate["decisionGradeReady"] = True
    gate["reasonCodes"] = ["CORPUS_READINESS_GATE_NOT_RUN"]
    gate["externalCorpusStatus"] = {"juliet": {"status": "available", "reasonCodes": []}}

    _assert_inconsistent_corpus_readiness_gate_not_decision_grade(gate)


def _assert_invalid_corpus_readiness_gate_not_decision_grade(
    readiness_gate: object,
    expected_input: dict[str, str],
    forbidden_substrings=(),
) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-corpus-readiness-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=readiness_gate,  # type: ignore[arg-type]
        system_stability=_passing_system_stability_gate(),
    )

    normalized_gate = report["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert normalized_gate["decisionGradeReady"] is False
    assert normalized_gate["reasonCodes"] == ["CORPUS_READINESS_GATE_INPUT_INVALID"]
    assert normalized_gate["inputValidation"]["status"] == "fail"
    assert normalized_gate["inputValidation"]["failures"] == [{
        "reasonCode": "CORPUS_READINESS_GATE_INPUT_INVALID",
        "input": expected_input,
    }]
    projected = report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]
    assert projected["status"] == "blocked"
    assert projected["reasonCodes"] == ["CORPUS_READINESS_GATE_INPUT_INVALID"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert report["qualityGate"]["decision"] == "insufficient-evidence-for-tool-change"
    assert "CORPUS_READINESS_GATE_INPUT_INVALID" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"
    serialized = json.dumps(report, sort_keys=True)
    for substring in forbidden_substrings:
        assert substring not in serialized


def test_experiment_report_blocks_when_corpus_readiness_gate_is_list() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        [],
        {"category": "non-mapping", "type": "list"},
    )


def test_experiment_report_blocks_when_corpus_readiness_gate_is_string() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        "available",
        {"category": "non-mapping", "type": "str"},
    )


def test_experiment_report_blocks_when_corpus_readiness_gate_is_empty_mapping() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {},
        {"category": "missing-field", "field": "status"},
    )


def test_experiment_report_blocks_when_corpus_readiness_status_is_unknown() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {"status": "unknown", "decisionGradeReady": False},
        {"category": "invalid-status", "status": "<invalid>"},
    )


def test_experiment_report_blocks_when_corpus_readiness_status_secret_is_not_echoed() -> None:
    secret = "SECRET_CORPUS_STATUS_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {"status": secret, "decisionGradeReady": False},
        {"category": "invalid-status", "status": "<invalid>"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_corpus_readiness_status_object_is_not_stringified() -> None:
    secret = "SECRET_CORPUS_STATUS_OBJECT_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {"status": {"secret": secret}, "decisionGradeReady": False},
        {"category": "invalid-field", "field": "status", "type": "dict"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_corpus_readiness_has_secret_unknown_top_level_field() -> None:
    secret = "SECRET_CORPUS_TOP_FIELD_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            secret: "value",
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_top_level_key_object_is_not_stringified() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            ("secret", "SECRET_CORPUS_TOP_KEY_OBJECT_SHOULD_NOT_LEAK"): "value",
        },
        {"category": "unknown-field", "field": "<invalid>", "type": "tuple"},
        forbidden_substrings=("SECRET_CORPUS_TOP_KEY_OBJECT_SHOULD_NOT_LEAK",),
    )


def test_experiment_report_blocks_when_corpus_readiness_schema_version_secret_is_not_echoed() -> None:
    secret = "SECRET_CORPUS_SCHEMA_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "schemaVersion": secret,
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
        },
        {"category": "invalid-schema-version", "field": "schemaVersion"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_consumer_policy_secret_is_not_echoed() -> None:
    secret = "SECRET_CORPUS_POLICY_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            "consumerPolicy": secret,
        },
        {"category": "invalid-consumer-policy", "field": "consumerPolicy"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_summary_secret_field_is_not_echoed() -> None:
    secret = "SECRET_CORPUS_SUMMARY_FIELD_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            "summary": {"checkedCaseCount": 0, secret: 1},
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_summary_split_key_secret_is_not_echoed() -> None:
    secret = "SECRET_CORPUS_SPLIT_KEY_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            "summary": {"checkedCaseCount": 0, "splitCounts": {secret: 1}},
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_acquisition_secret_field_is_not_echoed() -> None:
    secret = "SECRET_CORPUS_ACQUISITION_FIELD_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            "acquisitionStatuses": {
                "juliet-c-cpp-1.3": {
                    "status": "blocked",
                    "acquisitionId": "juliet-c-cpp-1.3",
                    "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
                    secret: "value",
                },
            },
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_case_secret_field_is_not_echoed() -> None:
    secret = "SECRET_CORPUS_CASE_FIELD_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["CORPUS_CASE_SOURCE_MISSING"],
            "caseStatuses": [{
                "status": "blocked",
                "acquisitionId": "juliet-c-cpp-1.3",
                "caseId": "case-1",
                "sourcePath": "safe.c",
                "resolvedPathStatus": "missing",
                "reasonCodes": ["CORPUS_CASE_SOURCE_MISSING"],
                secret: "value",
            }],
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_input_validation_smuggles_secret() -> None:
    secret = "SECRET_CORPUS_INPUT_VALIDATION_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            "inputValidation": {
                "status": "fail",
                "failures": [{"input": {"field": secret}}],
            },
        },
        {"category": "forbidden-field", "field": "inputValidation"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_corpus_readiness_consistency_checks_smuggle_secret() -> None:
    secret = "SECRET_CORPUS_CONSISTENCY_SHOULD_NOT_LEAK"
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {
            "status": "blocked",
            "decisionGradeReady": False,
            "reasonCodes": ["CORPUS_READINESS_GATE_INCONSISTENT"],
            "consistencyChecks": {
                "status": "fail",
                "failures": [{
                    "reasonCode": "CORPUS_READINESS_GATE_INCONSISTENT",
                    "observedStatus": secret,
                    "observedDecisionGradeReady": True,
                    "externalCorpusStatusAvailableOnly": True,
                }],
            },
        },
        {"category": "invalid-consistency-check", "field": "consistencyChecks.failures.0.observedStatus", "status": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_accepts_generated_required_corpus_input_validation_shape() -> None:
    gate = build_corpus_readiness_gate(
        acquisition_manifests=[_acquisition_manifest()],
        corpus_manifest=_corpus_manifest(),
        required_corpora=["SECRET CORPUS ID"],
    )

    report = build_experiment_report(
        run_id="generated-required-corpus-input-validation-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    normalized_gate = report["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert normalized_gate["reasonCodes"] == ["CORPUS_REQUIRED_CORPUS_ID_INVALID"]
    assert normalized_gate["requiredCorpusInputValidation"]["status"] == "fail"
    assert normalized_gate["requiredCorpusInputValidation"]["failures"] == [{"index": 0, "category": "invalid_string"}]


def test_experiment_report_reaccepts_normalized_inconsistent_corpus_readiness_gate() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["status"] = "blocked"
    gate["decisionGradeReady"] = False
    gate["reasonCodes"] = ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]
    gate["acquisitionStatuses"]["juliet-c-cpp-1.3"]["status"] = "blocked"

    corpus, by_config = _clean_quality_corpus_and_findings()
    first = build_experiment_report(
        run_id="inconsistent-corpus-readiness-first-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )
    second = build_experiment_report(
        run_id="inconsistent-corpus-readiness-second-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=first["corpusReadinessGate"],
        system_stability=_passing_system_stability_gate(),
    )

    normalized_gate = second["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert "CORPUS_READINESS_GATE_INCONSISTENT" in normalized_gate["reasonCodes"]
    assert "CORPUS_READINESS_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    assert normalized_gate["consistencyChecks"]["failures"][0]["reasonCode"] == "CORPUS_READINESS_GATE_INCONSISTENT"


def test_experiment_report_accepts_harness_slice_counts_in_corpus_readiness_summary() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["summary"]["sliceCounts"] = {
        "s4-harness-fixture-positive": 1,
        "s4-harness-fixture-negative": 1,
    }

    report = build_experiment_report(
        run_id="harness-slice-count-readiness-summary-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    assert report["corpusReadinessGate"]["summary"]["sliceCounts"] == gate["summary"]["sliceCounts"]


def test_experiment_report_blocks_when_corpus_readiness_decision_grade_ready_is_not_bool() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {"status": "blocked", "decisionGradeReady": "false"},
        {"category": "invalid-field", "field": "decisionGradeReady", "type": "str"},
    )


def test_experiment_report_blocks_when_corpus_readiness_reason_codes_are_malformed() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {"status": "blocked", "decisionGradeReady": False, "reasonCodes": "LOCAL_JULIET_CORPUS_NOT_PRESENT"},
        {"category": "invalid-field", "field": "reasonCodes", "type": "str"},
    )


def test_experiment_report_blocks_when_corpus_readiness_reason_code_item_is_malformed() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {"status": "blocked", "decisionGradeReady": False, "reasonCodes": [{"bad": "shape"}]},
        {"category": "invalid-reason-code", "field": "reasonCodes.0", "type": "dict"},
    )


def test_experiment_report_blocks_available_readiness_with_unknown_local_path_status_without_raw_leak() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    secret_status = "SECRET_LOCAL_PATH_STATUS_SHOULD_NOT_LEAK"
    gate["acquisitionStatuses"]["juliet-c-cpp-1.3"]["localPathStatus"] = secret_status

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-readiness-path-status",
            "field": "acquisitionStatuses.juliet-c-cpp-1.3.localPathStatus",
            "reason": "unknown-status-value",
        },
        forbidden_substrings=[secret_status],
    )


def test_experiment_report_blocks_available_readiness_missing_case_resolved_path_status() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    del gate["caseStatuses"][0]["resolvedPathStatus"]

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {"category": "missing-field", "field": "caseStatuses.0.resolvedPathStatus"},
    )


def test_experiment_report_blocks_readiness_raw_path_fields_without_raw_leak() -> None:
    gate = {
        "schemaVersion": "s4-tool-portfolio-corpus-readiness-gate-v1",
        "status": "blocked",
        "decisionGradeReady": False,
        "requiredCorpora": ["juliet-c-cpp-1.3"],
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
        "acquisitionStatuses": {
            "juliet-c-cpp-1.3": {
                "status": "blocked",
                "acquisitionId": "juliet-c-cpp-1.3",
                "localPath": "/tmp/SECRET_LOCAL_PATH_SHOULD_NOT_LEAK",
                "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
            },
        },
        "caseStatuses": [
            {
                "status": "blocked",
                "acquisitionId": "juliet-c-cpp-1.3",
                "caseId": "blocked-case",
                "sourcePath": "blocked.c",
                "resolvedPath": "/tmp/SECRET_RESOLVED_PATH_SHOULD_NOT_LEAK",
                "reasonCodes": ["CORPUS_CASE_SOURCE_MISSING"],
            },
        ],
        "externalCorpusStatus": {
            "juliet": {
                "status": "blocked",
                "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
                "acquisitionIds": ["juliet-c-cpp-1.3"],
            },
        },
        "summary": {"checkedCaseCount": 0},
    }

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "forbidden-field",
            "field": "acquisitionStatuses.juliet-c-cpp-1.3.localPath",
        },
        forbidden_substrings=["SECRET_LOCAL_PATH_SHOULD_NOT_LEAK", "SECRET_RESOLVED_PATH_SHOULD_NOT_LEAK"],
    )


def test_experiment_report_blocks_available_readiness_extra_acquisition_raw_path_without_raw_leak() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["acquisitionStatuses"]["extra-corpus"] = {
        "status": "available",
        "acquisitionId": "extra-corpus",
        "localPath": "/tmp/SECRET_EXTRA_LOCAL_PATH_SHOULD_NOT_LEAK",
        "localPathStatus": "available",
        "resolvedLocalPathStatus": "available",
        "reasonCodes": [],
    }

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "forbidden-field",
            "field": "acquisitionStatuses.extra-corpus.localPath",
        },
        forbidden_substrings=["SECRET_EXTRA_LOCAL_PATH_SHOULD_NOT_LEAK"],
    )


def test_experiment_report_blocks_available_readiness_unsafe_source_path_without_raw_leak() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    secret_source_path = "/tmp/SECRET_SOURCEPATH_SHOULD_NOT_LEAK.c"
    gate["caseStatuses"][0]["sourcePath"] = secret_source_path

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-readiness-source-path",
            "field": "caseStatuses.0.sourcePath",
            "reason": "unsafe",
        },
        forbidden_substrings=[secret_source_path, "SECRET_SOURCEPATH_SHOULD_NOT_LEAK"],
    )


def test_experiment_report_blocks_available_readiness_with_unsafe_source_path_status() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["caseStatuses"][0]["sourcePathStatus"] = "unsafe"

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-readiness-path-status",
            "field": "caseStatuses.0.sourcePathStatus",
            "reason": "available-case-source-path-status",
        },
    )


def test_experiment_report_sanitizes_malicious_required_corpora_in_caller_readiness_gate() -> None:
    secret = "SECRET_CORPUS_SHOULD_NOT_LEAK\n"
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": ["CORPUS_REQUIRED_CORPUS_ID_INVALID"],
        "requiredCorpora": [secret],
        "externalCorpusStatus": {
            secret: {"status": "blocked", "reasonCodes": [secret]},
        },
    }

    report = build_experiment_report(
        run_id="malicious-required-corpora-readiness-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    payload = json.dumps(report, sort_keys=True)
    normalized_gate = report["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert normalized_gate["reasonCodes"] == ["CORPUS_READINESS_GATE_INPUT_INVALID"]
    assert normalized_gate["inputValidation"]["failures"][0]["input"]["field"] == "requiredCorpora.0"
    assert "SECRET_CORPUS_SHOULD_NOT_LEAK" not in payload


def test_experiment_report_sanitizes_malicious_external_status_key_and_reason_in_blocked_readiness_gate() -> None:
    secret = "SECRET_EXTERNAL_STATUS_SHOULD_NOT_LEAK\n"
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
        "externalCorpusStatus": {
            secret: {"status": "blocked", "reasonCodes": [secret]},
        },
    }

    report = build_experiment_report(
        run_id="malicious-external-status-readiness-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    payload = json.dumps(report, sort_keys=True)
    normalized_gate = report["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert normalized_gate["reasonCodes"] == ["CORPUS_READINESS_GATE_INPUT_INVALID"]
    assert normalized_gate["inputValidation"]["failures"][0]["input"]["field"] == "externalCorpusStatus.<unsafe>"
    assert "SECRET_EXTERNAL_STATUS_SHOULD_NOT_LEAK" not in payload


def test_experiment_report_sanitizes_safe_shaped_malicious_external_status_key_in_blocked_readiness_gate() -> None:
    secret_key = "SECRET_STATUS_KEY_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
        "externalCorpusStatus": {
            secret_key: {"status": "blocked", "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]},
        },
    }

    report = build_experiment_report(
        run_id="safe-shaped-external-status-readiness-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    payload = json.dumps(report, sort_keys=True)
    assert report["corpusReadinessGate"]["externalCorpusStatus"] == {}
    assert report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"] == {
        "status": "blocked",
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
    }
    assert "SECRET_STATUS_KEY_SHOULD_NOT_LEAK" not in payload


def test_experiment_report_drops_unknown_nested_external_status_fields_in_blocked_readiness_gate() -> None:
    secret_nested = "SECRET_NESTED_FIELD_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
        "externalCorpusStatus": {
            "juliet": {
                "status": "blocked",
                "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
                "attackerField": secret_nested,
            },
        },
    }

    report = build_experiment_report(
        run_id="nested-external-status-field-readiness-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    payload = json.dumps(report, sort_keys=True)
    assert report["corpusReadinessGate"]["externalCorpusStatus"]["juliet"] == {
        "status": "blocked",
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
    }
    assert "attackerField" not in payload
    assert "SECRET_NESTED_FIELD_SHOULD_NOT_LEAK" not in payload


def test_experiment_report_rejects_safe_shaped_malicious_readiness_reason_code_without_raw_leak() -> None:
    secret_reason = "SECRET_REASON_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": [secret_reason],
    }

    report = build_experiment_report(
        run_id="safe-shaped-reason-code-readiness-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    payload = json.dumps(report, sort_keys=True)
    normalized_gate = report["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert normalized_gate["reasonCodes"] == ["CORPUS_READINESS_GATE_INPUT_INVALID"]
    assert normalized_gate["inputValidation"]["failures"][0]["input"] == {
        "category": "invalid-reason-code",
        "field": "reasonCodes.0",
        "reason": "invalid_string",
    }
    assert "SECRET_REASON_SHOULD_NOT_LEAK" not in payload


def test_experiment_report_blocks_forged_available_corpus_readiness_without_required_corpora() -> None:
    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        {"status": "available", "decisionGradeReady": True},
        {"category": "missing-field", "field": "requiredCorpora"},
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_missing_required_acquisition() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["acquisitionStatuses"] = {}

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "missing-required-acquisition",
            "field": "acquisitionStatuses",
            "acquisitionId": "juliet-c-cpp-1.3",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_non_empty_acquisition_reasons() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["acquisitionStatuses"]["juliet-c-cpp-1.3"]["reasonCodes"] = ["LOCAL_CORPUS_PATH_NOT_FOUND"]

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-acquisition-reason-codes",
            "field": "acquisitionStatuses.juliet-c-cpp-1.3.reasonCodes",
            "reason": "non-empty",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_missing_acquisition_test_split() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["acquisitionStatuses"]["juliet-c-cpp-1.3"]["splitCounts"] = {"validation": 2}

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "missing-required-split",
            "field": "acquisitionStatuses.juliet-c-cpp-1.3.splitCounts.test",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_empty_case_statuses() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["caseStatuses"] = []

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {"category": "invalid-case-statuses", "reason": "empty"},
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_malformed_case_statuses() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["caseStatuses"] = "bad"

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {"category": "invalid-field", "field": "caseStatuses", "type": "str"},
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_failing_case_status() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["caseStatuses"][0]["reasonCodes"] = ["CORPUS_CASE_CHECKSUM_MISMATCH"]

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-case-status",
            "field": "caseStatuses.0.reasonCodes",
            "reason": "non-empty",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_unrelated_case_statuses() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    for case_status in gate["caseStatuses"]:
        case_status["acquisitionId"] = "unrelated-corpus"

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-case-acquisition",
            "field": "caseStatuses.0.acquisitionId",
            "acquisitionId": "unrelated-corpus",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_missing_required_case_evidence() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["requiredCorpora"].append("sard-c-v2-vulnerable")
    gate["acquisitionStatuses"]["sard-c-v2-vulnerable"] = {
        "status": "available",
        "acquisitionId": "sard-c-v2-vulnerable",
        "localPathStatus": "available",
        "resolvedLocalPathStatus": "available",
        "reasonCodes": [],
        "splitCounts": {"validation": 1, "test": 1},
    }
    gate["externalCorpusStatus"]["sard"] = {
        "status": "available",
        "reasonCodes": [],
        "acquisitionIds": ["sard-c-v2-vulnerable"],
    }

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "missing-required-case-evidence",
            "field": "caseStatuses",
            "acquisitionId": "sard-c-v2-vulnerable",
        },
    )


def test_experiment_report_accepts_available_corpus_readiness_with_multiple_external_projections() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["requiredCorpora"].append("sard-c-v2-vulnerable")
    gate["acquisitionStatuses"]["sard-c-v2-vulnerable"] = {
        "status": "available",
        "acquisitionId": "sard-c-v2-vulnerable",
        "localPathStatus": "available",
        "resolvedLocalPathStatus": "available",
        "reasonCodes": [],
        "splitCounts": {"validation": 1, "test": 1},
    }
    gate["caseStatuses"].extend([
        {
            "status": "available",
            "acquisitionId": "sard-c-v2-vulnerable",
                "caseId": "sard-validation-clean",
                "sourcePath": "sard-validation-clean.c",
                "resolvedPathStatus": "available",
                "reasonCodes": [],
            },
            {
            "status": "available",
            "acquisitionId": "sard-c-v2-vulnerable",
                "caseId": "sard-test-clean",
                "sourcePath": "sard-test-clean.c",
                "resolvedPathStatus": "available",
                "reasonCodes": [],
            },
    ])
    gate["externalCorpusStatus"]["sard"] = {
        "status": "available",
        "reasonCodes": [],
        "acquisitionIds": ["sard-c-v2-vulnerable"],
    }
    gate["summary"]["checkedCaseCount"] = 4
    gate["summary"]["splitCounts"] = {"validation": 2, "test": 2}

    report = build_experiment_report(
        run_id="multi-corpus-available-readiness-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"legacy": {"status": "available", "reasonCodes": []}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    assert report["corpusReadinessGate"] == gate
    assert report["decisionSupport"]["externalCorpusStatus"]["juliet"]["status"] == "available"
    assert report["decisionSupport"]["externalCorpusStatus"]["sard"]["status"] == "available"
    assert report["qualityGate"]["status"] == "pass"
    assert report["qualityGate"]["decision"] == "quality-gate-pass"


def test_experiment_report_available_readiness_ignores_unrelated_legacy_blocked_external_status() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="available-readiness-legacy-blocked-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"legacy": {"status": "blocked", "reasonCodes": ["LEGACY_BLOCKED"]}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["decisionSupport"]["externalCorpusStatus"]["legacy"]["status"] == "blocked"
    assert report["qualityGate"]["status"] == "pass"
    assert report["qualityGate"]["decision"] == "quality-gate-pass"
    assert report["qualityGate"]["reasonCodes"] == []
    assert report["decisionSupport"]["requiredFollowUps"] == []


def test_experiment_report_omits_reserved_legacy_external_corpus_status_key() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="reserved-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={
            "requiredCorpusReadiness": {"status": "blocked", "reasonCodes": ["LEGACY_BLOCKED"]},
        },
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    decision_support = report["decisionSupport"]
    assert "requiredCorpusReadiness" not in decision_support["externalCorpusStatus"]
    assert decision_support["externalCorpusStatus"]["juliet"]["status"] == "available"
    assert decision_support["requiredFollowUps"] == []
    assert report["qualityGate"]["status"] == "pass"
    assert decision_support["legacyExternalCorpusStatusInputValidation"] == {
        "status": "fail",
        "failures": [{"category": "reserved-key", "key": "requiredCorpusReadiness"}],
    }


def test_experiment_report_reports_reserved_legacy_key_when_readiness_owns_projection() -> None:
    report = build_experiment_report(
        run_id="reserved-legacy-external-corpus-status-readiness-owned-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={
            "requiredCorpusReadiness": {"status": "available", "reasonCodes": []},
        },
    )

    decision_support = report["decisionSupport"]
    assert decision_support["externalCorpusStatus"]["requiredCorpusReadiness"]["status"] == "not_run"
    assert decision_support["legacyExternalCorpusStatusInputValidation"] == {
        "status": "fail",
        "failures": [{"category": "reserved-key", "key": "requiredCorpusReadiness"}],
    }
    assert report["qualityGate"]["status"] == "not_decision_grade"


def test_experiment_report_does_not_echo_invalid_legacy_external_corpus_status_value() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-status-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"legacy": {"status": "SECRET_TOKEN_SHOULD_NOT_LEAK"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    validation = report["decisionSupport"]["legacyExternalCorpusStatusInputValidation"]
    assert validation == {
        "status": "fail",
        "failures": [{"category": "invalid-status", "key": "<invalid>", "field": "status"}],
    }
    assert "SECRET_TOKEN_SHOULD_NOT_LEAK" not in json.dumps(validation)
    assert "legacy" not in report["decisionSupport"]["externalCorpusStatus"]
    assert report["qualityGate"]["status"] == "pass"


def test_experiment_report_sanitizes_forbidden_legacy_external_corpus_status_context() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="forbidden-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"legacy": {"status": "available", "riskScore": 0.99}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    decision_support = report["decisionSupport"]
    assert "legacy" not in decision_support["externalCorpusStatus"]
    assert report["qualityGate"]["status"] == "pass"
    validation = decision_support["legacyExternalCorpusStatusInputValidation"]
    assert validation["status"] == "fail"
    assert validation["failures"] == [{"category": "unknown-field", "key": "<invalid>", "field": "<invalid>"}]
    assert "riskScore" not in validation["failures"][0]


def test_experiment_report_does_not_echo_invalid_legacy_external_corpus_status_key() -> None:
    secret_key = "SECRET_LEGACY_KEY_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-key-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={secret_key: "available"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    serialized = json.dumps(report, sort_keys=True)
    validation = report["decisionSupport"]["legacyExternalCorpusStatusInputValidation"]
    assert validation["failures"] == [{"category": "invalid-entry", "key": "<invalid>", "type": "str"}]
    assert secret_key not in serialized


def test_experiment_report_does_not_stringify_invalid_legacy_external_corpus_status_key() -> None:
    secret_key = "SECRET_LEGACY_KEY_OBJECT_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-object-key-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={("secret", secret_key): "available"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    serialized = json.dumps(report, sort_keys=True)
    validation = report["decisionSupport"]["legacyExternalCorpusStatusInputValidation"]
    assert validation["failures"] == [{
        "category": "invalid-key",
        "key": "<invalid>",
        "type": "tuple",
    }]
    assert secret_key not in serialized


def test_experiment_report_does_not_echo_unknown_legacy_external_corpus_status_field() -> None:
    secret_field = "SECRET_LEGACY_FIELD_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-field-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"legacy": {"status": "available", secret_field: "value"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    serialized = json.dumps(report, sort_keys=True)
    validation = report["decisionSupport"]["legacyExternalCorpusStatusInputValidation"]
    assert validation["failures"] == [{"category": "unknown-field", "key": "<invalid>", "field": "<invalid>"}]
    assert secret_field not in serialized


def test_experiment_report_does_not_stringify_unknown_legacy_external_corpus_status_field() -> None:
    secret_field = "SECRET_LEGACY_FIELD_OBJECT_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-object-field-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"legacy": {"status": "available", ("secret", secret_field): "value"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    serialized = json.dumps(report, sort_keys=True)
    validation = report["decisionSupport"]["legacyExternalCorpusStatusInputValidation"]
    assert validation["failures"] == [{
        "category": "unknown-field",
        "key": "<invalid>",
        "field": "<invalid>",
        "type": "tuple",
    }]
    assert secret_field not in serialized


def test_experiment_report_omits_malformed_legacy_external_corpus_status_entries() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="malformed-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={
            "stringEntry": "available",
            "badReasons": {"status": "blocked", "reasonCodes": "LEGACY_BLOCKED"},
            "badAcquisitionIds": {"status": "available", "acquisitionIds": [123]},
        },
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    decision_support = report["decisionSupport"]
    assert "stringEntry" not in decision_support["externalCorpusStatus"]
    assert "badReasons" not in decision_support["externalCorpusStatus"]
    assert "badAcquisitionIds" not in decision_support["externalCorpusStatus"]
    assert report["qualityGate"]["status"] == "pass"
    assert decision_support["legacyExternalCorpusStatusInputValidation"] == {
        "status": "fail",
        "failures": [
            {"category": "invalid-entry", "key": "<invalid>", "type": "str"},
            {"category": "invalid-field", "key": "<invalid>", "field": "reasonCodes", "type": "str"},
            {
                "category": "invalid-sequence-item",
                "key": "<invalid>",
                "field": "acquisitionIds.0",
                "type": "int",
            },
        ],
    }


def test_experiment_report_preserves_valid_non_readiness_owned_legacy_external_corpus_status() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="valid-legacy-external-corpus-status-context-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={
            "legacy": {
                "status": "blocked",
                "reasonCodes": ["LEGACY_BLOCKED"],
                "acquisitionIds": ["legacy-corpus-v1"],
            },
            "juliet": {"status": "blocked", "reasonCodes": ["LEGACY_JULIET_BLOCKED"]},
        },
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    decision_support = report["decisionSupport"]
    assert decision_support["externalCorpusStatus"]["legacy"] == {
        "status": "blocked",
        "reasonCodes": ["LEGACY_BLOCKED"],
        "acquisitionIds": ["legacy-corpus-v1"],
    }
    assert decision_support["externalCorpusStatus"]["juliet"]["status"] == "available"
    assert "LEGACY_JULIET_BLOCKED" not in decision_support["externalCorpusStatus"]["juliet"].get("reasonCodes", [])
    assert "legacyExternalCorpusStatusInputValidation" not in decision_support
    assert report["qualityGate"]["status"] == "pass"
    assert decision_support["requiredFollowUps"] == []


def test_experiment_report_blocks_forged_available_corpus_readiness_with_checked_count_mismatch() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["summary"]["checkedCaseCount"] = 1

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-summary",
            "field": "summary.checkedCaseCount",
            "expected": "2",
            "actual": "1",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_missing_summary_validation_split() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["summary"]["splitCounts"] = {"test": 2}

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {"category": "missing-required-split", "field": "summary.splitCounts.validation"},
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_unrelated_external_projection() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["externalCorpusStatus"] = {
        "unrelated": {
            "status": "available",
            "reasonCodes": [],
            "acquisitionIds": ["unrelated-corpus"],
        },
    }

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-external-corpus-status",
            "reason": "required-corpus-projection-missing",
            "acquisitionId": "juliet-c-cpp-1.3",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_wrong_external_acquisition_id() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["externalCorpusStatus"]["juliet"]["acquisitionIds"] = ["wrong-corpus"]

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-external-corpus-status",
            "reason": "required-corpus-projection-missing",
            "acquisitionId": "juliet-c-cpp-1.3",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_malformed_external_acquisition_ids() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["externalCorpusStatus"]["juliet"]["acquisitionIds"] = "juliet-c-cpp-1.3"

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-field",
            "field": "externalCorpusStatus.juliet.acquisitionIds",
            "type": "str",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_exact_key_wrong_acquisition_id() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["externalCorpusStatus"] = {
        "juliet-c-cpp-1.3": {
            "status": "available",
            "reasonCodes": [],
            "acquisitionIds": ["wrong-corpus"],
        },
    }

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-external-corpus-status",
            "reason": "required-corpus-projection-missing",
            "acquisitionId": "juliet-c-cpp-1.3",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_malformed_external_reason_code() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["externalCorpusStatus"]["juliet"]["reasonCodes"] = [{"bad": "shape"}]

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-reason-code",
            "field": "externalCorpusStatus.juliet.reasonCodes.0",
            "type": "dict",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_blank_external_reason_code() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["externalCorpusStatus"]["juliet"]["reasonCodes"] = [""]

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-reason-code",
            "field": "externalCorpusStatus.juliet.reasonCodes.0",
            "reason": "blank",
        },
    )


def test_experiment_report_blocks_forged_available_corpus_readiness_with_non_empty_external_reason_codes() -> None:
    gate = deepcopy(_available_corpus_readiness_gate())
    gate["externalCorpusStatus"]["juliet"]["reasonCodes"] = ["LOCAL_JULIET_CORPUS_INCOMPLETE"]

    _assert_invalid_corpus_readiness_gate_not_decision_grade(
        gate,
        {
            "category": "invalid-external-corpus-status",
            "field": "externalCorpusStatus.juliet.reasonCodes",
            "reason": "non-empty",
        },
    )


def test_experiment_report_preserves_minimal_blocked_corpus_readiness_evidence() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
    }

    report = build_experiment_report(
        run_id="minimal-blocked-corpus-readiness-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    assert report["corpusReadinessGate"] == gate
    assert "CORPUS_READINESS_GATE_INPUT_INVALID" not in report["corpusReadinessGate"]["reasonCodes"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"


def test_experiment_report_preserves_minimal_not_run_corpus_readiness_evidence() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "not_run",
        "decisionGradeReady": False,
        "reasonCodes": ["CORPUS_READINESS_GATE_NOT_RUN"],
    }

    report = build_experiment_report(
        run_id="minimal-not-run-corpus-readiness-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    assert report["corpusReadinessGate"] == gate
    assert "CORPUS_READINESS_GATE_INPUT_INVALID" not in report["corpusReadinessGate"]["reasonCodes"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "CORPUS_READINESS_GATE_NOT_RUN" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"


def test_experiment_report_blocks_inconsistent_corpus_readiness_with_malformed_external_status() -> None:
    gate = {
        "status": "not_run",
        "decisionGradeReady": True,
        "reasonCodes": ["CORPUS_READINESS_GATE_NOT_RUN"],
        "externalCorpusStatus": "bad",
    }

    report = build_experiment_report(
        run_id="inconsistent-readiness-malformed-external-status-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    normalized_gate = report["corpusReadinessGate"]
    assert normalized_gate["status"] == "blocked"
    assert normalized_gate["decisionGradeReady"] is False
    assert "CORPUS_READINESS_GATE_INCONSISTENT" in normalized_gate["reasonCodes"]
    assert "CORPUS_READINESS_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    assert normalized_gate["consistencyChecks"]["status"] == "fail"
    assert report["qualityGate"]["status"] == "not_decision_grade"


def test_experiment_report_blocks_when_blocked_readiness_embedded_status_has_no_reasons() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
        "externalCorpusStatus": {"juliet": {"status": "blocked", "reasonCodes": []}},
    }

    report = build_experiment_report(
        run_id="blocked-readiness-empty-embedded-reasons-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    projected = report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]
    assert projected["status"] == "blocked"
    assert projected["reasonCodes"] == ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"


def test_experiment_report_blocks_when_not_run_readiness_embedded_status_has_no_reasons() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "not_run",
        "decisionGradeReady": False,
        "reasonCodes": ["CORPUS_READINESS_GATE_NOT_RUN"],
        "externalCorpusStatus": {"juliet": {"status": "not_run", "reasonCodes": []}},
    }

    report = build_experiment_report(
        run_id="not-run-readiness-empty-embedded-reasons-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    projected = report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]
    assert projected["status"] == "not_run"
    assert projected["reasonCodes"] == ["CORPUS_READINESS_GATE_NOT_RUN"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "CORPUS_READINESS_GATE_NOT_RUN" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"


def test_experiment_report_blocks_when_non_available_readiness_has_malformed_embedded_projection() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"],
        "externalCorpusStatus": {"juliet": {"status": "mystery"}},
    }

    report = build_experiment_report(
        run_id="blocked-readiness-malformed-embedded-projection-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=gate,
        system_stability=_passing_system_stability_gate(),
    )

    projected = report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]
    assert projected["status"] == "blocked"
    assert projected["reasonCodes"] == ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"


def test_experiment_report_ignores_non_mapping_legacy_external_corpus_status() -> None:
    report = build_experiment_report(
        run_id="non-mapping-legacy-external-corpus-status-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status="available",  # type: ignore[arg-type]
    )

    assert report["corpusReadinessGate"]["status"] == "not_run"
    assert report["decisionSupport"]["externalCorpusStatus"]["requiredCorpusReadiness"]["status"] == "not_run"
    assert "juliet" not in report["decisionSupport"]["externalCorpusStatus"]
    assert report["qualityGate"]["status"] == "not_decision_grade"


def test_experiment_report_blocks_quality_metrics_when_system_stability_gate_fails() -> None:
    """도구 생존 전제조건이 깨지면 current-six config가 없어도 blocked report를 남긴다."""
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {
        "available": False,
        "version": None,
        "probeReason": "environment-drift",
        "expectedExecutablePath": "/svc/.venv/bin/semgrep",
    }
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="failed-preflight-run",
        created_at="2026-05-12T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        system_stability=system_gate,
    )

    assert report["systemStabilityGate"]["status"] == "fail"
    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "blocked"
    assert report["validationMetrics"]["status"] == "blocked"
    assert report["testMetrics"]["status"] == "blocked"
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert report["decisionSupport"]["currentDecision"] == "invalid-precondition"
    assert "SYSTEM_STABILITY_GATE_FAILED" in report["decisionSupport"]["reasonCodes"]


def test_experiment_report_not_decision_grade_when_system_stability_is_not_run_even_if_quality_passes() -> None:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [
            _case("validation-clean", "validation", "CWE-121", 40),
            _case("test-clean", "test", "CWE-416", 30),
            _case("canary-clean", "canary", "CWE-120", 12),
        ],
    }
    findings = [
        _finding("semgrep", "validation-clean", 40, "CWE-121"),
        _finding("gcc-fanalyzer", "test-clean", 30, "CWE-416"),
        _finding("semgrep", "canary-clean", 12, "CWE-120"),
    ]
    by_config: dict[str, list[SastFinding]] = {"full-current-six": findings}
    by_config.update({f"single-tool:{tool}": [f for f in findings if f.tool_id == tool] for tool in ALL_TOOLS})
    by_config.update({f"leave-one-out:{tool}": [f for f in findings if f.tool_id != tool] for tool in ALL_TOOLS})
    by_config["parser-only-current-six"] = []
    by_config["contract-canary-current-six"] = [findings[-1]]

    report = build_experiment_report(
        run_id="clean-quality-no-system-stability-run",
        created_at="2026-05-12T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
    )

    assert report["systemStabilityGate"]["status"] == "not_run"
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "SYSTEM_STABILITY_GATE_NOT_RUN" in report["qualityGate"]["reasonCodes"]
    assert report["decisionSupport"]["currentDecision"] == "insufficient-evidence-for-tool-change"


def test_experiment_report_quality_gate_passes_when_system_stability_and_required_splits_pass() -> None:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [
            _case("validation-clean", "validation", "CWE-121", 40),
            _case("test-clean", "test", "CWE-416", 30),
            _case("canary-clean", "canary", "CWE-120", 12),
        ],
    }
    findings = [
        _finding("semgrep", "validation-clean", 40, "CWE-121"),
        _finding("gcc-fanalyzer", "test-clean", 30, "CWE-416"),
        _finding("semgrep", "canary-clean", 12, "CWE-120"),
    ]
    by_config: dict[str, list[SastFinding]] = {"full-current-six": findings}
    by_config.update({f"single-tool:{tool}": [f for f in findings if f.tool_id == tool] for tool in ALL_TOOLS})
    by_config.update({f"leave-one-out:{tool}": [f for f in findings if f.tool_id != tool] for tool in ALL_TOOLS})
    by_config["parser-only-current-six"] = []
    by_config["contract-canary-current-six"] = [findings[-1]]

    report = build_experiment_report(
        run_id="clean-quality-run",
        created_at="2026-05-12T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["qualityGate"]["status"] == "pass"
    assert report["qualityGate"]["decision"] == "quality-gate-pass"
    assert report["qualityGate"]["localQualityAssessment"]["thresholdProfile"] == {
        "status": "decision_grade_candidate",
        "intent": "quality-sufficiency",
        "reasonCodes": [],
        "discriminatingThresholdFields": [
            "minimumTargetRecall",
            "minimumFindingPrecision",
            "maximumNegativeTargetFpr",
        ],
    }
    assert "reportIdentityValidation" not in report


def test_quality_diagnostics_are_available_without_mutating_quality_gate() -> None:
    report = build_experiment_report(
        run_id="quality-diagnostics-separation-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["FINDING_PRECISION_BELOW_THRESHOLD", "NEGATIVE_TARGET_FPR_ABOVE_THRESHOLD"]
    assert report["decisionSupport"]["currentDecision"] == "quality-gate-failed"
    assert report["decisionSupport"]["requiredFollowUps"] == []

    diagnostics = report["qualityDiagnostics"]
    assert diagnostics["status"] == "available"
    assert diagnostics["consumerPolicy"] == "diagnostic_only_not_quality_gate"
    assert diagnostics["diagnosticScope"] == "primary-tool-set-config-only"
    assert diagnostics["primaryToolSetConfig"] == "full-current-six"
    assert set(diagnostics["splitDiagnostics"]) == {"validation", "test", "canary"}
    diagnostics_json = json.dumps(diagnostics)
    assert all(f'"{key}"' not in diagnostics_json for key in FORBIDDEN_VERDICT_KEYS)


def test_quality_diagnostics_separate_target_rows_from_finding_pressure() -> None:
    report = build_experiment_report(
        run_id="quality-diagnostics-count-units-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.1, "requiredSplits": ["validation", "test"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    validation = report["qualityDiagnostics"]["splitDiagnostics"]["validation"]
    assert validation["targetOutcomeCounts"]["exact-target-match"] == 2
    assert validation["findingPressure"] == {
        "uniqueRawFindingCount": 3,
        "tpFindingCount": 2,
        "oracleCountedFpFindingCount": 1,
        "nonTpRawFindingCount": 1,
    }
    assert validation["byTool"]["semgrep"]["uniqueRawFindingCount"] == 2
    assert validation["byTool"]["semgrep"]["tpFindingCount"] == 2
    assert validation["byTool"]["cppcheck"]["uniqueRawFindingCount"] == 1
    assert validation["byTool"]["cppcheck"]["targetOutcomeCounts"] == {}
    assert validation["byTool"]["cppcheck"]["nonTpRawFindingCount"] == 1
    assert "NOISE_PRESSURE_PRESENT" in validation["diagnosticHints"]

    test = report["qualityDiagnostics"]["splitDiagnostics"]["test"]
    assert test["targetOutcomeCounts"]["exact-target-match"] == 1
    assert test["targetOutcomeCounts"]["negative-case-finding"] == 1
    assert test["findingPressure"]["oracleCountedFpFindingCount"] == 1
    assert test["byCweTool"]["CWE-121"]["flawfinder"] == {
        "targetTP": 0,
        "negativeTargetViolationCount": 1,
        "targetOutcomeCounts": {"negative-case-finding": 1},
        "triageReasonCodes": ["NEGATIVE_TARGET_VIOLATIONS_PRESENT"],
    }
    assert "NEGATIVE_TARGET_VIOLATIONS_PRESENT" in test["diagnosticHints"]


def test_quality_diagnostics_expose_score_row_scoped_cwe_tool_matrix_without_overclaiming_recall() -> None:
    report = build_experiment_report(
        run_id="quality-diagnostics-cwe-tool-matrix-run",
        created_at="2026-05-14T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.1, "requiredSplits": ["validation", "test"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    validation = report["qualityDiagnostics"]["splitDiagnostics"]["validation"]
    by_cwe_tool = validation["byCweTool"]
    assert by_cwe_tool["CWE-121"]["semgrep"] == {
        "targetTP": 1,
        "negativeTargetViolationCount": 0,
        "targetOutcomeCounts": {"exact-target-match": 1},
        "triageReasonCodes": [],
    }
    assert by_cwe_tool["CWE-190"]["semgrep"]["targetOutcomeCounts"] == {"exact-target-match": 1}
    assert by_cwe_tool["CWE-190"]["semgrep"]["targetTP"] == 1
    # The matrix is score-row-scoped. Cppcheck has raw pressure for the same CWE-190
    # file, but it is not the best-per-target score row and must not be promoted
    # to a per-tool TP claim here.
    assert validation["byTool"]["cppcheck"]["uniqueRawFindingCount"] == 1
    assert validation["byTool"]["cppcheck"]["targetOutcomeCounts"] == {}
    assert "cppcheck" not in by_cwe_tool["CWE-190"]

    forbidden_overclaim_fields = {
        "targetFN",
        "targetRecall",
        "findingPrecision",
        "uniqueRawFindingCount",
        "nonTpRawFindingCount",
    }
    for tools in by_cwe_tool.values():
        for bucket in tools.values():
            assert not forbidden_overclaim_fields.intersection(bucket)


def test_quality_diagnostic_triage_candidates_are_stable_ordered_and_allowlisted() -> None:
    report = build_experiment_report(
        run_id="quality-diagnostics-triage-order-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.1, "requiredSplits": ["validation", "test"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    test_triage = report["qualityDiagnostics"]["splitDiagnostics"]["test"]["diagnosticTriage"]
    assert test_triage["status"] == "available"
    assert test_triage["consumerPolicy"] == "candidate_investigation_lanes_not_root_cause_or_verdict"
    assert [candidate["candidateId"] for candidate in test_triage["candidates"]] == [
        "negative-discrimination-review",
        "noise-pressure-review",
    ]
    allowed_ids = {
        "matching-policy-review",
        "cwe-normalization-review",
        "negative-discrimination-review",
        "recall-gap-investigation",
        "noise-pressure-review",
    }
    allowed_categories = {"measurement-review", "coverage-or-noise-review"}
    allowed_actions = {
        "inspect-oracle-line-window-or-function-fallback",
        "inspect-tool-cwe-mapping-and-target-cwe-family",
        "inspect-negative-region-ruleset-discrimination",
        "inspect-missed-target-cwe-and-tool-coverage",
        "inspect-high-pressure-tools-and-rule-ids",
    }
    for candidate in test_triage["candidates"]:
        assert candidate["candidateId"] in allowed_ids
        assert candidate["category"] in allowed_categories
        assert candidate["nextLocalAction"] in allowed_actions
        assert "tuning" not in candidate["candidateId"]
        assert "gap" not in candidate["category"]


def test_quality_diagnostics_bucket_wrong_cwe_under_expected_target_cwe() -> None:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [_case("validation-wrong-cwe", "validation", "CWE-121", 40)],
    }
    finding = _finding("semgrep", "validation-wrong-cwe", 40, "CWE-190")

    report = build_experiment_report(
        run_id="quality-diagnostics-wrong-cwe-run",
        created_at="2026-05-13T00:00:00Z",
        phase="validation",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_by_config_for_primary_findings([finding]),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.1, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    diagnostics = report["qualityDiagnostics"]["splitDiagnostics"]["validation"]
    assert diagnostics["targetOutcomeCounts"]["wrong-cwe-target-location"] == 1
    assert diagnostics["byCwe"]["CWE-121"]["wrong-cwe-target-location"] == 1
    assert diagnostics["byCwe"]["CWE-121"]["targetFN"] == 1
    assert diagnostics["matchAttemptDiagnostics"]["wrongCweTargetLocationAttemptCount"] == 1
    assert "CWE-190" not in diagnostics["byCwe"]
    assert diagnostics["byCweTool"]["CWE-121"]["semgrep"]["targetOutcomeCounts"] == {
        "wrong-cwe-target-location": 1,
    }
    assert diagnostics["byCweTool"]["CWE-121"]["semgrep"]["triageReasonCodes"] == [
        "WRONG_CWE_MATCHES_PRESENT",
    ]
    assert "CWE-190" not in diagnostics["byCweTool"]
    assert "WRONG_CWE_MATCHES_PRESENT" in diagnostics["diagnosticHints"]
    triage = diagnostics["diagnosticTriage"]
    assert [candidate["candidateId"] for candidate in triage["candidates"]] == [
        "cwe-normalization-review",
        "recall-gap-investigation",
        "noise-pressure-review",
    ]
    cwe_candidate = triage["candidates"][0]
    assert cwe_candidate["category"] == "measurement-review"
    assert cwe_candidate["reasonCodes"] == ["WRONG_CWE_MATCHES_PRESENT"]
    assert cwe_candidate["evidence"]["wrongCweTargetLocationAttemptCount"] == 1
    assert diagnostics["byCwe"]["CWE-121"]["triageReasonCodes"] == [
        "RECALL_GAP_PRESENT",
        "WRONG_CWE_MATCHES_PRESENT",
    ]


def test_quality_diagnostics_deduplicate_raw_finding_keys() -> None:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [_case("validation-duplicate", "validation", "CWE-121", 40)],
    }
    finding = _finding("semgrep", "validation-duplicate", 40, "CWE-121")

    report = build_experiment_report(
        run_id="quality-diagnostics-dedupe-run",
        created_at="2026-05-13T00:00:00Z",
        phase="validation",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_by_config_for_primary_findings([finding, finding]),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 1.0, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    diagnostics = report["qualityDiagnostics"]["splitDiagnostics"]["validation"]
    assert diagnostics["findingPressure"]["uniqueRawFindingCount"] == 1
    assert diagnostics["findingPressure"]["tpFindingCount"] == 1
    assert diagnostics["byTool"]["semgrep"]["uniqueRawFindingCount"] == 1
    assert diagnostics["byTool"]["semgrep"]["tpFindingCount"] == 1


def test_quality_diagnostics_keep_allowed_negative_warning_as_raw_pressure_not_fp() -> None:
    negative = _case("validation-allowed-negative", "validation", "CWE-121", 80, polarity="negative")
    negative["expected"]["allowedWarningPolicy"] = {
        "mode": "allow-listed-rules-only",
        "allowedRuleIds": ["semgrep:allowed-warning"],
    }
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [negative],
    }
    finding = SastFinding(
        toolId="semgrep",
        ruleId="semgrep:allowed-warning",
        severity="warning",
        message="allowed warning fixture",
        location={"file": "validation-allowed-negative.c", "line": 80, "column": 1},
        metadata={"cweId": "CWE-121", "cwe": ["CWE-121"]},
    )

    report = build_experiment_report(
        run_id="quality-diagnostics-allowed-negative-run",
        created_at="2026-05-13T00:00:00Z",
        phase="validation",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_by_config_for_primary_findings([finding]),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"maximumNegativeTargetFpr": 0.0, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    diagnostics = report["qualityDiagnostics"]["splitDiagnostics"]["validation"]
    assert diagnostics["metricSummary"]["fpFindings"] == 0
    assert diagnostics["findingPressure"]["oracleCountedFpFindingCount"] == 0
    assert diagnostics["findingPressure"]["uniqueRawFindingCount"] == 1
    assert diagnostics["findingPressure"]["nonTpRawFindingCount"] == 1
    assert diagnostics["byTool"]["semgrep"]["nonTpRawFindingCount"] == 1
    assert "countedFpFindingCount" not in diagnostics["byTool"]["semgrep"]
    assert diagnostics["diagnosticTriage"]["candidates"] == []


def test_quality_diagnostic_triage_is_empty_for_clean_pass_and_does_not_mutate_gate() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="quality-diagnostics-clean-triage-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["qualityGate"]["status"] == "pass"
    assert report["decisionSupport"]["currentDecision"] == "quality-gate-pass"
    assert report["decisionSupport"]["requiredFollowUps"] == []
    for split in ("validation", "test", "canary"):
        assert report["qualityDiagnostics"]["splitDiagnostics"][split]["diagnosticTriage"]["candidates"] == []


def test_quality_diagnostic_triage_is_independent_of_threshold_profile() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    common = {
        "run_id": "quality-diagnostics-threshold-independence-run",
        "created_at": "2026-05-13T00:00:00Z",
        "phase": "test",
        "corpus_manifest": corpus,
        "acquisition_manifests": [_acquisition_manifest()],
        "findings_by_config": by_config,
        "matching_policy": {"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        "corpus_readiness_gate": _available_corpus_readiness_gate(),
        "system_stability": _passing_system_stability_gate(),
    }
    strict = build_experiment_report(
        **common,
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
    )
    low = build_experiment_report(
        **{**common, "run_id": "quality-diagnostics-low-threshold-independence-run"},
        thresholds={
            "minimumTargetRecall": 0.0,
            "minimumFindingPrecision": 0.0,
            "maximumNegativeTargetFpr": 1.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
    )

    assert strict["qualityGate"]["status"] == "pass"
    assert low["qualityGate"]["status"] == "not_decision_grade"
    assert (
        strict["qualityDiagnostics"]["splitDiagnostics"]["validation"]["diagnosticTriage"]
        == low["qualityDiagnostics"]["splitDiagnostics"]["validation"]["diagnosticTriage"]
    )


def test_quality_diagnostic_triage_raw_only_pressure_does_not_emit_noise_candidate() -> None:
    negative = _case("validation-allowed-negative", "validation", "CWE-121", 80, polarity="negative")
    negative["expected"]["allowedWarningPolicy"] = {
        "mode": "allow-listed-rules-only",
        "allowedRuleIds": ["semgrep:allowed-warning"],
    }
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [negative],
    }
    finding = SastFinding(
        toolId="semgrep",
        ruleId="semgrep:allowed-warning",
        severity="warning",
        message="allowed warning fixture",
        location={"file": "validation-allowed-negative.c", "line": 80, "column": 1},
        metadata={"cweId": "CWE-121", "cwe": ["CWE-121"]},
    )

    report = build_experiment_report(
        run_id="quality-diagnostics-raw-only-noise-run",
        created_at="2026-05-13T00:00:00Z",
        phase="validation",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_by_config_for_primary_findings([finding]),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"maximumNegativeTargetFpr": 0.0, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    diagnostics = report["qualityDiagnostics"]["splitDiagnostics"]["validation"]
    assert diagnostics["findingPressure"]["nonTpRawFindingCount"] == 1
    assert diagnostics["findingPressure"]["oracleCountedFpFindingCount"] == 0
    assert "noise-pressure-review" not in [
        candidate["candidateId"]
        for candidate in diagnostics["diagnosticTriage"]["candidates"]
    ]


def test_quality_diagnostics_omit_scored_buckets_when_system_gate_blocks() -> None:
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {"available": False, "probeReason": "environment-drift"}
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="quality-diagnostics-system-blocked-run",
        created_at="2026-05-13T00:00:00Z",
        phase="validation",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.1},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    diagnostics = report["qualityDiagnostics"]
    assert diagnostics["status"] == "blocked"
    assert "SYSTEM_STABILITY_GATE_FAILED" in diagnostics["reasonCodes"]
    assert diagnostics["splitDiagnostics"] == {}


def test_quality_diagnostics_omit_scored_buckets_when_local_inputs_are_invalid() -> None:
    report = build_experiment_report(
        run_id="quality-diagnostics-input-invalid-run",
        created_at="2026-05-13T00:00:00Z",
        phase="validation",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy=["not", "a", "mapping"],  # type: ignore[arg-type]
        thresholds={"minimumTargetRecall": 0.1},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    diagnostics = report["qualityDiagnostics"]
    assert diagnostics["status"] == "not_run"
    assert diagnostics["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
    assert diagnostics["splitDiagnostics"] == {}


def test_tool_contribution_diagnostics_are_available_without_mutating_gate_or_decision_support() -> None:
    report = _contribution_report()

    diagnostics = report["toolContributionDiagnostics"]
    assert diagnostics["schemaVersion"] == "s4-tool-portfolio-tool-contribution-diagnostics-v1"
    assert diagnostics["consumerPolicy"] == "diagnostic_only_not_tool_change_verdict"
    assert diagnostics["status"] == "available"
    assert diagnostics["primaryToolSetConfig"] == "full-current-six"
    assert diagnostics["metricScope"] == "aggregate_all_scored_targets"
    assert diagnostics["includedSplits"] == ["validation", "test", "canary"]
    assert [row["toolId"] for row in diagnostics["tools"]] == ALL_TOOLS

    assert report["qualityGate"]["status"] == "fail"
    assert report["decisionSupport"]["currentDecision"] == "quality-gate-failed"
    assert report["decisionSupport"]["addCandidates"] == []
    assert report["decisionSupport"]["removeCandidates"] == []
    assert report["decisionSupport"]["upgradeCandidates"] == []

    diagnostics_json = json.dumps(diagnostics)
    assert all(f'"{key}"' not in diagnostics_json for key in FORBIDDEN_VERDICT_KEYS)
    assert "addCandidate" not in diagnostics_json
    assert "removeCandidate" not in diagnostics_json
    assert "upgradeCandidate" not in diagnostics_json
    assert "recommend" not in diagnostics_json.lower()


def test_tool_contribution_diagnostics_classify_empirical_evidence_classes() -> None:
    report = _contribution_report()

    rows = {
        row["toolId"]: row
        for row in report["toolContributionDiagnostics"]["tools"]
    }

    assert rows["semgrep"]["evidenceClass"] == "unique-positive-contributor"
    assert rows["semgrep"]["reasonCodes"] == ["UNIQUE_POSITIVE_CONTRIBUTION_PRESENT"]
    assert rows["semgrep"]["uniqueTpContribution"] > 0
    assert rows["semgrep"]["leaveOneOutDelta"]["targetRecallDelta"] > 0

    assert rows["cppcheck"]["evidenceClass"] == "overlap-only-positive-contributor"
    assert rows["cppcheck"]["reasonCodes"] == ["OVERLAP_POSITIVE_CONTRIBUTION_PRESENT"]
    assert rows["cppcheck"]["singleTool"]["targetTP"] > 0
    assert rows["cppcheck"]["uniqueTpContribution"] == 0
    assert rows["cppcheck"]["leaveOneOutDelta"]["targetRecallDelta"] == 0

    assert rows["flawfinder"]["evidenceClass"] == "noise-only-or-no-positive-contribution"
    assert rows["flawfinder"]["reasonCodes"] == ["NOISE_WITHOUT_POSITIVE_CONTRIBUTION_PRESENT"]
    assert rows["flawfinder"]["singleTool"]["targetTP"] == 0
    assert rows["flawfinder"]["singleTool"]["negativeTargetViolationCount"] > 0

    assert rows["scan-build"]["evidenceClass"] == "no-observed-signal"
    assert rows["scan-build"]["reasonCodes"] == ["NO_OBSERVED_SIGNAL"]
    assert rows["scan-build"]["singleTool"]["targetTP"] == 0
    assert rows["scan-build"]["singleTool"]["fpFindings"] == 0


def test_tool_contribution_diagnostics_labels_aggregate_scope_when_canary_only_contributes() -> None:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [_case("canary-only", "canary", "CWE-120", 12)],
    }
    finding = _finding("semgrep", "canary-only", 12, "CWE-120")

    report = _contribution_report(
        corpus=corpus,
        by_config=_by_config_for_primary_findings([finding]),
        thresholds={"minimumTargetRecall": 1.0, "requiredSplits": ["canary"], "primaryToolSetConfig": "full-current-six"},
    )

    diagnostics = report["toolContributionDiagnostics"]
    assert diagnostics["status"] == "available"
    assert diagnostics["metricScope"] == "aggregate_all_scored_targets"
    assert diagnostics["includedSplits"] == ["canary"]
    semgrep = diagnostics["tools"][ALL_TOOLS.index("semgrep")]
    assert semgrep["toolId"] == "semgrep"
    assert semgrep["evidenceClass"] == "unique-positive-contributor"
    assert semgrep["singleTool"]["targetTP"] == 1


def test_tool_contribution_diagnostics_null_recall_without_positive_targets_is_no_observed_signal() -> None:
    negative = _case("validation-negative-only", "validation", "CWE-121", 80, polarity="negative")
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [negative],
    }

    report = _contribution_report(
        corpus=corpus,
        by_config=_by_config_for_primary_findings([]),
        thresholds={"maximumNegativeTargetFpr": 0.0, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
    )

    semgrep = report["toolContributionDiagnostics"]["tools"][ALL_TOOLS.index("semgrep")]
    assert semgrep["singleTool"]["targetRecall"] is None
    assert semgrep["singleTool"]["targetTP"] == 0
    assert semgrep["singleTool"]["fpFindings"] == 0
    assert semgrep["evidenceClass"] == "no-observed-signal"
    assert semgrep["reasonCodes"] == ["NO_OBSERVED_SIGNAL"]


def test_tool_contribution_diagnostics_are_threshold_independent() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    strict = _contribution_report(
        corpus=corpus,
        by_config=by_config,
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
    )
    low = _contribution_report(
        corpus=corpus,
        by_config=by_config,
        thresholds={
            "minimumTargetRecall": 0.0,
            "minimumFindingPrecision": 0.0,
            "maximumNegativeTargetFpr": 1.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
    )

    assert strict["qualityGate"]["status"] == "pass"
    assert low["qualityGate"]["status"] == "not_decision_grade"
    assert strict["toolContributionDiagnostics"] == low["toolContributionDiagnostics"]


def test_tool_contribution_diagnostics_not_run_when_comparative_config_is_incomplete() -> None:
    report = _contribution_report(
        tool_contribution_completeness={
            "status": "fail",
            "consumerPolicy": "comparative_config_requested_tool_completeness_not_negative_security_evidence",
            "failures": [{
                "toolSetConfig": "single-tool:semgrep",
                "toolId": "semgrep",
                "status": "partial",
                "reasonCode": "tool-degraded",
            }],
        },
    )

    diagnostics = report["toolContributionDiagnostics"]
    assert diagnostics["status"] == "not_run"
    assert diagnostics["reasonCodes"] == ["TOOL_CONTRIBUTION_COMPARATIVE_CONFIG_INCOMPLETE"]
    assert diagnostics["tools"] == []
    assert report["qualityGate"]["status"] == "fail"


def _assert_invalid_report_identity_fails_when_prerequisites_pass(
    *,
    run_id: object = "identity-validation-run",
    created_at: object = "2026-05-13T00:00:00Z",
    phase: object = "test",
    expected_failure: dict[str, str],
) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id=run_id,  # type: ignore[arg-type]
        created_at=created_at,  # type: ignore[arg-type]
        phase=phase,  # type: ignore[arg-type]
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["reportIdentityValidation"] == {
        "status": "fail",
        "reasonCodes": ["REPORT_IDENTITY_INPUT_INVALID"],
        "failures": [expected_failure],
    }
    assert report["runId"] == ("invalid-run-id" if expected_failure["field"] == "runId" else "identity-validation-run")
    assert report["createdAt"] == (
        "invalid-created-at" if expected_failure["field"] == "createdAt" else "2026-05-13T00:00:00Z"
    )
    assert report["decisionCycle"]["decisionCycleId"].startswith(report["runId"])
    assert report["decisionCycle"]["phase"] == ("validation" if expected_failure["field"] == "phase" else "test")
    for split in ("validationMetrics", "testMetrics", "canaryMetrics"):
        assert report[split]["status"] == "not_run"
        assert report[split]["reasonCodes"] == ["REPORT_IDENTITY_INPUT_INVALID"]
        assert report[split]["byConfig"] == {}
    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["REPORT_IDENTITY_INPUT_INVALID"]
    assert local["invalidReportIdentity"] == [expected_failure]
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["REPORT_IDENTITY_INPUT_INVALID"]
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert report["portfolioMetrics"]["reasonCodes"] == ["REPORT_IDENTITY_INPUT_INVALID"]


def test_experiment_report_fails_quality_when_run_id_is_non_string() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        run_id=123,
        expected_failure={"category": "invalid-field", "field": "runId", "type": "int"},
    )


def test_experiment_report_fails_quality_when_run_id_is_blank() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        run_id="  ",
        expected_failure={"category": "blank", "field": "runId"},
    )


def test_experiment_report_fails_quality_when_run_id_has_unsafe_characters_without_echoing_raw_value() -> None:
    report = build_experiment_report(
        run_id="SECRET_TOKEN_SHOULD_NOT_LEAK/../bad",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_clean_quality_corpus_and_findings()[0],
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_clean_quality_corpus_and_findings()[1],
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["runId"] == "invalid-run-id"
    assert report["reportIdentityValidation"]["failures"] == [
        {"category": "invalid-format", "field": "runId", "reason": "safe-identifier-required"},
    ]
    assert "SECRET_TOKEN_SHOULD_NOT_LEAK" not in json.dumps(report)
    assert report["qualityGate"]["status"] == "fail"


def test_experiment_report_fails_quality_when_run_id_has_trailing_newline() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        run_id="safe\n",
        expected_failure={"category": "invalid-format", "field": "runId", "reason": "safe-identifier-required"},
    )


def test_experiment_report_does_not_leak_secret_run_id_with_trailing_newline() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="SECRET_TOKEN_SHOULD_NOT_LEAK\n",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["runId"] == "invalid-run-id"
    assert report["decisionCycle"]["decisionCycleId"] == "invalid-run-id-cycle"
    assert report["qualityGate"]["status"] == "fail"
    assert "SECRET_TOKEN_SHOULD_NOT_LEAK" not in json.dumps(report)


def test_experiment_report_fails_quality_when_created_at_is_non_string() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        created_at=123,
        expected_failure={"category": "invalid-field", "field": "createdAt", "type": "int"},
    )


def test_experiment_report_fails_quality_when_created_at_is_malformed() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        created_at="2026-05-13 00:00:00",
        expected_failure={"category": "invalid-format", "field": "createdAt", "reason": "rfc3339-utc-seconds-required"},
    )


def test_experiment_report_fails_quality_when_created_at_is_impossible_date() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        created_at="2026-02-30T00:00:00Z",
        expected_failure={"category": "invalid-date", "field": "createdAt", "reason": "nonexistent-date"},
    )


def test_experiment_report_fails_quality_when_phase_is_unknown_without_crashing() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        phase="production",
        expected_failure={"category": "invalid-phase", "field": "phase"},
    )


def test_experiment_report_fails_quality_when_phase_is_non_string() -> None:
    _assert_invalid_report_identity_fails_when_prerequisites_pass(
        phase=123,
        expected_failure={"category": "invalid-field", "field": "phase", "type": "int"},
    )


def test_experiment_report_identity_invalid_keeps_system_precondition_blocked() -> None:
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {"available": False, "probeReason": "environment-drift"}
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="bad/secret",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert "REPORT_IDENTITY_INPUT_INVALID" not in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "blocked"
    assert report["reportIdentityValidation"]["status"] == "fail"


def test_experiment_report_identity_invalid_keeps_corpus_readiness_not_decision_grade() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="bad/secret",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        system_stability=_passing_system_stability_gate(),
    )

    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert "CORPUS_READINESS_GATE_NOT_RUN" in report["qualityGate"]["reasonCodes"]
    assert "REPORT_IDENTITY_INPUT_INVALID" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "fail"
    assert report["reportIdentityValidation"]["status"] == "fail"


def _assert_inconsistent_system_stability_gate_blocks(system_gate: dict) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="inconsistent-system-stability-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    normalized_gate = report["systemStabilityGate"]
    assert normalized_gate["status"] == "fail"
    assert normalized_gate["qualityGateAllowed"] is False
    assert "SYSTEM_STABILITY_GATE_INCONSISTENT" in normalized_gate["reasonCodes"]
    assert normalized_gate["phases"]["gateConsistency"]["status"] == "fail"
    assert normalized_gate["phases"]["preflight"] == system_gate["phases"]["preflight"]
    assert normalized_gate["phases"]["executionCompleteness"] == system_gate["phases"]["executionCompleteness"]
    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert "SYSTEM_STABILITY_GATE_INCONSISTENT" in report["qualityGate"]["reasonCodes"]
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "blocked"
    assert report["portfolioMetrics"]["status"] == "blocked"


def test_experiment_report_blocks_when_passing_system_gate_disallows_quality_gate() -> None:
    gate = _passing_system_stability_gate()
    gate["qualityGateAllowed"] = False

    _assert_inconsistent_system_stability_gate_blocks(gate)


def test_experiment_report_reaccepts_normalized_inconsistent_system_gate() -> None:
    gate = _passing_system_stability_gate()
    gate["qualityGateAllowed"] = False

    corpus, by_config = _clean_quality_corpus_and_findings()
    first_report = build_experiment_report(
        run_id="inconsistent-system-stability-first-report-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=gate,
    )

    second_report = build_experiment_report(
        run_id="inconsistent-system-stability-second-report-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=first_report["systemStabilityGate"],
    )

    normalized_gate = second_report["systemStabilityGate"]
    assert normalized_gate["status"] == "fail"
    assert normalized_gate["qualityGateAllowed"] is False
    assert "SYSTEM_STABILITY_GATE_INCONSISTENT" in normalized_gate["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    assert normalized_gate["phases"]["gateConsistency"]["failures"][0]["reasonCode"] == "SYSTEM_STABILITY_GATE_INCONSISTENT"


def test_experiment_report_blocks_when_passing_system_gate_omits_quality_gate_allowed() -> None:
    gate = _passing_system_stability_gate()
    gate.pop("qualityGateAllowed")

    _assert_invalid_system_stability_mapping_blocks(
        gate,
        {"category": "missing-field", "field": "qualityGateAllowed"},
    )


def test_experiment_report_blocks_when_not_run_system_gate_allows_quality_gate() -> None:
    gate = {
        "schemaVersion": "s4-tool-portfolio-system-stability-gate-v1",
        "status": "not_run",
        "requiredTools": list(ALL_TOOLS),
        "qualityGateAllowed": True,
        "reasonCodes": ["HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS"],
        "phases": {
            "preflight": {"status": "not_run", "failures": []},
            "executionCompleteness": {"status": "not_run", "failures": []},
        },
    }

    _assert_inconsistent_system_stability_gate_blocks(gate)


def test_experiment_report_blocks_when_not_run_system_gate_allows_quality_gate_with_malformed_phases() -> None:
    gate = {
        "schemaVersion": "s4-tool-portfolio-system-stability-gate-v1",
        "status": "not_run",
        "qualityGateAllowed": True,
        "reasonCodes": ["HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS"],
        "phases": "bad",
    }

    _assert_invalid_system_stability_mapping_blocks(
        gate,
        {"category": "invalid-field", "field": "phases", "type": "str"},
    )


def test_experiment_report_blocks_when_failing_system_gate_allows_quality_gate_with_malformed_phases() -> None:
    gate = {
        "schemaVersion": "s4-tool-portfolio-system-stability-gate-v1",
        "status": "fail",
        "qualityGateAllowed": True,
        "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        "phases": "bad",
    }

    _assert_invalid_system_stability_mapping_blocks(
        gate,
        {"category": "invalid-field", "field": "phases", "type": "str"},
    )


def _assert_invalid_system_stability_payload_blocks(system_stability: object, expected_type: str) -> None:
    expected_input = {"category": "non-mapping", "type": expected_type}
    _assert_invalid_system_stability_mapping_blocks(system_stability, expected_input)


def _assert_invalid_system_stability_mapping_blocks(
    system_stability: object,
    expected_input: dict[str, str],
    forbidden_substrings=(),
) -> None:
    report = build_experiment_report(
        run_id="invalid-system-stability-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_stability,  # type: ignore[arg-type]
    )

    gate = report["systemStabilityGate"]
    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert gate["requiredTools"] == list(ALL_TOOLS)
    assert gate["reasonCodes"] == ["SYSTEM_STABILITY_GATE_INPUT_INVALID"]
    assert gate["phases"]["gateInputValidation"]["status"] == "fail"
    failure = gate["phases"]["gateInputValidation"]["failures"][0]
    assert failure == {
        "phase": "gateInputValidation",
        "reasonCode": "SYSTEM_STABILITY_GATE_INPUT_INVALID",
        "input": expected_input,
    }
    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" in report["qualityGate"]["reasonCodes"]
    for split in ("validationMetrics", "testMetrics", "canaryMetrics"):
        assert report[split]["status"] == "blocked"
        assert report[split]["byConfig"] == {}
        assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" in report[split]["reasonCodes"]
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" in report["portfolioMetrics"]["reasonCodes"]
    serialized = json.dumps(report, sort_keys=True)
    for substring in forbidden_substrings:
        assert substring not in serialized


def test_experiment_report_defaults_missing_system_stability_to_not_run() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="missing-system-stability-default-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
    )

    assert report["systemStabilityGate"]["status"] == "not_run"
    assert report["systemStabilityGate"]["qualityGateAllowed"] is False
    assert report["qualityGate"]["status"] == "not_decision_grade"


def test_experiment_report_blocks_when_system_stability_payload_is_empty_list() -> None:
    _assert_invalid_system_stability_payload_blocks([], "list")


def test_experiment_report_blocks_when_system_stability_payload_is_empty_string() -> None:
    _assert_invalid_system_stability_payload_blocks("", "str")


def test_experiment_report_blocks_when_system_stability_payload_is_string() -> None:
    _assert_invalid_system_stability_payload_blocks("strict", "str")


def test_experiment_report_blocks_when_system_stability_payload_is_int() -> None:
    _assert_invalid_system_stability_payload_blocks(7, "int")


def test_experiment_report_blocks_when_system_stability_mapping_is_empty() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {},
        {"category": "missing-field", "field": "status"},
    )


def test_experiment_report_blocks_when_system_stability_status_is_unknown() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "unknown", "qualityGateAllowed": False},
        {"category": "invalid-status", "status": "<invalid>"},
    )


def test_experiment_report_blocks_when_system_stability_status_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_STATUS_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {"status": secret, "qualityGateAllowed": False},
        {"category": "invalid-status", "status": "<invalid>"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_system_stability_status_object_is_not_stringified() -> None:
    secret = "SECRET_SYSTEM_STATUS_OBJECT_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {"status": {"secret": secret}, "qualityGateAllowed": False},
        {"category": "invalid-field", "field": "status", "type": "dict"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_system_stability_pass_lacks_required_tool_evidence() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True},
        {"category": "missing-field", "field": "requiredTools"},
    )


def test_experiment_report_blocks_when_system_stability_pass_has_empty_required_tools() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True, "requiredTools": [], "phases": {}},
        {"category": "invalid-required-tools", "reason": "empty"},
    )


def test_experiment_report_blocks_when_system_stability_pass_has_unknown_required_tool() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True, "requiredTools": [*ALL_TOOLS, "typo-tool"], "phases": {}},
        {"category": "invalid-required-tools", "reason": "unknown-tool", "tool": "<invalid>"},
    )


def test_experiment_report_blocks_when_system_stability_required_tool_secret_is_not_echoed() -> None:
    secret = "SECRET_REQUIRED_TOOL_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True, "requiredTools": [*ALL_TOOLS, secret], "phases": {}},
        {"category": "invalid-required-tools", "reason": "unknown-tool", "tool": "<invalid>"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_system_stability_required_tool_object_is_not_stringified() -> None:
    secret = "SECRET_REQUIRED_TOOL_OBJECT_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True, "requiredTools": [*ALL_TOOLS, {"secret": secret}], "phases": {}},
        {
            "category": "invalid-required-tools",
            "reason": "invalid-tool",
            "field": f"requiredTools.{len(ALL_TOOLS)}",
            "type": "dict",
        },
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_system_stability_pass_has_partial_required_tools() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True, "requiredTools": ["semgrep"], "phases": {}},
        {"category": "invalid-required-tools", "reason": "missing-required-tool", "tool": "cppcheck"},
    )


def test_experiment_report_blocks_when_system_stability_phases_are_invalid() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True, "requiredTools": list(ALL_TOOLS), "phases": "bad"},
        {"category": "invalid-field", "field": "phases", "type": "str"},
    )


def test_experiment_report_blocks_when_system_stability_pass_has_empty_phases() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {"status": "pass", "qualityGateAllowed": True, "requiredTools": list(ALL_TOOLS), "phases": {}},
        {"category": "missing-field", "field": "phases.preflight"},
    )


def test_experiment_report_blocks_when_system_stability_pass_has_empty_phase_mappings() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {"preflight": {}, "executionCompleteness": {}},
        },
        {"category": "missing-field", "field": "phases.preflight.status"},
    )


def test_experiment_report_blocks_when_system_stability_pass_has_failed_phase_status() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": "fail", "failures": []},
                "executionCompleteness": {"status": "pass", "failures": []},
            },
        },
        {"category": "invalid-phase-status", "field": "phases.preflight.status", "status": "<invalid>"},
    )


def test_experiment_report_blocks_when_system_stability_phase_status_secret_is_not_echoed() -> None:
    secret = "SECRET_PHASE_STATUS_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": secret, "failures": []},
                "executionCompleteness": {"status": "pass", "failures": []},
            },
        },
        {"category": "invalid-phase-status", "field": "phases.preflight.status", "status": "<invalid>"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_system_stability_phase_status_object_is_not_stringified() -> None:
    secret = "SECRET_PHASE_STATUS_OBJECT_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": {"secret": secret}, "failures": []},
                "executionCompleteness": {"status": "pass", "failures": []},
            },
        },
        {"category": "invalid-field", "field": "phases.preflight.status", "type": "dict"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_blocks_when_system_stability_pass_has_non_empty_phase_failures() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": "pass", "failures": [{"reasonCode": "tool-missing"}]},
                "executionCompleteness": {"status": "pass", "failures": []},
            },
        },
        {"category": "invalid-phase-failures", "field": "phases.preflight.failures", "reason": "non-empty"},
    )


def test_experiment_report_blocks_when_system_stability_pass_has_malformed_phase_failures() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": "pass", "failures": "bad"},
                "executionCompleteness": {"status": "pass", "failures": []},
            },
        },
        {"category": "invalid-field", "field": "phases.preflight.failures", "type": "str"},
    )


def test_experiment_report_blocks_when_system_stability_pass_has_execution_phase_invalid() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": "pass", "failures": []},
                "executionCompleteness": {"status": "fail", "failures": []},
            },
        },
        {
            "category": "invalid-phase-status",
            "field": "phases.executionCompleteness.status",
            "status": "<invalid>",
        },
    )


def test_experiment_report_blocks_when_system_stability_pass_has_execution_phase_failures() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": "pass", "failures": []},
                "executionCompleteness": {"status": "pass", "failures": [{"reasonCode": "missing-result"}]},
            },
        },
        {
            "category": "invalid-phase-failures",
            "field": "phases.executionCompleteness.failures",
            "reason": "non-empty",
        },
    )


def test_experiment_report_blocks_when_system_stability_pass_has_malformed_execution_phase_failures() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "pass",
            "qualityGateAllowed": True,
            "requiredTools": list(ALL_TOOLS),
            "phases": {
                "preflight": {"status": "pass", "failures": []},
                "executionCompleteness": {"status": "pass", "failures": "bad"},
            },
        },
        {"category": "invalid-field", "field": "phases.executionCompleteness.failures", "type": "str"},
    )


class _SecretSystemGateValue:
    def __repr__(self) -> str:
        return "SECRET_SYSTEM_GATE_OBJECT_SHOULD_NOT_LEAK"


def test_experiment_report_blocks_when_system_stability_reason_code_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_REASON_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": [secret],
        },
        {"category": "invalid-reason-code", "field": "reasonCodes.0", "reason": "invalid_string"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_reason_code_object_is_not_stringified() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": [_SecretSystemGateValue()],
        },
        {"category": "invalid-reason-code", "field": "reasonCodes.0", "type": "_SecretSystemGateValue"},
        forbidden_substrings=("SECRET_SYSTEM_GATE_OBJECT_SHOULD_NOT_LEAK",),
    )


def test_experiment_report_blocks_when_system_stability_has_secret_unknown_top_level_field() -> None:
    secret = "SECRET_SYSTEM_FIELD_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
            secret: "value",
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_top_level_key_object_is_not_stringified() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
            ("secret", "SECRET_SYSTEM_FIELD_OBJECT_SHOULD_NOT_LEAK"): "value",
        },
        {"category": "unknown-field", "field": "<invalid>", "type": "tuple"},
        forbidden_substrings=("SECRET_SYSTEM_FIELD_OBJECT_SHOULD_NOT_LEAK",),
    )


def test_experiment_report_blocks_when_system_stability_required_tool_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_TOOL_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "requiredTools": ["semgrep", secret],
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        },
        {"category": "invalid-required-tools", "reason": "unknown-tool", "tool": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_required_tool_object_is_not_stringified() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "requiredTools": ["semgrep", _SecretSystemGateValue()],
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        },
        {"category": "invalid-required-tools", "reason": "invalid-tool", "field": "requiredTools.1", "type": "_SecretSystemGateValue"},
        forbidden_substrings=("SECRET_SYSTEM_GATE_OBJECT_SHOULD_NOT_LEAK",),
    )


def test_experiment_report_accepts_non_pass_system_stability_required_tool_subset() -> None:
    system_gate = {
        "status": "fail",
        "qualityGateAllowed": False,
        "requiredTools": ["semgrep"],
        "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
    }

    report = build_experiment_report(
        run_id="non-pass-system-stability-required-tool-subset-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    normalized_gate = report["systemStabilityGate"]
    assert normalized_gate == system_gate
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    assert report["qualityGate"]["status"] == "blocked"


def test_experiment_report_accepts_generated_fail_gate_without_required_tools() -> None:
    system_gate = build_system_stability_gate(
        required_tools=[],
        tool_availability=None,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="generated-empty-required-tools-system-gate-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    normalized_gate = report["systemStabilityGate"]
    assert normalized_gate["status"] == "fail"
    assert normalized_gate["requiredTools"] == []
    assert normalized_gate["reasonCodes"] == ["SYSTEM_REQUIRED_TOOLS_NOT_DECLARED"]
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    assert normalized_gate["phases"]["preflight"]["failures"][0] == {
        "toolId": None,
        "phase": "preflight",
        "reasonCode": "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED",
    }
    assert report["qualityGate"]["status"] == "blocked"


def test_experiment_report_blocks_when_system_stability_schema_version_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_SCHEMA_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "schemaVersion": secret,
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        },
        {"category": "invalid-schema-version", "field": "schemaVersion"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_schema_version_object_is_not_stringified() -> None:
    _assert_invalid_system_stability_mapping_blocks(
        {
            "schemaVersion": _SecretSystemGateValue(),
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        },
        {"category": "invalid-field", "field": "schemaVersion", "type": "_SecretSystemGateValue"},
        forbidden_substrings=("SECRET_SYSTEM_GATE_OBJECT_SHOULD_NOT_LEAK",),
    )


def test_experiment_report_blocks_when_system_stability_phase_failure_reason_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_PHASE_REASON_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
            "phases": {
                "preflight": {
                    "status": "fail",
                    "failures": [{"toolId": "semgrep", "phase": "preflight", "reasonCode": secret}],
                },
            },
        },
        {"category": "invalid-phase-failure", "field": "phases.preflight.failures.0.reasonCode", "reason": "invalid_string"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_phase_failure_tool_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_PHASE_TOOL_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
            "phases": {
                "preflight": {
                    "status": "fail",
                    "failures": [{"toolId": secret, "phase": "preflight", "reasonCode": "REQUIRED_TOOL_UNKNOWN"}],
                },
            },
        },
        {"category": "invalid-phase-failure", "field": "phases.preflight.failures.0.toolId", "tool": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_phase_failure_status_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_PHASE_STATUS_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_INCOMPLETE"],
            "phases": {
                "executionCompleteness": {
                    "status": "fail",
                    "failures": [{"toolId": "semgrep", "phase": "executionCompleteness", "status": secret, "reasonCode": "tool-status-unknown"}],
                },
            },
        },
        {"category": "invalid-phase-failure", "field": "phases.executionCompleteness.failures.0.status", "status": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_phase_failure_degrade_reason_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_DEGRADE_REASON_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_INCOMPLETE"],
            "phases": {
                "executionCompleteness": {
                    "status": "fail",
                    "failures": [{
                        "toolId": "semgrep",
                        "phase": "executionCompleteness",
                        "status": "partial",
                        "reasonCode": "tool-partial",
                        "degradeReasons": [secret],
                    }],
                },
            },
        },
        {"category": "invalid-phase-failure", "field": "phases.executionCompleteness.failures.0.degradeReasons.0", "reason": "invalid_string"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_blocks_when_system_stability_phase_failure_unknown_field_secret_is_not_echoed() -> None:
    secret = "SECRET_SYSTEM_PHASE_FIELD_SHOULD_NOT_LEAK"
    _assert_invalid_system_stability_mapping_blocks(
        {
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
            "phases": {
                "preflight": {
                    "status": "fail",
                    "failures": [{"toolId": "semgrep", "phase": "preflight", "reasonCode": "not-found", secret: "value"}],
                },
            },
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=(secret,),
    )


def test_experiment_report_redacts_system_stability_phase_failure_version_and_expected_path() -> None:
    secret_version = "SECRET_SYSTEM_VERSION_SHOULD_NOT_LEAK"
    secret_path = "/tmp/SECRET_SYSTEM_PATH_SHOULD_NOT_LEAK/tool"
    gate = {
        "status": "fail",
        "qualityGateAllowed": False,
        "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        "phases": {
            "preflight": {
                "status": "fail",
                "failures": [{
                    "toolId": "semgrep",
                    "phase": "preflight",
                    "reasonCode": "not-found",
                    "version": secret_version,
                    "expectedExecutablePath": secret_path,
                }],
            },
        },
    }

    report = build_experiment_report(
        run_id="redacted-system-stability-phase-evidence-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=gate,
    )

    failure = report["systemStabilityGate"]["phases"]["preflight"]["failures"][0]
    assert failure["versionStatus"] == "present"
    assert failure["expectedExecutablePathStatus"] == "redacted"
    serialized = json.dumps(report, sort_keys=True)
    assert secret_version not in serialized
    assert secret_path not in serialized


def test_experiment_report_preserves_minimal_failing_system_gate_evidence() -> None:
    system_gate = {
        "status": "fail",
        "qualityGateAllowed": False,
        "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
    }

    report = build_experiment_report(
        run_id="minimal-failing-system-gate-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    normalized_gate = report["systemStabilityGate"]
    assert normalized_gate == system_gate
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert "REQUIRED_TOOL_UNAVAILABLE" in report["qualityGate"]["reasonCodes"]


def test_experiment_report_preserves_minimal_not_run_system_gate_evidence() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    system_gate = {
        "status": "not_run",
        "qualityGateAllowed": False,
        "reasonCodes": ["HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS"],
    }

    report = build_experiment_report(
        run_id="minimal-not-run-system-gate-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    normalized_gate = report["systemStabilityGate"]
    assert normalized_gate == system_gate
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert report["qualityGate"]["decision"] == "insufficient-evidence-for-tool-change"
    assert "SYSTEM_STABILITY_GATE_NOT_RUN" in report["qualityGate"]["reasonCodes"]


def test_experiment_report_preserves_legitimate_failing_system_gate_evidence() -> None:
    availability = {
        tool: {"available": True, "version": f"{idx}.0.0", "probeReason": None}
        for idx, tool in enumerate(ALL_TOOLS, start=1)
    }
    availability["semgrep"] = {"available": False, "version": None, "probeReason": "not-found"}
    results = {
        tool: {"status": "ok", "findingsCount": 0, "elapsedMs": 10, "version": f"{idx}.0.0"}
        for idx, tool in enumerate(ALL_TOOLS, start=1)
    }
    results["semgrep"] = {"status": "not_run", "reasonCode": "TOOL_UNAVAILABLE"}
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=results,
    )

    report = build_experiment_report(
        run_id="legitimate-failing-system-gate-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    normalized_gate = report["systemStabilityGate"]
    assert normalized_gate["status"] == "fail"
    assert normalized_gate["reasonCodes"] == system_gate["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" not in normalized_gate["reasonCodes"]
    preflight_failure = normalized_gate["phases"]["preflight"]["failures"][0]
    assert preflight_failure == {
        "toolId": "semgrep",
        "phase": "preflight",
        "reasonCode": "not-found",
        "versionStatus": "missing",
        "expectedExecutablePathStatus": "not-configured",
    }
    assert "version" not in preflight_failure
    assert "expectedExecutablePath" not in preflight_failure
    assert normalized_gate["phases"]["executionCompleteness"] == system_gate["phases"]["executionCompleteness"]
    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"


def test_experiment_report_fails_quality_when_required_splits_are_empty() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="empty-required-splits-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": [],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_NOT_DECLARED"]
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_NOT_DECLARED"]


def test_experiment_report_fails_quality_when_required_splits_are_blank() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="blank-required-splits-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["", "  "],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_NOT_DECLARED"]
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_NOT_DECLARED"]


def test_experiment_report_fails_quality_when_required_splits_include_unknown_entry_without_scoring() -> None:
    secret_split = "SECRET_REQUIRED_SPLIT_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-required-splits-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", secret_split, "test"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_INVALID"]
    assert local["invalidRequiredSplits"] == {"category": "invalid-entry"}
    assert local["thresholds"]["requiredSplits"] == ["validation", "<invalid>", "test"]
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_INVALID"]
    assert secret_split not in json.dumps(report, sort_keys=True)


def test_experiment_report_fails_quality_when_required_splits_include_structured_entry_without_scoring() -> None:
    secret_split = "SECRET_REQUIRED_SPLIT_OBJECT_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-structured-required-splits-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", {"name": secret_split}],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_INVALID"]
    assert local["invalidRequiredSplits"] == {"category": "invalid-entry"}
    assert local["thresholds"]["requiredSplits"] == ["validation", "<invalid>"]
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert secret_split not in json.dumps(report, sort_keys=True)


def test_experiment_report_fails_quality_when_no_threshold_criteria_are_declared() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="no-threshold-criteria-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_THRESHOLDS_NOT_DECLARED"]
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLDS_NOT_DECLARED"]


def test_experiment_report_marks_non_discriminating_thresholds_not_decision_grade() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="runner-integrity-threshold-profile-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 0.0,
            "minimumFindingPrecision": 0.0,
            "maximumNegativeTargetFpr": 1.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "not_decision_grade"
    assert local["reasonCodes"] == ["QUALITY_THRESHOLDS_NON_DISCRIMINATING"]
    assert local["thresholdProfile"] == {
        "status": "not_decision_grade",
        "intent": "runner-integrity-only",
        "reasonCodes": ["QUALITY_THRESHOLDS_NON_DISCRIMINATING"],
        "nonDiscriminatingThresholdFields": [
            "minimumTargetRecall",
            "minimumFindingPrecision",
            "maximumNegativeTargetFpr",
        ],
    }
    assert local["failingSplits"] == []
    assert local["passingSplits"] == ["validation", "test", "canary"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert report["qualityGate"]["decision"] == "insufficient-evidence-for-tool-change"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLDS_NON_DISCRIMINATING"]


def test_experiment_report_marks_zero_recall_only_threshold_not_decision_grade() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="zero-recall-only-threshold-profile-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 0.0,
            "requiredSplits": ["validation", "test"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "not_decision_grade"
    assert local["thresholdProfile"]["intent"] == "runner-integrity-only"
    assert local["thresholdProfile"]["nonDiscriminatingThresholdFields"] == ["minimumTargetRecall"]
    assert report["qualityGate"]["status"] == "not_decision_grade"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLDS_NON_DISCRIMINATING"]


def _assert_invalid_thresholds_payload_fails(thresholds: object, expected_type: str) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-thresholds-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds=thresholds,  # type: ignore[arg-type]
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_THRESHOLDS_INPUT_INVALID"]
    assert local["primaryToolSetConfig"] == "full-current-six"
    assert local["thresholds"] == {"inputType": expected_type}
    assert local["invalidThresholdPayload"] == {"category": "non-mapping", "type": expected_type}
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLDS_INPUT_INVALID"]


def test_experiment_report_fails_quality_when_thresholds_payload_is_none() -> None:
    _assert_invalid_thresholds_payload_fails(None, "NoneType")


def test_experiment_report_fails_quality_when_thresholds_payload_is_list() -> None:
    _assert_invalid_thresholds_payload_fails([], "list")


def test_experiment_report_fails_quality_when_thresholds_payload_is_string() -> None:
    _assert_invalid_thresholds_payload_fails("strict", "str")


class _SecretThreshold:
    def __repr__(self) -> str:
        return "SECRET_THRESHOLD_SHOULD_NOT_LEAK"


def _assert_non_json_serializable_thresholds_fail_closed(
    thresholds: object,
    expected_diagnostic: dict[str, str],
    *,
    forbidden_text: str,
) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="non-json-thresholds-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds=thresholds,  # type: ignore[arg-type]
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_THRESHOLDS_INPUT_INVALID"]
    assert local["invalidThresholdPayload"] == expected_diagnostic
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLDS_INPUT_INVALID"]
    assert report["validationMetrics"]["status"] == "pass"
    assert report["testMetrics"]["status"] == "pass"
    assert report["canaryMetrics"]["status"] == "pass"
    assert report["portfolioMetrics"]["uniqueTpContribution"]["semgrep"] >= 1
    assert report["decisionCycle"]["thresholdsChecksum"].startswith("sha256:")
    assert forbidden_text not in json.dumps(report, sort_keys=True)
    write_experiment_report(report, Path("/tmp/s4-non-json-threshold-report.json"))


def test_experiment_report_fails_quality_when_thresholds_payload_is_object_without_crashing() -> None:
    _assert_non_json_serializable_thresholds_fail_closed(
        _SecretThreshold(),
        {"category": "non-mapping", "type": "_SecretThreshold"},
        forbidden_text="SECRET_THRESHOLD_SHOULD_NOT_LEAK",
    )


def test_experiment_report_fails_quality_when_threshold_value_is_object_without_crashing() -> None:
    _assert_non_json_serializable_thresholds_fail_closed(
        {"minimumTargetRecall": _SecretThreshold()},
        {"category": "non-json-serializable", "field": "minimumTargetRecall", "type": "_SecretThreshold"},
        forbidden_text="SECRET_THRESHOLD_SHOULD_NOT_LEAK",
    )


def test_experiment_report_fails_quality_when_nested_threshold_value_is_set_without_leaking_contents() -> None:
    _assert_non_json_serializable_thresholds_fail_closed(
        {"minimumTargetRecall": 1.0, "nested": {"bad": {"SECRET_THRESHOLD_SET_SHOULD_NOT_LEAK"}}},
        {"category": "non-json-serializable", "field": "<invalid>.<invalid>", "type": "set"},
        forbidden_text="SECRET_THRESHOLD_SET_SHOULD_NOT_LEAK",
    )


def test_experiment_report_does_not_echo_secret_unknown_threshold_key_in_non_json_diagnostic() -> None:
    secret_key = "SECRET_THRESHOLD_FIELD_SHOULD_NOT_LEAK"
    _assert_non_json_serializable_thresholds_fail_closed(
        {"minimumTargetRecall": 1.0, secret_key: _SecretThreshold()},
        {"category": "non-json-serializable", "field": "<invalid>", "type": "_SecretThreshold"},
        forbidden_text=secret_key,
    )


def test_experiment_report_does_not_echo_secret_nested_threshold_key_in_non_json_diagnostic() -> None:
    secret_key = "SECRET_NESTED_THRESHOLD_FIELD_SHOULD_NOT_LEAK"
    _assert_non_json_serializable_thresholds_fail_closed(
        {"minimumTargetRecall": {secret_key: _SecretThreshold()}},
        {"category": "non-json-serializable", "field": "minimumTargetRecall.<invalid>", "type": "_SecretThreshold"},
        forbidden_text=secret_key,
    )


def test_experiment_report_blocks_without_crashing_when_system_fails_and_thresholds_payload_is_invalid() -> None:
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {"available": False, "probeReason": "environment-drift"}
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="blocked-invalid-thresholds-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds=[],  # type: ignore[arg-type]
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert local["status"] == "blocked"
    assert local["thresholds"] == {"inputType": "list"}
    assert local["reasonCodes"]


def _assert_invalid_matching_policy_payload_fails(matching_policy: object, expected_type: str) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-matching-policy-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy=matching_policy,  # type: ignore[arg-type]
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["matchingPolicy"]["schemaVersion"] == "s4-oracle-matching-policy-v1"
    assert report["matchingPolicy"]["inputInvalid"] is True
    assert report["matchingPolicy"]["invalidInputType"] == expected_type
    for split in ("validationMetrics", "testMetrics", "canaryMetrics"):
        assert report[split]["status"] == "not_run"
        assert report[split]["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
        assert report[split]["byConfig"] == {}
    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
    assert local["invalidMatchingPolicyPayload"] == {"category": "non-mapping", "type": expected_type}
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert report["portfolioMetrics"]["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]


def test_experiment_report_fails_quality_when_matching_policy_payload_is_none() -> None:
    _assert_invalid_matching_policy_payload_fails(None, "NoneType")


def test_experiment_report_fails_quality_when_matching_policy_payload_is_list() -> None:
    _assert_invalid_matching_policy_payload_fails([], "list")


def test_experiment_report_fails_quality_when_matching_policy_payload_is_string() -> None:
    _assert_invalid_matching_policy_payload_fails("strict", "str")


def _assert_invalid_matching_policy_semantics_fail(
    matching_policy: dict[str, object],
    expected_diagnostic: dict[str, str],
    forbidden_substrings=(),
) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-matching-policy-semantics-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy=matching_policy,
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["matchingPolicy"]["schemaVersion"] == "s4-oracle-matching-policy-v1"
    assert report["matchingPolicy"]["lineWindowDefault"] == 5
    assert report["matchingPolicy"]["functionFallbackDefault"] is False
    assert report["matchingPolicy"]["inputInvalid"] is True
    assert report["matchingPolicy"]["invalidInputCategory"] == expected_diagnostic["category"]
    if "field" in expected_diagnostic:
        assert report["matchingPolicy"]["invalidInputField"] == expected_diagnostic["field"]
    for split in ("validationMetrics", "testMetrics", "canaryMetrics"):
        assert report[split]["status"] == "not_run"
        assert report[split]["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
        assert report[split]["byConfig"] == {}
    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
    assert local["invalidMatchingPolicyPayload"] == expected_diagnostic
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert report["portfolioMetrics"]["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
    serialized = json.dumps(report, sort_keys=True)
    for substring in forbidden_substrings:
        assert substring not in serialized


def test_experiment_report_fails_quality_when_matching_policy_schema_is_unknown() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": "future-oracle-policy-v9", "lineWindowDefault": 3, "functionFallbackDefault": False},
        {"category": "invalid-schema-version", "field": "schemaVersion", "value": "<invalid>"},
    )


def test_experiment_report_does_not_echo_secret_matching_policy_schema_version() -> None:
    secret = "SECRET_MATCHING_POLICY_SCHEMA_SHOULD_NOT_LEAK"
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": secret, "lineWindowDefault": 3, "functionFallbackDefault": False},
        {"category": "invalid-schema-version", "field": "schemaVersion", "value": "<invalid>"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_fails_quality_when_matching_policy_schema_is_non_string() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": 1, "lineWindowDefault": 3, "functionFallbackDefault": False},
        {"category": "invalid-field", "field": "schemaVersion", "type": "int"},
    )


def test_experiment_report_fails_quality_when_matching_policy_has_unknown_field() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {
            "schemaVersion": "s4-oracle-matching-policy-v1",
            "lineWindowDefault": 3,
            "functionFallbackDefault": False,
            "strictMode": True,
        },
        {"category": "unknown-field", "field": "<invalid>"},
    )


def test_experiment_report_does_not_echo_secret_matching_policy_unknown_field() -> None:
    secret = "SECRET_MATCHING_POLICY_FIELD_SHOULD_NOT_LEAK"
    _assert_invalid_matching_policy_semantics_fail(
        {
            "schemaVersion": "s4-oracle-matching-policy-v1",
            "lineWindowDefault": 3,
            "functionFallbackDefault": False,
            secret: True,
        },
        {"category": "unknown-field", "field": "<invalid>"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_does_not_stringify_secret_matching_policy_unknown_field() -> None:
    secret = "SECRET_MATCHING_POLICY_FIELD_OBJECT_SHOULD_NOT_LEAK"
    _assert_invalid_matching_policy_semantics_fail(
        {
            "schemaVersion": "s4-oracle-matching-policy-v1",
            "lineWindowDefault": 3,
            "functionFallbackDefault": False,
            ("secret", secret): True,
        },
        {"category": "unknown-field", "field": "<invalid>", "type": "tuple"},
        forbidden_substrings=[secret],
    )


def test_experiment_report_fails_quality_when_matching_policy_line_window_is_bool() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": True, "functionFallbackDefault": False},
        {"category": "invalid-field", "field": "lineWindowDefault", "type": "bool"},
    )


def test_experiment_report_fails_quality_when_matching_policy_line_window_is_negative() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": -1, "functionFallbackDefault": False},
        {"category": "invalid-range", "field": "lineWindowDefault", "value": "<invalid>", "expected": "0..25"},
    )


def test_experiment_report_fails_quality_when_matching_policy_line_window_is_too_large() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 26, "functionFallbackDefault": False},
        {"category": "invalid-range", "field": "lineWindowDefault", "value": "<invalid>", "expected": "0..25"},
    )


def test_experiment_report_fails_quality_when_matching_policy_line_window_is_non_int() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3.5, "functionFallbackDefault": False},
        {"category": "invalid-field", "field": "lineWindowDefault", "type": "float"},
    )


def test_experiment_report_fails_quality_when_matching_policy_function_fallback_is_non_bool() -> None:
    _assert_invalid_matching_policy_semantics_fail(
        {"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": "false"},
        {"category": "invalid-field", "field": "functionFallbackDefault", "type": "str"},
    )


def test_experiment_report_canonicalizes_minimal_matching_policy_defaults() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="minimal-matching-policy-defaults-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["matchingPolicy"] == {
        "schemaVersion": "s4-oracle-matching-policy-v1",
        "lineWindowDefault": 5,
        "functionFallbackDefault": False,
    }
    assert report["qualityGate"]["status"] == "pass"
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"


def test_experiment_report_blocks_without_crashing_when_system_fails_and_matching_policy_payload_is_invalid() -> None:
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {"available": False, "probeReason": "environment-drift"}
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="blocked-invalid-matching-policy-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config={},
        matching_policy=[],  # type: ignore[arg-type]
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "blocked"
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert "SYSTEM_STABILITY_GATE_FAILED" in report["portfolioMetrics"]["reasonCodes"]


def _assert_invalid_findings_by_config_payload_fails(
    findings_by_config: object,
    expected_diagnostic: dict[str, str],
) -> dict:
    corpus, _ = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-findings-by-config-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=findings_by_config,  # type: ignore[arg-type]
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    for split in ("validationMetrics", "testMetrics", "canaryMetrics"):
        assert report[split]["status"] == "not_run"
        assert report[split]["reasonCodes"] == ["FINDINGS_BY_CONFIG_INPUT_INVALID"]
        assert report[split]["byConfig"] == {}
    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["FINDINGS_BY_CONFIG_INPUT_INVALID"]
    assert local["invalidFindingsByConfigPayload"] == expected_diagnostic
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["FINDINGS_BY_CONFIG_INPUT_INVALID"]
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert report["portfolioMetrics"]["reasonCodes"] == ["FINDINGS_BY_CONFIG_INPUT_INVALID"]
    return report


def test_experiment_report_fails_quality_when_findings_by_config_payload_is_none() -> None:
    _assert_invalid_findings_by_config_payload_fails(None, {"category": "non-mapping", "type": "NoneType"})


def test_experiment_report_fails_quality_when_findings_by_config_payload_is_list() -> None:
    _assert_invalid_findings_by_config_payload_fails([], {"category": "non-mapping", "type": "list"})


def test_experiment_report_fails_quality_when_findings_by_config_payload_is_string() -> None:
    _assert_invalid_findings_by_config_payload_fails("strict", {"category": "non-mapping", "type": "str"})


def test_experiment_report_fails_quality_when_findings_by_config_is_empty() -> None:
    _assert_invalid_findings_by_config_payload_fails(
        {},
        {"category": "missing-required-config", "config": "full-current-six"},
    )


def test_experiment_report_fails_quality_when_findings_by_config_missing_one_required_config() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    del by_config["single-tool:semgrep"]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {"category": "missing-required-config", "config": "single-tool:semgrep"},
    )


def test_experiment_report_fails_quality_when_config_findings_value_is_string() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = "not-a-finding-sequence"  # type: ignore[assignment]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {"category": "invalid-config-findings", "config": "full-current-six", "type": "str"},
    )


def test_experiment_report_fails_quality_when_config_findings_value_is_non_sequence() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = 7  # type: ignore[assignment]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {"category": "invalid-config-findings", "config": "full-current-six", "type": "int"},
    )


def test_experiment_report_fails_quality_when_config_findings_contains_string_element() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = ["bad"]  # type: ignore[list-item]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {"category": "invalid-finding-element", "config": "full-current-six", "index": "0", "type": "str"},
    )


def test_experiment_report_fails_quality_when_config_findings_contains_none_element() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [None]  # type: ignore[list-item]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {"category": "invalid-finding-element", "config": "full-current-six", "index": "0", "type": "NoneType"},
    )


def test_experiment_report_fails_quality_when_config_findings_contains_int_element() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [1]  # type: ignore[list-item]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {"category": "invalid-finding-element", "config": "full-current-six", "index": "0", "type": "int"},
    )


def test_experiment_report_fails_quality_without_leaking_unknown_finding_tool_id() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [{
        "toolId": "routeTo",
        "ruleId": "routeTo:fixture",
        "location": {"file": "validation-clean.c", "line": 40, "column": 1},
        "metadata": {"cweId": "CWE-121"},
    }]

    report = _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-tool-id",
            "config": "full-current-six",
            "index": "0",
            "reason": "unknown-tool",
        },
    )

    assert "routeTo" not in json.dumps(report, sort_keys=True)


def test_experiment_report_fails_quality_when_mapping_finding_tool_id_is_missing_or_non_string() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [{
        "ruleId": "missing-tool:fixture",
        "location": {"file": "validation-clean.c", "line": 40, "column": 1},
        "metadata": {"cweId": "CWE-121"},
    }]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-tool-id",
            "config": "full-current-six",
            "index": "0",
            "reason": "missing-or-non-string",
        },
    )

    _, by_config = _clean_quality_corpus_and_findings()
    by_config["full-current-six"] = [{
        "toolId": 123,
        "ruleId": "non-string-tool:fixture",
        "location": {"file": "validation-clean.c", "line": 40, "column": 1},
        "metadata": {"cweId": "CWE-121"},
    }]
    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-tool-id",
            "config": "full-current-six",
            "index": "0",
            "reason": "missing-or-non-string",
        },
    )


def test_experiment_report_fails_quality_when_single_tool_config_contains_other_tool_finding() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["single-tool:semgrep"] = [_finding("cppcheck", "validation-clean", 40, "CWE-121")]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-tool-id",
            "config": "single-tool:semgrep",
            "index": "0",
            "reason": "single-tool-mismatch",
            "expectedTool": "semgrep",
        },
    )


def test_experiment_report_fails_quality_when_leave_one_out_config_contains_excluded_tool() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["leave-one-out:semgrep"] = [_finding("semgrep", "validation-clean", 40, "CWE-121")]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-tool-id",
            "config": "leave-one-out:semgrep",
            "index": "0",
            "reason": "leave-one-out-excluded-tool",
            "excludedTool": "semgrep",
        },
    )


def test_experiment_report_accepts_mapping_finding_tool_id_snake_case_alias() -> None:
    finding = {
        "tool_id": "semgrep",
        "rule_id": "semgrep:fixture",
        "location": {"file": "validation-clean.c", "line": 40, "column": 1},
        "metadata": {"cweId": "CWE-121"},
    }
    by_config = _by_config_for_primary_findings([])
    by_config["full-current-six"] = [finding]
    by_config["single-tool:semgrep"] = [finding]
    by_config["leave-one-out:cppcheck"] = [finding]

    report = build_experiment_report(
        run_id="valid-snake-case-tool-id-run",
        created_at="2026-05-14T00:00:00Z",
        phase="validation",
        corpus_manifest={
            "schemaVersion": CORPUS_SCHEMA_VERSION,
            "profile": "c-cpp-tool-portfolio-v1",
            "createdAt": "2026-05-14",
            "owner": "s4-sast-runner",
            "cases": [_case("validation-clean", "validation", "CWE-121", 40)],
        },
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 1.0, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    assert report["qualityGate"]["localQualityAssessment"]["reasonCodes"] != ["FINDINGS_BY_CONFIG_INPUT_INVALID"]
    assert report["qualityDiagnostics"]["splitDiagnostics"]["validation"]["byTool"]["semgrep"]["tpFindingCount"] == 1


def test_experiment_report_fails_quality_without_leaking_mapping_finding_line_value() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [{
        "toolId": "semgrep",
        "ruleId": "semgrep:fixture",
        "location": {"file": "validation-clean.c", "line": "SECRET_RAW", "column": 1},
        "metadata": {"cweId": "CWE-121"},
    }]

    report = _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-payload",
            "config": "full-current-six",
            "index": "0",
            "field": "line",
            "reason": "invalid-line",
            "type": "str",
        },
    )

    assert "SECRET_RAW" not in json.dumps(report, sort_keys=True)


def test_experiment_report_fails_quality_without_leaking_mapping_finding_location_value() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [{
        "toolId": "semgrep",
        "ruleId": "semgrep:fixture",
        "location": "SECRET_RAW",
        "metadata": {"cweId": "CWE-121"},
    }]

    report = _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-payload",
            "config": "full-current-six",
            "index": "0",
            "field": "location",
            "reason": "non-mapping",
            "type": "str",
        },
    )

    assert "SECRET_RAW" not in json.dumps(report, sort_keys=True)


def test_experiment_report_fails_quality_without_leaking_mapping_finding_metadata_value() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [{
        "toolId": "semgrep",
        "ruleId": "semgrep:fixture",
        "location": {"file": "validation-clean.c", "line": 40, "column": 1},
        "metadata": "SECRET_RAW",
    }]

    report = _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-payload",
            "config": "full-current-six",
            "index": "0",
            "field": "metadata",
            "reason": "non-mapping",
            "type": "str",
        },
    )

    assert "SECRET_RAW" not in json.dumps(report, sort_keys=True)


def test_experiment_report_fails_quality_when_mapping_finding_rule_or_file_is_blank() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [{
        "toolId": "semgrep",
        "ruleId": " ",
        "location": {"file": "validation-clean.c", "line": 40, "column": 1},
        "metadata": {"cweId": "CWE-121"},
    }]

    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-payload",
            "config": "full-current-six",
            "index": "0",
            "field": "ruleId",
            "reason": "missing-or-blank",
        },
    )

    _, by_config = _clean_quality_corpus_and_findings()
    by_config["full-current-six"] = [{
        "toolId": "semgrep",
        "ruleId": "semgrep:fixture",
        "location": {"file": " ", "line": 40, "column": 1},
        "metadata": {"cweId": "CWE-121"},
    }]
    _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-payload",
            "config": "full-current-six",
            "index": "0",
            "field": "file",
            "reason": "missing-or-blank",
        },
    )


def test_experiment_report_fails_quality_for_invalid_mapping_finding_data_flow_step() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    del corpus
    by_config["full-current-six"] = [{
        "toolId": "semgrep",
        "ruleId": "semgrep:fixture",
        "location": {"file": "validation-clean.c", "line": 40, "column": 1},
        "metadata": {"cweId": "CWE-121"},
        "dataFlow": [{"line": "SECRET_RAW"}],
    }]

    report = _assert_invalid_findings_by_config_payload_fails(
        by_config,
        {
            "category": "invalid-finding-payload",
            "config": "full-current-six",
            "index": "0",
            "field": "dataFlow.line",
            "dataFlowIndex": "0",
            "reason": "invalid-line",
            "type": "str",
        },
    )

    assert "SECRET_RAW" not in json.dumps(report, sort_keys=True)


def test_experiment_report_rejects_unsafe_corpus_source_path_before_scoring() -> None:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-14",
        "owner": "s4-sast-runner",
        "cases": [_case("validation-clean", "validation", "CWE-121", 40)],
    }
    corpus["cases"][0]["sourcePath"] = "../SECRET_RAW.c"

    with pytest.raises(ValueError) as excinfo:
        build_experiment_report(
            run_id="unsafe-source-path-report-run",
            created_at="2026-05-14T00:00:00Z",
            phase="validation",
            corpus_manifest=corpus,
            acquisition_manifests=[_acquisition_manifest()],
            findings_by_config=_by_config_for_primary_findings([]),
            matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
            thresholds={"minimumTargetRecall": 1.0, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
            corpus_readiness_gate=_available_corpus_readiness_gate(),
            system_stability=_passing_system_stability_gate(),
        )

    message = str(excinfo.value)
    assert "validation-clean.sourcePath" in message
    assert "path traversal" in message
    assert "SECRET_RAW" not in message


def test_experiment_report_canonicalizes_top_level_file_line_mapping_finding_for_scoring() -> None:
    finding = {
        "tool_id": "semgrep",
        "rule_id": "semgrep:fixture",
        "file": "validation-clean.c",
        "line": 40,
        "metadata": {"cweId": "CWE-121"},
    }
    by_config = _by_config_for_primary_findings([])
    by_config["full-current-six"] = [finding]
    by_config["single-tool:semgrep"] = [finding]
    by_config["leave-one-out:cppcheck"] = [finding]

    report = build_experiment_report(
        run_id="valid-top-level-file-line-mapping-run",
        created_at="2026-05-14T00:00:00Z",
        phase="validation",
        corpus_manifest={
            "schemaVersion": CORPUS_SCHEMA_VERSION,
            "profile": "c-cpp-tool-portfolio-v1",
            "createdAt": "2026-05-14",
            "owner": "s4-sast-runner",
            "cases": [_case("validation-clean", "validation", "CWE-121", 40)],
        },
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 1.0, "requiredSplits": ["validation"], "primaryToolSetConfig": "full-current-six"},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    validation = report["qualityDiagnostics"]["splitDiagnostics"]["validation"]
    assert validation["byTool"]["semgrep"]["tpFindingCount"] == 1
    assert validation["byCweTool"]["CWE-121"]["semgrep"]["targetTP"] == 1


def test_experiment_report_blocks_without_crashing_when_system_fails_and_findings_by_config_payload_is_invalid() -> None:
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {"available": False, "probeReason": "environment-drift"}
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="blocked-invalid-findings-by-config-payload-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=None,  # type: ignore[arg-type]
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    assert report["qualityGate"]["status"] == "blocked"
    assert report["qualityGate"]["decision"] == "invalid-precondition"
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "blocked"
    assert report["portfolioMetrics"]["status"] == "blocked"
    assert "SYSTEM_STABILITY_GATE_FAILED" in report["portfolioMetrics"]["reasonCodes"]


def _assert_invalid_threshold_value_fails(
    threshold_overrides: dict[str, object],
    *,
    expected_invalid_fields: list[str],
) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()
    thresholds: dict[str, object] = {
        "minimumTargetRecall": 1.0,
        "minimumFindingPrecision": 1.0,
        "maximumNegativeTargetFpr": 0.0,
        "requiredSplits": ["validation", "test", "canary"],
        "primaryToolSetConfig": "full-current-six",
    }
    thresholds.update(threshold_overrides)

    report = build_experiment_report(
        run_id="invalid-threshold-value-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds=thresholds,
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_THRESHOLD_VALUE_INVALID"]
    assert local["invalidThresholdFields"] == expected_invalid_fields
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_THRESHOLD_VALUE_INVALID"]


def test_experiment_report_fails_quality_when_minimum_threshold_is_negative() -> None:
    _assert_invalid_threshold_value_fails(
        {"minimumTargetRecall": -0.1},
        expected_invalid_fields=["minimumTargetRecall"],
    )


def test_experiment_report_fails_quality_when_maximum_threshold_is_above_one() -> None:
    _assert_invalid_threshold_value_fails(
        {"maximumNegativeTargetFpr": 1.1},
        expected_invalid_fields=["maximumNegativeTargetFpr"],
    )


def test_experiment_report_fails_quality_when_threshold_is_non_numeric() -> None:
    _assert_invalid_threshold_value_fails(
        {"minimumFindingPrecision": "strict"},
        expected_invalid_fields=["minimumFindingPrecision"],
    )


def test_experiment_report_fails_quality_when_threshold_is_non_finite() -> None:
    _assert_invalid_threshold_value_fails(
        {"minimumTargetRecall": float("inf")},
        expected_invalid_fields=["minimumTargetRecall"],
    )


def test_experiment_report_redacts_secret_invalid_threshold_value_from_threshold_snapshot() -> None:
    secret_value = "SECRET_THRESHOLD_VALUE_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-invalid-threshold-value-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": secret_value,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["reasonCodes"] == ["QUALITY_THRESHOLD_VALUE_INVALID"]
    assert local["thresholds"]["minimumFindingPrecision"] == "<invalid>"
    assert secret_value not in json.dumps(report, sort_keys=True)


def test_experiment_report_omits_secret_unknown_threshold_key_from_threshold_snapshot() -> None:
    secret_key = "SECRET_UNKNOWN_THRESHOLD_KEY_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-unknown-threshold-key-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": "full-current-six",
            secret_key: 1.0,
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "pass"
    assert secret_key not in local["thresholds"]
    assert secret_key not in json.dumps(report, sort_keys=True)


def _assert_invalid_primary_tool_set_config_fails(primary_tool_set_config: object) -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="invalid-primary-tool-set-config-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": primary_tool_set_config,
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "fail"
    assert local["reasonCodes"] == ["QUALITY_PRIMARY_TOOL_SET_CONFIG_INVALID"]
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert report["qualityGate"]["status"] == "fail"
    assert report["qualityGate"]["reasonCodes"] == ["QUALITY_PRIMARY_TOOL_SET_CONFIG_INVALID"]


def test_experiment_report_fails_quality_when_primary_tool_set_config_is_blank() -> None:
    _assert_invalid_primary_tool_set_config_fails("")


def test_experiment_report_fails_quality_when_primary_tool_set_config_is_whitespace() -> None:
    _assert_invalid_primary_tool_set_config_fails("  ")


def test_experiment_report_fails_quality_when_primary_tool_set_config_is_unknown() -> None:
    _assert_invalid_primary_tool_set_config_fails("future-current-seven")


def test_experiment_report_fails_quality_when_primary_tool_set_config_is_non_string() -> None:
    _assert_invalid_primary_tool_set_config_fails(True)


def test_experiment_report_redacts_secret_unknown_primary_tool_set_config() -> None:
    secret_config = "SECRET_PRIMARY_TOOL_SET_CONFIG_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-primary-tool-set-config-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": secret_config,
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["reasonCodes"] == ["QUALITY_PRIMARY_TOOL_SET_CONFIG_INVALID"]
    assert local["invalidPrimaryToolSetConfig"] == {"category": "unknown", "value": "<invalid>"}
    assert local["thresholds"]["primaryToolSetConfig"] == "<invalid>"
    assert secret_config not in json.dumps(report, sort_keys=True)


def test_experiment_report_redacts_secret_primary_tool_set_config_when_matching_policy_fails_first() -> None:
    secret_config = "SECRET_PRIMARY_TOOL_SET_CONFIG_WITH_MATCHING_POLICY_FAILURE_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-primary-config-matching-policy-failure-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 999, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": secret_config,
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["reasonCodes"] == ["ORACLE_MATCHING_POLICY_INPUT_INVALID"]
    assert local["thresholds"]["primaryToolSetConfig"] == "<invalid>"
    assert secret_config not in json.dumps(report, sort_keys=True)


def test_experiment_report_redacts_secret_primary_tool_set_config_when_system_gate_blocks_first() -> None:
    secret_config = "SECRET_PRIMARY_TOOL_SET_CONFIG_WITH_SYSTEM_BLOCK_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()
    availability = {
        tool: {"available": True, "version": "1.0.0", "probeReason": None}
        for tool in ALL_TOOLS
    }
    availability["semgrep"] = {"available": False, "probeReason": "environment-drift"}
    system_gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    report = build_experiment_report(
        run_id="secret-primary-config-system-blocked-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": secret_config,
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=system_gate,
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "blocked"
    assert local["thresholds"]["primaryToolSetConfig"] == "<invalid>"
    assert secret_config not in json.dumps(report, sort_keys=True)


def test_experiment_report_redacts_secret_unknown_required_split_from_split_outputs() -> None:
    secret_split = "SECRET_REQUIRED_SPLIT_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-required-split-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", secret_split, "test"],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_INVALID"]
    assert local["invalidRequiredSplits"] == {"category": "invalid-entry"}
    assert local["thresholds"]["requiredSplits"] == ["validation", "<invalid>", "test"]
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert secret_split not in json.dumps(report, sort_keys=True)


def test_experiment_report_redacts_secret_structured_required_split_from_split_outputs() -> None:
    secret_split = "SECRET_REQUIRED_SPLIT_OBJECT_SHOULD_NOT_LEAK"
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="secret-structured-required-split-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", {"name": secret_split}],
            "primaryToolSetConfig": "full-current-six",
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["reasonCodes"] == ["QUALITY_REQUIRED_SPLITS_INVALID"]
    assert local["invalidRequiredSplits"] == {"category": "invalid-entry"}
    assert local["thresholds"]["requiredSplits"] == ["validation", "<invalid>"]
    assert local["splitAssessments"] == {}
    assert local["passingSplits"] == []
    assert local["failingSplits"] == []
    assert secret_split not in json.dumps(report, sort_keys=True)


def test_experiment_report_defaults_absent_primary_tool_set_config_to_full_current_six() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="absent-primary-tool-set-config-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "pass"
    assert local["primaryToolSetConfig"] == "full-current-six"
    assert report["qualityGate"]["status"] == "pass"


def test_experiment_report_defaults_null_primary_tool_set_config_to_full_current_six() -> None:
    corpus, by_config = _clean_quality_corpus_and_findings()

    report = build_experiment_report(
        run_id="null-primary-tool-set-config-quality-run",
        created_at="2026-05-13T00:00:00Z",
        phase="test",
        corpus_manifest=corpus,
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=by_config,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={
            "minimumTargetRecall": 1.0,
            "minimumFindingPrecision": 1.0,
            "maximumNegativeTargetFpr": 0.0,
            "requiredSplits": ["validation", "test", "canary"],
            "primaryToolSetConfig": None,
        },
        external_corpus_status={"juliet": {"status": "available"}},
        corpus_readiness_gate=_available_corpus_readiness_gate(),
        system_stability=_passing_system_stability_gate(),
    )

    local = report["qualityGate"]["localQualityAssessment"]
    assert local["status"] == "pass"
    assert local["primaryToolSetConfig"] == "full-current-six"
    assert report["qualityGate"]["status"] == "pass"


def test_experiment_report_contains_unique_contribution_leave_one_out_and_row_metadata() -> None:
    report = build_experiment_report(
        run_id="unit-fixture-run",
        created_at="2026-05-12T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "blocked", "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]}},
    )

    unique = report["portfolioMetrics"]["uniqueTpContribution"]
    leave_one_out = report["portfolioMetrics"]["leaveOneOutDelta"]

    assert unique["semgrep"] >= 1
    assert unique["gcc-fanalyzer"] >= 1
    assert leave_one_out["semgrep"]["targetRecallDelta"] > 0
    assert leave_one_out["gcc-fanalyzer"]["targetRecallDelta"] > 0
    row = report["validationMetrics"]["byConfig"]["full-current-six"]["rows"][0]
    assert row["sourceArtifact"] == "s4-harness-fixture"
    assert row["sliceKind"].startswith("s4-harness-fixture")
    assert row["toolSetConfig"] == "full-current-six"
    assert row["matchingPolicy"] == "s4-oracle-matching-policy-v1"


def test_experiment_report_has_no_forbidden_verdict_keys_and_can_be_written(tmp_path: Path) -> None:
    report = build_experiment_report(
        run_id="unit-fixture-run",
        created_at="2026-05-12T00:00:00Z",
        phase="test",
        corpus_manifest=_corpus_manifest(),
        acquisition_manifests=[_acquisition_manifest()],
        findings_by_config=_findings_by_config(),
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
        thresholds={"minimumTargetRecall": 0.0},
        external_corpus_status={"juliet": {"status": "blocked", "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]}},
    )

    serialized = json.dumps(report, sort_keys=True)
    for key in FORBIDDEN_VERDICT_KEYS:
        assert key not in serialized

    path = write_experiment_report(report, tmp_path / "report.json")
    assert path.read_text(encoding="utf-8").startswith("{\n")


def test_experiment_report_forbidden_key_guard_does_not_echo_parent_path_label() -> None:
    secret_parent = "SECRET_REPORT_FORBIDDEN_PARENT_SHOULD_NOT_LEAK"
    report = {"decisionSupport": {secret_parent: {"safe": False}}}

    with pytest.raises(ValueError) as excinfo:
        _reject_forbidden_keys(report)

    message = str(excinfo.value)
    assert "forbidden verdict key" in message
    assert "safe" in message
    assert secret_parent not in message


def test_experiment_report_forbidden_key_guard_does_not_stringify_parent_key_object() -> None:
    class SecretKey:
        def __str__(self) -> str:
            return "SECRET_REPORT_PARENT_STR_SHOULD_NOT_LEAK"

        def __repr__(self) -> str:
            return "SECRET_REPORT_PARENT_REPR_SHOULD_NOT_LEAK"

    report = {"decisionSupport": {SecretKey(): {"safe": False}}}

    with pytest.raises(ValueError) as excinfo:
        _reject_forbidden_keys(report)

    message = str(excinfo.value)
    assert "forbidden verdict key" in message
    assert "safe" in message
    assert "SECRET_REPORT_PARENT_STR_SHOULD_NOT_LEAK" not in message
    assert "SECRET_REPORT_PARENT_REPR_SHOULD_NOT_LEAK" not in message


def test_experiment_report_forbidden_key_guard_does_not_stringify_forbidden_key_object() -> None:
    class SecretForbiddenKey(str):
        def __new__(cls) -> "SecretForbiddenKey":
            return str.__new__(cls, "safe")

        def __str__(self) -> str:
            return "SECRET_REPORT_FORBIDDEN_KEY_STR_SHOULD_NOT_LEAK"

        def __repr__(self) -> str:
            return "SECRET_REPORT_FORBIDDEN_KEY_REPR_SHOULD_NOT_LEAK"

    report = {"decisionSupport": {SecretForbiddenKey(): False}}

    with pytest.raises(ValueError) as excinfo:
        _reject_forbidden_keys(report)

    message = str(excinfo.value)
    assert "forbidden verdict key" in message
    assert "safe" in message
    assert "SECRET_REPORT_FORBIDDEN_KEY_STR_SHOULD_NOT_LEAK" not in message
    assert "SECRET_REPORT_FORBIDDEN_KEY_REPR_SHOULD_NOT_LEAK" not in message
