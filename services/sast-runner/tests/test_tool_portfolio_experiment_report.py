from __future__ import annotations

import json
from pathlib import Path

from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.response import SastFinding
from benchmark.tool_portfolio_acquisition_manifest import ACQUISITION_SCHEMA_VERSION, build_acquisition_index, manifest_checksum
from benchmark.tool_portfolio_experiment_manifest import CORPUS_SCHEMA_VERSION, required_current_six_configs
from benchmark.tool_portfolio_experiment_report import (
    EXPERIMENT_REPORT_SCHEMA_VERSION,
    build_experiment_report,
    write_experiment_report,
)
from benchmark.tool_portfolio_harness_fixture import build_harness_fixture_report, load_harness_fixture
from benchmark.tool_portfolio_system_gate import build_system_stability_gate

FORBIDDEN_VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}


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


def test_file_based_s4_harness_fixture_builds_end_to_end_report() -> None:
    fixture = load_harness_fixture()
    report = build_harness_fixture_report(repo_root=Path(__file__).parents[1])
    oracle = json.loads(
        (Path(__file__).parent / "fixtures" / "tool_portfolio_experiment_v1" / "quality_gate_oracle.json")
        .read_text(encoding="utf-8"),
    )

    assert fixture["schemaVersion"] == "s4-tool-portfolio-harness-fixture-v1"
    assert report["schemaVersion"] == EXPERIMENT_REPORT_SCHEMA_VERSION
    assert report["corpusReadinessGate"]["status"] == "blocked"
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in report["corpusReadinessGate"]["reasonCodes"]
    assert report["validationMetrics"]["status"] == "pass"
    assert report["testMetrics"]["status"] == "pass"
    assert report["decisionSupport"]["externalCorpusStatus"]["juliet"]["status"] == "blocked"
    assert report["portfolioMetrics"]["uniqueTpContribution"]["scan-build"] >= 1
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


def test_experiment_report_quality_gate_passes_when_all_required_splits_meet_thresholds() -> None:
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
    )

    assert report["qualityGate"]["status"] == "pass"
    assert report["qualityGate"]["decision"] == "quality-gate-pass"
    assert report["qualityGate"]["localQualityAssessment"]["status"] == "pass"
    assert report["qualityGate"]["localQualityAssessment"]["passingSplits"] == ["validation", "test", "canary"]
    assert report["decisionSupport"]["currentDecision"] == "quality-gate-pass"


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
