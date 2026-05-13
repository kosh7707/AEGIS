from __future__ import annotations

from pathlib import Path

import pytest

from benchmark.tool_portfolio_decision_cycle import (
    assert_no_forbidden_runtime_coupling,
    assert_test_phase_not_drifted,
    build_decision_cycle_lock,
)


def _lock() -> dict:
    return build_decision_cycle_lock(
        decision_cycle_id="s4-tool-portfolio-20260512-001",
        phase="test",
        corpus_manifest={"schemaVersion": "s4-tool-portfolio-experiment-corpus-v1", "cases": []},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 5},
        thresholds={"minimumTargetRecall": 0.0},
        split_assignments={"validation": ["a"], "test": ["b"]},
        rulesets={"semgrep": ["rules/automotive"]},
        tool_versions={"semgrep": "fixture"},
        tool_paths={"semgrep": "/usr/bin/semgrep"},
        timeout_config={"timeoutSeconds": 300},
        environment_summary={"python": "3.12"},
        lockfile={"requirements": "fixture"},
    )


def test_decision_cycle_lock_contains_all_reproducibility_checksums() -> None:
    lock = _lock()

    assert lock["decisionCycleId"] == "s4-tool-portfolio-20260512-001"
    assert lock["phase"] == "test"
    for key in [
        "corpusManifestChecksum",
        "matchingPolicyChecksum",
        "thresholdsChecksum",
        "splitAssignmentChecksum",
        "rulesetChecksums",
        "toolVersions",
        "toolPaths",
        "timeoutConfig",
        "environmentSummary",
        "lockfileChecksum",
    ]:
        assert key in lock
    assert lock["frozen"] is True


def test_held_out_test_run_is_rejected_after_policy_or_threshold_drift() -> None:
    lock = _lock()

    assert_test_phase_not_drifted(
        lock,
        corpus_manifest={"schemaVersion": "s4-tool-portfolio-experiment-corpus-v1", "cases": []},
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 5},
        thresholds={"minimumTargetRecall": 0.0},
        split_assignments={"validation": ["a"], "test": ["b"]},
    )

    with pytest.raises(ValueError, match="thresholdsChecksum drift"):
        assert_test_phase_not_drifted(
            lock,
            corpus_manifest={"schemaVersion": "s4-tool-portfolio-experiment-corpus-v1", "cases": []},
            matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 5},
            thresholds={"minimumTargetRecall": 0.9},
            split_assignments={"validation": ["a"], "test": ["b"]},
        )


def test_new_experiment_modules_have_no_network_llm_or_s5_coupling() -> None:
    root = Path(__file__).parents[1]
    result = assert_no_forbidden_runtime_coupling([
        root / "benchmark" / "tool_portfolio_acquisition_manifest.py",
        root / "benchmark" / "tool_portfolio_experiment_manifest.py",
        root / "benchmark" / "tool_portfolio_oracle_matcher.py",
        root / "benchmark" / "tool_portfolio_decision_cycle.py",
        root / "benchmark" / "tool_portfolio_experiment_report.py",
        root / "benchmark" / "tool_portfolio_harness_fixture.py",
    ])

    assert result["status"] == "pass"
    assert result["checkedFiles"] == 6
