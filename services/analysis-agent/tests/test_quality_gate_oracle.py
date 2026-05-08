from __future__ import annotations

from eval.quality_gate_oracle import (
    classify_quality_state,
    evaluate_quality_gate_oracle,
    load_quality_gate_oracle,
)


def test_quality_gate_oracle_self_check_passes():
    verdict = evaluate_quality_gate_oracle(load_quality_gate_oracle())

    assert verdict["passed"] is True
    assert verdict["caseCount"] >= 5


def test_completed_poc_inconclusive_is_anomaly_not_clean():
    actual = classify_quality_state({
        "status": "completed",
        "result": {
            "pocOutcome": "poc_inconclusive",
            "qualityOutcome": "rejected",
            "cleanPass": False,
        },
    }, task_type="generate-poc")

    assert actual["taskCompleted"] is True
    assert actual["clean"] is False
    assert actual["anomaly"] is True
    assert actual["bucket"] == "poc_not_clean"


def test_clean_poc_requires_all_three_clean_signals():
    actual = classify_quality_state({
        "status": "completed",
        "result": {
            "pocOutcome": "poc_accepted",
            "qualityOutcome": "accepted",
            "cleanPass": True,
        },
    }, task_type="generate-poc")

    assert actual["clean"] is True
    assert actual["bucket"] == "clean"
