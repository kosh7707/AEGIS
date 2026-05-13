from __future__ import annotations

import pytest

from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.response import ToolExecutionResult
from benchmark.tool_portfolio_system_gate import (
    SYSTEM_STABILITY_GATE_SCHEMA_VERSION,
    build_quality_gate,
    build_system_stability_gate,
)


def _availability_all_ok() -> dict[str, dict]:
    return {
        tool: {"available": True, "version": f"{idx}.0.0", "probeReason": None}
        for idx, tool in enumerate(ALL_TOOLS, start=1)
    }


def _results_all_ok() -> dict[str, ToolExecutionResult]:
    return {
        tool: ToolExecutionResult(status="ok", findings_count=0, elapsed_ms=10, version=f"{idx}.0.0")
        for idx, tool in enumerate(ALL_TOOLS, start=1)
    }


def test_system_stability_gate_passes_only_when_all_required_tools_are_alive_and_complete() -> None:
    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=_availability_all_ok(),
        tool_results=_results_all_ok(),
    )

    assert gate["schemaVersion"] == SYSTEM_STABILITY_GATE_SCHEMA_VERSION
    assert gate["status"] == "pass"
    assert gate["qualityGateAllowed"] is True
    assert gate["phases"]["preflight"]["status"] == "pass"
    assert gate["phases"]["executionCompleteness"]["status"] == "pass"
    assert gate["reasonCodes"] == []


@pytest.mark.parametrize("missing_tool", ALL_TOOLS)
def test_system_stability_gate_fails_when_any_required_tool_is_unavailable_before_execution(
    missing_tool: str,
) -> None:
    availability = _availability_all_ok()
    availability[missing_tool] = {
        "available": False,
        "version": None,
        "probeReason": "environment-drift",
        "expectedExecutablePath": f"/svc/bin/{missing_tool}",
    }

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert "REQUIRED_TOOL_UNAVAILABLE" in gate["reasonCodes"]
    failure = gate["phases"]["preflight"]["failures"][0]
    assert failure["toolId"] == missing_tool
    assert failure["reasonCode"] == "environment-drift"
    assert failure["expectedExecutablePath"] == f"/svc/bin/{missing_tool}"


@pytest.mark.parametrize("bad_tool", ALL_TOOLS)
@pytest.mark.parametrize(
    ("bad_result", "expected_status"),
    [
        (ToolExecutionResult(status="failed", findings_count=0, elapsed_ms=10, skip_reason="tool crashed"), "failed"),
        (ToolExecutionResult(status="partial", findings_count=1, elapsed_ms=10, timed_out_files=1), "partial"),
        (ToolExecutionResult(status="ok", findings_count=1, elapsed_ms=10, degraded=True, degrade_reasons=["bad-output"]), "ok"),
    ],
)
def test_system_stability_gate_fails_when_any_required_tool_returns_non_normal_execution(
    bad_tool: str,
    bad_result: ToolExecutionResult,
    expected_status: str,
) -> None:
    results = _results_all_ok()
    results[bad_tool] = bad_result

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=_availability_all_ok(),
        tool_results=results,
    )

    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert "REQUIRED_TOOL_INCOMPLETE" in gate["reasonCodes"]
    failures = gate["phases"]["executionCompleteness"]["failures"]
    assert failures == [
        {
            "toolId": bad_tool,
            "phase": "executionCompleteness",
            "status": expected_status,
            "reasonCode": bad_result.skip_reason or ("tool-degraded" if bad_result.degraded else f"tool-{expected_status}"),
            "degradeReasons": bad_result.degrade_reasons or [],
            "timedOutFiles": bad_result.timed_out_files,
            "failedFiles": bad_result.failed_files,
        },
    ]


@pytest.mark.parametrize("raw_status", ["unknown", "weird-status"])
def test_system_stability_gate_fails_raw_required_tool_unknown_or_non_normal_status(
    raw_status: str,
) -> None:
    """Report-side gate must not pass malformed/raw non-normal required tool states."""
    results = {
        tool: result.model_dump(by_alias=True, exclude_none=True)
        for tool, result in _results_all_ok().items()
    }
    results["semgrep"] = {
        "status": raw_status,
        "findingsCount": 0,
        "elapsedMs": 10,
    }

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=_availability_all_ok(),
        tool_results=results,
    )

    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert "REQUIRED_TOOL_INCOMPLETE" in gate["reasonCodes"]
    failures = gate["phases"]["executionCompleteness"]["failures"]
    assert failures == [
        {
            "toolId": "semgrep",
            "phase": "executionCompleteness",
            "status": raw_status,
            "reasonCode": "tool-status-unknown",
            "degradeReasons": [],
            "timedOutFiles": None,
            "failedFiles": None,
        },
    ]


def test_system_stability_gate_fails_when_required_tool_is_skipped_failed_or_partial() -> None:
    results = _results_all_ok()
    results["cppcheck"] = ToolExecutionResult(
        status="skipped",
        findings_count=0,
        elapsed_ms=0,
        skip_reason="environment-drift",
    )
    results["scan-build"] = ToolExecutionResult(
        status="partial",
        findings_count=2,
        elapsed_ms=100,
        timed_out_files=1,
        degraded=True,
        degrade_reasons=["timed-out-files"],
    )

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=_availability_all_ok(),
        tool_results=results,
    )

    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert "REQUIRED_TOOL_INCOMPLETE" in gate["reasonCodes"]
    failures = {failure["toolId"]: failure for failure in gate["phases"]["executionCompleteness"]["failures"]}
    assert failures["cppcheck"]["status"] == "skipped"
    assert failures["scan-build"]["status"] == "partial"
    assert failures["scan-build"]["degradeReasons"] == ["timed-out-files"]


def test_quality_gate_is_blocked_when_system_stability_fails_even_if_oracle_data_exists() -> None:
    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability={**_availability_all_ok(), "semgrep": {"available": False, "probeReason": "environment-drift"}},
        tool_results=None,
    )

    quality = build_quality_gate(
        system_stability_gate=gate,
        external_corpus_status={"juliet": {"status": "available"}},
    )

    assert quality["status"] == "blocked"
    assert quality["decision"] == "invalid-precondition"
    assert quality["blockedBy"] == ["systemStabilityGate"]
    assert "SYSTEM_STABILITY_GATE_FAILED" in quality["reasonCodes"]


def test_quality_gate_is_not_decision_grade_when_system_passes_but_juliet_is_missing() -> None:
    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=_availability_all_ok(),
        tool_results=_results_all_ok(),
    )

    quality = build_quality_gate(
        system_stability_gate=gate,
        external_corpus_status={"juliet": {"status": "blocked", "reasonCodes": ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]}},
    )

    assert quality["status"] == "not_decision_grade"
    assert quality["decision"] == "insufficient-evidence-for-tool-change"
    assert quality["blockedBy"] == []
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in quality["reasonCodes"]
