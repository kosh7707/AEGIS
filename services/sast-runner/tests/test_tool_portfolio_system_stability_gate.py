from __future__ import annotations

import pytest

from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.response import ToolExecutionResult
from benchmark.tool_portfolio_system_gate import (
    SYSTEM_STABILITY_GATE_SCHEMA_VERSION,
    blocked_metric_bucket,
    build_quality_gate,
    build_system_stability_gate,
    default_not_run_system_gate,
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


class _SecretReason:
    def __str__(self) -> str:
        return "SECRET_OBJECT_REASON_SHOULD_NOT_LEAK"

    def __repr__(self) -> str:
        return "SECRET_OBJECT_REPR_SHOULD_NOT_LEAK"


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


def test_blocked_metric_bucket_preserves_valid_split_and_reason_code() -> None:
    assert blocked_metric_bucket("validation", ["REQUIRED_TOOL_UNAVAILABLE"]) == {
        "status": "blocked",
        "split": "validation",
        "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        "byConfig": {},
    }


def test_blocked_metric_bucket_redacts_invalid_split_and_reason_codes_without_raw_echo() -> None:
    bucket = blocked_metric_bucket(
        "SECRET_SPLIT_SHOULD_NOT_LEAK",
        [
            "REQUIRED_TOOL_UNAVAILABLE",
            "SECRET_REASON_SHOULD_NOT_LEAK",
            _SecretReason(),
            123,
            "",
        ],
    )

    serialized = repr(bucket)
    assert bucket == {
        "status": "blocked",
        "split": "<invalid>",
        "reasonCodes": [
            "REQUIRED_TOOL_UNAVAILABLE",
            "SYSTEM_STABILITY_GATE_INPUT_INVALID",
        ],
        "byConfig": {},
    }
    assert "SECRET_SPLIT_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REPR_SHOULD_NOT_LEAK" not in serialized


def test_blocked_metric_bucket_does_not_expand_string_reason_codes() -> None:
    bucket = blocked_metric_bucket("test", "SECRET_REASON_STRING_SHOULD_NOT_LEAK")  # type: ignore[arg-type]

    serialized = repr(bucket)
    assert bucket == {
        "status": "blocked",
        "split": "test",
        "reasonCodes": ["SYSTEM_STABILITY_GATE_INPUT_INVALID"],
        "byConfig": {},
    }
    assert "SECRET_REASON_STRING_SHOULD_NOT_LEAK" not in serialized


def test_system_stability_gate_fails_when_required_tools_are_not_declared() -> None:
    gate = build_system_stability_gate(
        required_tools=[],
        tool_availability={},
        tool_results={},
    )

    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert gate["requiredTools"] == []
    assert gate["reasonCodes"] == ["SYSTEM_REQUIRED_TOOLS_NOT_DECLARED"]
    assert gate["phases"]["preflight"]["status"] == "fail"
    assert gate["phases"]["preflight"]["failures"] == [
        {
            "toolId": None,
            "phase": "preflight",
            "reasonCode": "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED",
        },
    ]
    assert gate["phases"]["executionCompleteness"]["failures"] == []


def test_default_not_run_system_gate_disallows_decision_grade_quality_gate() -> None:
    gate = default_not_run_system_gate()

    assert gate["status"] == "not_run"
    assert gate["qualityGateAllowed"] is False
    assert gate["reasonCodes"] == ["HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS"]


def test_system_stability_gate_normalizes_required_tools_to_canonical_order() -> None:
    gate = build_system_stability_gate(
        required_tools=["semgrep", "cppcheck", "semgrep"],
        tool_availability=_availability_all_ok(),
        tool_results=_results_all_ok(),
    )

    assert gate["status"] == "pass"
    assert gate["requiredTools"] == ["semgrep", "cppcheck"]


def test_system_stability_gate_fails_unknown_required_tools_without_execution_fallthrough() -> None:
    gate = build_system_stability_gate(
        required_tools=["semgrep", "typo-tool"],
        tool_availability=_availability_all_ok(),
        tool_results=_results_all_ok(),
    )

    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert gate["requiredTools"] == ["semgrep", "<invalid>"]
    assert "REQUIRED_TOOL_UNAVAILABLE" in gate["reasonCodes"]
    assert gate["phases"]["preflight"]["failures"] == [
        {
            "toolId": "<invalid>",
            "phase": "preflight",
            "reasonCode": "REQUIRED_TOOL_UNKNOWN",
        },
    ]
    assert gate["phases"]["executionCompleteness"]["failures"] == []


def test_system_stability_gate_redacts_invalid_required_tool_identities_without_raw_echo() -> None:
    gate = build_system_stability_gate(
        required_tools=[
            "semgrep",
            "SECRET_REQUIRED_TOOL_SHOULD_NOT_LEAK",
            _SecretReason(),
            " ",
        ],
        tool_availability=_availability_all_ok(),
        tool_results=_results_all_ok(),
    )

    serialized = repr(gate)
    assert gate["status"] == "fail"
    assert gate["qualityGateAllowed"] is False
    assert gate["requiredTools"] == ["semgrep", "<invalid>"]
    assert gate["phases"]["preflight"]["failures"] == [
        {
            "toolId": "<invalid>",
            "phase": "preflight",
            "reasonCode": "REQUIRED_TOOL_UNKNOWN",
        },
    ]
    assert "SECRET_REQUIRED_TOOL_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REPR_SHOULD_NOT_LEAK" not in serialized


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
    assert failure["versionStatus"] == "missing"
    assert failure["expectedExecutablePathStatus"] == "redacted"
    assert "version" not in failure
    assert "expectedExecutablePath" not in failure


def test_system_stability_gate_preflight_failure_redacts_unavailable_tool_metadata_without_raw_echo() -> None:
    availability = _availability_all_ok()
    availability["semgrep"] = {
        "available": False,
        "version": "SECRET_TOOL_VERSION_SHOULD_NOT_LEAK",
        "probeReason": "SECRET_PROBE_REASON_SHOULD_NOT_LEAK",
        "expectedExecutablePath": "/SECRET/TOOL/PATH/SHOULD_NOT_LEAK",
    }

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    failure = gate["phases"]["preflight"]["failures"][0]
    serialized = repr(gate)
    assert failure == {
        "toolId": "semgrep",
        "phase": "preflight",
        "reasonCode": "runtime-tool-missing",
        "versionStatus": "present",
        "expectedExecutablePathStatus": "redacted",
    }
    assert "SECRET_TOOL_VERSION_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_PROBE_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "/SECRET/TOOL/PATH/SHOULD_NOT_LEAK" not in serialized
    assert "version" not in failure
    assert "expectedExecutablePath" not in failure


def test_system_stability_gate_preflight_preserves_allowlisted_probe_reason() -> None:
    availability = _availability_all_ok()
    availability["semgrep"] = {
        "available": False,
        "version": "1.2.3",
        "probeReason": "environment-drift",
        "expectedExecutablePath": "",
    }

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=availability,
        tool_results=None,
    )

    failure = gate["phases"]["preflight"]["failures"][0]
    assert failure == {
        "toolId": "semgrep",
        "phase": "preflight",
        "reasonCode": "environment-drift",
        "versionStatus": "present",
        "expectedExecutablePathStatus": "not-configured",
    }


@pytest.mark.parametrize("bad_tool", ALL_TOOLS)
@pytest.mark.parametrize(
    ("bad_result", "expected_status", "expected_reason"),
    [
        (ToolExecutionResult(status="failed", findings_count=0, elapsed_ms=10, skip_reason="tool crashed"), "failed", "tool-failed"),
        (ToolExecutionResult(status="partial", findings_count=1, elapsed_ms=10, timed_out_files=1), "partial", "tool-partial"),
        (ToolExecutionResult(status="ok", findings_count=1, elapsed_ms=10, degraded=True, degrade_reasons=["bad-output"]), "ok", "tool-degraded"),
    ],
)
def test_system_stability_gate_fails_when_any_required_tool_returns_non_normal_execution(
    bad_tool: str,
    bad_result: ToolExecutionResult,
    expected_status: str,
    expected_reason: str,
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
            "reasonCode": expected_reason,
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
            "status": "unknown",
            "reasonCode": "tool-status-unknown",
            "degradeReasons": [],
            "timedOutFiles": None,
            "failedFiles": None,
        },
    ]


def test_system_stability_gate_execution_failure_redacts_raw_metadata_without_echo() -> None:
    results = {
        tool: result.model_dump(by_alias=True, exclude_none=True)
        for tool, result in _results_all_ok().items()
    }
    results["semgrep"] = {
        "status": "SECRET_EXEC_STATUS_SHOULD_NOT_LEAK",
        "skipReason": "SECRET_SKIP_REASON_SHOULD_NOT_LEAK",
        "degraded": True,
        "degradeReasons": [
            "timed-out-files",
            "SECRET_DEGRADE_REASON_SHOULD_NOT_LEAK",
            _SecretReason(),
            "",
        ],
        "timedOutFiles": _SecretReason(),
        "failedFiles": -1,
    }

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=_availability_all_ok(),
        tool_results=results,
    )

    failure = gate["phases"]["executionCompleteness"]["failures"][0]
    serialized = repr(gate)
    assert failure == {
        "toolId": "semgrep",
        "phase": "executionCompleteness",
        "status": "unknown",
        "reasonCode": "tool-degraded",
        "degradeReasons": ["timed-out-files"],
        "timedOutFiles": None,
        "failedFiles": None,
    }
    assert "SECRET_EXEC_STATUS_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_SKIP_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_DEGRADE_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REPR_SHOULD_NOT_LEAK" not in serialized


def test_system_stability_gate_execution_failure_preserves_allowlisted_metadata() -> None:
    results = _results_all_ok()
    results["semgrep"] = ToolExecutionResult(
        status="partial",
        findings_count=3,
        elapsed_ms=50,
        timed_out_files=2,
        failed_files=1,
        degraded=True,
        degrade_reasons=["timed-out-files", "failed-files"],
    )

    gate = build_system_stability_gate(
        required_tools=ALL_TOOLS,
        tool_availability=_availability_all_ok(),
        tool_results=results,
    )

    assert gate["phases"]["executionCompleteness"]["failures"][0] == {
        "toolId": "semgrep",
        "phase": "executionCompleteness",
        "status": "partial",
        "reasonCode": "tool-partial",
        "degradeReasons": ["timed-out-files", "failed-files"],
        "timedOutFiles": 2,
        "failedFiles": 1,
    }


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


def test_quality_gate_is_eligible_only_when_system_gate_passes_and_allows_quality() -> None:
    quality = build_quality_gate(
        system_stability_gate={
            "status": "pass",
            "qualityGateAllowed": True,
            "reasonCodes": [],
        },
        external_corpus_status={"juliet": {"status": "available"}},
    )

    assert quality["status"] == "eligible"
    assert quality["decision"] == "insufficient-evidence-for-tool-change"
    assert quality["blockedBy"] == []
    assert quality["reasonCodes"] == []


@pytest.mark.parametrize(
    ("quality_gate_allowed", "expected_reason"),
    [
        (False, "SYSTEM_STABILITY_GATE_INCONSISTENT"),
        (None, "SYSTEM_STABILITY_GATE_INPUT_INVALID"),
        ("yes", "SYSTEM_STABILITY_GATE_INPUT_INVALID"),
    ],
)
def test_quality_gate_blocks_passed_system_gate_without_explicit_quality_allowance(
    quality_gate_allowed: object,
    expected_reason: str,
) -> None:
    gate = {
        "status": "pass",
        "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
    }
    if quality_gate_allowed is not None:
        gate["qualityGateAllowed"] = quality_gate_allowed

    quality = build_quality_gate(
        system_stability_gate=gate,
        external_corpus_status={"juliet": {"status": "available"}},
    )

    assert quality["status"] == "blocked"
    assert quality["decision"] == "invalid-precondition"
    assert quality["blockedBy"] == ["systemStabilityGate"]
    assert "SYSTEM_STABILITY_GATE_FAILED" in quality["reasonCodes"]
    assert expected_reason in quality["reasonCodes"]
    assert "REQUIRED_TOOL_UNAVAILABLE" in quality["reasonCodes"]


@pytest.mark.parametrize("bad_status", ["unknown", "", None, 123])
@pytest.mark.parametrize("quality_gate_allowed", [False, True])
def test_quality_gate_blocks_unknown_or_malformed_system_gate_status(
    bad_status: object,
    quality_gate_allowed: bool,
) -> None:
    quality = build_quality_gate(
        system_stability_gate={
            "status": bad_status,
            "qualityGateAllowed": quality_gate_allowed,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        },
        external_corpus_status={"juliet": {"status": "available"}},
    )

    assert quality["status"] == "blocked"
    assert quality["decision"] == "invalid-precondition"
    assert quality["blockedBy"] == ["systemStabilityGate"]
    assert "SYSTEM_STABILITY_GATE_FAILED" in quality["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" in quality["reasonCodes"]
    assert "REQUIRED_TOOL_UNAVAILABLE" in quality["reasonCodes"]


def test_quality_gate_blocks_non_pass_system_gate_that_allows_quality() -> None:
    quality = build_quality_gate(
        system_stability_gate={
            "status": "blocked",
            "qualityGateAllowed": True,
            "reasonCodes": ["REQUIRED_TOOL_UNAVAILABLE"],
        },
        external_corpus_status={"juliet": {"status": "available"}},
    )

    assert quality["status"] == "blocked"
    assert quality["decision"] == "invalid-precondition"
    assert quality["blockedBy"] == ["systemStabilityGate"]
    assert "SYSTEM_STABILITY_GATE_FAILED" in quality["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_INCONSISTENT" in quality["reasonCodes"]
    assert "REQUIRED_TOOL_UNAVAILABLE" in quality["reasonCodes"]


def test_quality_gate_sanitizes_system_reason_codes_without_raw_echo() -> None:
    quality = build_quality_gate(
        system_stability_gate={
            "status": "fail",
            "qualityGateAllowed": False,
            "reasonCodes": [
                "REQUIRED_TOOL_UNAVAILABLE",
                "SECRET_RAW_SYSTEM_REASON_SHOULD_NOT_LEAK",
                _SecretReason(),
                123,
                "",
            ],
        },
        external_corpus_status={"juliet": {"status": "available"}},
    )

    serialized = repr(quality)
    assert quality["status"] == "blocked"
    assert "SYSTEM_STABILITY_GATE_FAILED" in quality["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" in quality["reasonCodes"]
    assert "REQUIRED_TOOL_UNAVAILABLE" in quality["reasonCodes"]
    assert "SECRET_RAW_SYSTEM_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REPR_SHOULD_NOT_LEAK" not in serialized


def test_quality_gate_sanitizes_inconsistent_system_reason_codes_without_raw_echo() -> None:
    quality = build_quality_gate(
        system_stability_gate={
            "status": "pass",
            "qualityGateAllowed": False,
            "reasonCodes": [
                "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED",
                "SECRET_INCONSISTENT_SYSTEM_REASON_SHOULD_NOT_LEAK",
                _SecretReason(),
            ],
        },
        external_corpus_status={"juliet": {"status": "available"}},
    )

    serialized = repr(quality)
    assert quality["status"] == "blocked"
    assert "SYSTEM_STABILITY_GATE_FAILED" in quality["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_INCONSISTENT" in quality["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_INPUT_INVALID" in quality["reasonCodes"]
    assert "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED" in quality["reasonCodes"]
    assert "SECRET_INCONSISTENT_SYSTEM_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REPR_SHOULD_NOT_LEAK" not in serialized


def test_quality_gate_sanitizes_external_corpus_reason_codes_without_raw_echo() -> None:
    quality = build_quality_gate(
        system_stability_gate={
            "status": "pass",
            "qualityGateAllowed": True,
            "reasonCodes": [],
        },
        external_corpus_status={
            "juliet": {
                "status": "blocked",
                "reasonCodes": [
                    "LOCAL_JULIET_CORPUS_NOT_PRESENT",
                    "SECRET_EXTERNAL_REASON_SHOULD_NOT_LEAK",
                    _SecretReason(),
                    123,
                    "",
                ],
            },
        },
    )

    serialized = repr(quality)
    assert quality["status"] == "not_decision_grade"
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in quality["reasonCodes"]
    assert "CORPUS_READINESS_GATE_INPUT_INVALID" in quality["reasonCodes"]
    assert "SECRET_EXTERNAL_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REASON_SHOULD_NOT_LEAK" not in serialized
    assert "SECRET_OBJECT_REPR_SHOULD_NOT_LEAK" not in serialized


def test_quality_gate_treats_absent_system_gate_as_not_run_quality_evidence() -> None:
    quality = build_quality_gate(
        system_stability_gate=None,
        external_corpus_status={"juliet": {"status": "available"}},
    )

    assert quality["status"] == "not_decision_grade"
    assert quality["decision"] == "insufficient-evidence-for-tool-change"
    assert quality["blockedBy"] == []
    assert quality["reasonCodes"] == ["SYSTEM_STABILITY_GATE_NOT_RUN"]


def test_quality_gate_preserves_not_run_system_gate_as_not_decision_grade() -> None:
    quality = build_quality_gate(
        system_stability_gate=default_not_run_system_gate(),
        external_corpus_status={"juliet": {"status": "available"}},
    )

    assert quality["status"] == "not_decision_grade"
    assert quality["decision"] == "insufficient-evidence-for-tool-change"
    assert quality["blockedBy"] == []
    assert "SYSTEM_STABILITY_GATE_NOT_RUN" in quality["reasonCodes"]
    assert "SYSTEM_STABILITY_GATE_FAILED" not in quality["reasonCodes"]


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
