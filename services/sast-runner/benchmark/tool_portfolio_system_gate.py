from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.scanner.orchestrator import ALL_TOOLS
from benchmark.tool_portfolio_corpus_readiness import READINESS_REASON_CODE_ALLOWLIST

SYSTEM_STABILITY_GATE_SCHEMA_VERSION = "s4-tool-portfolio-system-stability-gate-v1"
QUALITY_GATE_SCHEMA_VERSION = "s4-tool-portfolio-quality-gate-v1"
CANONICAL_SPLITS = {"validation", "test", "canary"}
SYSTEM_STABILITY_TOP_LEVEL_REASON_CODE_ALLOWLIST = {
    "HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS",
    "REQUIRED_TOOL_EXECUTION_INCOMPLETE",
    "REQUIRED_TOOL_INCOMPLETE",
    "REQUIRED_TOOL_UNAVAILABLE",
    "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED",
    "SYSTEM_STABILITY_GATE_FAILED",
    "SYSTEM_STABILITY_GATE_INPUT_INVALID",
    "SYSTEM_STABILITY_GATE_INCONSISTENT",
    "SYSTEM_STABILITY_GATE_NOT_RUN",
}
SYSTEM_STABILITY_FAILURE_REASON_CODE_ALLOWLIST = {
    "REQUIRED_TOOL_UNKNOWN",
    "SYSTEM_STABILITY_GATE_INCONSISTENT",
    "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED",
    "TOOL_RESULT_NOT_RECORDED",
    "TOOL_UNAVAILABLE",
    "blocked-by-required-tool-preflight-failure",
    "environment-drift",
    "not-found",
    "operator-requested-subset",
    "parse-error",
    "profile-not-applicable",
    "required-tool-unavailable",
    "runner-error",
    "runtime-tool-missing",
    "tool-check-failed",
    "tool-degraded",
    "tool-failed",
    "tool-partial",
    "tool-skipped",
    "tool-status-unknown",
}
SYSTEM_STABILITY_FAILURE_STATUS_VALUES = {"ok", "partial", "failed", "skipped", "missing", "not_run", "unknown"}
SYSTEM_STABILITY_DEGRADE_REASON_ALLOWLIST = {
    "bad-output",
    "comparative-fixture-degraded",
    "failed-files",
    "oracle-degraded",
    "recovered-nonfatal-warning",
    "test-degraded",
    "timed-out-files",
    "timeout-floor",
}
_MISSING = object()

def build_system_stability_gate(
    *,
    required_tools: Sequence[str],
    tool_availability: Mapping[str, Mapping[str, Any]] | None,
    tool_results: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Build a fail-closed system-stability gate independent of quality scoring.

    This gate answers only whether a run is trustworthy enough to enter oracle
    quality scoring. It does not compute TP/FP/FN and does not rank tools.
    """

    required = _normalize_required_tools(required_tools)
    availability = tool_availability or {}
    preflight_failures = []
    if not required:
        preflight_failures.append({
            "toolId": None,
            "phase": "preflight",
            "reasonCode": "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED",
        })
    unknown_tools = [tool for tool in required if tool not in ALL_TOOLS]
    for tool in unknown_tools:
        preflight_failures.append({
            "toolId": tool,
            "phase": "preflight",
            "reasonCode": "REQUIRED_TOOL_UNKNOWN",
        })
    for tool in required:
        if tool in unknown_tools:
            continue
        info = availability.get(tool, {})
        if info.get("available") is True:
            continue
        preflight_failures.append(_unavailable_tool_preflight_failure(tool, info))

    execution_failures = []
    if tool_results is not None:
        for tool in required:
            if tool in unknown_tools:
                continue
            result = _as_mapping(tool_results.get(tool) if isinstance(tool_results, Mapping) else None)
            if result is None:
                execution_failures.append({
                    "toolId": tool,
                    "phase": "executionCompleteness",
                    "status": "missing",
                    "reasonCode": "TOOL_RESULT_NOT_RECORDED",
                })
                continue
            status = _sanitize_execution_status(_first_present(result, "status"))
            degraded = bool(_first_present(result, "degraded") or False)
            degrade_reasons = _sanitize_degrade_reasons(_first_present(result, "degradeReasons", "degrade_reasons"))
            if status != "ok" or degraded:
                execution_failures.append({
                    "toolId": tool,
                    "phase": "executionCompleteness",
                    "status": status,
                    "reasonCode": _sanitize_execution_reason(
                        _first_present(result, "skipReason", "skip_reason"),
                        status=status,
                        degraded=degraded,
                    ),
                    "degradeReasons": degrade_reasons,
                    "timedOutFiles": _sanitize_failure_count(_first_present(result, "timedOutFiles", "timed_out_files")),
                    "failedFiles": _sanitize_failure_count(_first_present(result, "failedFiles", "failed_files")),
                })

    reason_codes = []
    if any(failure.get("reasonCode") == "SYSTEM_REQUIRED_TOOLS_NOT_DECLARED" for failure in preflight_failures):
        reason_codes.append("SYSTEM_REQUIRED_TOOLS_NOT_DECLARED")
    if preflight_failures and required:
        reason_codes.append("REQUIRED_TOOL_UNAVAILABLE")
    if execution_failures:
        reason_codes.append("REQUIRED_TOOL_INCOMPLETE")

    status = "fail" if reason_codes else "pass"
    return {
        "schemaVersion": SYSTEM_STABILITY_GATE_SCHEMA_VERSION,
        "status": status,
        "requiredTools": required,
        "qualityGateAllowed": status == "pass",
        "reasonCodes": reason_codes,
        "phases": {
            "preflight": {
                "status": "fail" if preflight_failures else "pass",
                "failures": preflight_failures,
            },
            "executionCompleteness": {
                "status": "fail" if execution_failures else "pass",
                "failures": execution_failures,
            },
        },
    }


def build_quality_gate(
    *,
    system_stability_gate: Mapping[str, Any] | None,
    external_corpus_status: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Build quality gate state after system-stability eligibility is known."""

    reason_codes = _external_corpus_reason_codes(external_corpus_status)
    if system_stability_gate is None:
        reason_codes = sorted({"SYSTEM_STABILITY_GATE_NOT_RUN", *reason_codes})
        return {
            "schemaVersion": QUALITY_GATE_SCHEMA_VERSION,
            "status": "not_decision_grade",
            "decision": "insufficient-evidence-for-tool-change",
            "blockedBy": [],
            "reasonCodes": reason_codes,
            "consumerPolicy": "quality_metrics_are_harness_or_prerequisite_only",
        }

    status = system_stability_gate.get("status")
    quality_gate_allowed = system_stability_gate.get("qualityGateAllowed")
    system_gate_failure_reason = _system_gate_quality_eligibility_failure_reason(
        status=status,
        quality_gate_allowed=quality_gate_allowed,
    )
    if system_gate_failure_reason is not None:
        system_reason_codes = _sanitize_reason_codes(
            system_stability_gate.get("reasonCodes", _MISSING),
            allowed=SYSTEM_STABILITY_TOP_LEVEL_REASON_CODE_ALLOWLIST,
            invalid_reason="SYSTEM_STABILITY_GATE_INPUT_INVALID",
        )
        return {
            "schemaVersion": QUALITY_GATE_SCHEMA_VERSION,
            "status": "blocked",
            "decision": "invalid-precondition",
            "blockedBy": ["systemStabilityGate"],
            "reasonCodes": sorted({
                "SYSTEM_STABILITY_GATE_FAILED",
                system_gate_failure_reason,
                *system_reason_codes,
            }),
            "consumerPolicy": "do_not_score_quality_when_system_gate_failed",
        }

    if status == "not_run":
        reason_codes = sorted({"SYSTEM_STABILITY_GATE_NOT_RUN", *reason_codes})
        return {
            "schemaVersion": QUALITY_GATE_SCHEMA_VERSION,
            "status": "not_decision_grade",
            "decision": "insufficient-evidence-for-tool-change",
            "blockedBy": [],
            "reasonCodes": reason_codes,
            "consumerPolicy": "quality_metrics_are_harness_or_prerequisite_only",
        }

    if reason_codes:
        return {
            "schemaVersion": QUALITY_GATE_SCHEMA_VERSION,
            "status": "not_decision_grade",
            "decision": "insufficient-evidence-for-tool-change",
            "blockedBy": [],
            "reasonCodes": reason_codes,
            "consumerPolicy": "quality_metrics_are_harness_or_prerequisite_only",
        }

    return {
        "schemaVersion": QUALITY_GATE_SCHEMA_VERSION,
        "status": "eligible",
        "decision": "insufficient-evidence-for-tool-change",
        "blockedBy": [],
        "reasonCodes": [],
        "consumerPolicy": "quality_metrics_may_be_scored",
    }


def default_not_run_system_gate() -> dict[str, Any]:
    """Default gate for precomputed harness reports that do not execute tools."""
    return {
        "schemaVersion": SYSTEM_STABILITY_GATE_SCHEMA_VERSION,
        "status": "not_run",
        "requiredTools": list(ALL_TOOLS),
        "qualityGateAllowed": False,
        "reasonCodes": ["HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS"],
        "phases": {
            "preflight": {"status": "not_run", "failures": []},
            "executionCompleteness": {"status": "not_run", "failures": []},
        },
    }


def blocked_metric_bucket(split: str, reason_codes: Sequence[str]) -> dict[str, Any]:
    return {
        "status": "blocked",
        "split": _sanitize_split(split),
        "reasonCodes": _sanitize_reason_codes(
            reason_codes,
            allowed=SYSTEM_STABILITY_TOP_LEVEL_REASON_CODE_ALLOWLIST,
            invalid_reason="SYSTEM_STABILITY_GATE_INPUT_INVALID",
        ),
        "byConfig": {},
    }


def _sanitize_split(value: Any) -> str:
    if not isinstance(value, str):
        return "<invalid>"
    split = value.strip()
    return split if split in CANONICAL_SPLITS else "<invalid>"


def _unavailable_tool_preflight_failure(tool: str, info: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "toolId": tool,
        "phase": "preflight",
        "reasonCode": _sanitize_preflight_probe_reason(info.get("probeReason")),
        "versionStatus": _version_status(info.get("version")),
        "expectedExecutablePathStatus": _expected_executable_path_status(info.get("expectedExecutablePath")),
    }


def _sanitize_preflight_probe_reason(value: Any) -> str:
    if not isinstance(value, str):
        return "runtime-tool-missing"
    reason = value.strip()
    if reason in SYSTEM_STABILITY_FAILURE_REASON_CODE_ALLOWLIST:
        return reason
    return "runtime-tool-missing"


def _sanitize_execution_status(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    status = value.strip()
    return status if status in SYSTEM_STABILITY_FAILURE_STATUS_VALUES else "unknown"


def _sanitize_execution_reason(value: Any, *, status: str, degraded: bool) -> str:
    if isinstance(value, str):
        reason = value.strip()
        if reason in SYSTEM_STABILITY_FAILURE_REASON_CODE_ALLOWLIST:
            return reason
    return _status_reason(status, degraded)


def _sanitize_degrade_reasons(value: Any) -> list[str]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return []
    reasons: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        reason = item.strip()
        if reason and reason in SYSTEM_STABILITY_DEGRADE_REASON_ALLOWLIST and reason not in reasons:
            reasons.append(reason)
    return reasons


def _sanitize_failure_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _version_status(value: Any) -> str:
    return "present" if isinstance(value, str) and bool(value.strip()) else "missing"


def _expected_executable_path_status(value: Any) -> str:
    return "redacted" if isinstance(value, str) and bool(value.strip()) else "not-configured"


def _external_corpus_reason_codes(external_corpus_status: Mapping[str, Any] | None) -> list[str]:
    reason_codes: list[str] = []
    for status in (external_corpus_status or {}).values():
        if not isinstance(status, Mapping):
            continue
        if status.get("status") in {"blocked", "not_run"}:
            reason_codes.extend(_sanitize_reason_codes(
                status.get("reasonCodes", _MISSING),
                allowed=READINESS_REASON_CODE_ALLOWLIST,
                invalid_reason="CORPUS_READINESS_GATE_INPUT_INVALID",
            ))
    return sorted(set(reason_codes))


def _sanitize_reason_codes(
    value: Any,
    *,
    allowed: set[str],
    invalid_reason: str,
) -> list[str]:
    if value is _MISSING:
        return []
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return [invalid_reason]

    reason_codes: set[str] = set()
    invalid = False
    for reason in value:
        if not isinstance(reason, str) or not reason.strip() or reason not in allowed:
            invalid = True
            continue
        reason_codes.add(reason)
    if invalid:
        reason_codes.add(invalid_reason)
    return sorted(reason_codes)


def _system_gate_quality_eligibility_failure_reason(
    *,
    status: Any,
    quality_gate_allowed: Any,
) -> str | None:
    if status == "fail":
        return "SYSTEM_STABILITY_GATE_FAILED"
    if status == "not_run" and quality_gate_allowed is False:
        return None
    if status == "pass" and quality_gate_allowed is True:
        return None
    if status == "pass" and quality_gate_allowed is False:
        return "SYSTEM_STABILITY_GATE_INCONSISTENT"
    if status == "pass":
        return "SYSTEM_STABILITY_GATE_INPUT_INVALID"
    if not isinstance(status, str) or not status.strip() or status == "unknown":
        return "SYSTEM_STABILITY_GATE_INPUT_INVALID"
    if quality_gate_allowed is True:
        return "SYSTEM_STABILITY_GATE_INCONSISTENT"
    return "SYSTEM_STABILITY_GATE_INPUT_INVALID"


def _status_reason(status: str, degraded: bool) -> str:
    if status == "partial":
        return "tool-partial"
    if status == "failed":
        return "tool-failed"
    if status == "skipped":
        return "tool-skipped"
    if degraded:
        return "tool-degraded"
    return "tool-status-unknown"


def _first_present(mapping: Mapping[str, Any], *keys: str) -> Any | None:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _as_mapping(value: Any | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items() if item is not None}
    return None


def _normalize_required_tools(required_tools: Sequence[str]) -> list[str]:
    if isinstance(required_tools, (str, bytes, bytearray)) or not isinstance(required_tools, Sequence):
        return ["<invalid>"]

    seen_known: set[str] = set()
    has_invalid = False
    for tool in required_tools:
        if not isinstance(tool, str):
            has_invalid = True
            continue
        normalized = tool.strip()
        if normalized in ALL_TOOLS:
            seen_known.add(normalized)
            continue
        has_invalid = True

    known = [tool for tool in ALL_TOOLS if tool in seen_known]
    if has_invalid:
        known.append("<invalid>")
    return known
