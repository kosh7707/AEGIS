from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.scanner.orchestrator import ALL_TOOLS

SYSTEM_STABILITY_GATE_SCHEMA_VERSION = "s4-tool-portfolio-system-stability-gate-v1"
QUALITY_GATE_SCHEMA_VERSION = "s4-tool-portfolio-quality-gate-v1"

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

    required = list(required_tools)
    availability = tool_availability or {}
    preflight_failures = []
    for tool in required:
        info = availability.get(tool, {})
        if info.get("available") is True:
            continue
        preflight_failures.append({
            "toolId": tool,
            "phase": "preflight",
            "reasonCode": info.get("probeReason") or "runtime-tool-missing",
            "version": info.get("version"),
            "expectedExecutablePath": info.get("expectedExecutablePath"),
        })

    execution_failures = []
    if tool_results is not None:
        for tool in required:
            result = _as_mapping(tool_results.get(tool) if isinstance(tool_results, Mapping) else None)
            if result is None:
                execution_failures.append({
                    "toolId": tool,
                    "phase": "executionCompleteness",
                    "status": "missing",
                    "reasonCode": "TOOL_RESULT_NOT_RECORDED",
                })
                continue
            status = str(_first_present(result, "status") or "unknown")
            degraded = bool(_first_present(result, "degraded") or False)
            degrade_reasons = list(_first_present(result, "degradeReasons", "degrade_reasons") or [])
            if status != "ok" or degraded:
                execution_failures.append({
                    "toolId": tool,
                    "phase": "executionCompleteness",
                    "status": status,
                    "reasonCode": _first_present(result, "skipReason", "skip_reason") or _status_reason(status, degraded),
                    "degradeReasons": degrade_reasons,
                    "timedOutFiles": _first_present(result, "timedOutFiles", "timed_out_files"),
                    "failedFiles": _first_present(result, "failedFiles", "failed_files"),
                })

    reason_codes = []
    if preflight_failures:
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

    if system_stability_gate and system_stability_gate.get("status") == "fail":
        return {
            "schemaVersion": QUALITY_GATE_SCHEMA_VERSION,
            "status": "blocked",
            "decision": "invalid-precondition",
            "blockedBy": ["systemStabilityGate"],
            "reasonCodes": ["SYSTEM_STABILITY_GATE_FAILED"],
            "consumerPolicy": "do_not_score_quality_when_system_gate_failed",
        }

    reason_codes = _external_corpus_reason_codes(external_corpus_status)
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
        "qualityGateAllowed": True,
        "reasonCodes": ["HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS"],
        "phases": {
            "preflight": {"status": "not_run", "failures": []},
            "executionCompleteness": {"status": "not_run", "failures": []},
        },
    }


def blocked_metric_bucket(split: str, reason_codes: Sequence[str]) -> dict[str, Any]:
    return {
        "status": "blocked",
        "split": split,
        "reasonCodes": list(reason_codes),
        "byConfig": {},
    }


def _external_corpus_reason_codes(external_corpus_status: Mapping[str, Any] | None) -> list[str]:
    reason_codes: list[str] = []
    for status in (external_corpus_status or {}).values():
        if not isinstance(status, Mapping):
            continue
        if status.get("status") in {"blocked", "not_run"}:
            reason_codes.extend(str(reason) for reason in status.get("reasonCodes") or [])
    return sorted(set(reason_codes))


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
