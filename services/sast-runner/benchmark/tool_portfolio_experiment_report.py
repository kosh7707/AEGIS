from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.response import SastFinding
from benchmark.benchmark_slice_report import build_default_benchmark_slice_report
from benchmark.tool_portfolio_acquisition_manifest import build_acquisition_index
from benchmark.tool_portfolio_corpus_readiness import (
    CASE_RESOLVED_PATH_STATUS_VALUES,
    CORPUS_READINESS_GATE_SCHEMA_VERSION,
    LOCAL_PATH_STATUS_VALUES,
    READINESS_STATUS_VALUES,
    READINESS_REASON_CODE_ALLOWLIST,
    RESOLVED_LOCAL_PATH_STATUS_VALUES,
    SOURCE_PATH_STATUS_VALUES,
    build_corpus_readiness_gate,
    default_not_run_corpus_readiness_gate,
    external_corpus_status_from_readiness,
)
from benchmark.tool_portfolio_decision_cycle import build_decision_cycle_lock, checksum_json
from benchmark.tool_portfolio_experiment_manifest import (
    SLICE_KINDS,
    SPLITS,
    corpus_targets,
    required_current_six_configs,
    validate_corpus_manifest,
    validate_tool_set_config,
)
from benchmark.tool_portfolio_oracle_matcher import MATCHING_POLICY_SCHEMA_VERSION, finding_to_evidence, score_targets
from benchmark.tool_portfolio_system_gate import (
    SYSTEM_STABILITY_GATE_SCHEMA_VERSION,
    blocked_metric_bucket,
    build_quality_gate,
    default_not_run_system_gate,
)

EXPERIMENT_REPORT_SCHEMA_VERSION = "s4-tool-portfolio-experiment-report-v1"
QUALITY_DIAGNOSTICS_SCHEMA_VERSION = "s4-tool-portfolio-quality-diagnostics-v1"
TOOL_CONTRIBUTION_DIAGNOSTICS_SCHEMA_VERSION = "s4-tool-portfolio-tool-contribution-diagnostics-v1"
FORBIDDEN_VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}
CANONICAL_SPLIT_ORDER = ["validation", "test", "canary"]
QUALITY_THRESHOLD_FIELDS = ["minimumTargetRecall", "minimumFindingPrecision", "maximumNegativeTargetFpr"]
QUALITY_THRESHOLD_CONFIG_FIELDS = [*QUALITY_THRESHOLD_FIELDS, "requiredSplits", "primaryToolSetConfig"]
QUALITY_THRESHOLD_CONFIG_FIELD_SET = set(QUALITY_THRESHOLD_CONFIG_FIELDS)
QUALITY_REQUIRED_SPLITS_INVALID_REASON = "QUALITY_REQUIRED_SPLITS_INVALID"
QUALITY_THRESHOLDS_NON_DISCRIMINATING_REASON = "QUALITY_THRESHOLDS_NON_DISCRIMINATING"
TOOL_CONTRIBUTION_COMPARATIVE_INCOMPLETE_REASON = "TOOL_CONTRIBUTION_COMPARATIVE_CONFIG_INCOMPLETE"
TARGET_OUTCOME_MATCH_CLASSES = [
    "exact-target-match",
    "strong-related-match",
    "weak-related-match",
    "wrong-cwe-target-location",
    "off-target-finding",
    "negative-case-finding",
    "missed-target",
]
TRIAGE_REASON_RECALL = "RECALL_GAP_PRESENT"
TRIAGE_REASON_NOISE = "NOISE_PRESSURE_PRESENT"
TRIAGE_REASON_WRONG_CWE = "WRONG_CWE_MATCHES_PRESENT"
TRIAGE_REASON_WEAK_RELATED = "WEAK_RELATED_MATCHES_PRESENT"
TRIAGE_REASON_NEGATIVE_VIOLATION = "NEGATIVE_TARGET_VIOLATIONS_PRESENT"
TOOL_CONTRIBUTION_REASON_UNIQUE = "UNIQUE_POSITIVE_CONTRIBUTION_PRESENT"
TOOL_CONTRIBUTION_REASON_OVERLAP = "OVERLAP_POSITIVE_CONTRIBUTION_PRESENT"
TOOL_CONTRIBUTION_REASON_NOISE_ONLY = "NOISE_WITHOUT_POSITIVE_CONTRIBUTION_PRESENT"
TOOL_CONTRIBUTION_REASON_NO_SIGNAL = "NO_OBSERVED_SIGNAL"
MATCHING_POLICY_DEFAULT_LINE_WINDOW = 5
MATCHING_POLICY_MAX_LINE_WINDOW = 25
MATCHING_POLICY_ALLOWED_KEYS = {"schemaVersion", "lineWindowDefault", "functionFallbackDefault"}
LEGACY_EXTERNAL_CORPUS_STATUS_ALLOWED_KEYS = {"status", "reasonCodes", "acquisitionIds"}
LEGACY_EXTERNAL_CORPUS_STATUS_RESERVED_KEYS = {"requiredCorpusReadiness"}
LEGACY_EXTERNAL_CORPUS_STATUS_VALUES = {"available", "blocked", "not_run"}
REPORT_IDENTITY_REASON_CODE = "REPORT_IDENTITY_INPUT_INVALID"
REPORT_IDENTITY_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
REPORT_IDENTITY_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
REPORT_PHASE_VALUES = {"validation", "test", "canary"}
READINESS_REQUIRED_CORPUS_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
READINESS_SHA256_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
CORPUS_READINESS_GATE_ALLOWED_KEYS = {
    "schemaVersion",
    "status",
    "decisionGradeReady",
    "requiredCorpora",
    "reasonCodes",
    "acquisitionStatuses",
    "caseStatuses",
    "externalCorpusStatus",
    "summary",
    "consumerPolicy",
    "requiredCorpusInputValidation",
    "consistencyChecks",
}
CORPUS_READINESS_GATE_FORBIDDEN_CALLER_KEYS = {"inputValidation"}
CORPUS_READINESS_CONSUMER_POLICY_VALUES = {
    "local_filesystem_readiness_only_not_quality_or_security_verdict",
    "no_decision_grade_corpus_readiness_claim",
    "invalid_input_no_decision_grade_corpus_readiness_claim",
    "output_write_failed_no_decision_grade_corpus_readiness_claim",
}
CORPUS_READINESS_ACQUISITION_STATUS_ALLOWED_KEYS = {
    "status",
    "acquisitionId",
    "corpusName",
    "localPathStatus",
    "resolvedLocalPathStatus",
    "manifestChecksum",
    "reasonCodes",
    "caseCount",
    "splitCounts",
}
CORPUS_READINESS_CASE_STATUS_ALLOWED_KEYS = {
    "status",
    "acquisitionId",
    "caseId",
    "sourcePath",
    "sourcePathStatus",
    "resolvedPathStatus",
    "expectedChecksum",
    "actualChecksum",
    "checksum",
    "reasonCodes",
}
CORPUS_READINESS_SUMMARY_ALLOWED_KEYS = {
    "caseCount",
    "checkedCaseCount",
    "splitCounts",
    "sliceCounts",
}
CORPUS_READINESS_REQUIRED_CORPUS_INPUT_VALIDATION_ALLOWED_KEYS = {
    "status",
    "reasonCodes",
    "failures",
}
CORPUS_READINESS_REQUIRED_CORPUS_INPUT_FAILURE_ALLOWED_KEYS = {
    "index",
    "category",
}
CORPUS_READINESS_REQUIRED_CORPUS_INPUT_FAILURE_CATEGORIES = {
    "invalid-container",
    "non_string",
    "invalid_string",
}
CORPUS_READINESS_CONSISTENCY_CHECKS_ALLOWED_KEYS = {"status", "failures"}
CORPUS_READINESS_CONSISTENCY_FAILURE_ALLOWED_KEYS = {
    "reasonCode",
    "observedStatus",
    "observedDecisionGradeReady",
    "externalCorpusStatusAvailableOnly",
}
SYSTEM_STABILITY_GATE_ALLOWED_KEYS = {
    "schemaVersion",
    "status",
    "requiredTools",
    "qualityGateAllowed",
    "reasonCodes",
    "phases",
}
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
SYSTEM_STABILITY_PHASE_NAMES = {"preflight", "executionCompleteness", "gateConsistency"}
SYSTEM_STABILITY_REQUIRED_PASS_PHASES = ("preflight", "executionCompleteness")
SYSTEM_STABILITY_PHASE_ALLOWED_KEYS = {"status", "failures"}
SYSTEM_STABILITY_PHASE_STATUS_VALUES = {"pass", "fail", "not_run"}
SYSTEM_STABILITY_FAILURE_ALLOWED_KEYS = {
    "toolId",
    "phase",
    "reasonCode",
    "status",
    "degradeReasons",
    "timedOutFiles",
    "failedFiles",
    "version",
    "versionStatus",
    "expectedExecutablePath",
    "expectedExecutablePathStatus",
    "observedStatus",
    "observedQualityGateAllowed",
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


def build_experiment_report(
    *,
    run_id: str,
    created_at: str,
    phase: str,
    corpus_manifest: Mapping[str, Any],
    acquisition_manifests: Sequence[Mapping[str, Any]],
    findings_by_config: Any,
    matching_policy: Any,
    thresholds: Any,
    external_corpus_status: Any = None,
    corpus_readiness_gate: Any = None,
    required_corpora: Sequence[str] | None = None,
    corpus_readiness_base_path: Path | str | None = None,
    system_stability: Any = None,
    tool_contribution_completeness: Any = None,
    repo_root: Path | str | None = None,
) -> dict[str, Any]:
    report_identity = _normalize_report_identity(run_id=run_id, created_at=created_at, phase=phase)
    report_identity_failures = report_identity.get("failures", [])
    report_identity_invalid = bool(report_identity_failures)
    safe_run_id = str(report_identity["runId"])
    safe_created_at = str(report_identity["createdAt"])
    safe_phase = str(report_identity["phase"])

    acquisition_index = build_acquisition_index(acquisition_manifests)
    corpus_report = validate_corpus_manifest(corpus_manifest, acquisition_index=acquisition_index)
    required_configs = required_current_six_configs()
    for config in required_configs:
        validate_tool_set_config(config)
    system_stability_gate = _normalize_system_stability_gate(
        default_not_run_system_gate() if system_stability is None else system_stability
    )
    if corpus_readiness_gate is None and required_corpora is not None:
        corpus_readiness_gate = build_corpus_readiness_gate(
            acquisition_manifests=acquisition_manifests,
            corpus_manifest=corpus_manifest,
            required_corpora=required_corpora,
            base_path=corpus_readiness_base_path,
        )
    corpus_readiness_gate = _normalize_corpus_readiness_gate(
        default_not_run_corpus_readiness_gate() if corpus_readiness_gate is None else corpus_readiness_gate
    )
    readiness_external_corpus_status = external_corpus_status_from_readiness(corpus_readiness_gate)
    effective_external_corpus_status, legacy_external_corpus_status_failures = _merge_external_corpus_status(
        explicit_status=external_corpus_status,
        readiness_status=readiness_external_corpus_status,
    )
    prerequisite_quality_gate = build_quality_gate(
        system_stability_gate=system_stability_gate,
        external_corpus_status=readiness_external_corpus_status,
    )
    system_gate_failed = system_stability_gate.get("status") == "fail"
    matching_policy, invalid_matching_policy_payload = _normalize_matching_policy(matching_policy)
    matching_policy_invalid = invalid_matching_policy_payload is not None
    findings_by_config, invalid_findings_payload = _normalize_findings_by_config(
        findings_by_config,
        required_configs=required_configs,
    )
    findings_by_config_invalid = invalid_findings_payload is not None
    missing_configs = sorted(set(required_configs) - set(findings_by_config))
    if missing_configs and not system_gate_failed and not matching_policy_invalid and not findings_by_config_invalid:
        raise ValueError(f"missing current-six experiment configs: {missing_configs}")

    targets = corpus_targets(corpus_manifest)
    split_targets = _targets_by_split(targets)
    split_assignments = {split: [target["targetId"] for target in items] for split, items in sorted(split_targets.items())}
    invalid_threshold_payload_for_lock = _invalid_threshold_payload_diagnostic(thresholds)
    decision_cycle = build_decision_cycle_lock(
        decision_cycle_id=f"{safe_run_id}-cycle",
        phase=safe_phase,
        corpus_manifest=corpus_manifest,
        matching_policy=matching_policy,
        thresholds=_thresholds_checksum_input(
            thresholds,
            invalid_threshold_payload=invalid_threshold_payload_for_lock,
        ),
        split_assignments=split_assignments,
        rulesets={"current-six": required_configs},
        tool_versions={tool: "not-recorded-fixture" for tool in ALL_TOOLS},
        tool_paths={tool: "not-recorded-fixture" for tool in ALL_TOOLS},
        timeout_config={"timeoutSeconds": "not-run-fixture"},
        environment_summary={"executionMode": "s4-harness-fixture"},
        lockfile={"corpusManifestChecksum": checksum_json(corpus_manifest)},
    )

    by_config_by_split: dict[str, dict[str, Any]] = {"validation": {}, "test": {}, "canary": {}}
    all_config_scores: dict[str, dict[str, Any]] = {}
    local_input_invalid_reason = (
        REPORT_IDENTITY_REASON_CODE if report_identity_invalid
        else "ORACLE_MATCHING_POLICY_INPUT_INVALID" if matching_policy_invalid
        else "FINDINGS_BY_CONFIG_INPUT_INVALID" if findings_by_config_invalid
        else None
    )
    if not system_gate_failed and local_input_invalid_reason is None:
        for config in required_configs:
            config_findings = list(findings_by_config.get(config, []))
            all_config_scores[config] = score_targets(targets, config_findings, tool_set_config=config, matching_policy=matching_policy)
            for split, split_items in split_targets.items():
                split_findings = _filter_findings_to_targets(config_findings, split_items)
                by_config_by_split.setdefault(split, {})[config] = score_targets(split_items, split_findings, tool_set_config=config, matching_policy=matching_policy)

    validation_metrics = (
        blocked_metric_bucket("validation", list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]))
        if system_gate_failed else _not_run_metric_bucket("validation", [local_input_invalid_reason])
        if local_input_invalid_reason is not None else _split_bucket("validation", by_config_by_split.get("validation", {}))
    )
    test_metrics = (
        blocked_metric_bucket("test", list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]))
        if system_gate_failed else _not_run_metric_bucket("test", [local_input_invalid_reason])
        if local_input_invalid_reason is not None else _split_bucket("test", by_config_by_split.get("test", {}))
    )
    canary_metrics = (
        blocked_metric_bucket("canary", list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]))
        if system_gate_failed else _not_run_metric_bucket("canary", [local_input_invalid_reason])
        if local_input_invalid_reason is not None else _split_bucket("canary", by_config_by_split.get("canary", {}))
    )
    split_metric_buckets = {
        "validation": validation_metrics,
        "test": test_metrics,
        "canary": canary_metrics,
    }
    local_quality_assessment = _local_quality_assessment(
        split_metric_buckets,
        thresholds,
        blocked=system_gate_failed,
        blocked_reason_codes=list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]),
        invalid_report_identity_failures=report_identity_failures if report_identity_invalid else None,
        invalid_matching_policy_payload=invalid_matching_policy_payload,
        invalid_findings_by_config_payload=invalid_findings_payload,
    )
    quality_gate = _compose_quality_gate(
        prerequisite_quality_gate,
        local_quality_assessment,
    )
    blocked_reasons = list(quality_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"])
    decision_support = {
        "currentDecision": quality_gate.get("decision", "insufficient-evidence-for-tool-change"),
        "reasonCodes": list(quality_gate.get("reasonCodes") or []),
        "removeCandidates": [],
        "upgradeCandidates": [],
        "addCandidates": [],
        "futureCandidateActionsRequireWr": True,
        "externalCorpusStatus": effective_external_corpus_status,
        "requiredFollowUps": _required_followups(readiness_external_corpus_status),
    }
    if legacy_external_corpus_status_failures:
        decision_support["legacyExternalCorpusStatusInputValidation"] = {
            "status": "fail",
            "failures": legacy_external_corpus_status_failures,
        }
    quality_diagnostics = _quality_diagnostics(
        split_metric_buckets=split_metric_buckets,
        findings_by_config=findings_by_config,
        split_targets=split_targets,
        primary_config=str(local_quality_assessment.get("primaryToolSetConfig") or "full-current-six"),
        system_gate_failed=system_gate_failed,
        system_reason_codes=list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]),
        local_input_invalid_reason=local_input_invalid_reason,
    )
    portfolio_metrics = (
        {"status": "blocked", "reasonCodes": blocked_reasons}
        if system_gate_failed else {"status": "blocked", "reasonCodes": [local_input_invalid_reason]}
        if local_input_invalid_reason is not None else _portfolio_metrics(all_config_scores, findings_by_config)
    )
    tool_contribution_diagnostics = _tool_contribution_diagnostics(
        all_config_scores=all_config_scores,
        split_targets=split_targets,
        portfolio_metrics=portfolio_metrics,
        primary_config=str(local_quality_assessment.get("primaryToolSetConfig") or "full-current-six"),
        system_gate_failed=system_gate_failed,
        system_reason_codes=list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]),
        local_input_invalid_reason=local_input_invalid_reason,
        comparative_completeness=tool_contribution_completeness,
    )

    report = {
        "schemaVersion": EXPERIMENT_REPORT_SCHEMA_VERSION,
        "runId": safe_run_id,
        "createdAt": safe_created_at,
        "producer": {"service": "s4-sast-runner", "deterministic": True},
        "decisionCycle": decision_cycle,
        "corpusManifest": {
            "schemaVersion": corpus_manifest.get("schemaVersion"),
            "checksum": checksum_json(corpus_manifest),
            "caseCount": corpus_report["caseCount"],
            "splitCounts": corpus_report["splitCounts"],
        },
        "matchingPolicy": matching_policy,
        "toolSetConfigs": required_configs,
        "systemStabilityGate": system_stability_gate,
        "corpusReadinessGate": corpus_readiness_gate,
        "qualityGate": quality_gate,
        "validationMetrics": validation_metrics,
        "testMetrics": test_metrics,
        "canaryMetrics": canary_metrics,
        "parserCompatibility": {"status": "not_run", "reasonCodes": ["PARSER_COMPATIBILITY_CONSUMED_AS_PREREQUISITE_GATE"]},
        "runtimeStability": _runtime_stability_bucket(system_stability_gate),
        "claimBoundaryImpact": {
            "status": "pass",
            "consumerPolicy": "empty_or_missing_s4_evidence_is_not_negative_security_evidence",
        },
        "portfolioMetrics": portfolio_metrics,
        "qualityDiagnostics": quality_diagnostics,
        "toolContributionDiagnostics": tool_contribution_diagnostics,
        "benchmarkSliceEvidence": _historical_benchmark_evidence(repo_root),
        "decisionSupport": decision_support,
    }
    if report_identity_invalid:
        report["reportIdentityValidation"] = {
            "status": "fail",
            "reasonCodes": [REPORT_IDENTITY_REASON_CODE],
            "failures": report_identity_failures,
        }
    _reject_forbidden_keys(report)
    return report


def write_experiment_report(report: Mapping[str, Any], path: Path | str) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return output


def _normalize_report_identity(*, run_id: Any, created_at: Any, phase: Any) -> dict[str, Any]:
    failures: list[dict[str, str]] = []
    safe_run_id = run_id
    safe_created_at = created_at
    safe_phase = phase

    run_id_failure = _run_id_input_diagnostic(run_id)
    if run_id_failure is not None:
        failures.append(run_id_failure)
        safe_run_id = "invalid-run-id"
    else:
        safe_run_id = str(run_id)

    created_at_failure = _created_at_input_diagnostic(created_at)
    if created_at_failure is not None:
        failures.append(created_at_failure)
        safe_created_at = "invalid-created-at"
    else:
        safe_created_at = str(created_at)

    phase_failure = _phase_input_diagnostic(phase)
    if phase_failure is not None:
        failures.append(phase_failure)
        safe_phase = "validation"
    else:
        safe_phase = str(phase)

    return {
        "runId": safe_run_id,
        "createdAt": safe_created_at,
        "phase": safe_phase,
        "failures": failures,
    }


def _run_id_input_diagnostic(run_id: Any) -> dict[str, str] | None:
    if not isinstance(run_id, str):
        return {"category": "invalid-field", "field": "runId", "type": type(run_id).__name__}
    if not run_id.strip():
        return {"category": "blank", "field": "runId"}
    if not REPORT_IDENTITY_SAFE_RUN_ID.match(run_id):
        return {"category": "invalid-format", "field": "runId", "reason": "safe-identifier-required"}
    return None


def _created_at_input_diagnostic(created_at: Any) -> dict[str, str] | None:
    if not isinstance(created_at, str):
        return {"category": "invalid-field", "field": "createdAt", "type": type(created_at).__name__}
    if not REPORT_IDENTITY_TIMESTAMP.match(created_at):
        return {"category": "invalid-format", "field": "createdAt", "reason": "rfc3339-utc-seconds-required"}
    try:
        datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return {"category": "invalid-date", "field": "createdAt", "reason": "nonexistent-date"}
    return None


def _phase_input_diagnostic(phase: Any) -> dict[str, str] | None:
    if not isinstance(phase, str):
        return {"category": "invalid-field", "field": "phase", "type": type(phase).__name__}
    if phase not in REPORT_PHASE_VALUES:
        return {"category": "invalid-phase", "field": "phase"}
    return None


def _merge_external_corpus_status(
    *,
    explicit_status: Any,
    readiness_status: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    merged, failures = _sanitize_legacy_external_corpus_status(
        explicit_status,
        readiness_owned_keys=set(str(key) for key in readiness_status),
    )
    # Corpus readiness is authoritative for decision-grade eligibility. Legacy
    # explicit externalCorpusStatus may add context, but it must not suppress a
    # not_run/blocked readiness projection.
    merged.update({
        str(key): dict(value)
        for key, value in readiness_status.items()
        if isinstance(value, Mapping)
    })
    return merged, failures


def _sanitize_legacy_external_corpus_status(
    explicit_status: Any,
    *,
    readiness_owned_keys: set[str],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    if not isinstance(explicit_status, Mapping):
        return {}, []

    sanitized: dict[str, dict[str, Any]] = {}
    failures: list[dict[str, str]] = []
    for raw_key, raw_value in explicit_status.items():
        if not isinstance(raw_key, str):
            failures.append({"category": "invalid-key", "key": "<invalid>", "type": type(raw_key).__name__})
            continue
        key = raw_key
        if key in LEGACY_EXTERNAL_CORPUS_STATUS_RESERVED_KEYS:
            failures.append({"category": "reserved-key", "key": key})
            continue
        if key in readiness_owned_keys:
            continue
        if key in FORBIDDEN_VERDICT_KEYS:
            failures.append({"category": "forbidden-key", "key": key})
            continue
        if not isinstance(raw_value, Mapping):
            failures.append({"category": "invalid-entry", "key": "<invalid>", "type": type(raw_value).__name__})
            continue

        normalized_entry, diagnostic = _normalize_legacy_external_corpus_status_entry(key, raw_value)
        if diagnostic is not None:
            failures.append(diagnostic)
            continue
        sanitized[key] = normalized_entry

    return sanitized, failures


def _normalize_legacy_external_corpus_status_entry(
    key: str,
    entry: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str] | None]:
    diagnostic_key = "<invalid>"
    for field in entry:
        if not isinstance(field, str):
            return {}, {
                "category": "unknown-field",
                "key": diagnostic_key,
                "field": "<invalid>",
                "type": type(field).__name__,
            }
        if field not in LEGACY_EXTERNAL_CORPUS_STATUS_ALLOWED_KEYS:
            return {}, {"category": "unknown-field", "key": diagnostic_key, "field": "<invalid>"}

    if "status" not in entry:
        return {}, {"category": "missing-field", "key": diagnostic_key, "field": "status"}
    status = entry.get("status")
    if not isinstance(status, str):
        return {}, {"category": "invalid-field", "key": diagnostic_key, "field": "status", "type": type(status).__name__}
    if status not in LEGACY_EXTERNAL_CORPUS_STATUS_VALUES:
        return {}, {
            "category": "invalid-status",
            "key": diagnostic_key,
            "field": "status",
        }

    reason_codes, reason_code_diagnostic = _normalize_optional_legacy_string_sequence(
        entry.get("reasonCodes"),
        key=diagnostic_key,
        field="reasonCodes",
    )
    if reason_code_diagnostic is not None:
        return {}, reason_code_diagnostic
    acquisition_ids, acquisition_ids_diagnostic = _normalize_optional_legacy_string_sequence(
        entry.get("acquisitionIds"),
        key=diagnostic_key,
        field="acquisitionIds",
    )
    if acquisition_ids_diagnostic is not None:
        return {}, acquisition_ids_diagnostic

    normalized: dict[str, Any] = {"status": status}
    if reason_codes:
        normalized["reasonCodes"] = reason_codes
    if acquisition_ids:
        normalized["acquisitionIds"] = acquisition_ids
    return normalized, None


def _normalize_optional_legacy_string_sequence(
    value: Any,
    *,
    key: str,
    field: str,
) -> tuple[list[str], dict[str, str] | None]:
    if value is None:
        return [], None
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return [], {"category": "invalid-field", "key": key, "field": field, "type": type(value).__name__}

    normalized: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            return [], {
                "category": "invalid-sequence-item",
                "key": key,
                "field": f"{field}.{index}",
                "type": type(item).__name__,
            }
        item = item.strip()
        if not item:
            return [], {
                "category": "invalid-sequence-item",
                "key": key,
                "field": f"{field}.{index}",
                "reason": "blank",
            }
        normalized.append(item)
    return normalized, None


def _normalize_system_stability_gate(system_stability: Any) -> dict[str, Any]:
    if not isinstance(system_stability, Mapping):
        return _invalid_system_stability_gate({"category": "non-mapping", "type": type(system_stability).__name__})
    top_level_key_diagnostic = _system_stability_top_level_key_diagnostic(system_stability)
    if top_level_key_diagnostic is not None:
        return _invalid_system_stability_gate(top_level_key_diagnostic)
    gate = dict(system_stability)
    input_diagnostic = _system_stability_input_diagnostic(gate)
    if input_diagnostic is not None:
        return _invalid_system_stability_gate(input_diagnostic)
    gate = _sanitize_system_stability_gate_projection(gate)

    status = str(gate.get("status") or "unknown")
    quality_gate_allowed = gate.get("qualityGateAllowed")
    pass_gate_disallowed = status == "pass" and quality_gate_allowed is not True
    non_pass_gate_allowed = status != "pass" and quality_gate_allowed is True
    if not pass_gate_disallowed and not non_pass_gate_allowed:
        return gate

    reason_codes = list(gate.get("reasonCodes") or [])
    if "SYSTEM_STABILITY_GATE_INCONSISTENT" not in reason_codes:
        reason_codes.append("SYSTEM_STABILITY_GATE_INCONSISTENT")

    observed_phases = gate.get("phases")
    phases = {str(name): dict(value) for name, value in observed_phases.items()} if isinstance(observed_phases, Mapping) else {}
    phases["gateConsistency"] = {
        "status": "fail",
        "failures": [{
            "phase": "gateConsistency",
            "reasonCode": "SYSTEM_STABILITY_GATE_INCONSISTENT",
            "observedStatus": status,
            "observedQualityGateAllowed": (
                "<missing>" if "qualityGateAllowed" not in gate else bool(quality_gate_allowed)
            ),
        }],
    }

    return {
        **gate,
        "status": "fail",
        "qualityGateAllowed": False,
        "reasonCodes": reason_codes,
        "phases": phases,
    }


def _system_stability_top_level_key_diagnostic(gate: Mapping[Any, Any]) -> dict[str, str] | None:
    for key in gate:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in SYSTEM_STABILITY_GATE_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    return None


def _invalid_system_stability_gate(input_diagnostic: Mapping[str, str]) -> dict[str, Any]:
    return {
        "schemaVersion": SYSTEM_STABILITY_GATE_SCHEMA_VERSION,
        "status": "fail",
        "requiredTools": list(ALL_TOOLS),
        "qualityGateAllowed": False,
        "reasonCodes": ["SYSTEM_STABILITY_GATE_INPUT_INVALID"],
        "phases": {
            "gateInputValidation": {
                "status": "fail",
                "failures": [{
                    "phase": "gateInputValidation",
                    "reasonCode": "SYSTEM_STABILITY_GATE_INPUT_INVALID",
                    "input": dict(input_diagnostic),
                }],
            },
        },
    }


def _sanitize_system_stability_gate_projection(gate: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    if "schemaVersion" in gate:
        sanitized["schemaVersion"] = gate["schemaVersion"]
    if "status" in gate:
        sanitized["status"] = str(gate["status"]).strip()
    if "requiredTools" in gate:
        sanitized["requiredTools"] = [tool.strip() for tool in gate["requiredTools"]]
    if "qualityGateAllowed" in gate:
        sanitized["qualityGateAllowed"] = gate["qualityGateAllowed"]
    if "reasonCodes" in gate:
        sanitized["reasonCodes"] = [reason.strip() for reason in gate.get("reasonCodes") or []]
    if "phases" in gate and isinstance(gate.get("phases"), Mapping):
        sanitized["phases"] = _sanitize_system_stability_phases_projection(gate["phases"])
    return sanitized


def _sanitize_system_stability_phases_projection(phases: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for phase_name, raw_phase in phases.items():
        if not isinstance(raw_phase, Mapping):
            continue
        phase: dict[str, Any] = {}
        if "status" in raw_phase:
            phase["status"] = str(raw_phase["status"]).strip()
        if "failures" in raw_phase:
            phase["failures"] = [
                _sanitize_system_stability_failure_projection(failure)
                for failure in raw_phase["failures"]
                if isinstance(failure, Mapping)
            ]
        sanitized[phase_name] = phase
    return sanitized


def _sanitize_system_stability_failure_projection(failure: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    if "toolId" in failure:
        raw_tool = failure["toolId"]
        sanitized["toolId"] = None if raw_tool is None else str(raw_tool).strip()
    if "phase" in failure:
        sanitized["phase"] = str(failure["phase"]).strip()
    if "reasonCode" in failure:
        sanitized["reasonCode"] = str(failure["reasonCode"]).strip()
    if "status" in failure:
        sanitized["status"] = str(failure["status"]).strip()
    if "degradeReasons" in failure:
        sanitized["degradeReasons"] = [str(reason).strip() for reason in failure["degradeReasons"]]
    for field in ("timedOutFiles", "failedFiles"):
        if field in failure:
            sanitized[field] = failure[field]
    if "version" in failure:
        sanitized["versionStatus"] = "missing" if failure["version"] is None else "present"
    if "versionStatus" in failure:
        sanitized["versionStatus"] = failure["versionStatus"]
    if failure.get("expectedExecutablePath") is not None and "expectedExecutablePath" in failure:
        sanitized["expectedExecutablePathStatus"] = "redacted"
    if "expectedExecutablePathStatus" in failure:
        sanitized["expectedExecutablePathStatus"] = failure["expectedExecutablePathStatus"]
    if "observedStatus" in failure:
        sanitized["observedStatus"] = str(failure["observedStatus"]).strip()
    if "observedQualityGateAllowed" in failure:
        sanitized["observedQualityGateAllowed"] = failure["observedQualityGateAllowed"]
    return sanitized


def _system_stability_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    schema_version_diagnostic = _system_stability_schema_version_input_diagnostic(gate)
    if schema_version_diagnostic is not None:
        return schema_version_diagnostic
    if "status" not in gate:
        return {"category": "missing-field", "field": "status"}
    raw_status = gate.get("status")
    if not isinstance(raw_status, str):
        return {"category": "invalid-field", "field": "status", "type": type(raw_status).__name__}
    status = raw_status
    if status not in {"pass", "fail", "not_run"}:
        return {"category": "invalid-status", "status": "<blank>" if not status else "<invalid>"}
    if "qualityGateAllowed" not in gate:
        return {"category": "missing-field", "field": "qualityGateAllowed"}
    if not isinstance(gate.get("qualityGateAllowed"), bool):
        return {
            "category": "invalid-field",
            "field": "qualityGateAllowed",
            "type": type(gate.get("qualityGateAllowed")).__name__,
        }
    required_tools_diagnostic = _system_stability_required_tools_input_diagnostic(
        gate,
        required=status == "pass",
    )
    if required_tools_diagnostic is not None:
        return required_tools_diagnostic
    reason_codes_diagnostic = _system_stability_reason_codes_input_diagnostic(gate.get("reasonCodes"), "reasonCodes")
    if reason_codes_diagnostic is not None:
        return reason_codes_diagnostic
    phases_diagnostic = _system_stability_phases_input_diagnostic(
        gate,
        require_pass_evidence=status == "pass",
    )
    if phases_diagnostic is not None:
        return phases_diagnostic
    return None


def _system_stability_schema_version_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "schemaVersion" not in gate:
        return None
    schema_version = gate.get("schemaVersion")
    if not isinstance(schema_version, str):
        return {"category": "invalid-field", "field": "schemaVersion", "type": type(schema_version).__name__}
    if schema_version != SYSTEM_STABILITY_GATE_SCHEMA_VERSION:
        return {"category": "invalid-schema-version", "field": "schemaVersion"}
    return None


def _system_stability_required_tools_input_diagnostic(
    gate: Mapping[str, Any],
    *,
    required: bool,
) -> dict[str, str] | None:
    if "requiredTools" not in gate:
        if required:
            return {"category": "missing-field", "field": "requiredTools"}
        return None
    if (
        isinstance(gate.get("requiredTools"), (str, bytes, bytearray))
        or not isinstance(gate.get("requiredTools"), Sequence)
    ):
        return {
            "category": "invalid-field",
            "field": "requiredTools",
            "type": type(gate.get("requiredTools")).__name__,
        }
    required_tools = []
    for index, raw_tool in enumerate(gate.get("requiredTools")):
        if not isinstance(raw_tool, str):
            return {
                "category": "invalid-required-tools",
                "reason": "invalid-tool",
                "field": f"requiredTools.{index}",
                "type": type(raw_tool).__name__,
            }
        tool = raw_tool.strip()
        if not tool:
            return {
                "category": "invalid-required-tools",
                "reason": "blank-tool",
                "field": f"requiredTools.{index}",
            }
        required_tools.append(tool)
    if not required_tools:
        if required:
            return {"category": "invalid-required-tools", "reason": "empty"}
        return None
    for tool in required_tools:
        if tool not in ALL_TOOLS:
            return {"category": "invalid-required-tools", "reason": "unknown-tool", "tool": "<invalid>"}
    if required:
        for tool in ALL_TOOLS:
            if tool not in required_tools:
                return {"category": "invalid-required-tools", "reason": "missing-required-tool", "tool": tool}
    if len(required_tools) != len(set(required_tools)):
        return {"category": "invalid-required-tools", "reason": "duplicate-tool"}
    return None


def _system_stability_reason_codes_input_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return {"category": "invalid-field", "field": field, "type": type(value).__name__}
    for index, raw_reason in enumerate(value):
        reason_field = f"{field}.{index}"
        if not isinstance(raw_reason, str):
            return {"category": "invalid-reason-code", "field": reason_field, "type": type(raw_reason).__name__}
        reason = raw_reason.strip()
        if not reason:
            return {"category": "invalid-reason-code", "field": reason_field, "reason": "blank"}
        if reason not in SYSTEM_STABILITY_TOP_LEVEL_REASON_CODE_ALLOWLIST:
            return {"category": "invalid-reason-code", "field": reason_field, "reason": "invalid_string"}
    return None


def _system_stability_phases_input_diagnostic(
    gate: Mapping[str, Any],
    *,
    require_pass_evidence: bool,
) -> dict[str, str] | None:
    if "phases" not in gate:
        if require_pass_evidence:
            return {"category": "missing-field", "field": "phases"}
        return None
    if not isinstance(gate.get("phases"), Mapping):
        return {
            "category": "invalid-field",
            "field": "phases",
            "type": type(gate.get("phases")).__name__,
        }
    phases = gate.get("phases")
    for raw_phase_name in phases:
        if not isinstance(raw_phase_name, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(raw_phase_name).__name__}
        if raw_phase_name not in SYSTEM_STABILITY_PHASE_NAMES:
            return {"category": "unknown-field", "field": "<invalid>"}
    if require_pass_evidence:
        for phase_name in SYSTEM_STABILITY_REQUIRED_PASS_PHASES:
            if phase_name not in phases:
                return {"category": "missing-field", "field": f"phases.{phase_name}"}
    for phase_name, phase in phases.items():
        if phase_name not in phases:
            return {"category": "missing-field", "field": f"phases.{phase_name}"}
        if not isinstance(phase, Mapping):
            return {
                "category": "invalid-field",
                "field": f"phases.{phase_name}",
                "type": type(phase).__name__,
            }
        for phase_key in phase:
            if not isinstance(phase_key, str):
                return {"category": "unknown-field", "field": "<invalid>", "type": type(phase_key).__name__}
            if phase_key not in SYSTEM_STABILITY_PHASE_ALLOWED_KEYS:
                return {"category": "unknown-field", "field": "<invalid>"}
    for phase_name in phases:
        phase_diagnostic = _system_stability_phase_input_diagnostic(
            phases,
            phase_name,
            require_pass_evidence=require_pass_evidence,
        )
        if phase_diagnostic is not None:
            return phase_diagnostic
    return None


def _system_stability_phase_input_diagnostic(
    phases: Mapping[str, Any],
    phase_name: str,
    *,
    require_pass_evidence: bool,
) -> dict[str, str] | None:
    phase = phases.get(phase_name)
    field_prefix = f"phases.{phase_name}"
    if not isinstance(phase, Mapping):
        return {
            "category": "invalid-field",
            "field": field_prefix,
            "type": type(phase).__name__,
        }
    if "status" not in phase:
        return {"category": "missing-field", "field": f"{field_prefix}.status"}
    raw_phase_status = phase.get("status")
    if not isinstance(raw_phase_status, str):
        return {
            "category": "invalid-field",
            "field": f"{field_prefix}.status",
            "type": type(raw_phase_status).__name__,
        }
    phase_status = raw_phase_status
    if phase_status not in SYSTEM_STABILITY_PHASE_STATUS_VALUES:
        return {
            "category": "invalid-phase-status",
            "field": f"{field_prefix}.status",
            "status": "<blank>" if not phase_status else "<invalid>",
        }
    if "failures" not in phase:
        return {"category": "missing-field", "field": f"{field_prefix}.failures"}
    failures = phase.get("failures")
    if isinstance(failures, (str, bytes, bytearray)) or not isinstance(failures, Sequence):
        return {
            "category": "invalid-field",
            "field": f"{field_prefix}.failures",
            "type": type(failures).__name__,
        }
    failure_list = list(failures)
    if require_pass_evidence and phase_name in SYSTEM_STABILITY_REQUIRED_PASS_PHASES and phase_status != "pass":
        return {
            "category": "invalid-phase-status",
            "field": f"{field_prefix}.status",
            "status": "<blank>" if not phase_status else "<invalid>",
        }
    if require_pass_evidence and phase_name in SYSTEM_STABILITY_REQUIRED_PASS_PHASES and failure_list:
        return {
            "category": "invalid-phase-failures",
            "field": f"{field_prefix}.failures",
            "reason": "non-empty",
        }
    if phase_status == "pass" and failure_list:
        return {
            "category": "invalid-phase-failures",
            "field": f"{field_prefix}.failures",
            "reason": "non-empty",
        }
    for index, failure in enumerate(failure_list):
        failure_diagnostic = _system_stability_phase_failure_input_diagnostic(failure, phase_name, index)
        if failure_diagnostic is not None:
            return failure_diagnostic
    return None


def _system_stability_phase_failure_input_diagnostic(
    failure: Any,
    phase_name: str,
    index: int,
) -> dict[str, str] | None:
    failure_prefix = f"phases.{phase_name}.failures.{index}"
    if not isinstance(failure, Mapping):
        return {"category": "invalid-field", "field": failure_prefix, "type": type(failure).__name__}
    for key in failure:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in SYSTEM_STABILITY_FAILURE_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    if "toolId" in failure:
        tool_diagnostic = _system_stability_failure_tool_id_diagnostic(failure.get("toolId"), f"{failure_prefix}.toolId")
        if tool_diagnostic is not None:
            return tool_diagnostic
    if "phase" in failure:
        phase_diagnostic = _system_stability_failure_phase_diagnostic(failure.get("phase"), phase_name, f"{failure_prefix}.phase")
        if phase_diagnostic is not None:
            return phase_diagnostic
    if "reasonCode" in failure:
        reason_diagnostic = _system_stability_failure_reason_code_diagnostic(
            failure.get("reasonCode"),
            f"{failure_prefix}.reasonCode",
        )
        if reason_diagnostic is not None:
            return reason_diagnostic
    if "status" in failure:
        status_diagnostic = _system_stability_failure_status_diagnostic(failure.get("status"), f"{failure_prefix}.status")
        if status_diagnostic is not None:
            return status_diagnostic
    if "degradeReasons" in failure:
        degrade_diagnostic = _system_stability_failure_degrade_reasons_diagnostic(
            failure.get("degradeReasons"),
            f"{failure_prefix}.degradeReasons",
        )
        if degrade_diagnostic is not None:
            return degrade_diagnostic
    for field in ("timedOutFiles", "failedFiles"):
        if field in failure:
            count_diagnostic = _system_stability_failure_count_diagnostic(failure.get(field), f"{failure_prefix}.{field}")
            if count_diagnostic is not None:
                return count_diagnostic
    if "version" in failure and failure.get("version") is not None and not isinstance(failure.get("version"), str):
        return {"category": "invalid-phase-failure", "field": f"{failure_prefix}.version", "type": type(failure.get("version")).__name__}
    if "versionStatus" in failure and failure.get("versionStatus") not in {"present", "missing"}:
        return {
            "category": "invalid-phase-failure",
            "field": f"{failure_prefix}.versionStatus",
            "status": "<invalid>",
        }
    if "expectedExecutablePath" in failure:
        path = failure.get("expectedExecutablePath")
        if path is not None and not isinstance(path, str):
            return {
                "category": "invalid-phase-failure",
                "field": f"{failure_prefix}.expectedExecutablePath",
                "type": type(path).__name__,
            }
        if isinstance(path, str) and not path.strip():
            return {
                "category": "invalid-phase-failure",
                "field": f"{failure_prefix}.expectedExecutablePath",
                "reason": "blank",
            }
    if "expectedExecutablePathStatus" in failure and failure.get("expectedExecutablePathStatus") not in {
        "redacted",
        "not-configured",
    }:
        return {
            "category": "invalid-phase-failure",
            "field": f"{failure_prefix}.expectedExecutablePathStatus",
            "status": "<invalid>",
        }
    if "observedStatus" in failure:
        observed_status = failure.get("observedStatus")
        if not isinstance(observed_status, str):
            return {"category": "invalid-phase-failure", "field": f"{failure_prefix}.observedStatus", "type": type(observed_status).__name__}
        if observed_status not in {"pass", "fail", "not_run", "unknown"}:
            return {"category": "invalid-phase-failure", "field": f"{failure_prefix}.observedStatus", "status": "<invalid>"}
    if "observedQualityGateAllowed" in failure and not (
        isinstance(failure.get("observedQualityGateAllowed"), bool)
        or failure.get("observedQualityGateAllowed") == "<missing>"
    ):
        return {
            "category": "invalid-phase-failure",
            "field": f"{failure_prefix}.observedQualityGateAllowed",
            "type": type(failure.get("observedQualityGateAllowed")).__name__,
        }
    return None


def _system_stability_failure_tool_id_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return {"category": "invalid-phase-failure", "field": field, "type": type(value).__name__}
    tool = value.strip()
    if not tool or tool not in ALL_TOOLS:
        return {"category": "invalid-phase-failure", "field": field, "tool": "<invalid>"}
    return None


def _system_stability_failure_phase_diagnostic(value: Any, expected_phase: str, field: str) -> dict[str, str] | None:
    if not isinstance(value, str):
        return {"category": "invalid-phase-failure", "field": field, "type": type(value).__name__}
    phase = value.strip()
    if phase != expected_phase:
        return {"category": "invalid-phase-failure", "field": field, "phase": "<invalid>"}
    return None


def _system_stability_failure_reason_code_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if not isinstance(value, str):
        return {"category": "invalid-phase-failure", "field": field, "type": type(value).__name__}
    reason = value.strip()
    if not reason:
        return {"category": "invalid-phase-failure", "field": field, "reason": "blank"}
    if reason not in SYSTEM_STABILITY_FAILURE_REASON_CODE_ALLOWLIST:
        return {"category": "invalid-phase-failure", "field": field, "reason": "invalid_string"}
    return None


def _system_stability_failure_status_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if not isinstance(value, str):
        return {"category": "invalid-phase-failure", "field": field, "type": type(value).__name__}
    status = value.strip()
    if status not in SYSTEM_STABILITY_FAILURE_STATUS_VALUES:
        return {"category": "invalid-phase-failure", "field": field, "status": "<blank>" if not status else "<invalid>"}
    return None


def _system_stability_failure_degrade_reasons_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return {"category": "invalid-phase-failure", "field": field, "type": type(value).__name__}
    for index, raw_reason in enumerate(value):
        item_field = f"{field}.{index}"
        if not isinstance(raw_reason, str):
            return {"category": "invalid-phase-failure", "field": item_field, "type": type(raw_reason).__name__}
        reason = raw_reason.strip()
        if not reason:
            return {"category": "invalid-phase-failure", "field": item_field, "reason": "blank"}
        if reason not in SYSTEM_STABILITY_DEGRADE_REASON_ALLOWLIST:
            return {"category": "invalid-phase-failure", "field": item_field, "reason": "invalid_string"}
    return None


def _system_stability_failure_count_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        return {"category": "invalid-phase-failure", "field": field, "type": type(value).__name__}
    if value < 0:
        return {"category": "invalid-phase-failure", "field": field, "reason": "negative"}
    return None


def _normalize_corpus_readiness_gate(corpus_readiness_gate: Any) -> dict[str, Any]:
    if not isinstance(corpus_readiness_gate, Mapping):
        return _invalid_corpus_readiness_gate({"category": "non-mapping", "type": type(corpus_readiness_gate).__name__})
    top_level_key_diagnostic = _corpus_readiness_top_level_key_diagnostic(corpus_readiness_gate)
    if top_level_key_diagnostic is not None:
        return _invalid_corpus_readiness_gate(top_level_key_diagnostic)
    gate = dict(corpus_readiness_gate)
    input_diagnostic = _corpus_readiness_input_diagnostic(gate)
    if input_diagnostic is not None:
        return _invalid_corpus_readiness_gate(input_diagnostic)
    gate = _sanitize_corpus_readiness_gate_projection(gate)

    status = str(gate.get("status") or "blocked")
    decision_grade_ready = gate.get("decisionGradeReady")
    available_gate_not_ready = status == "available" and decision_grade_ready is not True
    available_gate_has_reason_codes = status == "available" and bool(gate.get("reasonCodes") or [])
    non_available_gate_ready = status != "available" and decision_grade_ready is True
    external_available_only = _external_corpus_status_is_available_only(gate.get("externalCorpusStatus"))
    non_available_projects_available = status != "available" and external_available_only
    if not (
        available_gate_not_ready
        or available_gate_has_reason_codes
        or non_available_gate_ready
        or non_available_projects_available
    ):
        return gate

    reason_codes = list(gate.get("reasonCodes") or [])
    if "CORPUS_READINESS_GATE_INCONSISTENT" not in reason_codes:
        reason_codes.append("CORPUS_READINESS_GATE_INCONSISTENT")

    observed_external_status = gate.get("externalCorpusStatus")
    external_status = (
        {
            str(key): dict(value)
            for key, value in observed_external_status.items()
            if isinstance(value, Mapping)
        }
        if isinstance(observed_external_status, Mapping)
        else {}
    )
    external_status["requiredCorpusReadiness"] = {
        "status": "blocked",
        "reasonCodes": sorted(str(reason) for reason in reason_codes),
    }

    return {
        **gate,
        "status": "blocked",
        "decisionGradeReady": False,
        "reasonCodes": sorted(str(reason) for reason in reason_codes),
        "externalCorpusStatus": external_status,
        "consistencyChecks": {
            "status": "fail",
            "failures": [{
                "reasonCode": "CORPUS_READINESS_GATE_INCONSISTENT",
                "observedStatus": status,
                "observedDecisionGradeReady": (
                    "<missing>" if "decisionGradeReady" not in gate else bool(decision_grade_ready)
                ),
                "externalCorpusStatusAvailableOnly": external_available_only,
            }],
        },
    }


def _invalid_corpus_readiness_gate(input_diagnostic: Mapping[str, str]) -> dict[str, Any]:
    reason_codes = ["CORPUS_READINESS_GATE_INPUT_INVALID"]
    return {
        "schemaVersion": CORPUS_READINESS_GATE_SCHEMA_VERSION,
        "status": "blocked",
        "decisionGradeReady": False,
        "requiredCorpora": [],
        "reasonCodes": reason_codes,
        "acquisitionStatuses": {},
        "caseStatuses": [],
        "externalCorpusStatus": {
            "requiredCorpusReadiness": {
                "status": "blocked",
                "reasonCodes": reason_codes,
            },
        },
        "summary": {"checkedCaseCount": 0},
        "inputValidation": {
            "status": "fail",
            "failures": [{
                "reasonCode": "CORPUS_READINESS_GATE_INPUT_INVALID",
                "input": dict(input_diagnostic),
            }],
        },
        "consumerPolicy": "invalid_input_no_decision_grade_corpus_readiness_claim",
    }


def _sanitize_corpus_readiness_gate_projection(gate: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for field in ("schemaVersion", "status", "decisionGradeReady", "consumerPolicy"):
        if field in gate:
            sanitized[field] = gate[field]
    if "requiredCorpora" in gate:
        sanitized["requiredCorpora"] = [
            corpus for corpus in gate.get("requiredCorpora") or []
            if isinstance(corpus, str) and _valid_readiness_required_corpus_id(corpus)
        ]
    if "reasonCodes" in gate:
        sanitized["reasonCodes"] = [
            reason for reason in gate.get("reasonCodes") or []
            if isinstance(reason, str) and _valid_readiness_reason_code(reason)
        ]
    if "acquisitionStatuses" in gate and isinstance(gate.get("acquisitionStatuses"), Mapping):
        sanitized["acquisitionStatuses"] = _sanitize_corpus_readiness_acquisition_statuses_projection(
            gate["acquisitionStatuses"]
        )
    if "caseStatuses" in gate and _readiness_sequence(gate.get("caseStatuses")):
        sanitized["caseStatuses"] = [
            _sanitize_corpus_readiness_case_status_projection(case_status)
            for case_status in gate["caseStatuses"]
            if isinstance(case_status, Mapping)
        ]
    if "externalCorpusStatus" in gate:
        external_status = external_corpus_status_from_readiness(gate)
        raw_external_status = gate.get("externalCorpusStatus")
        if not (
            isinstance(raw_external_status, Mapping)
            and "requiredCorpusReadiness" in raw_external_status
        ):
            external_status.pop("requiredCorpusReadiness", None)
        sanitized["externalCorpusStatus"] = external_status
    if "summary" in gate and isinstance(gate.get("summary"), Mapping):
        sanitized["summary"] = _sanitize_corpus_readiness_summary_projection(gate["summary"])
    if "requiredCorpusInputValidation" in gate and isinstance(gate.get("requiredCorpusInputValidation"), Mapping):
        sanitized["requiredCorpusInputValidation"] = _sanitize_required_corpus_input_validation_projection(
            gate["requiredCorpusInputValidation"]
        )
    if "consistencyChecks" in gate and isinstance(gate.get("consistencyChecks"), Mapping):
        sanitized["consistencyChecks"] = _sanitize_corpus_readiness_consistency_checks_projection(
            gate["consistencyChecks"]
        )
    return sanitized


def _sanitize_corpus_readiness_acquisition_statuses_projection(statuses: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for acquisition_id, value in statuses.items():
        if not isinstance(acquisition_id, str) or not _valid_readiness_required_corpus_id(acquisition_id):
            continue
        if not isinstance(value, Mapping):
            continue
        entry: dict[str, Any] = {}
        for field in ("status", "acquisitionId", "corpusName", "localPathStatus", "resolvedLocalPathStatus", "manifestChecksum"):
            if field in value:
                entry[field] = value[field]
        if "reasonCodes" in value:
            entry["reasonCodes"] = [
                reason for reason in value.get("reasonCodes") or []
                if isinstance(reason, str) and _valid_readiness_reason_code(reason)
            ]
        if "caseCount" in value:
            entry["caseCount"] = value["caseCount"]
        if "splitCounts" in value and isinstance(value.get("splitCounts"), Mapping):
            entry["splitCounts"] = {
                split: count
                for split, count in value["splitCounts"].items()
                if isinstance(split, str) and split in SPLITS and _nonnegative_int(count)
            }
        sanitized[acquisition_id] = entry
    return sanitized


def _sanitize_corpus_readiness_case_status_projection(case_status: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for field in (
        "status",
        "acquisitionId",
        "caseId",
        "sourcePath",
        "sourcePathStatus",
        "resolvedPathStatus",
        "expectedChecksum",
        "actualChecksum",
        "checksum",
    ):
        if field in case_status:
            sanitized[field] = case_status[field]
    if "reasonCodes" in case_status:
        sanitized["reasonCodes"] = [
            reason for reason in case_status.get("reasonCodes") or []
            if isinstance(reason, str) and _valid_readiness_reason_code(reason)
        ]
    return sanitized


def _sanitize_corpus_readiness_summary_projection(summary: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for field in ("caseCount", "checkedCaseCount"):
        if field in summary:
            sanitized[field] = summary[field]
    if "splitCounts" in summary and isinstance(summary.get("splitCounts"), Mapping):
        sanitized["splitCounts"] = {
            split: count
            for split, count in summary["splitCounts"].items()
            if isinstance(split, str) and split in SPLITS and _nonnegative_int(count)
        }
    if "sliceCounts" in summary and isinstance(summary.get("sliceCounts"), Mapping):
        sanitized["sliceCounts"] = {
            slice_kind: count
            for slice_kind, count in summary["sliceCounts"].items()
            if isinstance(slice_kind, str) and slice_kind in SLICE_KINDS and _nonnegative_int(count)
        }
    return sanitized


def _sanitize_required_corpus_input_validation_projection(validation: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    if "status" in validation:
        sanitized["status"] = validation["status"]
    if "reasonCodes" in validation:
        sanitized["reasonCodes"] = [
            reason for reason in validation.get("reasonCodes") or []
            if reason == "CORPUS_REQUIRED_CORPUS_ID_INVALID"
        ]
    if "failures" in validation and _readiness_sequence(validation.get("failures")):
        sanitized["failures"] = [
            _sanitize_required_corpus_input_failure_projection(failure)
            for failure in validation["failures"]
            if isinstance(failure, Mapping)
        ]
    return sanitized


def _sanitize_required_corpus_input_failure_projection(failure: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    if "index" in failure:
        sanitized["index"] = failure["index"]
    if "category" in failure:
        sanitized["category"] = failure["category"]
    return sanitized


def _sanitize_corpus_readiness_consistency_checks_projection(consistency_checks: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    if "status" in consistency_checks:
        sanitized["status"] = consistency_checks["status"]
    if "failures" in consistency_checks and _readiness_sequence(consistency_checks.get("failures")):
        sanitized["failures"] = [
            _sanitize_corpus_readiness_consistency_failure_projection(failure)
            for failure in consistency_checks["failures"]
            if isinstance(failure, Mapping)
        ]
    return sanitized


def _sanitize_corpus_readiness_consistency_failure_projection(failure: Mapping[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for field in (
        "reasonCode",
        "observedStatus",
        "observedDecisionGradeReady",
        "externalCorpusStatusAvailableOnly",
    ):
        if field in failure:
            sanitized[field] = failure[field]
    return sanitized


def _corpus_readiness_top_level_key_diagnostic(gate: Mapping[Any, Any]) -> dict[str, str] | None:
    for key in gate:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key in CORPUS_READINESS_GATE_FORBIDDEN_CALLER_KEYS:
            return {"category": "forbidden-field", "field": key}
        if key not in CORPUS_READINESS_GATE_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    return None


def _corpus_readiness_schema_version_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "schemaVersion" not in gate:
        return None
    schema_version = gate.get("schemaVersion")
    if not isinstance(schema_version, str):
        return {"category": "invalid-field", "field": "schemaVersion", "type": type(schema_version).__name__}
    if schema_version != CORPUS_READINESS_GATE_SCHEMA_VERSION:
        return {"category": "invalid-schema-version", "field": "schemaVersion"}
    return None


def _corpus_readiness_consumer_policy_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "consumerPolicy" not in gate:
        return None
    consumer_policy = gate.get("consumerPolicy")
    if not isinstance(consumer_policy, str) or consumer_policy not in CORPUS_READINESS_CONSUMER_POLICY_VALUES:
        return {"category": "invalid-consumer-policy", "field": "consumerPolicy"}
    return None


def _corpus_readiness_summary_shape_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "summary" not in gate:
        return None
    summary = gate.get("summary")
    if not isinstance(summary, Mapping):
        return {"category": "invalid-field", "field": "summary", "type": type(summary).__name__}
    for key in summary:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in CORPUS_READINESS_SUMMARY_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    for field in ("caseCount", "checkedCaseCount"):
        if field in summary:
            diagnostic = _nonnegative_int_field_diagnostic(summary.get(field), f"summary.{field}", category="invalid-summary")
            if diagnostic is not None:
                return diagnostic
    split_counts_diagnostic = _readiness_counts_mapping_input_diagnostic(
        summary.get("splitCounts"),
        "summary.splitCounts",
        allowed_keys=SPLITS,
    ) if "splitCounts" in summary else None
    if split_counts_diagnostic is not None:
        return split_counts_diagnostic
    slice_counts_diagnostic = _readiness_counts_mapping_input_diagnostic(
        summary.get("sliceCounts"),
        "summary.sliceCounts",
        allowed_keys=SLICE_KINDS,
    ) if "sliceCounts" in summary else None
    if slice_counts_diagnostic is not None:
        return slice_counts_diagnostic
    return None


def _corpus_readiness_acquisition_statuses_shape_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "acquisitionStatuses" not in gate:
        return None
    acquisition_statuses = gate.get("acquisitionStatuses")
    if not isinstance(acquisition_statuses, Mapping):
        return {"category": "invalid-field", "field": "acquisitionStatuses", "type": type(acquisition_statuses).__name__}
    for key, acquisition in acquisition_statuses.items():
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if not _valid_readiness_required_corpus_id(key):
            return {"category": "unknown-field", "field": "<invalid>"}
        field_prefix = f"acquisitionStatuses.{key}"
        if not isinstance(acquisition, Mapping):
            return {"category": "invalid-field", "field": field_prefix, "type": type(acquisition).__name__}
        path_status_diagnostic = _readiness_acquisition_path_status_input_diagnostic(
            acquisition,
            field_prefix,
            require_available=False,
        )
        if path_status_diagnostic is not None:
            return path_status_diagnostic
        for nested_key in acquisition:
            if not isinstance(nested_key, str):
                return {"category": "unknown-field", "field": "<invalid>", "type": type(nested_key).__name__}
            if nested_key not in CORPUS_READINESS_ACQUISITION_STATUS_ALLOWED_KEYS:
                return {"category": "unknown-field", "field": "<invalid>"}
        if "status" in acquisition:
            status_diagnostic = _readiness_status_value_input_diagnostic(
                acquisition.get("status"),
                f"{field_prefix}.status",
                category="invalid-acquisition-status",
            )
            if status_diagnostic is not None:
                return status_diagnostic
        if "acquisitionId" in acquisition:
            acquisition_id_diagnostic = _readiness_safe_identifier_input_diagnostic(
                acquisition.get("acquisitionId"),
                f"{field_prefix}.acquisitionId",
                category="invalid-acquisition-id",
            )
            if acquisition_id_diagnostic is not None:
                return acquisition_id_diagnostic
        if "corpusName" in acquisition:
            corpus_name_diagnostic = _readiness_safe_identifier_input_diagnostic(
                acquisition.get("corpusName"),
                f"{field_prefix}.corpusName",
                category="invalid-acquisition-corpus-name",
            )
            if corpus_name_diagnostic is not None:
                return corpus_name_diagnostic
        if "manifestChecksum" in acquisition:
            checksum_diagnostic = _readiness_optional_checksum_input_diagnostic(
                acquisition.get("manifestChecksum"),
                f"{field_prefix}.manifestChecksum",
            )
            if checksum_diagnostic is not None:
                return checksum_diagnostic
        if "reasonCodes" in acquisition:
            reason_code_diagnostic = _optional_reason_codes_diagnostic(
                acquisition.get("reasonCodes"),
                f"{field_prefix}.reasonCodes",
            )
            if reason_code_diagnostic is not None:
                return reason_code_diagnostic
        if "caseCount" in acquisition:
            count_diagnostic = _nonnegative_int_field_diagnostic(
                acquisition.get("caseCount"),
                f"{field_prefix}.caseCount",
                category="invalid-acquisition-count",
            )
            if count_diagnostic is not None:
                return count_diagnostic
        if "splitCounts" in acquisition:
            split_counts_diagnostic = _readiness_counts_mapping_input_diagnostic(
                acquisition.get("splitCounts"),
                f"{field_prefix}.splitCounts",
                allowed_keys=SPLITS,
            )
            if split_counts_diagnostic is not None:
                return split_counts_diagnostic
    return None


def _corpus_readiness_case_statuses_shape_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "caseStatuses" not in gate:
        return None
    case_statuses = gate.get("caseStatuses")
    if not _readiness_sequence(case_statuses):
        return {"category": "invalid-field", "field": "caseStatuses", "type": type(case_statuses).__name__}
    for index, case_status in enumerate(case_statuses):
        field_prefix = f"caseStatuses.{index}"
        if not isinstance(case_status, Mapping):
            return {"category": "invalid-field", "field": field_prefix, "type": type(case_status).__name__}
        path_status_diagnostic = _readiness_case_path_status_input_diagnostic(
            case_status,
            field_prefix,
            require_available=False,
        )
        if path_status_diagnostic is not None:
            return path_status_diagnostic
        for nested_key in case_status:
            if not isinstance(nested_key, str):
                return {"category": "unknown-field", "field": "<invalid>", "type": type(nested_key).__name__}
            if nested_key not in CORPUS_READINESS_CASE_STATUS_ALLOWED_KEYS:
                return {"category": "unknown-field", "field": "<invalid>"}
        if "status" in case_status:
            status_diagnostic = _readiness_status_value_input_diagnostic(
                case_status.get("status"),
                f"{field_prefix}.status",
                category="invalid-case-status",
            )
            if status_diagnostic is not None:
                return status_diagnostic
        if "acquisitionId" in case_status:
            acquisition_id_diagnostic = _readiness_safe_identifier_input_diagnostic(
                case_status.get("acquisitionId"),
                f"{field_prefix}.acquisitionId",
                category="invalid-case-acquisition",
            )
            if acquisition_id_diagnostic is not None:
                return acquisition_id_diagnostic
        if "caseId" in case_status:
            case_id_diagnostic = _readiness_safe_identifier_input_diagnostic(
                case_status.get("caseId"),
                f"{field_prefix}.caseId",
                category="invalid-case-id",
            )
            if case_id_diagnostic is not None:
                return case_id_diagnostic
        for checksum_field in ("expectedChecksum", "actualChecksum", "checksum"):
            if checksum_field in case_status:
                checksum_diagnostic = _readiness_optional_checksum_input_diagnostic(
                    case_status.get(checksum_field),
                    f"{field_prefix}.{checksum_field}",
                )
                if checksum_diagnostic is not None:
                    return checksum_diagnostic
        if "reasonCodes" in case_status:
            reason_code_diagnostic = _optional_reason_codes_diagnostic(
                case_status.get("reasonCodes"),
                f"{field_prefix}.reasonCodes",
            )
            if reason_code_diagnostic is not None:
                return reason_code_diagnostic
    return None


def _required_corpus_input_validation_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "requiredCorpusInputValidation" not in gate:
        return None
    validation = gate.get("requiredCorpusInputValidation")
    if not isinstance(validation, Mapping):
        return {
            "category": "invalid-required-corpus-input-validation",
            "field": "requiredCorpusInputValidation",
            "type": type(validation).__name__,
        }
    for key in validation:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in CORPUS_READINESS_REQUIRED_CORPUS_INPUT_VALIDATION_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    if validation.get("status") != "fail":
        return {
            "category": "invalid-required-corpus-input-validation",
            "field": "requiredCorpusInputValidation.status",
            "status": "<invalid>",
        }
    if validation.get("reasonCodes") != ["CORPUS_REQUIRED_CORPUS_ID_INVALID"]:
        return {
            "category": "invalid-required-corpus-input-validation",
            "field": "requiredCorpusInputValidation.reasonCodes",
            "reason": "invalid_string",
        }
    failures = validation.get("failures")
    if not _readiness_sequence(failures):
        return {
            "category": "invalid-required-corpus-input-validation",
            "field": "requiredCorpusInputValidation.failures",
            "type": type(failures).__name__,
        }
    for index, failure in enumerate(failures):
        failure_diagnostic = _required_corpus_input_validation_failure_input_diagnostic(failure, index)
        if failure_diagnostic is not None:
            return failure_diagnostic
    return None


def _required_corpus_input_validation_failure_input_diagnostic(failure: Any, index: int) -> dict[str, str] | None:
    field_prefix = f"requiredCorpusInputValidation.failures.{index}"
    if not isinstance(failure, Mapping):
        return {
            "category": "invalid-required-corpus-input-validation",
            "field": field_prefix,
            "type": type(failure).__name__,
        }
    for key in failure:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in CORPUS_READINESS_REQUIRED_CORPUS_INPUT_FAILURE_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    if "index" in failure:
        index_diagnostic = _nonnegative_int_field_diagnostic(
            failure.get("index"),
            f"{field_prefix}.index",
            category="invalid-required-corpus-input-validation",
        )
        if index_diagnostic is not None:
            return index_diagnostic
    category = failure.get("category")
    if not isinstance(category, str) or category not in CORPUS_READINESS_REQUIRED_CORPUS_INPUT_FAILURE_CATEGORIES:
        return {
            "category": "invalid-required-corpus-input-validation",
            "field": f"{field_prefix}.category",
            "reason": "invalid_string",
        }
    return None


def _corpus_readiness_consistency_checks_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    if "consistencyChecks" not in gate:
        return None
    consistency_checks = gate.get("consistencyChecks")
    if not isinstance(consistency_checks, Mapping):
        return {
            "category": "invalid-consistency-check",
            "field": "consistencyChecks",
            "type": type(consistency_checks).__name__,
        }
    for key in consistency_checks:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in CORPUS_READINESS_CONSISTENCY_CHECKS_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    if consistency_checks.get("status") != "fail":
        return {"category": "invalid-consistency-check", "field": "consistencyChecks.status", "status": "<invalid>"}
    failures = consistency_checks.get("failures")
    if not _readiness_sequence(failures):
        return {
            "category": "invalid-consistency-check",
            "field": "consistencyChecks.failures",
            "type": type(failures).__name__,
        }
    for index, failure in enumerate(failures):
        failure_diagnostic = _corpus_readiness_consistency_failure_input_diagnostic(failure, index)
        if failure_diagnostic is not None:
            return failure_diagnostic
    return None


def _corpus_readiness_consistency_failure_input_diagnostic(failure: Any, index: int) -> dict[str, str] | None:
    field_prefix = f"consistencyChecks.failures.{index}"
    if not isinstance(failure, Mapping):
        return {"category": "invalid-consistency-check", "field": field_prefix, "type": type(failure).__name__}
    for key in failure:
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in CORPUS_READINESS_CONSISTENCY_FAILURE_ALLOWED_KEYS:
            return {"category": "unknown-field", "field": "<invalid>"}
    if failure.get("reasonCode") != "CORPUS_READINESS_GATE_INCONSISTENT":
        return {
            "category": "invalid-consistency-check",
            "field": f"{field_prefix}.reasonCode",
            "reason": "invalid_string",
        }
    observed_status = failure.get("observedStatus")
    if not isinstance(observed_status, str) or observed_status not in READINESS_STATUS_VALUES:
        return {
            "category": "invalid-consistency-check",
            "field": f"{field_prefix}.observedStatus",
            "status": "<invalid>",
        }
    observed_decision_grade_ready = failure.get("observedDecisionGradeReady")
    if not (isinstance(observed_decision_grade_ready, bool) or observed_decision_grade_ready == "<missing>"):
        return {
            "category": "invalid-consistency-check",
            "field": f"{field_prefix}.observedDecisionGradeReady",
            "type": type(observed_decision_grade_ready).__name__,
        }
    if not isinstance(failure.get("externalCorpusStatusAvailableOnly"), bool):
        return {
            "category": "invalid-consistency-check",
            "field": f"{field_prefix}.externalCorpusStatusAvailableOnly",
            "type": type(failure.get("externalCorpusStatusAvailableOnly")).__name__,
        }
    return None


def _corpus_readiness_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    schema_version_diagnostic = _corpus_readiness_schema_version_input_diagnostic(gate)
    if schema_version_diagnostic is not None:
        return schema_version_diagnostic
    if "status" not in gate:
        return {"category": "missing-field", "field": "status"}
    raw_status = gate.get("status")
    if not isinstance(raw_status, str):
        return {"category": "invalid-field", "field": "status", "type": type(raw_status).__name__}
    status = raw_status
    if status not in {"available", "blocked", "not_run"}:
        return {"category": "invalid-status", "status": "<blank>" if not status else "<invalid>"}
    if "decisionGradeReady" not in gate:
        return {"category": "missing-field", "field": "decisionGradeReady"}
    if not isinstance(gate.get("decisionGradeReady"), bool):
        return {
            "category": "invalid-field",
            "field": "decisionGradeReady",
            "type": type(gate.get("decisionGradeReady")).__name__,
        }
    reason_code_diagnostic = _optional_reason_codes_diagnostic(gate.get("reasonCodes"), "reasonCodes")
    if reason_code_diagnostic is not None:
        return reason_code_diagnostic
    consumer_policy_diagnostic = _corpus_readiness_consumer_policy_input_diagnostic(gate)
    if consumer_policy_diagnostic is not None:
        return consumer_policy_diagnostic
    required_corpus_input_validation_diagnostic = _required_corpus_input_validation_input_diagnostic(gate)
    if required_corpus_input_validation_diagnostic is not None:
        return required_corpus_input_validation_diagnostic
    consistency_checks_diagnostic = _corpus_readiness_consistency_checks_input_diagnostic(gate)
    if consistency_checks_diagnostic is not None:
        return consistency_checks_diagnostic
    summary_shape_diagnostic = _corpus_readiness_summary_shape_input_diagnostic(gate)
    if summary_shape_diagnostic is not None:
        return summary_shape_diagnostic
    acquisition_statuses_shape_diagnostic = _corpus_readiness_acquisition_statuses_shape_input_diagnostic(gate)
    if acquisition_statuses_shape_diagnostic is not None:
        return acquisition_statuses_shape_diagnostic
    case_statuses_shape_diagnostic = _corpus_readiness_case_statuses_shape_input_diagnostic(gate)
    if case_statuses_shape_diagnostic is not None:
        return case_statuses_shape_diagnostic

    if status == "available" and gate.get("decisionGradeReady") is True:
        return _available_corpus_readiness_input_diagnostic(gate)
    required_corpora_diagnostic = _required_corpora_input_diagnostic(gate, required=False)
    if required_corpora_diagnostic is not None:
        return required_corpora_diagnostic
    path_status_diagnostic = _optional_readiness_path_status_input_diagnostic(gate)
    if path_status_diagnostic is not None:
        return path_status_diagnostic
    if not (
        status != "available"
        and gate.get("decisionGradeReady") is True
        and "externalCorpusStatus" in gate
        and not isinstance(gate.get("externalCorpusStatus"), Mapping)
    ):
        external_status_diagnostic = _readiness_external_status_input_diagnostic(
            gate,
            required=False,
            required_corpora=[],
        )
        if external_status_diagnostic is not None:
            return external_status_diagnostic
    return None


def _available_corpus_readiness_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    required_corpora_diagnostic = _required_corpora_input_diagnostic(gate, required=True)
    if required_corpora_diagnostic is not None:
        return required_corpora_diagnostic
    required_corpora = _normalized_required_corpora(gate.get("requiredCorpora"))

    acquisition_statuses_diagnostic = _mapping_field_input_diagnostic(gate, "acquisitionStatuses")
    if acquisition_statuses_diagnostic is not None:
        return acquisition_statuses_diagnostic
    acquisition_statuses = gate.get("acquisitionStatuses")
    for acquisition_key, acquisition in acquisition_statuses.items():
        field_key = (
            str(acquisition_key)
            if isinstance(acquisition_key, str) and _valid_readiness_required_corpus_id(acquisition_key)
            else "<unsafe>"
        )
        field_prefix = f"acquisitionStatuses.{field_key}"
        if not isinstance(acquisition, Mapping):
            return {"category": "invalid-field", "field": field_prefix, "type": type(acquisition).__name__}
        path_status_diagnostic = _readiness_acquisition_path_status_input_diagnostic(
            acquisition,
            field_prefix,
            require_available=True,
        )
        if path_status_diagnostic is not None:
            return path_status_diagnostic
    for corpus_id in required_corpora:
        if corpus_id not in acquisition_statuses:
            return {
                "category": "missing-required-acquisition",
                "field": "acquisitionStatuses",
                "acquisitionId": corpus_id,
            }
        acquisition = acquisition_statuses.get(corpus_id)
        field_prefix = f"acquisitionStatuses.{corpus_id}"
        if not isinstance(acquisition, Mapping):
            return {"category": "invalid-field", "field": field_prefix, "type": type(acquisition).__name__}
        path_status_diagnostic = _readiness_acquisition_path_status_input_diagnostic(
            acquisition,
            field_prefix,
            require_available=True,
        )
        if path_status_diagnostic is not None:
            return path_status_diagnostic
        if str(acquisition.get("status") or "") != "available":
            return {
                "category": "invalid-acquisition-status",
                "field": f"{field_prefix}.status",
                "status": str(acquisition.get("status") or "<missing>"),
            }
        reason_code_diagnostic = _optional_reason_codes_diagnostic(
            acquisition.get("reasonCodes"),
            f"{field_prefix}.reasonCodes",
        )
        if reason_code_diagnostic is not None:
            return reason_code_diagnostic
        if list(acquisition.get("reasonCodes") or []):
            return {
                "category": "invalid-acquisition-reason-codes",
                "field": f"{field_prefix}.reasonCodes",
                "reason": "non-empty",
            }
        split_counts_diagnostic = _mapping_field_input_diagnostic(acquisition, "splitCounts", field_prefix=field_prefix)
        if split_counts_diagnostic is not None:
            return split_counts_diagnostic
        split_counts = acquisition.get("splitCounts")
        for split in ("validation", "test"):
            if not _positive_count(split_counts.get(split)):
                return {"category": "missing-required-split", "field": f"{field_prefix}.splitCounts.{split}"}

    case_statuses = gate.get("caseStatuses")
    if "caseStatuses" not in gate:
        return {"category": "missing-field", "field": "caseStatuses"}
    if isinstance(case_statuses, (str, bytes, bytearray)) or not isinstance(case_statuses, Sequence):
        return {"category": "invalid-field", "field": "caseStatuses", "type": type(case_statuses).__name__}
    if not case_statuses:
        return {"category": "invalid-case-statuses", "reason": "empty"}
    required_corpus_set = set(required_corpora)
    case_evidence_corpora: set[str] = set()
    for index, case_status in enumerate(case_statuses):
        field_prefix = f"caseStatuses.{index}"
        if not isinstance(case_status, Mapping):
            return {"category": "invalid-field", "field": field_prefix, "type": type(case_status).__name__}
        path_status_diagnostic = _readiness_case_path_status_input_diagnostic(
            case_status,
            field_prefix,
            require_available=True,
        )
        if path_status_diagnostic is not None:
            return path_status_diagnostic
        acquisition_id = str(case_status.get("acquisitionId") or "")
        if acquisition_id not in required_corpus_set:
            return {
                "category": "invalid-case-acquisition",
                "field": f"{field_prefix}.acquisitionId",
                "acquisitionId": acquisition_id or "<missing>",
            }
        if str(case_status.get("status") or "") != "available":
            return {
                "category": "invalid-case-status",
                "field": f"{field_prefix}.status",
                "status": str(case_status.get("status") or "<missing>"),
            }
        reason_code_diagnostic = _optional_reason_codes_diagnostic(
            case_status.get("reasonCodes"),
            f"{field_prefix}.reasonCodes",
        )
        if reason_code_diagnostic is not None:
            return reason_code_diagnostic
        if list(case_status.get("reasonCodes") or []):
            return {
                "category": "invalid-case-status",
                "field": f"{field_prefix}.reasonCodes",
                "reason": "non-empty",
            }
        case_evidence_corpora.add(acquisition_id)
    for corpus_id in required_corpora:
        if corpus_id not in case_evidence_corpora:
            return {
                "category": "missing-required-case-evidence",
                "field": "caseStatuses",
                "acquisitionId": corpus_id,
            }

    summary_diagnostic = _mapping_field_input_diagnostic(gate, "summary")
    if summary_diagnostic is not None:
        return summary_diagnostic
    summary = gate.get("summary")
    checked_case_count = summary.get("checkedCaseCount")
    expected_checked_case_count = len(case_statuses)
    if not isinstance(checked_case_count, int) or isinstance(checked_case_count, bool) or checked_case_count != expected_checked_case_count:
        actual_checked_case_count = (
            "<missing>" if checked_case_count is None
            else str(checked_case_count) if isinstance(checked_case_count, int) and not isinstance(checked_case_count, bool)
            else "<invalid>"
        )
        return {
            "category": "invalid-summary",
            "field": "summary.checkedCaseCount",
            "expected": str(expected_checked_case_count),
            "actual": actual_checked_case_count,
        }
    if checked_case_count <= 0:
        return {
            "category": "invalid-summary",
            "field": "summary.checkedCaseCount",
            "expected": f">{0}",
            "actual": str(checked_case_count),
        }
    split_counts_diagnostic = _mapping_field_input_diagnostic(summary, "splitCounts", field_prefix="summary")
    if split_counts_diagnostic is not None:
        return split_counts_diagnostic
    summary_split_counts = summary.get("splitCounts")
    for split in ("validation", "test"):
        if not _positive_count(summary_split_counts.get(split)):
            return {"category": "missing-required-split", "field": f"summary.splitCounts.{split}"}

    external_status_diagnostic = _readiness_external_status_input_diagnostic(
        gate,
        required=True,
        required_corpora=required_corpora,
    )
    if external_status_diagnostic is not None:
        return external_status_diagnostic
    external_status = gate.get("externalCorpusStatus")
    external_corpus_names = [_readiness_external_corpus_name(corpus_id) for corpus_id in required_corpora]
    external_name_counts = {
        name: external_corpus_names.count(name)
        for name in set(external_corpus_names)
    }
    for corpus_id in required_corpora:
        if not _external_status_projects_required_corpus(
            external_status,
            corpus_id,
            external_name_counts=external_name_counts,
        ):
            return {
                "category": "invalid-external-corpus-status",
                "reason": "required-corpus-projection-missing",
                "acquisitionId": corpus_id,
            }
    return None


def _required_corpora_input_diagnostic(gate: Mapping[str, Any], *, required: bool) -> dict[str, str] | None:
    if "requiredCorpora" not in gate:
        if required:
            return {"category": "missing-field", "field": "requiredCorpora"}
        return None
    required_corpora = gate.get("requiredCorpora")
    if isinstance(required_corpora, (str, bytes, bytearray)) or not isinstance(required_corpora, Sequence):
        return {"category": "invalid-field", "field": "requiredCorpora", "type": type(required_corpora).__name__}
    normalized: list[str] = []
    seen: set[str] = set()
    for index, corpus in enumerate(required_corpora):
        if not isinstance(corpus, str):
            return {
                "category": "invalid-required-corpora",
                "field": f"requiredCorpora.{index}",
                "reason": "non_string",
            }
        if not _valid_readiness_required_corpus_id(corpus):
            return {
                "category": "invalid-required-corpora",
                "field": f"requiredCorpora.{index}",
                "reason": "invalid_string",
            }
        if corpus in seen:
            return {
                "category": "invalid-required-corpora",
                "field": f"requiredCorpora.{index}",
                "reason": "duplicate",
            }
        normalized.append(corpus)
        seen.add(corpus)
    if required and not normalized:
        return {"category": "invalid-required-corpora", "reason": "empty"}
    return None


def _normalized_required_corpora(required_corpora: Any) -> list[str]:
    if isinstance(required_corpora, Sequence) and not isinstance(required_corpora, (str, bytes, bytearray)):
        return [corpus for corpus in required_corpora if isinstance(corpus, str) and _valid_readiness_required_corpus_id(corpus)]
    return []


def _valid_readiness_required_corpus_id(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        and READINESS_REQUIRED_CORPUS_ID_RE.match(value) is not None
    )


def _readiness_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _nonnegative_int_field_diagnostic(value: Any, field: str, *, category: str) -> dict[str, str] | None:
    if _nonnegative_int(value):
        return None
    diagnostic: dict[str, str] = {"category": category, "field": field}
    if category == "invalid-summary":
        diagnostic["actual"] = "<invalid>"
    elif isinstance(value, bool) or not isinstance(value, int):
        diagnostic["type"] = type(value).__name__
    else:
        diagnostic["reason"] = "negative"
    return diagnostic


def _readiness_counts_mapping_input_diagnostic(
    value: Any,
    field: str,
    *,
    allowed_keys: set[str],
) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return {"category": "invalid-field", "field": field, "type": type(value).__name__}
    for key, count in value.items():
        if not isinstance(key, str):
            return {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
        if key not in allowed_keys:
            return {"category": "unknown-field", "field": "<invalid>"}
        count_diagnostic = _nonnegative_int_field_diagnostic(
            count,
            f"{field}.{key}",
            category="invalid-count",
        )
        if count_diagnostic is not None:
            return count_diagnostic
    return None


def _readiness_status_value_input_diagnostic(value: Any, field: str, *, category: str) -> dict[str, str] | None:
    if not isinstance(value, str):
        return {"category": category, "field": field, "status": "<invalid>"}
    status = value.strip()
    if status not in READINESS_STATUS_VALUES:
        return {"category": category, "field": field, "status": "<blank>" if not status else "<invalid>"}
    return None


def _readiness_safe_identifier_input_diagnostic(value: Any, field: str, *, category: str) -> dict[str, str] | None:
    if not isinstance(value, str):
        return {"category": category, "field": field, "reason": "non_string"}
    if not _valid_readiness_required_corpus_id(value):
        return {"category": category, "field": field, "reason": "invalid_string"}
    return None


def _readiness_optional_checksum_input_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, str) or READINESS_SHA256_RE.match(value) is None:
        return {"category": "invalid-checksum", "field": field}
    return None


def _optional_readiness_path_status_input_diagnostic(gate: Mapping[str, Any]) -> dict[str, str] | None:
    acquisition_statuses = gate.get("acquisitionStatuses")
    if isinstance(acquisition_statuses, Mapping):
        for key, acquisition in acquisition_statuses.items():
            if not isinstance(acquisition, Mapping):
                continue
            field_key = str(key) if isinstance(key, str) and _valid_readiness_required_corpus_id(key) else "<unsafe>"
            diagnostic = _readiness_acquisition_path_status_input_diagnostic(
                acquisition,
                f"acquisitionStatuses.{field_key}",
                require_available=False,
            )
            if diagnostic is not None:
                return diagnostic

    case_statuses = gate.get("caseStatuses")
    if (
        isinstance(case_statuses, Sequence)
        and not isinstance(case_statuses, (str, bytes, bytearray))
    ):
        for index, case_status in enumerate(case_statuses):
            if not isinstance(case_status, Mapping):
                continue
            diagnostic = _readiness_case_path_status_input_diagnostic(
                case_status,
                f"caseStatuses.{index}",
                require_available=False,
            )
            if diagnostic is not None:
                return diagnostic
    return None


def _readiness_acquisition_path_status_input_diagnostic(
    acquisition: Mapping[str, Any],
    field_prefix: str,
    *,
    require_available: bool,
) -> dict[str, str] | None:
    for field in ("localPath", "resolvedLocalPath"):
        if field in acquisition:
            return {"category": "forbidden-field", "field": f"{field_prefix}.{field}"}

    local_path_diagnostic = _readiness_status_field_input_diagnostic(
        acquisition,
        "localPathStatus",
        field_prefix,
        allowed_values=LOCAL_PATH_STATUS_VALUES,
        required=require_available,
        expected_value="available" if require_available else None,
    )
    if local_path_diagnostic is not None:
        return local_path_diagnostic

    return _readiness_status_field_input_diagnostic(
        acquisition,
        "resolvedLocalPathStatus",
        field_prefix,
        allowed_values=RESOLVED_LOCAL_PATH_STATUS_VALUES,
        required=require_available,
        expected_value="available" if require_available else None,
    )


def _readiness_case_path_status_input_diagnostic(
    case_status: Mapping[str, Any],
    field_prefix: str,
    *,
    require_available: bool,
) -> dict[str, str] | None:
    if "resolvedPath" in case_status:
        return {"category": "forbidden-field", "field": f"{field_prefix}.resolvedPath"}
    if "sourcePath" in case_status:
        source_path = case_status.get("sourcePath")
        source_path_field = f"{field_prefix}.sourcePath"
        if not isinstance(source_path, str) or not source_path.strip() or source_path != source_path.strip():
            return {
                "category": "invalid-readiness-source-path",
                "field": source_path_field,
                "reason": "invalid",
            }
        if _unsafe_readiness_source_path(source_path):
            return {
                "category": "invalid-readiness-source-path",
                "field": source_path_field,
                "reason": "unsafe",
            }

    resolved_path_diagnostic = _readiness_status_field_input_diagnostic(
        case_status,
        "resolvedPathStatus",
        field_prefix,
        allowed_values=CASE_RESOLVED_PATH_STATUS_VALUES,
        required=require_available,
        expected_value="available" if require_available else None,
    )
    if resolved_path_diagnostic is not None:
        return resolved_path_diagnostic

    source_path_status = case_status.get("sourcePathStatus")
    if "sourcePathStatus" in case_status:
        if not isinstance(source_path_status, str) or source_path_status not in SOURCE_PATH_STATUS_VALUES:
            return {
                "category": "invalid-readiness-path-status",
                "field": f"{field_prefix}.sourcePathStatus",
                "reason": "unknown-status-value",
            }
        if require_available:
            return {
                "category": "invalid-readiness-path-status",
                "field": f"{field_prefix}.sourcePathStatus",
                "reason": "available-case-source-path-status",
            }
    return None


def _unsafe_readiness_source_path(source_path: str) -> bool:
    normalized = source_path.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return True
    if len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/" and normalized[0].isalpha():
        return True
    return any(part == ".." for part in normalized.split("/"))


def _readiness_status_field_input_diagnostic(
    owner: Mapping[str, Any],
    field: str,
    field_prefix: str,
    *,
    allowed_values: set[str],
    required: bool,
    expected_value: str | None = None,
) -> dict[str, str] | None:
    full_field = f"{field_prefix}.{field}"
    if field not in owner:
        if required:
            return {"category": "missing-field", "field": full_field}
        return None
    value = owner.get(field)
    if not isinstance(value, str) or value not in allowed_values:
        return {
            "category": "invalid-readiness-path-status",
            "field": full_field,
            "reason": "unknown-status-value",
        }
    if expected_value is not None and value != expected_value:
        return {
            "category": "invalid-readiness-path-status",
            "field": full_field,
            "reason": "available-status-not-available",
        }
    return None


def _readiness_external_status_input_diagnostic(
    gate: Mapping[str, Any],
    *,
    required: bool,
    required_corpora: Sequence[str],
) -> dict[str, str] | None:
    if "externalCorpusStatus" not in gate:
        if required:
            return {"category": "missing-field", "field": "externalCorpusStatus"}
        return None
    external_status = gate.get("externalCorpusStatus")
    if not isinstance(external_status, Mapping):
        return {"category": "invalid-field", "field": "externalCorpusStatus", "type": type(external_status).__name__}
    for key, value in external_status.items():
        field_key = _readiness_external_status_key_field(key)
        field_prefix = f"externalCorpusStatus.{field_key}"
        if field_key == "<unsafe>":
            return {
                "category": "invalid-external-corpus-status",
                "field": field_prefix,
                "reason": "invalid-key",
            }
        if not isinstance(value, Mapping):
            return {"category": "invalid-field", "field": field_prefix, "type": type(value).__name__}
        observed_status = value.get("status")
        if (
            observed_status is not None
            and (
                not isinstance(observed_status, str)
                or not _safe_readiness_status_value(observed_status)
                or (required and observed_status not in LEGACY_EXTERNAL_CORPUS_STATUS_VALUES)
            )
        ):
            return {
                "category": "invalid-external-corpus-status",
                "field": f"{field_prefix}.status",
                "status": "<invalid>",
            }
        reason_code_diagnostic = _optional_reason_codes_diagnostic(
            value.get("reasonCodes"),
            f"{field_prefix}.reasonCodes",
        )
        if reason_code_diagnostic is not None:
            return reason_code_diagnostic
        if value.get("status") == "available" and list(value.get("reasonCodes") or []):
            return {
                "category": "invalid-external-corpus-status",
                "field": f"{field_prefix}.reasonCodes",
                "reason": "non-empty",
            }
        acquisition_ids_diagnostic = _optional_acquisition_ids_diagnostic(
            value.get("acquisitionIds"),
            f"{field_prefix}.acquisitionIds",
        )
        if acquisition_ids_diagnostic is not None:
            return acquisition_ids_diagnostic

    if required:
        external_corpus_names = [_readiness_external_corpus_name(corpus_id) for corpus_id in required_corpora]
        external_name_counts = {
            name: external_corpus_names.count(name)
            for name in set(external_corpus_names)
        }
        for corpus_id in required_corpora:
            if not _external_status_projects_required_corpus(
                external_status,
                corpus_id,
                external_name_counts=external_name_counts,
            ):
                return {
                    "category": "invalid-external-corpus-status",
                    "reason": "required-corpus-projection-missing",
                    "acquisitionId": corpus_id,
                }
    return None


def _readiness_external_status_key_field(key: Any) -> str:
    if isinstance(key, str) and _valid_readiness_required_corpus_id(key):
        return key
    return "<unsafe>"


def _safe_readiness_status_value(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        and READINESS_REQUIRED_CORPUS_ID_RE.match(value) is not None
    )


def _mapping_field_input_diagnostic(
    owner: Mapping[str, Any],
    field: str,
    *,
    field_prefix: str | None = None,
) -> dict[str, str] | None:
    full_field = f"{field_prefix}.{field}" if field_prefix else field
    if field not in owner:
        return {"category": "missing-field", "field": full_field}
    value = owner.get(field)
    if not isinstance(value, Mapping):
        return {"category": "invalid-field", "field": full_field, "type": type(value).__name__}
    return None


def _optional_reason_codes_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return {"category": "invalid-field", "field": field, "type": type(value).__name__}
    for index, reason in enumerate(value):
        if not isinstance(reason, str):
            return {
                "category": "invalid-reason-code",
                "field": f"{field}.{index}",
                "type": type(reason).__name__,
            }
        if not reason.strip():
            return {
                "category": "invalid-reason-code",
                "field": f"{field}.{index}",
                "reason": "blank",
            }
        if not _valid_readiness_reason_code(reason):
            return {
                "category": "invalid-reason-code",
                "field": f"{field}.{index}",
                "reason": "invalid_string",
            }
    return None


def _valid_readiness_reason_code(value: str) -> bool:
    return (
        value == value.strip()
        and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        and value in READINESS_REASON_CODE_ALLOWLIST
    )


def _positive_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _external_status_projects_required_corpus(
    external_status: Mapping[str, Any],
    corpus_id: str,
    *,
    external_name_counts: Mapping[str, int],
) -> bool:
    external_name = _readiness_external_corpus_name(corpus_id)
    for key, value in external_status.items():
        if not isinstance(value, Mapping) or value.get("status") != "available":
            continue
        acquisition_ids = value.get("acquisitionIds")
        if acquisition_ids is not None:
            if corpus_id in {
                item
                for item in acquisition_ids
                if isinstance(item, str) and _valid_readiness_required_corpus_id(item)
            }:
                return True
            continue
        if not isinstance(key, str):
            continue
        normalized_key = key
        if normalized_key == corpus_id:
            return True
        if normalized_key == external_name and external_name_counts.get(external_name, 0) == 1:
            return True
    return False


def _optional_acquisition_ids_diagnostic(value: Any, field: str) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return {"category": "invalid-field", "field": field, "type": type(value).__name__}
    for index, item in enumerate(value):
        if not isinstance(item, str):
            return {"category": "invalid-acquisition-id", "field": f"{field}.{index}", "reason": "non_string"}
        if not _valid_readiness_required_corpus_id(item):
            return {"category": "invalid-acquisition-id", "field": f"{field}.{index}", "reason": "invalid_string"}
    return None


def _readiness_external_corpus_name(corpus_id: str) -> str:
    lowered = corpus_id.lower()
    if "juliet" in lowered:
        return "juliet"
    if "sard" in lowered:
        return "sard"
    return "external"


def _external_corpus_status_is_available_only(external_corpus_status: Any) -> bool:
    if not isinstance(external_corpus_status, Mapping) or not external_corpus_status:
        return False
    projected = [
        value
        for value in external_corpus_status.values()
        if isinstance(value, Mapping)
    ]
    return bool(projected) and all(value.get("status") == "available" for value in projected)


def _normalize_matching_policy(matching_policy: Any) -> tuple[dict[str, Any], dict[str, str] | None]:
    if not isinstance(matching_policy, Mapping):
        payload = {"category": "non-mapping", "type": type(matching_policy).__name__}
        return _invalid_matching_policy(payload), payload

    for key in matching_policy:
        if not isinstance(key, str):
            payload = {"category": "unknown-field", "field": "<invalid>", "type": type(key).__name__}
            return _invalid_matching_policy(payload), payload
    normalized_input = dict(matching_policy)
    diagnostic = _matching_policy_input_diagnostic(normalized_input)
    if diagnostic is not None:
        return _invalid_matching_policy(diagnostic), diagnostic

    return {
        "schemaVersion": MATCHING_POLICY_SCHEMA_VERSION,
        "lineWindowDefault": int(normalized_input.get("lineWindowDefault", MATCHING_POLICY_DEFAULT_LINE_WINDOW)),
        "functionFallbackDefault": bool(normalized_input.get("functionFallbackDefault", False)),
    }, None


def _invalid_matching_policy(input_diagnostic: Mapping[str, str]) -> dict[str, Any]:
    policy = {
        "schemaVersion": MATCHING_POLICY_SCHEMA_VERSION,
        "lineWindowDefault": MATCHING_POLICY_DEFAULT_LINE_WINDOW,
        "functionFallbackDefault": False,
        "inputInvalid": True,
        "invalidInputCategory": input_diagnostic.get("category", "invalid"),
    }
    if "type" in input_diagnostic:
        policy["invalidInputType"] = input_diagnostic["type"]
    if "field" in input_diagnostic:
        policy["invalidInputField"] = input_diagnostic["field"]
    if "value" in input_diagnostic:
        policy["invalidInputValue"] = input_diagnostic["value"]
    return policy


def _matching_policy_input_diagnostic(policy: Mapping[str, Any]) -> dict[str, str] | None:
    unknown_keys = sorted(key for key in policy if key not in MATCHING_POLICY_ALLOWED_KEYS)
    if unknown_keys:
        return {"category": "unknown-field", "field": "<invalid>"}

    schema_version = policy.get("schemaVersion", MATCHING_POLICY_SCHEMA_VERSION)
    if not isinstance(schema_version, str):
        return {"category": "invalid-field", "field": "schemaVersion", "type": type(schema_version).__name__}
    if schema_version != MATCHING_POLICY_SCHEMA_VERSION:
        return {
            "category": "invalid-schema-version",
            "field": "schemaVersion",
            "value": "<invalid>",
        }

    line_window = policy.get("lineWindowDefault", MATCHING_POLICY_DEFAULT_LINE_WINDOW)
    if type(line_window) is not int:
        return {"category": "invalid-field", "field": "lineWindowDefault", "type": type(line_window).__name__}
    if not 0 <= line_window <= MATCHING_POLICY_MAX_LINE_WINDOW:
        return {
            "category": "invalid-range",
            "field": "lineWindowDefault",
            "value": "<invalid>",
            "expected": f"0..{MATCHING_POLICY_MAX_LINE_WINDOW}",
        }

    function_fallback = policy.get("functionFallbackDefault", False)
    if not isinstance(function_fallback, bool):
        return {
            "category": "invalid-field",
            "field": "functionFallbackDefault",
            "type": type(function_fallback).__name__,
        }
    return None


def _normalize_findings_by_config(
    findings_by_config: Any,
    *,
    required_configs: Sequence[str],
) -> tuple[dict[str, list[SastFinding | Mapping[str, Any]]], dict[str, str] | None]:
    if not isinstance(findings_by_config, Mapping):
        return {}, {"category": "non-mapping", "type": type(findings_by_config).__name__}

    normalized: dict[str, list[SastFinding | Mapping[str, Any]]] = {}
    for config in required_configs:
        if config not in findings_by_config:
            return {}, {"category": "missing-required-config", "config": config}
        value = findings_by_config.get(config)
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
            return {}, {
                "category": "invalid-config-findings",
                "config": config,
                "type": type(value).__name__,
            }
        items: list[SastFinding | Mapping[str, Any]] = []
        for index, item in enumerate(value):
            if not isinstance(item, (SastFinding, Mapping)):
                return {}, {
                    "category": "invalid-finding-element",
                    "config": config,
                    "index": str(index),
                    "type": type(item).__name__,
                }
            tool_diagnostic = _finding_tool_id_diagnostic(item, config=config, index=index)
            if tool_diagnostic is not None:
                return {}, tool_diagnostic
            if isinstance(item, Mapping):
                item, payload_diagnostic = _normalize_mapping_finding_payload(item, config=config, index=index)
                if payload_diagnostic is not None:
                    return {}, payload_diagnostic
            items.append(item)
        normalized[config] = items

    for config, value in findings_by_config.items():
        key = str(config)
        if key in normalized:
            continue
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            normalized[key] = [item for item in value if isinstance(item, (SastFinding, Mapping))]
    return normalized, None


def _finding_tool_id_diagnostic(
    item: SastFinding | Mapping[str, Any],
    *,
    config: str,
    index: int,
) -> dict[str, str] | None:
    tool_id = _finding_tool_id(item)
    if tool_id is None:
        return {
            "category": "invalid-finding-tool-id",
            "config": config,
            "index": str(index),
            "reason": "missing-or-non-string",
        }
    if tool_id not in ALL_TOOLS:
        return {
            "category": "invalid-finding-tool-id",
            "config": config,
            "index": str(index),
            "reason": "unknown-tool",
        }
    if config.startswith("single-tool:"):
        expected_tool = config.removeprefix("single-tool:")
        if tool_id != expected_tool:
            return {
                "category": "invalid-finding-tool-id",
                "config": config,
                "index": str(index),
                "reason": "single-tool-mismatch",
                "expectedTool": expected_tool,
            }
    if config.startswith("leave-one-out:"):
        excluded_tool = config.removeprefix("leave-one-out:")
        if tool_id == excluded_tool:
            return {
                "category": "invalid-finding-tool-id",
                "config": config,
                "index": str(index),
                "reason": "leave-one-out-excluded-tool",
                "excludedTool": excluded_tool,
            }
    return None


def _finding_tool_id(item: SastFinding | Mapping[str, Any]) -> str | None:
    if isinstance(item, SastFinding):
        raw_tool = item.tool_id
    elif "toolId" in item:
        raw_tool = item.get("toolId")
    else:
        raw_tool = item.get("tool_id")
    if not isinstance(raw_tool, str):
        return None
    stripped = raw_tool.strip()
    if not stripped or stripped != raw_tool:
        return None
    return stripped


def _normalize_mapping_finding_payload(
    item: Mapping[str, Any],
    *,
    config: str,
    index: int,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    rule_id = item.get("ruleId") if "ruleId" in item else item.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        return {}, _invalid_finding_payload(config, index, field="ruleId", reason="missing-or-blank")
    if rule_id != rule_id.strip():
        return {}, _invalid_finding_payload(config, index, field="ruleId", reason="surrounding-whitespace")

    location = item.get("location")
    if location is not None and not isinstance(location, Mapping):
        return {}, _invalid_finding_payload(
            config,
            index,
            field="location",
            reason="non-mapping",
            value_type=type(location).__name__,
        )
    location_map = location if isinstance(location, Mapping) else {}

    resolved_file = location_map.get("file") if "file" in location_map else item.get("file")
    if not isinstance(resolved_file, str) or not resolved_file.strip():
        return {}, _invalid_finding_payload(config, index, field="file", reason="missing-or-blank")
    if resolved_file != resolved_file.strip():
        return {}, _invalid_finding_payload(config, index, field="file", reason="surrounding-whitespace")

    resolved_line = location_map.get("line") if "line" in location_map else item.get("line")
    line_diagnostic = _line_diagnostic(resolved_line, config=config, index=index, field="line")
    if line_diagnostic is not None:
        return {}, line_diagnostic

    column = location_map.get("column", item.get("column", 1))
    if isinstance(column, bool) or not isinstance(column, int) or column <= 0 or column > 1_000_000:
        column = 1

    metadata = item.get("metadata")
    if metadata is not None and not isinstance(metadata, Mapping):
        return {}, _invalid_finding_payload(
            config,
            index,
            field="metadata",
            reason="non-mapping",
            value_type=type(metadata).__name__,
        )

    data_flow_key = "dataFlow" if "dataFlow" in item else "data_flow" if "data_flow" in item else None
    if data_flow_key is not None:
        data_flow = item.get(data_flow_key)
        if (
            isinstance(data_flow, (str, bytes, bytearray))
            or not isinstance(data_flow, Sequence)
        ):
            return {}, _invalid_finding_payload(
                config,
                index,
                field=data_flow_key,
                reason="non-sequence",
                value_type=type(data_flow).__name__,
            )
        for data_flow_index, step in enumerate(data_flow):
            if not isinstance(step, Mapping):
                return {}, _invalid_finding_payload(
                    config,
                    index,
                    field=data_flow_key,
                    reason="invalid-step",
                    value_type=type(step).__name__,
                    data_flow_index=data_flow_index,
                )
            if "line" in step:
                line_diagnostic = _line_diagnostic(
                    step.get("line"),
                    config=config,
                    index=index,
                    field=f"{data_flow_key}.line",
                    data_flow_index=data_flow_index,
                )
                if line_diagnostic is not None:
                    return {}, line_diagnostic

    normalized = dict(item)
    normalized["location"] = {
        **dict(location_map),
        "file": resolved_file,
        "line": resolved_line,
        "column": column,
    }
    return normalized, None


def _line_diagnostic(
    value: Any,
    *,
    config: str,
    index: int,
    field: str,
    data_flow_index: int | None = None,
) -> dict[str, str] | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 1_000_000:
        return _invalid_finding_payload(
            config,
            index,
            field=field,
            reason="invalid-line",
            value_type=type(value).__name__,
            data_flow_index=data_flow_index,
        )
    return None


def _invalid_finding_payload(
    config: str,
    index: int,
    *,
    field: str,
    reason: str,
    value_type: str | None = None,
    data_flow_index: int | None = None,
) -> dict[str, str]:
    diagnostic = {
        "category": "invalid-finding-payload",
        "config": config,
        "index": str(index),
        "field": field,
        "reason": reason,
    }
    if value_type is not None:
        diagnostic["type"] = value_type
    if data_flow_index is not None:
        diagnostic["dataFlowIndex"] = str(data_flow_index)
    return diagnostic


def _targets_by_split(targets: Sequence[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    result: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for target in targets:
        result[str(target.get("split") or "validation")].append(target)
    return dict(result)


def _split_bucket(split: str, by_config: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    status = "pass" if by_config else "not_run"
    return {
        "status": status,
        "split": split,
        "byConfig": dict(by_config),
    }


def _not_run_metric_bucket(split: str, reason_codes: Sequence[str]) -> dict[str, Any]:
    return {
        "status": "not_run",
        "split": split,
        "reasonCodes": list(reason_codes),
        "byConfig": {},
    }


def _local_quality_assessment(
    split_metric_buckets: Mapping[str, Mapping[str, Any]],
    thresholds: Any,
    *,
    blocked: bool = False,
    blocked_reason_codes: Sequence[str] | None = None,
    invalid_report_identity_failures: Sequence[Mapping[str, str]] | None = None,
    invalid_matching_policy_payload: Mapping[str, str] | None = None,
    invalid_findings_by_config_payload: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    invalid_threshold_payload = _invalid_threshold_payload_diagnostic(thresholds)
    if invalid_threshold_payload is not None:
        if blocked:
            result = {
                "status": "blocked",
                "primaryToolSetConfig": "full-current-six",
                "thresholds": {"inputType": invalid_threshold_payload["type"]},
                "reasonCodes": list(blocked_reason_codes or ["SYSTEM_STABILITY_GATE_FAILED"]),
                "invalidThresholdPayload": invalid_threshold_payload,
                "splitAssessments": {},
                "failingSplits": [],
                "passingSplits": [],
                "consumerPolicy": "do_not_score_quality_when_system_gate_failed",
            }
            if invalid_report_identity_failures is not None:
                result["invalidReportIdentity"] = [dict(failure) for failure in invalid_report_identity_failures]
            return result
        if invalid_report_identity_failures is not None:
            return {
                "status": "fail",
                "primaryToolSetConfig": "full-current-six",
                "thresholds": {"inputType": invalid_threshold_payload["type"]},
                "reasonCodes": [REPORT_IDENTITY_REASON_CODE],
                "invalidReportIdentity": [dict(failure) for failure in invalid_report_identity_failures],
                "splitAssessments": {},
                "failingSplits": [],
                "passingSplits": [],
                "consumerPolicy": "report_identity_configuration_invalid",
            }
        return {
            "status": "fail",
            "primaryToolSetConfig": "full-current-six",
            "thresholds": {"inputType": invalid_threshold_payload["type"]},
            "reasonCodes": ["QUALITY_THRESHOLDS_INPUT_INVALID"],
            "invalidThresholdPayload": invalid_threshold_payload,
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "quality_threshold_configuration_invalid",
        }

    primary_config, invalid_primary_config = _normalize_primary_tool_set_config(thresholds)
    threshold_snapshot = _json_safe_thresholds(
        thresholds,
        invalid_primary_tool_set_config=invalid_primary_config is not None,
    )
    required_splits, invalid_required_splits = _normalize_required_splits(
        thresholds.get("requiredSplits", CANONICAL_SPLIT_ORDER)
    )
    if blocked:
        result = {
            "status": "blocked",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": list(blocked_reason_codes or ["SYSTEM_STABILITY_GATE_FAILED"]),
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "do_not_score_quality_when_system_gate_failed",
        }
        if invalid_report_identity_failures is not None:
            result["invalidReportIdentity"] = [dict(failure) for failure in invalid_report_identity_failures]
        if invalid_matching_policy_payload is not None:
            result["invalidMatchingPolicyPayload"] = dict(invalid_matching_policy_payload)
        if invalid_findings_by_config_payload is not None:
            result["invalidFindingsByConfigPayload"] = dict(invalid_findings_by_config_payload)
        return result
    if invalid_report_identity_failures is not None:
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": [REPORT_IDENTITY_REASON_CODE],
            "invalidReportIdentity": [dict(failure) for failure in invalid_report_identity_failures],
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "report_identity_configuration_invalid",
        }
    if invalid_matching_policy_payload is not None:
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": ["ORACLE_MATCHING_POLICY_INPUT_INVALID"],
            "invalidMatchingPolicyPayload": dict(invalid_matching_policy_payload),
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "oracle_matching_policy_configuration_invalid",
        }
    if invalid_findings_by_config_payload is not None:
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": ["FINDINGS_BY_CONFIG_INPUT_INVALID"],
            "invalidFindingsByConfigPayload": dict(invalid_findings_by_config_payload),
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "oracle_findings_input_configuration_invalid",
        }
    if invalid_required_splits is not None:
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": [QUALITY_REQUIRED_SPLITS_INVALID_REASON],
            "invalidRequiredSplits": dict(invalid_required_splits),
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "quality_threshold_configuration_invalid",
        }
    if not required_splits:
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": ["QUALITY_REQUIRED_SPLITS_NOT_DECLARED"],
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "quality_threshold_configuration_invalid",
        }
    if not _declared_quality_threshold_fields(thresholds):
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": ["QUALITY_THRESHOLDS_NOT_DECLARED"],
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "quality_threshold_configuration_invalid",
        }
    if invalid_primary_config is not None:
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": ["QUALITY_PRIMARY_TOOL_SET_CONFIG_INVALID"],
            "invalidPrimaryToolSetConfig": invalid_primary_config,
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "quality_threshold_configuration_invalid",
        }
    invalid_threshold_fields = _invalid_quality_threshold_fields(thresholds)
    if invalid_threshold_fields:
        return {
            "status": "fail",
            "primaryToolSetConfig": primary_config,
            "thresholds": threshold_snapshot,
            "reasonCodes": ["QUALITY_THRESHOLD_VALUE_INVALID"],
            "invalidThresholdFields": invalid_threshold_fields,
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "quality_threshold_configuration_invalid",
        }

    threshold_profile = _threshold_profile(thresholds)
    split_assessments: dict[str, dict[str, Any]] = {}
    failing_splits: list[str] = []
    passing_splits: list[str] = []
    aggregate_reason_codes: set[str] = set()

    for split in required_splits:
        bucket = split_metric_buckets.get(split) or {}
        by_config = bucket.get("byConfig") if isinstance(bucket.get("byConfig"), Mapping) else {}
        metrics = by_config.get(primary_config) if isinstance(by_config, Mapping) else None
        assessment = _assess_split_quality(split, metrics, thresholds, threshold_profile=threshold_profile)
        split_assessments[split] = assessment
        if assessment["status"] == "pass":
            passing_splits.append(split)
        else:
            failing_splits.append(split)
            aggregate_reason_codes.update(assessment["reasonCodes"])

    local_status = "fail" if failing_splits else "pass"
    reason_codes = sorted(aggregate_reason_codes)
    consumer_policy = "local_oracle_metrics_are_not_decision_grade_without_external_corpus"
    if not failing_splits and threshold_profile["status"] == "not_decision_grade":
        local_status = "not_decision_grade"
        reason_codes = list(threshold_profile.get("reasonCodes") or [QUALITY_THRESHOLDS_NON_DISCRIMINATING_REASON])
        consumer_policy = "runner_integrity_thresholds_are_not_quality_sufficiency_evidence"

    return {
        "status": local_status,
        "primaryToolSetConfig": primary_config,
        "thresholds": threshold_snapshot,
        "thresholdProfile": threshold_profile,
        "reasonCodes": reason_codes,
        "splitAssessments": split_assessments,
        "failingSplits": failing_splits,
        "passingSplits": passing_splits,
        "consumerPolicy": consumer_policy,
    }


def _assess_split_quality(
    split: str,
    metrics: Mapping[str, Any] | None,
    thresholds: Mapping[str, Any],
    *,
    threshold_profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(metrics, Mapping):
        return {
            "status": "fail",
            "split": split,
            "reasonCodes": ["SPLIT_METRICS_MISSING"],
            "metrics": {},
        }

    reason_codes: list[str] = []
    target_recall = metrics.get("targetRecall")
    finding_precision = metrics.get("findingPrecision")
    negative_target_fpr = metrics.get("negativeTargetFpr")

    minimum_target_recall = thresholds.get("minimumTargetRecall")
    if minimum_target_recall is not None and (
        _metric_missing_for_threshold(target_recall, "minimumTargetRecall", threshold_profile)
        or (target_recall is not None and float(target_recall) < float(minimum_target_recall))
    ):
        reason_codes.append("TARGET_RECALL_BELOW_THRESHOLD")

    minimum_finding_precision = thresholds.get("minimumFindingPrecision")
    if minimum_finding_precision is not None and (
        _metric_missing_for_threshold(finding_precision, "minimumFindingPrecision", threshold_profile)
        or (finding_precision is not None and float(finding_precision) < float(minimum_finding_precision))
    ):
        reason_codes.append("FINDING_PRECISION_BELOW_THRESHOLD")

    maximum_negative_target_fpr = thresholds.get("maximumNegativeTargetFpr")
    if (
        maximum_negative_target_fpr is not None
        and negative_target_fpr is not None
        and float(negative_target_fpr) > float(maximum_negative_target_fpr)
    ):
        reason_codes.append("NEGATIVE_TARGET_FPR_ABOVE_THRESHOLD")

    return {
        "status": "fail" if reason_codes else "pass",
        "split": split,
        "reasonCodes": reason_codes,
        "metrics": {
            "targetRecall": target_recall,
            "findingPrecision": finding_precision,
            "negativeTargetFpr": negative_target_fpr,
            "targetTP": metrics.get("targetTP"),
            "targetFN": metrics.get("targetFN"),
            "fpFindings": metrics.get("fpFindings"),
            "negativeTargetViolationCount": metrics.get("negativeTargetViolationCount"),
            "negativeTargetCleanCount": metrics.get("negativeTargetCleanCount"),
        },
    }


def _metric_missing_for_threshold(
    value: Any,
    threshold_field: str,
    threshold_profile: Mapping[str, Any] | None,
) -> bool:
    if value is not None:
        return False
    non_discriminating = set(threshold_profile.get("nonDiscriminatingThresholdFields") or []) if threshold_profile else set()
    return threshold_field not in non_discriminating


def _normalize_required_splits(required_splits: Any) -> tuple[list[str], dict[str, str] | None]:
    if required_splits is None:
        raw_splits: Sequence[Any] = CANONICAL_SPLIT_ORDER
        invalid_entry_seen = False
    elif isinstance(required_splits, str):
        raw_splits = [required_splits]
        invalid_entry_seen = False
    elif isinstance(required_splits, Sequence) and not isinstance(required_splits, (bytes, bytearray)):
        raw_splits = required_splits
        invalid_entry_seen = False
    else:
        raw_splits = []
        invalid_entry_seen = True
    seen: set[str] = set()
    for split in raw_splits:
        if not isinstance(split, str):
            invalid_entry_seen = True
            continue
        normalized = split.strip()
        if not normalized:
            continue
        if normalized in CANONICAL_SPLIT_ORDER:
            seen.add(normalized)
        else:
            invalid_entry_seen = True
    known = [split for split in CANONICAL_SPLIT_ORDER if split in seen]
    invalid_diagnostic = {"category": "invalid-entry"} if invalid_entry_seen else None
    return known, invalid_diagnostic


def _invalid_threshold_payload_diagnostic(thresholds: Any) -> dict[str, str] | None:
    if not isinstance(thresholds, Mapping):
        return {"category": "non-mapping", "type": type(thresholds).__name__}
    return _non_json_serializable_value_diagnostic(thresholds)


def _thresholds_checksum_input(
    thresholds: Any,
    *,
    invalid_threshold_payload: Mapping[str, str] | None,
) -> Any:
    if invalid_threshold_payload is None:
        return thresholds
    return {
        "inputInvalid": True,
        "reasonCode": "QUALITY_THRESHOLDS_INPUT_INVALID",
        "diagnostic": dict(sorted(invalid_threshold_payload.items())),
    }


def _non_json_serializable_value_diagnostic(value: Any, *, field_path: str = "") -> dict[str, str] | None:
    if value is None or isinstance(value, (str, int, float, bool)):
        return None

    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                return {
                    "category": "non-json-serializable",
                    "field": _join_field_path(field_path, "<invalid>"),
                    "type": type(key).__name__,
                }
            diagnostic_segment = _threshold_diagnostic_field_segment(key, field_path=field_path)
            diagnostic = _non_json_serializable_value_diagnostic(
                nested,
                field_path=_join_field_path(field_path, diagnostic_segment),
            )
            if diagnostic is not None:
                return diagnostic
        return None

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            diagnostic = _non_json_serializable_value_diagnostic(
                nested,
                field_path=_join_field_path(field_path, str(index)),
            )
            if diagnostic is not None:
                return diagnostic
        return None

    return {
        "category": "non-json-serializable",
        "field": field_path or "$",
        "type": type(value).__name__,
    }


def _threshold_diagnostic_field_segment(key: str, *, field_path: str) -> str:
    if not field_path and key in QUALITY_THRESHOLD_CONFIG_FIELD_SET:
        return key
    return "<invalid>"


def _join_field_path(prefix: str, segment: str) -> str:
    return f"{prefix}.{segment}" if prefix else segment


def _normalize_primary_tool_set_config(thresholds: Mapping[str, Any]) -> tuple[str, dict[str, str] | None]:
    raw_value = thresholds.get("primaryToolSetConfig")
    default_config = "full-current-six"
    if "primaryToolSetConfig" not in thresholds or raw_value is None:
        return default_config, None
    if not isinstance(raw_value, str):
        return default_config, {"category": "non-string", "type": type(raw_value).__name__}

    normalized = raw_value.strip()
    if not normalized:
        return default_config, {"category": "blank"}
    if normalized not in set(required_current_six_configs()):
        return default_config, {"category": "unknown", "value": "<invalid>"}
    return normalized, None


def _declared_quality_threshold_fields(thresholds: Mapping[str, Any]) -> list[str]:
    return [field for field in QUALITY_THRESHOLD_FIELDS if thresholds.get(field) is not None]


def _invalid_quality_threshold_fields(thresholds: Mapping[str, Any]) -> list[str]:
    return [
        field
        for field in QUALITY_THRESHOLD_FIELDS
        if thresholds.get(field) is not None and not _is_valid_quality_threshold_value(thresholds.get(field))
    ]


def _is_valid_quality_threshold_value(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    numeric_value = float(value)
    return math.isfinite(numeric_value) and 0.0 <= numeric_value <= 1.0


def _threshold_profile(thresholds: Mapping[str, Any]) -> dict[str, Any]:
    declared_fields = _declared_quality_threshold_fields(thresholds)
    discriminating_fields: list[str] = []
    non_discriminating_fields: list[str] = []

    for field in QUALITY_THRESHOLD_FIELDS:
        if field not in declared_fields:
            continue
        numeric_value = float(thresholds[field])
        if _is_non_discriminating_quality_threshold(field, numeric_value):
            non_discriminating_fields.append(field)
        else:
            discriminating_fields.append(field)

    if declared_fields and not discriminating_fields:
        return {
            "status": "not_decision_grade",
            "intent": "runner-integrity-only",
            "reasonCodes": [QUALITY_THRESHOLDS_NON_DISCRIMINATING_REASON],
            "nonDiscriminatingThresholdFields": non_discriminating_fields,
        }

    profile: dict[str, Any] = {
        "status": "decision_grade_candidate",
        "intent": "quality-sufficiency",
        "reasonCodes": [],
        "discriminatingThresholdFields": discriminating_fields,
    }
    if non_discriminating_fields:
        profile["nonDiscriminatingThresholdFields"] = non_discriminating_fields
    return profile


def _is_non_discriminating_quality_threshold(field: str, value: float) -> bool:
    if field in {"minimumTargetRecall", "minimumFindingPrecision"}:
        return value <= 0.0
    if field == "maximumNegativeTargetFpr":
        return value >= 1.0
    return False


def _json_safe_thresholds(
    thresholds: Mapping[str, Any],
    *,
    invalid_primary_tool_set_config: bool = False,
) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for field in QUALITY_THRESHOLD_FIELDS:
        if field in thresholds:
            sanitized[field] = _json_safe_quality_threshold_value(thresholds[field])
    if "requiredSplits" in thresholds:
        sanitized["requiredSplits"] = _json_safe_required_splits(thresholds["requiredSplits"])
    if "primaryToolSetConfig" in thresholds:
        sanitized["primaryToolSetConfig"] = _json_safe_primary_tool_set_config(
            thresholds["primaryToolSetConfig"],
            invalid=invalid_primary_tool_set_config,
        )
    return sanitized


def _json_safe_quality_threshold_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "<invalid>"
    if isinstance(value, float) and not math.isfinite(value):
        return "non-finite"
    return value


def _json_safe_required_splits(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized if normalized in CANONICAL_SPLIT_ORDER else "<invalid>"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            split.strip() if isinstance(split, str) and split.strip() in CANONICAL_SPLIT_ORDER else "<invalid>"
            for split in value
        ]
    return "<invalid>"


def _json_safe_primary_tool_set_config(value: Any, *, invalid: bool) -> Any:
    if value is None:
        return None
    if invalid:
        return "<invalid>"
    if not isinstance(value, str):
        return "<invalid>"
    normalized = value.strip()
    return normalized if normalized in set(required_current_six_configs()) else "<invalid>"


def _compose_quality_gate(
    prerequisite_quality_gate: Mapping[str, Any],
    local_quality_assessment: Mapping[str, Any],
) -> dict[str, Any]:
    gate = dict(prerequisite_quality_gate)
    gate["localQualityAssessment"] = dict(local_quality_assessment)
    local_status = local_quality_assessment.get("status")

    if gate.get("status") == "blocked":
        return gate

    if gate.get("status") == "not_decision_grade":
        reason_codes = set(gate.get("reasonCodes") or [])
        if local_status == "fail":
            reason_codes.add("LOCAL_ORACLE_QUALITY_FAILED")
            reason_codes.update(str(reason) for reason in (local_quality_assessment.get("reasonCodes") or []) if str(reason))
        if local_status == "not_decision_grade":
            reason_codes.update(str(reason) for reason in (local_quality_assessment.get("reasonCodes") or []) if str(reason))
        gate["reasonCodes"] = sorted(reason_codes)
        gate["consumerPolicy"] = "local_quality_assessment_available_but_not_decision_grade"
        return gate

    if local_status == "fail":
        return {
            **gate,
            "status": "fail",
            "decision": "quality-gate-failed",
            "reasonCodes": list(local_quality_assessment.get("reasonCodes") or ["LOCAL_ORACLE_QUALITY_FAILED"]),
            "consumerPolicy": "quality_metrics_failed_thresholds",
        }
    if local_status == "not_decision_grade":
        return {
            **gate,
            "status": "not_decision_grade",
            "decision": "insufficient-evidence-for-tool-change",
            "reasonCodes": list(local_quality_assessment.get("reasonCodes") or [QUALITY_THRESHOLDS_NON_DISCRIMINATING_REASON]),
            "consumerPolicy": "quality_threshold_profile_not_decision_grade",
        }
    if local_status == "pass":
        return {
            **gate,
            "status": "pass",
            "decision": "quality-gate-pass",
            "reasonCodes": [],
            "consumerPolicy": "quality_metrics_passed_thresholds",
        }
    return {
        **gate,
        "status": "partial",
        "decision": "quality-gate-partial",
        "reasonCodes": list(local_quality_assessment.get("reasonCodes") or ["LOCAL_ORACLE_QUALITY_PARTIAL"]),
        "consumerPolicy": "quality_metrics_partial",
    }


def _runtime_stability_bucket(system_stability_gate: Mapping[str, Any]) -> dict[str, Any]:
    status = system_stability_gate.get("status")
    if status == "fail":
        return {
            "status": "fail",
            "reasonCodes": list(system_stability_gate.get("reasonCodes") or []),
            "consumerPolicy": "blocks_quality_evaluation",
        }
    if status == "pass":
        return {
            "status": "pass",
            "reasonCodes": [],
            "consumerPolicy": "quality_gate_eligible",
        }
    return {
        "status": "not_run",
        "reasonCodes": list(system_stability_gate.get("reasonCodes") or ["HARNESS_FIXTURE_DOES_NOT_EXECUTE_TOOLS"]),
    }


def _filter_findings_to_targets(
    findings: Sequence[SastFinding | Mapping[str, Any]],
    targets: Sequence[Mapping[str, Any]],
) -> list[SastFinding | Mapping[str, Any]]:
    target_files = {str(target.get("sourcePath")) for target in targets if target.get("sourcePath")}
    if not target_files:
        return []
    result: list[SastFinding | Mapping[str, Any]] = []
    for finding in findings:
        if isinstance(finding, SastFinding):
            file_name = finding.location.file
        else:
            location = finding.get("location") if isinstance(finding, Mapping) else None
            file_name = location.get("file") if isinstance(location, Mapping) else None
        if str(file_name) in target_files:
            result.append(finding)
    return result


def _quality_diagnostics(
    *,
    split_metric_buckets: Mapping[str, Mapping[str, Any]],
    findings_by_config: Mapping[str, Sequence[SastFinding | Mapping[str, Any]]],
    split_targets: Mapping[str, Sequence[Mapping[str, Any]]],
    primary_config: str,
    system_gate_failed: bool,
    system_reason_codes: Sequence[str],
    local_input_invalid_reason: str | None,
) -> dict[str, Any]:
    base = {
        "schemaVersion": QUALITY_DIAGNOSTICS_SCHEMA_VERSION,
        "consumerPolicy": "diagnostic_only_not_quality_gate",
        "diagnosticScope": "primary-tool-set-config-only",
        "primaryToolSetConfig": primary_config,
    }
    if system_gate_failed:
        return {
            **base,
            "status": "blocked",
            "reasonCodes": sorted({"SYSTEM_STABILITY_GATE_FAILED", *(str(reason) for reason in system_reason_codes if str(reason))}),
            "splitDiagnostics": {},
        }
    if local_input_invalid_reason is not None:
        return {
            **base,
            "status": "not_run",
            "reasonCodes": [local_input_invalid_reason],
            "splitDiagnostics": {},
        }

    split_diagnostics: dict[str, Any] = {}
    primary_findings = list(findings_by_config.get(primary_config, []))
    for split in CANONICAL_SPLIT_ORDER:
        bucket = split_metric_buckets.get(split) or {}
        by_config = bucket.get("byConfig") if isinstance(bucket.get("byConfig"), Mapping) else {}
        metrics = by_config.get(primary_config) if isinstance(by_config, Mapping) else None
        if not isinstance(metrics, Mapping):
            continue
        targets = list(split_targets.get(split, []))
        split_findings = _filter_findings_to_targets(primary_findings, targets)
        split_diagnostics[split] = _split_quality_diagnostic(
            split=split,
            metrics=metrics,
            targets=targets,
            findings=split_findings,
        )

    if not split_diagnostics:
        return {
            **base,
            "status": "not_run",
            "reasonCodes": ["QUALITY_DIAGNOSTICS_PRIMARY_METRICS_NOT_AVAILABLE"],
            "splitDiagnostics": {},
        }
    return {
        **base,
        "status": "available",
        "reasonCodes": [],
        "splitDiagnostics": split_diagnostics,
    }


def _split_quality_diagnostic(
    *,
    split: str,
    metrics: Mapping[str, Any],
    targets: Sequence[Mapping[str, Any]],
    findings: Sequence[SastFinding | Mapping[str, Any]],
) -> dict[str, Any]:
    target_by_id = {_target_id(target): target for target in targets}
    rows = [row for row in metrics.get("rows", []) if isinstance(row, Mapping)]
    target_outcome_counts = {match_class: 0 for match_class in TARGET_OUTCOME_MATCH_CLASSES}
    by_cwe: dict[str, dict[str, int]] = {}
    by_cwe_tool_working: dict[str, dict[str, dict[str, Any]]] = {}
    by_tool_working: dict[str, dict[str, Any]] = {}
    raw_keys_by_tool: dict[str, set[str]] = defaultdict(set)
    raw_keys: set[str] = set()

    for finding in findings:
        evidence = finding_to_evidence(finding)
        key = _finding_evidence_key(evidence)
        raw_keys.add(key)
        raw_keys_by_tool[evidence.tool_id].add(key)

    tp_keys = {
        str(row.get("findingKey"))
        for row in rows
        if row.get("countsAsTargetTp") is True and row.get("findingKey")
    }
    tp_raw_keys = tp_keys & raw_keys

    for row in rows:
        match_class = str(row.get("matchClass") or "")
        if match_class in target_outcome_counts:
            target_outcome_counts[match_class] += 1
        target = target_by_id.get(str(row.get("targetId") or ""))
        cwe_key = _target_expected_cwe_bucket(target)
        cwe_bucket = by_cwe.setdefault(cwe_key, _empty_cwe_bucket())
        if match_class in TARGET_OUTCOME_MATCH_CLASSES:
            cwe_bucket[match_class] += 1
        if row.get("countsAsTargetTp") is True:
            cwe_bucket["targetTP"] += 1
        elif _target_is_positive(target) and match_class == "missed-target":
            cwe_bucket["targetFN"] += 1
        if match_class == "negative-case-finding":
            cwe_bucket["negativeTargetViolationCount"] += 1

        tool = row.get("toolId")
        if isinstance(tool, str) and tool:
            cwe_tool_bucket = by_cwe_tool_working.setdefault(cwe_key, {}).setdefault(tool, _empty_cwe_tool_bucket())
            if match_class in TARGET_OUTCOME_MATCH_CLASSES:
                cwe_tool_bucket["targetOutcomeCounts"][match_class] = (
                    cwe_tool_bucket["targetOutcomeCounts"].get(match_class, 0) + 1
                )
            if row.get("countsAsTargetTp") is True:
                cwe_tool_bucket["targetTP"] += 1
            if match_class == "negative-case-finding":
                cwe_tool_bucket["negativeTargetViolationCount"] += 1

            tool_bucket = by_tool_working.setdefault(tool, _empty_tool_bucket())
            if match_class in TARGET_OUTCOME_MATCH_CLASSES:
                tool_bucket["targetOutcomeCounts"][match_class] = tool_bucket["targetOutcomeCounts"].get(match_class, 0) + 1

    by_tool: dict[str, dict[str, Any]] = {}
    for tool in sorted(set(raw_keys_by_tool) | set(by_tool_working), key=_tool_sort_key):
        bucket = by_tool_working.setdefault(tool, _empty_tool_bucket())
        raw_tool_keys = raw_keys_by_tool.get(tool, set())
        tp_tool_keys = {key for key in tp_raw_keys if key.startswith(f"{tool}:")}
        bucket["uniqueRawFindingCount"] = len(raw_tool_keys)
        bucket["tpFindingCount"] = len(tp_tool_keys)
        bucket["nonTpRawFindingCount"] = max(0, len(raw_tool_keys - tp_tool_keys))
        by_tool[tool] = bucket
    by_cwe = {cwe: {**bucket, "triageReasonCodes": _cwe_triage_reason_codes(bucket)} for cwe, bucket in by_cwe.items()}
    by_cwe_tool = {
        cwe: {
            tool: {**bucket, "triageReasonCodes": _cwe_tool_triage_reason_codes(bucket)}
            for tool, bucket in sorted(tool_buckets.items(), key=lambda item: _tool_sort_key(item[0]))
        }
        for cwe, tool_buckets in sorted(by_cwe_tool_working.items())
    }

    finding_pressure = {
        "uniqueRawFindingCount": len(raw_keys),
        "tpFindingCount": len(tp_raw_keys),
        "oracleCountedFpFindingCount": int(metrics.get("fpFindings") or 0),
        "nonTpRawFindingCount": max(0, len(raw_keys - tp_raw_keys)),
    }
    metric_summary = _quality_metric_summary(metrics)
    match_attempt_diagnostics = {
        "weakRelatedAttemptCount": int(metrics.get("weakRelatedCount") or 0),
        "wrongCweTargetLocationAttemptCount": int(metrics.get("wrongCweCount") or 0),
    }
    return {
        "status": "available",
        "split": split,
        "metricSummary": metric_summary,
        "targetOutcomeCounts": target_outcome_counts,
        "findingPressure": finding_pressure,
        "matchAttemptDiagnostics": match_attempt_diagnostics,
        "byCwe": by_cwe,
        "byCweTool": by_cwe_tool,
        "byTool": by_tool,
        "diagnosticHints": _quality_diagnostic_hints(metric_summary),
        "diagnosticTriage": _diagnostic_triage(
            metric_summary=metric_summary,
            finding_pressure=finding_pressure,
            match_attempt_diagnostics=match_attempt_diagnostics,
        ),
    }


def _quality_metric_summary(metrics: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "targetRecall": metrics.get("targetRecall"),
        "findingPrecision": metrics.get("findingPrecision"),
        "negativeTargetFpr": metrics.get("negativeTargetFpr"),
        "targetTP": int(metrics.get("targetTP") or 0),
        "targetFN": int(metrics.get("targetFN") or 0),
        "fpFindings": int(metrics.get("fpFindings") or 0),
        "weakRelatedCount": int(metrics.get("weakRelatedCount") or 0),
        "wrongCweCount": int(metrics.get("wrongCweCount") or 0),
        "negativeTargetViolationCount": int(metrics.get("negativeTargetViolationCount") or 0),
        "negativeTargetCleanCount": int(metrics.get("negativeTargetCleanCount") or 0),
    }


def _quality_diagnostic_hints(metric_summary: Mapping[str, Any]) -> list[str]:
    hints: list[str] = []
    if int(metric_summary.get("targetFN") or 0) > 0:
        hints.append(TRIAGE_REASON_RECALL)
    if int(metric_summary.get("fpFindings") or 0) > 0:
        hints.append(TRIAGE_REASON_NOISE)
    if int(metric_summary.get("wrongCweCount") or 0) > 0:
        hints.append(TRIAGE_REASON_WRONG_CWE)
    if int(metric_summary.get("weakRelatedCount") or 0) > 0:
        hints.append(TRIAGE_REASON_WEAK_RELATED)
    if int(metric_summary.get("negativeTargetViolationCount") or 0) > 0:
        hints.append(TRIAGE_REASON_NEGATIVE_VIOLATION)
    return hints


def _diagnostic_triage(
    *,
    metric_summary: Mapping[str, Any],
    finding_pressure: Mapping[str, Any],
    match_attempt_diagnostics: Mapping[str, Any],
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    weak_related_count = int(match_attempt_diagnostics.get("weakRelatedAttemptCount") or 0)
    wrong_cwe_count = int(match_attempt_diagnostics.get("wrongCweTargetLocationAttemptCount") or 0)
    negative_violations = int(metric_summary.get("negativeTargetViolationCount") or 0)
    target_fn = int(metric_summary.get("targetFN") or 0)
    fp_findings = int(metric_summary.get("fpFindings") or 0)
    oracle_fp = int(finding_pressure.get("oracleCountedFpFindingCount") or 0)

    if weak_related_count > 0:
        candidates.append({
            "candidateId": "matching-policy-review",
            "category": "measurement-review",
            "reasonCodes": [TRIAGE_REASON_WEAK_RELATED],
            "evidence": {"weakRelatedAttemptCount": weak_related_count},
            "nextLocalAction": "inspect-oracle-line-window-or-function-fallback",
        })
    if wrong_cwe_count > 0:
        candidates.append({
            "candidateId": "cwe-normalization-review",
            "category": "measurement-review",
            "reasonCodes": [TRIAGE_REASON_WRONG_CWE],
            "evidence": {"wrongCweTargetLocationAttemptCount": wrong_cwe_count},
            "nextLocalAction": "inspect-tool-cwe-mapping-and-target-cwe-family",
        })
    if negative_violations > 0:
        candidates.append({
            "candidateId": "negative-discrimination-review",
            "category": "coverage-or-noise-review",
            "reasonCodes": [TRIAGE_REASON_NEGATIVE_VIOLATION],
            "evidence": {"negativeTargetViolationCount": negative_violations},
            "nextLocalAction": "inspect-negative-region-ruleset-discrimination",
        })
    if target_fn > 0:
        candidates.append({
            "candidateId": "recall-gap-investigation",
            "category": "coverage-or-noise-review",
            "reasonCodes": [TRIAGE_REASON_RECALL],
            "evidence": {"targetFN": target_fn, "targetRecall": metric_summary.get("targetRecall")},
            "nextLocalAction": "inspect-missed-target-cwe-and-tool-coverage",
        })
    if fp_findings > 0 or oracle_fp > 0:
        candidates.append({
            "candidateId": "noise-pressure-review",
            "category": "coverage-or-noise-review",
            "reasonCodes": [TRIAGE_REASON_NOISE],
            "evidence": {
                "fpFindings": fp_findings,
                "oracleCountedFpFindingCount": oracle_fp,
                "nonTpRawFindingCount": int(finding_pressure.get("nonTpRawFindingCount") or 0),
            },
            "nextLocalAction": "inspect-high-pressure-tools-and-rule-ids",
        })
    return {
        "status": "available",
        "consumerPolicy": "candidate_investigation_lanes_not_root_cause_or_verdict",
        "candidates": candidates,
    }


def _cwe_triage_reason_codes(bucket: Mapping[str, Any]) -> list[str]:
    reason_codes: list[str] = []
    if int(bucket.get("targetFN") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_RECALL)
    if int(bucket.get("wrong-cwe-target-location") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_WRONG_CWE)
    if int(bucket.get("weak-related-match") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_WEAK_RELATED)
    if int(bucket.get("negativeTargetViolationCount") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_NEGATIVE_VIOLATION)
    return reason_codes


def _cwe_tool_triage_reason_codes(bucket: Mapping[str, Any]) -> list[str]:
    target_outcomes = bucket.get("targetOutcomeCounts")
    target_outcomes = target_outcomes if isinstance(target_outcomes, Mapping) else {}
    reason_codes: list[str] = []
    if int(target_outcomes.get("wrong-cwe-target-location") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_WRONG_CWE)
    if int(target_outcomes.get("weak-related-match") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_WEAK_RELATED)
    if int(target_outcomes.get("off-target-finding") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_NOISE)
    if int(bucket.get("negativeTargetViolationCount") or 0) > 0:
        reason_codes.append(TRIAGE_REASON_NEGATIVE_VIOLATION)
    return reason_codes


def _empty_cwe_bucket() -> dict[str, int]:
    return {
        "targetTP": 0,
        "targetFN": 0,
        "negativeTargetViolationCount": 0,
        **{match_class: 0 for match_class in TARGET_OUTCOME_MATCH_CLASSES},
    }


def _empty_cwe_tool_bucket() -> dict[str, Any]:
    return {
        "targetTP": 0,
        "negativeTargetViolationCount": 0,
        "targetOutcomeCounts": {},
    }


def _empty_tool_bucket() -> dict[str, Any]:
    return {
        "uniqueRawFindingCount": 0,
        "tpFindingCount": 0,
        "nonTpRawFindingCount": 0,
        "targetOutcomeCounts": {},
    }


def _target_id(target: Mapping[str, Any]) -> str:
    expected = target.get("expected")
    if isinstance(expected, Mapping) and expected.get("targetId"):
        return str(expected.get("targetId"))
    return str(target.get("targetId") or target.get("caseId") or "unknown-target")


def _target_expected_cwe_bucket(target: Mapping[str, Any] | None) -> str:
    if not isinstance(target, Mapping):
        return "unknown"
    expected = target.get("expected")
    expected = expected if isinstance(expected, Mapping) else target
    cwe = expected.get("cweId")
    if isinstance(cwe, str) and cwe.strip():
        return cwe.strip().upper() if cwe.strip().upper().startswith("CWE-") else f"CWE-{cwe.strip().upper()}"
    if expected.get("polarity") == "negative":
        return "negative-region"
    return "unknown"


def _target_is_positive(target: Mapping[str, Any] | None) -> bool:
    if not isinstance(target, Mapping):
        return False
    expected = target.get("expected")
    expected = expected if isinstance(expected, Mapping) else target
    return expected.get("polarity", "positive") == "positive"


def _finding_evidence_key(evidence: Any) -> str:
    return f"{evidence.tool_id}:{evidence.rule_id}:{evidence.file}:{evidence.line}"


def _tool_sort_key(tool: str) -> tuple[int, str]:
    try:
        return (ALL_TOOLS.index(tool), tool)
    except ValueError:
        return (len(ALL_TOOLS), tool)


def _tool_contribution_diagnostics(
    *,
    all_config_scores: Mapping[str, Mapping[str, Any]],
    split_targets: Mapping[str, Sequence[Mapping[str, Any]]],
    portfolio_metrics: Mapping[str, Any],
    primary_config: str,
    system_gate_failed: bool,
    system_reason_codes: Sequence[str],
    local_input_invalid_reason: str | None,
    comparative_completeness: Any,
) -> dict[str, Any]:
    base = {
        "schemaVersion": TOOL_CONTRIBUTION_DIAGNOSTICS_SCHEMA_VERSION,
        "consumerPolicy": "diagnostic_only_not_tool_change_verdict",
        "primaryToolSetConfig": primary_config,
        "metricScope": "aggregate_all_scored_targets",
        "includedSplits": [
            split
            for split in CANONICAL_SPLIT_ORDER
            if split_targets.get(split)
        ],
    }
    if system_gate_failed:
        return {
            **base,
            "status": "blocked",
            "reasonCodes": sorted({"SYSTEM_STABILITY_GATE_FAILED", *(str(reason) for reason in system_reason_codes if str(reason))}),
            "tools": [],
        }
    if local_input_invalid_reason is not None:
        return {
            **base,
            "status": "not_run",
            "reasonCodes": [local_input_invalid_reason],
            "tools": [],
        }
    if _comparative_completeness_failed(comparative_completeness) or _tool_contribution_scores_incomplete(all_config_scores):
        return {
            **base,
            "status": "not_run",
            "reasonCodes": [TOOL_CONTRIBUTION_COMPARATIVE_INCOMPLETE_REASON],
            "tools": [],
        }

    unique = portfolio_metrics.get("uniqueTpContribution") if isinstance(portfolio_metrics.get("uniqueTpContribution"), Mapping) else {}
    leave_one_out = portfolio_metrics.get("leaveOneOutDelta") if isinstance(portfolio_metrics.get("leaveOneOutDelta"), Mapping) else {}
    tools: list[dict[str, Any]] = []
    for tool in ALL_TOOLS:
        single_tool = _tool_contribution_score_summary(all_config_scores.get(f"single-tool:{tool}") or {})
        leave_one_out_delta = _leave_one_out_delta_summary(leave_one_out.get(tool) if isinstance(leave_one_out, Mapping) else None)
        unique_tp = int(unique.get(tool) or 0) if isinstance(unique, Mapping) else 0
        evidence_class, reason_code = _tool_contribution_evidence_class(
            single_tool=single_tool,
            leave_one_out_delta=leave_one_out_delta,
            unique_tp_contribution=unique_tp,
        )
        tools.append({
            "toolId": tool,
            "singleTool": single_tool,
            "leaveOneOutDelta": leave_one_out_delta,
            "uniqueTpContribution": unique_tp,
            "evidenceClass": evidence_class,
            "reasonCodes": [reason_code],
        })

    return {
        **base,
        "status": "available",
        "reasonCodes": [],
        "tools": tools,
    }


def _comparative_completeness_failed(comparative_completeness: Any) -> bool:
    if comparative_completeness is None:
        return False
    if not isinstance(comparative_completeness, Mapping):
        return True
    return comparative_completeness.get("status") != "pass"


def _tool_contribution_scores_incomplete(all_config_scores: Mapping[str, Mapping[str, Any]]) -> bool:
    required = ["full-current-six"]
    required.extend(f"single-tool:{tool}" for tool in ALL_TOOLS)
    required.extend(f"leave-one-out:{tool}" for tool in ALL_TOOLS)
    for config in required:
        score = all_config_scores.get(config)
        if not isinstance(score, Mapping):
            return True
        if score.get("status") is not None and score.get("status") != "pass":
            return True
    return False


def _tool_contribution_score_summary(score: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "targetTP": int(score.get("targetTP") or 0),
        "targetFN": int(score.get("targetFN") or 0),
        "fpFindings": int(score.get("fpFindings") or 0),
        "targetRecall": score.get("targetRecall"),
        "findingPrecision": score.get("findingPrecision"),
        "negativeTargetViolationCount": int(score.get("negativeTargetViolationCount") or 0),
        "negativeTargetFpr": score.get("negativeTargetFpr"),
    }


def _leave_one_out_delta_summary(delta: Any) -> dict[str, Any]:
    delta = delta if isinstance(delta, Mapping) else {}
    return {
        "targetRecallDelta": delta.get("targetRecallDelta", 0),
        "fpFindingsDelta": int(delta.get("fpFindingsDelta") or 0),
    }


def _tool_contribution_evidence_class(
    *,
    single_tool: Mapping[str, Any],
    leave_one_out_delta: Mapping[str, Any],
    unique_tp_contribution: int,
) -> tuple[str, str]:
    recall_delta = leave_one_out_delta.get("targetRecallDelta") or 0
    if unique_tp_contribution > 0 or recall_delta > 0:
        return "unique-positive-contributor", TOOL_CONTRIBUTION_REASON_UNIQUE
    if int(single_tool.get("targetTP") or 0) > 0:
        return "overlap-only-positive-contributor", TOOL_CONTRIBUTION_REASON_OVERLAP
    if int(single_tool.get("fpFindings") or 0) > 0 or int(single_tool.get("negativeTargetViolationCount") or 0) > 0:
        return "noise-only-or-no-positive-contribution", TOOL_CONTRIBUTION_REASON_NOISE_ONLY
    return "no-observed-signal", TOOL_CONTRIBUTION_REASON_NO_SIGNAL


def _portfolio_metrics(
    all_config_scores: Mapping[str, Mapping[str, Any]],
    findings_by_config: Mapping[str, Sequence[SastFinding | Mapping[str, Any]]],
) -> dict[str, Any]:
    full = all_config_scores.get("full-current-six", {})
    unique = {tool: 0 for tool in ALL_TOOLS}
    # Use row-level full-config positive matches: if the same target is matched by only one tool in single-tool configs, count unique.
    for tool in ALL_TOOLS:
        single = all_config_scores.get(f"single-tool:{tool}", {})
        for row in single.get("rows", []):
            if row.get("countsAsTargetTp") is True:
                target_id = row.get("targetId")
                matched_by_others = False
                for other in ALL_TOOLS:
                    if other == tool:
                        continue
                    other_rows = all_config_scores.get(f"single-tool:{other}", {}).get("rows", [])
                    if any(item.get("targetId") == target_id and item.get("countsAsTargetTp") is True for item in other_rows):
                        matched_by_others = True
                        break
                if not matched_by_others:
                    unique[tool] += 1
    full_recall = full.get("targetRecall") or 0
    full_noise = full.get("fpFindings") or 0
    leave_one_out: dict[str, dict[str, Any]] = {}
    for tool in ALL_TOOLS:
        score = all_config_scores.get(f"leave-one-out:{tool}", {})
        recall = score.get("targetRecall") or 0
        noise = score.get("fpFindings") or 0
        leave_one_out[tool] = {
            "targetRecallDelta": round(full_recall - recall, 4),
            "fpFindingsDelta": full_noise - noise,
        }
    return {
        "uniqueTpContribution": unique,
        "leaveOneOutDelta": leave_one_out,
        "overlapPolicy": "equivalent_strong_related_weak_related_rows_are_reported_per_config",
    }


def _historical_benchmark_evidence(repo_root: Path | str | None) -> dict[str, Any]:
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]
    try:
        report = build_default_benchmark_slice_report(Path(repo_root))
    except Exception:
        return {
            "status": "not_available",
            "consumerPolicy": "historical_prerequisite_not_replacement_test_evidence",
            "reasonCodes": ["HISTORICAL_BASELINES_NOT_AVAILABLE"],
        }
    return {
        "status": "available",
        "schemaVersion": report.get("schemaVersion"),
        "consumerPolicy": "historical_prerequisite_not_replacement_test_evidence",
        "sources": report.get("sources", {}),
        "weakestSlices": report.get("weakestSlices", {}),
    }


def _required_followups(external_corpus_status: Mapping[str, Any] | None) -> list[str]:
    followups: list[str] = []
    for corpus_name, status in (external_corpus_status or {}).items():
        if isinstance(status, Mapping) and status.get("status") in {"blocked", "not_run"}:
            if corpus_name == "requiredCorpusReadiness":
                followups.append("Run Corpus Readiness Gate with explicit required corpora before decision-grade validation/test evidence.")
            else:
                followups.append(f"Provide local pinned {corpus_name} corpus before decision-grade validation/test evidence.")
    return followups


def _reject_forbidden_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            forbidden_key = _canonical_forbidden_verdict_key(key)
            if forbidden_key is not None:
                raise ValueError(f"forbidden verdict key at {path}.{forbidden_key}: {forbidden_key}")
            _reject_forbidden_keys(nested, f"{path}.<field>")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _reject_forbidden_keys(item, f"{path}[{idx}]")


def _canonical_forbidden_verdict_key(key: Any) -> str | None:
    for forbidden_key in sorted(FORBIDDEN_VERDICT_KEYS):
        if key == forbidden_key:
            return forbidden_key
    return None
