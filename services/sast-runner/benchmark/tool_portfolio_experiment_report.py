from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.response import SastFinding
from benchmark.benchmark_slice_report import build_default_benchmark_slice_report
from benchmark.tool_portfolio_acquisition_manifest import build_acquisition_index
from benchmark.tool_portfolio_corpus_readiness import (
    build_corpus_readiness_gate,
    default_not_run_corpus_readiness_gate,
    external_corpus_status_from_readiness,
)
from benchmark.tool_portfolio_decision_cycle import build_decision_cycle_lock, checksum_json
from benchmark.tool_portfolio_experiment_manifest import (
    corpus_targets,
    required_current_six_configs,
    validate_corpus_manifest,
    validate_tool_set_config,
)
from benchmark.tool_portfolio_oracle_matcher import MATCHING_POLICY_SCHEMA_VERSION, score_targets
from benchmark.tool_portfolio_system_gate import (
    blocked_metric_bucket,
    build_quality_gate,
    default_not_run_system_gate,
)

EXPERIMENT_REPORT_SCHEMA_VERSION = "s4-tool-portfolio-experiment-report-v1"
FORBIDDEN_VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}


def build_experiment_report(
    *,
    run_id: str,
    created_at: str,
    phase: str,
    corpus_manifest: Mapping[str, Any],
    acquisition_manifests: Sequence[Mapping[str, Any]],
    findings_by_config: Mapping[str, Sequence[SastFinding | Mapping[str, Any]]],
    matching_policy: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    external_corpus_status: Mapping[str, Any] | None = None,
    corpus_readiness_gate: Mapping[str, Any] | None = None,
    required_corpora: Sequence[str] | None = None,
    corpus_readiness_base_path: Path | str | None = None,
    system_stability: Mapping[str, Any] | None = None,
    repo_root: Path | str | None = None,
) -> dict[str, Any]:
    acquisition_index = build_acquisition_index(acquisition_manifests)
    corpus_report = validate_corpus_manifest(corpus_manifest, acquisition_index=acquisition_index)
    required_configs = required_current_six_configs()
    for config in required_configs:
        validate_tool_set_config(config)
    system_stability_gate = dict(system_stability or default_not_run_system_gate())
    if corpus_readiness_gate is None and required_corpora is not None:
        corpus_readiness_gate = build_corpus_readiness_gate(
            acquisition_manifests=acquisition_manifests,
            corpus_manifest=corpus_manifest,
            required_corpora=required_corpora,
            base_path=corpus_readiness_base_path,
        )
    corpus_readiness_gate = dict(corpus_readiness_gate or default_not_run_corpus_readiness_gate())
    effective_external_corpus_status = (
        dict(external_corpus_status)
        if external_corpus_status is not None
        else external_corpus_status_from_readiness(corpus_readiness_gate)
    )
    prerequisite_quality_gate = build_quality_gate(
        system_stability_gate=system_stability_gate,
        external_corpus_status=effective_external_corpus_status,
    )
    system_gate_failed = system_stability_gate.get("status") == "fail"
    missing_configs = sorted(set(required_configs) - set(findings_by_config))
    if missing_configs and not system_gate_failed:
        raise ValueError(f"missing current-six experiment configs: {missing_configs}")

    targets = corpus_targets(corpus_manifest)
    split_targets = _targets_by_split(targets)
    matching_policy = dict(matching_policy)
    matching_policy.setdefault("schemaVersion", MATCHING_POLICY_SCHEMA_VERSION)
    split_assignments = {split: [target["targetId"] for target in items] for split, items in sorted(split_targets.items())}
    decision_cycle = build_decision_cycle_lock(
        decision_cycle_id=f"{run_id}-cycle",
        phase=phase,
        corpus_manifest=corpus_manifest,
        matching_policy=matching_policy,
        thresholds=thresholds,
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
    if not system_gate_failed:
        for config in required_configs:
            config_findings = list(findings_by_config.get(config, []))
            all_config_scores[config] = score_targets(targets, config_findings, tool_set_config=config, matching_policy=matching_policy)
            for split, split_items in split_targets.items():
                split_findings = _filter_findings_to_targets(config_findings, split_items)
                by_config_by_split.setdefault(split, {})[config] = score_targets(split_items, split_findings, tool_set_config=config, matching_policy=matching_policy)

    validation_metrics = (
        blocked_metric_bucket("validation", list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]))
        if system_gate_failed else _split_bucket("validation", by_config_by_split.get("validation", {}))
    )
    test_metrics = (
        blocked_metric_bucket("test", list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]))
        if system_gate_failed else _split_bucket("test", by_config_by_split.get("test", {}))
    )
    canary_metrics = (
        blocked_metric_bucket("canary", list(system_stability_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"]))
        if system_gate_failed else _split_bucket("canary", by_config_by_split.get("canary", {}))
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
    )
    quality_gate = _compose_quality_gate(
        prerequisite_quality_gate,
        local_quality_assessment,
    )
    blocked_reasons = list(quality_gate.get("reasonCodes") or ["SYSTEM_STABILITY_GATE_FAILED"])

    report = {
        "schemaVersion": EXPERIMENT_REPORT_SCHEMA_VERSION,
        "runId": run_id,
        "createdAt": created_at,
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
        "portfolioMetrics": (
            {"status": "blocked", "reasonCodes": blocked_reasons}
            if system_gate_failed else _portfolio_metrics(all_config_scores, findings_by_config)
        ),
        "benchmarkSliceEvidence": _historical_benchmark_evidence(repo_root),
        "decisionSupport": {
            "currentDecision": quality_gate.get("decision", "insufficient-evidence-for-tool-change"),
            "reasonCodes": list(quality_gate.get("reasonCodes") or []),
            "removeCandidates": [],
            "upgradeCandidates": [],
            "addCandidates": [],
            "futureCandidateActionsRequireWr": True,
            "externalCorpusStatus": effective_external_corpus_status,
            "requiredFollowUps": _required_followups(effective_external_corpus_status),
        },
    }
    _reject_forbidden_keys(report)
    return report


def write_experiment_report(report: Mapping[str, Any], path: Path | str) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return output


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


def _local_quality_assessment(
    split_metric_buckets: Mapping[str, Mapping[str, Any]],
    thresholds: Mapping[str, Any],
    *,
    blocked: bool = False,
    blocked_reason_codes: Sequence[str] | None = None,
) -> dict[str, Any]:
    primary_config = str(thresholds.get("primaryToolSetConfig") or "full-current-six")
    required_splits = [str(split) for split in thresholds.get("requiredSplits", ["validation", "test", "canary"])]
    if blocked:
        return {
            "status": "blocked",
            "primaryToolSetConfig": primary_config,
            "thresholds": dict(thresholds),
            "reasonCodes": list(blocked_reason_codes or ["SYSTEM_STABILITY_GATE_FAILED"]),
            "splitAssessments": {},
            "failingSplits": [],
            "passingSplits": [],
            "consumerPolicy": "do_not_score_quality_when_system_gate_failed",
        }

    split_assessments: dict[str, dict[str, Any]] = {}
    failing_splits: list[str] = []
    passing_splits: list[str] = []
    aggregate_reason_codes: set[str] = set()

    for split in required_splits:
        bucket = split_metric_buckets.get(split) or {}
        by_config = bucket.get("byConfig") if isinstance(bucket.get("byConfig"), Mapping) else {}
        metrics = by_config.get(primary_config) if isinstance(by_config, Mapping) else None
        assessment = _assess_split_quality(split, metrics, thresholds)
        split_assessments[split] = assessment
        if assessment["status"] == "pass":
            passing_splits.append(split)
        else:
            failing_splits.append(split)
            aggregate_reason_codes.update(assessment["reasonCodes"])

    return {
        "status": "fail" if failing_splits else "pass",
        "primaryToolSetConfig": primary_config,
        "thresholds": dict(thresholds),
        "reasonCodes": sorted(aggregate_reason_codes),
        "splitAssessments": split_assessments,
        "failingSplits": failing_splits,
        "passingSplits": passing_splits,
        "consumerPolicy": "local_oracle_metrics_are_not_decision_grade_without_external_corpus",
    }


def _assess_split_quality(
    split: str,
    metrics: Mapping[str, Any] | None,
    thresholds: Mapping[str, Any],
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
        target_recall is None or float(target_recall) < float(minimum_target_recall)
    ):
        reason_codes.append("TARGET_RECALL_BELOW_THRESHOLD")

    minimum_finding_precision = thresholds.get("minimumFindingPrecision")
    if minimum_finding_precision is not None and (
        finding_precision is None or float(finding_precision) < float(minimum_finding_precision)
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
            followups.append(f"Provide local pinned {corpus_name} corpus before decision-grade validation/test evidence.")
    return followups


def _reject_forbidden_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key in FORBIDDEN_VERDICT_KEYS:
                raise ValueError(f"forbidden verdict key at {path}.{key}: {key}")
            _reject_forbidden_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _reject_forbidden_keys(item, f"{path}[{idx}]")
