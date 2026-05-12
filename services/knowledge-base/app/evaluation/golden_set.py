"""Golden Set v1 manifest validation and offline gate reporting.

G002 intentionally provides a lightweight, deterministic harness.  It does not
run live retrieval, mutate the ledger, or claim runtime TP/FP semantics.  The
only place TP/FP/FN/Recall/Precision/NDCG/MRR appear is this offline fixture
report.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from app.contracts.acquisition import ACQUISITION_STATUSES, OFFLINE_QUALITY_VOCABULARY

DEFAULT_GOLDEN_SET_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "golden-set-v1" / "manifest.json"

REQUIRED_FAMILIES = {
    "cve-package",
    "etl-transform",
    "threat-graphrag-retrieval",
    "code-graph",
    "s3-evidence-slot",
}

REQUIRED_CASE_FIELDS = {
    "caseId",
    "family",
    "surface",
    "queryIntent",
    "corpusPartition",
    "profiles",
    "methodsAttempted",
    "methodsUsed",
    "runtimeObservation",
    "consumerPolicy",
    "evidenceReadinessOracle",
    "qualityOracle",
    "expectedCandidateIds",
    "retrievedCandidateIds",
}

REQUIRED_RETRIEVAL_CASE_IDS = {
    "retrieval-command-exec-no-automotive-keyword",
    "retrieval-automotive-gateway-enrichment-not-vuln",
    "retrieval-keyword-absence-not-no-hit",
    "retrieval-global-embedding-noise-suppressed",
    "retrieval-keyword-fp-weak-candidate",
    "retrieval-keyword-fn-offline-miss-only",
    "retrieval-tool-rule-cwe-context-no-local-support",
    "retrieval-package-identity-alias-no-nvd-keyword-only",
    "retrieval-profile-tags-additive-context-only",
}

REQUIRED_CVE_CASE_IDS = {
    "cve-candidate-range-out-discovery-no-hit",
    "cve-candidate-range-out-discovery-other-hit",
    "cve-version-unknown-input-insufficient",
    "cve-keyword-only-no-result-not-no-hit",
    "cve-provider-timeout-envelope",
    "cve-stale-cache-only-diagnostic",
    "cve-no-hit-plus-failure-not-partial-hit",
}

REQUIRED_EVIDENCE_POLICIES = {
    "contextual_only",
    "diagnostic_only",
    "scoped_no_hit_record_only",
    "s3_may_derive_local_support_if_refs_validate",
}

OFFLINE_METRIC_FIELDS = {
    "precisionAtK",
    "recallAtK",
    "ndcgAtK",
    "mrr",
    "hitRate",
    "expectedCandidateCoverage",
    "falsePositiveCount",
    "falseNegativeCount",
    "falsePositiveRate",
    "falseNegativeRate",
}

RUNTIME_STATUS_WORDS = set(ACQUISITION_STATUSES)

FORBIDDEN_RUNTIME_OBSERVATION_TERMS = {
    *(term.lower() for term in OFFLINE_QUALITY_VOCABULARY),
    *(term.lower() for term in OFFLINE_METRIC_FIELDS),
    "tp",
    "fp",
    "fn",
    "true-positive",
    "false-positive",
    "false-negative",
    "true positive",
    "false positive",
    "false negative",
}


def load_golden_set(path: Path | str = DEFAULT_GOLDEN_SET_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _runtime_observation_metric_leaks(value: Any) -> list[str]:
    serialized = json.dumps(value, ensure_ascii=False).lower()
    leaks: list[str] = []
    for term in FORBIDDEN_RUNTIME_OBSERVATION_TERMS:
        if len(term) <= 3 and term.isalpha():
            if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", serialized):
                leaks.append(term)
        elif term in serialized:
            leaks.append(term)
    return sorted(set(leaks))


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    """Return validation issues; empty means schema-ready for G002."""
    issues: list[str] = []
    if manifest.get("schemaVersion") != "s5-golden-set-v1":
        issues.append("schemaVersion must be s5-golden-set-v1")

    cases = _as_list(manifest.get("cases"))
    if not cases:
        issues.append("cases must be a non-empty list")
        return issues

    seen: set[str] = set()
    family_seen: set[str] = set()
    case_ids: set[str] = set()
    evidence_policies: set[str] = set()

    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            issues.append(f"case[{index}] must be object")
            continue
        missing = REQUIRED_CASE_FIELDS - set(case)
        if missing:
            issues.append(f"{case.get('caseId', f'case[{index}]')} missing fields: {sorted(missing)}")
        case_id = str(case.get("caseId", ""))
        if not case_id:
            issues.append(f"case[{index}] missing caseId")
        elif case_id in seen:
            issues.append(f"duplicate caseId: {case_id}")
        seen.add(case_id)
        case_ids.add(case_id)

        family = str(case.get("family", ""))
        family_seen.add(family)
        if family not in REQUIRED_FAMILIES:
            issues.append(f"{case_id} has unknown family {family!r}")

        for list_field in ("profiles", "methodsAttempted", "methodsUsed", "expectedCandidateIds", "retrievedCandidateIds"):
            if not isinstance(case.get(list_field), list):
                issues.append(f"{case_id}.{list_field} must be list")

        runtime_observation = case.get("runtimeObservation")
        if not isinstance(runtime_observation, dict):
            issues.append(f"{case_id}.runtimeObservation must be object")
        elif any(metric in runtime_observation for metric in OFFLINE_METRIC_FIELDS):
            issues.append(f"{case_id}.runtimeObservation contains offline metric fields")
        else:
            status = runtime_observation.get("acquisitionStatus")
            if status not in RUNTIME_STATUS_WORDS:
                issues.append(f"{case_id}.runtimeObservation.acquisitionStatus is outside runtime contract vocabulary")
            metric_leaks = _runtime_observation_metric_leaks(runtime_observation)
            if metric_leaks:
                issues.append(f"{case_id}.runtimeObservation contains offline metric vocabulary: {metric_leaks}")

        readiness = case.get("evidenceReadinessOracle")
        if not isinstance(readiness, dict):
            issues.append(f"{case_id}.evidenceReadinessOracle must be object")
        else:
            evidence_policies.add(str(case.get("consumerPolicy")))
            if "maySupportClaim" not in readiness or "mayBeNegativeEvidence" not in readiness:
                issues.append(f"{case_id}.evidenceReadinessOracle must define support/negative-evidence booleans")

        quality = case.get("qualityOracle")
        if not isinstance(quality, dict):
            issues.append(f"{case_id}.qualityOracle must be object")
        elif quality.get("evaluated") and not isinstance(quality.get("k"), int):
            issues.append(f"{case_id}.qualityOracle.evaluated requires integer k")

        if family == "etl-transform":
            transform = case.get("transformOracle")
            if not isinstance(transform, dict):
                issues.append(f"{case_id}.transformOracle is required for etl-transform")
            else:
                for field in ("rawInput", "normalizedExpected", "transformDiagnostics", "provenanceExpectations", "freshnessExpectations"):
                    if field not in transform:
                        issues.append(f"{case_id}.transformOracle missing {field}")

    missing_families = REQUIRED_FAMILIES - family_seen
    if missing_families:
        issues.append(f"missing fixture families: {sorted(missing_families)}")

    missing_retrieval = REQUIRED_RETRIEVAL_CASE_IDS - case_ids
    if missing_retrieval:
        issues.append(f"missing S3 retrieval/taxonomy cases: {sorted(missing_retrieval)}")

    missing_cve = REQUIRED_CVE_CASE_IDS - case_ids
    if missing_cve:
        issues.append(f"missing CVE/package cases: {sorted(missing_cve)}")

    missing_policies = REQUIRED_EVIDENCE_POLICIES - evidence_policies
    if missing_policies:
        issues.append(f"missing evidence-slot consumer policies: {sorted(missing_policies)}")

    return issues


def _precision(retrieved: list[str], expected: set[str], k: int) -> float:
    if k <= 0:
        return 0.0
    top = retrieved[:k]
    if not top:
        return 0.0
    return sum(1 for item in top if item in expected) / len(top)


def _recall(retrieved: list[str], expected: set[str], k: int) -> float:
    if not expected or k <= 0:
        return 0.0
    top = set(retrieved[:k])
    return len(top & expected) / len(expected)


def _ndcg(retrieved: list[str], ideal_order: list[str], k: int) -> float:
    if not ideal_order or k <= 0:
        return 0.0
    rel = {candidate: len(ideal_order) - rank for rank, candidate in enumerate(ideal_order)}
    dcg = 0.0
    for idx, candidate in enumerate(retrieved[:k]):
        gain = rel.get(candidate, 0)
        if gain:
            dcg += gain / math.log2(idx + 2)
    idcg = sum(gain / math.log2(idx + 2) for idx, gain in enumerate(sorted(rel.values(), reverse=True)[:k]))
    return dcg / idcg if idcg else 0.0


def _mrr(retrieved: list[str], expected: set[str]) -> float:
    for idx, candidate in enumerate(retrieved):
        if candidate in expected:
            return 1.0 / (idx + 1)
    return 0.0


def _mean(values: Iterable[float]) -> float:
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def _case_metrics(case: dict[str, Any]) -> dict[str, Any] | None:
    quality = case.get("qualityOracle") or {}
    if not quality.get("evaluated"):
        return None
    k = int(quality.get("k", 5))
    expected_list = [str(v) for v in case.get("expectedCandidateIds", [])]
    retrieved = [str(v) for v in case.get("retrievedCandidateIds", [])]
    expected = set(expected_list)
    retrieved_top = retrieved[:k]
    retrieved_set = set(retrieved_top)
    fp = len(retrieved_set - expected)
    fn = len(expected - retrieved_set)
    return {
        "caseId": case["caseId"],
        "precisionAtK": _precision(retrieved, expected, k),
        "recallAtK": _recall(retrieved, expected, k),
        "ndcgAtK": _ndcg(retrieved, expected_list or list(quality.get("idealCandidateOrder", [])), k),
        "mrr": _mrr(retrieved, expected),
        "hitRate": 1.0 if retrieved_set & expected else 0.0,
        "expectedCandidateCoverage": _recall(retrieved, expected, k),
        "falsePositiveCount": fp,
        "falseNegativeCount": fn,
        "retrievedCount": len(retrieved_top),
        "expectedCount": len(expected),
    }


def _aggregate(case_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    retrieved_count = sum(m["retrievedCount"] for m in case_metrics)
    expected_count = sum(m["expectedCount"] for m in case_metrics)
    fp_count = sum(m["falsePositiveCount"] for m in case_metrics)
    fn_count = sum(m["falseNegativeCount"] for m in case_metrics)
    return {
        "caseCount": len(case_metrics),
        "precisionAtK": _mean(m["precisionAtK"] for m in case_metrics),
        "recallAtK": _mean(m["recallAtK"] for m in case_metrics),
        "ndcgAtK": _mean(m["ndcgAtK"] for m in case_metrics),
        "mrr": _mean(m["mrr"] for m in case_metrics),
        "hitRate": _mean(m["hitRate"] for m in case_metrics),
        "expectedCandidateCoverage": _mean(m["expectedCandidateCoverage"] for m in case_metrics),
        "falsePositiveCount": fp_count,
        "falseNegativeCount": fn_count,
        "falsePositiveRate": fp_count / retrieved_count if retrieved_count else 0.0,
        "falseNegativeRate": fn_count / expected_count if expected_count else 0.0,
    }


def _breakdowns(cases: list[dict[str, Any]], metrics_by_case: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, list[dict[str, Any]]]] = {
        "method": defaultdict(list),
        "queryIntent": defaultdict(list),
        "corpusPartition": defaultdict(list),
        "profile": defaultdict(list),
    }
    for case in cases:
        metric = metrics_by_case.get(case["caseId"])
        if not metric:
            continue
        for method in case.get("methodsUsed", []):
            groups["method"][str(method)].append(metric)
        groups["queryIntent"][str(case.get("queryIntent"))].append(metric)
        groups["corpusPartition"][str(case.get("corpusPartition"))].append(metric)
        for profile in case.get("profiles", []):
            groups["profile"][str(profile)].append(metric)
    return {
        group_name: {key: _aggregate(value) for key, value in group.items()}
        for group_name, group in groups.items()
    }


def compute_quality_metrics(manifest: dict[str, Any]) -> dict[str, Any]:
    cases = _as_list(manifest.get("cases"))
    per_case = [m for case in cases if (m := _case_metrics(case)) is not None]
    by_case = {metric["caseId"]: metric for metric in per_case}
    return {
        "offlineOnly": True,
        "metrics": _aggregate(per_case),
        "perCase": per_case,
        "breakdowns": _breakdowns(cases, by_case),
    }


def _retrieval_quality_summary(cases: list[dict[str, Any]], quality: dict[str, Any]) -> dict[str, Any]:
    """Return G009 retrieval-quality metadata inside the offline Quality Gate only."""
    retrieval_families = {"threat-graphrag-retrieval", "code-graph"}
    retrieval_cases = [case for case in cases if case.get("family") in retrieval_families]
    breakdowns = quality.get("breakdowns", {})
    method_breakdown = breakdowns.get("method", {})
    return {
        "schemaVersion": "s5-g009-retrieval-quality-summary-v1",
        "offlineOnly": True,
        "runtimeTraceFieldsExcluded": True,
        "retrievalCaseCount": len(retrieval_cases),
        "breakdownsPresent": {
            "method": bool(method_breakdown),
            "queryIntent": bool(breakdowns.get("queryIntent")),
            "corpusPartition": bool(breakdowns.get("corpusPartition")),
            "profile": bool(breakdowns.get("profile")),
        },
        "methodCases": {
            method: {"caseCount": stats.get("caseCount", 0)}
            for method, stats in method_breakdown.items()
        },
        "globalEmbeddingPolicy": {
            "method": "global_embedding_search",
            "trust": "low",
            "caseCovered": any(
                "global_embedding_search" in case.get("methodsUsed", [])
                or "global_embedding_search" in case.get("methodsAttempted", [])
                for case in retrieval_cases
            ),
            "negativeEvidenceAllowed": False,
        },
    }


def build_gate_report(manifest: dict[str, Any]) -> dict[str, Any]:
    issues = validate_manifest(manifest)
    cases = _as_list(manifest.get("cases"))
    readiness_failures = []
    for case in cases:
        readiness = case.get("evidenceReadinessOracle") or {}
        if readiness.get("maySupportClaim") and case.get("consumerPolicy") in {
            "contextual_only",
            "diagnostic_only",
            "scoped_no_hit_record_only",
            "do_not_use_as_negative_evidence",
        }:
            readiness_failures.append({"caseId": case.get("caseId"), "reason": "consumer_policy_cannot_support_claim"})
        if readiness.get("mayBeNegativeEvidence") and case.get("consumerPolicy") != "scoped_no_hit_record_only":
            readiness_failures.append({"caseId": case.get("caseId"), "reason": "unsafe_negative_evidence"})

    quality = compute_quality_metrics(manifest)
    quality = {
        **quality,
        "retrievalQuality": _retrieval_quality_summary(cases, quality),
    }
    return {
        "schemaVersion": "s5-golden-set-report-v1",
        "systemStability": {
            "status": "passed" if not issues else "failed",
            "manifestLoaded": True,
            "caseCount": len(cases),
            "issues": issues,
        },
        "evidenceReadiness": {
            "status": "passed" if not readiness_failures and not issues else "failed",
            "failures": readiness_failures,
            "consumerPoliciesCovered": sorted({str(case.get("consumerPolicy")) for case in cases}),
        },
        "qualityGate": {
            "status": "evaluated" if quality["metrics"]["caseCount"] else "not_evaluated",
            "offlineOnly": True,
            **quality,
        },
        "runtimeStatusVocabulary": sorted(RUNTIME_STATUS_WORDS),
    }
