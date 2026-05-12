"""Retrieval Quality Lab v1 for S5 GraphRAG modernization.

The lab is offline-only.  It uses fixture expected/retrieved candidate lists to
measure retrieval policy quality without leaking TP/FP/Recall vocabulary into
runtime S5 responses.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

DEFAULT_RETRIEVAL_QUALITY_LAB_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "retrieval-quality-lab-v1" / "manifest.json"

REQUIRED_FAMILIES = {
    "memory_safety",
    "command_execution",
    "path_file_access",
    "crypto_tls",
    "network_parser",
    "concurrency_resource_lifecycle",
    "package_identity_cve",
    "embedded_ics_profile",
}

REQUIRED_CASE_FIELDS = {
    "caseId",
    "family",
    "surface",
    "query",
    "queryIntent",
    "corpusPartition",
    "profiles",
    "methodsAttempted",
    "methodsUsed",
    "runtimeObservation",
    "consumerPolicy",
    "expectedCandidateIds",
    "retrievedCandidateIds",
    "qualityOracle",
    "topKPolicy",
    "candidatePoolPolicy",
}

OFFLINE_TERMS = {
    "tp", "fp", "fn", "true-positive", "false-positive", "false-negative",
    "true positive", "false positive", "false negative", "precision", "recall",
    "ndcg", "mrr", "hit-rate", "hit rate", "falsepositive", "falsenegative",
}


def load_retrieval_quality_lab(path: Path | str = DEFAULT_RETRIEVAL_QUALITY_LAB_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _runtime_metric_leaks(value: Any) -> list[str]:
    serialized = json.dumps(value, ensure_ascii=False).lower()
    leaks: list[str] = []
    for term in OFFLINE_TERMS:
        if len(term) <= 3 and term.isalpha():
            if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", serialized):
                leaks.append(term)
        elif term in serialized:
            leaks.append(term)
    return sorted(set(leaks))


def validate_retrieval_quality_lab(manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if manifest.get("schemaVersion") != "s5-retrieval-quality-lab-v1":
        issues.append("schemaVersion must be s5-retrieval-quality-lab-v1")
    cases = _as_list(manifest.get("cases"))
    if not cases:
        issues.append("cases must be a non-empty list")
        return issues

    seen: set[str] = set()
    families: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            issues.append(f"case[{index}] must be object")
            continue
        case_id = str(case.get("caseId") or f"case[{index}]")
        if case_id in seen:
            issues.append(f"duplicate caseId: {case_id}")
        seen.add(case_id)
        missing = REQUIRED_CASE_FIELDS - set(case)
        if missing:
            issues.append(f"{case_id} missing fields: {sorted(missing)}")
        family = str(case.get("family", ""))
        families.add(family)
        if family not in REQUIRED_FAMILIES:
            issues.append(f"{case_id} unknown family: {family}")
        for list_field in ("profiles", "methodsAttempted", "methodsUsed", "expectedCandidateIds", "retrievedCandidateIds"):
            if not isinstance(case.get(list_field), list):
                issues.append(f"{case_id}.{list_field} must be list")
        runtime = case.get("runtimeObservation")
        if not isinstance(runtime, dict):
            issues.append(f"{case_id}.runtimeObservation must be object")
        else:
            leaks = _runtime_metric_leaks(runtime)
            if leaks:
                issues.append(f"{case_id}.runtimeObservation contains offline metric vocabulary: {leaks}")
        top_k_policy = case.get("topKPolicy") or {}
        candidate_policy = case.get("candidatePoolPolicy") or {}
        if not isinstance(top_k_policy.get("finalTopK"), int):
            issues.append(f"{case_id}.topKPolicy.finalTopK must be int")
        if not isinstance(candidate_policy.get("candidatePoolK"), int):
            issues.append(f"{case_id}.candidatePoolPolicy.candidatePoolK must be int")
        elif isinstance(top_k_policy.get("finalTopK"), int) and candidate_policy["candidatePoolK"] < top_k_policy["finalTopK"]:
            issues.append(f"{case_id}.candidatePoolPolicy must be >= finalTopK")
        quality = case.get("qualityOracle") or {}
        if quality.get("evaluated") is not True or not isinstance(quality.get("k"), int):
            issues.append(f"{case_id}.qualityOracle must be evaluated with integer k")

    missing_families = REQUIRED_FAMILIES - families
    if missing_families:
        issues.append(f"missing retrieval lab families: {sorted(missing_families)}")
    return issues


def _precision(retrieved: list[str], expected: set[str], k: int) -> float:
    top = retrieved[:k]
    return sum(1 for item in top if item in expected) / len(top) if top else 0.0


def _recall(retrieved: list[str], expected: set[str], k: int) -> float:
    if not expected:
        return 0.0
    return len(set(retrieved[:k]) & expected) / len(expected)


def _ndcg(retrieved: list[str], ideal_order: list[str], k: int) -> float:
    if not ideal_order:
        return 0.0
    relevance = {candidate: len(ideal_order) - rank for rank, candidate in enumerate(ideal_order)}
    dcg = 0.0
    for index, candidate in enumerate(retrieved[:k]):
        gain = relevance.get(candidate, 0)
        if gain:
            dcg += gain / math.log2(index + 2)
    ideal_gains = sorted(relevance.values(), reverse=True)[:k]
    idcg = sum(gain / math.log2(index + 2) for index, gain in enumerate(ideal_gains))
    return dcg / idcg if idcg else 0.0


def _mrr(retrieved: list[str], expected: set[str]) -> float:
    for index, candidate in enumerate(retrieved):
        if candidate in expected:
            return 1.0 / (index + 1)
    return 0.0


def _mean(values: Iterable[float]) -> float:
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def _case_metrics(case: dict[str, Any]) -> dict[str, Any]:
    k = int((case.get("qualityOracle") or {}).get("k", 5))
    expected_list = [str(v) for v in case.get("expectedCandidateIds", [])]
    expected = set(expected_list)
    retrieved = [str(v) for v in case.get("retrievedCandidateIds", [])]
    top = retrieved[:k]
    top_set = set(top)
    fp = len(top_set - expected)
    fn = len(expected - top_set)
    return {
        "caseId": case["caseId"],
        "precisionAtK": _precision(retrieved, expected, k),
        "recallAtK": _recall(retrieved, expected, k),
        "ndcgAtK": _ndcg(retrieved, expected_list, k),
        "mrr": _mrr(retrieved, expected),
        "hitRate": 1.0 if top_set & expected else 0.0,
        "falsePositiveCount": fp,
        "falseNegativeCount": fn,
        "retrievedCount": len(top),
        "expectedCount": len(expected),
        "candidatePoolK": int(case["candidatePoolPolicy"]["candidatePoolK"]),
        "finalTopK": int(case["topKPolicy"]["finalTopK"]),
    }


def _aggregate(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    retrieved_count = sum(m["retrievedCount"] for m in metrics)
    expected_count = sum(m["expectedCount"] for m in metrics)
    fp_count = sum(m["falsePositiveCount"] for m in metrics)
    fn_count = sum(m["falseNegativeCount"] for m in metrics)
    return {
        "caseCount": len(metrics),
        "precisionAtK": _mean(m["precisionAtK"] for m in metrics),
        "recallAtK": _mean(m["recallAtK"] for m in metrics),
        "ndcgAtK": _mean(m["ndcgAtK"] for m in metrics),
        "mrr": _mean(m["mrr"] for m in metrics),
        "hitRate": _mean(m["hitRate"] for m in metrics),
        "falsePositiveCount": fp_count,
        "falseNegativeCount": fn_count,
        "falsePositiveRate": fp_count / retrieved_count if retrieved_count else 0.0,
        "falseNegativeRate": fn_count / expected_count if expected_count else 0.0,
        "avgCandidatePoolK": _mean(m["candidatePoolK"] for m in metrics),
        "avgFinalTopK": _mean(m["finalTopK"] for m in metrics),
    }


def _breakdowns(cases: list[dict[str, Any]], metrics_by_case: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, list[dict[str, Any]]]] = {
        "family": defaultdict(list),
        "method": defaultdict(list),
        "queryIntent": defaultdict(list),
        "corpusPartition": defaultdict(list),
        "profile": defaultdict(list),
    }
    for case in cases:
        metric = metrics_by_case[case["caseId"]]
        groups["family"][str(case.get("family"))].append(metric)
        for method in case.get("methodsUsed", []):
            groups["method"][str(method)].append(metric)
        groups["queryIntent"][str(case.get("queryIntent"))].append(metric)
        groups["corpusPartition"][str(case.get("corpusPartition"))].append(metric)
        for profile in case.get("profiles", []) or ["none"]:
            groups["profile"][str(profile)].append(metric)
    return {name: {key: _aggregate(value) for key, value in group.items()} for name, group in groups.items()}


def summarize_retrieval_quality_lab(manifest: dict[str, Any]) -> dict[str, Any]:
    issues = validate_retrieval_quality_lab(manifest)
    cases = _as_list(manifest.get("cases"))
    per_case = [_case_metrics(case) for case in cases if isinstance(case, dict) and not issues]
    by_case = {metric["caseId"]: metric for metric in per_case}
    return {
        "schemaVersion": "s5-retrieval-quality-lab-report-v1",
        "offlineOnly": True,
        "systemStability": {
            "status": "passed" if not issues else "failed",
            "caseCount": len(cases),
            "issues": issues,
        },
        "qualityGate": {
            "status": "evaluated" if per_case and not issues else "not_evaluated",
            "metrics": _aggregate(per_case),
            "perCase": per_case,
            "breakdowns": _breakdowns(cases, by_case) if per_case else {},
        },
        "policySummary": {
            "topKMeans": "final_returned_count",
            "candidatePoolMeans": "internal_exact_vector_graph_rerank_pool",
            "casesWithCandidatePoolLargerThanTopK": sum(
                1 for case in cases
                if (case.get("candidatePoolPolicy") or {}).get("candidatePoolK", 0)
                > (case.get("topKPolicy") or {}).get("finalTopK", 0)
            ),
            "modelBackedRerankerRequired": False,
        },
    }


def write_retrieval_quality_report(
    output_path: Path | str,
    manifest_path: Path | str = DEFAULT_RETRIEVAL_QUALITY_LAB_PATH,
) -> dict[str, Any]:
    report = summarize_retrieval_quality_lab(load_retrieval_quality_lab(manifest_path))
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
