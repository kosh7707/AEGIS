"""Quality Gate anomaly oracle for analysis/generate-poc result envelopes.

This evaluator is intentionally deterministic. It verifies lifecycle/outcome
semantics, not vulnerability truth: `completed` alone is never accepted as a
paper-quality pass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_ORACLE_PATH = Path(__file__).resolve().parent / "golden/qg_anomaly_oracle.json"


def load_quality_gate_oracle(path: Path = DEFAULT_ORACLE_PATH) -> dict[str, Any]:
    oracle = json.loads(path.read_text())
    if not isinstance(oracle, dict):
        raise ValueError("quality gate oracle must be a JSON object")
    cases = oracle.get("cases")
    if not isinstance(cases, list) or not all(isinstance(item, dict) for item in cases):
        raise ValueError("quality gate oracle cases must be a list of objects")
    return oracle


def classify_quality_state(response: dict[str, Any], *, task_type: str | None = None) -> dict[str, Any]:
    status = str(response.get("status") or "")
    result = response.get("result") if isinstance(response.get("result"), dict) else {}
    task_completed = status == "completed"
    if not task_completed:
        return {
            "taskCompleted": False,
            "clean": False,
            "anomaly": True,
            "bucket": "dependency_or_task_failure",
            "reasons": [f"status={status or 'missing'}", f"failureCode={response.get('failureCode') or 'unknown'}"],
        }

    inferred_task = task_type or _infer_task_type(result)
    if inferred_task == "generate-poc":
        poc = result.get("pocOutcome")
        quality = result.get("qualityOutcome")
        clean_pass = result.get("cleanPass") is True
        clean = poc == "poc_accepted" and quality == "accepted" and clean_pass
        return {
            "taskCompleted": True,
            "clean": clean,
            "anomaly": not clean,
            "bucket": "clean" if clean else "poc_not_clean",
            "reasons": [] if clean else [f"pocOutcome={poc}", f"qualityOutcome={quality}", f"cleanPass={clean_pass}"],
        }

    analysis = result.get("analysisOutcome")
    quality = result.get("qualityOutcome")
    clean_pass = result.get("cleanPass") is True
    clean = analysis == "accepted_claims" and quality == "accepted" and clean_pass
    if clean:
        bucket = "clean"
    elif analysis != "accepted_claims":
        bucket = "analysis_not_clean"
    else:
        bucket = "quality_not_clean"
    return {
        "taskCompleted": True,
        "clean": clean,
        "anomaly": not clean,
        "bucket": bucket,
        "reasons": [] if clean else [f"analysisOutcome={analysis}", f"qualityOutcome={quality}", f"cleanPass={clean_pass}"],
    }


def evaluate_quality_gate_oracle(oracle: dict[str, Any]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for case in oracle.get("cases", []):
        actual = classify_quality_state(case.get("sample") or {}, task_type=case.get("taskType"))
        expected = case.get("expected") or {}
        checked_fields = ("taskCompleted", "clean", "anomaly", "bucket")
        mismatches = [
            {"field": field, "expected": expected.get(field), "actual": actual.get(field)}
            for field in checked_fields
            if actual.get(field) != expected.get(field)
        ]
        results.append({
            "id": case.get("id"),
            "passed": not mismatches,
            "expected": {field: expected.get(field) for field in checked_fields},
            "actual": {field: actual.get(field) for field in checked_fields},
            "mismatches": mismatches,
            "reasons": actual.get("reasons", []),
        })
    return {
        "schemaVersion": oracle.get("schemaVersion"),
        "passed": all(item["passed"] for item in results),
        "caseCount": len(results),
        "results": results,
    }


def _infer_task_type(result: dict[str, Any]) -> str:
    if result.get("pocOutcome") and result.get("pocOutcome") != "poc_not_requested":
        return "generate-poc"
    return "deep-analyze"
