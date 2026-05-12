from __future__ import annotations

from copy import deepcopy
from typing import Any

from benchmark.golden_corpus_validator import validate_manifest

PROFILE_NAME = "golden-corpus-v1"
PROFILE_SCHEMA_VERSION = "s4-static-evidence-validation-report-v1"


def build_validation_report(manifest: dict[str, Any], *, repo_root: str) -> dict[str, Any]:
    manifest_report = validate_manifest(manifest, repo_root=repo_root)
    quality_evaluation = _quality_evaluation(manifest_report)
    return {
        "schemaVersion": PROFILE_SCHEMA_VERSION,
        "profile": PROFILE_NAME,
        "analysisProfile": manifest.get("analysisProfile", "c-cpp-core"),
        "gates": {
            "systemStability": {
                "status": "not_applicable",
                "reasonCodes": ["REPORT_ONLY_NO_RUNTIME_EXECUTION"],
                "consumerPolicy": "do_not_use_as_runtime_stability_gate",
            },
            "evidenceReadiness": {
                "status": "not_applicable",
                "reasonCodes": ["REPORT_ONLY_NO_RUNTIME_ARTIFACT"],
                "consumerPolicy": "do_not_use_as_runtime_readiness_gate",
            },
            "qualityEvaluation": quality_evaluation,
        },
        "validation": manifest_report,
    }


def attach_quality_evaluation(
    static_evidence_contract: dict[str, Any],
    validation_report: dict[str, Any],
) -> dict[str, Any]:
    updated = deepcopy(static_evidence_contract)
    quality = validation_report.get("gates", {}).get("qualityEvaluation")
    if not isinstance(quality, dict):
        raise ValueError("validation report lacks gates.qualityEvaluation")
    updated.setdefault("gates", {})["qualityEvaluation"] = deepcopy(quality)
    return updated


def _quality_evaluation(manifest_report: dict[str, Any]) -> dict[str, Any]:
    errors = list(manifest_report.get("errors") or [])
    layer_reports = list(manifest_report.get("layers") or [])
    failed_layers = [layer.get("layer") for layer in layer_reports if layer.get("status") != "pass"]

    if manifest_report.get("status") == "pass" and not failed_layers:
        return {
            "status": "pass",
            "profile": PROFILE_NAME,
            "reasonCodes": [],
            "consumerPolicy": "quality_profile_result_only",
            "summary": "Golden Corpus v1 validation profile passed.",
            "layerResults": layer_reports,
        }

    if layer_reports and len(failed_layers) < len(layer_reports):
        return {
            "status": "partial",
            "profile": PROFILE_NAME,
            "reasonCodes": ["VALIDATION_PROFILE_PARTIAL"],
            "consumerPolicy": "quality_profile_result_only",
            "summary": "Golden Corpus v1 validation profile partially passed.",
            "failedLayers": failed_layers,
            "errors": errors,
            "layerResults": layer_reports,
        }

    return {
        "status": "fail",
        "profile": PROFILE_NAME,
        "reasonCodes": ["VALIDATION_PROFILE_FAILED"],
        "consumerPolicy": "quality_profile_result_only",
        "summary": "Golden Corpus v1 validation profile failed.",
        "failedLayers": failed_layers,
        "errors": errors,
        "layerResults": layer_reports,
    }
