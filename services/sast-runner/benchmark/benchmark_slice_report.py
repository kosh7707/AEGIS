from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "s4-benchmark-slice-report-v1"
CONSUMER_POLICY = "benchmark_quality_evidence_not_runtime_verdict"
DEFAULT_VARIANT01_ARTIFACT = "v0.6.0-full.json"
DEFAULT_ALL_VARIANTS_ARTIFACT = "v0.7.0-all-variants.json"


def build_default_benchmark_slice_report(repo_root: Path | str | None = None) -> dict[str, Any]:
    root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parents[1]
    baselines = root / "benchmark" / "data" / "baselines"
    return build_benchmark_slice_report(
        variant01_path=baselines / DEFAULT_VARIANT01_ARTIFACT,
        all_variants_path=baselines / DEFAULT_ALL_VARIANTS_ARTIFACT,
    )


def build_benchmark_slice_report(*, variant01_path: Path, all_variants_path: Path) -> dict[str, Any]:
    variant01 = _load_artifact(variant01_path)
    all_variants = _load_artifact(all_variants_path)
    cwes = sorted(set(variant01.get("results", {})) | set(all_variants.get("results", {})))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "consumerPolicy": CONSUMER_POLICY,
        "scope": "historical-juliet-benchmark-slices",
        "toolSetChangePolicy": "benchmark_slices_are_required_evidence_not_a_tool_change_decision",
        "sources": {
            "variant01": _source_summary(variant01_path, variant01),
            "allVariants": _source_summary(all_variants_path, all_variants),
        },
        "cweSlices": {
            cwe: _cwe_slice(
                cwe,
                variant01_path.name,
                _as_mapping(variant01.get("results", {}).get(cwe)),
                all_variants_path.name,
                _as_mapping(all_variants.get("results", {}).get(cwe)),
            )
            for cwe in cwes
        },
        "weakestSlices": {
            "variant01": _weakest_slices(variant01_path.name, variant01, profile_key="variant01"),
            "allVariants": _weakest_slices(all_variants_path.name, all_variants, profile_key="allVariants"),
        },
    }


def _load_artifact(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"benchmark artifact must be an object: {path}")
    return data


def _source_summary(path: Path, artifact: dict[str, Any]) -> dict[str, Any]:
    summary = _as_mapping(artifact.get("summary")) or {}
    return {
        "artifact": path.name,
        "timestamp": artifact.get("timestamp"),
        "variantFilter": artifact.get("variantFilter"),
        "targetCWEs": list(artifact.get("targetCWEs", [])),
        "cweCount": summary.get("cweCount") or len(artifact.get("results", {})),
        "summary": _copy_metric_subset(
            summary,
            ["overallRecall", "overallPrecision", "overallF1", "overallNoisePerFile", "totalTP", "totalFN", "totalFP", "totalNoise"],
        ),
    }


def _cwe_slice(
    cwe: str,
    variant01_artifact: str,
    variant01_result: dict[str, Any] | None,
    all_variants_artifact: str,
    all_variants_result: dict[str, Any] | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"cwe": cwe}
    if variant01_result is not None:
        result["variant01"] = _profile_slice(variant01_artifact, variant01_result, include_noise=False)
    if all_variants_result is not None:
        result["allVariants"] = _profile_slice(all_variants_artifact, all_variants_result, include_noise=True)
    return result


def _profile_slice(source_artifact: str, cwe_result: dict[str, Any], *, include_noise: bool) -> dict[str, Any]:
    combined = _as_mapping(cwe_result.get("combined")) or {}
    metric_keys = ["tp", "fn", "recall"] + (["noise", "noisePerFile"] if include_noise else ["fp", "precision", "f1"])
    return {
        "sourceArtifact": source_artifact,
        "variantFilter": "all" if include_noise else "01",
        "cweName": cwe_result.get("cweName"),
        "totalFiles": cwe_result.get("totalFiles"),
        **_copy_metric_subset(combined, metric_keys),
        "byTool": _by_tool_slices(source_artifact, cwe_result, include_noise=include_noise),
    }


def _by_tool_slices(source_artifact: str, cwe_result: dict[str, Any], *, include_noise: bool) -> dict[str, dict[str, Any]]:
    by_tool = _as_mapping(cwe_result.get("byTool")) or {}
    metric_keys = ["tp", "fn", "recall"] + (["noise"] if include_noise else ["fp", "precision", "f1"])
    result: dict[str, dict[str, Any]] = {}
    for tool_id, metrics in by_tool.items():
        metric_map = _as_mapping(metrics) or {}
        result[str(tool_id)] = {
            "sourceArtifact": source_artifact,
            **_copy_metric_subset(metric_map, metric_keys),
        }
    return result


def _weakest_slices(source_artifact: str, artifact: dict[str, Any], *, profile_key: str, limit: int = 3) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cwe, cwe_result in (_as_mapping(artifact.get("results")) or {}).items():
        cwe_map = _as_mapping(cwe_result) or {}
        combined = _as_mapping(cwe_map.get("combined")) or {}
        recall = combined.get("recall")
        if isinstance(recall, int | float):
            rows.append({
                "cwe": str(cwe),
                "profile": profile_key,
                "variantFilter": artifact.get("variantFilter"),
                "sourceArtifact": source_artifact,
                "recall": recall,
                "totalFiles": cwe_map.get("totalFiles"),
            })
    rows.sort(key=lambda item: (item["recall"], item["cwe"]))
    return rows[:limit]


def _copy_metric_subset(source: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: source[key] for key in keys if key in source}


def _as_mapping(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None
