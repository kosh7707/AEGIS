from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmark.benchmark_slice_report import build_benchmark_slice_report

BASELINES_DIR = Path(__file__).parents[1] / "benchmark" / "data" / "baselines"
VARIANT01 = BASELINES_DIR / "v0.6.0-full.json"
ALL_VARIANTS = BASELINES_DIR / "v0.7.0-all-variants.json"
FORBIDDEN_KEYS = {
    "verdict",
    "securityVerdict",
    "riskScore",
    "risk",
    "shouldCallS5",
    "routeTo",
    "nextService",
    "agentDecision",
}


def _collect_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for nested in value.values():
            keys.update(_collect_keys(nested))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for item in value:
            keys.update(_collect_keys(item))
        return keys
    return set()


def _report() -> dict[str, Any]:
    return build_benchmark_slice_report(variant01_path=VARIANT01, all_variants_path=ALL_VARIANTS)


def test_benchmark_slice_report_uses_pinned_historical_artifacts() -> None:
    report = _report()

    assert report["schemaVersion"] == "s4-benchmark-slice-report-v1"
    assert report["consumerPolicy"] == "benchmark_quality_evidence_not_runtime_verdict"
    assert report["sources"]["variant01"]["artifact"] == "v0.6.0-full.json"
    assert report["sources"]["allVariants"]["artifact"] == "v0.7.0-all-variants.json"
    assert report["sources"]["variant01"]["variantFilter"] == "01"
    assert report["sources"]["allVariants"]["variantFilter"] == "all"
    assert report["sources"]["variant01"]["cweCount"] == 12
    assert report["sources"]["allVariants"]["cweCount"] == 12


def test_benchmark_slice_report_keeps_metrics_source_scoped() -> None:
    report = _report()
    cwe_121 = report["cweSlices"]["CWE-121"]
    cwe_476 = report["cweSlices"]["CWE-476"]

    assert cwe_476["variant01"]["recall"] == 1.0
    assert cwe_476["variant01"]["precision"] == 0.127
    assert cwe_476["variant01"]["sourceArtifact"] == "v0.6.0-full.json"
    assert cwe_121["allVariants"]["noise"] == 36214
    assert cwe_121["allVariants"]["noisePerFile"] == 20.55
    assert cwe_121["allVariants"]["sourceArtifact"] == "v0.7.0-all-variants.json"
    assert "noise" not in cwe_121["variant01"]
    assert "precision" not in cwe_121["allVariants"]


def test_benchmark_slice_report_identifies_weak_recall_slices_per_source() -> None:
    report = _report()

    weakest_variant = report["weakestSlices"]["variant01"][0]
    weakest_all = report["weakestSlices"]["allVariants"][0]
    assert weakest_variant["cwe"] == "CWE-457"
    assert weakest_variant["recall"] == 0.5556
    assert weakest_variant["sourceArtifact"] == "v0.6.0-full.json"
    assert weakest_variant["variantFilter"] == "01"
    assert weakest_all["cwe"] == "CWE-457"
    assert weakest_all["recall"] == 0.5432
    assert weakest_all["sourceArtifact"] == "v0.7.0-all-variants.json"
    assert weakest_all["variantFilter"] == "all"


def test_benchmark_slice_report_preserves_per_tool_slices_without_merging_profiles() -> None:
    report = _report()
    semgrep_369 = report["cweSlices"]["CWE-369"]["variant01"]["byTool"]["semgrep"]
    cppcheck_121_all = report["cweSlices"]["CWE-121"]["allVariants"]["byTool"]["cppcheck"]

    assert semgrep_369["recall"] == 0.8333
    assert semgrep_369["precision"] == 0.4545
    assert semgrep_369["sourceArtifact"] == "v0.6.0-full.json"
    assert cppcheck_121_all["noise"] == 13953
    assert cppcheck_121_all["sourceArtifact"] == "v0.7.0-all-variants.json"


def test_benchmark_slice_report_has_no_verdict_risk_or_orchestration_fields() -> None:
    report = _report()

    forbidden = _collect_keys(report).intersection(FORBIDDEN_KEYS)
    assert not forbidden, f"benchmark slice report contains forbidden keys: {sorted(forbidden)}"
    serialized = json.dumps(report, sort_keys=True)
    for token in ["securityVerdict", "riskScore", "shouldCallS5", "routeTo", "nextService"]:
        assert token not in serialized


def test_benchmark_slice_report_helper_is_offline_json_only() -> None:
    helper = Path(__file__).parents[1] / "benchmark" / "benchmark_slice_report.py"
    text = helper.read_text(encoding="utf-8")

    forbidden_tokens = [
        "juliet_runner",
        "create_subprocess",
        "subprocess",
        "Popen",
        "check_output",
        "app.scanner",
        "app.routers",
        "app.main",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "socket",
        "grpc",
        "FastAPI",
        "openai",
        "anthropic",
    ]
    for token in forbidden_tokens:
        assert token not in text, f"benchmark slice report helper must not reference {token!r}"
