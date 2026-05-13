from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.schemas.response import SastFinding
from benchmark.tool_portfolio_experiment_report import build_experiment_report, write_experiment_report

FIXTURE_SCHEMA_VERSION = "s4-tool-portfolio-harness-fixture-v1"
DEFAULT_FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "tool_portfolio_experiment_v1"


def load_harness_fixture(root: Path | str = DEFAULT_FIXTURE_ROOT) -> dict[str, Any]:
    fixture_root = Path(root)
    acquisition = json.loads((fixture_root / "acquisition_manifest.json").read_text(encoding="utf-8"))
    corpus = json.loads((fixture_root / "corpus_manifest.json").read_text(encoding="utf-8"))
    raw_findings = json.loads((fixture_root / "findings_by_config.json").read_text(encoding="utf-8"))
    findings_by_config = {
        config: [SastFinding.model_validate(item) for item in items]
        for config, items in raw_findings.get("findingsByConfig", {}).items()
    }
    return {
        "schemaVersion": FIXTURE_SCHEMA_VERSION,
        "acquisitionManifests": [acquisition],
        "corpusManifest": corpus,
        "findingsByConfig": findings_by_config,
        "matchingPolicy": raw_findings.get("matchingPolicy", {
            "schemaVersion": "s4-oracle-matching-policy-v1",
            "lineWindowDefault": 3,
            "functionFallbackDefault": False,
        }),
        "thresholds": raw_findings.get("thresholds", {"minimumTargetRecall": 0.0}),
    }


def build_harness_fixture_report(
    *,
    run_id: str = "s4-harness-fixture-v1",
    created_at: str = "2026-05-12T00:00:00Z",
    root: Path | str = DEFAULT_FIXTURE_ROOT,
    repo_root: Path | str | None = None,
) -> dict[str, Any]:
    fixture = load_harness_fixture(root)
    return build_experiment_report(
        run_id=run_id,
        created_at=created_at,
        phase="test",
        corpus_manifest=fixture["corpusManifest"],
        acquisition_manifests=fixture["acquisitionManifests"],
        findings_by_config=fixture["findingsByConfig"],
        matching_policy=fixture["matchingPolicy"],
        thresholds=fixture["thresholds"],
        required_corpora=["juliet-c-cpp-1.3"],
        corpus_readiness_base_path=repo_root or Path(__file__).resolve().parents[1],
        repo_root=repo_root,
    )


def write_harness_fixture_report(path: Path | str, *, repo_root: Path | str | None = None) -> Path:
    return write_experiment_report(build_harness_fixture_report(repo_root=repo_root), path)
