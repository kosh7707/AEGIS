from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from benchmark.golden_corpus_validator import load_manifest
from benchmark.static_evidence_report import attach_quality_evaluation, build_validation_report
from app.scanner.static_evidence_contract import build_static_evidence_contract

MANIFEST_PATH = Path(__file__).parent / "fixtures" / "golden_corpus_v1" / "manifest.json"


def _manifest() -> dict:
    return load_manifest(MANIFEST_PATH)


def test_runtime_contract_quality_evaluation_defaults_to_not_evaluated() -> None:
    contract = build_static_evidence_contract(success=True, findings=[], execution=None)

    quality = contract["gates"]["qualityEvaluation"]
    assert quality == {
        "status": "not_evaluated",
        "reasonCodes": ["NO_VALIDATION_PROFILE_RAN"],
        "consumerPolicy": "do_not_treat_as_quality_score",
    }


def test_validation_report_populates_quality_evaluation_only_in_report_profile() -> None:
    report = build_validation_report(_manifest(), repo_root=Path(__file__).parents[1])

    assert report["schemaVersion"] == "s4-static-evidence-validation-report-v1"
    assert report["profile"] == "golden-corpus-v1"
    assert report["gates"]["systemStability"]["status"] == "not_applicable"
    assert report["gates"]["evidenceReadiness"]["status"] == "not_applicable"
    quality = report["gates"]["qualityEvaluation"]
    assert quality["status"] == "pass"
    assert quality["profile"] == "golden-corpus-v1"
    assert quality["consumerPolicy"] == "quality_profile_result_only"
    assert report["validation"]["status"] == "pass"


def test_attach_quality_evaluation_returns_copy_without_mutating_runtime_contract() -> None:
    contract = build_static_evidence_contract(success=True, findings=[], execution=None)
    original = deepcopy(contract)
    report = build_validation_report(_manifest(), repo_root=Path(__file__).parents[1])

    enriched = attach_quality_evaluation(contract, report)

    assert contract == original
    assert contract["gates"]["qualityEvaluation"]["status"] == "not_evaluated"
    assert enriched["gates"]["qualityEvaluation"]["status"] == "pass"
    assert enriched["gates"]["systemStability"] == contract["gates"]["systemStability"]
    assert enriched["gates"]["evidenceReadiness"] == contract["gates"]["evidenceReadiness"]


def test_validation_report_failure_does_not_become_runtime_stability_failure() -> None:
    manifest = _manifest()
    manifest["layers"]["contractOracles"] = []

    report = build_validation_report(manifest, repo_root=Path(__file__).parents[1])

    assert report["validation"]["status"] == "fail"
    assert report["gates"]["qualityEvaluation"]["status"] in {"partial", "fail"}
    assert report["gates"]["systemStability"]["status"] == "not_applicable"
    assert report["gates"]["evidenceReadiness"]["status"] == "not_applicable"
