from __future__ import annotations

import copy

import pytest

from benchmark.tool_portfolio_acquisition_manifest import ACQUISITION_SCHEMA_VERSION, build_acquisition_index, manifest_checksum
from benchmark.tool_portfolio_experiment_manifest import (
    CORPUS_SCHEMA_VERSION,
    TRACKED_CWES,
    required_current_six_configs,
    validate_corpus_manifest,
    validate_tool_set_config,
)


def _acquisition_manifest() -> dict:
    return {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "acquisitionId": "juliet-c-cpp-1.3",
        "sourceName": "Juliet C/C++",
        "sourceUrl": "https://samate.nist.gov/SARD/test-suites/112",
        "sourceVersion": "1.3",
        "licenseOrRedistributionNote": "Pinned local research corpus.",
        "downloadedAt": "2026-05-12",
        "archiveChecksum": "sha256:" + "a" * 64,
        "extractionRootChecksum": "sha256:" + "b" * 64,
        "localPath": "/tmp/aegis-corpora/juliet-c-cpp-1.3",
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }


def _external_case(case_id: str, split: str, *, polarity: str = "positive", lineage_id: str | None = None) -> dict:
    acquisition = _acquisition_manifest()
    expected = {
        "targetId": f"{case_id}-target",
        "granularity": "sink-line" if polarity == "positive" else "negative-region",
        "cweId": "CWE-121",
        "polarity": polarity,
        "locations": [{"file": "CWE121/foo.c", "line": 42, "role": "sink"}],
        "functionRegion": {"function": "bad" if polarity == "positive" else "good", "startLine": 35, "endLine": 50},
        "allowedMatchWindows": {"lineDelta": 5, "functionFallback": False},
    }
    if polarity == "negative":
        expected["allowedWarningPolicy"] = {"mode": "no-findings-in-region", "allowedRuleIds": []}
    return {
        "caseId": case_id,
        "targetId": expected["targetId"],
        "lineageId": lineage_id or case_id,
        "sliceKind": "juliet-controlled-positive" if polarity == "positive" else "juliet-controlled-negative",
        "split": split,
        "language": "c",
        "sourceArtifact": "Juliet C/C++ 1.3",
        "acquisitionId": acquisition["acquisitionId"],
        "acquisitionManifestChecksum": manifest_checksum(acquisition),
        "sourceRef": f"juliet-c-cpp-1.3:{case_id}",
        "sourcePath": "CWE121/foo.c",
        "checksum": "sha256:" + "c" * 64,
        "expected": expected,
        "buildContext": {"requiresCompileCommands": False, "compileCommandsFixture": None, "defines": [], "includePaths": []},
        "notes": [],
    }


def _corpus_manifest() -> tuple[dict, dict]:
    acquisition = _acquisition_manifest()
    canary = {
        "caseId": "s4-cwe120-canary",
        "targetId": "s4-cwe120-canary-target",
        "lineageId": "s4-cwe120-canary",
        "sliceKind": "s4-canary",
        "split": "canary",
        "language": "c",
        "sourceArtifact": "S4 Golden Corpus v1",
        "sourcePath": "tests/fixtures/golden_corpus_v1/vulnerability_canaries/cwe120_buffer_copy/main.c",
        "checksum": "sha256:" + "d" * 64,
        "expected": {
            "targetId": "s4-cwe120-canary-target",
            "granularity": "sink-line",
            "cweId": "CWE-120",
            "polarity": "positive",
            "locations": [{"file": "main.c", "line": 9, "role": "sink"}],
            "allowedMatchWindows": {"lineDelta": 5, "functionFallback": False},
        },
        "buildContext": {"requiresCompileCommands": False, "compileCommandsFixture": None, "defines": [], "includePaths": []},
        "notes": [],
    }
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "trackedCwes": TRACKED_CWES,
        "cases": [
            _external_case("juliet-cwe121-validation", "validation"),
            _external_case("juliet-cwe121-test-good", "test", polarity="negative"),
            canary,
        ],
    }
    return corpus, acquisition


def test_corpus_manifest_validates_splits_tracked_cwes_and_acquisition_links() -> None:
    corpus, acquisition = _corpus_manifest()

    report = validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    assert report["status"] == "pass"
    assert report["schemaVersion"] == CORPUS_SCHEMA_VERSION
    assert report["trackedCwes"] == TRACKED_CWES
    assert report["caseCount"] == 3
    assert report["splitCounts"] == {"canary": 1, "test": 1, "validation": 1}
    assert report["sliceCounts"]["s4-canary"] == 1


def test_corpus_manifest_rejects_duplicate_case_ids() -> None:
    corpus, acquisition = _corpus_manifest()
    corpus["cases"].append(copy.deepcopy(corpus["cases"][0]))

    with pytest.raises(ValueError, match="duplicate caseId"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_external_case_without_acquisition_linkage() -> None:
    corpus, acquisition = _corpus_manifest()
    del corpus["cases"][0]["acquisitionManifestChecksum"]

    with pytest.raises(ValueError, match="acquisitionManifestChecksum"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_acquisition_checksum_mismatch() -> None:
    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["acquisitionManifestChecksum"] = "sha256:" + "0" * 64

    with pytest.raises(ValueError, match="acquisition checksum mismatch"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_validation_test_lineage_leakage() -> None:
    acquisition = _acquisition_manifest()
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [
            _external_case("case-validation", "validation", lineage_id="same-lineage"),
            _external_case("case-test", "test", lineage_id="same-lineage"),
        ],
    }

    with pytest.raises(ValueError, match="lineage leakage"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_negative_target_without_allowed_warning_policy() -> None:
    corpus, acquisition = _corpus_manifest()
    negative = _external_case("juliet-cwe121-test-bad-policy", "test", polarity="negative")
    del negative["expected"]["allowedWarningPolicy"]
    corpus["cases"].append(negative)

    with pytest.raises(ValueError, match="allowedWarningPolicy"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_forbidden_verdict_keys_recursively() -> None:
    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["expected"]["safe"] = False

    with pytest.raises(ValueError, match="forbidden verdict key"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_current_six_tool_configs_are_complete_and_future_configs_are_wr_gated() -> None:
    configs = required_current_six_configs()

    assert "full-current-six" in configs
    assert "single-tool:semgrep" in configs
    assert "leave-one-out:gcc-fanalyzer" in configs
    assert "parser-only-current-six" in configs
    assert "contract-canary-current-six" in configs
    assert len(configs) == 15
    for config in configs:
        assert validate_tool_set_config(config)["status"] == "pass"

    with pytest.raises(ValueError, match="future WR-gated"):
        validate_tool_set_config("add-one-in:clang-analyzer-next")
