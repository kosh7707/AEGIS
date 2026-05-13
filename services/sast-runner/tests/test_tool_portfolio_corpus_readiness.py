from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from benchmark.tool_portfolio_acquisition_manifest import ACQUISITION_SCHEMA_VERSION, manifest_checksum
from benchmark.tool_portfolio_corpus_readiness import (
    CORPUS_READINESS_GATE_SCHEMA_VERSION,
    build_corpus_readiness_gate,
    external_corpus_status_from_readiness,
)
from benchmark.tool_portfolio_experiment_manifest import CORPUS_SCHEMA_VERSION


def _sha256_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _acquisition(local_path: Path | str, *, acquisition_id: str = "juliet-c-cpp-1.3") -> dict:
    return {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "acquisitionId": acquisition_id,
        "sourceName": "Juliet C/C++",
        "sourceUrl": "https://samate.nist.gov/SARD/test-suites/112",
        "sourceVersion": "1.3",
        "licenseOrRedistributionNote": "NIST SAMATE/SARD public benchmark corpus; keep local copy pinned by checksum.",
        "downloadedAt": "2026-05-13",
        "archiveChecksum": "sha256:" + "a" * 64,
        "extractionRootChecksum": "sha256:" + "b" * 64,
        "localPath": str(local_path),
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }


def _case(
    case_id: str,
    *,
    split: str,
    source_path: str,
    checksum: str,
    acquisition: dict,
    polarity: str = "positive",
) -> dict:
    return {
        "caseId": case_id,
        "targetId": f"{case_id}-target",
        "lineageId": case_id,
        "sliceKind": "juliet-controlled-positive" if polarity == "positive" else "juliet-controlled-negative",
        "split": split,
        "language": "c",
        "sourceArtifact": "Juliet C/C++ 1.3",
        "acquisitionId": acquisition["acquisitionId"],
        "acquisitionManifestChecksum": manifest_checksum(acquisition),
        "sourceRef": f"{acquisition['acquisitionId']}:{source_path}",
        "sourcePath": source_path,
        "checksum": checksum,
        "expected": {
            "targetId": f"{case_id}-target",
            "granularity": "sink-line" if polarity == "positive" else "negative-region",
            "cweId": "CWE-121",
            "polarity": polarity,
            "locations": [{"file": source_path, "line": 42, "role": "sink"}],
            "functionRegion": {"function": "bad" if polarity == "positive" else "good", "startLine": 35, "endLine": 45},
            "allowedMatchWindows": {"lineDelta": 5, "functionFallback": False},
            **({"allowedWarningPolicy": {"mode": "no-findings-in-region", "allowedRuleIds": []}} if polarity == "negative" else {}),
        },
        "buildContext": {"requiresCompileCommands": False, "compileCommandsFixture": None, "defines": [], "includePaths": []},
        "notes": [],
    }


def _corpus(cases: list[dict]) -> dict:
    return {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": cases,
    }


def test_readiness_blocks_when_required_juliet_acquisition_is_absent() -> None:
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-13",
        "owner": "s4-sast-runner",
        "cases": [
            {
                "caseId": "local-canary",
                "targetId": "local-canary-target",
                "lineageId": "local-canary",
                "sliceKind": "s4-canary",
                "split": "canary",
                "language": "c",
                "sourceArtifact": "S4 local canary",
                "sourcePath": "local-canary.c",
                "checksum": "sha256:" + "1" * 64,
                "expected": {
                    "targetId": "local-canary-target",
                    "granularity": "sink-line",
                    "cweId": "CWE-120",
                    "polarity": "positive",
                    "locations": [{"file": "local-canary.c", "line": 1, "role": "sink"}],
                },
            }
        ],
    }

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["schemaVersion"] == CORPUS_READINESS_GATE_SCHEMA_VERSION
    assert gate["status"] == "blocked"
    assert gate["decisionGradeReady"] is False
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in gate["reasonCodes"]
    external = external_corpus_status_from_readiness(gate)
    assert external["juliet"]["status"] == "blocked"


def test_readiness_blocks_when_juliet_local_path_is_missing(tmp_path: Path) -> None:
    acquisition = _acquisition(tmp_path / "missing-juliet")
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum="sha256:" + "3" * 64, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum="sha256:" + "4" * 64, acquisition=acquisition),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["status"] == "blocked"
    assert "LOCAL_CORPUS_PATH_NOT_FOUND" in gate["reasonCodes"]
    assert "LOCAL_JULIET_CORPUS_NOT_PRESENT" in gate["externalCorpusStatus"]["juliet"]["reasonCodes"]
    assert gate["acquisitionStatuses"][acquisition["acquisitionId"]]["status"] == "blocked"


def test_readiness_blocks_when_referenced_case_file_is_missing(tmp_path: Path) -> None:
    root = tmp_path / "juliet"
    root.mkdir()
    acquisition = _acquisition(root)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum="sha256:" + "3" * 64, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum="sha256:" + "4" * 64, acquisition=acquisition),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["status"] == "blocked"
    assert "CORPUS_CASE_SOURCE_MISSING" in gate["reasonCodes"]
    assert gate["caseStatuses"][0]["status"] == "blocked"
    assert gate["caseStatuses"][0]["reasonCodes"] == ["CORPUS_CASE_SOURCE_MISSING"]


def test_readiness_blocks_when_case_checksum_does_not_match(tmp_path: Path) -> None:
    root = tmp_path / "juliet"
    (root / "CWE121").mkdir(parents=True)
    (root / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (root / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    acquisition = _acquisition(root)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum="sha256:" + "3" * 64, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["status"] == "blocked"
    assert "CORPUS_CASE_CHECKSUM_MISMATCH" in gate["reasonCodes"]
    mismatch = [case for case in gate["caseStatuses"] if case["caseId"] == "juliet-validation"][0]
    assert mismatch["status"] == "blocked"
    assert mismatch["actualChecksum"] == _sha256_text("bad();\n")


def test_readiness_passes_when_required_juliet_cases_exist_and_match_checksums(tmp_path: Path) -> None:
    root = tmp_path / "juliet"
    (root / "CWE121").mkdir(parents=True)
    (root / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (root / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    acquisition = _acquisition(root)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition, polarity="negative"),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["status"] == "available"
    assert gate["decisionGradeReady"] is True
    assert gate["reasonCodes"] == []
    assert gate["externalCorpusStatus"]["juliet"]["status"] == "available"
    assert gate["summary"]["checkedCaseCount"] == 2
    assert {case["status"] for case in gate["caseStatuses"]} == {"available"}


def test_readiness_rejects_unsafe_case_source_paths(tmp_path: Path) -> None:
    root = tmp_path / "juliet"
    root.mkdir()
    acquisition = _acquisition(root)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="../escape.c", checksum="sha256:" + "3" * 64, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum="sha256:" + "4" * 64, acquisition=acquisition),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["status"] == "blocked"
    assert "CORPUS_CASE_SOURCE_PATH_UNSAFE" in gate["reasonCodes"]
