from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from benchmark.tool_portfolio_acquisition_manifest import ACQUISITION_SCHEMA_VERSION, manifest_checksum
from benchmark.tool_portfolio_corpus_readiness import (
    CASE_RESOLVED_PATH_STATUS_VALUES,
    CORPUS_READINESS_GATE_SCHEMA_VERSION,
    LOCAL_PATH_STATUS_VALUES,
    RESOLVED_LOCAL_PATH_STATUS_VALUES,
    SOURCE_PATH_STATUS_VALUES,
    _load_json_object,
    build_corpus_readiness_gate,
    default_not_run_corpus_readiness_gate,
    external_corpus_status_from_readiness,
    main as corpus_readiness_main,
)
from benchmark.tool_portfolio_experiment_manifest import CORPUS_SCHEMA_VERSION


EXPECTED_LOCAL_PATH_STATUS_VALUES = {
    "available",
    "base_required",
    "missing",
    "not_declared",
    "not_resolved",
    "outside_base",
}
EXPECTED_RESOLVED_LOCAL_PATH_STATUS_VALUES = {
    "available",
    "missing",
    "not_resolved",
    "outside_base",
}
EXPECTED_CASE_RESOLVED_PATH_STATUS_VALUES = {
    "available",
    "checksum_mismatch",
    "missing",
    "outside_root",
    "unsafe",
}
EXPECTED_SOURCE_PATH_STATUS_VALUES = {"unsafe"}


def _sha256_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _sha(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


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


def _local_canary_corpus() -> dict:
    return {
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


def _assert_readiness_status_field_contract(gate: dict) -> None:
    for acquisition_status in gate["acquisitionStatuses"].values():
        assert "localPath" not in acquisition_status
        assert "resolvedLocalPath" not in acquisition_status
        assert acquisition_status["localPathStatus"] in LOCAL_PATH_STATUS_VALUES
        assert acquisition_status["resolvedLocalPathStatus"] in RESOLVED_LOCAL_PATH_STATUS_VALUES

    for case_status in gate["caseStatuses"]:
        assert "resolvedPath" not in case_status
        assert case_status["resolvedPathStatus"] in CASE_RESOLVED_PATH_STATUS_VALUES
        if "sourcePathStatus" in case_status:
            assert case_status["sourcePathStatus"] in SOURCE_PATH_STATUS_VALUES


def test_readiness_status_field_constants_are_frozen_contracts() -> None:
    assert LOCAL_PATH_STATUS_VALUES == EXPECTED_LOCAL_PATH_STATUS_VALUES
    assert RESOLVED_LOCAL_PATH_STATUS_VALUES == EXPECTED_RESOLVED_LOCAL_PATH_STATUS_VALUES
    assert CASE_RESOLVED_PATH_STATUS_VALUES == EXPECTED_CASE_RESOLVED_PATH_STATUS_VALUES
    assert SOURCE_PATH_STATUS_VALUES == EXPECTED_SOURCE_PATH_STATUS_VALUES


def test_readiness_path_status_fields_are_allowlisted_across_representative_gates(tmp_path: Path) -> None:
    base = tmp_path / "base"
    (base / "juliet" / "CWE121").mkdir(parents=True)
    (base / "juliet" / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (base / "juliet" / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    absolute_root = tmp_path / "absolute-juliet"
    (absolute_root / "CWE121").mkdir(parents=True)
    (absolute_root / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (absolute_root / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")

    relative_acquisition = _acquisition("juliet")
    absolute_acquisition = _acquisition(absolute_root)

    available_corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=relative_acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=relative_acquisition, polarity="negative"),
    ])
    available_gate = build_corpus_readiness_gate(
        acquisition_manifests=[relative_acquisition],
        corpus_manifest=available_corpus,
        required_corpora=["juliet-c-cpp-1.3"],
        base_path=base,
    )

    missing_acquisition_gate = build_corpus_readiness_gate(
        acquisition_manifests=[],
        corpus_manifest=_local_canary_corpus(),
        required_corpora=["juliet-c-cpp-1.3"],
    )

    base_required_corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=relative_acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=relative_acquisition, polarity="negative"),
    ])
    base_required_gate = build_corpus_readiness_gate(
        acquisition_manifests=[relative_acquisition],
        corpus_manifest=base_required_corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    outside_base_acquisition = _acquisition("../outside-juliet")
    outside_base_corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=outside_base_acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=outside_base_acquisition, polarity="negative"),
    ])
    outside_base_gate = build_corpus_readiness_gate(
        acquisition_manifests=[outside_base_acquisition],
        corpus_manifest=outside_base_corpus,
        required_corpora=["juliet-c-cpp-1.3"],
        base_path=base,
    )

    missing_local_path_acquisition = _acquisition(tmp_path / "missing-juliet")
    missing_local_path_corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum="sha256:" + "3" * 64, acquisition=missing_local_path_acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum="sha256:" + "4" * 64, acquisition=missing_local_path_acquisition),
    ])
    missing_local_path_gate = build_corpus_readiness_gate(
        acquisition_manifests=[missing_local_path_acquisition],
        corpus_manifest=missing_local_path_corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    missing_case_corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/missing-validation.c", checksum="sha256:" + "3" * 64, acquisition=absolute_acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=absolute_acquisition, polarity="negative"),
    ])
    missing_case_gate = build_corpus_readiness_gate(
        acquisition_manifests=[absolute_acquisition],
        corpus_manifest=missing_case_corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    checksum_mismatch_corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum="sha256:" + "3" * 64, acquisition=absolute_acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=absolute_acquisition, polarity="negative"),
    ])
    checksum_mismatch_gate = build_corpus_readiness_gate(
        acquisition_manifests=[absolute_acquisition],
        corpus_manifest=checksum_mismatch_corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    unsafe_source_corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="..\\SECRET_RAW_SHOULD_NOT_LEAK.c", checksum="sha256:" + "3" * 64, acquisition=absolute_acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=absolute_acquisition, polarity="negative"),
    ])
    unsafe_source_gate = build_corpus_readiness_gate(
        acquisition_manifests=[absolute_acquisition],
        corpus_manifest=unsafe_source_corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    gates = [
        available_gate,
        missing_acquisition_gate,
        base_required_gate,
        outside_base_gate,
        missing_local_path_gate,
        missing_case_gate,
        checksum_mismatch_gate,
        unsafe_source_gate,
    ]
    for gate in gates:
        _assert_readiness_status_field_contract(gate)

    observed_local_statuses = {
        status["localPathStatus"]
        for gate in gates
        for status in gate["acquisitionStatuses"].values()
    }
    observed_resolved_local_statuses = {
        status["resolvedLocalPathStatus"]
        for gate in gates
        for status in gate["acquisitionStatuses"].values()
    }
    observed_case_resolved_statuses = {
        status["resolvedPathStatus"]
        for gate in gates
        for status in gate["caseStatuses"]
    }
    observed_source_path_statuses = {
        status["sourcePathStatus"]
        for gate in gates
        for status in gate["caseStatuses"]
        if "sourcePathStatus" in status
    }

    assert observed_local_statuses == LOCAL_PATH_STATUS_VALUES - {"not_resolved"}
    assert observed_resolved_local_statuses == RESOLVED_LOCAL_PATH_STATUS_VALUES
    assert observed_case_resolved_statuses == {"available", "checksum_mismatch", "missing", "unsafe"}
    assert observed_source_path_statuses == SOURCE_PATH_STATUS_VALUES


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
    acquisition_status = gate["acquisitionStatuses"]["juliet-c-cpp-1.3"]
    assert "localPath" not in acquisition_status
    assert "resolvedLocalPath" not in acquisition_status
    assert acquisition_status["localPathStatus"] == "not_declared"
    assert acquisition_status["resolvedLocalPathStatus"] == "not_resolved"
    assert acquisition_status["reasonCodes"] == ["LOCAL_JULIET_CORPUS_NOT_PRESENT"]
    external = external_corpus_status_from_readiness(gate)
    assert external["juliet"]["status"] == "blocked"


def test_readiness_blocks_when_required_corpora_are_not_declared() -> None:
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
        required_corpora=[],
    )

    assert gate["status"] == "blocked"
    assert gate["decisionGradeReady"] is False
    assert gate["reasonCodes"] == ["CORPUS_REQUIRED_CORPORA_NOT_DECLARED"]


def test_readiness_rejects_required_corpus_id_with_control_chars_without_raw_leak() -> None:
    secret = "SECRET_CORPUS_SHOULD_NOT_LEAK\n"
    gate = build_corpus_readiness_gate(
        acquisition_manifests=[],
        corpus_manifest=_local_canary_corpus(),
        required_corpora=[secret],
    )

    payload = json.dumps(gate, sort_keys=True)
    assert gate["status"] == "blocked"
    assert gate["reasonCodes"] == ["CORPUS_REQUIRED_CORPUS_ID_INVALID"]
    assert gate["requiredCorpora"] == []
    assert gate["caseStatuses"] == []
    assert "SECRET_CORPUS_SHOULD_NOT_LEAK" not in payload


def test_readiness_rejects_non_string_required_corpus_id_without_raw_repr_leak() -> None:
    class SecretCorpusId:
        def __repr__(self) -> str:
            return "SECRET_CORPUS_REPR_SHOULD_NOT_LEAK"

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[],
        corpus_manifest=_local_canary_corpus(),
        required_corpora=[SecretCorpusId()],
    )

    payload = json.dumps(gate, sort_keys=True)
    assert gate["status"] == "blocked"
    assert gate["reasonCodes"] == ["CORPUS_REQUIRED_CORPUS_ID_INVALID"]
    assert "SECRET_CORPUS_REPR_SHOULD_NOT_LEAK" not in payload


def test_readiness_projects_safe_unknown_required_corpus_as_generic_external_status() -> None:
    gate = build_corpus_readiness_gate(
        acquisition_manifests=[],
        corpus_manifest=_local_canary_corpus(),
        required_corpora=["custom-corpus-1"],
    )

    assert gate["status"] == "blocked"
    assert gate["requiredCorpora"] == ["custom-corpus-1"]
    assert "LOCAL_EXTERNAL_CORPUS_NOT_PRESENT" in gate["reasonCodes"]
    assert "custom-corpus-1" in gate["acquisitionStatuses"]
    assert gate["externalCorpusStatus"] == {
        "external": {
            "status": "blocked",
            "reasonCodes": ["LOCAL_EXTERNAL_CORPUS_NOT_PRESENT"],
            "acquisitionIds": ["custom-corpus-1"],
        },
    }


def test_external_projection_sanitizes_caller_supplied_readiness_status_without_raw_leak() -> None:
    secret_key = "SECRET_STATUS_KEY_SHOULD_NOT_LEAK"
    secret_reason = "SECRET_REASON_SHOULD_NOT_LEAK"
    secret_nested = "SECRET_NESTED_FIELD_SHOULD_NOT_LEAK"
    gate = {
        "status": "blocked",
        "decisionGradeReady": False,
        "requiredCorpora": ["custom-corpus-1"],
        "reasonCodes": ["LOCAL_EXTERNAL_CORPUS_NOT_PRESENT", secret_reason],
        "externalCorpusStatus": {
            secret_key: {"status": "blocked", "reasonCodes": ["LOCAL_EXTERNAL_CORPUS_NOT_PRESENT"]},
            "external": {
                "status": "blocked",
                "reasonCodes": ["LOCAL_EXTERNAL_CORPUS_NOT_PRESENT", secret_reason],
                "acquisitionIds": ["custom-corpus-1", secret_key],
                "attackerField": secret_nested,
            },
        },
    }

    external = external_corpus_status_from_readiness(gate)

    payload = json.dumps(external, sort_keys=True)
    assert external["external"] == {
        "status": "blocked",
        "reasonCodes": ["LOCAL_EXTERNAL_CORPUS_NOT_PRESENT"],
        "acquisitionIds": ["custom-corpus-1"],
    }
    assert external["requiredCorpusReadiness"] == {
        "status": "blocked",
        "reasonCodes": ["LOCAL_EXTERNAL_CORPUS_NOT_PRESENT"],
    }
    assert "SECRET_STATUS_KEY_SHOULD_NOT_LEAK" not in payload
    assert "SECRET_REASON_SHOULD_NOT_LEAK" not in payload
    assert "SECRET_NESTED_FIELD_SHOULD_NOT_LEAK" not in payload


def test_default_not_run_readiness_projects_external_corpus_blocker() -> None:
    external = external_corpus_status_from_readiness(default_not_run_corpus_readiness_gate())

    assert external == {
        "requiredCorpusReadiness": {
            "status": "not_run",
            "reasonCodes": ["CORPUS_READINESS_GATE_NOT_RUN"],
        },
    }


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
    root = tmp_path / "SECRET_ROOT_SHOULD_NOT_LEAK" / "juliet"
    root.mkdir(parents=True)
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
    payload = json.dumps(gate, sort_keys=True)
    assert "SECRET_ROOT_SHOULD_NOT_LEAK" not in payload
    assert str(root.resolve()) not in payload
    assert all("resolvedPath" not in status for status in gate["caseStatuses"])
    acquisition_status = gate["acquisitionStatuses"][acquisition["acquisitionId"]]
    assert "localPath" not in acquisition_status
    assert "resolvedLocalPath" not in acquisition_status
    assert acquisition_status["localPathStatus"] == "available"
    assert acquisition_status["resolvedLocalPathStatus"] == "available"
    validation_status = next(
        status
        for status in gate["caseStatuses"]
        if status["caseId"] == "juliet-validation"
    )
    assert validation_status["status"] == "blocked"
    assert validation_status["reasonCodes"] == ["CORPUS_CASE_SOURCE_MISSING"]
    assert validation_status["sourcePath"] == "CWE121/validation.c"
    assert validation_status["resolvedPathStatus"] == "missing"


def test_readiness_blocks_when_case_checksum_does_not_match(tmp_path: Path) -> None:
    root = tmp_path / "SECRET_ROOT_SHOULD_NOT_LEAK" / "juliet"
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
    payload = json.dumps(gate, sort_keys=True)
    assert "SECRET_ROOT_SHOULD_NOT_LEAK" not in payload
    assert str(root.resolve()) not in payload
    assert all("resolvedPath" not in status for status in gate["caseStatuses"])
    acquisition_status = gate["acquisitionStatuses"][acquisition["acquisitionId"]]
    assert "localPath" not in acquisition_status
    assert "resolvedLocalPath" not in acquisition_status
    assert acquisition_status["localPathStatus"] == "available"
    assert acquisition_status["resolvedLocalPathStatus"] == "available"
    mismatch = [case for case in gate["caseStatuses"] if case["caseId"] == "juliet-validation"][0]
    assert mismatch["status"] == "blocked"
    assert mismatch["sourcePath"] == "CWE121/validation.c"
    assert mismatch["expectedChecksum"] == "sha256:" + "3" * 64
    assert mismatch["actualChecksum"] == _sha256_text("bad();\n")
    assert mismatch["resolvedPathStatus"] == "checksum_mismatch"


def test_readiness_rejects_malformed_case_checksum_before_expected_checksum_projection(
    tmp_path: Path,
) -> None:
    root = tmp_path / "SECRET_ROOT_SHOULD_NOT_LEAK" / "juliet"
    (root / "CWE121").mkdir(parents=True)
    (root / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (root / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    acquisition = _acquisition(root)
    secret_checksum = "sha256:SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK"
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=secret_checksum, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition, polarity="negative"),
    ])

    with pytest.raises(ValueError) as excinfo:
        build_corpus_readiness_gate(
            acquisition_manifests=[acquisition],
            corpus_manifest=corpus,
            required_corpora=["juliet-c-cpp-1.3"],
        )

    message = str(excinfo.value)
    assert "juliet-validation.checksum" in message
    assert "sha256:<64 lowercase hex>" in message
    assert "SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK" not in message
    assert secret_checksum not in message


def test_readiness_passes_when_required_juliet_cases_exist_and_match_checksums(tmp_path: Path) -> None:
    root = tmp_path / "SECRET_ROOT_SHOULD_NOT_LEAK" / "juliet"
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
    payload = json.dumps(gate, sort_keys=True)
    assert "SECRET_ROOT_SHOULD_NOT_LEAK" not in payload
    assert str(root.resolve()) not in payload
    assert all("resolvedPath" not in status for status in gate["caseStatuses"])
    acquisition_status = gate["acquisitionStatuses"][acquisition["acquisitionId"]]
    assert "localPath" not in acquisition_status
    assert "resolvedLocalPath" not in acquisition_status
    assert acquisition_status["localPathStatus"] == "available"
    assert acquisition_status["resolvedLocalPathStatus"] == "available"
    assert {
        (case["sourcePath"], case["resolvedPathStatus"], case["checksum"])
        for case in gate["caseStatuses"]
    } == {
        ("CWE121/validation.c", "available", _sha256_text("bad();\n")),
        ("CWE121/test.c", "available", _sha256_text("good();\n")),
    }


def test_readiness_blocks_relative_local_path_that_escapes_explicit_base(tmp_path: Path) -> None:
    base = tmp_path / "base"
    outside = tmp_path / "outside-juliet"
    (outside / "CWE121").mkdir(parents=True)
    (outside / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (outside / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    acquisition = _acquisition("../outside-juliet")
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition, polarity="negative"),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
        base_path=base,
    )

    assert gate["status"] == "blocked"
    assert "LOCAL_CORPUS_PATH_OUTSIDE_BASE" in gate["reasonCodes"]
    assert "LOCAL_CORPUS_PATH_NOT_FOUND" not in gate["reasonCodes"]
    assert gate["caseStatuses"] == []
    assert gate["summary"]["checkedCaseCount"] == 0


def test_readiness_blocks_relative_local_path_symlink_that_escapes_explicit_base(tmp_path: Path) -> None:
    base = tmp_path / "base"
    outside = tmp_path / "outside-juliet"
    link = base / "corpora" / "juliet-link"
    (outside / "CWE121").mkdir(parents=True)
    (outside / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (outside / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    link.parent.mkdir(parents=True)
    link.symlink_to(outside, target_is_directory=True)
    acquisition = _acquisition("corpora/juliet-link")
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition, polarity="negative"),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
        base_path=base,
    )

    assert gate["status"] == "blocked"
    assert "LOCAL_CORPUS_PATH_OUTSIDE_BASE" in gate["reasonCodes"]
    assert "LOCAL_CORPUS_PATH_NOT_FOUND" not in gate["reasonCodes"]
    assert gate["caseStatuses"] == []
    assert gate["summary"]["checkedCaseCount"] == 0


def test_readiness_allows_absolute_local_path_outside_explicit_base(tmp_path: Path) -> None:
    base = tmp_path / "base"
    outside = tmp_path / "outside-juliet"
    (outside / "CWE121").mkdir(parents=True)
    (outside / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (outside / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    acquisition = _acquisition(outside)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition, polarity="negative"),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
        base_path=base,
    )

    assert gate["status"] == "available"
    assert gate["reasonCodes"] == []
    assert gate["summary"]["checkedCaseCount"] == 2


def test_readiness_aggregates_multiple_sard_acquisitions_without_hiding_blockers(tmp_path: Path) -> None:
    root = tmp_path / "sard-vulnerable"
    (root / "case" / "src").mkdir(parents=True)
    (root / "case" / "src" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (root / "case" / "src" / "test.c").write_text("bad2();\n", encoding="utf-8")
    vulnerable = _acquisition(root, acquisition_id="sard-c-v2-vulnerable")
    secure = _acquisition(tmp_path / "missing-secure", acquisition_id="sard-c-v2-secure")
    corpus = _corpus([
        _case("sard-vulnerable-validation", split="validation", source_path="case/src/validation.c", checksum=_sha256_text("bad();\n"), acquisition=vulnerable),
        _case("sard-vulnerable-test", split="test", source_path="case/src/test.c", checksum=_sha256_text("bad2();\n"), acquisition=vulnerable),
        _case("sard-secure-validation", split="validation", source_path="case/src/validation.c", checksum="sha256:" + "5" * 64, acquisition=secure),
        _case("sard-secure-test", split="test", source_path="case/src/test.c", checksum="sha256:" + "6" * 64, acquisition=secure),
    ])
    for case in corpus["cases"]:
        case["sliceKind"] = "sard-focused"
        case["sourceArtifact"] = "SARD C v2"

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[vulnerable, secure],
        corpus_manifest=corpus,
        required_corpora=["sard-c-v2-vulnerable", "sard-c-v2-secure"],
    )

    assert gate["status"] == "blocked"
    assert gate["externalCorpusStatus"]["sard"]["status"] == "blocked"
    assert gate["externalCorpusStatus"]["sard"]["acquisitionIds"] == ["sard-c-v2-secure", "sard-c-v2-vulnerable"]
    assert "LOCAL_SARD_CORPUS_NOT_PRESENT" in gate["externalCorpusStatus"]["sard"]["reasonCodes"]


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


@pytest.mark.parametrize(
    "source_path",
    [
        "/tmp/SECRET_RAW_SHOULD_NOT_LEAK.c",
        "../SECRET_RAW_SHOULD_NOT_LEAK.c",
        "..\\SECRET_RAW_SHOULD_NOT_LEAK.c",
        "safe\\..\\SECRET_RAW_SHOULD_NOT_LEAK.c",
        "C:\\SECRET_RAW_SHOULD_NOT_LEAK.c",
        "\\\\server\\share\\SECRET_RAW_SHOULD_NOT_LEAK.c",
    ],
)
def test_readiness_redacts_unsafe_case_source_paths_without_losing_blocker_identity(
    tmp_path: Path,
    source_path: str,
) -> None:
    root = tmp_path / "juliet"
    root.mkdir()
    acquisition = _acquisition(root)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path=source_path, checksum="sha256:" + "3" * 64, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum="sha256:" + "4" * 64, acquisition=acquisition),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    payload = json.dumps(gate, sort_keys=True)
    unsafe_status = next(
        status
        for status in gate["caseStatuses"]
        if status["caseId"] == "juliet-validation"
    )

    assert gate["status"] == "blocked"
    assert "CORPUS_CASE_SOURCE_PATH_UNSAFE" in gate["reasonCodes"]
    assert "SECRET_RAW_SHOULD_NOT_LEAK" not in payload
    assert json.dumps(source_path)[1:-1] not in payload
    assert unsafe_status["status"] == "blocked"
    assert unsafe_status["acquisitionId"] == acquisition["acquisitionId"]
    assert unsafe_status["caseId"] == "juliet-validation"
    assert unsafe_status["sourcePath"] == "<unsafe>"
    assert unsafe_status["sourcePathStatus"] == "unsafe"
    assert unsafe_status["reasonCodes"] == ["CORPUS_CASE_SOURCE_PATH_UNSAFE"]


@pytest.mark.parametrize(
    "source_path",
    [
        "..\\escape.c",
        "safe\\..\\escape.c",
        "C:\\secret.c",
        "\\\\server\\share\\secret.c",
    ],
)
def test_readiness_rejects_backslash_normalized_unsafe_case_source_paths(
    tmp_path: Path,
    source_path: str,
) -> None:
    root = tmp_path / "juliet"
    root.mkdir()
    acquisition = _acquisition(root)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path=source_path, checksum="sha256:" + "3" * 64, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum="sha256:" + "4" * 64, acquisition=acquisition),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["status"] == "blocked"
    assert "CORPUS_CASE_SOURCE_PATH_UNSAFE" in gate["reasonCodes"]
    unsafe_status = next(
        status
        for status in gate["caseStatuses"]
        if status["caseId"] == "juliet-validation"
    )
    assert unsafe_status["reasonCodes"] == ["CORPUS_CASE_SOURCE_PATH_UNSAFE"]


def test_readiness_rejects_backslash_unsafe_path_even_when_literal_file_exists(tmp_path: Path) -> None:
    root = tmp_path / "juliet"
    root.mkdir()
    literal = root / "..\\escape.c"
    literal.write_text("literal unsafe-looking path", encoding="utf-8")
    acquisition = _acquisition(root)
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="..\\escape.c", checksum=_sha(literal), acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum="sha256:" + "4" * 64, acquisition=acquisition),
    ])

    gate = build_corpus_readiness_gate(
        acquisition_manifests=[acquisition],
        corpus_manifest=corpus,
        required_corpora=["juliet-c-cpp-1.3"],
    )

    assert gate["status"] == "blocked"
    assert "CORPUS_CASE_SOURCE_PATH_UNSAFE" in gate["reasonCodes"]
    assert all(status["status"] != "available" for status in gate["caseStatuses"])


def test_readiness_cli_blocks_without_required_corpora(tmp_path: Path, capsys) -> None:
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(json.dumps({
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
    }), encoding="utf-8")

    exit_code = corpus_readiness_main(["--corpus-manifest", str(corpus_path)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 2
    assert payload["status"] == "blocked"
    assert payload["reasonCodes"] == ["CORPUS_REQUIRED_CORPORA_NOT_DECLARED"]


def test_readiness_cli_missing_required_arg_fails_without_argparse_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    def fail_if_loaded(path: Path, label: str) -> dict:
        pytest.fail(f"_load_json_object should not be called for parser failure: {label} {path}")

    def fail_if_built(**kwargs: object) -> dict:
        pytest.fail(f"build_corpus_readiness_gate should not be called for parser failure: {kwargs}")

    monkeypatch.setattr("benchmark.tool_portfolio_corpus_readiness._load_json_object", fail_if_loaded)
    monkeypatch.setattr("benchmark.tool_portfolio_corpus_readiness.build_corpus_readiness_gate", fail_if_built)

    exit_code = corpus_readiness_main([])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    serialized = json.dumps(payload, sort_keys=True)
    assert exit_code == 1
    assert captured.err == ""
    assert payload["status"] == "invalid"
    assert payload["reasonCodes"] == ["CORPUS_READINESS_INPUT_INVALID"]
    assert payload["error"] == "input validation failed"
    assert payload["errorClass"] == "ValueError"
    assert "usage:" not in serialized
    assert "SystemExit" not in serialized
    assert "required" not in serialized
    assert "--corpus-manifest" not in serialized


def test_readiness_cli_unknown_arg_fails_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    secret_corpus_path = tmp_path / "SECRET_CORPUS_PATH_SHOULD_NOT_LEAK.json"
    secret_flag = "--SECRET_FLAG_SHOULD_NOT_LEAK"

    def fail_if_loaded(path: Path, label: str) -> dict:
        pytest.fail(f"_load_json_object should not be called for parser failure: {label} {path}")

    def fail_if_built(**kwargs: object) -> dict:
        pytest.fail(f"build_corpus_readiness_gate should not be called for parser failure: {kwargs}")

    monkeypatch.setattr("benchmark.tool_portfolio_corpus_readiness._load_json_object", fail_if_loaded)
    monkeypatch.setattr("benchmark.tool_portfolio_corpus_readiness.build_corpus_readiness_gate", fail_if_built)

    exit_code = corpus_readiness_main([
        "--corpus-manifest",
        str(secret_corpus_path),
        secret_flag,
    ])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    serialized = json.dumps(payload, sort_keys=True)
    assert exit_code == 1
    assert captured.err == ""
    assert payload["status"] == "invalid"
    assert payload["reasonCodes"] == ["CORPUS_READINESS_INPUT_INVALID"]
    assert payload["error"] == "input validation failed"
    assert "usage:" not in serialized
    assert "unrecognized arguments" not in serialized
    assert "SystemExit" not in serialized
    assert str(secret_corpus_path) not in serialized
    assert "SECRET_CORPUS_PATH_SHOULD_NOT_LEAK" not in serialized
    assert secret_flag not in serialized
    assert "SECRET_FLAG_SHOULD_NOT_LEAK" not in serialized


def test_readiness_cli_missing_required_corpus_value_fails_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    def fail_if_loaded(path: Path, label: str) -> dict:
        pytest.fail(f"_load_json_object should not be called for parser failure: {label} {path}")

    def fail_if_built(**kwargs: object) -> dict:
        pytest.fail(f"build_corpus_readiness_gate should not be called for parser failure: {kwargs}")

    monkeypatch.setattr("benchmark.tool_portfolio_corpus_readiness._load_json_object", fail_if_loaded)
    monkeypatch.setattr("benchmark.tool_portfolio_corpus_readiness.build_corpus_readiness_gate", fail_if_built)

    exit_code = corpus_readiness_main([
        "--corpus-manifest",
        str(tmp_path / "corpus.json"),
        "--required-corpus",
    ])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    serialized = json.dumps(payload, sort_keys=True)
    assert exit_code == 1
    assert captured.err == ""
    assert payload["status"] == "invalid"
    assert payload["reasonCodes"] == ["CORPUS_READINESS_INPUT_INVALID"]
    assert payload["error"] == "input validation failed"
    assert "usage:" not in serialized
    assert "expected one argument" not in serialized
    assert "SystemExit" not in serialized


def test_readiness_cli_invalid_input_does_not_leak_raw_exception_path(
    tmp_path: Path,
    capsys,
) -> None:
    corpus_path = tmp_path / "SECRET_RAW_SHOULD_NOT_LEAK-corpus.json"
    corpus_path.write_text("[]", encoding="utf-8")

    exit_code = corpus_readiness_main(["--corpus-manifest", str(corpus_path)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    serialized = json.dumps(payload, sort_keys=True)
    assert exit_code == 1
    assert payload["status"] == "invalid"
    assert payload["reasonCodes"] == ["CORPUS_READINESS_INPUT_INVALID"]
    assert payload["error"] == "input validation failed"
    assert payload["errorClass"] == "ValueError"
    assert "SECRET_RAW_SHOULD_NOT_LEAK" not in serialized
    assert str(corpus_path) not in serialized


def test_readiness_json_object_loader_does_not_echo_raw_path(tmp_path: Path) -> None:
    json_path = tmp_path / "SECRET_JSON_OBJECT_PATH_SHOULD_NOT_LEAK.json"
    json_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError) as error:
        _load_json_object(json_path, "corpus manifest")

    message = str(error.value)
    assert "corpus manifest must be a JSON object" in message
    assert str(json_path) not in message
    assert "SECRET_JSON_OBJECT_PATH_SHOULD_NOT_LEAK" not in message


def test_readiness_cli_malformed_case_checksum_is_sanitized_invalid_input(
    tmp_path: Path,
    capsys,
) -> None:
    root = tmp_path / "corpora" / "juliet"
    (root / "CWE121").mkdir(parents=True)
    (root / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (root / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    acquisition = _acquisition("corpora/juliet")
    secret_checksum = "sha256:SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK"
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=secret_checksum, acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition, polarity="negative"),
    ])
    acquisition_path = tmp_path / "acquisition.json"
    corpus_path = tmp_path / "corpus.json"
    acquisition_path.write_text(json.dumps(acquisition), encoding="utf-8")
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    exit_code = corpus_readiness_main([
        "--corpus-manifest",
        str(corpus_path),
        "--acquisition-manifest",
        str(acquisition_path),
        "--required-corpus",
        "juliet-c-cpp-1.3",
        "--base-path",
        str(tmp_path),
    ])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    serialized = json.dumps(payload, sort_keys=True)
    assert exit_code == 1
    assert payload["status"] == "invalid"
    assert payload["reasonCodes"] == ["CORPUS_READINESS_INPUT_INVALID"]
    assert payload["error"] == "input validation failed"
    assert payload["errorClass"] == "ValueError"
    assert "SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK" not in serialized
    assert secret_checksum not in serialized


def test_readiness_cli_output_write_failure_falls_back_to_sanitized_stdout(
    tmp_path: Path,
    capsys,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(json.dumps(_local_canary_corpus()), encoding="utf-8")
    output_dir = tmp_path / "SECRET_OUTPUT_PATH_SHOULD_NOT_LEAK"
    output_dir.mkdir()

    exit_code = corpus_readiness_main([
        "--corpus-manifest",
        str(corpus_path),
        "--output",
        str(output_dir),
    ])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    serialized = json.dumps(payload, sort_keys=True)
    assert exit_code == 1
    assert output_dir.is_dir()
    assert payload["status"] == "invalid"
    assert payload["decisionGradeReady"] is False
    assert payload["reasonCodes"] == ["CORPUS_READINESS_OUTPUT_WRITE_FAILED"]
    assert payload["error"] == "output write failed"
    assert payload["errorClass"] == "IsADirectoryError"
    assert "SECRET_OUTPUT_PATH_SHOULD_NOT_LEAK" not in serialized
    assert str(output_dir) not in serialized


def test_readiness_cli_writes_available_gate_for_matching_required_corpus(tmp_path: Path, capsys) -> None:
    root = tmp_path / "corpora" / "juliet"
    (root / "CWE121").mkdir(parents=True)
    (root / "CWE121" / "validation.c").write_text("bad();\n", encoding="utf-8")
    (root / "CWE121" / "test.c").write_text("good();\n", encoding="utf-8")
    acquisition = _acquisition("corpora/juliet")
    corpus = _corpus([
        _case("juliet-validation", split="validation", source_path="CWE121/validation.c", checksum=_sha256_text("bad();\n"), acquisition=acquisition),
        _case("juliet-test", split="test", source_path="CWE121/test.c", checksum=_sha256_text("good();\n"), acquisition=acquisition, polarity="negative"),
    ])
    acquisition_path = tmp_path / "acquisition.json"
    corpus_path = tmp_path / "corpus.json"
    output_path = tmp_path / "readiness.json"
    acquisition_path.write_text(json.dumps(acquisition), encoding="utf-8")
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")

    exit_code = corpus_readiness_main([
        "--corpus-manifest",
        str(corpus_path),
        "--acquisition-manifest",
        str(acquisition_path),
        "--required-corpus",
        "juliet-c-cpp-1.3",
        "--base-path",
        str(tmp_path),
        "--output",
        str(output_path),
    ])

    captured = capsys.readouterr()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert captured.out == ""
    assert exit_code == 0
    assert payload["status"] == "available"
    assert payload["decisionGradeReady"] is True
    assert payload["requiredCorpora"] == ["juliet-c-cpp-1.3"]
