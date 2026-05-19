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


def test_corpus_manifest_rejects_duplicate_case_id_without_echoing_safe_shaped_secret() -> None:
    secret_case_id = "SECRET_DUPLICATE_CASE_ID_SHOULD_NOT_LEAK"
    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["caseId"] = secret_case_id
    corpus["cases"][0]["targetId"] = f"{secret_case_id}-target"
    corpus["cases"][0]["lineageId"] = "secret-duplicate-validation-lineage"
    corpus["cases"][0]["expected"]["targetId"] = f"{secret_case_id}-target"
    duplicate = copy.deepcopy(corpus["cases"][0])
    duplicate["lineageId"] = "secret-duplicate-test-lineage"
    corpus["cases"].append(duplicate)

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "duplicate caseId" in message
    assert secret_case_id not in message


def test_corpus_manifest_rejects_external_case_without_acquisition_linkage() -> None:
    corpus, acquisition = _corpus_manifest()
    del corpus["cases"][0]["acquisitionManifestChecksum"]

    with pytest.raises(ValueError, match="acquisitionManifestChecksum"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_acquisition_checksum_mismatch() -> None:
    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["acquisitionManifestChecksum"] = "sha256:" + "0" * 64

    with pytest.raises(ValueError, match="acquisitionManifestChecksum mismatch"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_missing_acquisition_without_echoing_safe_shaped_secret() -> None:
    corpus, acquisition = _corpus_manifest()
    secret_acquisition_id = "SECRET_ACQUISITION_ID_SHOULD_NOT_LEAK"
    corpus["cases"][0]["acquisitionId"] = secret_acquisition_id

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "acquisitionId not found in acquisition index" in message
    assert secret_acquisition_id not in message


def test_corpus_manifest_rejects_acquisition_checksum_mismatch_without_echoing_acquisition_id() -> None:
    corpus, acquisition = _corpus_manifest()
    secret_acquisition_id = "SECRET_ACQUISITION_ID_SHOULD_NOT_LEAK"
    acquisition["acquisitionId"] = secret_acquisition_id
    corpus["cases"][0]["acquisitionId"] = secret_acquisition_id
    corpus["cases"][0]["sourceRef"] = f"{secret_acquisition_id}:CWE121/foo.c"
    corpus["cases"][0]["acquisitionManifestChecksum"] = "sha256:" + "0" * 64

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "acquisitionManifestChecksum mismatch" in message
    assert secret_acquisition_id not in message


@pytest.mark.parametrize(
    "checksum",
    [
        "sha256:SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK",
        "sha256:" + "a" * 63,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
    ],
)
def test_corpus_manifest_rejects_malformed_case_checksum_without_echoing_raw_value(
    checksum: str,
) -> None:
    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["checksum"] = checksum

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "juliet-cwe121-validation.checksum" in message
    assert "sha256:<64 lowercase hex>" in message
    assert checksum not in message
    assert "SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK" not in message


@pytest.mark.parametrize(
    ("field", "value", "expected_fragment"),
    [
        ("caseId", "SECRET_CASE_ID_SHOULD_NOT_LEAK\n", "cases[0].caseId"),
        ("targetId", "SECRET_TARGET_ID_SHOULD_NOT_LEAK\n", "juliet-cwe121-validation.expected.targetId"),
        ("lineageId", "SECRET_LINEAGE_ID_SHOULD_NOT_LEAK\n", "juliet-cwe121-validation.lineageId"),
        ("acquisitionId", "SECRET_ACQUISITION_ID_SHOULD_NOT_LEAK\n", "juliet-cwe121-validation.acquisitionId"),
    ],
)
def test_corpus_manifest_rejects_unsafe_identity_fields_without_echoing_raw_value(
    field: str,
    value: str,
    expected_fragment: str,
) -> None:
    corpus, acquisition = _corpus_manifest()
    if field == "targetId":
        corpus["cases"][0]["expected"]["targetId"] = value
    else:
        corpus["cases"][0][field] = value

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert expected_fragment in message
    assert "safe identifier" in message
    assert value not in message
    assert "SHOULD_NOT_LEAK" not in message


@pytest.mark.parametrize(
    ("source_path", "reason"),
    [
        ("", "non-empty"),
        (" ", "surrounding whitespace"),
        (123, "non-empty"),
        ("/tmp/secret.c", "absolute path"),
        ("C:\\\\secret.c", "absolute path"),
        ("\\\\\\\\server\\\\share\\\\secret.c", "absolute path"),
        ("../secret.c", "path traversal"),
        ("safe/../secret.c", "path traversal"),
        ("..\\\\secret.c", "path traversal"),
        ("safe\\\\..\\\\secret.c", "path traversal"),
    ],
)
def test_corpus_manifest_rejects_unsafe_source_path_without_echoing_raw_value(
    source_path: object,
    reason: str,
) -> None:
    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["sourcePath"] = source_path

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "juliet-cwe121-validation.sourcePath" in message
    assert reason in message
    if isinstance(source_path, str) and len(source_path) > 1:
        assert source_path not in message


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


def test_corpus_manifest_rejects_validation_test_lineage_leakage_without_echoing_lineage_id() -> None:
    acquisition = _acquisition_manifest()
    secret_lineage_id = "SECRET_LINEAGE_ID_SHOULD_NOT_LEAK"
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [
            _external_case("case-validation", "validation", lineage_id=secret_lineage_id),
            _external_case("case-test", "test", lineage_id=secret_lineage_id),
        ],
    }

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "lineage leakage" in message
    assert secret_lineage_id not in message


def test_corpus_manifest_rejects_validation_test_source_artifact_leakage_even_with_distinct_lineage() -> None:
    acquisition = _acquisition_manifest()
    validation_case = _external_case("case-validation", "validation", lineage_id="validation-lineage")
    test_case = _external_case("case-test", "test", lineage_id="test-lineage")
    test_case["sourceRef"] = validation_case["sourceRef"]
    test_case["checksum"] = validation_case["checksum"]
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [validation_case, test_case],
    }

    with pytest.raises(ValueError, match="source artifact leakage"):
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))


def test_corpus_manifest_rejects_source_artifact_leakage_without_echoing_source_ref() -> None:
    acquisition = _acquisition_manifest()
    secret_source_ref = "juliet-c-cpp-1.3:SECRET_SOURCE_REF_SHOULD_NOT_LEAK"
    validation_case = _external_case("case-validation", "validation", lineage_id="validation-lineage")
    test_case = _external_case("case-test", "test", lineage_id="test-lineage")
    validation_case["sourceRef"] = secret_source_ref
    test_case["sourceRef"] = secret_source_ref
    test_case["checksum"] = validation_case["checksum"]
    corpus = {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "profile": "c-cpp-tool-portfolio-v1",
        "createdAt": "2026-05-12",
        "owner": "s4-sast-runner",
        "cases": [validation_case, test_case],
    }

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "source artifact leakage" in message
    assert "SECRET_SOURCE_REF_SHOULD_NOT_LEAK" not in message
    assert secret_source_ref not in message


def test_corpus_manifest_uses_case_id_as_public_lineage_fallback_when_lineage_id_absent() -> None:
    corpus, acquisition = _corpus_manifest()
    del corpus["cases"][0]["lineageId"]
    corpus["cases"][0]["sourceRef"] = "juliet-c-cpp-1.3:SECRET_SOURCE_REF_SHOULD_NOT_LEAK"

    report = validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    target = next(item for item in report["targets"] if item["caseId"] == "juliet-cwe121-validation")
    assert target["lineageId"] == "juliet-cwe121-validation"
    assert "SECRET_SOURCE_REF_SHOULD_NOT_LEAK" not in str(target["lineageId"])


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


def test_corpus_manifest_rejects_forbidden_verdict_key_without_echoing_parent_path() -> None:
    corpus, acquisition = _corpus_manifest()
    secret_parent = "SECRET_FORBIDDEN_PARENT_SHOULD_NOT_LEAK"
    corpus["cases"][0]["expected"][secret_parent] = {"safe": False}

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "forbidden verdict key" in message
    assert "safe" in message
    assert secret_parent not in message


def test_corpus_manifest_rejects_forbidden_verdict_key_without_stringifying_parent_key_object() -> None:
    class SecretKey:
        def __str__(self) -> str:
            return "SECRET_FORBIDDEN_PARENT_STR_SHOULD_NOT_LEAK"

        def __repr__(self) -> str:
            return "SECRET_FORBIDDEN_PARENT_REPR_SHOULD_NOT_LEAK"

    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["expected"][SecretKey()] = {"safe": False}

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "forbidden verdict key" in message
    assert "safe" in message
    assert "SECRET_FORBIDDEN_PARENT_STR_SHOULD_NOT_LEAK" not in message
    assert "SECRET_FORBIDDEN_PARENT_REPR_SHOULD_NOT_LEAK" not in message


def test_corpus_manifest_rejects_forbidden_verdict_key_without_stringifying_key_object() -> None:
    class SecretForbiddenKey(str):
        def __new__(cls) -> "SecretForbiddenKey":
            return str.__new__(cls, "safe")

        def __str__(self) -> str:
            return "SECRET_FORBIDDEN_KEY_STR_SHOULD_NOT_LEAK"

        def __repr__(self) -> str:
            return "SECRET_FORBIDDEN_KEY_REPR_SHOULD_NOT_LEAK"

    corpus, acquisition = _corpus_manifest()
    corpus["cases"][0]["expected"][SecretForbiddenKey()] = False

    with pytest.raises(ValueError) as excinfo:
        validate_corpus_manifest(corpus, acquisition_index=build_acquisition_index([acquisition]))

    message = str(excinfo.value)
    assert "forbidden verdict key" in message
    assert "safe" in message
    assert "SECRET_FORBIDDEN_KEY_STR_SHOULD_NOT_LEAK" not in message
    assert "SECRET_FORBIDDEN_KEY_REPR_SHOULD_NOT_LEAK" not in message


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

    future = validate_tool_set_config("add-one-in:clang-analyzer-next", allow_future=True)
    assert future["status"] == "pass"
    assert future["toolSetConfig"] == "add-one-in:clang-analyzer-next"


@pytest.mark.parametrize(
    ("config", "expected_fragment", "secret"),
    [
        ("single-tool:SECRET_TOOL_SHOULD_NOT_LEAK", "unknown current S4 tool", "SECRET_TOOL_SHOULD_NOT_LEAK"),
        ("leave-one-out:SECRET_TOOL_SHOULD_NOT_LEAK", "unknown current S4 tool", "SECRET_TOOL_SHOULD_NOT_LEAK"),
        ("add-one-in:SECRET_CONFIG_SHOULD_NOT_LEAK", "future WR-gated", "SECRET_CONFIG_SHOULD_NOT_LEAK"),
        ("SECRET_CONFIG_SHOULD_NOT_LEAK", "unknown tool-set config", "SECRET_CONFIG_SHOULD_NOT_LEAK"),
    ],
)
def test_tool_set_config_rejects_invalid_values_without_raw_echo(
    config: str,
    expected_fragment: str,
    secret: str,
) -> None:
    with pytest.raises(ValueError) as excinfo:
        validate_tool_set_config(config)

    message = str(excinfo.value)
    assert expected_fragment in message
    assert secret not in message
    assert config not in message


def test_tool_set_config_rejects_non_string_without_stringifying_object() -> None:
    class SecretConfig:
        def __str__(self) -> str:
            return "SECRET_TOOL_SET_CONFIG_STR_SHOULD_NOT_LEAK"

        def __repr__(self) -> str:
            return "SECRET_TOOL_SET_CONFIG_REPR_SHOULD_NOT_LEAK"

    with pytest.raises(ValueError) as excinfo:
        validate_tool_set_config(SecretConfig())  # type: ignore[arg-type]

    message = str(excinfo.value)
    assert "tool-set config must be a string" in message
    assert "SECRET_TOOL_SET_CONFIG_STR_SHOULD_NOT_LEAK" not in message
    assert "SECRET_TOOL_SET_CONFIG_REPR_SHOULD_NOT_LEAK" not in message
