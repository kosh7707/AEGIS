from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

import benchmark.tool_portfolio_corpus_acquisition as corpus_acquisition
from benchmark.tool_portfolio_acquisition_manifest import validate_acquisition_manifest
from benchmark.tool_portfolio_corpus_acquisition import (
    JULIET_SOURCE,
    SARD_SECURE_SOURCE,
    SARD_VULNERABLE_SOURCE,
    _require_checksum,
    _sard_artifact_and_line,
    _safe_rmtree,
    _select_juliet_file,
    acquire_known_corpora,
)
from benchmark.tool_portfolio_corpus_readiness import build_corpus_readiness_gate
from benchmark.tool_portfolio_experiment_manifest import TRACKED_CWES, validate_corpus_manifest


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stderr_payload(stderr: str) -> dict[str, object]:
    payload = json.loads(stderr.strip())
    assert set(payload) == {"error", "reasonCode", "stage"}
    return payload


def _write_zip(path: Path, entries: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, text in entries.items():
            archive.writestr(name, text)
    return path


def test_corpus_acquisition_cli_invalid_corpus_fails_before_acquire_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_corpus = "SECRET_CORPUS_SHOULD_NOT_LEAK"
    secret_output_root = tmp_path / "SECRET_OUTPUT_ROOT_SHOULD_NOT_LEAK"
    secret_summary_output = tmp_path / "SECRET_SUMMARY_OUTPUT_SHOULD_NOT_LEAK.json"

    def fail_if_acquired(**kwargs: object) -> dict[str, object]:
        pytest.fail(f"acquire_known_corpora should not be called for invalid corpus: {kwargs}")

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fail_if_acquired)

    exit_code = corpus_acquisition.main([
        "--corpus",
        secret_corpus,
        "--output-root",
        str(secret_output_root),
        "--summary-output",
        str(secret_summary_output),
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "input validation failed" in captured.err
    assert _stderr_payload(captured.err) == {
        "error": "input validation failed",
        "reasonCode": "CORPUS_ACQUISITION_CLI_INPUT_INVALID",
        "stage": "input",
    }
    assert "usage:" not in captured.err
    assert "invalid choice" not in captured.err
    assert "SystemExit" not in captured.err
    assert secret_corpus not in captured.err
    assert "SECRET_CORPUS_SHOULD_NOT_LEAK" not in captured.err
    assert str(secret_output_root) not in captured.err
    assert "SECRET_OUTPUT_ROOT_SHOULD_NOT_LEAK" not in captured.err
    assert str(secret_summary_output) not in captured.err
    assert "SECRET_SUMMARY_OUTPUT_SHOULD_NOT_LEAK" not in captured.err
    assert not secret_summary_output.exists()


def test_corpus_acquisition_cli_unknown_arg_fails_without_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_flag = "--SECRET_FLAG_SHOULD_NOT_LEAK"

    def fail_if_acquired(**kwargs: object) -> dict[str, object]:
        pytest.fail(f"acquire_known_corpora should not be called for unknown arg: {kwargs}")

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fail_if_acquired)

    exit_code = corpus_acquisition.main([secret_flag])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "input validation failed" in captured.err
    assert _stderr_payload(captured.err) == {
        "error": "input validation failed",
        "reasonCode": "CORPUS_ACQUISITION_CLI_INPUT_INVALID",
        "stage": "input",
    }
    assert "usage:" not in captured.err
    assert "unrecognized arguments" not in captured.err
    assert "SystemExit" not in captured.err
    assert secret_flag not in captured.err
    assert "SECRET_FLAG_SHOULD_NOT_LEAK" not in captured.err


def test_corpus_acquisition_cli_missing_corpus_value_fails_without_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_if_acquired(**kwargs: object) -> dict[str, object]:
        pytest.fail(f"acquire_known_corpora should not be called for malformed option shape: {kwargs}")

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fail_if_acquired)

    exit_code = corpus_acquisition.main(["--corpus"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "input validation failed" in captured.err
    assert "usage:" not in captured.err
    assert "expected one argument" not in captured.err
    assert "SystemExit" not in captured.err


def test_corpus_acquisition_cli_valid_selection_preserves_acquire_and_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, object] = {}
    output_root = tmp_path / "SECRET_VALID_OUTPUT_ROOT_SHOULD_NOT_LEAK"
    summary_output = tmp_path / "SECRET_VALID_SUMMARY_OUTPUT_SHOULD_NOT_LEAK.json"
    bundle = {
        "schemaVersion": "s4-tool-portfolio-corpus-acquisition-bundle-v1",
        "status": "blocked",
        "decisionGradeReady": False,
        "requiredCorpora": [
            JULIET_SOURCE.acquisition_id,
            SARD_VULNERABLE_SOURCE.acquisition_id,
        ],
    }

    def fake_acquire_known_corpora(**kwargs: object) -> dict[str, object]:
        captured["sourceIds"] = [
            source.acquisition_id
            for source in kwargs["sources"]  # type: ignore[index]
        ]
        captured["outputRoot"] = kwargs["output_root"]
        captured["force"] = kwargs["force"]
        return bundle

    def fake_write_json(payload: dict[str, object], path: Path) -> None:
        captured["summaryPayload"] = payload
        captured["summaryPath"] = path

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fake_acquire_known_corpora)
    monkeypatch.setattr(corpus_acquisition, "_write_json", fake_write_json)

    exit_code = corpus_acquisition.main([
        "--corpus",
        JULIET_SOURCE.acquisition_id,
        "--corpus",
        SARD_VULNERABLE_SOURCE.acquisition_id,
        "--output-root",
        str(output_root),
        "--force",
        "--summary-output",
        str(summary_output),
    ])

    captured_io = capsys.readouterr()
    assert exit_code == 2
    assert captured_io.err == ""
    emitted = json.loads(captured_io.out)
    assert emitted == bundle
    assert str(output_root) not in captured_io.out
    assert str(summary_output) not in captured_io.out
    assert "SECRET_VALID_OUTPUT_ROOT_SHOULD_NOT_LEAK" not in captured_io.out
    assert "SECRET_VALID_SUMMARY_OUTPUT_SHOULD_NOT_LEAK" not in captured_io.out
    assert captured["sourceIds"] == [JULIET_SOURCE.acquisition_id, SARD_VULNERABLE_SOURCE.acquisition_id]
    assert captured["outputRoot"] == str(output_root)
    assert captured["force"] is True
    assert captured["summaryPayload"] == bundle
    assert captured["summaryPath"] == summary_output


def test_corpus_acquisition_cli_summary_output_failure_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []
    summary_output = tmp_path / "SECRET_SUMMARY_OUTPUT_FAILURE_SHOULD_NOT_LEAK.json"
    bundle = {"status": "available", "decisionGradeReady": True}

    def fake_acquire_known_corpora(**kwargs: object) -> dict[str, object]:
        calls.append("acquire")
        return bundle

    def fail_write_json(payload: dict[str, object], path: Path) -> None:
        assert payload == bundle
        assert path == summary_output
        raise OSError("SECRET_SUMMARY_WRITE_SHOULD_NOT_LEAK")

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fake_acquire_known_corpora)
    monkeypatch.setattr(corpus_acquisition, "_write_json", fail_write_json)

    exit_code = corpus_acquisition.main(["--summary-output", str(summary_output)])

    captured = capsys.readouterr()
    assert calls == ["acquire"]
    assert exit_code == 1
    assert captured.out == ""
    assert "corpus acquisition output failed" in captured.err
    assert _stderr_payload(captured.err) == {
        "error": "corpus acquisition output failed",
        "reasonCode": "CORPUS_ACQUISITION_CLI_OUTPUT_FAILED",
        "stage": "output",
    }
    assert "OSError" not in captured.err
    assert "SECRET_SUMMARY_WRITE_SHOULD_NOT_LEAK" not in captured.err
    assert str(summary_output) not in captured.err
    assert "SECRET_SUMMARY_OUTPUT_FAILURE_SHOULD_NOT_LEAK" not in captured.err
    assert "usage:" not in captured.err
    assert "SystemExit" not in captured.err


def test_corpus_acquisition_cli_stdout_serialization_failure_without_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class SECRET_BUNDLE_OBJECT_SHOULD_NOT_LEAK:
        pass

    def fake_acquire_known_corpora(**kwargs: object) -> dict[str, object]:
        return {"status": "available", "bad": SECRET_BUNDLE_OBJECT_SHOULD_NOT_LEAK()}

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fake_acquire_known_corpora)

    exit_code = corpus_acquisition.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "corpus acquisition output failed" in captured.err
    assert _stderr_payload(captured.err) == {
        "error": "corpus acquisition output failed",
        "reasonCode": "CORPUS_ACQUISITION_CLI_OUTPUT_FAILED",
        "stage": "output",
    }
    assert "TypeError" not in captured.err
    assert "SECRET_BUNDLE_OBJECT_SHOULD_NOT_LEAK" not in captured.err
    assert "not JSON serializable" not in captured.err
    assert "SystemExit" not in captured.err


def test_corpus_acquisition_cli_stdout_write_failure_without_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_acquire_known_corpora(**kwargs: object) -> dict[str, object]:
        return {"status": "available", "decisionGradeReady": True}

    def fail_stdout_write(text: str) -> int:
        raise OSError("SECRET_STDOUT_WRITE_SHOULD_NOT_LEAK")

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fake_acquire_known_corpora)
    monkeypatch.setattr(corpus_acquisition.sys.stdout, "write", fail_stdout_write)

    exit_code = corpus_acquisition.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "corpus acquisition output failed" in captured.err
    assert "OSError" not in captured.err
    assert "SECRET_STDOUT_WRITE_SHOULD_NOT_LEAK" not in captured.err
    assert "SystemExit" not in captured.err


def test_corpus_acquisition_cli_stderr_failure_suppresses_output_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class BrokenStderr:
        def write(self, text: str) -> int:
            raise OSError("SECRET_STDERR_WRITE_SHOULD_NOT_LEAK")

        def flush(self) -> None:
            raise OSError("SECRET_STDERR_FLUSH_SHOULD_NOT_LEAK")

    def fake_acquire_known_corpora(**kwargs: object) -> dict[str, object]:
        return {"status": "available", "bad": object()}

    monkeypatch.setattr(corpus_acquisition, "acquire_known_corpora", fake_acquire_known_corpora)
    monkeypatch.setattr(corpus_acquisition.sys, "stderr", BrokenStderr())

    exit_code = corpus_acquisition.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "SECRET_STDERR_WRITE_SHOULD_NOT_LEAK" not in captured.err
    assert "SECRET_STDERR_FLUSH_SHOULD_NOT_LEAK" not in captured.err


def _juliet_fixture_zip(path: Path) -> Path:
    entries: dict[str, str] = {}
    for cwe_id in TRACKED_CWES:
        cwe = cwe_id.split("-", 1)[1]
        for variant in ["01", "02"]:
            source_path = f"C/testcases/CWE{cwe}_Fixture/s01/CWE{cwe}_Fixture__case_{variant}.c"
            entries[source_path] = (
                "#include <string.h>\n"
                "void bad(void) { char dst[4]; char src[8] = \"abcdef\"; memcpy(dst, src, 8); }\n"
                "void good(void) { char dst[8]; char src[4] = \"abc\"; memcpy(dst, src, 4); }\n"
            )
    return _write_zip(path, entries)


def _sard_manifest(cwe: str, source_uri: str, line: int, *, kind: str) -> str:
    return json.dumps({
        "version": "2.1.0",
        "runs": [
            {
                "properties": {"state": "bad" if kind == "fail" else "good"},
                "artifacts": [{"location": {"uri": source_uri}, "sourceLanguage": "c"}],
                "taxonomies": [{"name": "CWE", "taxa": [{"id": cwe}]}],
                "results": [
                    {
                        "ruleId": f"CWE-{cwe}",
                        "kind": kind,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": source_uri},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                        "taxa": [{"id": cwe}],
                    }
                ],
            }
        ],
    })


def _sard_fixture_zip(path: Path, *, secure: bool) -> Path:
    entries: dict[str, str] = {}
    for idx, cwe in enumerate(["134", "121"], start=1):
        for split_idx in [1, 2]:
            case_dir = f"sard-{cwe}-{split_idx}-v1.0.0"
            source_name = "fmt-good.c" if secure else "fmt-bad.c"
            entries[f"{case_dir}/src/{source_name}"] = (
                "#include <stdio.h>\n"
                "int main(int argc, char **argv) {\n"
                "  printf(argc > 1 ? argv[1] : \"ok\");\n"
                "  return 0;\n"
                "}\n"
            )
            entries[f"{case_dir}/manifest.sarif"] = _sard_manifest(
                cwe,
                f"src/{source_name}",
                3,
                kind="pass" if secure else "fail",
            )
    return _write_zip(path, entries)


def _single_candidate_sard_fixture_zip(path: Path, *, secure: bool) -> Path:
    source_name = "fmt-good.c" if secure else "fmt-bad.c"
    return _write_zip(
        path,
        {
            f"sard-134-only/src/{source_name}": (
                "#include <stdio.h>\n"
                "int main(int argc, char **argv) {\n"
                "  printf(argc > 1 ? argv[1] : \"ok\");\n"
                "  return 0;\n"
                "}\n"
            ),
            "sard-134-only/manifest.sarif": _sard_manifest(
                "134",
                f"src/{source_name}",
                3,
                kind="pass" if secure else "fail",
            ),
        },
    )


def test_acquire_known_corpora_from_local_archives_builds_manifests_and_available_readiness(tmp_path: Path) -> None:
    downloads = tmp_path / "source-archives"
    juliet_zip = _juliet_fixture_zip(downloads / "juliet.zip")
    sard_bad_zip = _sard_fixture_zip(downloads / "sard-bad.zip", secure=False)
    sard_good_zip = _sard_fixture_zip(downloads / "sard-good.zip", secure=True)
    sources = [
        replace(JULIET_SOURCE, source_url=juliet_zip.as_uri(), archive_sha256=_sha256_file(juliet_zip), archive_name="juliet.zip"),
        replace(SARD_VULNERABLE_SOURCE, source_url=sard_bad_zip.as_uri(), archive_sha256=_sha256_file(sard_bad_zip), archive_name="sard-bad.zip"),
        replace(SARD_SECURE_SOURCE, source_url=sard_good_zip.as_uri(), archive_sha256=_sha256_file(sard_good_zip), archive_name="sard-good.zip"),
    ]

    bundle = acquire_known_corpora(sources=sources, output_root=tmp_path / "cache", downloaded_at="2026-05-13T00:00:00Z")

    assert bundle["status"] == "available"
    assert bundle["decisionGradeReady"] is True
    assert bundle["requiredCorpora"] == ["juliet-c-cpp-1.3", "sard-c-v2-vulnerable", "sard-c-v2-secure"]
    assert bundle["caseCount"] == 56  # Juliet: 12 CWEs * validation/test * pos/neg; SARD: 2 CWEs * validation/test * vuln/secure.
    corpus_manifest = json.loads(Path(bundle["corpusManifestPath"]).read_text(encoding="utf-8"))
    readiness_gate = json.loads(Path(bundle["readinessGatePath"]).read_text(encoding="utf-8"))
    acquisition_manifests = [
        json.loads(Path(record["manifestPath"]).read_text(encoding="utf-8"))
        for record in bundle["acquisitions"]
    ]

    for manifest in acquisition_manifests:
        assert validate_acquisition_manifest(manifest)["status"] == "pass"
    assert validate_corpus_manifest(corpus_manifest, acquisition_index={
        manifest["acquisitionId"]: {"manifest": manifest, **validate_acquisition_manifest(manifest)}
        for manifest in acquisition_manifests
    })["status"] == "pass"
    assert readiness_gate["status"] == "available"
    assert readiness_gate["decisionGradeReady"] is True
    assert {case["status"] for case in readiness_gate["caseStatuses"]} == {"available"}

    recomputed = build_corpus_readiness_gate(
        acquisition_manifests=acquisition_manifests,
        corpus_manifest=corpus_manifest,
        required_corpora=bundle["requiredCorpora"],
    )
    assert recomputed["status"] == "available"


def test_acquisition_reextracts_existing_cache_before_repinning_cases(tmp_path: Path) -> None:
    downloads = tmp_path / "source-archives"
    juliet_zip = _juliet_fixture_zip(downloads / "juliet.zip")
    source = replace(
        JULIET_SOURCE,
        source_url=juliet_zip.as_uri(),
        archive_sha256=_sha256_file(juliet_zip),
        archive_name="juliet.zip",
    )
    output_root = tmp_path / "cache"

    first_bundle = acquire_known_corpora(
        sources=[source],
        output_root=output_root,
        downloaded_at="2026-05-13T00:00:00Z",
    )
    first_corpus = json.loads(Path(first_bundle["corpusManifestPath"]).read_text(encoding="utf-8"))
    selected_case = first_corpus["cases"][0]
    selected_file = Path(first_bundle["acquisitions"][0]["extractionRoot"]) / selected_case["sourcePath"]
    original_text = selected_file.read_text(encoding="utf-8")
    selected_file.write_text(original_text + "\n/* tampered */\n", encoding="utf-8")

    second_bundle = acquire_known_corpora(
        sources=[source],
        output_root=output_root,
        downloaded_at="2026-05-13T00:00:00Z",
    )
    second_corpus = json.loads(Path(second_bundle["corpusManifestPath"]).read_text(encoding="utf-8"))

    assert second_bundle["status"] == "available"
    assert selected_file.read_text(encoding="utf-8") == original_text
    assert second_corpus["cases"][0]["checksum"] == selected_case["checksum"]


def test_acquisition_reuses_existing_trusted_cache_without_reextracting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    downloads = tmp_path / "source-archives"
    juliet_zip = _juliet_fixture_zip(downloads / "juliet.zip")
    source = replace(
        JULIET_SOURCE,
        source_url=juliet_zip.as_uri(),
        archive_sha256=_sha256_file(juliet_zip),
        archive_name="juliet.zip",
    )
    output_root = tmp_path / "cache"

    first_bundle = acquire_known_corpora(
        sources=[source],
        output_root=output_root,
        downloaded_at="2026-05-13T00:00:00Z",
    )
    first_manifest = json.loads(Path(first_bundle["acquisitions"][0]["manifestPath"]).read_text(encoding="utf-8"))

    def fail_if_reextracting(path: Path, *, allowed_root: Path) -> None:
        raise AssertionError(f"trusted cache should not be re-extracted: {path} under {allowed_root}")

    monkeypatch.setattr(corpus_acquisition, "_safe_rmtree", fail_if_reextracting)
    second_bundle = acquire_known_corpora(
        sources=[source],
        output_root=output_root,
        downloaded_at="2026-05-14T00:00:00Z",
    )
    second_manifest = json.loads(Path(second_bundle["acquisitions"][0]["manifestPath"]).read_text(encoding="utf-8"))

    assert second_bundle["status"] == "available"
    assert second_manifest == first_manifest


@pytest.mark.parametrize(
    "field_name,source_update",
    [
        ("sourcePageUrl", {"source_page_url": "https://example.test/updated-page"}),
        ("licenseOrRedistributionNote", {"license_or_redistribution_note": "Updated local research redistribution note."}),
    ],
)
def test_acquisition_metadata_change_repins_manifest_without_reextracting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
    source_update: dict[str, str],
) -> None:
    downloads = tmp_path / "source-archives"
    juliet_zip = _juliet_fixture_zip(downloads / "juliet.zip")
    source = replace(
        JULIET_SOURCE,
        source_url=juliet_zip.as_uri(),
        archive_sha256=_sha256_file(juliet_zip),
        archive_name="juliet.zip",
    )
    output_root = tmp_path / "cache"

    first_bundle = acquire_known_corpora(
        sources=[source],
        output_root=output_root,
        downloaded_at="2026-05-13T00:00:00Z",
    )
    first_manifest_path = Path(first_bundle["acquisitions"][0]["manifestPath"])
    first_manifest = json.loads(first_manifest_path.read_text(encoding="utf-8"))

    def fail_if_reextracting(path: Path, *, allowed_root: Path) -> None:
        raise AssertionError(f"metadata-only change should not re-extract: {path} under {allowed_root}")

    monkeypatch.setattr(corpus_acquisition, "_safe_rmtree", fail_if_reextracting)
    updated_source = replace(source, **source_update)
    second_bundle = acquire_known_corpora(
        sources=[updated_source],
        output_root=output_root,
        downloaded_at="2026-05-14T00:00:00Z",
    )
    second_manifest = json.loads(Path(second_bundle["acquisitions"][0]["manifestPath"]).read_text(encoding="utf-8"))

    assert second_bundle["status"] == "available"
    assert second_manifest[field_name] == source_update[next(iter(source_update))]
    assert second_manifest["downloadedAt"] == first_manifest["downloadedAt"]
    assert validate_acquisition_manifest(second_manifest)["status"] == "pass"
    assert second_manifest != first_manifest


def test_corpus_manifest_created_at_reuses_pinned_acquisition_manifest_date(tmp_path: Path) -> None:
    downloads = tmp_path / "source-archives"
    juliet_zip = _juliet_fixture_zip(downloads / "juliet.zip")
    source = replace(
        JULIET_SOURCE,
        source_url=juliet_zip.as_uri(),
        archive_sha256=_sha256_file(juliet_zip),
        archive_name="juliet.zip",
    )
    output_root = tmp_path / "cache"

    first_bundle = acquire_known_corpora(
        sources=[source],
        output_root=output_root,
        downloaded_at="2026-05-13T00:00:00Z",
    )
    second_bundle = acquire_known_corpora(
        sources=[source],
        output_root=output_root,
        downloaded_at="2026-05-14T00:00:00Z",
    )

    first_corpus = json.loads(Path(first_bundle["corpusManifestPath"]).read_text(encoding="utf-8"))
    second_corpus = json.loads(Path(second_bundle["corpusManifestPath"]).read_text(encoding="utf-8"))
    assert first_corpus["createdAt"] == "2026-05-13"
    assert second_corpus["createdAt"] == "2026-05-13"


def test_single_sard_candidate_is_not_duplicated_across_validation_and_test(tmp_path: Path) -> None:
    sard_zip = _single_candidate_sard_fixture_zip(tmp_path / "sard-one.zip", secure=False)
    source = replace(
        SARD_VULNERABLE_SOURCE,
        source_url=sard_zip.as_uri(),
        archive_sha256=_sha256_file(sard_zip),
        archive_name="sard-one.zip",
    )

    bundle = acquire_known_corpora(
        sources=[source],
        output_root=tmp_path / "cache",
        downloaded_at="2026-05-13T00:00:00Z",
    )
    corpus_manifest = json.loads(Path(bundle["corpusManifestPath"]).read_text(encoding="utf-8"))
    readiness_gate = json.loads(Path(bundle["readinessGatePath"]).read_text(encoding="utf-8"))

    assert bundle["status"] == "blocked"
    assert bundle["decisionGradeReady"] is False
    assert bundle["splitCounts"] == {"validation": 1}
    assert {case["split"] for case in corpus_manifest["cases"]} == {"validation"}
    assert readiness_gate["status"] == "blocked"
    assert "CORPUS_REQUIRED_SPLITS_MISSING" in readiness_gate["reasonCodes"]


def test_acquisition_rejects_zip_path_traversal(tmp_path: Path) -> None:
    malicious_zip = _write_zip(tmp_path / "evil.zip", {"../escape.c": "int main(void) { return 0; }\n"})
    source = replace(
        JULIET_SOURCE,
        source_url=malicious_zip.as_uri(),
        archive_sha256=_sha256_file(malicious_zip),
        archive_name="evil.zip",
    )

    with pytest.raises(ValueError, match="unsafe zip member path"):
        acquire_known_corpora(sources=[source], output_root=tmp_path / "cache", downloaded_at="2026-05-13T00:00:00Z")


def test_acquisition_rejects_zip_path_traversal_without_raw_member_echo(tmp_path: Path) -> None:
    secret_member = "../SECRET_ZIP_MEMBER_SHOULD_NOT_LEAK.c"
    malicious_zip = _write_zip(tmp_path / "evil-secret.zip", {secret_member: "int main(void) { return 0; }\n"})
    source = replace(
        JULIET_SOURCE,
        source_url=malicious_zip.as_uri(),
        archive_sha256=_sha256_file(malicious_zip),
        archive_name="evil-secret.zip",
    )

    with pytest.raises(ValueError) as error:
        acquire_known_corpora(sources=[source], output_root=tmp_path / "cache", downloaded_at="2026-05-13T00:00:00Z")

    message = str(error.value)
    assert "unsafe zip member path" in message
    assert secret_member not in message
    assert "SECRET_ZIP_MEMBER_SHOULD_NOT_LEAK" not in message


def test_juliet_file_selection_failure_does_not_echo_root_path(tmp_path: Path) -> None:
    secret_root = tmp_path / "SECRET_JULIET_ROOT_SHOULD_NOT_LEAK"
    (secret_root / "C" / "testcases").mkdir(parents=True)

    with pytest.raises(FileNotFoundError) as error:
        _select_juliet_file(secret_root, "121", preferred_suffix="_01.c")

    message = str(error.value)
    assert "No Juliet file found" in message
    assert str(secret_root) not in message
    assert "SECRET_JULIET_ROOT_SHOULD_NOT_LEAK" not in message


def test_safe_rmtree_rejects_outside_path_without_raw_path_echo(tmp_path: Path) -> None:
    allowed_root = tmp_path / "cache"
    secret_path = tmp_path / "SECRET_RMTREE_PATH_SHOULD_NOT_LEAK"

    with pytest.raises(ValueError) as error:
        _safe_rmtree(secret_path, allowed_root=allowed_root)

    message = str(error.value)
    assert "refusing to delete extraction path outside corpus cache" in message
    assert str(secret_path) not in message
    assert "SECRET_RMTREE_PATH_SHOULD_NOT_LEAK" not in message


def test_require_checksum_rejects_mismatch_without_raw_path_or_checksum_echo(tmp_path: Path) -> None:
    secret_path = tmp_path / "SECRET_CHECKSUM_PATH_SHOULD_NOT_LEAK.bin"
    secret_path.write_text("fixture", encoding="utf-8")
    secret_expected = "sha256:SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK"
    actual_checksum = corpus_acquisition._sha256_file(secret_path)

    with pytest.raises(ValueError) as error:
        _require_checksum(secret_path, secret_expected)

    message = str(error.value)
    assert "checksum mismatch" in message
    assert str(secret_path) not in message
    assert "SECRET_CHECKSUM_PATH_SHOULD_NOT_LEAK" not in message
    assert secret_expected not in message
    assert "SECRET_EXPECTED_CHECKSUM_SHOULD_NOT_LEAK" not in message
    assert actual_checksum not in message


def test_sard_artifact_line_uses_artifact_table_when_result_uri_is_omitted() -> None:
    sarif = {
        "runs": [
            {
                "artifacts": [{"location": {"uri": "src/from-artifact-table.c"}}],
                "results": [{"locations": [{"physicalLocation": {"region": {"startLine": 7}}}]}],
            }
        ]
    }

    assert _sard_artifact_and_line(sarif) == ("src/from-artifact-table.c", 7)


def test_sard_artifact_line_rejects_missing_artifact_evidence() -> None:
    with pytest.raises(ValueError, match="SARD SARIF did not contain an artifact URI"):
        _sard_artifact_and_line({"runs": [{"results": []}]})
