from __future__ import annotations

import pytest

from benchmark.tool_portfolio_acquisition_manifest import (
    ACQUISITION_SCHEMA_VERSION,
    build_acquisition_index,
    manifest_checksum,
    validate_acquisition_manifest,
)


def _acquisition_manifest() -> dict:
    return {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "acquisitionId": "juliet-c-cpp-1.3",
        "sourceName": "Juliet C/C++",
        "sourceUrl": "https://samate.nist.gov/SARD/test-suites/112",
        "sourceVersion": "1.3",
        "licenseOrRedistributionNote": "NIST SAMATE/SARD public benchmark corpus; keep local copy pinned by checksum.",
        "downloadedAt": "2026-05-12",
        "archiveChecksum": "sha256:" + "a" * 64,
        "extractionRootChecksum": "sha256:" + "b" * 64,
        "localPath": "/tmp/aegis-corpora/juliet-c-cpp-1.3",
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }


def test_acquisition_manifest_validates_and_has_stable_checksum() -> None:
    manifest = _acquisition_manifest()

    report = validate_acquisition_manifest(manifest)

    assert report["status"] == "pass"
    assert report["schemaVersion"] == ACQUISITION_SCHEMA_VERSION
    assert report["acquisitionId"] == "juliet-c-cpp-1.3"
    assert report["manifestChecksum"].startswith("sha256:")
    assert report["manifestChecksum"] == manifest_checksum(manifest)


def test_acquisition_manifest_accepts_known_optional_provenance_fields() -> None:
    manifest = _acquisition_manifest()
    manifest["sourcePageUrl"] = "https://samate.nist.gov/SARD/test-suites/112"
    manifest["expectedArchiveChecksum"] = manifest["archiveChecksum"]

    report = validate_acquisition_manifest(manifest)

    assert report["status"] == "pass"
    assert report["manifestChecksum"] == manifest_checksum(manifest)
    assert report["manifestChecksum"] != manifest_checksum(_acquisition_manifest())


class _SecretExtra:
    def __repr__(self) -> str:
        return "SECRET_ACQUISITION_EXTRA_SHOULD_NOT_LEAK"


@pytest.mark.parametrize("downloaded_at", ["2026-05-12", "2026-05-12T00:00:00Z"])
def test_acquisition_manifest_accepts_supported_downloaded_at_formats(downloaded_at: str) -> None:
    manifest = _acquisition_manifest()
    manifest["downloadedAt"] = downloaded_at

    assert validate_acquisition_manifest(manifest)["status"] == "pass"


@pytest.mark.parametrize("downloaded_at", ["not-a-date", "2026-02-31", "2026-5-3", "2026-05-12T00:00:00+00:00"])
def test_acquisition_manifest_rejects_invalid_downloaded_at_without_raw_value_echo(downloaded_at: str) -> None:
    manifest = _acquisition_manifest()
    manifest["downloadedAt"] = downloaded_at

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "downloadedAt" in message
    assert downloaded_at not in message


def test_acquisition_manifest_rejects_invalid_calendar_date_without_exception_chain() -> None:
    downloaded_at = "2026-02-31"
    manifest = _acquisition_manifest()
    manifest["downloadedAt"] = downloaded_at

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "downloadedAt" in message
    assert downloaded_at not in message
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "source_url",
    [
        "https://samate.nist.gov/SARD/test-suites/112",
        "http://example.test/corpus.zip",
        "file:///tmp/aegis-corpora/juliet.zip",
        "local://services/sast-runner/tests/fixtures/tool_portfolio_experiment_v1",
    ],
)
def test_acquisition_manifest_accepts_supported_source_url_schemes(source_url: str) -> None:
    manifest = _acquisition_manifest()
    manifest["sourceUrl"] = source_url

    assert validate_acquisition_manifest(manifest)["status"] == "pass"


@pytest.mark.parametrize("source_url", ["https:///missing-host", "file://", "ftp://example.test/corpus.zip", "not a url"])
def test_acquisition_manifest_rejects_invalid_source_url_without_raw_value_echo(source_url: str) -> None:
    manifest = _acquisition_manifest()
    manifest["sourceUrl"] = source_url

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "sourceUrl" in message
    assert source_url not in message


@pytest.mark.parametrize(
    "source_url",
    [
        "https://?q",
        "https://#frag",
        "https://:443",
        "https://user@",
        "https://user@:443/path",
        "https:// /x",
    ],
)
def test_acquisition_manifest_rejects_hostless_http_source_url_without_raw_value_echo(source_url: str) -> None:
    manifest = _acquisition_manifest()
    manifest["sourceUrl"] = source_url

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "sourceUrl" in message
    assert source_url not in message


@pytest.mark.parametrize("source_url", ["https://example.test?q", "https://example.test#frag"])
def test_acquisition_manifest_rejects_query_or_fragment_only_http_paths_without_raw_value_echo(source_url: str) -> None:
    manifest = _acquisition_manifest()
    manifest["sourceUrl"] = source_url

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "sourceUrl" in message
    assert source_url not in message


@pytest.mark.parametrize("source_page_url", ["https://samate.nist.gov/SARD/test-suites/112", "http://example.test/corpus"])
def test_acquisition_manifest_accepts_http_source_page_url(source_page_url: str) -> None:
    manifest = _acquisition_manifest()
    manifest["sourcePageUrl"] = source_page_url

    assert validate_acquisition_manifest(manifest)["status"] == "pass"


@pytest.mark.parametrize(
    "source_page_url",
    ["local://fixture", "file:///tmp/page", "https:///missing-host", "https://?q", "https://#frag", "https://:443", "not a url"],
)
def test_acquisition_manifest_rejects_invalid_source_page_url_without_raw_value_echo(source_page_url: str) -> None:
    manifest = _acquisition_manifest()
    manifest["sourcePageUrl"] = source_page_url

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "sourcePageUrl" in message
    assert source_page_url not in message


def test_acquisition_manifest_rejects_unknown_extra_field_before_checksum_without_raw_value_leak() -> None:
    manifest = _acquisition_manifest()
    manifest["unexpected"] = _SecretExtra()

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "unknown acquisition manifest field: unexpected" in message
    assert "SECRET_ACQUISITION_EXTRA_SHOULD_NOT_LEAK" not in message


def test_acquisition_manifest_rejects_unknown_string_field() -> None:
    manifest = _acquisition_manifest()
    manifest["unexpected"] = "legacy"

    with pytest.raises(ValueError, match="unknown acquisition manifest field: unexpected"):
        validate_acquisition_manifest(manifest)


def test_acquisition_manifest_sanitizes_unsafe_unknown_field_key_without_raw_key_leak() -> None:
    manifest = _acquisition_manifest()
    secret_field = "SECRET_FIELD_SHOULD_NOT_LEAK\n"
    manifest[secret_field] = "legacy"

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "unknown acquisition manifest field: <unsafe>" in message
    assert "SECRET_FIELD_SHOULD_NOT_LEAK" not in message


def test_manifest_checksum_sanitizes_unsafe_unknown_field_key_without_raw_key_leak() -> None:
    manifest = _acquisition_manifest()
    secret_field = "SECRET_FIELD_SHOULD_NOT_LEAK\n"
    manifest[secret_field] = "legacy"

    with pytest.raises(ValueError) as error:
        manifest_checksum(manifest)

    message = str(error.value)
    assert "unknown acquisition manifest field: <unsafe>" in message
    assert "SECRET_FIELD_SHOULD_NOT_LEAK" not in message


def test_manifest_checksum_rejects_unknown_extra_field_before_json_serialization() -> None:
    manifest = _acquisition_manifest()
    manifest["unexpected"] = _SecretExtra()

    with pytest.raises(ValueError) as error:
        manifest_checksum(manifest)

    message = str(error.value)
    assert "unknown acquisition manifest field: unexpected" in message
    assert "SECRET_ACQUISITION_EXTRA_SHOULD_NOT_LEAK" not in message


def test_acquisition_manifest_rejects_optional_object_before_checksum_without_raw_value_leak() -> None:
    manifest = _acquisition_manifest()
    manifest["sourcePageUrl"] = _SecretExtra()

    with pytest.raises(ValueError) as error:
        validate_acquisition_manifest(manifest)

    message = str(error.value)
    assert "sourcePageUrl must be a non-empty string" in message
    assert "SECRET_ACQUISITION_EXTRA_SHOULD_NOT_LEAK" not in message


def test_acquisition_index_is_keyed_by_acquisition_id_and_checksum() -> None:
    manifest = _acquisition_manifest()

    index = build_acquisition_index([manifest])

    assert list(index) == ["juliet-c-cpp-1.3"]
    assert index["juliet-c-cpp-1.3"]["manifestChecksum"] == manifest_checksum(manifest)


def test_acquisition_index_rejects_duplicate_acquisition_id_without_raw_value_echo() -> None:
    secret_acquisition_id = "SECRET_DUPLICATE_ACQUISITION_ID_SHOULD_NOT_LEAK"
    first = _acquisition_manifest()
    second = _acquisition_manifest()
    first["acquisitionId"] = secret_acquisition_id
    second["acquisitionId"] = secret_acquisition_id

    with pytest.raises(ValueError) as error:
        build_acquisition_index([first, second])

    message = str(error.value)
    assert "duplicate acquisitionId" in message
    assert secret_acquisition_id not in message


@pytest.mark.parametrize(
    "field,value",
    [
        ("offlineScoringOnly", False),
        ("networkAccessRequiredForScoring", True),
        ("archiveChecksum", "not-a-sha"),
        ("licenseOrRedistributionNote", ""),
    ],
)
def test_acquisition_manifest_rejects_non_deterministic_or_unpinned_sources(field: str, value: object) -> None:
    manifest = _acquisition_manifest()
    manifest[field] = value

    with pytest.raises(ValueError, match=field):
        validate_acquisition_manifest(manifest)
