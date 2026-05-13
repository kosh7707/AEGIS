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


def test_acquisition_index_is_keyed_by_acquisition_id_and_checksum() -> None:
    manifest = _acquisition_manifest()

    index = build_acquisition_index([manifest])

    assert list(index) == ["juliet-c-cpp-1.3"]
    assert index["juliet-c-cpp-1.3"]["manifestChecksum"] == manifest_checksum(manifest)


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
