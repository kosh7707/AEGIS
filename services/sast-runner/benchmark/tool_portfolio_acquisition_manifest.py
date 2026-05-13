from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Iterable, Mapping

ACQUISITION_SCHEMA_VERSION = "s4-tool-portfolio-acquisition-v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def stable_json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_checksum(manifest: Mapping[str, Any]) -> str:
    return "sha256:" + sha256(stable_json_dumps(dict(manifest)).encode("utf-8")).hexdigest()


def validate_acquisition_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("acquisition manifest must be an object")
    data = dict(manifest)
    _require_equal(data, "schemaVersion", ACQUISITION_SCHEMA_VERSION)
    for field in [
        "acquisitionId",
        "sourceName",
        "sourceUrl",
        "sourceVersion",
        "licenseOrRedistributionNote",
        "downloadedAt",
        "archiveChecksum",
        "extractionRootChecksum",
        "localPath",
    ]:
        _require_non_empty_string(data, field)
    for field in ["archiveChecksum", "extractionRootChecksum"]:
        value = data[field]
        if not _SHA256_RE.match(value):
            raise ValueError(f"{field} must be sha256:<64 lowercase hex>")
    if data.get("offlineScoringOnly") is not True:
        raise ValueError("offlineScoringOnly must be true")
    if data.get("networkAccessRequiredForScoring") is not False:
        raise ValueError("networkAccessRequiredForScoring must be false")
    return {
        "schemaVersion": ACQUISITION_SCHEMA_VERSION,
        "status": "pass",
        "acquisitionId": data["acquisitionId"],
        "sourceName": data["sourceName"],
        "sourceVersion": data["sourceVersion"],
        "manifestChecksum": manifest_checksum(data),
        "offlineScoringOnly": True,
        "networkAccessRequiredForScoring": False,
    }


def build_acquisition_index(manifests: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        report = validate_acquisition_manifest(manifest)
        acquisition_id = report["acquisitionId"]
        if acquisition_id in index:
            raise ValueError(f"duplicate acquisitionId: {acquisition_id}")
        index[acquisition_id] = {"manifest": dict(manifest), **report}
    return index


def _require_equal(data: Mapping[str, Any], field: str, expected: Any) -> None:
    if data.get(field) != expected:
        raise ValueError(f"{field} must be {expected!r}")


def _require_non_empty_string(data: Mapping[str, Any], field: str) -> None:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
