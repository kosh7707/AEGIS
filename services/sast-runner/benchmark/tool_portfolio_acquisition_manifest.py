from __future__ import annotations

import json
import re
from datetime import datetime
from hashlib import sha256
from typing import Any, Iterable, Mapping

ACQUISITION_SCHEMA_VERSION = "s4-tool-portfolio-acquisition-v1"
ACQUISITION_REQUIRED_FIELDS = frozenset({
    "schemaVersion",
    "acquisitionId",
    "sourceName",
    "sourceUrl",
    "sourceVersion",
    "licenseOrRedistributionNote",
    "downloadedAt",
    "archiveChecksum",
    "extractionRootChecksum",
    "localPath",
    "offlineScoringOnly",
    "networkAccessRequiredForScoring",
})
ACQUISITION_OPTIONAL_FIELDS = frozenset({
    "sourcePageUrl",
    "expectedArchiveChecksum",
})
ACQUISITION_ALLOWED_FIELDS = ACQUISITION_REQUIRED_FIELDS | ACQUISITION_OPTIONAL_FIELDS
_REQUIRED_STRING_FIELDS = [
    "acquisitionId",
    "sourceName",
    "sourceUrl",
    "sourceVersion",
    "licenseOrRedistributionNote",
    "downloadedAt",
    "archiveChecksum",
    "extractionRootChecksum",
    "localPath",
]
_OPTIONAL_STRING_FIELDS = [
    "sourcePageUrl",
    "expectedArchiveChecksum",
]
_SHA256_FIELDS = [
    "archiveChecksum",
    "extractionRootChecksum",
    "expectedArchiveChecksum",
]
_SHA256_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")
_UTC_TIMESTAMP_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SAFE_FIELD_LABEL_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{0,63}\Z")


def stable_json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_checksum(manifest: Mapping[str, Any]) -> str:
    return "sha256:" + sha256(stable_json_dumps(_canonical_acquisition_manifest(manifest)).encode("utf-8")).hexdigest()


def validate_acquisition_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    data = _canonical_acquisition_manifest(manifest)
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


def _canonical_acquisition_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("acquisition manifest must be an object")
    data = dict(manifest)
    for field in data:
        if not isinstance(field, str):
            raise ValueError("unknown acquisition manifest field: <non-string>")
        if field not in ACQUISITION_ALLOWED_FIELDS:
            raise ValueError(f"unknown acquisition manifest field: {_safe_field_label(field)}")
    _require_equal(data, "schemaVersion", ACQUISITION_SCHEMA_VERSION)
    for field in _REQUIRED_STRING_FIELDS:
        _require_non_empty_string(data, field)
    for field in _OPTIONAL_STRING_FIELDS:
        if field in data:
            _require_non_empty_string(data, field)
    _require_downloaded_at(data, "downloadedAt")
    _require_url(data, "sourceUrl", allowed_schemes={"file", "http", "https", "local"})
    if "sourcePageUrl" in data:
        _require_url(data, "sourcePageUrl", allowed_schemes={"http", "https"})
    for field in _SHA256_FIELDS:
        if field not in data:
            continue
        value = data[field]
        if not _SHA256_RE.match(value):
            raise ValueError(f"{field} must be sha256:<64 lowercase hex>")
    if data.get("offlineScoringOnly") is not True:
        raise ValueError("offlineScoringOnly must be true")
    if data.get("networkAccessRequiredForScoring") is not False:
        raise ValueError("networkAccessRequiredForScoring must be false")
    canonical = {
        "schemaVersion": data["schemaVersion"],
        "acquisitionId": data["acquisitionId"],
        "sourceName": data["sourceName"],
        "sourceUrl": data["sourceUrl"],
        "sourceVersion": data["sourceVersion"],
        "licenseOrRedistributionNote": data["licenseOrRedistributionNote"],
        "downloadedAt": data["downloadedAt"],
        "archiveChecksum": data["archiveChecksum"],
        "extractionRootChecksum": data["extractionRootChecksum"],
        "localPath": data["localPath"],
        "offlineScoringOnly": data["offlineScoringOnly"],
        "networkAccessRequiredForScoring": data["networkAccessRequiredForScoring"],
    }
    for field in _OPTIONAL_STRING_FIELDS:
        if field in data:
            canonical[field] = data[field]
    return canonical


def build_acquisition_index(manifests: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        report = validate_acquisition_manifest(manifest)
        acquisition_id = report["acquisitionId"]
        if acquisition_id in index:
            raise ValueError("duplicate acquisitionId")
        index[acquisition_id] = {"manifest": _canonical_acquisition_manifest(manifest), **report}
    return index


def _require_equal(data: Mapping[str, Any], field: str, expected: Any) -> None:
    if data.get(field) != expected:
        raise ValueError(f"{field} must be {expected!r}")


def _require_non_empty_string(data: Mapping[str, Any], field: str) -> None:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")


def _require_downloaded_at(data: Mapping[str, Any], field: str) -> None:
    value = data[field]
    if _DATE_RE.match(value):
        _parse_datetime(value, "%Y-%m-%d", field)
        return
    if _UTC_TIMESTAMP_RE.match(value):
        _parse_datetime(value, "%Y-%m-%dT%H:%M:%SZ", field)
        return
    raise ValueError(f"{field} must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ")


def _parse_datetime(value: str, fmt: str, field: str) -> None:
    try:
        datetime.strptime(value, fmt)
    except ValueError:
        raise ValueError(f"{field} must be a real calendar date/time") from None


def _require_url(data: Mapping[str, Any], field: str, *, allowed_schemes: set[str]) -> None:
    value = data[field]
    scheme, separator, rest = value.partition("://")
    if separator != "://" or scheme not in allowed_schemes:
        raise ValueError(f"{field} must use an allowed URL scheme")
    if any(char.isspace() for char in value):
        raise ValueError(f"{field} must be a valid URL")
    authority = _url_authority(rest)
    if scheme in {"http", "https"}:
        _require_http_authority(field, authority, rest)
    if scheme == "file" and not rest:
        raise ValueError(f"{field} must include a file path")
    if scheme == "local" and not rest:
        raise ValueError(f"{field} must include a local reference")


def _safe_field_label(field: str) -> str:
    if _SAFE_FIELD_LABEL_RE.match(field):
        return field
    return "<unsafe>"


def _url_authority(rest: str) -> str:
    first_boundary = len(rest)
    for separator in ["/", "?", "#"]:
        index = rest.find(separator)
        if index != -1:
            first_boundary = min(first_boundary, index)
    return rest[:first_boundary]


def _require_http_authority(field: str, authority: str, rest: str) -> None:
    if not authority or authority.startswith((":")):
        raise ValueError(f"{field} must include a URL host")
    if "@" in authority:
        raise ValueError(f"{field} must not include URL userinfo")
    if rest.startswith(("?", "#")):
        raise ValueError(f"{field} must include a URL host")
    if "?" in rest or "#" in rest:
        raise ValueError(f"{field} must not include query or fragment")
