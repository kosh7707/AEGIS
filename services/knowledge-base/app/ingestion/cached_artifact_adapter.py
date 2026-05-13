"""Local/manual cached artifact verification for S5 corpus ingestion.

This adapter deliberately performs no network I/O. It verifies the local cache
surface described by the source manifest and reports provider-style diagnostics
that future live adapters can mirror when they are explicitly invoked.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

DEFAULT_SOURCE_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "corpus-ingestion-v1" / "source-manifest.json"
REQUIRED_ARTIFACT_FIELDS = {"rawArtifactId", "fixturePath", "contentHash", "retrievedAt", "transformVersion"}


def _manifest_dir(path: Path | str) -> Path:
    return Path(path).resolve().parent


def _hash_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _diag(code: str, message: str, *, source_id: str | None = None, raw_artifact_id: str | None = None, severity: str = "error", **extra: Any) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "sourceId": source_id,
        "rawArtifactId": raw_artifact_id,
        **extra,
    }


def verify_cached_artifacts(manifest: dict[str, Any], manifest_path: Path | str = DEFAULT_SOURCE_MANIFEST_PATH) -> dict[str, Any]:
    """Verify local cached artifacts without dereferencing sourceUrl/artifact URI."""

    base = _manifest_dir(manifest_path)
    diagnostics: list[dict[str, Any]] = []
    artifact_results: list[dict[str, Any]] = []
    sources = manifest.get("sources") if isinstance(manifest.get("sources"), list) else []

    for source in sources:
        if not isinstance(source, dict):
            diagnostics.append(_diag("SOURCE_ENTRY_NOT_OBJECT", "Source manifest entry must be an object."))
            continue
        source_id = str(source.get("sourceId", "<missing>"))
        provider_state = source.get("providerState")
        if not isinstance(provider_state, dict) or not provider_state.get("state"):
            diagnostics.append(
                _diag(
                    "PROVIDER_STATE_MISSING_OR_MALFORMED",
                    "providerState must be an object with a state field.",
                    source_id=source_id,
                    providerState=provider_state,
                )
            )
        if not provider_state or not provider_state.get("retrievedAt"):
            diagnostics.append(
                _diag(
                    "PROVIDER_RETRIEVED_AT_MISSING",
                    "providerState.retrievedAt is required for cached/manual artifacts.",
                    source_id=source_id,
                )
            )
        raw_artifacts = source.get("rawArtifacts")
        if not isinstance(raw_artifacts, list):
            diagnostics.append(_diag("RAW_ARTIFACTS_NOT_LIST", "rawArtifacts must be a list.", source_id=source_id))
            continue
        for artifact in raw_artifacts:
            if not isinstance(artifact, dict):
                diagnostics.append(_diag("RAW_ARTIFACT_NOT_OBJECT", "raw artifact entry must be an object.", source_id=source_id))
                continue
            raw_id = str(artifact.get("rawArtifactId", "<missing>"))
            artifact_diags: list[dict[str, Any]] = []
            missing_fields = sorted(REQUIRED_ARTIFACT_FIELDS - set(artifact))
            if missing_fields:
                artifact_diags.append(
                    _diag(
                        "RAW_ARTIFACT_REQUIRED_FIELDS_MISSING",
                        "raw artifact is missing cache-verification fields.",
                        source_id=source_id,
                        raw_artifact_id=raw_id,
                        missingFields=missing_fields,
                    )
                )
            if not artifact.get("retrievedAt"):
                artifact_diags.append(
                    _diag("RAW_ARTIFACT_RETRIEVED_AT_MISSING", "raw artifact retrievedAt is required.", source_id=source_id, raw_artifact_id=raw_id)
                )
            if not artifact.get("transformVersion"):
                artifact_diags.append(
                    _diag("RAW_ARTIFACT_TRANSFORM_VERSION_MISSING", "raw artifact transformVersion is required.", source_id=source_id, raw_artifact_id=raw_id)
                )
            expected_hash = str(artifact.get("contentHash", ""))
            if not expected_hash:
                artifact_diags.append(
                    _diag("RAW_ARTIFACT_CONTENT_HASH_MISSING", "raw artifact contentHash is required.", source_id=source_id, raw_artifact_id=raw_id)
                )
            elif not expected_hash.startswith("sha256:"):
                artifact_diags.append(
                    _diag(
                        "RAW_ARTIFACT_HASH_PREFIX_INVALID",
                        "raw artifact contentHash must use sha256: prefix.",
                        source_id=source_id,
                        raw_artifact_id=raw_id,
                        contentHash=expected_hash,
                    )
                )
            fixture_path = artifact.get("fixturePath")
            path = base / str(fixture_path) if fixture_path else None
            actual_hash = None
            if not fixture_path:
                artifact_diags.append(
                    _diag("RAW_ARTIFACT_FIXTURE_PATH_MISSING", "raw artifact fixturePath is required for local cache verification.", source_id=source_id, raw_artifact_id=raw_id)
                )
            elif path is None or not path.exists():
                artifact_diags.append(
                    _diag(
                        "CACHED_ARTIFACT_FILE_MISSING",
                        "local cached artifact fixturePath does not exist.",
                        source_id=source_id,
                        raw_artifact_id=raw_id,
                        fixturePath=str(fixture_path),
                    )
                )
            else:
                actual_hash = _hash_file(path)
                if expected_hash and actual_hash != expected_hash:
                    artifact_diags.append(
                        _diag(
                            "CACHED_ARTIFACT_HASH_MISMATCH",
                            "local cached artifact hash does not match manifest contentHash.",
                            source_id=source_id,
                            raw_artifact_id=raw_id,
                            expected=expected_hash,
                            actual=actual_hash,
                        )
                    )
            diagnostics.extend(artifact_diags)
            artifact_results.append(
                {
                    "sourceId": source_id,
                    "sourceKind": source.get("sourceKind"),
                    "rawArtifactId": raw_id,
                    "fixturePath": str(fixture_path) if fixture_path else None,
                    "uri": artifact.get("uri"),
                    "sourceUrl": source.get("sourceUrl"),
                    "networkDereferenceAttempted": False,
                    "uriDereferenceAttempted": False,
                    "sourceUrlDereferenceAttempted": False,
                    "expectedHash": expected_hash or None,
                    "actualHash": actual_hash,
                    "verified": not artifact_diags,
                    "diagnostics": artifact_diags,
                }
            )

    hard_fail = any(diag.get("severity") == "error" for diag in diagnostics)
    return {
        "schemaVersion": "s5-cached-artifact-verification-v1",
        "artifactCount": len(artifact_results),
        "verifiedArtifactCount": sum(1 for item in artifact_results if item.get("verified")),
        "diagnosticCount": len(diagnostics),
        "hardFail": hard_fail,
        "networkPolicy": "local_cache_only_no_network_dereference",
        "networkDereferenceAttempted": False,
        "sourceUrlDereferenceAttempted": False,
        "uriDereferenceAttempted": False,
        "artifacts": artifact_results,
        "providerDiagnostics": diagnostics,
    }
