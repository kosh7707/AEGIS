"""Target context durable ledger for S3 target-aware S5 acquisition.

This module owns the storage-neutral part of TargetContextBundleV1 ingest:
normalization, deterministic hashing, idempotent versioning, and durable JSON
persistence. Routers attach runtime acquisition services (CVE/code/threat) on top.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.ledger.repository import LedgerRepositoryError


class TargetContextStoreError(RuntimeError):
    """Raised when the target context store cannot be read or written."""


class TargetContextService:
    """Target context version service with SQLite-ledger authority.

    The service intentionally stores opaque normalized bundles so the public API can
    evolve additively while the ledger keeps deterministic id/version semantics.
    The JSON file is only a compatibility mirror unless `legacy_json_only=True` is
    explicitly requested by tests or migration tooling.
    """

    def __init__(
        self,
        store_file: str = "data/target-contexts.json",
        *,
        ledger_repository: Any | None = None,
        legacy_json_only: bool = False,
    ) -> None:
        if ledger_repository is None and not legacy_json_only:
            raise TargetContextStoreError(
                "TargetContextService requires a SQLite ledger repository; "
                "JSON-only mode is non-authoritative and must be explicit"
            )
        self._store_file = Path(store_file)
        self._ledger = ledger_repository
        self._legacy_json_only = legacy_json_only
        if self._ledger is not None:
            try:
                self._ledger.initialize()
            except LedgerRepositoryError as exc:
                raise TargetContextStoreError(str(exc)) from exc
        self._data = self._load()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _get(mapping: dict[str, Any] | None, *keys: str) -> Any:
        if not isinstance(mapping, dict):
            return None
        for key in keys:
            if key in mapping and mapping[key] not in (None, ""):
                return mapping[key]
        return None

    @classmethod
    def _normalize(cls, value: Any) -> Any:
        """Return a JSON-stable, null-stripped representation."""
        if isinstance(value, dict):
            return {
                str(k): cls._normalize(v)
                for k, v in sorted(value.items(), key=lambda item: str(item[0]))
                if v is not None
            }
        if isinstance(value, list):
            return [cls._normalize(v) for v in value]
        return value

    @classmethod
    def _hash_json(cls, value: Any) -> str:
        payload = json.dumps(
            cls._normalize(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    @classmethod
    def _identity(cls, bundle: dict[str, Any]) -> tuple[dict[str, str | None], list[str]]:
        target = bundle.get("target") if isinstance(bundle.get("target"), dict) else {}
        provenance = bundle.get("provenance") if isinstance(bundle.get("provenance"), dict) else {}

        project_id = cls._get(bundle, "projectId", "project_id")
        target_id = cls._get(target, "targetId", "target_id")
        if not target_id:
            path_or_name = cls._get(target, "path", "name")
            if project_id and path_or_name:
                target_id = f"{project_id}:{path_or_name}"

        build_snapshot_id = cls._get(provenance, "buildSnapshotId", "build_snapshot_id")
        build_unit_id = (
            cls._get(provenance, "buildUnitId", "build_unit_id")
            or cls._get(target, "buildUnitId", "build_unit_id")
        )
        snapshot_schema_version = cls._get(
            provenance, "snapshotSchemaVersion", "snapshot_schema_version",
        )
        source_build_attempt_id = cls._get(
            provenance, "sourceBuildAttemptId", "source_build_attempt_id",
        )

        missing = []
        if not project_id:
            missing.append("projectId")
        if not target_id:
            missing.append("target.targetId|target.path|target.name")
        if not (build_snapshot_id or build_unit_id):
            missing.append("provenance.buildSnapshotId|provenance.buildUnitId|target.buildUnitId")

        return {
            "projectId": project_id,
            "targetId": target_id,
            "buildSnapshotId": build_snapshot_id,
            "buildUnitId": build_unit_id,
            "snapshotSchemaVersion": snapshot_schema_version,
            "sourceBuildAttemptId": source_build_attempt_id,
        }, missing

    def _load(self) -> dict[str, Any]:
        if not self._store_file.exists():
            return {"targets": {}}
        try:
            with self._store_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise TargetContextStoreError(
                f"Invalid target context store JSON: {self._store_file}"
            ) from exc
        if not isinstance(data, dict):
            return {"targets": {}}
        data.setdefault("targets", {})
        return data

    def _save(self) -> None:
        self._store_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self._store_file.name,
            suffix=".tmp",
            dir=str(self._store_file.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, sort_keys=True, indent=2)
                f.write("\n")
            os.replace(tmp_name, self._store_file)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    @staticmethod
    def _target_knowledge_id(project_id: str, target_id: str) -> str:
        digest = hashlib.sha256(f"{project_id}\0{target_id}".encode("utf-8")).hexdigest()
        return f"tctx-{digest[:16]}"

    @staticmethod
    def _ingest_id(target_knowledge_id: str, input_hash: str) -> str:
        digest = hashlib.sha256(f"{target_knowledge_id}\0{input_hash}".encode("utf-8")).hexdigest()
        return f"tctx-ing-{digest[:16]}"

    def ingest(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Normalize and persist a target context bundle.

        Returns a structured result used by the API layer to build an
        AcquisitionEnvelopeV1. Insufficient identity is represented as data, not
        by an exception, so callers receive `input_insufficient` diagnostics.
        """
        if not isinstance(bundle, dict):
            raise ValueError("Target context bundle must be a JSON object")

        normalized = self._normalize(bundle)
        input_hash = self._hash_json(normalized)
        identity, missing = self._identity(normalized)
        if missing:
            return {
                "ok": False,
                "missingFields": missing,
                "targetContextInputHash": input_hash,
                "targetContextIngestId": f"tctx-ing-{input_hash.split(':', 1)[1][:16]}",
                "normalizedBundle": normalized,
                "identity": identity,
            }

        project_id = str(identity["projectId"])
        target_id = str(identity["targetId"])
        target_knowledge_id = self._target_knowledge_id(project_id, target_id)
        ingest_id = self._ingest_id(target_knowledge_id, input_hash)
        now = self._now()

        if self._ledger is not None:
            return self._ingest_ledger_authoritative(
                normalized=normalized,
                input_hash=input_hash,
                identity=identity,
                target_knowledge_id=target_knowledge_id,
                ingest_id=ingest_id,
            )

        if self._legacy_json_only:
            return self._ingest_json_only(
                normalized=normalized,
                input_hash=input_hash,
                identity=identity,
                target_knowledge_id=target_knowledge_id,
                ingest_id=ingest_id,
            )

        raise TargetContextStoreError("No authoritative S5 ledger is configured")

    def _ingest_ledger_authoritative(
        self,
        *,
        normalized: dict[str, Any],
        input_hash: str,
        identity: dict[str, Any],
        target_knowledge_id: str,
        ingest_id: str,
    ) -> dict[str, Any]:
        try:
            result = self._ledger.upsert_target_context_version(
                target_knowledge_id=target_knowledge_id,
                target_context_ingest_id=ingest_id,
                target_context_input_hash=input_hash,
                identity=identity,
                bundle=normalized,
            )
        except Exception as exc:
            raise TargetContextStoreError(f"S5 ledger write failed: {exc}") from exc

        mirror_error = self._mirror_ledger_result(result)
        diagnostics = []
        compatibility_mirror = {"state": "synced", "authoritative": False}
        if mirror_error:
            compatibility_mirror = {
                "state": "failed",
                "authoritative": False,
                "error": mirror_error,
            }
            diagnostics.append({
                "code": "TARGET_CONTEXT_JSON_MIRROR_FAILED",
                "message": "Compatibility JSON mirror failed after authoritative ledger write",
                "detail": mirror_error,
            })

        return {
            **result,
            "storage": {
                "authoritative": "sqlite-ledger",
                "compatibilityMirror": compatibility_mirror,
            },
            "diagnostics": diagnostics,
        }

    def _mirror_ledger_result(self, result: dict[str, Any]) -> str | None:
        try:
            target_knowledge_id = result["targetKnowledgeId"]
            identity = result.get("identity") or {}
            normalized = result.get("normalizedBundle") or {}
            version_record = deepcopy(result.get("record") or {})
            targets = self._data.setdefault("targets", {})
            now = self._now()
            record = targets.get(target_knowledge_id)
            if record is None:
                record = {
                    "targetKnowledgeId": target_knowledge_id,
                    "projectId": str(identity.get("projectId")),
                    "targetId": str(identity.get("targetId")),
                    "createdAt": version_record.get("createdAt", now),
                    "updatedAt": now,
                    "latestVersion": 0,
                    "versions": [],
                }
                targets[target_knowledge_id] = record

            version_record["bundle"] = normalized
            versions = record.setdefault("versions", [])
            existing_index = next(
                (
                    idx for idx, existing in enumerate(versions)
                    if int(existing.get("targetContextVersion", -1)) == int(result["targetContextVersion"])
                ),
                None,
            )
            if existing_index is None:
                versions.append(version_record)
            else:
                versions[existing_index] = version_record
            record["latestVersion"] = max(int(record.get("latestVersion", 0)), int(result["targetContextVersion"]))
            record["updatedAt"] = now
            self._save()
            return None
        except Exception as exc:  # mirror is explicitly non-authoritative
            return str(exc)

    def _ingest_json_only(
        self,
        *,
        normalized: dict[str, Any],
        input_hash: str,
        identity: dict[str, Any],
        target_knowledge_id: str,
        ingest_id: str,
    ) -> dict[str, Any]:
        project_id = str(identity["projectId"])
        target_id = str(identity["targetId"])
        now = self._now()
        targets = self._data.setdefault("targets", {})
        record = targets.get(target_knowledge_id)
        if record is None:
            record = {
                "targetKnowledgeId": target_knowledge_id,
                "projectId": project_id,
                "targetId": target_id,
                "createdAt": now,
                "updatedAt": now,
                "latestVersion": 0,
                "versions": [],
            }
            targets[target_knowledge_id] = record

        for version in record.get("versions", []):
            if (
                version.get("targetContextInputHash") == input_hash
                and version.get("buildSnapshotId") == identity.get("buildSnapshotId")
            ):
                record["updatedAt"] = now
                version["lastIngestedAt"] = now
                self._save()
                return {
                    "ok": True,
                    "reused": True,
                    "targetKnowledgeId": target_knowledge_id,
                    "targetContextVersion": version["targetContextVersion"],
                    "targetContextIngestId": ingest_id,
                    "targetContextInputHash": input_hash,
                    "identity": identity,
                    "record": deepcopy(version),
                    "normalizedBundle": normalized,
                    "storage": {
                        "authoritative": "legacy-json",
                        "compatibilityMirror": {"state": "authoritative_legacy_mode", "authoritative": True},
                    },
                    "diagnostics": [{
                        "code": "TARGET_CONTEXT_LEGACY_JSON_ONLY",
                        "message": "Target context stored in explicit non-default legacy JSON-only mode",
                    }],
                }

        next_version = int(record.get("latestVersion", 0)) + 1
        previous_version = record.get("latestVersion") or None
        version_record = {
            "targetContextVersion": next_version,
            "targetContextIngestId": ingest_id,
            "targetContextInputHash": input_hash,
            "bundle": normalized,
            "projectId": project_id,
            "targetId": target_id,
            "buildSnapshotId": identity.get("buildSnapshotId"),
            "buildUnitId": identity.get("buildUnitId"),
            "snapshotSchemaVersion": identity.get("snapshotSchemaVersion"),
            "sourceBuildAttemptId": identity.get("sourceBuildAttemptId"),
            "createdAt": now,
            "updatedAt": now,
            "lastIngestedAt": now,
        }
        if previous_version:
            version_record["supersedesTargetContextVersion"] = previous_version

        record.setdefault("versions", []).append(version_record)
        record["latestVersion"] = next_version
        record["updatedAt"] = now
        self._save()

        return {
            "ok": True,
            "reused": False,
            "targetKnowledgeId": target_knowledge_id,
            "targetContextVersion": next_version,
            "targetContextIngestId": ingest_id,
            "targetContextInputHash": input_hash,
            "identity": identity,
            "record": deepcopy(version_record),
            "normalizedBundle": normalized,
            "storage": {
                "authoritative": "legacy-json",
                "compatibilityMirror": {"state": "authoritative_legacy_mode", "authoritative": True},
            },
            "diagnostics": [{
                "code": "TARGET_CONTEXT_LEGACY_JSON_ONLY",
                "message": "Target context stored in explicit non-default legacy JSON-only mode",
            }],
        }

    def get(self, target_knowledge_id: str, version: int | None = None) -> dict[str, Any] | None:
        if self._ledger is not None:
            return self._ledger.get_target_context(target_knowledge_id, version)

        record = self._data.get("targets", {}).get(target_knowledge_id)
        if record is None:
            return None
        versions = record.get("versions", [])
        if not versions:
            return None
        if version is None:
            version = int(record.get("latestVersion", 0))
        for version_record in versions:
            if int(version_record.get("targetContextVersion", -1)) == version:
                return {
                    "targetKnowledgeId": target_knowledge_id,
                    "targetContextVersion": version,
                    "record": deepcopy(version_record),
                    "bundle": deepcopy(version_record.get("bundle", {})),
                }
        return None
