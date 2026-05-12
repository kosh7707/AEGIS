"""SQLite-backed S5 acquisition ledger repository.

G004 establishes the repository and schema.  Later goals populate the broader
knowledge-corpus tables and rebuild Neo4j/Qdrant projections from this ledger.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

SCHEMA_VERSION = 1
MIGRATION_PATH = Path(__file__).resolve().parent / "migrations" / "0001_init.sql"


class LedgerRepositoryError(RuntimeError):
    """Raised when the S5 ledger cannot be initialized or written."""


class LedgerRepository(Protocol):
    def initialize(self) -> None: ...
    def list_tables(self) -> list[str]: ...
    def get_meta(self) -> dict[str, Any]: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True)


def _json_list(value: Any) -> str:
    return json.dumps(value if value is not None else [], ensure_ascii=False, sort_keys=True)


def _loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _digest(prefix: str, *parts: Any) -> str:
    payload = "\0".join(str(part) for part in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:16]}"


class SQLiteLedgerRepository:
    """Small SQLite implementation for the S5 durable acquisition ledger."""

    def __init__(self, ledger_url: str = "sqlite:///data/s5-ledger.sqlite") -> None:
        self.ledger_url = ledger_url
        self.path = self._path_from_url(ledger_url)

    @staticmethod
    def _path_from_url(ledger_url: str) -> str:
        if ledger_url == "sqlite:///:memory:":
            return ":memory:"
        prefix = "sqlite:///"
        if not ledger_url.startswith(prefix):
            raise LedgerRepositoryError("Only sqlite:/// ledger URLs are supported in G004")
        return ledger_url[len(prefix):]

    def _connect(self) -> sqlite3.Connection:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def initialize(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(MIGRATION_PATH.read_text(encoding="utf-8"))
                now = _now()
                conn.execute(
                    """
                    INSERT INTO ledger_meta (id, schema_version, initialized_at, updated_at)
                    VALUES (1, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      schema_version=excluded.schema_version,
                      updated_at=excluded.updated_at
                    """,
                    (SCHEMA_VERSION, now, now),
                )
        except sqlite3.Error as exc:
            raise LedgerRepositoryError(f"Failed to initialize S5 ledger: {exc}") from exc

    def list_tables(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            return [row["name"] for row in rows]

    def get_meta(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM ledger_meta WHERE id=1").fetchone()
            user_version = conn.execute("PRAGMA user_version").fetchone()[0]
            if row is None:
                raise LedgerRepositoryError("S5 ledger is not initialized")
            return {
                "schemaVersion": int(row["schema_version"]),
                "userVersion": int(user_version),
                "initializedAt": row["initialized_at"],
                "updatedAt": row["updated_at"],
            }

    def upsert_target_context_version(
        self,
        *,
        target_knowledge_id: str,
        target_context_ingest_id: str,
        target_context_input_hash: str,
        identity: dict[str, Any],
        bundle: dict[str, Any],
    ) -> dict[str, Any]:
        project_id = str(identity["projectId"])
        target_id = str(identity["targetId"])
        build_snapshot_id = identity.get("buildSnapshotId")
        build_snapshot_key = str(build_snapshot_id or "")
        now = _now()
        try:
            with self._connect() as conn:
                conn.execute("BEGIN")
                existing_target = conn.execute(
                    "SELECT latest_version, created_at FROM target_context WHERE target_knowledge_id=?",
                    (target_knowledge_id,),
                ).fetchone()
                if existing_target is None:
                    conn.execute(
                        """
                        INSERT INTO target_context (
                          target_knowledge_id, project_id, target_id, created_at, updated_at, latest_version
                        ) VALUES (?, ?, ?, ?, ?, 0)
                        """,
                        (target_knowledge_id, project_id, target_id, now, now),
                    )
                    latest_version = 0
                else:
                    latest_version = int(existing_target["latest_version"])
                    conn.execute(
                        "UPDATE target_context SET updated_at=? WHERE target_knowledge_id=?",
                        (now, target_knowledge_id),
                    )

                existing = conn.execute(
                    """
                    SELECT * FROM target_context_version
                    WHERE target_knowledge_id=? AND target_context_input_hash=? AND build_snapshot_key=?
                    """,
                    (target_knowledge_id, target_context_input_hash, build_snapshot_key),
                ).fetchone()
                if existing is not None:
                    conn.execute(
                        "UPDATE target_context_version SET last_ingested_at=?, updated_at=? WHERE target_context_version_id=?",
                        (now, now, existing["target_context_version_id"]),
                    )
                    conn.execute(
                        "UPDATE target_context SET updated_at=? WHERE target_knowledge_id=?",
                        (now, target_knowledge_id),
                    )
                    row = conn.execute(
                        "SELECT * FROM target_context_version WHERE target_context_version_id=?",
                        (existing["target_context_version_id"],),
                    ).fetchone()
                    conn.commit()
                    return self._target_context_result(row, reused=True)

                next_version = latest_version + 1
                version_id = f"{target_knowledge_id}:v{next_version}"
                previous_version = latest_version or None
                conn.execute(
                    """
                    INSERT INTO target_context_version (
                      target_context_version_id, target_knowledge_id, target_context_version,
                      target_context_ingest_id, target_context_input_hash, build_snapshot_id, build_snapshot_key,
                      build_unit_id, snapshot_schema_version, source_build_attempt_id,
                      bundle_json, identity_json, created_at, updated_at, last_ingested_at,
                      supersedes_target_context_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        version_id,
                        target_knowledge_id,
                        next_version,
                        target_context_ingest_id,
                        target_context_input_hash,
                        build_snapshot_id,
                        build_snapshot_key,
                        identity.get("buildUnitId"),
                        identity.get("snapshotSchemaVersion"),
                        identity.get("sourceBuildAttemptId"),
                        _json(bundle),
                        _json(identity),
                        now,
                        now,
                        now,
                        previous_version,
                    ),
                )
                conn.execute(
                    "UPDATE target_context SET latest_version=?, updated_at=? WHERE target_knowledge_id=?",
                    (next_version, now, target_knowledge_id),
                )
                row = conn.execute(
                    "SELECT * FROM target_context_version WHERE target_context_version_id=?",
                    (version_id,),
                ).fetchone()
                conn.commit()
                return self._target_context_result(row, reused=False)
        except sqlite3.Error as exc:
            raise LedgerRepositoryError(f"Failed to write target context to S5 ledger: {exc}") from exc

    def _target_context_result(self, row: sqlite3.Row, *, reused: bool) -> dict[str, Any]:
        record = self._version_record(row)
        return {
            "ok": True,
            "reused": reused,
            "targetKnowledgeId": row["target_knowledge_id"],
            "targetContextVersion": int(row["target_context_version"]),
            "targetContextIngestId": row["target_context_ingest_id"],
            "targetContextInputHash": row["target_context_input_hash"],
            "identity": _loads(row["identity_json"], {}),
            "record": record,
            "normalizedBundle": _loads(row["bundle_json"], {}),
        }

    def _version_record(self, row: sqlite3.Row) -> dict[str, Any]:
        record = {
            "targetContextVersion": int(row["target_context_version"]),
            "targetContextIngestId": row["target_context_ingest_id"],
            "targetContextInputHash": row["target_context_input_hash"],
            "bundle": _loads(row["bundle_json"], {}),
            "projectId": (_loads(row["identity_json"], {}) or {}).get("projectId"),
            "targetId": (_loads(row["identity_json"], {}) or {}).get("targetId"),
            "buildSnapshotId": row["build_snapshot_id"],
            "buildUnitId": row["build_unit_id"],
            "snapshotSchemaVersion": row["snapshot_schema_version"],
            "sourceBuildAttemptId": row["source_build_attempt_id"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
            "lastIngestedAt": row["last_ingested_at"],
        }
        if row["supersedes_target_context_version"] is not None:
            record["supersedesTargetContextVersion"] = int(row["supersedes_target_context_version"])
        return record

    def get_target_context(self, target_knowledge_id: str, version: int | None = None) -> dict[str, Any] | None:
        with self._connect() as conn:
            if version is None:
                target = conn.execute(
                    "SELECT latest_version FROM target_context WHERE target_knowledge_id=?",
                    (target_knowledge_id,),
                ).fetchone()
                if target is None or int(target["latest_version"]) <= 0:
                    return None
                version = int(target["latest_version"])
            row = conn.execute(
                """
                SELECT * FROM target_context_version
                WHERE target_knowledge_id=? AND target_context_version=?
                """,
                (target_knowledge_id, version),
            ).fetchone()
            if row is None:
                return None
            return {
                "targetKnowledgeId": target_knowledge_id,
                "targetContextVersion": int(row["target_context_version"]),
                "record": self._version_record(row),
                "bundle": _loads(row["bundle_json"], {}),
            }

    def record_acquisition_run(
        self,
        *,
        acquisition_id: str,
        surface: str,
        acquisition_status: str,
        acquisition_quality_gate: str,
        consumer_policy: str,
        target_knowledge_id: str | None = None,
        target_context_version: int | None = None,
        scope: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
        results: dict[str, Any] | None = None,
        completed_at: str | None = None,
    ) -> dict[str, Any]:
        started_at = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO acquisition_run (
                  acquisition_id, target_knowledge_id, target_context_version, surface,
                  acquisition_status, acquisition_quality_gate, consumer_policy,
                  scope_json, provenance_json, results_json, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    acquisition_id,
                    target_knowledge_id,
                    target_context_version,
                    surface,
                    acquisition_status,
                    acquisition_quality_gate,
                    consumer_policy,
                    _json(scope),
                    _json(provenance),
                    _json(results),
                    started_at,
                    completed_at,
                ),
            )
        return {"acquisitionId": acquisition_id, "startedAt": started_at, "completedAt": completed_at}

    def record_acquisition_item(
        self,
        *,
        acquisition_id: str,
        item_key: str,
        item_type: str,
        acquisition_status: str,
        acquisition_quality_gate: str,
        consumer_policy: str,
        scope: dict[str, Any] | None = None,
        diagnostics: list[dict[str, Any]] | None = None,
        results: dict[str, Any] | None = None,
        item_id: str | None = None,
    ) -> dict[str, Any]:
        item_id = item_id or _digest("acq-item", acquisition_id, item_key, item_type)
        created_at = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO acquisition_item (
                  item_id, acquisition_id, item_key, item_type, acquisition_status,
                  acquisition_quality_gate, consumer_policy, scope_json, diagnostics_json,
                  results_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_id,
                    acquisition_id,
                    item_key,
                    item_type,
                    acquisition_status,
                    acquisition_quality_gate,
                    consumer_policy,
                    _json(scope),
                    _json_list(diagnostics),
                    _json(results),
                    created_at,
                ),
            )
        return {"itemId": item_id, "createdAt": created_at}

    def record_provider_observation(
        self,
        *,
        provider: str,
        subject_key: str,
        status: str,
        acquisition_id: str | None = None,
        freshness: dict[str, Any] | None = None,
        cache: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        observation_id: str | None = None,
    ) -> dict[str, Any]:
        observation_id = observation_id or _digest("prov-obs", provider, subject_key, status, acquisition_id or "")
        observed_at = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO provider_observation (
                  observation_id, acquisition_id, provider, subject_key, status,
                  freshness_json, cache_json, payload_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (observation_id, acquisition_id, provider, subject_key, status, _json(freshness), _json(cache), _json(payload), observed_at),
            )
        return {"observationId": observation_id, "observedAt": observed_at}

    def list_acquisition_runs(self, surface: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM acquisition_run"
        params: tuple[Any, ...] = ()
        if surface is not None:
            query += " WHERE surface=?"
            params = (surface,)
        query += " ORDER BY started_at, acquisition_id"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "acquisitionId": row["acquisition_id"],
                "targetKnowledgeId": row["target_knowledge_id"],
                "targetContextVersion": row["target_context_version"],
                "surface": row["surface"],
                "acquisitionStatus": row["acquisition_status"],
                "acquisitionQualityGate": row["acquisition_quality_gate"],
                "consumerPolicy": row["consumer_policy"],
                "scope": _loads(row["scope_json"], {}),
                "provenance": _loads(row["provenance_json"], {}),
                "results": _loads(row["results_json"], {}),
                "startedAt": row["started_at"],
                "completedAt": row["completed_at"],
            }
            for row in rows
        ]

    def list_acquisition_items(self, acquisition_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM acquisition_item"
        params: tuple[Any, ...] = ()
        if acquisition_id is not None:
            query += " WHERE acquisition_id=?"
            params = (acquisition_id,)
        query += " ORDER BY created_at, item_id"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "itemId": row["item_id"],
                "acquisitionId": row["acquisition_id"],
                "itemKey": row["item_key"],
                "itemType": row["item_type"],
                "acquisitionStatus": row["acquisition_status"],
                "acquisitionQualityGate": row["acquisition_quality_gate"],
                "consumerPolicy": row["consumer_policy"],
                "scope": _loads(row["scope_json"], {}),
                "diagnostics": _loads(row["diagnostics_json"], []),
                "results": _loads(row["results_json"], {}),
                "createdAt": row["created_at"],
            }
            for row in rows
        ]

    def list_provider_observations(self, provider: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM provider_observation"
        params: tuple[Any, ...] = ()
        if provider is not None:
            query += " WHERE provider=?"
            params = (provider,)
        query += " ORDER BY observed_at, observation_id"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "observationId": row["observation_id"],
                "acquisitionId": row["acquisition_id"],
                "provider": row["provider"],
                "subjectKey": row["subject_key"],
                "status": row["status"],
                "freshness": _loads(row["freshness_json"], {}),
                "cache": _loads(row["cache_json"], {}),
                "payload": _loads(row["payload_json"], {}),
                "observedAt": row["observed_at"],
            }
            for row in rows
        ]

    def record_projection_state(
        self,
        *,
        projection_name: str,
        scope_key: str,
        state: str,
        source_hash: str | None = None,
        projection_version: str | None = None,
        debt: dict[str, Any] | None = None,
        freshness: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        projection_state_id = _digest("proj-state", projection_name, scope_key)
        updated_at = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO projection_state (
                  projection_state_id, projection_name, scope_key, state, source_hash,
                  projection_version, debt_json, freshness_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(projection_name, scope_key) DO UPDATE SET
                  state=excluded.state,
                  source_hash=excluded.source_hash,
                  projection_version=excluded.projection_version,
                  debt_json=excluded.debt_json,
                  freshness_json=excluded.freshness_json,
                  updated_at=excluded.updated_at
                """,
                (projection_state_id, projection_name, scope_key, state, source_hash, projection_version, _json(debt), _json(freshness), updated_at),
            )
        return {"projectionStateId": projection_state_id, "updatedAt": updated_at}

    def get_projection_state(self, projection_name: str, scope_key: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM projection_state WHERE projection_name=? AND scope_key=?",
                (projection_name, scope_key),
            ).fetchone()
            if row is None:
                return None
            return {
                "projectionStateId": row["projection_state_id"],
                "projectionName": row["projection_name"],
                "scopeKey": row["scope_key"],
                "state": row["state"],
                "sourceHash": row["source_hash"],
                "projectionVersion": row["projection_version"],
                "debt": _loads(row["debt_json"], {}),
                "freshness": _loads(row["freshness_json"], {}),
                "updatedAt": row["updated_at"],
            }

    def record_projection_job(
        self,
        *,
        projection_name: str,
        scope_key: str,
        state: str,
        diagnostics: list[dict[str, Any]] | None = None,
        projection_job_id: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> dict[str, Any]:
        projection_job_id = projection_job_id or _digest("proj-job", projection_name, scope_key, started_at or _now())
        started_at = started_at or _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO projection_job (
                  projection_job_id, projection_name, scope_key, state,
                  diagnostics_json, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (projection_job_id, projection_name, scope_key, state, _json_list(diagnostics), started_at, completed_at),
            )
        return {"projectionJobId": projection_job_id, "startedAt": started_at, "completedAt": completed_at}

    def list_projection_jobs(self, projection_name: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if projection_name:
                rows = conn.execute(
                    "SELECT * FROM projection_job WHERE projection_name=? ORDER BY started_at, projection_job_id",
                    (projection_name,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM projection_job ORDER BY started_at, projection_job_id").fetchall()
        return [
            {
                "projectionJobId": row["projection_job_id"],
                "projectionName": row["projection_name"],
                "scopeKey": row["scope_key"],
                "state": row["state"],
                "diagnostics": _loads(row["diagnostics_json"], []),
                "startedAt": row["started_at"],
                "completedAt": row["completed_at"],
            }
            for row in rows
        ]

    def count_rows(self, table: str) -> int:
        self._ensure_known_table(table)
        with self._connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def fetch_all(self, table: str) -> list[dict[str, Any]]:
        self._ensure_known_table(table)
        with self._connect() as conn:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            return [dict(row) for row in rows]

    def _ensure_known_table(self, table: str) -> None:
        if table not in self.list_tables():
            raise LedgerRepositoryError(f"Unknown S5 ledger table: {table}")

    def upsert_knowledge_source(
        self,
        *,
        source_id: str,
        source_kind: str,
        name: str,
        version: str | None = None,
        source_url: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO knowledge_source (
                  source_id, source_kind, name, version, source_url, payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                  source_kind=excluded.source_kind,
                  name=excluded.name,
                  version=excluded.version,
                  source_url=excluded.source_url,
                  payload_json=excluded.payload_json,
                  updated_at=excluded.updated_at
                """,
                (source_id, source_kind, name, version, source_url, _json(payload), now, now),
            )
        return {"sourceId": source_id, "updatedAt": now}

    def upsert_raw_artifact(
        self,
        *,
        raw_artifact_id: str,
        source_id: str,
        uri: str,
        content_hash: str,
        payload: dict[str, Any] | None,
        retrieved_at: str,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO raw_artifact (
                  raw_artifact_id, source_id, uri, content_hash, payload_json, retrieved_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(raw_artifact_id) DO UPDATE SET
                  source_id=excluded.source_id,
                  uri=excluded.uri,
                  content_hash=excluded.content_hash,
                  payload_json=excluded.payload_json,
                  retrieved_at=excluded.retrieved_at
                """,
                (raw_artifact_id, source_id, uri, content_hash, _json(payload), retrieved_at),
            )
        return {"rawArtifactId": raw_artifact_id}

    def upsert_normalized_record(
        self,
        *,
        normalized_record_id: str,
        source_id: str,
        raw_artifact_id: str,
        record_type: str,
        external_id: str,
        payload: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO normalized_record (
                  normalized_record_id, source_id, raw_artifact_id, record_type, external_id,
                  payload_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(normalized_record_id) DO UPDATE SET
                  source_id=excluded.source_id,
                  raw_artifact_id=excluded.raw_artifact_id,
                  record_type=excluded.record_type,
                  external_id=excluded.external_id,
                  payload_json=excluded.payload_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (normalized_record_id, source_id, raw_artifact_id, record_type, external_id, _json(payload), _json(provenance), now, now),
            )
        return {"normalizedRecordId": normalized_record_id}

    def upsert_package_identity(
        self,
        *,
        package_identity_id: str,
        canonical_name: str,
        ecosystem: str | None = None,
        purl: str | None = None,
        cpe: str | None = None,
        repo_url: str | None = None,
        aliases: list[str] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO package_identity (
                  package_identity_id, canonical_name, ecosystem, purl, cpe, repo_url,
                  aliases_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(package_identity_id) DO UPDATE SET
                  canonical_name=excluded.canonical_name,
                  ecosystem=excluded.ecosystem,
                  purl=excluded.purl,
                  cpe=excluded.cpe,
                  repo_url=excluded.repo_url,
                  aliases_json=excluded.aliases_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (package_identity_id, canonical_name, ecosystem, purl, cpe, repo_url, _json_list(aliases), _json(provenance), now, now),
            )
        return {"packageIdentityId": package_identity_id}

    def upsert_vulnerability_advisory(
        self,
        *,
        advisory_id: str,
        source_id: str | None,
        source_kind: str,
        external_id: str,
        payload: dict[str, Any] | None = None,
        freshness: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vulnerability_advisory (
                  advisory_id, source_id, source_kind, external_id, payload_json,
                  freshness_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(advisory_id) DO UPDATE SET
                  source_id=excluded.source_id,
                  source_kind=excluded.source_kind,
                  external_id=excluded.external_id,
                  payload_json=excluded.payload_json,
                  freshness_json=excluded.freshness_json,
                  updated_at=excluded.updated_at
                """,
                (advisory_id, source_id, source_kind, external_id, _json(payload), _json(freshness), now, now),
            )
        return {"advisoryId": advisory_id}

    def upsert_affected_range(
        self,
        *,
        affected_range_id: str,
        advisory_id: str,
        package_identity_id: str | None = None,
        introduced: str | None = None,
        fixed: str | None = None,
        range_data: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO affected_range (
                  affected_range_id, advisory_id, package_identity_id, introduced, fixed,
                  range_json, provenance_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(affected_range_id) DO UPDATE SET
                  advisory_id=excluded.advisory_id,
                  package_identity_id=excluded.package_identity_id,
                  introduced=excluded.introduced,
                  fixed=excluded.fixed,
                  range_json=excluded.range_json,
                  provenance_json=excluded.provenance_json
                """,
                (affected_range_id, advisory_id, package_identity_id, introduced, fixed, _json(range_data), _json(provenance)),
            )
        return {"affectedRangeId": affected_range_id}

    def upsert_weakness(
        self,
        *,
        weakness_id: str,
        external_id: str,
        taxonomy_family: str | None = None,
        payload: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO weakness (
                  weakness_id, external_id, taxonomy_family, payload_json,
                  provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(weakness_id) DO UPDATE SET
                  external_id=excluded.external_id,
                  taxonomy_family=excluded.taxonomy_family,
                  payload_json=excluded.payload_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (weakness_id, external_id, taxonomy_family, _json(payload), _json(provenance), now, now),
            )
        return {"weaknessId": weakness_id}


    def upsert_attack_pattern(
        self,
        *,
        attack_pattern_id: str,
        external_id: str,
        source_kind: str,
        payload: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO attack_pattern (
                  attack_pattern_id, external_id, source_kind, payload_json,
                  provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(attack_pattern_id) DO UPDATE SET
                  external_id=excluded.external_id,
                  source_kind=excluded.source_kind,
                  payload_json=excluded.payload_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (attack_pattern_id, external_id, source_kind, _json(payload), _json(provenance), now, now),
            )
        return {"attackPatternId": attack_pattern_id}

    def upsert_tool_rule(
        self,
        *,
        tool_rule_id: str,
        tool_name: str,
        rule_id: str,
        payload: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_rule (
                  tool_rule_id, tool_name, rule_id, payload_json,
                  provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tool_rule_id) DO UPDATE SET
                  tool_name=excluded.tool_name,
                  rule_id=excluded.rule_id,
                  payload_json=excluded.payload_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (tool_rule_id, tool_name, rule_id, _json(payload), _json(provenance), now, now),
            )
        return {"toolRuleId": tool_rule_id}

    def upsert_transform_decision(
        self,
        *,
        transform_decision_id: str | None = None,
        input_id: str,
        output_id: str | None = None,
        method: str,
        decision: dict[str, Any] | None = None,
        diagnostics: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        transform_decision_id = transform_decision_id or _digest("transform", input_id, output_id or "", method)
        created_at = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO transform_decision (
                  transform_decision_id, input_id, output_id, method,
                  decision_json, diagnostics_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(transform_decision_id) DO UPDATE SET
                  input_id=excluded.input_id,
                  output_id=excluded.output_id,
                  method=excluded.method,
                  decision_json=excluded.decision_json,
                  diagnostics_json=excluded.diagnostics_json
                """,
                (transform_decision_id, input_id, output_id, method, _json(decision), _json_list(diagnostics), created_at),
            )
        return {"transformDecisionId": transform_decision_id, "createdAt": created_at}

    def upsert_relation_record(
        self,
        *,
        relation_record_id: str,
        subject_id: str,
        predicate: str,
        object_id: str,
        method: str,
        consumer_policy: str,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO relation_record (
                  relation_record_id, subject_id, predicate, object_id, method,
                  consumer_policy, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(relation_record_id) DO UPDATE SET
                  subject_id=excluded.subject_id,
                  predicate=excluded.predicate,
                  object_id=excluded.object_id,
                  method=excluded.method,
                  consumer_policy=excluded.consumer_policy,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (relation_record_id, subject_id, predicate, object_id, method, consumer_policy, _json(provenance), now, now),
            )
        return {"relationRecordId": relation_record_id}
