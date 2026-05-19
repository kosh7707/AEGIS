"""SQLite-backed S5 acquisition ledger repository.

G004 establishes the repository and schema.  Later goals populate the broader
knowledge-corpus tables and rebuild Neo4j/Qdrant projections from this ledger.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from app.config import redact_url_for_log

SCHEMA_VERSION = 4
MIGRATION_PATH = Path(__file__).resolve().parent / "migrations" / "0001_init.sql"
MAX_SOURCE_CONTEXT_GRAPH_NODES = 64
MAX_SOURCE_CONTEXT_GRAPH_EDGES = 128
MAX_SOURCE_CONTEXT_RICH_IR_ARTIFACTS = 32
MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES = 2048
MAX_SOURCE_RICH_IR_PAYLOAD_INLINE_BYTES = 2048
MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES = 2048
MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS = 64


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


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _nested_object_projection(field: str, value: dict[str, Any]) -> dict[str, Any]:
    raw_value = value if value is not None else {}
    redacted_value = _redact_urls_in_nested_value(raw_value)
    raw_encoded = json.dumps(raw_value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    truncated = len(raw_encoded) > MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES
    return {
        field: None if truncated else redacted_value,
        f"{field}ByteLength": len(raw_encoded),
        f"{field}MaxInlineBytes": MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES,
        f"{field}Truncated": truncated,
        f"{field}Redacted": truncated,
    }


def _redact_urls_in_nested_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_url_for_log(value)
    if isinstance(value, list):
        return [_redact_urls_in_nested_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(redact_url_for_log(str(key))): _redact_urls_in_nested_value(item)
            for key, item in value.items()
        }
    return value


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
        self._active_connection: ContextVar[sqlite3.Connection | None] = ContextVar(
            f"s5_ledger_active_connection_{id(self)}",
            default=None,
        )

    @staticmethod
    def _path_from_url(ledger_url: str) -> str:
        if ledger_url == "sqlite:///:memory:":
            return ":memory:"
        prefix = "sqlite:///"
        if not ledger_url.startswith(prefix):
            raise LedgerRepositoryError("Only sqlite:/// ledger URLs are supported in G004")
        return ledger_url[len(prefix):]

    def _new_connection(self) -> sqlite3.Connection:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    class _ConnectionContext:
        def __init__(self, repo: "SQLiteLedgerRepository") -> None:
            self.repo = repo
            self.conn: sqlite3.Connection | None = None
            self.owns_connection = False

        def __enter__(self) -> sqlite3.Connection:
            active = self.repo._active_connection.get()
            if active is not None:
                self.conn = active
                return active
            self.conn = self.repo._new_connection()
            self.owns_connection = True
            return self.conn

        def __exit__(self, exc_type, exc, tb) -> bool:
            if not self.owns_connection or self.conn is None:
                return False
            try:
                if exc_type is None:
                    self.conn.commit()
                else:
                    self.conn.rollback()
            finally:
                self.conn.close()
            return False

    def _connect(self) -> "SQLiteLedgerRepository._ConnectionContext":
        return self._ConnectionContext(self)

    @contextmanager
    def transaction(self):
        """Run repository operations on one SQLite transaction.

        Existing repository helpers open their own connection contexts.  During
        this scope they reuse the active transaction connection, so a late
        Source KG ingest failure rolls back all earlier rows instead of leaving
        partial source/build facts.
        """
        active = self._active_connection.get()
        if active is not None:
            yield active
            return

        conn = self._new_connection()
        token = self._active_connection.set(conn)
        try:
            conn.execute("BEGIN")
            yield conn
        except Exception:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            self._active_connection.reset(token)
            conn.close()

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

    def record_serving_query(
        self,
        *,
        request_packet: dict[str, Any],
        answer_packet: dict[str, Any],
        serving_run_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        canonical_query = answer_packet.get("canonicalQuery") or {}
        canonical_query_id = str(canonical_query.get("canonicalQueryId") or "")
        decision_fragment_key = str(answer_packet.get("decisionFragmentKey") or canonical_query.get("decisionFragmentKey") or "")
        created_at = created_at or _now()
        serving_run_id = serving_run_id or _digest("serving-run", canonical_query_id, decision_fragment_key, created_at)
        ledger_ref = {
            "schemaVersion": "s5-serving-ledger-ref-v1",
            "recorded": True,
            "servingRunId": serving_run_id,
            "createdAt": created_at,
        }
        stored_answer = {**answer_packet, "servingLedger": answer_packet.get("servingLedger") or ledger_ref}
        quality_gate = answer_packet.get("qualityGate") or {}
        score_policy = quality_gate.get("scorePolicy") or {}
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO serving_query_run (
                  serving_run_id, canonical_query_id, decision_fragment_key, answer_schema_version,
                  verdict, status, quality_gate, component_json, source_context_json, request_json,
                  canonical_query_json, answer_json, applied_controls_json, control_effects_json,
                  fallback_trace_json, cache_trace_json, score_vector_json, score_policy_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    serving_run_id,
                    canonical_query_id,
                    decision_fragment_key,
                    str(answer_packet.get("schemaVersion") or ""),
                    str(answer_packet.get("verdict") or ""),
                    str(answer_packet.get("status") or ""),
                    str(quality_gate.get("gate") or ""),
                    _json((answer_packet.get("queryContext") or {}).get("component") or {}),
                    _json((answer_packet.get("queryContext") or {}).get("sourceContext") or {}),
                    _json(request_packet),
                    _json(canonical_query),
                    _json(stored_answer),
                    _json(answer_packet.get("appliedControls") or {}),
                    _json_list(answer_packet.get("controlEffects") or []),
                    _json_list(answer_packet.get("fallbackTrace") or []),
                    _json(answer_packet.get("cacheTrace") or {}),
                    _json(answer_packet.get("scoreVector") or {}),
                    _json(score_policy),
                    created_at,
                ),
            )
        return ledger_ref

    def get_serving_query_run(self, serving_run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM serving_query_run WHERE serving_run_id=?", (serving_run_id,)).fetchone()
        if row is None:
            return None
        return self._serving_query_run_record(row)

    def list_serving_query_runs(
        self,
        *,
        decision_fragment_key: str | None = None,
        canonical_query_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM serving_query_run"
        clauses: list[str] = []
        params: list[Any] = []
        if decision_fragment_key is not None:
            clauses.append("decision_fragment_key=?")
            params.append(decision_fragment_key)
        if canonical_query_id is not None:
            clauses.append("canonical_query_id=?")
            params.append(canonical_query_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at, serving_run_id"
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [self._serving_query_run_record(row) for row in rows]

    def _serving_query_run_record(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "servingRunId": row["serving_run_id"],
            "canonicalQueryId": row["canonical_query_id"],
            "decisionFragmentKey": row["decision_fragment_key"],
            "answerSchemaVersion": row["answer_schema_version"],
            "verdict": row["verdict"],
            "status": row["status"],
            "qualityGate": row["quality_gate"],
            "component": _loads(row["component_json"], {}),
            "sourceContext": _loads(row["source_context_json"], {}),
            "request": _loads(row["request_json"], {}),
            "canonicalQuery": _loads(row["canonical_query_json"], {}),
            "answer": _loads(row["answer_json"], {}),
            "appliedControls": _loads(row["applied_controls_json"], {}),
            "controlEffects": _loads(row["control_effects_json"], []),
            "fallbackTrace": _loads(row["fallback_trace_json"], []),
            "cacheTrace": _loads(row["cache_trace_json"], {}),
            "scoreVector": _loads(row["score_vector_json"], {}),
            "scorePolicy": _loads(row["score_policy_json"], {}),
            "createdAt": row["created_at"],
        }

    def count_rows(self, table: str) -> int:
        self._ensure_known_table(table)
        with self._connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def fetch_all(self, table: str) -> list[dict[str, Any]]:
        self._ensure_known_table(table)
        with self._connect() as conn:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            return [dict(row) for row in rows]

    def revision_summaries(self, tables: list[str] | tuple[str, ...]) -> dict[str, dict[str, Any]]:
        """Return compact table revision stamps without materializing row payloads."""

        known_tables = set(self.list_tables())
        summaries: dict[str, dict[str, Any]] = {}
        with self._connect() as conn:
            for table in tables:
                if table not in known_tables:
                    continue
                columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
                updated_expr = "MAX(updated_at)" if "updated_at" in columns else "NULL"
                created_expr = "MAX(created_at)" if "created_at" in columns else "NULL"
                row = conn.execute(
                    f"""
                    SELECT
                      COUNT(*) AS row_count,
                      COALESCE({updated_expr}, '') AS max_updated_at,
                      COALESCE({created_expr}, '') AS max_created_at,
                      COALESCE(MAX(rowid), 0) AS max_rowid
                    FROM {table}
                    """
                ).fetchone()
                summaries[table] = {
                    "rowCount": int(row["row_count"]),
                    "maxUpdatedAt": row["max_updated_at"],
                    "maxCreatedAt": row["max_created_at"],
                    "maxRowId": int(row["max_rowid"]),
                }
        return summaries

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

    def upsert_source_artifact(
        self,
        *,
        source_artifact_id: str,
        source_id: str | None,
        source_family: str,
        source_name: str,
        artifact_uri: str,
        media_type: str,
        checksum_sha256: str,
        retrieved_at: str,
        source_version: str | None = None,
        schema_version: str | None = None,
        published_at: str | None = None,
        modified_at: str | None = None,
        parser_version: str = "unknown",
        normalizer_version: str = "unknown",
        record_count: int | None = None,
        required_files: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_artifact (
                  source_artifact_id, source_id, source_family, source_name, artifact_uri,
                  media_type, source_version, schema_version, retrieved_at, published_at,
                  modified_at, checksum_sha256, parser_version, normalizer_version,
                  record_count, required_files_json, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_artifact_id) DO UPDATE SET
                  source_id=excluded.source_id,
                  source_family=excluded.source_family,
                  source_name=excluded.source_name,
                  artifact_uri=excluded.artifact_uri,
                  media_type=excluded.media_type,
                  source_version=excluded.source_version,
                  schema_version=excluded.schema_version,
                  retrieved_at=excluded.retrieved_at,
                  published_at=excluded.published_at,
                  modified_at=excluded.modified_at,
                  checksum_sha256=excluded.checksum_sha256,
                  parser_version=excluded.parser_version,
                  normalizer_version=excluded.normalizer_version,
                  record_count=excluded.record_count,
                  required_files_json=excluded.required_files_json,
                  metadata_json=excluded.metadata_json,
                  updated_at=excluded.updated_at
                """,
                (
                    source_artifact_id,
                    source_id,
                    source_family,
                    source_name,
                    artifact_uri,
                    media_type,
                    source_version,
                    schema_version,
                    retrieved_at,
                    published_at,
                    modified_at,
                    checksum_sha256,
                    parser_version,
                    normalizer_version,
                    record_count,
                    _json_list(required_files),
                    _json(metadata),
                    now,
                    now,
                ),
            )
        return {"sourceArtifactId": source_artifact_id, "updatedAt": now}

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

    def upsert_product_identity(
        self,
        *,
        product_identity_id: str,
        vendor: str | None = None,
        product: str | None = None,
        version: str | None = None,
        cpe: str | None = None,
        match_criteria_id: str | None = None,
        qualifiers: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO product_identity (
                  product_identity_id, vendor, product, version, cpe, match_criteria_id,
                  qualifiers_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(product_identity_id) DO UPDATE SET
                  vendor=excluded.vendor,
                  product=excluded.product,
                  version=excluded.version,
                  cpe=excluded.cpe,
                  match_criteria_id=excluded.match_criteria_id,
                  qualifiers_json=excluded.qualifiers_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (product_identity_id, vendor, product, version, cpe, match_criteria_id, _json(qualifiers), _json(provenance), now, now),
            )
        return {"productIdentityId": product_identity_id}

    def upsert_source_component_identity(
        self,
        *,
        source_component_identity_id: str,
        repo_url: str | None = None,
        commit_id: str | None = None,
        source_path: str | None = None,
        fingerprint: str | None = None,
        qualifiers: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_component_identity (
                  source_component_identity_id, repo_url, commit_id, source_path, fingerprint,
                  qualifiers_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_component_identity_id) DO UPDATE SET
                  repo_url=excluded.repo_url,
                  commit_id=excluded.commit_id,
                  source_path=excluded.source_path,
                  fingerprint=excluded.fingerprint,
                  qualifiers_json=excluded.qualifiers_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (source_component_identity_id, repo_url, commit_id, source_path, fingerprint, _json(qualifiers), _json(provenance), now, now),
            )
        return {"sourceComponentIdentityId": source_component_identity_id}

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

    def upsert_affectedness_record(
        self,
        *,
        affectedness_id: str,
        advisory_id: str,
        subject_kind: str,
        subject_id: str,
        affectedness_status: str,
        introduced: str | None = None,
        fixed: str | None = None,
        range_data: dict[str, Any] | None = None,
        qualifiers: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        confidence: float = 1.0,
        decision_state: str = "accepted",
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO affectedness_record (
                  affectedness_id, advisory_id, subject_kind, subject_id, affectedness_status,
                  introduced, fixed, range_json, qualifiers_json, evidence_json,
                  confidence, decision_state, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(affectedness_id) DO UPDATE SET
                  advisory_id=excluded.advisory_id,
                  subject_kind=excluded.subject_kind,
                  subject_id=excluded.subject_id,
                  affectedness_status=excluded.affectedness_status,
                  introduced=excluded.introduced,
                  fixed=excluded.fixed,
                  range_json=excluded.range_json,
                  qualifiers_json=excluded.qualifiers_json,
                  evidence_json=excluded.evidence_json,
                  confidence=excluded.confidence,
                  decision_state=excluded.decision_state,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    affectedness_id,
                    advisory_id,
                    subject_kind,
                    subject_id,
                    affectedness_status,
                    introduced,
                    fixed,
                    _json(range_data),
                    _json(qualifiers),
                    _json(evidence),
                    confidence,
                    decision_state,
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"affectednessId": affectedness_id}

    def upsert_risk_signal(
        self,
        *,
        risk_signal_id: str,
        signal_kind: str,
        source_kind: str,
        advisory_id: str | None = None,
        signal_date: str | None = None,
        signal_value: float | None = None,
        payload: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO risk_signal (
                  risk_signal_id, advisory_id, signal_kind, signal_date, signal_value,
                  source_kind, payload_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(risk_signal_id) DO UPDATE SET
                  advisory_id=excluded.advisory_id,
                  signal_kind=excluded.signal_kind,
                  signal_date=excluded.signal_date,
                  signal_value=excluded.signal_value,
                  source_kind=excluded.source_kind,
                  payload_json=excluded.payload_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (risk_signal_id, advisory_id, signal_kind, signal_date, signal_value, source_kind, _json(payload), _json(provenance), now, now),
            )
        return {"riskSignalId": risk_signal_id}

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

    def upsert_identity_alias(
        self,
        *,
        identity_alias_id: str,
        subject_kind: str,
        subject_namespace: str,
        subject_id: str,
        alias_kind: str,
        alias_namespace: str,
        alias_id: str,
        relation_semantics: str,
        confidence: float = 1.0,
        source_artifact_id: str | None = None,
        normalized_record_id: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO identity_alias (
                  identity_alias_id, subject_kind, subject_namespace, subject_id,
                  alias_kind, alias_namespace, alias_id, relation_semantics, confidence,
                  source_artifact_id, normalized_record_id, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(identity_alias_id) DO UPDATE SET
                  subject_kind=excluded.subject_kind,
                  subject_namespace=excluded.subject_namespace,
                  subject_id=excluded.subject_id,
                  alias_kind=excluded.alias_kind,
                  alias_namespace=excluded.alias_namespace,
                  alias_id=excluded.alias_id,
                  relation_semantics=excluded.relation_semantics,
                  confidence=excluded.confidence,
                  source_artifact_id=excluded.source_artifact_id,
                  normalized_record_id=excluded.normalized_record_id,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    identity_alias_id,
                    subject_kind,
                    subject_namespace,
                    subject_id,
                    alias_kind,
                    alias_namespace,
                    alias_id,
                    relation_semantics,
                    confidence,
                    source_artifact_id,
                    normalized_record_id,
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"identityAliasId": identity_alias_id}

    def upsert_unresolved_reference(
        self,
        *,
        unresolved_reference_id: str,
        owner_record_id: str,
        reference_role: str,
        reference_kind: str,
        target_raw: str,
        status: str,
        reason: str,
        source_artifact_id: str | None = None,
        normalized_record_id: str | None = None,
        relation_record_id: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO unresolved_reference (
                  unresolved_reference_id, source_artifact_id, normalized_record_id,
                  relation_record_id, owner_record_id, reference_role, reference_kind,
                  target_raw, status, reason, evidence_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(unresolved_reference_id) DO UPDATE SET
                  source_artifact_id=excluded.source_artifact_id,
                  normalized_record_id=excluded.normalized_record_id,
                  relation_record_id=excluded.relation_record_id,
                  owner_record_id=excluded.owner_record_id,
                  reference_role=excluded.reference_role,
                  reference_kind=excluded.reference_kind,
                  target_raw=excluded.target_raw,
                  status=excluded.status,
                  reason=excluded.reason,
                  evidence_json=excluded.evidence_json,
                  updated_at=excluded.updated_at
                """,
                (
                    unresolved_reference_id,
                    source_artifact_id,
                    normalized_record_id,
                    relation_record_id,
                    owner_record_id,
                    reference_role,
                    reference_kind,
                    target_raw,
                    status,
                    reason,
                    _json(evidence),
                    now,
                    now,
                ),
            )
        return {"unresolvedReferenceId": unresolved_reference_id}

    def upsert_conflict_record(
        self,
        *,
        conflict_record_id: str,
        conflict_kind: str,
        subject_id: str,
        conflicting_values: list[dict[str, Any]] | None,
        status: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        conflicting_values_json = _json_list(conflicting_values)
        evidence_json = _json(evidence)
        with self._connect() as conn:
            existing = conn.execute(
                """
                SELECT conflict_kind, subject_id, conflicting_values_json, status, evidence_json
                FROM conflict_record
                WHERE conflict_record_id=?
                """,
                (conflict_record_id,),
            ).fetchone()
            if existing and dict(existing) == {
                "conflict_kind": conflict_kind,
                "subject_id": subject_id,
                "conflicting_values_json": conflicting_values_json,
                "status": status,
                "evidence_json": evidence_json,
            }:
                return {"conflictRecordId": conflict_record_id}
            conn.execute(
                """
                INSERT INTO conflict_record (
                  conflict_record_id, conflict_kind, subject_id, conflicting_values_json,
                  status, evidence_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(conflict_record_id) DO UPDATE SET
                  conflict_kind=excluded.conflict_kind,
                  subject_id=excluded.subject_id,
                  conflicting_values_json=excluded.conflicting_values_json,
                  status=excluded.status,
                  evidence_json=excluded.evidence_json,
                  updated_at=excluded.updated_at
                """,
                (conflict_record_id, conflict_kind, subject_id, conflicting_values_json, status, evidence_json, now, now),
            )
        return {"conflictRecordId": conflict_record_id}

    def upsert_source_repository_snapshot(
        self,
        *,
        repository_snapshot_id: str,
        commit_hash: str,
        repository_url: str | None = None,
        repository_id: str | None = None,
        tree_hash: str | None = None,
        submodule_hashes: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_repository_snapshot (
                  repository_snapshot_id, repository_url, repository_id, commit_hash, tree_hash,
                  submodule_hashes_json, metadata_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(repository_snapshot_id) DO UPDATE SET
                  repository_url=excluded.repository_url,
                  repository_id=excluded.repository_id,
                  commit_hash=excluded.commit_hash,
                  tree_hash=excluded.tree_hash,
                  submodule_hashes_json=excluded.submodule_hashes_json,
                  metadata_json=excluded.metadata_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    repository_snapshot_id,
                    repository_url,
                    repository_id,
                    commit_hash,
                    tree_hash,
                    _json(submodule_hashes),
                    _json(metadata),
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"repositorySnapshotId": repository_snapshot_id, "updatedAt": now}

    def upsert_source_repository_artifact(
        self,
        *,
        source_repository_artifact_id: str,
        repository_snapshot_id: str,
        artifact_uri: str,
        media_type: str,
        checksum_sha256: str,
        storage_mode: str,
        metadata: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_repository_artifact (
                  source_repository_artifact_id, repository_snapshot_id, artifact_uri, media_type,
                  checksum_sha256, storage_mode, metadata_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_repository_artifact_id) DO UPDATE SET
                  repository_snapshot_id=excluded.repository_snapshot_id,
                  artifact_uri=excluded.artifact_uri,
                  media_type=excluded.media_type,
                  checksum_sha256=excluded.checksum_sha256,
                  storage_mode=excluded.storage_mode,
                  metadata_json=excluded.metadata_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    source_repository_artifact_id,
                    repository_snapshot_id,
                    artifact_uri,
                    media_type,
                    checksum_sha256,
                    storage_mode,
                    _json(metadata),
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"sourceRepositoryArtifactId": source_repository_artifact_id, "updatedAt": now}

    def upsert_source_build_context(
        self,
        *,
        build_context_id: str,
        repository_snapshot_id: str,
        project_id: str | None = None,
        target_id: str | None = None,
        build_target: str | None = None,
        toolchain: dict[str, Any] | None = None,
        compile_commands_artifact_id: str | None = None,
        dependency_graph: dict[str, Any] | None = None,
        build_metadata: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_build_context (
                  build_context_id, repository_snapshot_id, project_id, target_id, build_target,
                  toolchain_json, compile_commands_artifact_id, dependency_graph_json,
                  build_metadata_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(build_context_id) DO UPDATE SET
                  repository_snapshot_id=excluded.repository_snapshot_id,
                  project_id=excluded.project_id,
                  target_id=excluded.target_id,
                  build_target=excluded.build_target,
                  toolchain_json=excluded.toolchain_json,
                  compile_commands_artifact_id=excluded.compile_commands_artifact_id,
                  dependency_graph_json=excluded.dependency_graph_json,
                  build_metadata_json=excluded.build_metadata_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    build_context_id,
                    repository_snapshot_id,
                    project_id,
                    target_id,
                    build_target,
                    _json(toolchain),
                    compile_commands_artifact_id,
                    _json(dependency_graph),
                    _json(build_metadata),
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"buildContextId": build_context_id, "updatedAt": now}

    def upsert_source_analysis_artifact_set(
        self,
        *,
        analysis_artifact_set_id: str,
        build_context_id: str,
        analyzer_name: str,
        analyzer_version: str | None = None,
        analysis_config: dict[str, Any] | None = None,
        artifact_hashes: dict[str, Any] | None = None,
        produced_at: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_analysis_artifact_set (
                  analysis_artifact_set_id, build_context_id, analyzer_name, analyzer_version,
                  analysis_config_json, artifact_hashes_json, produced_at, provenance_json,
                  created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_artifact_set_id) DO UPDATE SET
                  build_context_id=excluded.build_context_id,
                  analyzer_name=excluded.analyzer_name,
                  analyzer_version=excluded.analyzer_version,
                  analysis_config_json=excluded.analysis_config_json,
                  artifact_hashes_json=excluded.artifact_hashes_json,
                  produced_at=excluded.produced_at,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    analysis_artifact_set_id,
                    build_context_id,
                    analyzer_name,
                    analyzer_version,
                    _json(analysis_config),
                    _json(artifact_hashes),
                    produced_at,
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"analysisArtifactSetId": analysis_artifact_set_id, "updatedAt": now}

    def upsert_source_evidence_snippet(
        self,
        *,
        evidence_snippet_id: str,
        repository_snapshot_id: str,
        file_path: str,
        snippet_text: str,
        checksum_sha256: str,
        line_start: int | None = None,
        line_end: int | None = None,
        language: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_evidence_snippet (
                  evidence_snippet_id, repository_snapshot_id, file_path, line_start, line_end,
                  language, snippet_text, checksum_sha256, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(evidence_snippet_id) DO UPDATE SET
                  repository_snapshot_id=excluded.repository_snapshot_id,
                  file_path=excluded.file_path,
                  line_start=excluded.line_start,
                  line_end=excluded.line_end,
                  language=excluded.language,
                  snippet_text=excluded.snippet_text,
                  checksum_sha256=excluded.checksum_sha256,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    evidence_snippet_id,
                    repository_snapshot_id,
                    file_path,
                    line_start,
                    line_end,
                    language,
                    snippet_text,
                    checksum_sha256,
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"evidenceSnippetId": evidence_snippet_id, "updatedAt": now}

    def upsert_source_graph_node(
        self,
        *,
        source_graph_node_id: str,
        analysis_artifact_set_id: str,
        node_kind: str,
        stable_id: str,
        display_name: str | None = None,
        file_path: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        symbol: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        evidence_snippet_id: str | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_graph_node (
                  source_graph_node_id, analysis_artifact_set_id, node_kind, stable_id,
                  display_name, file_path, line_start, line_end, symbol_json, metadata_json,
                  evidence_snippet_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_graph_node_id) DO UPDATE SET
                  analysis_artifact_set_id=excluded.analysis_artifact_set_id,
                  node_kind=excluded.node_kind,
                  stable_id=excluded.stable_id,
                  display_name=excluded.display_name,
                  file_path=excluded.file_path,
                  line_start=excluded.line_start,
                  line_end=excluded.line_end,
                  symbol_json=excluded.symbol_json,
                  metadata_json=excluded.metadata_json,
                  evidence_snippet_id=excluded.evidence_snippet_id,
                  updated_at=excluded.updated_at
                """,
                (
                    source_graph_node_id,
                    analysis_artifact_set_id,
                    node_kind,
                    stable_id,
                    display_name,
                    file_path,
                    line_start,
                    line_end,
                    _json(symbol),
                    _json(metadata),
                    evidence_snippet_id,
                    now,
                    now,
                ),
            )
        return {"sourceGraphNodeId": source_graph_node_id, "updatedAt": now}

    def upsert_source_graph_edge(
        self,
        *,
        source_graph_edge_id: str,
        analysis_artifact_set_id: str,
        edge_kind: str,
        source_graph_node_id: str,
        target_graph_node_id: str,
        evidence: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_graph_edge (
                  source_graph_edge_id, analysis_artifact_set_id, edge_kind, source_graph_node_id,
                  target_graph_node_id, evidence_json, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_graph_edge_id) DO UPDATE SET
                  analysis_artifact_set_id=excluded.analysis_artifact_set_id,
                  edge_kind=excluded.edge_kind,
                  source_graph_node_id=excluded.source_graph_node_id,
                  target_graph_node_id=excluded.target_graph_node_id,
                  evidence_json=excluded.evidence_json,
                  metadata_json=excluded.metadata_json,
                  updated_at=excluded.updated_at
                """,
                (
                    source_graph_edge_id,
                    analysis_artifact_set_id,
                    edge_kind,
                    source_graph_node_id,
                    target_graph_node_id,
                    _json(evidence),
                    _json(metadata),
                    now,
                    now,
                ),
            )
        return {"sourceGraphEdgeId": source_graph_edge_id, "updatedAt": now}

    def upsert_source_rich_ir_artifact(
        self,
        *,
        rich_ir_artifact_id: str,
        analysis_artifact_set_id: str,
        artifact_kind: str,
        media_type: str,
        checksum_sha256: str,
        uri: str | None = None,
        payload: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO source_rich_ir_artifact (
                  rich_ir_artifact_id, analysis_artifact_set_id, artifact_kind, media_type, uri,
                  checksum_sha256, payload_json, provenance_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rich_ir_artifact_id) DO UPDATE SET
                  analysis_artifact_set_id=excluded.analysis_artifact_set_id,
                  artifact_kind=excluded.artifact_kind,
                  media_type=excluded.media_type,
                  uri=excluded.uri,
                  checksum_sha256=excluded.checksum_sha256,
                  payload_json=excluded.payload_json,
                  provenance_json=excluded.provenance_json,
                  updated_at=excluded.updated_at
                """,
                (
                    rich_ir_artifact_id,
                    analysis_artifact_set_id,
                    artifact_kind,
                    media_type,
                    uri,
                    checksum_sha256,
                    _json(payload),
                    _json(provenance),
                    now,
                    now,
                ),
            )
        return {"richIrArtifactId": rich_ir_artifact_id, "updatedAt": now}

    def get_source_kg_context(
        self,
        *,
        repository_snapshot_id: str | None = None,
        build_context_id: str | None = None,
        analysis_artifact_set_id: str | None = None,
        graph_node_ids: list[str] | None = None,
        evidence_snippet_ids: list[str] | None = None,
        rich_ir_artifact_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        context_diagnostics: list[dict[str, Any]] = []

        def append_collection_lineage_mismatch(
            *,
            field: str,
            requested_container_id: str,
            linked_by: str,
            out_of_lineage_ids: list[str],
        ) -> None:
            if not out_of_lineage_ids:
                return
            context_diagnostics.append(
                {
                    "code": "SOURCE_KG_CONTEXT_INCONSISTENT",
                    "field": field,
                    "requestedContainerId": requested_container_id,
                    "linkedBy": linked_by,
                    "outOfLineageIds": out_of_lineage_ids,
                }
            )

        with self._connect() as conn:
            analysis_row = None
            if analysis_artifact_set_id:
                analysis_row = conn.execute(
                    "SELECT * FROM source_analysis_artifact_set WHERE analysis_artifact_set_id=?",
                    (analysis_artifact_set_id,),
                ).fetchone()
                if analysis_row is not None:
                    build_context_id = build_context_id or analysis_row["build_context_id"]

            build_row = None
            if build_context_id:
                build_row = conn.execute(
                    "SELECT * FROM source_build_context WHERE build_context_id=?",
                    (build_context_id,),
                ).fetchone()
                if build_row is not None:
                    repository_snapshot_id = repository_snapshot_id or build_row["repository_snapshot_id"]

            repo_row = None
            if repository_snapshot_id:
                repo_row = conn.execute(
                    "SELECT * FROM source_repository_snapshot WHERE repository_snapshot_id=?",
                    (repository_snapshot_id,),
                ).fetchone()

            graph_nodes = []
            if graph_node_ids:
                placeholders = ",".join("?" for _ in graph_node_ids)
                graph_nodes = conn.execute(
                    f"SELECT * FROM source_graph_node WHERE source_graph_node_id IN ({placeholders}) ORDER BY source_graph_node_id",
                    tuple(graph_node_ids),
                ).fetchall()
                graph_nodes = self._order_rows_like_requested_ids(
                    graph_nodes,
                    key="source_graph_node_id",
                    requested_ids=graph_node_ids,
                )
                if analysis_artifact_set_id:
                    analysis_id = (
                        analysis_row["analysis_artifact_set_id"]
                        if analysis_row is not None
                        else analysis_artifact_set_id
                    )
                    out_of_lineage_ids = [
                        row["source_graph_node_id"]
                        for row in graph_nodes
                        if analysis_row is None or row["analysis_artifact_set_id"] != analysis_id
                    ]
                    append_collection_lineage_mismatch(
                        field="graphNodeIds",
                        requested_container_id=analysis_id,
                        linked_by="analysisArtifactSetId",
                        out_of_lineage_ids=out_of_lineage_ids,
                    )
                    if out_of_lineage_ids:
                        graph_nodes = [
                            row
                            for row in graph_nodes
                            if analysis_row is not None and row["analysis_artifact_set_id"] == analysis_id
                        ]
            elif analysis_artifact_set_id:
                graph_nodes = conn.execute(
                    "SELECT * FROM source_graph_node WHERE analysis_artifact_set_id=? ORDER BY source_graph_node_id",
                    (analysis_artifact_set_id,),
                ).fetchall()
                graph_nodes = self._cap_source_context_rows(
                    graph_nodes,
                    field="graphNodes",
                    max_count=MAX_SOURCE_CONTEXT_GRAPH_NODES,
                    diagnostics=context_diagnostics,
                )

            graph_edges = []
            if analysis_artifact_set_id:
                graph_edges = conn.execute(
                    "SELECT * FROM source_graph_edge WHERE analysis_artifact_set_id=? ORDER BY source_graph_edge_id",
                    (analysis_artifact_set_id,),
                ).fetchall()
                if graph_node_ids or context_diagnostics:
                    requested_graph_node_ids = {row["source_graph_node_id"] for row in graph_nodes}
                    graph_edges = [
                        row
                        for row in graph_edges
                        if row["source_graph_node_id"] in requested_graph_node_ids
                        and row["target_graph_node_id"] in requested_graph_node_ids
                    ]
                graph_edges = self._cap_source_context_rows(
                    graph_edges,
                    field="graphEdges",
                    max_count=MAX_SOURCE_CONTEXT_GRAPH_EDGES,
                    diagnostics=context_diagnostics,
                )

            evidence_snippets = []
            if evidence_snippet_ids:
                placeholders = ",".join("?" for _ in evidence_snippet_ids)
                evidence_snippets = conn.execute(
                    f"SELECT * FROM source_evidence_snippet WHERE evidence_snippet_id IN ({placeholders}) ORDER BY evidence_snippet_id",
                    tuple(evidence_snippet_ids),
                ).fetchall()
                evidence_snippets = self._order_rows_like_requested_ids(
                    evidence_snippets,
                    key="evidence_snippet_id",
                    requested_ids=evidence_snippet_ids,
                )
                if repository_snapshot_id:
                    repository_id = (
                        repo_row["repository_snapshot_id"]
                        if repo_row is not None
                        else repository_snapshot_id
                    )
                    out_of_lineage_ids = [
                        row["evidence_snippet_id"]
                        for row in evidence_snippets
                        if repo_row is None or row["repository_snapshot_id"] != repository_id
                    ]
                    append_collection_lineage_mismatch(
                        field="evidenceSnippetIds",
                        requested_container_id=repository_id,
                        linked_by="repositorySnapshotId",
                        out_of_lineage_ids=out_of_lineage_ids,
                    )
                    if out_of_lineage_ids:
                        evidence_snippets = [
                            row
                            for row in evidence_snippets
                            if repo_row is not None and row["repository_snapshot_id"] == repository_id
                        ]
            elif graph_nodes:
                snippet_ids = sorted({row["evidence_snippet_id"] for row in graph_nodes if row["evidence_snippet_id"]})
                if snippet_ids:
                    placeholders = ",".join("?" for _ in snippet_ids)
                    evidence_snippets = conn.execute(
                        f"SELECT * FROM source_evidence_snippet WHERE evidence_snippet_id IN ({placeholders}) ORDER BY evidence_snippet_id",
                        tuple(snippet_ids),
                    ).fetchall()

            rich_ir_artifacts = []
            if rich_ir_artifact_ids:
                placeholders = ",".join("?" for _ in rich_ir_artifact_ids)
                rich_ir_artifacts = conn.execute(
                    f"SELECT * FROM source_rich_ir_artifact WHERE rich_ir_artifact_id IN ({placeholders}) ORDER BY rich_ir_artifact_id",
                    tuple(rich_ir_artifact_ids),
                ).fetchall()
                rich_ir_artifacts = self._order_rows_like_requested_ids(
                    rich_ir_artifacts,
                    key="rich_ir_artifact_id",
                    requested_ids=rich_ir_artifact_ids,
                )
                if analysis_artifact_set_id:
                    analysis_id = (
                        analysis_row["analysis_artifact_set_id"]
                        if analysis_row is not None
                        else analysis_artifact_set_id
                    )
                    out_of_lineage_ids = [
                        row["rich_ir_artifact_id"]
                        for row in rich_ir_artifacts
                        if analysis_row is None or row["analysis_artifact_set_id"] != analysis_id
                    ]
                    append_collection_lineage_mismatch(
                        field="richIrArtifactIds",
                        requested_container_id=analysis_id,
                        linked_by="analysisArtifactSetId",
                        out_of_lineage_ids=out_of_lineage_ids,
                    )
                    if out_of_lineage_ids:
                        rich_ir_artifacts = [
                            row
                            for row in rich_ir_artifacts
                            if analysis_row is not None and row["analysis_artifact_set_id"] == analysis_id
                        ]
            elif analysis_artifact_set_id:
                rich_ir_artifacts = conn.execute(
                    "SELECT * FROM source_rich_ir_artifact WHERE analysis_artifact_set_id=? ORDER BY rich_ir_artifact_id",
                    (analysis_artifact_set_id,),
                ).fetchall()
                rich_ir_artifacts = self._cap_source_context_rows(
                    rich_ir_artifacts,
                    field="richIrArtifacts",
                    max_count=MAX_SOURCE_CONTEXT_RICH_IR_ARTIFACTS,
                    diagnostics=context_diagnostics,
                )

            source_artifacts = []
            if build_row is not None and build_row["compile_commands_artifact_id"]:
                source_artifact_row = conn.execute(
                    "SELECT * FROM source_repository_artifact WHERE source_repository_artifact_id=?",
                    (build_row["compile_commands_artifact_id"],),
                ).fetchone()
                if source_artifact_row is not None:
                    source_artifacts = [source_artifact_row]

            lineage_diagnostics = self._source_context_lineage_diagnostics(
                repository_snapshot_row=repo_row,
                build_context_row=build_row,
                analysis_artifact_set_row=analysis_row,
            )
            context_diagnostics.extend(lineage_diagnostics)
            context_diagnostics.extend(
                self._source_context_collection_lineage_diagnostics(
                    repository_snapshot_row=repo_row,
                    analysis_artifact_set_row=analysis_row,
                    graph_node_rows=graph_nodes,
                    evidence_snippet_rows=evidence_snippets,
                    rich_ir_artifact_rows=rich_ir_artifacts,
                )
            )
            repository_snapshot_record = self._source_repository_snapshot_record(repo_row) if repo_row else None
            build_context_record = self._source_build_context_record(build_row) if build_row else None
            analysis_artifact_set_record = self._source_analysis_artifact_set_record(analysis_row) if analysis_row else None
            source_artifact_records = [self._source_repository_artifact_record(row) for row in source_artifacts]
            graph_node_records = [self._source_graph_node_record(row) for row in graph_nodes]
            graph_edge_records = [self._source_graph_edge_record(row) for row in graph_edges]
            evidence_snippet_records = [self._source_evidence_snippet_record(row) for row in evidence_snippets]
            rich_ir_artifact_records = [self._source_rich_ir_artifact_record(row) for row in rich_ir_artifacts]
            projection_diagnostics = self._source_context_projection_diagnostics(
                    repository_snapshot_record=repository_snapshot_record,
                    build_context_record=build_context_record,
                    analysis_artifact_set_record=analysis_artifact_set_record,
                    source_artifact_records=source_artifact_records,
                    graph_node_records=graph_node_records,
                    graph_edge_records=graph_edge_records,
                    evidence_snippet_records=evidence_snippet_records,
                rich_ir_artifact_records=rich_ir_artifact_records,
            )
            context_diagnostics.extend(self._cap_source_context_projection_diagnostics(projection_diagnostics))
            context_resolution = self._source_context_resolution(
                requested={
                    "repositorySnapshotId": repository_snapshot_id,
                    "buildContextId": build_context_id,
                    "analysisArtifactSetId": analysis_artifact_set_id,
                    "sourceArtifactIds": [build_row["compile_commands_artifact_id"]]
                    if build_row is not None and build_row["compile_commands_artifact_id"]
                    else [],
                    "graphNodeIds": graph_node_ids or [],
                    "evidenceSnippetIds": evidence_snippet_ids or [],
                    "richIrArtifactIds": rich_ir_artifact_ids or [],
                },
                resolved={
                    "repositorySnapshotId": repo_row["repository_snapshot_id"] if repo_row else None,
                    "buildContextId": build_row["build_context_id"] if build_row else None,
                    "analysisArtifactSetId": analysis_row["analysis_artifact_set_id"] if analysis_row else None,
                    "sourceArtifactIds": [row["source_repository_artifact_id"] for row in source_artifacts],
                    "graphNodeIds": [row["source_graph_node_id"] for row in graph_nodes],
                    "evidenceSnippetIds": [row["evidence_snippet_id"] for row in evidence_snippets],
                    "richIrArtifactIds": [row["rich_ir_artifact_id"] for row in rich_ir_artifacts],
                },
                diagnostics=context_diagnostics,
            )
            resolved = bool(repo_row or build_row or analysis_row or graph_nodes or evidence_snippets or rich_ir_artifacts)
            return {
                "repositorySnapshot": repository_snapshot_record,
                "buildContext": build_context_record,
                "analysisArtifactSet": analysis_artifact_set_record,
                "sourceArtifacts": source_artifact_records,
                "graphNodes": graph_node_records,
                "graphEdges": graph_edge_records,
                "evidenceSnippets": evidence_snippet_records,
                "richIrArtifacts": rich_ir_artifact_records,
                "contextResolution": {**context_resolution, "partial": bool(context_resolution["diagnostics"] and resolved)},
                "resolved": resolved,
            }

    @staticmethod
    def _order_rows_like_requested_ids(
        rows: list[sqlite3.Row],
        *,
        key: str,
        requested_ids: list[str],
    ) -> list[sqlite3.Row]:
        requested_order = {item: index for index, item in enumerate(requested_ids)}
        return sorted(rows, key=lambda row: requested_order.get(row[key], len(requested_order)))

    @staticmethod
    def _cap_source_context_rows(
        rows: list[sqlite3.Row],
        *,
        field: str,
        max_count: int,
        diagnostics: list[dict[str, Any]],
    ) -> list[sqlite3.Row]:
        total_count = len(rows)
        if total_count <= max_count:
            return rows
        diagnostics.append(
            {
                "code": "SOURCE_KG_CONTEXT_TRUNCATED",
                "field": field,
                "totalCount": total_count,
                "returnedCount": max_count,
                "maxCount": max_count,
            }
        )
        return rows[:max_count]

    @staticmethod
    def _source_context_lineage_diagnostics(
        *,
        repository_snapshot_row: sqlite3.Row | None,
        build_context_row: sqlite3.Row | None,
        analysis_artifact_set_row: sqlite3.Row | None,
    ) -> list[dict[str, Any]]:
        diagnostics: list[dict[str, Any]] = []
        if (
            repository_snapshot_row is not None
            and build_context_row is not None
            and build_context_row["repository_snapshot_id"] != repository_snapshot_row["repository_snapshot_id"]
        ):
            diagnostics.append(
                {
                    "code": "SOURCE_KG_CONTEXT_INCONSISTENT",
                    "field": "repositorySnapshotId",
                    "requestedId": repository_snapshot_row["repository_snapshot_id"],
                    "linkedId": build_context_row["repository_snapshot_id"],
                    "linkedBy": "buildContextId",
                    "buildContextId": build_context_row["build_context_id"],
                }
            )
        if (
            build_context_row is not None
            and analysis_artifact_set_row is not None
            and analysis_artifact_set_row["build_context_id"] != build_context_row["build_context_id"]
        ):
            diagnostics.append(
                {
                    "code": "SOURCE_KG_CONTEXT_INCONSISTENT",
                    "field": "buildContextId",
                    "requestedId": build_context_row["build_context_id"],
                    "linkedId": analysis_artifact_set_row["build_context_id"],
                    "linkedBy": "analysisArtifactSetId",
                    "analysisArtifactSetId": analysis_artifact_set_row["analysis_artifact_set_id"],
                }
        )
        return diagnostics

    @staticmethod
    def _source_context_collection_lineage_diagnostics(
        *,
        repository_snapshot_row: sqlite3.Row | None,
        analysis_artifact_set_row: sqlite3.Row | None,
        graph_node_rows: list[sqlite3.Row],
        evidence_snippet_rows: list[sqlite3.Row],
        rich_ir_artifact_rows: list[sqlite3.Row],
    ) -> list[dict[str, Any]]:
        diagnostics: list[dict[str, Any]] = []

        def append_collection_mismatch(
            *,
            field: str,
            requested_container_id: str,
            linked_by: str,
            out_of_lineage_ids: list[str],
        ) -> None:
            if not out_of_lineage_ids:
                return
            diagnostics.append(
                {
                    "code": "SOURCE_KG_CONTEXT_INCONSISTENT",
                    "field": field,
                    "requestedContainerId": requested_container_id,
                    "linkedBy": linked_by,
                    "outOfLineageIds": out_of_lineage_ids,
                }
            )

        if analysis_artifact_set_row is not None:
            analysis_id = analysis_artifact_set_row["analysis_artifact_set_id"]
            append_collection_mismatch(
                field="graphNodeIds",
                requested_container_id=analysis_id,
                linked_by="analysisArtifactSetId",
                out_of_lineage_ids=[
                    row["source_graph_node_id"]
                    for row in graph_node_rows
                    if row["analysis_artifact_set_id"] != analysis_id
                ],
            )
            append_collection_mismatch(
                field="richIrArtifactIds",
                requested_container_id=analysis_id,
                linked_by="analysisArtifactSetId",
                out_of_lineage_ids=[
                    row["rich_ir_artifact_id"]
                    for row in rich_ir_artifact_rows
                    if row["analysis_artifact_set_id"] != analysis_id
                ],
            )

        if repository_snapshot_row is not None:
            repository_snapshot_id = repository_snapshot_row["repository_snapshot_id"]
            append_collection_mismatch(
                field="evidenceSnippetIds",
                requested_container_id=repository_snapshot_id,
                linked_by="repositorySnapshotId",
                out_of_lineage_ids=[
                    row["evidence_snippet_id"]
                    for row in evidence_snippet_rows
                    if row["repository_snapshot_id"] != repository_snapshot_id
                ],
            )
        return diagnostics

    @staticmethod
    def _source_context_projection_diagnostics(
        *,
        repository_snapshot_record: dict[str, Any] | None,
        build_context_record: dict[str, Any] | None,
        analysis_artifact_set_record: dict[str, Any] | None,
        source_artifact_records: list[dict[str, Any]],
        graph_node_records: list[dict[str, Any]],
        graph_edge_records: list[dict[str, Any]],
        evidence_snippet_records: list[dict[str, Any]],
        rich_ir_artifact_records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        diagnostics: list[dict[str, Any]] = []

        def append_record_diagnostics(path: str, record: dict[str, Any] | None, id_fields: tuple[str, ...]) -> None:
            if not record:
                return
            field_names = set()
            for key in record:
                if key.endswith("Redacted"):
                    field_names.add(key[: -len("Redacted")])
                if key.endswith("Truncated"):
                    field_names.add(key[: -len("Truncated")])
            for field in sorted(field_names):
                redacted = record.get(f"{field}Redacted") is True
                truncated = record.get(f"{field}Truncated") is True
                if not (redacted or truncated):
                    continue
                diagnostic: dict[str, Any] = {
                    "code": "SOURCE_KG_CONTEXT_REDACTED" if redacted else "SOURCE_KG_CONTEXT_TRUNCATED",
                    "field": f"{path}.{field}",
                    "redacted": redacted,
                    "truncated": truncated,
                }
                byte_length = record.get(f"{field}ByteLength")
                max_inline_bytes = record.get(f"{field}MaxInlineBytes")
                if isinstance(byte_length, int):
                    diagnostic["byteLength"] = byte_length
                if isinstance(max_inline_bytes, int):
                    diagnostic["maxInlineBytes"] = max_inline_bytes
                for id_field in id_fields:
                    if record.get(id_field):
                        diagnostic[id_field] = record[id_field]
                diagnostics.append(diagnostic)

        append_record_diagnostics(
            "repositorySnapshot",
            repository_snapshot_record,
            ("repositorySnapshotId",),
        )
        append_record_diagnostics(
            "buildContext",
            build_context_record,
            ("buildContextId", "repositorySnapshotId"),
        )
        append_record_diagnostics(
            "analysisArtifactSet",
            analysis_artifact_set_record,
            ("analysisArtifactSetId", "buildContextId"),
        )
        for index, record in enumerate(source_artifact_records):
            append_record_diagnostics(f"sourceArtifacts.{index}", record, ("sourceRepositoryArtifactId", "repositorySnapshotId"))
        for index, record in enumerate(graph_node_records):
            append_record_diagnostics(f"graphNodes.{index}", record, ("sourceGraphNodeId", "analysisArtifactSetId"))
        for index, record in enumerate(graph_edge_records):
            append_record_diagnostics(f"graphEdges.{index}", record, ("sourceGraphEdgeId", "analysisArtifactSetId"))
        for index, record in enumerate(evidence_snippet_records):
            append_record_diagnostics(f"evidenceSnippets.{index}", record, ("evidenceSnippetId", "repositorySnapshotId"))
        for index, record in enumerate(rich_ir_artifact_records):
            append_record_diagnostics(f"richIrArtifacts.{index}", record, ("richIrArtifactId", "analysisArtifactSetId"))
        return diagnostics

    @staticmethod
    def _cap_source_context_projection_diagnostics(diagnostics: list[dict[str, Any]]) -> list[dict[str, Any]]:
        total_count = len(diagnostics)
        if total_count <= MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS:
            return diagnostics
        return [
            *diagnostics[:MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS],
            {
                "code": "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED",
                "field": "projectionDiagnostics",
                "totalCount": total_count,
                "returnedCount": MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS,
                "maxCount": MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS,
            },
        ]

    @staticmethod
    def _source_context_resolution(
        *,
        requested: dict[str, Any],
        resolved: dict[str, Any],
        diagnostics: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        diagnostics = list(diagnostics or [])

        def safe_id(value: Any) -> Any:
            return redact_url_for_log(value) if isinstance(value, str) else value

        def safe_ids(values: list[Any]) -> list[Any]:
            return [safe_id(item) for item in values]

        def scalar(request_key: str, label: str) -> dict[str, Any]:
            requested_id = requested.get(request_key)
            resolved_id = resolved.get(request_key)
            missing_ids = [requested_id] if requested_id and not resolved_id else []
            if missing_ids:
                diagnostics.append({"code": "SOURCE_KG_CONTEXT_PARTIAL", "field": label, "missingIds": safe_ids(missing_ids)})
            return {"requestedId": safe_id(requested_id), "resolvedId": safe_id(resolved_id), "missingIds": safe_ids(missing_ids)}

        def collection(request_key: str, resolved_key: str, label: str) -> dict[str, Any]:
            requested_ids = list(requested.get(request_key) or [])
            resolved_ids = list(resolved.get(resolved_key) or [])
            resolved_set = set(resolved_ids)
            missing_ids = [item for item in requested_ids if item not in resolved_set]
            if missing_ids:
                diagnostics.append({"code": "SOURCE_KG_CONTEXT_PARTIAL", "field": label, "missingIds": safe_ids(missing_ids)})
            return {"requestedIds": safe_ids(requested_ids), "resolvedIds": safe_ids(resolved_ids), "missingIds": safe_ids(missing_ids)}

        return {
            "schemaVersion": "s5-source-kg-context-resolution-v1",
            "repositorySnapshot": scalar("repositorySnapshotId", "repositorySnapshotId"),
            "buildContext": scalar("buildContextId", "buildContextId"),
            "analysisArtifactSet": scalar("analysisArtifactSetId", "analysisArtifactSetId"),
            "sourceArtifacts": collection("sourceArtifactIds", "sourceArtifactIds", "sourceArtifactIds"),
            "graphNodes": collection("graphNodeIds", "graphNodeIds", "graphNodeIds"),
            "evidenceSnippets": collection("evidenceSnippetIds", "evidenceSnippetIds", "evidenceSnippetIds"),
            "richIrArtifacts": collection("richIrArtifactIds", "richIrArtifactIds", "richIrArtifactIds"),
            "diagnostics": diagnostics,
            "complete": not diagnostics,
            "partial": False,
        }

    def _source_repository_snapshot_record(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "repositorySnapshotId": row["repository_snapshot_id"],
            "repositoryUrl": redact_url_for_log(row["repository_url"]) if row["repository_url"] else row["repository_url"],
            "repositoryId": row["repository_id"],
            "commitHash": row["commit_hash"],
            "treeHash": row["tree_hash"],
            **_nested_object_projection("submoduleHashes", _loads(row["submodule_hashes_json"], {})),
            **_nested_object_projection("metadata", _loads(row["metadata_json"], {})),
            **_nested_object_projection("provenance", _loads(row["provenance_json"], {})),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _source_repository_artifact_record(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sourceRepositoryArtifactId": row["source_repository_artifact_id"],
            "repositorySnapshotId": row["repository_snapshot_id"],
            "artifactUri": redact_url_for_log(row["artifact_uri"]),
            "mediaType": row["media_type"],
            "checksumSha256": row["checksum_sha256"],
            "storageMode": row["storage_mode"],
            **_nested_object_projection("metadata", _loads(row["metadata_json"], {})),
            **_nested_object_projection("provenance", _loads(row["provenance_json"], {})),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _source_build_context_record(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "buildContextId": row["build_context_id"],
            "repositorySnapshotId": row["repository_snapshot_id"],
            "projectId": row["project_id"],
            "targetId": row["target_id"],
            "buildTarget": row["build_target"],
            **_nested_object_projection("toolchain", _loads(row["toolchain_json"], {})),
            "compileCommandsArtifactId": row["compile_commands_artifact_id"],
            **_nested_object_projection("dependencyGraph", _loads(row["dependency_graph_json"], {})),
            **_nested_object_projection("buildMetadata", _loads(row["build_metadata_json"], {})),
            **_nested_object_projection("provenance", _loads(row["provenance_json"], {})),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _source_analysis_artifact_set_record(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "analysisArtifactSetId": row["analysis_artifact_set_id"],
            "buildContextId": row["build_context_id"],
            "analyzerName": row["analyzer_name"],
            "analyzerVersion": row["analyzer_version"],
            **_nested_object_projection("analysisConfig", _loads(row["analysis_config_json"], {})),
            **_nested_object_projection("artifactHashes", _loads(row["artifact_hashes_json"], {})),
            "producedAt": row["produced_at"],
            **_nested_object_projection("provenance", _loads(row["provenance_json"], {})),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _source_graph_node_record(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sourceGraphNodeId": row["source_graph_node_id"],
            "analysisArtifactSetId": row["analysis_artifact_set_id"],
            "nodeKind": row["node_kind"],
            "stableId": row["stable_id"],
            "displayName": row["display_name"],
            "filePath": row["file_path"],
            "lineStart": row["line_start"],
            "lineEnd": row["line_end"],
            **_nested_object_projection("symbol", _loads(row["symbol_json"], {})),
            **_nested_object_projection("metadata", _loads(row["metadata_json"], {})),
            "evidenceSnippetId": row["evidence_snippet_id"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _source_graph_edge_record(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sourceGraphEdgeId": row["source_graph_edge_id"],
            "analysisArtifactSetId": row["analysis_artifact_set_id"],
            "edgeKind": row["edge_kind"],
            "sourceGraphNodeId": row["source_graph_node_id"],
            "targetGraphNodeId": row["target_graph_node_id"],
            **_nested_object_projection("evidence", _loads(row["evidence_json"], {})),
            **_nested_object_projection("metadata", _loads(row["metadata_json"], {})),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _source_evidence_snippet_record(self, row: sqlite3.Row) -> dict[str, Any]:
        snippet_text = row["snippet_text"] or ""
        snippet_text_byte_length = len(snippet_text.encode("utf-8"))
        snippet_text_truncated = snippet_text_byte_length > MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES
        return {
            "evidenceSnippetId": row["evidence_snippet_id"],
            "repositorySnapshotId": row["repository_snapshot_id"],
            "filePath": row["file_path"],
            "lineStart": row["line_start"],
            "lineEnd": row["line_end"],
            "language": row["language"],
            "snippetText": _truncate_utf8(snippet_text, MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES),
            "snippetTextByteLength": snippet_text_byte_length,
            "snippetTextMaxInlineBytes": MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES,
            "snippetTextTruncated": snippet_text_truncated,
            "checksumSha256": row["checksum_sha256"],
            **_nested_object_projection("provenance", _loads(row["provenance_json"], {})),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _source_rich_ir_artifact_record(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = _loads(row["payload_json"], {})
        payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        payload_byte_length = len(payload_json.encode("utf-8"))
        payload_truncated = payload_byte_length > MAX_SOURCE_RICH_IR_PAYLOAD_INLINE_BYTES
        return {
            "richIrArtifactId": row["rich_ir_artifact_id"],
            "analysisArtifactSetId": row["analysis_artifact_set_id"],
            "artifactKind": row["artifact_kind"],
            "mediaType": row["media_type"],
            "uri": redact_url_for_log(row["uri"]) if row["uri"] else row["uri"],
            "checksumSha256": row["checksum_sha256"],
            "payload": None if payload_truncated else payload,
            "payloadByteLength": payload_byte_length,
            "payloadMaxInlineBytes": MAX_SOURCE_RICH_IR_PAYLOAD_INLINE_BYTES,
            "payloadTruncated": payload_truncated,
            "payloadRedacted": payload_truncated,
            **_nested_object_projection("provenance", _loads(row["provenance_json"], {})),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def upsert_projection_bundle_manifest(
        self,
        *,
        projection_bundle_id: str,
        scope_key: str,
        projection_version: str,
        source_hash: str,
        manifest: dict[str, Any],
        qa_report: dict[str, Any],
        node_count: int,
        edge_count: int,
        text_chunk_count: int,
        checksums: dict[str, Any],
        production_write_enabled: bool = False,
    ) -> dict[str, Any]:
        created_at = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO projection_bundle_manifest (
                  projection_bundle_id, scope_key, projection_version, source_hash,
                  manifest_json, qa_report_json, node_count, edge_count, text_chunk_count,
                  checksums_json, production_write_enabled, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    projection_bundle_id,
                    scope_key,
                    projection_version,
                    source_hash,
                    _json(manifest),
                    _json(qa_report),
                    node_count,
                    edge_count,
                    text_chunk_count,
                    _json(checksums),
                    1 if production_write_enabled else 0,
                    created_at,
                ),
            )
        return {"projectionBundleId": projection_bundle_id, "createdAt": created_at}
