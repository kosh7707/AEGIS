from __future__ import annotations

import json
import sqlite3

from app.ledger.repository import SCHEMA_VERSION, SQLiteLedgerRepository


REQUIRED_TABLES = {
    "ledger_meta",
    "knowledge_source",
    "raw_artifact",
    "normalized_record",
    "package_identity",
    "vulnerability_advisory",
    "affected_range",
    "weakness",
    "attack_pattern",
    "mitigation",
    "tool_rule",
    "domain_concept",
    "relation_record",
    "transform_decision",
    "provider_observation",
    "target_context",
    "target_context_version",
    "acquisition_run",
    "acquisition_item",
    "projection_state",
    "projection_job",
}


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    return repo


def test_ledger_initializes_schema_idempotently_with_user_version(tmp_path):
    repo = _repo(tmp_path)
    repo.initialize()

    assert REQUIRED_TABLES <= set(repo.list_tables())
    meta = repo.get_meta()
    assert meta["schemaVersion"] == SCHEMA_VERSION
    assert meta["userVersion"] == SCHEMA_VERSION


def test_target_context_upsert_reuses_same_hash_and_versions_changed_hash(tmp_path):
    repo = _repo(tmp_path)
    identity = {
        "projectId": "re100",
        "targetId": "re100:gateway",
        "buildSnapshotId": "bsnap-1",
        "buildUnitId": "gateway",
        "snapshotSchemaVersion": "build-snapshot-v1",
        "sourceBuildAttemptId": "attempt-1",
    }

    first = repo.upsert_target_context_version(
        target_knowledge_id="tctx-test",
        target_context_ingest_id="ing-1",
        target_context_input_hash="sha256:aaa",
        identity=identity,
        bundle={"projectId": "re100", "target": {"targetId": "re100:gateway"}},
    )
    second = repo.upsert_target_context_version(
        target_knowledge_id="tctx-test",
        target_context_ingest_id="ing-1",
        target_context_input_hash="sha256:aaa",
        identity=identity,
        bundle={"projectId": "re100", "target": {"targetId": "re100:gateway"}},
    )
    changed = repo.upsert_target_context_version(
        target_knowledge_id="tctx-test",
        target_context_ingest_id="ing-2",
        target_context_input_hash="sha256:bbb",
        identity=identity,
        bundle={"projectId": "re100", "target": {"targetId": "re100:gateway"}, "changed": True},
    )

    assert first["targetContextVersion"] == 1
    assert first["reused"] is False
    assert second["targetContextVersion"] == 1
    assert second["reused"] is True
    assert changed["targetContextVersion"] == 2
    assert changed["record"]["supersedesTargetContextVersion"] == 1
    latest = repo.get_target_context("tctx-test")
    assert latest["targetContextVersion"] == 2
    assert latest["bundle"]["changed"] is True


def test_target_context_idempotency_without_build_snapshot_uses_stable_empty_key(tmp_path):
    repo = _repo(tmp_path)
    identity = {"projectId": "re100", "targetId": "re100:gateway", "buildSnapshotId": None, "buildUnitId": "gateway"}

    first = repo.upsert_target_context_version(
        target_knowledge_id="tctx-no-snapshot",
        target_context_ingest_id="ing-1",
        target_context_input_hash="sha256:same",
        identity=identity,
        bundle={"projectId": "re100"},
    )
    second = repo.upsert_target_context_version(
        target_knowledge_id="tctx-no-snapshot",
        target_context_ingest_id="ing-2",
        target_context_input_hash="sha256:same",
        identity=identity,
        bundle={"projectId": "re100"},
    )

    assert first["targetContextVersion"] == 1
    assert second["targetContextVersion"] == 1
    assert second["reused"] is True


def test_acquisition_run_item_provider_and_projection_state_roundtrip(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_target_context_version(
        target_knowledge_id="tctx-test",
        target_context_ingest_id="ing-1",
        target_context_input_hash="sha256:aaa",
        identity={"projectId": "re100", "targetId": "gateway", "buildSnapshotId": "bsnap-1"},
        bundle={"hello": "world"},
    )

    run = repo.record_acquisition_run(
        acquisition_id="acq-1",
        target_knowledge_id="tctx-test",
        target_context_version=1,
        surface="cveDiscovery",
        acquisition_status="completed_hit",
        acquisition_quality_gate="accepted_with_caveats",
        consumer_policy="contextual_only",
        scope={"library": "libcurl"},
        provenance={"source": "test"},
        results={"count": 1},
        completed_at="2026-05-11T00:00:00+00:00",
    )
    item = repo.record_acquisition_item(
        acquisition_id="acq-1",
        item_key="libcurl@8.0.0",
        item_type="library",
        acquisition_status="completed_hit",
        acquisition_quality_gate="accepted",
        consumer_policy="contextual_only",
        diagnostics=[{"code": "OK"}],
        results={"cves": ["CVE-2026-0001"]},
    )
    observation = repo.record_provider_observation(
        acquisition_id="acq-1",
        provider="osv",
        subject_key="pkg:generic/libcurl@8.0.0",
        status="fresh",
        freshness={"retrievedAt": "now"},
        cache={"hit": False},
        payload={"advisories": 1},
    )
    state = repo.record_projection_state(
        projection_name="neo4j-threat",
        scope_key="knowledge-corpus-v1",
        state="debt",
        source_hash="sha256:corpus",
        projection_version="v1",
        debt={"reason": "not_projected"},
        freshness={"status": "stale"},
    )

    assert run["acquisitionId"] == "acq-1"
    assert item["itemId"].startswith("acq-item-")
    assert observation["observationId"].startswith("prov-obs-")
    assert state["projectionStateId"].startswith("proj-state-")
    loaded_state = repo.get_projection_state("neo4j-threat", "knowledge-corpus-v1")
    assert loaded_state["state"] == "debt"
    assert loaded_state["debt"]["reason"] == "not_projected"


def test_projection_job_roundtrip_records_sync_and_debt_diagnostics(tmp_path):
    repo = _repo(tmp_path)

    job = repo.record_projection_job(
        projection_name="neo4j-threat",
        scope_key="knowledge-corpus-v1",
        state="debt",
        diagnostics=[{"code": "ADAPTER_MISSING"}],
        started_at="2026-05-11T00:00:00Z",
        completed_at="2026-05-11T00:00:01Z",
    )

    jobs = repo.list_projection_jobs("neo4j-threat")
    assert job["projectionJobId"].startswith("proj-job-")
    assert len(jobs) == 1
    assert jobs[0]["projectionName"] == "neo4j-threat"
    assert jobs[0]["state"] == "debt"
    assert jobs[0]["diagnostics"][0]["code"] == "ADAPTER_MISSING"


def test_transform_decision_roundtrip_persists_method_policy_and_diagnostics(tmp_path):
    repo = _repo(tmp_path)

    result = repo.upsert_transform_decision(
        transform_decision_id="transform-test",
        input_id="raw-cwe-78-sample",
        output_id="CWE-78",
        method="exact_id_match",
        decision={
            "method": "exact_id_match",
            "confidence": 1.0,
            "consumerPolicy": "contextual_only",
            "sourceRefs": [{"sourceKind": "CWE", "rawArtifactId": "raw-cwe-78-sample"}],
        },
        diagnostics=[{"code": "EXACT_ID_MATCH"}],
    )

    row = next(row for row in repo.fetch_all("transform_decision") if row["transform_decision_id"] == "transform-test")
    assert result["transformDecisionId"] == "transform-test"
    assert row["input_id"] == "raw-cwe-78-sample"
    assert row["output_id"] == "CWE-78"
    assert row["method"] == "exact_id_match"
    assert json.loads(row["decision_json"])["consumerPolicy"] == "contextual_only"
    assert json.loads(row["diagnostics_json"])[0]["code"] == "EXACT_ID_MATCH"


def test_schema_constraints_include_target_unique_and_projection_unique(tmp_path):
    repo = _repo(tmp_path)
    db_path = tmp_path / "s5-ledger.sqlite"

    with sqlite3.connect(db_path) as conn:
        target_indexes = conn.execute("PRAGMA index_list(target_context)").fetchall()
        projection_indexes = conn.execute("PRAGMA index_list(projection_state)").fetchall()

    assert any(row[2] for row in target_indexes)
    assert any(row[2] for row in projection_indexes)
