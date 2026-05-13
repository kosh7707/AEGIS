from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.judge.models import JudgeQueryRequest
from app.judge.service import build_judge_answer
from app.ledger.repository import SQLiteLedgerRepository
from app.projections.ledger_projection import build_projection_bundle
from app.quality import run_ledger_quality_gate
from app.relations import detect_relation_conflicts
from app.routers import api
from app.main import app

client = TestClient(app)


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo)
    return repo


def _codes(report):
    return {item["code"] for item in report.get("issues", [])}


def _conflict_kinds(repo):
    return {row["conflict_kind"] for row in repo.fetch_all("conflict_record")}


def test_default_fixture_has_no_conflicts_and_judge_uncertainty_shape_is_preserved(tmp_path):
    repo = _repo(tmp_path)

    conflict_report = detect_relation_conflicts(repo)
    quality = run_ledger_quality_gate(repo)
    answer = build_judge_answer(
        repo,
            JudgeQueryRequest(
                question="Is curl 8.0.0 affected?",
                component={"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
                sourceContext={"graphNodeIds": ["srcctx-curl-call-system"]},
            ),
        )

    assert conflict_report["schemaVersion"] == "s5-relation-conflict-report-v1"
    assert conflict_report["qualityImpact"] == "none"
    assert conflict_report["conflictCount"] == 0
    assert repo.count_rows("conflict_record") == 0
    assert quality["metrics"]["conflictRecordCount"] == 0
    assert quality["metrics"]["openConflictCount"] == 0
    assert quality["metrics"]["conflictKinds"] == []
    assert "conflicts" in answer["uncertainty"]
    assert answer["uncertainty"]["conflicts"] == []
    assert "conflicts" not in answer["evidence"]


def test_provider_cve_coreferences_are_related_aliases_not_exact_identity_conflicts(tmp_path):
    repo = _repo(tmp_path)
    cve_aliases = [
        row
        for row in repo.fetch_all("identity_alias")
        if row["alias_namespace"] == "cve" and row["alias_id"] == "CVE-2026-0001"
    ]

    assert any(row["relation_semantics"] == "RELATED_ALIAS" for row in cve_aliases)
    assert {row["relation_semantics"] for row in cve_aliases} >= {"NATIVE_ID", "SAME_AS_EXACT", "RELATED_ALIAS"}
    assert detect_relation_conflicts(repo)["conflictCount"] == 0


def test_affectedness_status_conflict_records_stable_conflict_and_rejects_quality(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_affectedness_record(
        affectedness_id="affectedness:test:not-affected",
        advisory_id="advisory:NVD_CVE:CVE-2026-0001",
        subject_kind="package_identity",
        subject_id="pkg:generic/curl",
        affectedness_status="known_not_affected",
        introduced="0",
        fixed="7.0.0",
        range_data={"range": "<7.0.0"},
        confidence=0.9,
        decision_state="accepted",
        provenance={"test": "status-conflict"},
    )

    first = detect_relation_conflicts(repo)
    second = detect_relation_conflicts(repo)
    quality = run_ledger_quality_gate(repo)

    assert first["qualityImpact"] == "reject"
    assert first["newlyRecordedConflictCount"] == 2  # status conflict plus range tuple conflict
    assert second["newlyRecordedConflictCount"] == 0
    assert "affectedness_status_conflict" in _conflict_kinds(repo)
    status_conflicts = [row for row in repo.fetch_all("conflict_record") if row["conflict_kind"] == "affectedness_status_conflict"]
    assert len(status_conflicts) == 1
    assert status_conflicts[0]["conflict_record_id"].startswith("conflict:affectedness_status_conflict:")
    evidence = json.loads(status_conflicts[0]["evidence_json"])
    assert evidence["involvedLedgerRefs"]
    assert {ref["ledgerTable"] for ref in evidence["involvedLedgerRefs"]} == {"affectedness_record"}
    assert quality["qualityGate"] == "rejected"
    assert quality["hardFail"] is True
    assert "AFFECTEDNESS_STATUS_CONFLICT" in _codes(quality)
    assert quality["metrics"]["openConflictCount"] >= 1
    assert quality["scoreVector"]["conflictPenalty"] > 0


def test_affectedness_range_conflict_is_soft_caveat_and_metric(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_affectedness_record(
        affectedness_id="affectedness:test:different-range",
        advisory_id="advisory:NVD_CVE:CVE-2026-0001",
        subject_kind="package_identity",
        subject_id="pkg:generic/curl",
        affectedness_status="affected",
        introduced="0",
        fixed="9.0.0",
        range_data={"range": "<9.0.0"},
        confidence=0.7,
        decision_state="accepted",
        provenance={"test": "range-conflict"},
    )

    conflict_report = detect_relation_conflicts(repo)
    quality = run_ledger_quality_gate(repo)

    assert conflict_report["qualityImpact"] == "caveat"
    assert "affectedness_range_conflict" in _conflict_kinds(repo)
    assert quality["qualityGate"] == "accepted_with_caveats"
    assert quality["hardFail"] is False
    assert "AFFECTEDNESS_RANGE_CONFLICT" in _codes(quality)
    assert quality["metrics"]["conflictKinds"] == ["affectedness_range_conflict"]
    assert quality["metrics"]["openConflictCount"] == 1


def test_opposite_relation_predicates_record_conflict_and_reject_quality(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_relation_record(
        relation_record_id="relation:test:not-affects",
        subject_id="advisory:NVD_CVE:CVE-2026-0001",
        predicate="does_not_affect_package",
        object_id="pkg:generic/curl",
        method="direct_source_relation",
        consumer_policy="contextual_only",
        provenance={"test": "predicate-conflict"},
    )

    report = detect_relation_conflicts(repo)
    quality = run_ledger_quality_gate(repo)

    assert report["qualityImpact"] == "reject"
    assert "relation_predicate_conflict" in _conflict_kinds(repo)
    assert quality["qualityGate"] == "rejected"
    assert "RELATION_PREDICATE_CONFLICT" in _codes(quality)


def test_identity_alias_exact_collision_records_conflict_and_rejects_quality(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_identity_alias(
        identity_alias_id="alias:test:curl-purl-other-package",
        subject_kind="package_identity",
        subject_namespace="purl",
        subject_id="pkg:generic/other-curl",
        alias_kind="package_identity",
        alias_namespace="purl",
        alias_id="pkg:generic/curl@8.0.0",
        relation_semantics="PACKAGE_IDENTITY",
        provenance={"test": "alias-conflict"},
    )

    report = detect_relation_conflicts(repo)
    quality = run_ledger_quality_gate(repo)

    assert report["qualityImpact"] == "reject"
    assert "identity_alias_exact_conflict" in _conflict_kinds(repo)
    assert quality["qualityGate"] == "rejected"
    assert "IDENTITY_ALIAS_EXACT_CONFLICT" in _codes(quality)


def test_projection_includes_conflict_nodes_text_and_non_negative_policy(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_relation_record(
        relation_record_id="relation:test:not-affects",
        subject_id="advisory:NVD_CVE:CVE-2026-0001",
        predicate="does_not_affect_package",
        object_id="pkg:generic/curl",
        method="direct_source_relation",
        consumer_policy="contextual_only",
        provenance={"test": "predicate-conflict"},
    )
    detect_relation_conflicts(repo)

    bundle = build_projection_bundle(repo)

    conflict_nodes = [node for node in bundle.projection_nodes if node["type"] == "conflict_record"]
    conflict_payloads = [payload for payload in bundle.qdrant_payloads if payload["recordType"] == "conflict_record"]
    assert len(conflict_nodes) == 1
    assert len(conflict_payloads) == 1
    assert conflict_nodes[0]["properties"]["consumerPolicy"] == "conflicting_evidence_not_negative_evidence"
    assert conflict_payloads[0]["metadata"]["consumerPolicy"] == "conflicting_evidence_not_negative_evidence"
    assert conflict_payloads[0]["metadata"]["negativeEvidenceAllowed"] is False


def test_conflict_quality_gate_does_not_change_health_or_ready_semantics(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_relation_record(
        relation_record_id="relation:test:not-affects",
        subject_id="advisory:NVD_CVE:CVE-2026-0001",
        predicate="does_not_affect_package",
        object_id="pkg:generic/curl",
        method="direct_source_relation",
        consumer_policy="contextual_only",
        provenance={"test": "predicate-conflict"},
    )
    quality = run_ledger_quality_gate(repo)

    assert quality["qualityGate"] == "rejected"
    health = client.get("/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    class FakeGraph:
        node_count = 100
        edge_count = 200

    class FakeAssembler:
        pass

    old_assembler = api._assembler
    old_graph = api._neo4j_graph
    old_qdrant = api._qdrant_ready
    try:
        api.set_assembler(FakeAssembler())
        api.set_neo4j_graph(FakeGraph())
        api.set_qdrant_ready(True)
        ready = client.get("/v1/ready")
        assert ready.status_code == 200
        assert ready.json()["ready"] is True
    finally:
        api.set_assembler(old_assembler)
        api.set_neo4j_graph(old_graph)
        api.set_qdrant_ready(old_qdrant)
