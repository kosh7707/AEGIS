from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.judge.models import JudgeQueryRequest
from app.judge.service import build_judge_answer, validate_judge_answer
from app.ledger.repository import SQLiteLedgerRepository
from app.projections.ledger_projection import build_projection_bundle
from app.quality import run_ledger_quality_gate
from app.relations import detect_relation_conflicts
from app.routers import api, judge_api, source_kg_api
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


def test_judge_surfaces_relevant_open_conflicts_in_uncertainty_and_quality_gate(tmp_path):
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

    answer = build_judge_answer(
        repo,
        JudgeQueryRequest(
            question="Is curl 8.0.0 affected?",
            component={"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            sourceContext={"graphNodeIds": ["srcctx-curl-call-system"]},
        ),
    )

    assert repo.count_rows("conflict_record") >= 1
    assert answer["verdict"] == "affected"
    assert answer["qualityGate"]["gate"] == "rejected"
    assert answer["qualityGate"]["hardFail"] is True
    assert answer["scoreVector"]["conflictPenalty"] > 0
    conflicts = answer["uncertainty"]["conflicts"]
    status_conflicts = [item for item in conflicts if item["conflictKind"] == "affectedness_status_conflict"]
    assert len(status_conflicts) == 1
    status_conflict = status_conflicts[0]
    assert status_conflict["issueCode"] == "AFFECTEDNESS_STATUS_CONFLICT"
    assert status_conflict["severity"] == "hard"
    assert status_conflict["status"] == "open"
    assert status_conflict["subjectId"] == "advisory:NVD_CVE:CVE-2026-0001:package_identity:pkg:generic/curl"
    assert status_conflict["consumerPolicy"] == "conflicting_evidence_not_negative_evidence"
    assert "negative_evidence" in status_conflict["forbiddenEffects"]
    assert {ref["ledgerTable"] for ref in status_conflict["involvedLedgerRefs"]} == {"affectedness_record"}
    assert {
        item["value"]["affectednessStatus"]
        for item in status_conflict["conflictingValues"]
        if item["ledgerTable"] == "affectedness_record"
    } == {"affected", "known_not_affected"}
    assert all("provenance" in item for item in status_conflict["conflictingValues"])
    assert any(
        item["code"] == "AFFECTEDNESS_STATUS_CONFLICT"
        and item["conflictRecordId"] == status_conflict["conflictRecordId"]
        for item in answer["qualityGate"]["diagnostics"]
    )
    assert validate_judge_answer(answer) == []

    silent_conflict = json.loads(json.dumps(answer))
    silent_conflict["qualityGate"]["diagnostics"] = [
        item
        for item in silent_conflict["qualityGate"]["diagnostics"]
        if item.get("conflictRecordId") != status_conflict["conflictRecordId"]
    ]
    assert any(issue["code"] == "CONFLICT_DIAGNOSTIC_SILENT" for issue in validate_judge_answer(silent_conflict))

    negative_conflict = json.loads(json.dumps(answer))
    negative_conflict["uncertainty"]["conflicts"][0]["negativeEvidenceAllowed"] = True
    assert any(issue["code"] == "CONFLICT_USED_AS_NEGATIVE_EVIDENCE" for issue in validate_judge_answer(negative_conflict))

    hidden_values = json.loads(json.dumps(answer))
    hidden_values["uncertainty"]["conflicts"][0]["conflictingValues"] = []
    assert any(issue["code"] == "CONFLICT_VALUES_MISSING" for issue in validate_judge_answer(hidden_values))


def test_judge_conflict_summary_caps_conflicting_values_and_validates_metadata(tmp_path):
    repo = _repo(tmp_path)
    for index in range(9):
        repo.upsert_affectedness_record(
            affectedness_id=f"affectedness:test:not-affected:{index}",
            advisory_id="advisory:NVD_CVE:CVE-2026-0001",
            subject_kind="package_identity",
            subject_id="pkg:generic/curl",
            affectedness_status="known_not_affected",
            introduced="0",
            fixed=f"7.{index}.0",
            range_data={"range": f"<7.{index}.0"},
            confidence=0.8,
            decision_state="accepted",
            provenance={"test": "status-conflict-cap", "index": index},
        )

    answer = build_judge_answer(
        repo,
        JudgeQueryRequest(
            question="Is curl 8.0.0 affected?",
            component={"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            sourceContext={"graphNodeIds": ["srcctx-curl-call-system"]},
        ),
    )

    status_conflict = next(
        item
        for item in answer["uncertainty"]["conflicts"]
        if item["conflictKind"] == "affectedness_status_conflict"
    )
    assert status_conflict["conflictingValueCount"] == 10
    assert len(status_conflict["conflictingValues"]) == 8
    assert status_conflict["conflictingValuesTruncated"] is True
    assert validate_judge_answer(answer) == []

    over_limit = json.loads(json.dumps(answer))
    over_limit["uncertainty"]["conflicts"][0]["conflictingValues"].append(
        {"ledgerTable": "affectedness_record", "ledgerId": "too-many", "value": {}, "provenance": {}}
    )
    assert any(issue["code"] == "CONFLICT_VALUES_OVER_LIMIT" for issue in validate_judge_answer(over_limit))

    missing_truncation = json.loads(json.dumps(answer))
    missing_truncation["uncertainty"]["conflicts"][0]["conflictingValuesTruncated"] = False
    assert any(issue["code"] == "CONFLICT_VALUES_TRUNCATION_INVALID" for issue in validate_judge_answer(missing_truncation))


def test_judge_does_not_surface_same_advisory_conflict_for_different_package_prefix(tmp_path):
    repo = _repo(tmp_path)
    for affectedness_id, status, fixed in (
        ("affectedness:test:extra-affected", "affected", "9.0.0"),
        ("affectedness:test:extra-not-affected", "known_not_affected", "7.0.0"),
    ):
        repo.upsert_affectedness_record(
            affectedness_id=affectedness_id,
            advisory_id="advisory:NVD_CVE:CVE-2026-0001",
            subject_kind="package_identity",
            subject_id="pkg:generic/curl-extra",
            affectedness_status=status,
            introduced="0",
            fixed=fixed,
            range_data={"range": f"<{fixed}"},
            confidence=0.9,
            decision_state="accepted",
            provenance={"test": "same-advisory-different-package"},
        )

    answer = build_judge_answer(
        repo,
        JudgeQueryRequest(
            question="Is curl 8.0.0 affected?",
            component={"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
            sourceContext={"graphNodeIds": ["srcctx-curl-call-system"]},
        ),
    )

    assert repo.count_rows("conflict_record") >= 1
    assert answer["verdict"] == "affected"
    assert answer["uncertainty"]["conflicts"] == []
    assert answer["qualityGate"]["gate"] != "rejected"
    assert not any(item.get("conflictRecordId") for item in answer["qualityGate"]["diagnostics"])
    assert validate_judge_answer(answer) == []


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
    old_source_kg_repo = source_kg_api._ledger_repository
    old_judge_repo = judge_api._ledger_repository
    try:
        api.set_assembler(FakeAssembler())
        api.set_neo4j_graph(FakeGraph())
        api.set_qdrant_ready(True)
        source_kg_api.set_ledger_repository(repo)
        judge_api.set_ledger_repository(repo)
        ready = client.get("/v1/ready")
        assert ready.status_code == 200
        assert ready.json()["ready"] is True
    finally:
        api.set_assembler(old_assembler)
        api.set_neo4j_graph(old_graph)
        api.set_qdrant_ready(old_qdrant)
        source_kg_api.set_ledger_repository(old_source_kg_repo)
        judge_api.set_ledger_repository(old_judge_repo)
