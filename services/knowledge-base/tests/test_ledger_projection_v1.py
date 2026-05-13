from __future__ import annotations

import copy
from pathlib import Path

from app.contracts.acquisition import apply_no_hit_safety
from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.ledger.repository import SQLiteLedgerRepository
from app.projections.ledger_projection import (
    NEO4J_THREAT_PROJECTION,
    PROJECTION_VERSION,
    QDRANT_THREAT_PROJECTION,
    SCOPE_KEY,
    LedgerProjectionRebuilder,
    build_projection_bundle,
    validate_projection_bundle,
    write_projection_bundle,
)


class FakeNeo4jAdapter:
    def __init__(self, *, fail: bool = False) -> None:
        self.records = None
        self.fail = fail

    def load_from_records(self, records):
        if self.fail:
            raise RuntimeError("neo4j boom")
        self.records = copy.deepcopy(records)


class FakeQdrantAdapter:
    def __init__(self, *, fail: bool = False) -> None:
        self.payloads = None
        self.fail = fail

    def load_payloads(self, payloads):
        if self.fail:
            raise RuntimeError("qdrant boom")
        self.payloads = copy.deepcopy(payloads)


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo)
    return repo


def test_projection_bundle_is_derived_from_ledger_rows_with_source_hash(tmp_path):
    repo = _repo(tmp_path)

    bundle = build_projection_bundle(repo)

    assert bundle.projection_version == PROJECTION_VERSION
    assert bundle.source_hash.startswith("sha256:")
    assert len(bundle.neo4j_records) == 7  # 1 CWE + 3 advisory/CVE-context + 3 CAPEC/ATT&CK attack records
    assert len(bundle.qdrant_payloads) == 43
    assert len(bundle.projection_nodes) == 22
    assert len(bundle.projection_edges) == 40
    assert {record["ledger_id"] for record in bundle.neo4j_records} >= {"CWE-78", "advisory:OSV:OSV-2026-CURL-0001"}
    assert all(record["projection_source_hash"] == bundle.source_hash for record in bundle.neo4j_records)
    assert all(payload["sourceHash"] == bundle.source_hash for payload in bundle.qdrant_payloads)
    assert all(payload["projectionVersion"] == PROJECTION_VERSION for payload in bundle.qdrant_payloads)
    assert bundle.manifest["schemaVersion"] == "s5-projection-bundle-manifest-v1"
    assert bundle.manifest["productionWriteEnabled"] is False
    assert bundle.manifest["counts"] == {
        "nodes": 22,
        "edges": 40,
        "textChunks": 43,
        "neo4jCompatibilityRecords": 7,
    }
    assert bundle.manifest["coverageProfilesBySourceKind"]["CWE"] == ["fixture_slice"]
    assert {payload["corpusPartition"] for payload in bundle.qdrant_payloads} >= {
        "weakness_taxonomy",
        "public_vulnerability_knowledge",
        "attack_pattern",
        "tool_rule_mapping",
        "package_identity",
        "product_identity",
        "source_component_identity",
        "affectedness",
        "risk_signal",
        "relation_provenance",
    }
    qa = validate_projection_bundle(bundle)
    assert qa["qualityGate"] == "accepted"


def test_projection_source_hash_is_stable_across_idempotent_ingest(tmp_path):
    repo = _repo(tmp_path)
    first = build_projection_bundle(repo)

    ingest_fixture_corpus(repo)
    second = build_projection_bundle(repo)

    assert first.source_hash == second.source_hash
    assert first.neo4j_records == second.neo4j_records
    assert first.qdrant_payloads == second.qdrant_payloads
    assert first.manifest == second.manifest


def test_projection_bundle_writer_emits_dry_run_files_without_production_write(tmp_path):
    repo = _repo(tmp_path)
    out_dir = tmp_path / "bundle"

    report = write_projection_bundle(repo, out_dir)

    assert report["schemaVersion"] == "s5-projection-bundle-write-report-v1"
    assert report["productionWriteEnabled"] is False
    assert report["qaReport"]["qualityGate"] == "accepted"
    assert (out_dir / "manifest.json").exists()
    assert (out_dir / "nodes.jsonl").read_text(encoding="utf-8").count("\n") == 22
    assert (out_dir / "edges.jsonl").read_text(encoding="utf-8").count("\n") == 40
    assert (out_dir / "text_chunks.jsonl").read_text(encoding="utf-8").count("\n") == 43
    stored = repo.fetch_all("projection_bundle_manifest")
    assert len(stored) == 1
    assert stored[0]["production_write_enabled"] == 0


def test_rebuilder_sends_only_ledger_derived_data_to_projection_adapters(tmp_path):
    repo = _repo(tmp_path)
    neo4j = FakeNeo4jAdapter()
    qdrant = FakeQdrantAdapter()

    report = LedgerProjectionRebuilder(repo, neo4j_adapter=neo4j, qdrant_adapter=qdrant).rebuild()

    assert report["projectionStates"] == {NEO4J_THREAT_PROJECTION: "ready", QDRANT_THREAT_PROJECTION: "ready"}
    assert neo4j.records is not None and qdrant.payloads is not None
    assert all("ledger_id" in record and "projection_source_hash" in record for record in neo4j.records)
    assert all("ledgerId" in payload and "sourceHash" in payload for payload in qdrant.payloads)
    assert {job["state"] for job in repo.list_projection_jobs()} == {"completed"}
    assert repo.get_projection_state(NEO4J_THREAT_PROJECTION, SCOPE_KEY)["state"] == "ready"
    assert repo.get_projection_state(QDRANT_THREAT_PROJECTION, SCOPE_KEY)["state"] == "ready"


def test_missing_projection_adapters_record_explicit_debt(tmp_path):
    repo = _repo(tmp_path)

    report = LedgerProjectionRebuilder(repo).rebuild()

    assert report["projectionStates"] == {NEO4J_THREAT_PROJECTION: "debt", QDRANT_THREAT_PROJECTION: "debt"}
    states = {
        name: repo.get_projection_state(name, SCOPE_KEY)
        for name in (NEO4J_THREAT_PROJECTION, QDRANT_THREAT_PROJECTION)
    }
    assert states[NEO4J_THREAT_PROJECTION]["debt"]["diagnostics"][0]["code"] == "NEO4J_PROJECTION_ADAPTER_MISSING"
    assert states[QDRANT_THREAT_PROJECTION]["debt"]["diagnostics"][0]["code"] == "QDRANT_PROJECTION_ADAPTER_MISSING"
    assert {job["state"] for job in repo.list_projection_jobs()} == {"debt"}


def test_projection_adapter_failure_records_failed_state_and_diagnostics(tmp_path):
    repo = _repo(tmp_path)
    neo4j = FakeNeo4jAdapter(fail=True)
    qdrant = FakeQdrantAdapter()

    report = LedgerProjectionRebuilder(repo, neo4j_adapter=neo4j, qdrant_adapter=qdrant).rebuild()

    assert report["projectionStates"][NEO4J_THREAT_PROJECTION] == "failed"
    assert report["projectionStates"][QDRANT_THREAT_PROJECTION] == "ready"
    failed = repo.get_projection_state(NEO4J_THREAT_PROJECTION, SCOPE_KEY)
    assert failed["state"] == "failed"
    assert failed["debt"]["diagnostics"][0]["code"] == "PROJECTION_ADAPTER_FAILED"
    assert "neo4j boom" in failed["debt"]["diagnostics"][0]["message"]


def test_projection_debt_downgrades_projection_dependent_completed_no_hit():
    unsafe_no_hit = {
        "acquisitionStatus": "completed_no_hit",
        "acquisitionQualityGate": "accepted",
        "consumerPolicy": "scoped_no_hit_record_only",
        "scope": {
            "query": "popen",
            "methodsRequiredForNoHit": ["id_exact", "graph_neighbor", "vector_semantic"],
            "noHitBasis": "completed_required_methods",
            "projectionState": {"state": "debt", "surface": "semanticThreatRetrieval"},
        },
        "methodsAttempted": ["id_exact", "graph_neighbor", "vector_semantic"],
        "methodsSucceeded": ["id_exact", "graph_neighbor", "vector_semantic"],
        "providerState": {"state": "not_applicable"},
        "projectionState": {"state": "debt", "surface": "semanticThreatRetrieval"},
        "diagnostics": [],
    }

    downgraded = apply_no_hit_safety(unsafe_no_hit)

    assert downgraded["acquisitionStatus"] == "incomplete_acquisition"
    assert downgraded["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert any(
        reason == "NO_HIT_PROJECTION_STATE_UNSAFE:debt"
        for reason in downgraded["diagnostics"][-1]["reasons"]
    )


def test_neo4j_seed_default_path_is_ledger_not_qdrant_scroll():
    source = Path("scripts/neo4j-seed.py").read_text(encoding="utf-8")

    assert "--ledger-url" in source
    assert "build_projection_bundle" in source
    assert "scroll_all_metadata" not in source
    assert "ThreatSearch" not in source
