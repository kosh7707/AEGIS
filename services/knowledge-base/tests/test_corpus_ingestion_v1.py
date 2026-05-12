from __future__ import annotations

import json
from pathlib import Path

from app.ingestion import corpus_ingestion
from app.ingestion.corpus_ingestion import (
    DEFAULT_SOURCE_MANIFEST_PATH,
    MANIFEST_ONLY_SOURCE_KINDS,
    REQUIRED_COMPLETED_SOURCE_KINDS,
    REQUIRED_SOURCE_KINDS,
    ingest_fixture_corpus,
    load_source_manifest,
    manifest_coverage_summary,
    validate_source_manifest,
)
from app.ledger.repository import SQLiteLedgerRepository

EXPECTED_FULL_COUNTS = {
    "knowledge_source": 18,
    "raw_artifact": 18,
    "normalized_record": 18,
    "weakness": 1,
    "attack_pattern": 3,
    "tool_rule": 6,
    "package_identity": 1,
    "vulnerability_advisory": 3,
    "affected_range": 3,
    "relation_record": 20,
    "provider_observation": 5,
}


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    return repo


def _loads(row, field):
    return json.loads(row[field])


def test_source_manifest_schema_hashes_and_required_source_families_are_valid():
    manifest = load_source_manifest()

    assert validate_source_manifest(manifest) == []
    source_kinds = {source["sourceKind"] for source in manifest["sources"]}
    assert REQUIRED_SOURCE_KINDS <= source_kinds
    assert REQUIRED_COMPLETED_SOURCE_KINDS <= set(manifest["summary"]["completedCoverageSourceKinds"])

    base = DEFAULT_SOURCE_MANIFEST_PATH.parent
    for source in manifest["sources"]:
        for artifact in source["rawArtifacts"]:
            fixture = base / artifact["fixturePath"]
            assert fixture.exists(), artifact
            assert artifact["contentHash"] == corpus_ingestion._hash_file(fixture)
            assert artifact["transformVersion"] == "corpus-ingestion-v1"


def test_completed_fixture_coverage_now_includes_capec_and_attack_samples():
    manifest = load_source_manifest()
    summary = manifest_coverage_summary(manifest)

    assert summary["sourceCount"] == 18
    assert summary["completedSourceCount"] == 18
    assert summary["nonCompletedSourceCount"] == 0
    assert summary["nonCompletedSourceKinds"] == []
    assert MANIFEST_ONLY_SOURCE_KINDS == set()
    assert {"CAPEC", "ATTACK_ICS", "ATTACK_ENTERPRISE"} <= set(summary["completedCoverageSourceKinds"])
    for source in manifest["sources"]:
        if source["sourceKind"] in {"CAPEC", "ATTACK_ICS", "ATTACK_ENTERPRISE"}:
            assert source["completedCoverage"] is True
            assert source["coverageStatus"] == "completed_fixture"
            assert source["rawArtifacts"]
            assert source["providerState"]["scope"] == "sample_fixture_not_production_scale"


def test_ingest_fixture_corpus_writes_expected_ledger_rows(tmp_path):
    repo = _repo(tmp_path)

    report = ingest_fixture_corpus(repo)

    assert report["schemaVersion"] == "s5-corpus-ingestion-report-v1"
    assert report["coverage"]["completedSourceCount"] == 18
    assert report["rowCounts"] == EXPECTED_FULL_COUNTS
    assert repo.count_rows("transform_decision") == 38


def test_ingest_fixture_corpus_persists_transform_decisions_for_records_and_relations(tmp_path):
    repo = _repo(tmp_path)
    ingest_fixture_corpus(repo)

    decisions = repo.fetch_all("transform_decision")
    normalized = next(row for row in decisions if row["transform_decision_id"] == "transform:norm:CWE:CWE-78")
    normalized_decision = _loads(normalized, "decision_json")
    assert normalized["method"] == "exact_id_match"
    assert normalized_decision["sourceRefs"][0]["rawArtifactId"] == "raw-cwe-fixture"
    assert normalized_decision["consumerPolicy"] == "contextual_only"

    relation = next(row for row in decisions if row["transform_decision_id"].startswith("transform:relation:advisory:OSV:"))
    relation_decision = _loads(relation, "decision_json")
    assert relation["method"] == "direct_source_relation"
    assert relation_decision["relation"]["predicate"] == "affects_package"
    assert relation_decision["relationSource"] == "direct_source"
    assert _loads(relation, "diagnostics_json")[0]["code"] == "RELATION_SIGNAL_DECISION_RECORDED"


def test_ingested_records_preserve_provenance_freshness_and_diagnostics(tmp_path):
    repo = _repo(tmp_path)
    ingest_fixture_corpus(repo)

    advisories = repo.fetch_all("vulnerability_advisory")
    assert {row["source_kind"] for row in advisories} == {"OSV", "NVD_CVE", "GHSA"}
    for row in advisories:
        payload = _loads(row, "payload_json")
        assert payload["provenance"]["rawArtifactId"].startswith("raw-")
        assert payload["freshness"]["status"] == "fixture_current"
        assert payload["transformDiagnostics"]
        assert payload["packageIdentityId"] == "pkg:generic/curl"

    ranges = repo.fetch_all("affected_range")
    assert len(ranges) == 3
    assert {row["package_identity_id"] for row in ranges} == {"pkg:generic/curl"}
    assert all(row["fixed"] == "8.1.0" for row in ranges)


def test_attack_pattern_rows_are_normalized_from_capec_and_attack_fixtures(tmp_path):
    repo = _repo(tmp_path)
    ingest_fixture_corpus(repo)

    attack_patterns = repo.fetch_all("attack_pattern")
    assert {row["external_id"] for row in attack_patterns} == {"CAPEC-88", "T0807", "T1059"}
    assert {row["source_kind"] for row in attack_patterns} == {"CAPEC", "ATTACK_ICS", "ATTACK_ENTERPRISE"}
    relations = repo.fetch_all("relation_record")
    command_relations = [row for row in relations if row["subject_id"] in {"CAPEC-88", "T0807", "T1059"}]
    assert len(command_relations) == 9
    assert {row["predicate"] for row in command_relations} == {"maps_to_weakness", "related_attack_pattern", "related_capec"}


def test_tool_rule_package_and_weakness_rows_are_normalized(tmp_path):
    repo = _repo(tmp_path)
    ingest_fixture_corpus(repo)

    weakness = repo.fetch_all("weakness")
    assert weakness[0]["external_id"] == "CWE-78"
    assert weakness[0]["taxonomy_family"] == "command_execution"

    rules = repo.fetch_all("tool_rule")
    assert len(rules) == 6
    assert {row["tool_name"] for row in rules} == {
        "semgrep",
        "cppcheck",
        "clang-tidy",
        "gcc-fanalyzer",
        "scan-build",
        "flawfinder",
    }

    package = repo.fetch_all("package_identity")[0]
    assert package["package_identity_id"] == "pkg:generic/curl"
    assert package["purl"] == "pkg:generic/curl@8.0.0"
    assert "curl/curl" in _loads(package, "aliases_json")


def test_kev_and_epss_are_enrichment_only_not_advisory_truth(tmp_path):
    repo = _repo(tmp_path)

    report = ingest_fixture_corpus(repo, source_kinds={"CISA_KEV", "FIRST_EPSS"})

    assert report["rowCounts"]["knowledge_source"] == 2
    assert report["rowCounts"]["raw_artifact"] == 2
    assert report["rowCounts"]["normalized_record"] == 2
    assert report["rowCounts"]["vulnerability_advisory"] == 0
    assert report["rowCounts"]["affected_range"] == 0
    assert report["rowCounts"]["relation_record"] == 2
    assert report["rowCounts"]["provider_observation"] == 2
    predicates = {row["predicate"] for row in repo.fetch_all("relation_record")}
    assert predicates == {"enriches_advisory", "risk_signal_for"}
    assert {row["consumer_policy"] for row in repo.fetch_all("relation_record")} == {"contextual_only"}


def test_double_ingest_is_idempotent_for_g005_tables(tmp_path):
    repo = _repo(tmp_path)

    first = ingest_fixture_corpus(repo)["rowCounts"]
    second = ingest_fixture_corpus(repo)["rowCounts"]

    assert first == EXPECTED_FULL_COUNTS
    assert second == EXPECTED_FULL_COUNTS


def test_manifest_validation_rejects_missing_fields_and_hash_mismatch(tmp_path):
    manifest = load_source_manifest()
    manifest["sources"][0].pop("sourceUrl")
    manifest["sources"][1]["rawArtifacts"][0]["contentHash"] = "sha256:bad"
    bad_path = tmp_path / "source-manifest.json"
    bad_path.write_text(json.dumps(manifest), encoding="utf-8")

    issues = validate_source_manifest(manifest, DEFAULT_SOURCE_MANIFEST_PATH)

    assert any("missing source fields" in issue for issue in issues)
    assert any("contentHash mismatch" in issue for issue in issues)


def test_ingestion_harness_does_not_import_or_invoke_projection_stores():
    source = Path(corpus_ingestion.__file__).read_text(encoding="utf-8")

    assert "qdrant_client" not in source
    assert "neo4j.GraphDatabase" not in source
    assert "app.graphrag" not in source
