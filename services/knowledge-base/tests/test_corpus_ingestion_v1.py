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
    "source_artifact": 18,
    "raw_artifact": 18,
    "normalized_record": 18,
    "identity_alias": 10,
    "weakness": 1,
    "attack_pattern": 3,
    "tool_rule": 6,
    "package_identity": 1,
    "product_identity": 1,
    "source_component_identity": 1,
    "vulnerability_advisory": 3,
    "affected_range": 3,
    "affectedness_record": 3,
    "risk_signal": 3,
    "relation_record": 21,
    "unresolved_reference": 0,
    "conflict_record": 0,
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
    assert summary["coverageProfiles"] == ["fixture_slice"]
    assert "CWE" in summary["fixtureSliceSourceKinds"]
    assert summary["productionSnapshotSourceKinds"] == []
    assert MANIFEST_ONLY_SOURCE_KINDS == set()
    assert {"CAPEC", "ATTACK_ICS", "ATTACK_ENTERPRISE"} <= set(summary["completedCoverageSourceKinds"])
    for source in manifest["sources"]:
        if source["sourceKind"] in {"CAPEC", "ATTACK_ICS", "ATTACK_ENTERPRISE"}:
            assert source["completedCoverage"] is True
            assert source["coverageStatus"] == "completed_fixture"
            assert source["coverageProfile"] == "fixture_slice"
            assert source["rawArtifacts"]
            assert source["providerState"]["scope"] == "sample_fixture_not_production_scale"


def test_ingest_fixture_corpus_writes_expected_ledger_rows(tmp_path):
    repo = _repo(tmp_path)

    report = ingest_fixture_corpus(repo)

    assert report["schemaVersion"] == "s5-corpus-ingestion-report-v1"
    assert report["coverage"]["completedSourceCount"] == 18
    assert report["rowCounts"] == EXPECTED_FULL_COUNTS
    assert repo.count_rows("transform_decision") == 39


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


def test_ingestion_records_source_artifacts_and_identity_classes_without_cpe_purl_collapse(tmp_path):
    repo = _repo(tmp_path)
    ingest_fixture_corpus(repo)

    artifacts = repo.fetch_all("source_artifact")
    assert len(artifacts) == 18
    assert {row["source_family"] for row in artifacts} >= {
        "vulnerability_advisory_fact",
        "product_package_identity",
        "risk_exploitation_signal",
        "weakness_taxonomy",
        "attack_pattern_ontology",
    }
    assert all(row["checksum_sha256"].startswith("sha256:") for row in artifacts)

    package = repo.fetch_all("package_identity")[0]
    product = repo.fetch_all("product_identity")[0]
    source_component = repo.fetch_all("source_component_identity")[0]
    assert package["package_identity_id"] == "pkg:generic/curl"
    assert product["cpe"] == "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"
    assert source_component["repo_url"] == "https://github.com/curl/curl"

    aliases = repo.fetch_all("identity_alias")
    assert any(row["relation_semantics"] == "RELATED_PRODUCT_IDENTITY" for row in aliases)
    assert not any(
        row["relation_semantics"] == "SAME_AS_EXACT"
        and {row["subject_namespace"], row["alias_namespace"]} == {"purl", "cpe"}
        for row in aliases
    )


def test_affectedness_and_risk_signal_records_are_first_class(tmp_path):
    repo = _repo(tmp_path)
    ingest_fixture_corpus(repo)

    affectedness = repo.fetch_all("affectedness_record")
    assert len(affectedness) == 3
    assert {row["subject_kind"] for row in affectedness} == {"package_identity"}
    assert {row["subject_id"] for row in affectedness} == {"pkg:generic/curl"}
    assert all(row["affectedness_status"] == "affected" for row in affectedness)
    assert all(row["fixed"] == "8.1.0" for row in affectedness)

    signals = repo.fetch_all("risk_signal")
    assert {row["signal_kind"] for row in signals} == {"CVSS", "KEV", "EPSS"}
    assert all(row["signal_date"] for row in signals)


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
    assert report["rowCounts"]["affectedness_record"] == 0
    assert report["rowCounts"]["risk_signal"] == 2
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


def test_manifest_validation_rejects_single_cwe_fixture_claiming_production_snapshot():
    manifest = load_source_manifest()
    cwe_source = next(source for source in manifest["sources"] if source["sourceKind"] == "CWE")
    cwe_source["coverageProfile"] = "production_snapshot"
    cwe_source["coverageStatus"] = "completed_snapshot"
    cwe_source["expectedCoverage"] = {
        "productionComplete": True,
        "minimumWeaknessCount": 5,
        "requiredWeaknessIds": ["CWE-78", "CWE-190", "CWE-134", "CWE-415", "CWE-416"],
    }
    manifest["summary"] = manifest_coverage_summary(manifest)

    issues = validate_source_manifest(manifest, DEFAULT_SOURCE_MANIFEST_PATH)

    assert any("catalog/production/full CWE weakness count 1 below minimum 5" in issue for issue in issues)
    assert any("catalog/production/full missing required CWE ids" in issue for issue in issues)


def test_manifest_validation_rejects_single_cwe_fixture_claiming_cached_catalog_snapshot():
    manifest = load_source_manifest()
    cwe_source = next(source for source in manifest["sources"] if source["sourceKind"] == "CWE")
    cwe_source["coverageProfile"] = "cached_catalog_snapshot"
    cwe_source["coverageStatus"] = "completed_snapshot"
    cwe_source["expectedCoverage"] = {
        "productionComplete": False,
        "minimumWeaknessCount": 5,
        "requiredWeaknessIds": ["CWE-78", "CWE-190"],
    }
    manifest["summary"] = manifest_coverage_summary(manifest)

    issues = validate_source_manifest(manifest, DEFAULT_SOURCE_MANIFEST_PATH)

    assert any("catalog/production/full CWE weakness count 1 below minimum 5" in issue for issue in issues)
    assert any("catalog/production/full missing required CWE ids" in issue for issue in issues)


def test_manifest_validation_rejects_cached_cwe_catalog_missing_declared_expected_coverage(tmp_path):
    base = tmp_path / "manifest"
    raw_dir = base / "raw"
    raw_dir.mkdir(parents=True)
    catalog = {
        "id": "CWE-CACHED-CATALOG-UNDERCOVERED",
        "weaknesses": [
            {"id": "CWE-78", "name": "OS Command Injection"},
            {"id": "CWE-190", "name": "Integer Overflow or Wraparound"},
        ],
    }
    catalog_path = raw_dir / "cwe_cached_catalog.json"
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    manifest = load_source_manifest()
    cwe_source = next(source for source in manifest["sources"] if source["sourceKind"] == "CWE")
    cwe_source["coverageProfile"] = "cached_catalog_snapshot"
    cwe_source["coverageStatus"] = "completed_snapshot"
    cwe_source["sourceId"] = "source-cwe-undercovered-catalog"
    cwe_source["expectedCoverage"] = {
        "productionComplete": False,
        "minimumWeaknessCount": 3,
        "requiredWeaknessIds": ["CWE-78", "CWE-190", "CWE-416"],
    }
    cwe_source["rawArtifacts"] = [
        {
            "artifactKind": "weakness_catalog",
            "contentHash": corpus_ingestion._hash_file(catalog_path),
            "fixturePath": "raw/cwe_cached_catalog.json",
            "rawArtifactId": "raw-cwe-undercovered-catalog",
            "retrievedAt": "2026-05-12T00:00:00Z",
            "transformVersion": "corpus-ingestion-v1",
            "uri": "file://cwe_cached_catalog.json",
        }
    ]
    manifest["summary"] = manifest_coverage_summary(manifest)
    manifest_path = base / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    issues = validate_source_manifest(manifest, manifest_path)

    assert any("catalog/production/full CWE weakness count 2 below minimum 3" in issue for issue in issues)
    assert any("catalog/production/full missing required CWE ids: ['CWE-416']" in issue for issue in issues)


def test_ingestion_harness_does_not_import_or_invoke_projection_stores():
    source = Path(corpus_ingestion.__file__).read_text(encoding="utf-8")

    assert "qdrant_client" not in source
    assert "neo4j.GraphDatabase" not in source
    assert "app.graphrag" not in source
