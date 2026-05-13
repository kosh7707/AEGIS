from __future__ import annotations

import json
import shutil

from app.affectedness import query_affectedness
from app.ingestion.corpus_ingestion import DEFAULT_SOURCE_MANIFEST_PATH, _hash_file, ingest_fixture_corpus, load_source_manifest, manifest_coverage_summary, validate_source_manifest
from app.ledger.repository import SQLiteLedgerRepository
from app.quality import run_ledger_quality_gate


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo)
    return repo


def _write_cwe_catalog_manifest(tmp_path):
    source_root = DEFAULT_SOURCE_MANIFEST_PATH.parent
    target_root = tmp_path / "manifest"
    shutil.copytree(source_root, target_root)
    cwe_catalog = {
        "id": "CWE-CACHED-CATALOG-TEST",
        "taxonomyFamily": "native_code_core",
        "weaknesses": [
            {"id": "CWE-78", "name": "OS Command Injection", "taxonomyFamily": "command_execution", "relatedWeaknesses": ["CWE-77"]},
            {"id": "CWE-77", "name": "Command Injection", "taxonomyFamily": "command_execution"},
            {"id": "CWE-190", "name": "Integer Overflow or Wraparound", "taxonomyFamily": "numeric_errors", "parents": ["CWE-682"]},
            {"id": "CWE-134", "name": "Use of Externally-Controlled Format String", "taxonomyFamily": "format_string"},
            {"id": "CWE-415", "name": "Double Free", "taxonomyFamily": "memory_safety", "relatedWeaknesses": ["CWE-416"]},
            {"id": "CWE-416", "name": "Use After Free", "taxonomyFamily": "memory_safety", "relatedWeaknesses": ["CWE-415"]},
            {"id": "CWE-682", "name": "Incorrect Calculation", "taxonomyFamily": "numeric_errors"},
        ],
    }
    catalog_path = target_root / "raw" / "cwe_cached_catalog.json"
    catalog_path.write_text(json.dumps(cwe_catalog, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    manifest_path = target_root / "source-manifest.json"
    manifest = load_source_manifest(manifest_path)
    cwe_source = next(source for source in manifest["sources"] if source["sourceKind"] == "CWE")
    cwe_source["coverageProfile"] = "cached_catalog_snapshot"
    cwe_source["coverageStatus"] = "completed_snapshot"
    cwe_source["sourceId"] = "source-cwe-cached-catalog"
    cwe_source["sourceVersion"] = "4.15-cached-catalog-test"
    cwe_source["expectedCoverage"] = {
        "productionComplete": False,
        "minimumWeaknessCount": 5,
        "requiredWeaknessIds": ["CWE-78", "CWE-190", "CWE-134", "CWE-415", "CWE-416"],
    }
    cwe_source["rawArtifacts"] = [
        {
            "artifactKind": "weakness_catalog",
            "contentHash": _hash_file(catalog_path),
            "fixturePath": "raw/cwe_cached_catalog.json",
            "rawArtifactId": "raw-cwe-cached-catalog",
            "retrievedAt": "2026-05-12T00:00:00Z",
            "transformVersion": "corpus-ingestion-v1",
            "uri": "file://cwe_cached_catalog.json",
        }
    ]
    manifest["summary"] = manifest_coverage_summary(manifest)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def test_ledger_quality_gate_accepts_full_fixture_with_logged_unresolved_cwe_coverage_debt(tmp_path):
    repo = _repo(tmp_path)

    report = run_ledger_quality_gate(repo)

    assert report["schemaVersion"] == "s5-ledger-quality-report-v1"
    assert report["qualityGate"] == "accepted_with_caveats"
    assert report["hardFail"] is False
    assert report["scorePolicy"]["schemaVersion"] == "s5-score-policy-evaluation-v1"
    assert report["scorePolicy"]["phase"] == "etl_projection"
    assert report["scorePolicy"]["appliedProfile"] == "balanced"
    assert report["scorePolicy"]["policyHash"].startswith("sha256:")
    assert "overallAnswerability" in report["scoreVector"]
    assert report["metrics"]["sourceArtifactCount"] == 18
    assert report["metrics"]["affectednessRecordCount"] == 3
    assert report["metrics"]["riskSignalCount"] == 3
    assert report["metrics"]["newlyLoggedUnresolvedReferences"] == 5
    assert repo.count_rows("unresolved_reference") == 5
    assert repo.count_rows("conflict_record") == 0


def test_ledger_quality_gate_logs_unresolved_relation_endpoint_instead_of_silent_fallback(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_relation_record(
        relation_record_id="relation:broken:object",
        subject_id="advisory:NVD_CVE:CVE-2026-0001",
        predicate="related_to",
        object_id="CVE:CVE-DOES-NOT-EXIST",
        method="direct_source_relation",
        consumer_policy="contextual_only",
        provenance={"sourceRefs": [{"rawArtifactId": "raw-nvd-cve-fixture"}]},
    )

    report = run_ledger_quality_gate(repo)

    assert report["qualityGate"] == "accepted_with_caveats"
    assert report["hardFail"] is False
    assert report["metrics"]["newlyLoggedUnresolvedReferences"] == 6
    unresolved = repo.fetch_all("unresolved_reference")
    assert any(
        row["relation_record_id"] == "relation:broken:object"
        and row["target_raw"] == "CVE:CVE-DOES-NOT-EXIST"
        for row in unresolved
    )


def test_ledger_quality_gate_rejects_unlogged_unresolved_when_logging_disabled(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_relation_record(
        relation_record_id="relation:broken:unlogged",
        subject_id="advisory:NVD_CVE:CVE-2026-0001",
        predicate="related_to",
        object_id="CVE:CVE-DOES-NOT-EXIST",
        method="direct_source_relation",
        consumer_policy="contextual_only",
        provenance={"sourceRefs": [{"rawArtifactId": "raw-nvd-cve-fixture"}]},
    )

    report = run_ledger_quality_gate(repo, log_unresolved=False)

    assert report["qualityGate"] == "rejected"
    assert report["hardFail"] is True
    assert any(issue["code"] == "UNLOGGED_UNRESOLVED_REFERENCE" for issue in report["issues"])


def test_affectedness_engine_answers_positive_negative_and_unknown_with_evidence(tmp_path):
    repo = _repo(tmp_path)

    affected = query_affectedness(repo, {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"})
    patched = query_affectedness(repo, {"name": "curl", "version": "8.1.0", "purl": "pkg:generic/curl@8.1.0"})
    unknown = query_affectedness(repo, {"name": "not-curl", "version": "1.0.0"})

    assert affected["affectedness"] == "affected"
    assert {item["sourceKind"] for item in affected["evidence"]} == {"OSV", "NVD_CVE", "GHSA"}
    risk_kinds = {signal["signalKind"] for item in affected["evidence"] for signal in item["riskSignals"]}
    assert {"CVSS", "KEV", "EPSS"} <= risk_kinds
    assert patched["affectedness"] == "known_not_affected"
    assert patched["consumerPolicy"] == "source_backed_range_exclusion"
    assert unknown["affectedness"] == "unknown"
    assert unknown["diagnostics"][0]["code"] == "AFFECTEDNESS_EVIDENCE_INSUFFICIENT"


def test_quality_gate_rejects_exact_cpe_purl_alias_for_hard_affectedness(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_identity_alias(
        identity_alias_id="alias:bad-cpe-purl",
        subject_kind="package_identity",
        subject_namespace="purl",
        subject_id="pkg:generic/curl",
        alias_kind="product_identity",
        alias_namespace="cpe",
        alias_id="cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
        relation_semantics="SAME_AS_EXACT",
        source_artifact_id="raw-package-identity-fixture",
        normalized_record_id="norm:package-identity:pkg:generic/curl",
        provenance={"reason": "test invalid hard alias"},
    )

    report = run_ledger_quality_gate(repo)

    assert report["qualityGate"] == "rejected"
    assert any(issue["code"] == "FUZZY_CPE_PURL_USED_AS_EXACT" for issue in report["issues"])


def test_cached_cwe_catalog_manifest_resolves_tool_rule_cwe_debt(tmp_path):
    manifest_path = _write_cwe_catalog_manifest(tmp_path)
    manifest = load_source_manifest(manifest_path)
    assert validate_source_manifest(manifest, manifest_path) == []
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-cached-catalog.sqlite'}")
    repo.initialize()

    report = ingest_fixture_corpus(repo, manifest_path)
    quality = run_ledger_quality_gate(repo)

    assert report["rowCounts"]["weakness"] >= 7
    assert {"CWE-78", "CWE-190", "CWE-134", "CWE-415", "CWE-416"} <= {
        row["weakness_id"] for row in repo.fetch_all("weakness")
    }
    assert quality["qualityGate"] == "accepted"
    assert quality["hardFail"] is False
    assert quality["scorePolicy"]["gate"] in {"accepted", "accepted_with_caveats"}
    assert quality["scorePolicy"]["phase"] == "etl_projection"
    assert quality["metrics"]["newlyLoggedUnresolvedReferences"] == 0
    assert quality["metrics"]["coverageProfilesBySourceKind"]["CWE"] == ["cached_catalog_snapshot"]


def test_cached_cwe_catalog_profile_hard_fails_missing_referenced_cwe(tmp_path):
    manifest_path = _write_cwe_catalog_manifest(tmp_path)
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-cached-catalog-broken.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo, manifest_path)
    repo.upsert_relation_record(
        relation_record_id="relation:tool-rule:test:maps_to:CWE-9999",
        subject_id="tool-rule:semgrep:c.lang.security.audit.system-command",
        predicate="maps_to_weakness",
        object_id="CWE-9999",
        method="curated_mapping",
        consumer_policy="contextual_only",
        provenance={"sourceRefs": [{"rawArtifactId": "raw-semgrep-fixture"}]},
    )

    quality = run_ledger_quality_gate(repo)

    assert quality["qualityGate"] == "rejected"
    assert quality["hardFail"] is True
    assert any(issue["code"] == "PRODUCTION_CWE_REFERENCE_UNRESOLVED" for issue in quality["issues"])
