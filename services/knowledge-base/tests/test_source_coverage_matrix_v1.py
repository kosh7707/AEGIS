from __future__ import annotations

import copy
import json
from pathlib import Path

from app.ingestion.cached_artifact_adapter import verify_cached_artifacts
from app.ingestion.corpus_ingestion import DEFAULT_SOURCE_MANIFEST_PATH, ingest_fixture_corpus, load_source_manifest
from app.ingestion.source_coverage_matrix import (
    COVERAGE_GATE_KIND,
    evaluate_source_coverage,
    load_source_coverage_matrix,
    validate_source_coverage,
)
from app.ledger.repository import SQLiteLedgerRepository


def _repo(tmp_path: Path) -> SQLiteLedgerRepository:
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    return repo


def _role(evaluation: dict, role_id: str) -> dict:
    return next(role for role in evaluation["roles"] if role["roleId"] == role_id)


def _codes(evaluation: dict) -> set[str]:
    return {diag["code"] for diag in evaluation.get("diagnostics", [])}


def test_default_manifest_evaluates_fixture_coverage_with_source_kg_deferred():
    manifest = load_source_manifest()
    evaluation = evaluate_source_coverage(manifest)

    assert evaluation["schemaVersion"] == "s5-source-coverage-evaluation-v1"
    assert evaluation["coverageGate"]["kind"] == COVERAGE_GATE_KIND
    assert evaluation["coverageGate"]["status"] == "accepted_with_caveats"
    assert evaluation["hardFail"] is False
    assert evaluation["domainScope"]["firstClass"][:2] == ["native", "system"]
    assert {"c", "cpp"} <= set(evaluation["languageScope"]["firstClass"])
    assert evaluation["missingRequiredSourceKinds"] == []
    assert evaluation["roleCount"] == 8
    assert evaluation["deferredRoleCount"] == 1
    assert _role(evaluation, "source_code_kg")["state"] == "deferred_not_required_for_fixture_corpus"
    assert _role(evaluation, "source_code_kg")["requiredSourceKinds"] == []
    assert _role(evaluation, "source_code_kg")["deferredSourceKinds"] == ["SOURCE_CODE_KG"]


def test_non_native_only_matrix_cannot_satisfy_first_class_s5_coverage():
    manifest = load_source_manifest()
    matrix = load_source_coverage_matrix()
    matrix["domainScope"]["firstClass"] = ["web_app_only"]
    matrix["languageScope"]["firstClass"] = ["javascript"]

    evaluation = evaluate_source_coverage(manifest, matrix)

    assert evaluation["coverageGate"]["status"] == "rejected"
    assert evaluation["hardFail"] is True
    assert {"NATIVE_DOMAIN_SCOPE_MISSING", "CPP_LANGUAGE_SCOPE_MISSING", "NON_NATIVE_ONLY_SCOPE_REJECTED"} <= _codes(evaluation)
    assert "NON_NATIVE_ONLY_SCOPE_REJECTED" in "\n".join(validate_source_coverage(manifest, matrix))


def test_non_native_role_source_kinds_cannot_bypass_cpp_scope_declaration():
    matrix = load_source_coverage_matrix()
    for role in matrix["roles"]:
        if role["roleId"] != "source_code_kg":
            role["requiredSourceKinds"] = ["NPM"]
    manifest = {
        "schemaVersion": "s5-corpus-source-manifest-v1",
        "sources": [
            {
                "sourceId": "source-npm-only",
                "sourceKind": "NPM",
                "coverageProfile": "fixture_slice",
                "coverageStatus": "completed_fixture",
                "completedCoverage": True,
            }
        ],
    }

    evaluation = evaluate_source_coverage(manifest, matrix)

    assert evaluation["languageScope"]["firstClass"] == ["c", "cpp"]
    assert evaluation["coverageGate"]["status"] == "rejected"
    assert evaluation["hardFail"] is True
    assert "NON_NATIVE_SOURCE_KIND_NOT_ALLOWED_FOR_FIRST_CLASS_COVERAGE" in _codes(evaluation)


def test_risk_signal_role_is_axis_c_only_and_cvss_is_nvd_derived_not_source_kind():
    manifest = load_source_manifest()
    evaluation = evaluate_source_coverage(manifest)
    risk = _role(evaluation, "risk_exploitation_signal")

    assert risk["answerAxes"] == ["C"]
    assert "CVSS" not in risk["requiredSourceKinds"]
    assert {"CISA_KEV", "FIRST_EPSS", "NVD_CVE"} <= set(risk["requiredSourceKinds"])

    matrix = load_source_coverage_matrix()
    risky_role = next(role for role in matrix["roles"] if role["roleId"] == "risk_exploitation_signal")
    risky_role["answerAxes"] = ["A", "C"]
    risky_role["requiredSourceKinds"].append("CVSS")

    rejected = evaluate_source_coverage(manifest, matrix)
    assert rejected["coverageGate"]["status"] == "rejected"
    assert {"RISK_SIGNAL_AXIS_NOT_C_ONLY", "CVSS_STANDALONE_SOURCE_KIND_FORBIDDEN_V1"} <= _codes(rejected)


def test_fixture_slice_cannot_satisfy_role_requiring_production_or_full_coverage():
    manifest = load_source_manifest()
    matrix = load_source_coverage_matrix()
    advisory_role = next(role for role in matrix["roles"] if role["roleId"] == "vulnerability_advisory_fact")
    advisory_role["minimumCoverageProfile"] = "production_snapshot"
    advisory_role["allowedCoverageProfiles"] = ["production_snapshot"]

    evaluation = evaluate_source_coverage(manifest, matrix)

    assert evaluation["coverageGate"]["status"] == "rejected"
    advisory = _role(evaluation, "vulnerability_advisory_fact")
    assert advisory["diagnostics"]
    violations = advisory["diagnostics"][0]["profileViolations"]
    assert any(item["reason"] == "fixture_slice_cannot_satisfy_catalog_or_production_claim" for item in violations)


def test_missing_hardfail_source_kind_rejects_coverage():
    manifest = load_source_manifest()
    manifest["sources"] = [source for source in manifest["sources"] if source["sourceKind"] != "OSV"]

    evaluation = evaluate_source_coverage(manifest)

    assert evaluation["coverageGate"]["status"] == "rejected"
    assert evaluation["hardFail"] is True
    assert "OSV" in evaluation["missingRequiredSourceKinds"]
    assert "ROLE_REQUIRED_SOURCE_KINDS_MISSING" in _codes(evaluation)


def test_coverage_gate_is_not_service_readiness_health_or_projection_freshness():
    evaluation = evaluate_source_coverage(load_source_manifest())
    payload = json.dumps(evaluation["coverageGate"], sort_keys=True).lower()

    assert evaluation["coverageGate"]["kind"] == "source_coverage_quality_gate_not_service_health"
    assert evaluation["coverageGate"]["scopeSemantic"] == "data_quality_coverage_only_not_runtime_readiness"
    assert "ready" not in evaluation["coverageGate"]
    assert "readiness" not in evaluation["coverageGate"]
    assert "health" not in {key.lower() for key in evaluation["coverageGate"]}
    assert "projectionfreshness" not in payload


def test_cached_artifact_adapter_verifies_default_artifacts_without_network():
    report = verify_cached_artifacts(load_source_manifest(), DEFAULT_SOURCE_MANIFEST_PATH)

    assert report["schemaVersion"] == "s5-cached-artifact-verification-v1"
    assert report["artifactCount"] == 18
    assert report["verifiedArtifactCount"] == 18
    assert report["hardFail"] is False
    assert report["networkPolicy"] == "local_cache_only_no_network_dereference"
    assert report["networkDereferenceAttempted"] is False
    assert all(item["networkDereferenceAttempted"] is False for item in report["artifacts"])


def test_cached_artifact_adapter_rejects_hash_missing_file_and_metadata_without_network(tmp_path):
    manifest = copy.deepcopy(load_source_manifest())
    manifest["sources"][0]["sourceUrl"] = "https://example.invalid/source-would-fail-if-dereferenced"
    manifest["sources"][0]["providerState"] = {}
    manifest["sources"][0]["rawArtifacts"][0]["uri"] = "https://example.invalid/artifact-would-fail-if-dereferenced"
    manifest["sources"][0]["rawArtifacts"][0]["contentHash"] = "sha256:bad"
    manifest["sources"][1]["rawArtifacts"][0]["fixturePath"] = "raw/does-not-exist.json"
    manifest["sources"][2]["rawArtifacts"][0].pop("retrievedAt")
    manifest["sources"][3]["rawArtifacts"][0].pop("transformVersion")
    report = verify_cached_artifacts(manifest, DEFAULT_SOURCE_MANIFEST_PATH)

    assert report["hardFail"] is True
    assert report["networkDereferenceAttempted"] is False
    assert report["sourceUrlDereferenceAttempted"] is False
    assert report["uriDereferenceAttempted"] is False
    codes = {diag["code"] for diag in report["providerDiagnostics"]}
    assert {
        "PROVIDER_STATE_MISSING_OR_MALFORMED",
        "PROVIDER_RETRIEVED_AT_MISSING",
        "CACHED_ARTIFACT_HASH_MISMATCH",
        "CACHED_ARTIFACT_FILE_MISSING",
        "RAW_ARTIFACT_RETRIEVED_AT_MISSING",
        "RAW_ARTIFACT_TRANSFORM_VERSION_MISSING",
    } <= codes


def test_ingestion_report_includes_source_coverage_and_keeps_row_counts_stable(tmp_path):
    repo = _repo(tmp_path)

    report = ingest_fixture_corpus(repo)

    assert report["sourceCoverage"]["schemaVersion"] == "s5-source-coverage-evaluation-v1"
    assert report["sourceCoverage"]["coverageGate"]["kind"] == COVERAGE_GATE_KIND
    assert report["sourceCoverage"]["coverageGate"]["status"] == "accepted_with_caveats"
    assert report["rowCounts"]["knowledge_source"] == 18
    assert report["rowCounts"]["raw_artifact"] == 18
    assert report["rowCounts"]["relation_record"] == 21
