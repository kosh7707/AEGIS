"""Fixture-backed corpus source manifest ingestion for G005.

The harness is intentionally deterministic: no network calls, no Neo4j/Qdrant
projection, and no runtime CVE semantics.  It converts fixture raw artifacts into
S5 SQLite ledger rows with provenance and transform diagnostics.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.ledger.repository import SQLiteLedgerRepository

DEFAULT_SOURCE_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "corpus-ingestion-v1" / "source-manifest.json"

REQUIRED_SOURCE_KINDS = {
    "knowledge-corpus-v1",
    "golden-set-v1",
    "CWE",
    "CAPEC",
    "ATTACK_ICS",
    "ATTACK_ENTERPRISE",
    "semgrep",
    "cppcheck",
    "clang-tidy",
    "gcc-fanalyzer",
    "scan-build",
    "flawfinder",
    "package-identity",
    "OSV",
    "NVD_CVE",
    "GHSA",
    "CISA_KEV",
    "FIRST_EPSS",
}

REQUIRED_COMPLETED_SOURCE_KINDS = {
    "knowledge-corpus-v1",
    "golden-set-v1",
    "CWE",
    "CAPEC",
    "ATTACK_ICS",
    "ATTACK_ENTERPRISE",
    "semgrep",
    "cppcheck",
    "clang-tidy",
    "gcc-fanalyzer",
    "scan-build",
    "flawfinder",
    "package-identity",
    "OSV",
    "NVD_CVE",
    "GHSA",
    "CISA_KEV",
    "FIRST_EPSS",
}

MANIFEST_ONLY_SOURCE_KINDS: set[str] = set()
SOURCE_FIELDS = {
    "sourceId",
    "sourceKind",
    "family",
    "sourceVersion",
    "sourceUrl",
    "coverageStatus",
    "completedCoverage",
    "providerState",
    "rawArtifacts",
}
RAW_ARTIFACT_FIELDS = {
    "rawArtifactId",
    "uri",
    "fixturePath",
    "contentHash",
    "retrievedAt",
    "artifactKind",
    "transformVersion",
}
ALLOWED_COVERAGE_STATUSES = {"completed_fixture", "manifest_only", "deferred"}
G005_TABLES = [
    "knowledge_source",
    "raw_artifact",
    "normalized_record",
    "weakness",
    "attack_pattern",
    "tool_rule",
    "package_identity",
    "vulnerability_advisory",
    "affected_range",
    "relation_record",
    "provider_observation",
]


def load_source_manifest(path: Path | str = DEFAULT_SOURCE_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _manifest_dir(path: Path | str) -> Path:
    return Path(path).resolve().parent


def _hash_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _as_sources(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    sources = manifest.get("sources")
    return sources if isinstance(sources, list) else []


def manifest_coverage_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    sources = _as_sources(manifest)
    completed = [s for s in sources if s.get("completedCoverage") is True]
    non_completed = [s for s in sources if s.get("completedCoverage") is not True]
    return {
        "sourceCount": len(sources),
        "completedSourceCount": len(completed),
        "nonCompletedSourceCount": len(non_completed),
        "completedCoverageSourceKinds": sorted(str(s.get("sourceKind")) for s in completed),
        "nonCompletedSourceKinds": sorted(str(s.get("sourceKind")) for s in non_completed),
    }


def validate_source_manifest(manifest: dict[str, Any], path: Path | str = DEFAULT_SOURCE_MANIFEST_PATH) -> list[str]:
    issues: list[str] = []
    if manifest.get("schemaVersion") != "s5-corpus-source-manifest-v1":
        issues.append("schemaVersion must be s5-corpus-source-manifest-v1")
    sources = _as_sources(manifest)
    if not sources:
        issues.append("sources must be a non-empty list")
        return issues

    source_kinds = {str(source.get("sourceKind")) for source in sources}
    missing_kinds = REQUIRED_SOURCE_KINDS - source_kinds
    if missing_kinds:
        issues.append(f"missing source kinds: {sorted(missing_kinds)}")

    completed_kinds = {str(source.get("sourceKind")) for source in sources if source.get("completedCoverage") is True}
    missing_completed = REQUIRED_COMPLETED_SOURCE_KINDS - completed_kinds
    if missing_completed:
        issues.append(f"missing completed fixture coverage: {sorted(missing_completed)}")
    forbidden_completed = MANIFEST_ONLY_SOURCE_KINDS & completed_kinds
    if forbidden_completed:
        issues.append(f"manifest-only/deferred sources counted as completed: {sorted(forbidden_completed)}")

    base = _manifest_dir(path)
    for source in sources:
        if not isinstance(source, dict):
            issues.append("source entries must be objects")
            continue
        source_id = str(source.get("sourceId", "<missing>"))
        missing = SOURCE_FIELDS - set(source)
        if missing:
            issues.append(f"{source_id} missing source fields: {sorted(missing)}")
        if source.get("coverageStatus") not in ALLOWED_COVERAGE_STATUSES:
            issues.append(f"{source_id}.coverageStatus is invalid")
        provider_state = source.get("providerState")
        if not isinstance(provider_state, dict) or "state" not in provider_state:
            issues.append(f"{source_id}.providerState must include state")
        if source.get("completedCoverage") is True:
            if source.get("coverageStatus") != "completed_fixture":
                issues.append(f"{source_id} completedCoverage requires completed_fixture status")
            if not source.get("rawArtifacts"):
                issues.append(f"{source_id} completedCoverage requires rawArtifacts")
        else:
            if source.get("sourceKind") in REQUIRED_COMPLETED_SOURCE_KINDS:
                issues.append(f"{source_id} required source kind is not completed")
        raw_artifacts = source.get("rawArtifacts")
        if not isinstance(raw_artifacts, list):
            issues.append(f"{source_id}.rawArtifacts must be list")
            continue
        for artifact in raw_artifacts:
            if not isinstance(artifact, dict):
                issues.append(f"{source_id}.rawArtifacts entries must be objects")
                continue
            raw_id = str(artifact.get("rawArtifactId", "<missing>"))
            missing_raw = RAW_ARTIFACT_FIELDS - set(artifact)
            if missing_raw:
                issues.append(f"{raw_id} missing raw artifact fields: {sorted(missing_raw)}")
                continue
            fixture_path = base / str(artifact["fixturePath"])
            if not fixture_path.exists():
                issues.append(f"{raw_id}.fixturePath does not exist: {artifact['fixturePath']}")
            else:
                actual_hash = _hash_file(fixture_path)
                if actual_hash != artifact.get("contentHash"):
                    issues.append(f"{raw_id}.contentHash mismatch: expected {artifact.get('contentHash')} actual {actual_hash}")
            if not str(artifact.get("contentHash", "")).startswith("sha256:"):
                issues.append(f"{raw_id}.contentHash must use sha256: prefix")
            if artifact.get("transformVersion") != "corpus-ingestion-v1":
                issues.append(f"{raw_id}.transformVersion must be corpus-ingestion-v1")

    summary = manifest_coverage_summary(manifest)
    declared_summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    for key in ("sourceCount", "completedSourceCount", "nonCompletedSourceCount"):
        if declared_summary.get(key) != summary[key]:
            issues.append(f"summary.{key} must be {summary[key]}")
    if declared_summary.get("completedCoverageSourceKinds") != summary["completedCoverageSourceKinds"]:
        issues.append("summary.completedCoverageSourceKinds is inconsistent")
    if declared_summary.get("nonCompletedSourceKinds") != summary["nonCompletedSourceKinds"]:
        issues.append("summary.nonCompletedSourceKinds is inconsistent")
    return issues


def _load_artifact(manifest_path: Path | str, artifact: dict[str, Any]) -> dict[str, Any]:
    return json.loads((_manifest_dir(manifest_path) / artifact["fixturePath"]).read_text(encoding="utf-8"))


def _norm_id(source_kind: str, external_id: str) -> str:
    return f"norm:{source_kind}:{external_id}"


def _package_id_from_payload(payload: dict[str, Any]) -> str:
    if payload.get("packageIdentityId"):
        return str(payload["packageIdentityId"])
    purl = str(payload.get("package", {}).get("purl") or "")
    if purl.startswith("pkg:generic/curl"):
        return "pkg:generic/curl"
    return purl or "pkg:generic/curl"


def _advisory_payload(source_kind: str, source_id: str, raw: dict[str, Any], artifact: dict[str, Any]) -> dict[str, Any]:
    if source_kind == "OSV":
        external_id = raw["id"]
        ranges = raw.get("affected", [])
        package_identity_id = _package_id_from_payload(raw)
        return {
            "advisoryId": f"advisory:OSV:{external_id}",
            "externalId": external_id,
            "sourceKind": source_kind,
            "sourceId": source_id,
            "packageIdentityId": package_identity_id,
            "aliases": raw.get("aliases", []),
            "affectedRanges": ranges,
            "fixedVersions": [r.get("fixed") for r in ranges if r.get("fixed")],
            "cweIds": raw.get("cweIds", []),
            "cvss": None,
            "publishedAt": raw.get("published"),
            "modifiedAt": raw.get("modified"),
            "retrievedAt": artifact["retrievedAt"],
            "freshness": {"status": "fixture_current"},
            "transformDiagnostics": ["osv_fixture_normalized", "affected_range_extracted"],
            "provenance": {"sourceKind": source_kind, "sourceId": source_id, "rawArtifactId": artifact["rawArtifactId"]},
        }
    if source_kind == "NVD_CVE":
        external_id = raw["id"]
        ranges = raw.get("affected", [])
        package_identity_id = _package_id_from_payload(ranges[0] if ranges else {})
        return {
            "advisoryId": f"advisory:NVD_CVE:{external_id}",
            "externalId": external_id,
            "sourceKind": source_kind,
            "sourceId": source_id,
            "packageIdentityId": package_identity_id,
            "aliases": [external_id],
            "affectedRanges": ranges,
            "fixedVersions": [r.get("fixed") for r in ranges if r.get("fixed")],
            "cweIds": raw.get("cweIds", []),
            "cvss": raw.get("cvss"),
            "publishedAt": raw.get("published"),
            "modifiedAt": raw.get("lastModified"),
            "retrievedAt": artifact["retrievedAt"],
            "freshness": {"status": "fixture_current"},
            "transformDiagnostics": ["nvd_fixture_normalized", "cpe_reference_preserved"],
            "provenance": {"sourceKind": source_kind, "sourceId": source_id, "rawArtifactId": artifact["rawArtifactId"]},
        }
    external_id = raw["id"]
    vulns = raw.get("vulnerabilities", [])
    ranges = [
        {
            "packageIdentityId": item.get("packageIdentityId", "pkg:generic/curl"),
            "introduced": "0",
            "fixed": item.get("firstPatchedVersion"),
            "range": item.get("vulnerableVersionRange"),
        }
        for item in vulns
    ]
    return {
        "advisoryId": f"advisory:GHSA:{external_id}",
        "externalId": external_id,
        "sourceKind": source_kind,
        "sourceId": source_id,
        "packageIdentityId": ranges[0].get("packageIdentityId") if ranges else "pkg:generic/curl",
        "aliases": raw.get("aliases", []),
        "affectedRanges": ranges,
        "fixedVersions": [r.get("fixed") for r in ranges if r.get("fixed")],
        "cweIds": raw.get("cweIds", []),
        "cvss": None,
        "publishedAt": raw.get("publishedAt"),
        "modifiedAt": raw.get("updatedAt"),
        "retrievedAt": artifact["retrievedAt"],
        "freshness": {"status": "fixture_current"},
        "transformDiagnostics": ["ghsa_fixture_normalized", "patched_version_extracted"],
        "provenance": {"sourceKind": source_kind, "sourceId": source_id, "rawArtifactId": artifact["rawArtifactId"]},
    }


def _external_id(source_kind: str, raw: dict[str, Any]) -> str:
    if source_kind == "CISA_KEV":
        return str(raw["cveID"])
    if source_kind == "FIRST_EPSS":
        return str(raw["cve"])
    if source_kind == "package-identity":
        return str(raw["packageIdentityId"])
    if source_kind in {"semgrep", "cppcheck", "clang-tidy", "gcc-fanalyzer", "scan-build", "flawfinder"}:
        return str(raw["ruleId"])
    return str(raw.get("id") or raw.get("asset") or source_kind)


def _transform_method_for_source_kind(source_kind: str) -> str:
    if source_kind in {"semgrep", "cppcheck", "clang-tidy", "gcc-fanalyzer", "scan-build", "flawfinder"}:
        return "curated_mapping"
    if source_kind in {"CWE", "package-identity"}:
        return "exact_id_match"
    if source_kind in {"CAPEC", "ATTACK_ICS", "ATTACK_ENTERPRISE", "OSV", "NVD_CVE", "GHSA", "CISA_KEV", "FIRST_EPSS"}:
        return "direct_source_relation"
    return "curated_mapping"

def _source_refs(source: dict[str, Any], artifact: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "sourceKind": str(source["sourceKind"]),
            "sourceId": str(source["sourceId"]),
            "sourceVersion": str(source["sourceVersion"]),
            "sourceUrl": str(source["sourceUrl"]),
            "rawArtifactId": str(artifact["rawArtifactId"]),
        }
    ]


def _record_transform_decision(
    repo: SQLiteLedgerRepository,
    *,
    transform_decision_id: str,
    input_id: str,
    output_id: str | None,
    method: str,
    source: dict[str, Any],
    artifact: dict[str, Any],
    taxonomy_family: str | None = None,
    consumer_policy: str = "contextual_only",
    matched_terms: list[str] | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
    decision_extra: dict[str, Any] | None = None,
) -> None:
    decision = {
        "schemaVersion": "s5-transform-decision-v1",
        "transformVersion": artifact.get("transformVersion"),
        "method": method,
        "confidence": decision_extra.get("confidence", 0.9) if decision_extra else 0.9,
        "sourceRefs": _source_refs(source, artifact),
        "matchedTerms": matched_terms or [],
        "taxonomyFamily": taxonomy_family,
        "specializationProfiles": [],
        "consumerPolicy": consumer_policy,
        "outputId": output_id,
        "runtimeObservation": {
            "candidate_returned": bool(output_id),
            "candidate_count": 1 if output_id else 0,
            "methodsUsed": [method] if output_id else [],
            "methodsAttempted": [method],
        },
        "allowedEffects": ["candidate_returned", "contextual_relation"] if output_id else ["no_candidate_returned"],
        "forbiddenEffects": ["clean_pass", "final_security_verdict", "complete_project_safety"],
    }
    if decision_extra:
        decision.update(decision_extra)
    repo.upsert_transform_decision(
        transform_decision_id=transform_decision_id,
        input_id=input_id,
        output_id=output_id,
        method=method,
        decision=decision,
        diagnostics=diagnostics or [{"code": "FIXTURE_TRANSFORM_DECISION_RECORDED"}],
    )


def _upsert_relation_record_with_decision(
    repo: SQLiteLedgerRepository,
    *,
    relation_record_id: str,
    subject_id: str,
    predicate: str,
    object_id: str,
    method: str,
    consumer_policy: str,
    source: dict[str, Any],
    artifact: dict[str, Any],
    provenance: dict[str, Any],
    taxonomy_family: str | None = None,
    matched_terms: list[str] | None = None,
    relation_source: str | None = None,
) -> None:
    relation_source = relation_source or (
        "curated_mapping"
        if method == "curated_mapping"
        else "provider_range_eval"
        if method == "provider_range_eval"
        else "direct_source"
    )
    repo.upsert_relation_record(
        relation_record_id=relation_record_id,
        subject_id=subject_id,
        predicate=predicate,
        object_id=object_id,
        method=method,
        consumer_policy=consumer_policy,
        provenance={
            **provenance,
            "relationSource": relation_source,
            "sourceRefs": _source_refs(source, artifact),
            "matchedTerms": matched_terms or provenance.get("matchedTerms", []),
            "consumerPolicy": consumer_policy,
        },
    )
    _record_transform_decision(
        repo,
        transform_decision_id=f"transform:{relation_record_id}",
        input_id=str(artifact["rawArtifactId"]),
        output_id=relation_record_id,
        method=method,
        source=source,
        artifact=artifact,
        taxonomy_family=taxonomy_family,
        consumer_policy=consumer_policy,
        matched_terms=matched_terms,
        diagnostics=[{"code": "RELATION_SIGNAL_DECISION_RECORDED", "relationSource": relation_source}],
        decision_extra={
            "relation": {
                "subjectId": subject_id,
                "predicate": predicate,
                "objectId": object_id,
                "relationRecordId": relation_record_id,
            },
            "relationSource": relation_source,
        },
    )


def _write_specific_record(repo: SQLiteLedgerRepository, source: dict[str, Any], artifact: dict[str, Any], raw: dict[str, Any]) -> None:
    source_kind = str(source["sourceKind"])
    source_id = str(source["sourceId"])
    external_id = _external_id(source_kind, raw)
    provenance = {"sourceKind": source_kind, "sourceId": source_id, "rawArtifactId": artifact["rawArtifactId"], "transformMethod": "fixture_transform"}

    if source_kind == "CWE":
        repo.upsert_weakness(
            weakness_id=str(raw["id"]),
            external_id=str(raw["id"]),
            taxonomy_family=raw.get("taxonomyFamily"),
            payload={**raw, "transformDiagnostics": ["cwe_fixture_normalized"]},
            provenance=provenance,
        )
        return

    if source_kind in {"CAPEC", "ATTACK_ICS", "ATTACK_ENTERPRISE"}:
        attack_pattern_id = str(raw["id"])
        repo.upsert_attack_pattern(
            attack_pattern_id=attack_pattern_id,
            external_id=attack_pattern_id,
            source_kind=source_kind,
            payload={**raw, "transformDiagnostics": ["attack_pattern_fixture_normalized"]},
            provenance=provenance,
        )
        seen_relations: set[tuple[str, str, str]] = set()

        def _relation(predicate: str, object_id: str, *, relation_source: str = "direct_source") -> None:
            key = (attack_pattern_id, predicate, object_id)
            if key in seen_relations:
                return
            seen_relations.add(key)
            _upsert_relation_record_with_decision(
                repo,
                relation_record_id=f"relation:{attack_pattern_id}:{predicate}:{object_id}",
                subject_id=attack_pattern_id,
                predicate=predicate,
                object_id=str(object_id),
                method="direct_source_relation",
                consumer_policy="contextual_only",
                source=source,
                artifact=artifact,
                taxonomy_family=raw.get("taxonomyFamily"),
                matched_terms=[attack_pattern_id, str(object_id)],
                provenance={**provenance, "matchedTerms": [attack_pattern_id, str(object_id)]},
                relation_source=relation_source,
            )

        for cwe in raw.get("cweIds", []) + raw.get("relatedWeaknesses", []):
            _relation("maps_to_weakness", str(cwe))
        for related_id in raw.get("relatedAttackPatterns", []) + raw.get("relatedTechniques", []):
            _relation("related_attack_pattern", str(related_id))
        for capec in raw.get("relatedCapec", []):
            _relation("related_capec", str(capec))
        return

    if source_kind in {"semgrep", "cppcheck", "clang-tidy", "gcc-fanalyzer", "scan-build", "flawfinder"}:
        tool_rule_id = f"tool-rule:{raw['tool']}:{raw['ruleId']}"
        repo.upsert_tool_rule(
            tool_rule_id=tool_rule_id,
            tool_name=str(raw["tool"]),
            rule_id=str(raw["ruleId"]),
            payload={**raw, "transformDiagnostics": ["tool_rule_fixture_normalized"]},
            provenance=provenance,
        )
        for cwe in raw.get("mapsTo", []):
            _upsert_relation_record_with_decision(
                repo,
                relation_record_id=f"relation:{tool_rule_id}:maps_to:{cwe}",
                subject_id=tool_rule_id,
                predicate="maps_to_weakness",
                object_id=str(cwe),
                method="curated_mapping",
                consumer_policy="contextual_only",
                source=source,
                artifact=artifact,
                taxonomy_family=raw.get("taxonomyFamily"),
                matched_terms=[str(cwe)],
                provenance={**provenance, "matchedTerms": raw.get("mapsTo", [])},
            )
        return

    if source_kind == "package-identity":
        repo.upsert_package_identity(
            package_identity_id=str(raw["packageIdentityId"]),
            canonical_name=str(raw["canonicalName"]),
            ecosystem=raw.get("ecosystem"),
            purl=raw.get("purl"),
            cpe=raw.get("cpe"),
            repo_url=raw.get("repoUrl"),
            aliases=raw.get("aliases", []),
            provenance=provenance,
        )
        return

    if source_kind in {"OSV", "NVD_CVE", "GHSA"}:
        advisory = _advisory_payload(source_kind, source_id, raw, artifact)
        repo.upsert_vulnerability_advisory(
            advisory_id=advisory["advisoryId"],
            source_id=source_id,
            source_kind=source_kind,
            external_id=advisory["externalId"],
            payload=advisory,
            freshness=advisory["freshness"],
        )
        for idx, affected in enumerate(advisory["affectedRanges"]):
            repo.upsert_affected_range(
                affected_range_id=f"affected:{advisory['advisoryId']}:{idx}",
                advisory_id=advisory["advisoryId"],
                package_identity_id=affected.get("packageIdentityId") or advisory.get("packageIdentityId"),
                introduced=affected.get("introduced"),
                fixed=affected.get("fixed"),
                range_data=affected,
                provenance=advisory["provenance"],
            )
        _upsert_relation_record_with_decision(
            repo,
            relation_record_id=f"relation:{advisory['advisoryId']}:affects:{advisory['packageIdentityId']}",
            subject_id=advisory["advisoryId"],
            predicate="affects_package",
            object_id=advisory["packageIdentityId"],
            method="direct_source_relation",
            consumer_policy="contextual_only",
            source=source,
            artifact=artifact,
            taxonomy_family="third_party_component",
            matched_terms=[advisory["externalId"], advisory["packageIdentityId"]],
            provenance=advisory["provenance"],
        )
        repo.record_provider_observation(
            observation_id=f"provider:{source_kind}:{advisory['externalId']}",
            provider=source_kind,
            subject_key=advisory["externalId"],
            status="completed_fixture",
            freshness=advisory["freshness"],
            cache={"fixture": True},
            payload={"advisoryId": advisory["advisoryId"]},
        )
        return

    if source_kind in {"CISA_KEV", "FIRST_EPSS"}:
        cve = str(raw.get("cveID") or raw.get("cve"))
        predicate = "risk_signal_for" if source_kind == "FIRST_EPSS" else "enriches_advisory"
        payload_key = "epss" if source_kind == "FIRST_EPSS" else "kev"
        _upsert_relation_record_with_decision(
            repo,
            relation_record_id=f"relation:{source_kind}:{cve}:{predicate}",
            subject_id=f"risk-signal:{source_kind}:{cve}",
            predicate=predicate,
            object_id=f"CVE:{cve}",
            method="direct_source_relation",
            consumer_policy="contextual_only",
            source=source,
            artifact=artifact,
            taxonomy_family="third_party_component",
            matched_terms=[cve],
            provenance={**provenance, payload_key: raw},
        )
        repo.record_provider_observation(
            observation_id=f"provider:{source_kind}:{cve}",
            provider=source_kind,
            subject_key=cve,
            status="completed_fixture",
            freshness={"status": "fixture_current", "retrievedAt": artifact["retrievedAt"]},
            cache={"fixture": True},
            payload={payload_key: raw},
        )


def ingest_fixture_corpus(
    repo: SQLiteLedgerRepository,
    manifest_path: Path | str = DEFAULT_SOURCE_MANIFEST_PATH,
    *,
    source_kinds: set[str] | None = None,
) -> dict[str, Any]:
    repo.initialize()
    manifest = load_source_manifest(manifest_path)
    issues = validate_source_manifest(manifest, manifest_path)
    if issues:
        raise ValueError(f"Invalid corpus source manifest: {issues}")

    processed_sources = []
    for source in _as_sources(manifest):
        source_kind = str(source["sourceKind"])
        if source_kinds is not None and source_kind not in source_kinds:
            continue
        repo.upsert_knowledge_source(
            source_id=str(source["sourceId"]),
            source_kind=source_kind,
            name=source_kind,
            version=str(source["sourceVersion"]),
            source_url=str(source["sourceUrl"]),
            payload={
                "family": source["family"],
                "coverageStatus": source["coverageStatus"],
                "completedCoverage": source["completedCoverage"],
                "providerState": source["providerState"],
            },
        )
        processed_sources.append(source_kind)
        if source.get("completedCoverage") is not True:
            continue
        for artifact in source["rawArtifacts"]:
            raw = _load_artifact(manifest_path, artifact)
            repo.upsert_raw_artifact(
                raw_artifact_id=str(artifact["rawArtifactId"]),
                source_id=str(source["sourceId"]),
                uri=str(artifact["uri"]),
                content_hash=str(artifact["contentHash"]),
                payload={"manifest": artifact, "raw": raw},
                retrieved_at=str(artifact["retrievedAt"]),
            )
            external_id = _external_id(source_kind, raw)
            normalized_record_id = _norm_id(source_kind, external_id)
            repo.upsert_normalized_record(
                normalized_record_id=normalized_record_id,
                source_id=str(source["sourceId"]),
                raw_artifact_id=str(artifact["rawArtifactId"]),
                record_type=str(artifact["artifactKind"]),
                external_id=external_id,
                payload={"sourceKind": source_kind, "externalId": external_id, "raw": raw},
                provenance={"sourceId": source["sourceId"], "rawArtifactId": artifact["rawArtifactId"], "transformVersion": artifact["transformVersion"]},
            )
            _record_transform_decision(
                repo,
                transform_decision_id=f"transform:{normalized_record_id}",
                input_id=str(artifact["rawArtifactId"]),
                output_id=normalized_record_id,
                method=_transform_method_for_source_kind(source_kind),
                source=source,
                artifact=artifact,
                taxonomy_family=raw.get("taxonomyFamily"),
                consumer_policy="contextual_only",
                matched_terms=[external_id],
                diagnostics=[{"code": "NORMALIZED_RECORD_TRANSFORM_DECISION_RECORDED", "sourceKind": source_kind}],
                decision_extra={
                    "recordType": str(artifact["artifactKind"]),
                    "externalId": external_id,
                },
            )
            _write_specific_record(repo, source, artifact, raw)

    return {
        "schemaVersion": "s5-corpus-ingestion-report-v1",
        "coverage": manifest_coverage_summary(manifest),
        "processedSourceKinds": sorted(processed_sources),
        "rowCounts": {table: repo.count_rows(table) for table in G005_TABLES},
    }
