"""Quality gates for the S5 evidence ledger.

The gate is intentionally ledger-first: it validates source provenance,
identity/affectedness invariants, unresolved-reference logging, and projection
preconditions without writing to Neo4j or Qdrant.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.ledger.repository import SQLiteLedgerRepository
from app.quality.scoring_policy import default_score_vector, evaluate_score_vector
from app.relations import detect_relation_conflicts


def _loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _stable_unresolved_id(relation_id: str, role: str, target: str) -> str:
    digest = hashlib.sha256(f"{relation_id}\0{role}\0{target}".encode("utf-8")).hexdigest()[:16]
    return f"unresolved:{digest}"


def _entity_ids(repo: SQLiteLedgerRepository) -> set[str]:
    ids: set[str] = set()
    table_keys = {
        "weakness": "weakness_id",
        "attack_pattern": "attack_pattern_id",
        "tool_rule": "tool_rule_id",
        "package_identity": "package_identity_id",
        "product_identity": "product_identity_id",
        "source_component_identity": "source_component_identity_id",
        "vulnerability_advisory": "advisory_id",
        "affectedness_record": "affectedness_id",
        "risk_signal": "risk_signal_id",
        "source_artifact": "source_artifact_id",
        "normalized_record": "normalized_record_id",
    }
    for table, key in table_keys.items():
        if table not in repo.list_tables():
            continue
        ids.update(str(row[key]) for row in repo.fetch_all(table) if row.get(key))

    for row in repo.fetch_all("identity_alias") if "identity_alias" in repo.list_tables() else []:
        alias_id = str(row.get("alias_id") or "")
        if alias_id:
            ids.add(alias_id)
            if row.get("alias_namespace") == "cve" and alias_id.startswith("CVE-"):
                ids.add(f"CVE:{alias_id}")
    return ids


def _existing_unresolved_keys(repo: SQLiteLedgerRepository) -> set[tuple[str | None, str, str]]:
    if "unresolved_reference" not in repo.list_tables():
        return set()
    return {
        (row.get("relation_record_id"), row.get("reference_role"), row.get("target_raw"))
        for row in repo.fetch_all("unresolved_reference")
    }


def _issue(code: str, severity: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message, **extra}


def _coverage_profiles_by_source(source_artifacts: list[dict[str, Any]]) -> dict[str, set[str]]:
    profiles: dict[str, set[str]] = {}
    for row in source_artifacts:
        metadata = _loads(row.get("metadata_json"), {})
        source_name = str(row.get("source_name") or "")
        profile = str(metadata.get("coverageProfile") or "")
        if not source_name or not profile:
            continue
        profiles.setdefault(source_name, set()).add(profile)
    return profiles


def _hard_reference_profiles(profiles: dict[str, set[str]], source_name: str) -> bool:
    return bool(profiles.get(source_name, set()) & {"cached_catalog_snapshot", "production_snapshot", "full_cwe_expected"})


def _unresolved_reference_severity(target: str, profiles: dict[str, set[str]]) -> tuple[str, str]:
    if target.startswith("CWE-") and _hard_reference_profiles(profiles, "CWE"):
        return "hard", "PRODUCTION_CWE_REFERENCE_UNRESOLVED"
    return "soft", "RELATION_ENDPOINT_UNRESOLVED"


def _ledger_score_vector(*, hard_count: int, soft_count: int, source_artifact_count: int, affectedness_record_count: int) -> dict[str, float]:
    vector = default_score_vector(
        source_resolved=source_artifact_count > 0,
        affectedness_status="affected" if affectedness_record_count else "unknown",
        hard_issue_count=hard_count,
        soft_issue_count=soft_count,
    )
    vector["retrievalRelevance"] = 0.0
    vector["coverageScore"] = max(0.0, min(1.0, source_artifact_count / 10))
    vector["overallAnswerability"] = max(0.0, min(1.0, (vector["evidenceStrength"] + vector["coverageScore"] + vector["sourceReliability"]) / 3))
    return vector


def _conflict_issue(conflict: dict[str, Any]) -> dict[str, Any]:
    return _issue(
        str(conflict["issueCode"]),
        "hard" if conflict.get("severity") == "hard" else "soft",
        "typed relation/affectedness conflict is open in the S5 evidence ledger",
        conflictRecordId=conflict.get("conflictRecordId"),
        conflictKind=conflict.get("conflictKind"),
        subjectId=conflict.get("subjectId"),
    )


def run_ledger_quality_gate(
    repo: SQLiteLedgerRepository,
    *,
    log_unresolved: bool = True,
) -> dict[str, Any]:
    """Run the S5 ledger quality gate.

    Hard failures are limited to corruption of provenance, identity,
    affectedness, or projection preconditions. Unresolved references are allowed
    only when they are explicitly logged in the unresolved ledger.
    """

    repo.initialize()
    issues: list[dict[str, Any]] = []
    tables = set(repo.list_tables())

    source_artifacts = repo.fetch_all("source_artifact") if "source_artifact" in tables else []
    raw_artifacts = repo.fetch_all("raw_artifact") if "raw_artifact" in tables else []
    normalized_records = repo.fetch_all("normalized_record") if "normalized_record" in tables else []
    relations = repo.fetch_all("relation_record") if "relation_record" in tables else []
    affectedness_records = repo.fetch_all("affectedness_record") if "affectedness_record" in tables else []
    aliases = repo.fetch_all("identity_alias") if "identity_alias" in tables else []
    risk_signals = repo.fetch_all("risk_signal") if "risk_signal" in tables else []
    coverage_profiles = _coverage_profiles_by_source(source_artifacts)
    conflict_report = detect_relation_conflicts(repo, record=True)

    if not source_artifacts:
        issues.append(_issue("SOURCE_ARTIFACT_MISSING", "hard", "No source_artifact rows are present"))

    source_artifact_ids = {row["source_artifact_id"] for row in source_artifacts}
    raw_artifact_ids = {row["raw_artifact_id"] for row in raw_artifacts}
    for row in source_artifacts:
        checksum = str(row.get("checksum_sha256") or "")
        if not checksum.startswith("sha256:"):
            issues.append(_issue("SOURCE_ARTIFACT_CHECKSUM_INVALID", "hard", "source_artifact checksum must use sha256: prefix", sourceArtifactId=row["source_artifact_id"]))
        if not row.get("parser_version") or not row.get("normalizer_version"):
            issues.append(_issue("SOURCE_ARTIFACT_VERSION_MISSING", "hard", "parser_version and normalizer_version are required", sourceArtifactId=row["source_artifact_id"]))
        metadata = _loads(row.get("metadata_json"), {})
        if not metadata.get("coverageProfile"):
            issues.append(_issue("SOURCE_ARTIFACT_COVERAGE_PROFILE_MISSING", "hard", "source_artifact must persist coverageProfile", sourceArtifactId=row["source_artifact_id"]))

    for raw_id in sorted(raw_artifact_ids - source_artifact_ids):
        issues.append(_issue("RAW_ARTIFACT_WITHOUT_SOURCE_ARTIFACT", "hard", "raw_artifact must have a matching source_artifact row", rawArtifactId=raw_id))

    for row in normalized_records:
        if row.get("raw_artifact_id") not in raw_artifact_ids:
            issues.append(_issue("NORMALIZED_RECORD_RAW_ARTIFACT_MISSING", "hard", "normalized_record points to missing raw_artifact", normalizedRecordId=row["normalized_record_id"]))

    known_ids = _entity_ids(repo)
    unresolved_keys = _existing_unresolved_keys(repo)
    newly_logged = 0
    for row in relations:
        relation_id = str(row["relation_record_id"])
        provenance = _loads(row.get("provenance_json"), {})
        for role, field in (("subject", "subject_id"), ("object", "object_id")):
            target = str(row[field])
            if target in known_ids:
                continue
            key = (relation_id, role, target)
            if key not in unresolved_keys and log_unresolved:
                repo.upsert_unresolved_reference(
                    unresolved_reference_id=_stable_unresolved_id(relation_id, role, target),
                    relation_record_id=relation_id,
                    owner_record_id=relation_id,
                    reference_role=role,
                    reference_kind="relation_endpoint",
                    target_raw=target,
                    status="unresolved",
                    reason="relation endpoint is not present as a ledger entity or exact alias",
                    source_artifact_id=(provenance.get("sourceRefs") or [{}])[0].get("rawArtifactId"),
                    evidence={"predicate": row.get("predicate"), "method": row.get("method")},
                )
                unresolved_keys.add(key)
                newly_logged += 1
            if key not in unresolved_keys:
                issues.append(_issue("UNLOGGED_UNRESOLVED_REFERENCE", "hard", "missing relation endpoint must be recorded in unresolved_reference", relationRecordId=relation_id, role=role, target=target))
            else:
                severity, code = _unresolved_reference_severity(target, coverage_profiles)
                issues.append(_issue(code, severity, "relation endpoint is unresolved but logged", relationRecordId=relation_id, role=role, target=target))

    advisory_ids = {row["advisory_id"] for row in repo.fetch_all("vulnerability_advisory")}
    for row in affectedness_records:
        if row.get("advisory_id") not in advisory_ids:
            issues.append(_issue("AFFECTEDNESS_ADVISORY_MISSING", "hard", "affectedness_record points to missing advisory", affectednessId=row["affectedness_id"]))
        if row.get("subject_id") not in known_ids:
            issues.append(_issue("AFFECTEDNESS_SUBJECT_MISSING", "hard", "affectedness subject must resolve to package/product/source identity", affectednessId=row["affectedness_id"], subjectId=row.get("subject_id")))
        range_data = _loads(row.get("range_json"), {})
        if not any([row.get("introduced"), row.get("fixed"), range_data.get("range"), range_data.get("events")]):
            issues.append(_issue("AFFECTEDNESS_RANGE_MALFORMED", "hard", "affectedness must preserve an introduced/fixed/range expression", affectednessId=row["affectedness_id"]))
        confidence = float(row.get("confidence") or 0)
        if confidence < 0.0 or confidence > 1.0:
            issues.append(_issue("AFFECTEDNESS_CONFIDENCE_INVALID", "hard", "affectedness confidence must be between 0 and 1", affectednessId=row["affectedness_id"]))

    for row in aliases:
        subject_ns = str(row.get("subject_namespace") or "")
        alias_ns = str(row.get("alias_namespace") or "")
        semantics = str(row.get("relation_semantics") or "")
        if semantics == "SAME_AS_EXACT" and {subject_ns, alias_ns} == {"purl", "cpe"}:
            issues.append(_issue("FUZZY_CPE_PURL_USED_AS_EXACT", "hard", "CPE and PURL must not be exact aliases for hard affectedness", identityAliasId=row["identity_alias_id"]))

    for row in risk_signals:
        if not row.get("signal_date"):
            issues.append(_issue("RISK_SIGNAL_DATE_MISSING", "hard", "risk_signal must be time-stamped", riskSignalId=row["risk_signal_id"]))
        if row.get("signal_kind") in {"KEV", "EPSS"} and row.get("advisory_id") is None:
            issues.append(_issue("RISK_SIGNAL_ADVISORY_UNRESOLVED", "soft", "risk signal is stored but not linked to an advisory yet", riskSignalId=row["risk_signal_id"]))

    for conflict in conflict_report["conflicts"]:
        issues.append(_conflict_issue(conflict))

    hard_count = sum(1 for issue in issues if issue["severity"] == "hard")
    soft_count = sum(1 for issue in issues if issue["severity"] != "hard")
    score_vector = _ledger_score_vector(
        hard_count=hard_count,
        soft_count=soft_count,
        source_artifact_count=len(source_artifacts),
        affectedness_record_count=len(affectedness_records),
    )
    open_conflicts = [conflict for conflict in conflict_report["conflicts"] if conflict.get("status") == "open"]
    score_vector["conflictPenalty"] = max(score_vector.get("conflictPenalty", 0.0), min(1.0, len(open_conflicts) / 3))
    score_vector["overallAnswerability"] = max(0.0, score_vector["overallAnswerability"] - score_vector["conflictPenalty"])
    score_policy = evaluate_score_vector(score_vector, phase="etl_projection")
    conflict_rows = repo.fetch_all("conflict_record") if "conflict_record" in repo.list_tables() else []
    return {
        "schemaVersion": "s5-ledger-quality-report-v1",
        "qualityGate": "rejected" if hard_count else "accepted_with_caveats" if soft_count else "accepted",
        "hardFail": hard_count > 0,
        "scoreVector": score_vector,
        "scorePolicy": score_policy,
        "metrics": {
            "sourceArtifactCount": len(source_artifacts),
            "rawArtifactCount": len(raw_artifacts),
            "normalizedRecordCount": len(normalized_records),
            "relationRecordCount": len(relations),
            "affectednessRecordCount": len(affectedness_records),
            "riskSignalCount": len(risk_signals),
            "identityAliasCount": len(aliases),
            "conflictRecordCount": len(conflict_rows),
            "newlyRecordedConflictCount": conflict_report["newlyRecordedConflictCount"],
            "openConflictCount": len([row for row in conflict_rows if row.get("status") == "open"]),
            "conflictKinds": sorted({row.get("conflict_kind") for row in conflict_rows if row.get("conflict_kind")}),
            "newlyLoggedUnresolvedReferences": newly_logged,
            "hardIssueCount": hard_count,
            "softIssueCount": soft_count,
            "coverageProfilesBySourceKind": {key: sorted(value) for key, value in sorted(coverage_profiles.items())},
        },
        "issues": issues,
    }
