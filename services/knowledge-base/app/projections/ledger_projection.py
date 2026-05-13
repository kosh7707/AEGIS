"""Ledger-derived Neo4j/Qdrant projection helpers for G007.

The SQLite ledger is the source of truth.  This module builds projection records
and payloads from ledger rows only; it never scrolls Qdrant to seed Neo4j.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.ledger.repository import SQLiteLedgerRepository

PROJECTION_VERSION = "ledger-projection-v1"
NEO4J_THREAT_PROJECTION = "neo4j-threat"
QDRANT_THREAT_PROJECTION = "qdrant-threat"
SCOPE_KEY = "knowledge-corpus-v1"
_VOLATILE_ROW_KEYS = {"created_at", "updated_at", "observed_at", "started_at", "completed_at", "last_ingested_at"}


class Neo4jProjectionAdapter(Protocol):
    def load_from_records(self, records: list[dict[str, Any]]) -> None: ...


class QdrantProjectionAdapter(Protocol):
    def load_payloads(self, payloads: list[dict[str, Any]]) -> None: ...


@dataclass(frozen=True)
class LedgerProjectionBundle:
    source_hash: str
    projection_version: str
    neo4j_records: list[dict[str, Any]]
    qdrant_payloads: list[dict[str, Any]]
    projection_nodes: list[dict[str, Any]]
    projection_edges: list[dict[str, Any]]
    manifest: dict[str, Any]


class ProjectionRebuildError(RuntimeError):
    """Raised when a projection adapter fails while rebuilding from ledger."""


def _loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _canonical_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in sorted(row.items()) if key not in _VOLATILE_ROW_KEYS}


def _hash_rows(rows_by_table: dict[str, list[dict[str, Any]]]) -> str:
    canonical = {
        table: [_canonical_row(row) for row in rows]
        for table, rows in sorted(rows_by_table.items())
    }
    payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_jsonl(records: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) for record in records) + ("\n" if records else "")


def _checksum_records(records: list[dict[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_jsonl(records).encode("utf-8")).hexdigest()


def _text_parts(*values: Any) -> str:
    parts: list[str] = []
    for value in values:
        if isinstance(value, list):
            parts.extend(str(v) for v in value if v not in (None, ""))
        elif value not in (None, ""):
            parts.append(str(value))
    return "\n".join(parts)


def _base_payload(*, ledger_id: str, source_hash: str, corpus_partition: str, record_type: str, title: str, text: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "ledgerId": ledger_id,
        "projectionVersion": PROJECTION_VERSION,
        "sourceHash": source_hash,
        "corpusPartition": corpus_partition,
        "recordType": record_type,
        "title": title,
        "text": text,
        "metadata": metadata,
    }


def _weakness_record(row: dict[str, Any], *, relation_rows: list[dict[str, Any]], source_hash: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _loads(row.get("payload_json"), {})
    provenance = _loads(row.get("provenance_json"), {})
    weakness_id = row["weakness_id"]
    related_tool_rules = sorted(
        rel["subject_id"]
        for rel in relation_rows
        if rel.get("object_id") == weakness_id and rel.get("predicate") == "maps_to_weakness"
    )
    record = {
        "id": weakness_id,
        "source": "CWE",
        "title": payload.get("name") or payload.get("title") or weakness_id,
        "description": payload.get("description", ""),
        "threat_category": row.get("taxonomy_family") or payload.get("taxonomyFamily") or "",
        "related_cwe": [],
        "related_cve": [],
        "related_attack": [],
        "related_capec": [],
        "projection_version": PROJECTION_VERSION,
        "projection_source_hash": source_hash,
        "ledger_id": weakness_id,
        "relation_methods": sorted({rel.get("method") for rel in relation_rows if rel.get("object_id") == weakness_id and rel.get("method")}),
    }
    qdrant = _base_payload(
        ledger_id=weakness_id,
        source_hash=source_hash,
        corpus_partition="weakness_taxonomy",
        record_type="weakness",
        title=record["title"],
        text=_text_parts(record["title"], record["description"], record["threat_category"], related_tool_rules),
        metadata={
            "id": weakness_id,
            "source": "CWE",
            "taxonomyFamily": record["threat_category"],
            "provenance": provenance,
            "relationMethods": record["relation_methods"],
        },
    )
    return record, qdrant


def _advisory_record(row: dict[str, Any], *, relation_rows: list[dict[str, Any]], source_hash: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _loads(row.get("payload_json"), {})
    advisory_id = row["advisory_id"]
    cwe_ids = payload.get("cweIds") or []
    package_id = payload.get("packageIdentityId")
    record = {
        "id": payload.get("externalId") or row.get("external_id") or advisory_id,
        "source": "CVE",
        "title": payload.get("title") or payload.get("externalId") or advisory_id,
        "description": payload.get("summary") or payload.get("description") or "",
        "threat_category": "third_party_component",
        "related_cwe": cwe_ids,
        "related_cve": [],
        "related_attack": [],
        "related_capec": [],
        "projection_version": PROJECTION_VERSION,
        "projection_source_hash": source_hash,
        "ledger_id": advisory_id,
        "provider_source_kind": row.get("source_kind"),
        "package_identity_id": package_id,
    }
    qdrant = _base_payload(
        ledger_id=advisory_id,
        source_hash=source_hash,
        corpus_partition="public_vulnerability_knowledge",
        record_type="vulnerability_advisory",
        title=record["title"],
        text=_text_parts(record["title"], record["description"], cwe_ids, package_id, payload.get("aliases")),
        metadata={
            "id": record["id"],
            "source": row.get("source_kind"),
            "providerSourceKind": row.get("source_kind"),
            "packageIdentityId": package_id,
            "relatedCwe": cwe_ids,
            "freshness": _loads(row.get("freshness_json"), {}),
        },
    )
    return record, qdrant


def _attack_pattern_record(row: dict[str, Any], *, relation_rows: list[dict[str, Any]], source_hash: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _loads(row.get("payload_json"), {})
    provenance = _loads(row.get("provenance_json"), {})
    attack_id = row["attack_pattern_id"]
    related = [rel for rel in relation_rows if rel.get("subject_id") == attack_id or rel.get("object_id") == attack_id]
    related_cwe = sorted({rel.get("object_id") for rel in related if rel.get("predicate") == "maps_to_weakness" and rel.get("object_id")})
    related_attack = sorted({
        rel.get("object_id") for rel in related
        if rel.get("predicate") == "related_attack_pattern" and rel.get("object_id")
    } | {
        rel.get("subject_id") for rel in related
        if rel.get("predicate") == "related_attack_pattern" and rel.get("object_id") == attack_id
    })
    related_capec = sorted({
        rel.get("object_id") for rel in related
        if rel.get("predicate") == "related_capec" and rel.get("object_id")
    } | ({attack_id} if str(row.get("source_kind")) == "CAPEC" else set()))
    record = {
        "id": attack_id,
        "source": row.get("source_kind"),
        "title": payload.get("name") or payload.get("title") or attack_id,
        "description": payload.get("description", ""),
        "threat_category": payload.get("taxonomyFamily") or "attack_pattern",
        "related_cwe": related_cwe,
        "related_cve": [],
        "related_attack": related_attack,
        "related_capec": related_capec,
        "projection_version": PROJECTION_VERSION,
        "projection_source_hash": source_hash,
        "ledger_id": attack_id,
        "relation_methods": sorted({rel.get("method") for rel in related if rel.get("method")}),
    }
    qdrant = _base_payload(
        ledger_id=attack_id,
        source_hash=source_hash,
        corpus_partition="attack_pattern",
        record_type="attack_pattern",
        title=record["title"],
        text=_text_parts(record["title"], record["description"], record["threat_category"], related_cwe, related_attack, related_capec, payload.get("platforms"), payload.get("profiles")),
        metadata={
            "id": attack_id,
            "source": row.get("source_kind"),
            "taxonomyFamily": record["threat_category"],
            "relatedCwe": related_cwe,
            "relatedAttack": related_attack,
            "relatedCapec": related_capec,
            "profiles": payload.get("profiles", []),
            "provenance": provenance,
            "relationMethods": record["relation_methods"],
        },
    )
    return record, qdrant

def _tool_payload(row: dict[str, Any], *, relation_rows: list[dict[str, Any]], source_hash: str) -> dict[str, Any]:
    payload = _loads(row.get("payload_json"), {})
    tool_rule_id = row["tool_rule_id"]
    related = [rel for rel in relation_rows if rel.get("subject_id") == tool_rule_id]
    return _base_payload(
        ledger_id=tool_rule_id,
        source_hash=source_hash,
        corpus_partition="tool_rule_mapping",
        record_type="tool_rule",
        title=f"{row.get('tool_name')} {row.get('rule_id')}",
        text=_text_parts(row.get("tool_name"), row.get("rule_id"), payload.get("message"), payload.get("description"), [rel.get("object_id") for rel in related]),
        metadata={
            "toolName": row.get("tool_name"),
            "ruleId": row.get("rule_id"),
            "relationMethods": sorted({rel.get("method") for rel in related if rel.get("method")}),
            "mapsTo": sorted({rel.get("object_id") for rel in related if rel.get("object_id")}),
        },
    )


def _package_payload(row: dict[str, Any], *, source_hash: str) -> dict[str, Any]:
    aliases = _loads(row.get("aliases_json"), [])
    return _base_payload(
        ledger_id=row["package_identity_id"],
        source_hash=source_hash,
        corpus_partition="package_identity",
        record_type="package_identity",
        title=row.get("canonical_name") or row["package_identity_id"],
        text=_text_parts(row.get("canonical_name"), row.get("ecosystem"), row.get("purl"), row.get("cpe"), row.get("repo_url"), aliases),
        metadata={
            "packageIdentityId": row["package_identity_id"],
            "canonicalName": row.get("canonical_name"),
            "ecosystem": row.get("ecosystem"),
            "purl": row.get("purl"),
            "cpe": row.get("cpe"),
            "aliases": aliases,
        },
    )


def _product_payload(row: dict[str, Any], *, source_hash: str) -> dict[str, Any]:
    qualifiers = _loads(row.get("qualifiers_json"), {})
    return _base_payload(
        ledger_id=row["product_identity_id"],
        source_hash=source_hash,
        corpus_partition="product_identity",
        record_type="product_identity",
        title=row.get("product") or row["product_identity_id"],
        text=_text_parts(row.get("vendor"), row.get("product"), row.get("version"), row.get("cpe"), qualifiers),
        metadata={
            "productIdentityId": row["product_identity_id"],
            "vendor": row.get("vendor"),
            "product": row.get("product"),
            "version": row.get("version"),
            "cpe": row.get("cpe"),
            "matchCriteriaId": row.get("match_criteria_id"),
            "qualifiers": qualifiers,
        },
    )


def _source_component_payload(row: dict[str, Any], *, source_hash: str) -> dict[str, Any]:
    qualifiers = _loads(row.get("qualifiers_json"), {})
    return _base_payload(
        ledger_id=row["source_component_identity_id"],
        source_hash=source_hash,
        corpus_partition="source_component_identity",
        record_type="source_component_identity",
        title=row.get("repo_url") or row["source_component_identity_id"],
        text=_text_parts(row.get("repo_url"), row.get("commit_id"), row.get("source_path"), row.get("fingerprint"), qualifiers),
        metadata={
            "sourceComponentIdentityId": row["source_component_identity_id"],
            "repoUrl": row.get("repo_url"),
            "commitId": row.get("commit_id"),
            "sourcePath": row.get("source_path"),
            "fingerprint": row.get("fingerprint"),
            "qualifiers": qualifiers,
        },
    )


def _coverage_profiles(source_artifacts: list[dict[str, Any]]) -> dict[str, list[str]]:
    profiles: dict[str, set[str]] = {}
    for row in source_artifacts:
        metadata = _loads(row.get("metadata_json"), {})
        source_name = str(row.get("source_name") or "")
        profile = str(metadata.get("coverageProfile") or "")
        if source_name and profile:
            profiles.setdefault(source_name, set()).add(profile)
    return {key: sorted(value) for key, value in sorted(profiles.items())}


def _affectedness_payload(row: dict[str, Any], *, source_hash: str) -> dict[str, Any]:
    range_data = _loads(row.get("range_json"), {})
    qualifiers = _loads(row.get("qualifiers_json"), {})
    return _base_payload(
        ledger_id=row["affectedness_id"],
        source_hash=source_hash,
        corpus_partition="affectedness",
        record_type="affectedness_record",
        title=f"{row['advisory_id']} affects {row['subject_id']}",
        text=_text_parts(row["advisory_id"], row["subject_kind"], row["subject_id"], row.get("introduced"), row.get("fixed"), range_data, qualifiers),
        metadata={
            "affectednessId": row["affectedness_id"],
            "advisoryId": row["advisory_id"],
            "subjectKind": row["subject_kind"],
            "subjectId": row["subject_id"],
            "affectednessStatus": row["affectedness_status"],
            "introduced": row.get("introduced"),
            "fixed": row.get("fixed"),
            "range": range_data,
            "qualifiers": qualifiers,
            "confidence": row.get("confidence"),
            "decisionState": row.get("decision_state"),
        },
    )


def _risk_signal_payload(row: dict[str, Any], *, source_hash: str) -> dict[str, Any]:
    payload = _loads(row.get("payload_json"), {})
    return _base_payload(
        ledger_id=row["risk_signal_id"],
        source_hash=source_hash,
        corpus_partition="risk_signal",
        record_type="risk_signal",
        title=f"{row['signal_kind']} {row.get('advisory_id') or row['risk_signal_id']}",
        text=_text_parts(row["signal_kind"], row.get("signal_date"), row.get("signal_value"), row.get("source_kind"), payload),
        metadata={
            "riskSignalId": row["risk_signal_id"],
            "advisoryId": row.get("advisory_id"),
            "signalKind": row["signal_kind"],
            "signalDate": row.get("signal_date"),
            "signalValue": row.get("signal_value"),
            "sourceKind": row.get("source_kind"),
            "payload": payload,
        },
    )


def _conflict_payload(row: dict[str, Any], *, source_hash: str) -> dict[str, Any]:
    values = _loads(row.get("conflicting_values_json"), [])
    evidence = _loads(row.get("evidence_json"), {})
    return _base_payload(
        ledger_id=row["conflict_record_id"],
        source_hash=source_hash,
        corpus_partition="conflict_evidence",
        record_type="conflict_record",
        title=f"{row['conflict_kind']} {row['subject_id']}",
        text=_text_parts(row["conflict_kind"], row["subject_id"], row.get("status"), values),
        metadata={
            "conflictRecordId": row["conflict_record_id"],
            "conflictKind": row["conflict_kind"],
            "subjectId": row["subject_id"],
            "status": row.get("status"),
            "conflictingValues": values,
            "evidence": evidence,
            "consumerPolicy": "conflicting_evidence_not_negative_evidence",
            "negativeEvidenceAllowed": False,
            "forbiddenEffects": ["clean_pass", "negative_evidence", "s3_final_security_verdict"],
        },
    )


def _node(record_id: str, record_type: str, **properties: Any) -> dict[str, Any]:
    return {"id": record_id, "type": record_type, "properties": properties}


def _edge(edge_id: str, source_id: str, predicate: str, target_id: str, **properties: Any) -> dict[str, Any]:
    return {"id": edge_id, "source": source_id, "predicate": predicate, "target": target_id, "properties": properties}


def build_projection_bundle(repo: SQLiteLedgerRepository) -> LedgerProjectionBundle:
    """Build deterministic Neo4j/Qdrant projection input from ledger rows."""
    repo.initialize()
    tables = {
        "source_artifact": repo.fetch_all("source_artifact"),
        "weakness": repo.fetch_all("weakness"),
        "vulnerability_advisory": repo.fetch_all("vulnerability_advisory"),
        "attack_pattern": repo.fetch_all("attack_pattern"),
        "tool_rule": repo.fetch_all("tool_rule"),
        "package_identity": repo.fetch_all("package_identity"),
        "product_identity": repo.fetch_all("product_identity"),
        "source_component_identity": repo.fetch_all("source_component_identity"),
        "affectedness_record": repo.fetch_all("affectedness_record"),
        "risk_signal": repo.fetch_all("risk_signal"),
        "identity_alias": repo.fetch_all("identity_alias"),
        "relation_record": repo.fetch_all("relation_record"),
        "transform_decision": repo.fetch_all("transform_decision"),
        "unresolved_reference": repo.fetch_all("unresolved_reference"),
        "conflict_record": repo.fetch_all("conflict_record"),
    }
    source_hash = _hash_rows(tables)
    relation_rows = tables["relation_record"]
    neo4j_records: list[dict[str, Any]] = []
    qdrant_payloads: list[dict[str, Any]] = []
    projection_nodes: list[dict[str, Any]] = []
    projection_edges: list[dict[str, Any]] = []

    for row in tables["weakness"]:
        record, payload = _weakness_record(row, relation_rows=relation_rows, source_hash=source_hash)
        neo4j_records.append(record)
        qdrant_payloads.append(payload)
        projection_nodes.append(_node(row["weakness_id"], "weakness", externalId=row.get("external_id"), taxonomyFamily=row.get("taxonomy_family"), sourceHash=source_hash))

    for row in tables["vulnerability_advisory"]:
        record, payload = _advisory_record(row, relation_rows=relation_rows, source_hash=source_hash)
        neo4j_records.append(record)
        qdrant_payloads.append(payload)
        projection_nodes.append(_node(row["advisory_id"], "advisory", externalId=row.get("external_id"), sourceKind=row.get("source_kind"), sourceHash=source_hash))

    for row in tables["attack_pattern"]:
        record, payload = _attack_pattern_record(row, relation_rows=relation_rows, source_hash=source_hash)
        neo4j_records.append(record)
        qdrant_payloads.append(payload)
        projection_nodes.append(_node(row["attack_pattern_id"], "attack_pattern", externalId=row.get("external_id"), sourceKind=row.get("source_kind"), sourceHash=source_hash))

    for row in tables["tool_rule"]:
        qdrant_payloads.append(_tool_payload(row, relation_rows=relation_rows, source_hash=source_hash))
        projection_nodes.append(_node(row["tool_rule_id"], "tool_rule", toolName=row.get("tool_name"), ruleId=row.get("rule_id"), sourceHash=source_hash))

    for row in tables["package_identity"]:
        qdrant_payloads.append(_package_payload(row, source_hash=source_hash))
        projection_nodes.append(_node(row["package_identity_id"], "package_identity", canonicalName=row.get("canonical_name"), ecosystem=row.get("ecosystem"), purl=row.get("purl"), cpe=row.get("cpe"), sourceHash=source_hash))

    for row in tables["product_identity"]:
        qdrant_payloads.append(_product_payload(row, source_hash=source_hash))
        projection_nodes.append(_node(row["product_identity_id"], "product_identity", vendor=row.get("vendor"), product=row.get("product"), cpe=row.get("cpe"), sourceHash=source_hash))

    for row in tables["source_component_identity"]:
        qdrant_payloads.append(_source_component_payload(row, source_hash=source_hash))
        projection_nodes.append(_node(row["source_component_identity_id"], "source_component_identity", repoUrl=row.get("repo_url"), sourceHash=source_hash))

    for row in tables["affectedness_record"]:
        qdrant_payloads.append(_affectedness_payload(row, source_hash=source_hash))
        projection_nodes.append(_node(row["affectedness_id"], "affectedness_record", advisoryId=row.get("advisory_id"), subjectKind=row.get("subject_kind"), subjectId=row.get("subject_id"), sourceHash=source_hash))
        projection_edges.append(_edge(
            f"edge:{row['affectedness_id']}:advisory",
            row["affectedness_id"],
            "ASSERTS_AFFECTEDNESS_FOR",
            row["advisory_id"],
            evidence={"ledgerTable": "affectedness_record", "ledgerId": row["affectedness_id"]},
            sourceHash=source_hash,
        ))
        projection_edges.append(_edge(
            f"edge:{row['affectedness_id']}:subject",
            row["advisory_id"],
            "AFFECTS_SUBJECT",
            row["subject_id"],
            evidence={"ledgerTable": "affectedness_record", "ledgerId": row["affectedness_id"]},
            sourceHash=source_hash,
        ))

    for row in tables["risk_signal"]:
        qdrant_payloads.append(_risk_signal_payload(row, source_hash=source_hash))
        projection_nodes.append(_node(row["risk_signal_id"], "risk_signal", advisoryId=row.get("advisory_id"), signalKind=row.get("signal_kind"), signalDate=row.get("signal_date"), sourceHash=source_hash))
        if row.get("advisory_id"):
            projection_edges.append(_edge(
                f"edge:{row['risk_signal_id']}:advisory",
                row["risk_signal_id"],
                "SIGNAL_FOR",
                row["advisory_id"],
                evidence={"ledgerTable": "risk_signal", "ledgerId": row["risk_signal_id"]},
                sourceHash=source_hash,
            ))

    for row in tables["conflict_record"]:
        values = _loads(row.get("conflicting_values_json"), [])
        evidence = _loads(row.get("evidence_json"), {})
        qdrant_payloads.append(_conflict_payload(row, source_hash=source_hash))
        projection_nodes.append(_node(
            row["conflict_record_id"],
            "conflict_record",
            conflictKind=row.get("conflict_kind"),
            subjectId=row.get("subject_id"),
            status=row.get("status"),
            consumerPolicy="conflicting_evidence_not_negative_evidence",
            negativeEvidenceAllowed=False,
            sourceHash=source_hash,
        ))
        projection_edges.append(_edge(
            f"edge:{row['conflict_record_id']}:subject",
            row["conflict_record_id"],
            "CONFLICTS_ON",
            row["subject_id"],
            evidence={"ledgerTable": "conflict_record", "ledgerId": row["conflict_record_id"], "conflictEvidence": evidence, "conflictingValues": values},
            consumerPolicy="conflicting_evidence_not_negative_evidence",
            negativeEvidenceAllowed=False,
            sourceHash=source_hash,
        ))

    for rel in relation_rows:
        provenance = _loads(rel.get("provenance_json"), {})
        projection_edges.append(_edge(
            rel["relation_record_id"],
            rel["subject_id"],
            rel["predicate"],
            rel["object_id"],
            evidence={"ledgerTable": "relation_record", "ledgerId": rel["relation_record_id"], "provenance": provenance},
            method=rel["method"],
            consumerPolicy=rel["consumer_policy"],
            sourceHash=source_hash,
        ))
        qdrant_payloads.append(_base_payload(
            ledger_id=rel["relation_record_id"],
            source_hash=source_hash,
            corpus_partition="relation_provenance",
            record_type="relation_record",
            title=f"{rel['subject_id']} {rel['predicate']} {rel['object_id']}",
            text=_text_parts(rel["subject_id"], rel["predicate"], rel["object_id"], rel["method"]),
            metadata={
                "subjectId": rel["subject_id"],
                "predicate": rel["predicate"],
                "objectId": rel["object_id"],
                "method": rel["method"],
                "consumerPolicy": rel["consumer_policy"],
                "provenance": provenance,
            },
        ))

    for row in tables["identity_alias"]:
        projection_edges.append(_edge(
            row["identity_alias_id"],
            row["subject_id"],
            row["relation_semantics"],
            row["alias_id"],
            evidence={"ledgerTable": "identity_alias", "ledgerId": row["identity_alias_id"], "provenance": _loads(row.get("provenance_json"), {})},
            confidence=row.get("confidence"),
            sourceHash=source_hash,
        ))

    projection_nodes = sorted(projection_nodes, key=lambda item: (item["type"], item["id"]))
    projection_edges = sorted(projection_edges, key=lambda item: (item["predicate"], item["id"]))
    qdrant_payloads = sorted(qdrant_payloads, key=lambda item: (item.get("corpusPartition", ""), item.get("ledgerId", "")))
    checksums = {
        "nodes": _checksum_records(projection_nodes),
        "edges": _checksum_records(projection_edges),
        "textChunks": _checksum_records(qdrant_payloads),
    }
    manifest = {
        "schemaVersion": "s5-projection-bundle-manifest-v1",
        "projectionVersion": PROJECTION_VERSION,
        "scopeKey": SCOPE_KEY,
        "sourceHash": source_hash,
        "productionWriteEnabled": False,
        "coverageProfilesBySourceKind": _coverage_profiles(tables["source_artifact"]),
        "counts": {
            "nodes": len(projection_nodes),
            "edges": len(projection_edges),
            "textChunks": len(qdrant_payloads),
            "neo4jCompatibilityRecords": len(neo4j_records),
        },
        "checksums": checksums,
    }

    return LedgerProjectionBundle(
        source_hash=source_hash,
        projection_version=PROJECTION_VERSION,
        neo4j_records=sorted(neo4j_records, key=lambda item: (item.get("source", ""), item.get("id", ""), item.get("ledger_id", ""))),
        qdrant_payloads=qdrant_payloads,
        projection_nodes=projection_nodes,
        projection_edges=projection_edges,
        manifest=manifest,
    )


def validate_projection_bundle(bundle: LedgerProjectionBundle) -> dict[str, Any]:
    checksums = {
        "nodes": _checksum_records(bundle.projection_nodes),
        "edges": _checksum_records(bundle.projection_edges),
        "textChunks": _checksum_records(bundle.qdrant_payloads),
    }
    issues: list[dict[str, Any]] = []
    for key, actual in checksums.items():
        expected = bundle.manifest.get("checksums", {}).get(key)
        if expected != actual:
            issues.append({"code": "PROJECTION_BUNDLE_CHECKSUM_MISMATCH", "severity": "hard", "artifact": key, "expected": expected, "actual": actual})
    expected_counts = bundle.manifest.get("counts", {})
    actual_counts = {
        "nodes": len(bundle.projection_nodes),
        "edges": len(bundle.projection_edges),
        "textChunks": len(bundle.qdrant_payloads),
        "neo4jCompatibilityRecords": len(bundle.neo4j_records),
    }
    for key, actual in actual_counts.items():
        if expected_counts.get(key) != actual:
            issues.append({"code": "PROJECTION_BUNDLE_COUNT_MISMATCH", "severity": "hard", "artifact": key, "expected": expected_counts.get(key), "actual": actual})
    for edge in bundle.projection_edges:
        evidence = edge.get("properties", {}).get("evidence")
        if not evidence or not evidence.get("ledgerId"):
            issues.append({"code": "PROJECTION_EDGE_WITHOUT_EVIDENCE", "severity": "hard", "edgeId": edge.get("id")})
    return {
        "schemaVersion": "s5-projection-bundle-qa-report-v1",
        "qualityGate": "rejected" if issues else "accepted",
        "hardFail": bool(issues),
        "issues": issues,
        "counts": actual_counts,
        "checksums": checksums,
    }


def write_projection_bundle(
    repo: SQLiteLedgerRepository,
    out_dir: str | Path,
    *,
    production_write_enabled: bool = False,
) -> dict[str, Any]:
    """Write a dry-run projection bundle to JSONL files and record its manifest.

    This is a staging artifact only; by default it never writes to Neo4j/Qdrant.
    """

    bundle = build_projection_bundle(repo)
    qa_report = validate_projection_bundle(bundle)
    manifest = {**bundle.manifest, "productionWriteEnabled": production_write_enabled}
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    (target / "nodes.jsonl").write_text(_canonical_jsonl(bundle.projection_nodes), encoding="utf-8")
    (target / "edges.jsonl").write_text(_canonical_jsonl(bundle.projection_edges), encoding="utf-8")
    (target / "text_chunks.jsonl").write_text(_canonical_jsonl(bundle.qdrant_payloads), encoding="utf-8")
    (target / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    (target / "qa_report.json").write_text(json.dumps(qa_report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    projection_bundle_id = f"projection-bundle:{bundle.source_hash.removeprefix('sha256:')[:16]}"
    repo.upsert_projection_bundle_manifest(
        projection_bundle_id=projection_bundle_id,
        scope_key=SCOPE_KEY,
        projection_version=bundle.projection_version,
        source_hash=bundle.source_hash,
        manifest=manifest,
        qa_report=qa_report,
        node_count=len(bundle.projection_nodes),
        edge_count=len(bundle.projection_edges),
        text_chunk_count=len(bundle.qdrant_payloads),
        checksums=bundle.manifest["checksums"],
        production_write_enabled=production_write_enabled,
    )
    return {
        "schemaVersion": "s5-projection-bundle-write-report-v1",
        "projectionBundleId": projection_bundle_id,
        "outDir": str(target),
        "manifest": manifest,
        "qaReport": qa_report,
        "productionWriteEnabled": production_write_enabled,
    }


class LedgerProjectionRebuilder:
    """Coordinate ledger-derived projection writes and debt reporting."""

    def __init__(
        self,
        repo: SQLiteLedgerRepository,
        *,
        neo4j_adapter: Neo4jProjectionAdapter | None = None,
        qdrant_adapter: QdrantProjectionAdapter | None = None,
    ) -> None:
        self._repo = repo
        self._neo4j = neo4j_adapter
        self._qdrant = qdrant_adapter

    def rebuild(self) -> dict[str, Any]:
        bundle = build_projection_bundle(self._repo)
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result: dict[str, Any] = {
            "schemaVersion": "s5-ledger-projection-report-v1",
            "projectionVersion": bundle.projection_version,
            "sourceHash": bundle.source_hash,
            "neo4jRecordCount": len(bundle.neo4j_records),
            "qdrantPayloadCount": len(bundle.qdrant_payloads),
            "projectionStates": {},
            "diagnostics": [],
        }
        self._project_one(
            result,
            projection_name=NEO4J_THREAT_PROJECTION,
            started_at=started_at,
            adapter=self._neo4j,
            payload=bundle.neo4j_records,
            adapter_method="load_from_records",
            missing_code="NEO4J_PROJECTION_ADAPTER_MISSING",
        )
        self._project_one(
            result,
            projection_name=QDRANT_THREAT_PROJECTION,
            started_at=started_at,
            adapter=self._qdrant,
            payload=bundle.qdrant_payloads,
            adapter_method="load_payloads",
            missing_code="QDRANT_PROJECTION_ADAPTER_MISSING",
        )
        return result

    def _project_one(
        self,
        result: dict[str, Any],
        *,
        projection_name: str,
        started_at: str,
        adapter: Any | None,
        payload: list[dict[str, Any]],
        adapter_method: str,
        missing_code: str,
    ) -> None:
        if adapter is None:
            diag = {"code": missing_code, "message": f"{projection_name} adapter was not provided"}
            self._record_projection_outcome(
                projection_name=projection_name,
                state="debt",
                job_state="debt",
                started_at=started_at,
                diagnostics=[diag],
                source_hash=result["sourceHash"],
                count=len(payload),
            )
            result["projectionStates"][projection_name] = "debt"
            result["diagnostics"].append(diag)
            return

        try:
            getattr(adapter, adapter_method)(payload)
        except Exception as exc:
            diag = {"code": "PROJECTION_ADAPTER_FAILED", "projection": projection_name, "message": str(exc)}
            self._record_projection_outcome(
                projection_name=projection_name,
                state="failed",
                job_state="failed",
                started_at=started_at,
                diagnostics=[diag],
                source_hash=result["sourceHash"],
                count=len(payload),
            )
            result["projectionStates"][projection_name] = "failed"
            result["diagnostics"].append(diag)
            return

        self._record_projection_outcome(
            projection_name=projection_name,
            state="ready",
            job_state="completed",
            started_at=started_at,
            diagnostics=[],
            source_hash=result["sourceHash"],
            count=len(payload),
        )
        result["projectionStates"][projection_name] = "ready"

    def _record_projection_outcome(
        self,
        *,
        projection_name: str,
        state: str,
        job_state: str,
        started_at: str,
        diagnostics: list[dict[str, Any]],
        source_hash: str,
        count: int,
    ) -> None:
        self._repo.record_projection_job(
            projection_name=projection_name,
            scope_key=SCOPE_KEY,
            state=job_state,
            diagnostics=diagnostics,
            started_at=started_at,
            completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._repo.record_projection_state(
            projection_name=projection_name,
            scope_key=SCOPE_KEY,
            state=state,
            source_hash=source_hash,
            projection_version=PROJECTION_VERSION,
            debt={"diagnostics": diagnostics, "recordCount": count} if state in {"debt", "failed"} else {},
            freshness={"status": "current" if state == "ready" else state, "recordCount": count},
        )
