"""Threat KB retrieval evidence packet assembly for Judge answers.

This module is intentionally ledger-backed for v1.  It shapes Threat KB context
like GraphRAG/retrieval evidence without requiring live Neo4j/Qdrant writes, and
it never grants affectedness authority to keyword/vector/graph/risk evidence.
"""

from __future__ import annotations

import json
from typing import Any

from app.ledger.repository import SQLiteLedgerRepository

SCHEMA_VERSION = "s5-threat-retrieval-evidence-v1"
AUTHORITY = "contextual_support_not_affectedness_proof"


def _loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _clean(value: Any, *, upper: bool = False, lower: bool = False) -> str | None:
    if value is None:
        return None
    item = str(value).strip()
    if not item:
        return None
    if upper:
        return item.upper()
    if lower:
        return item.lower()
    return item


def _advisory_aliases(payload: dict[str, Any]) -> set[str]:
    return {str(item) for item in [payload.get("externalId"), *payload.get("aliases", [])] if item}


def _relation_rows(repo: SQLiteLedgerRepository, subject_ids: set[str], object_ids: set[str] | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in repo.fetch_all("relation_record"):
        if row.get("subject_id") in subject_ids or (object_ids and row.get("object_id") in object_ids):
            out.append(row)
    return out


def _weakness_semantics(repo: SQLiteLedgerRepository, relation_rows: list[dict[str, Any]], cwe_ids: set[str] | None = None) -> list[dict[str, Any]]:
    weakness_by_id = {row["weakness_id"]: row for row in repo.fetch_all("weakness")}
    by_external = {row["external_id"]: row for row in repo.fetch_all("weakness")}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cwe_id in sorted(cwe_ids or set()):
        row = weakness_by_id.get(cwe_id) or by_external.get(cwe_id)
        if cwe_id in seen:
            continue
        seen.add(cwe_id)
        payload = _loads((row or {}).get("payload_json"), {}) if row else {}
        out.append(
            {
                "weaknessId": (row or {}).get("weakness_id") or cwe_id,
                "externalId": (row or {}).get("external_id") or cwe_id,
                "title": payload.get("name") or payload.get("title") or payload.get("Name"),
                "relationId": None,
                "predicate": "advisory_cwe",
                "authority": AUTHORITY,
            }
        )
    for relation in relation_rows:
        if relation.get("predicate") not in {"maps_to_weakness", "has_weakness", "related_weakness"}:
            continue
        target = str(relation.get("object_id") or "")
        row = weakness_by_id.get(target) or by_external.get(target)
        external_id = (row or {}).get("external_id") or target
        if external_id in seen:
            continue
        seen.add(external_id)
        payload = _loads((row or {}).get("payload_json"), {}) if row else {}
        out.append(
            {
                "weaknessId": (row or {}).get("weakness_id") or target,
                "externalId": external_id,
                "title": payload.get("name") or payload.get("title") or payload.get("Name"),
                "relationId": relation.get("relation_record_id"),
                "predicate": relation.get("predicate"),
                "authority": AUTHORITY,
            }
        )
    return out


def _attack_semantics(repo: SQLiteLedgerRepository, relation_rows: list[dict[str, Any]], weakness_ids: set[str] | None = None) -> list[dict[str, Any]]:
    attack_by_id = {row["attack_pattern_id"]: row for row in repo.fetch_all("attack_pattern")}
    by_external = {row["external_id"]: row for row in repo.fetch_all("attack_pattern")}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    candidate_relations = list(relation_rows)
    for relation in repo.fetch_all("relation_record"):
        if relation.get("object_id") in (weakness_ids or set()) and relation.get("predicate") == "maps_to_weakness":
            candidate_relations.append(relation)
    for relation in candidate_relations:
        if relation.get("predicate") == "maps_to_weakness" and relation.get("object_id") in (weakness_ids or set()):
            target = str(relation.get("subject_id") or "")
        elif relation.get("predicate") in {"related_attack_pattern", "related_capec", "uses_attack_pattern", "maps_to_attack_pattern"}:
            target = str(relation.get("object_id") or "")
        else:
            continue
        row = attack_by_id.get(target) or by_external.get(target)
        external_id = (row or {}).get("external_id") or target
        if external_id in seen:
            continue
        seen.add(external_id)
        payload = _loads((row or {}).get("payload_json"), {}) if row else {}
        out.append(
            {
                "attackPatternId": (row or {}).get("attack_pattern_id") or target,
                "externalId": external_id,
                "sourceKind": (row or {}).get("source_kind"),
                "title": payload.get("name") or payload.get("title") or payload.get("Name"),
                "relationId": relation.get("relation_record_id"),
                "predicate": relation.get("predicate"),
                "authority": AUTHORITY,
            }
        )
    return out


def _risk_signals(repo: SQLiteLedgerRepository, advisory_ids: set[str], advisory_aliases: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in repo.fetch_all("risk_signal"):
        payload = _loads(row.get("payload_json"), {})
        cve = str(payload.get("cve") or payload.get("cveID") or "")
        if row.get("advisory_id") in advisory_ids or cve in advisory_aliases:
            out.append(
                {
                    "riskSignalId": row["risk_signal_id"],
                    "advisoryId": row["advisory_id"],
                    "signalKind": row["signal_kind"],
                    "signalDate": row["signal_date"],
                    "signalValue": row["signal_value"],
                    "sourceKind": row["source_kind"],
                    "payload": payload,
                    "authority": "prioritization_signal_not_affectedness_proof",
                }
            )
    return sorted(out, key=lambda item: (item["signalKind"], item["riskSignalId"]))


def _candidate_from_advisory(row: dict[str, Any], *, used_for_affectedness: bool, suppressed: bool) -> dict[str, Any]:
    payload = _loads(row.get("payload_json"), {})
    return {
        "advisoryId": row["advisory_id"],
        "externalId": row["external_id"],
        "sourceKind": row["source_kind"],
        "aliases": payload.get("aliases", []),
        "packageIdentityId": payload.get("packageIdentityId"),
        "cweIds": payload.get("cweIds", []),
        "usedForAffectedness": used_for_affectedness,
        "suppressedByControls": suppressed,
        "authority": AUTHORITY,
    }


def build_threat_retrieval_evidence(
    repo: SQLiteLedgerRepository,
    component: dict[str, Any],
    affectedness: dict[str, Any],
    identity_resolution: dict[str, Any] | None,
    controls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    repo.initialize()
    component = component or {}
    controls = controls or {}
    accepted = controls.get("accepted") or controls
    excludes = {_clean(item, upper=True) for item in accepted.get("exclude", []) if _clean(item)}
    query_terms = [term for term in [_clean(component.get("name"), lower=True), _clean(component.get("purl")), _clean(component.get("packageIdentityId")), _clean(component.get("cpe")), _clean(component.get("repoUrl"))] if term]
    diagnostics: list[dict[str, Any]] = []

    used_advisory_ids = {str(item.get("advisoryId")) for item in affectedness.get("evidence", []) if item.get("advisoryId")}
    package_ids = set((identity_resolution or {}).get("hardAffectednessPackageIds") or [])
    product_context_advisory_ids = {
        str(row.get("subject_id"))
        for row in repo.fetch_all("identity_alias")
        if row.get("subject_kind") == "advisory"
        and row.get("alias_kind") == "product_identity"
        and row.get("relation_semantics") == "AFFECTS_CPE_MATCH"
        and _clean(row.get("alias_id")) == _clean(component.get("cpe"))
    }
    candidate_rows: list[dict[str, Any]] = []
    seen_candidate_ids: set[str] = set()
    for row in repo.fetch_all("vulnerability_advisory"):
        payload = _loads(row.get("payload_json"), {})
        aliases = {_clean(alias, upper=True) for alias in _advisory_aliases(payload) if _clean(alias)}
        external = _clean(row.get("external_id"), upper=True)
        package_match = payload.get("packageIdentityId") in package_ids if package_ids else False
        used = row["advisory_id"] in used_advisory_ids
        product_context = row["advisory_id"] in product_context_advisory_ids
        suppressed = bool(excludes & ({external} | aliases))
        if (used or package_match or product_context or suppressed) and row["advisory_id"] not in seen_candidate_ids:
            candidate_rows.append(row)
            seen_candidate_ids.add(row["advisory_id"])
    if not candidate_rows:
        diagnostics.append({"code": "THREAT_RETRIEVAL_NO_CONTEXT", "negativeEvidenceAllowed": False})

    candidate_evidence = []
    suppressed_candidate_evidence = []
    advisory_ids: set[str] = set()
    advisory_alias_set: set[str] = set()
    cwe_ids: set[str] = set()
    for row in candidate_rows:
        payload = _loads(row.get("payload_json"), {})
        aliases = {_clean(alias, upper=True) for alias in _advisory_aliases(payload) if _clean(alias)}
        external = _clean(row.get("external_id"), upper=True)
        suppressed = bool(excludes & ({external} | aliases))
        used = row["advisory_id"] in used_advisory_ids and not suppressed
        candidate = _candidate_from_advisory(row, used_for_affectedness=used, suppressed=suppressed)
        if suppressed:
            suppressed_candidate_evidence.append(candidate)
            continue
        candidate_evidence.append(candidate)
        advisory_ids.add(str(row["advisory_id"]))
        advisory_alias_set.update(str(alias) for alias in _advisory_aliases(payload))
        cwe_ids.update(str(cwe) for cwe in payload.get("cweIds", []) if cwe)

    relation_rows = _relation_rows(repo, advisory_ids)
    weakness_semantics = _weakness_semantics(repo, relation_rows, cwe_ids)
    weakness_ids = {item["externalId"] for item in weakness_semantics}
    attack_semantics = _attack_semantics(repo, [*relation_rows, *_relation_rows(repo, set(), weakness_ids)], weakness_ids)
    risk_signals = _risk_signals(repo, advisory_ids, advisory_alias_set)
    methods_used = []
    if candidate_evidence:
        methods_used.append("direct_source_relation")
    if weakness_semantics or attack_semantics:
        methods_used.append("graph_expansion")
    if risk_signals:
        methods_used.append("risk_signal_join")
    methods_attempted = ["direct_source_relation", "graph_expansion", "risk_signal_join"]

    return {
        "schemaVersion": SCHEMA_VERSION,
        "queryTerms": query_terms,
        "candidateEvidence": candidate_evidence,
        "suppressedCandidateEvidence": suppressed_candidate_evidence,
        "weaknessSemantics": weakness_semantics,
        "attackSemantics": attack_semantics,
        "riskSignals": risk_signals,
        "retrievalTrace": {
            "queryIntent": "judge_threat_context",
            "corpusPartitionsSearched": ["public_vulnerability", "weakness_taxonomy", "attack_pattern"],
            "candidateSetSize": len(candidate_evidence),
            "returnedCount": len(candidate_evidence),
            "methodsAttempted": methods_attempted,
            "methodsUsed": methods_used,
            "embeddingUsed": False,
            "keywordUsed": False,
            "negativeEvidenceAllowed": False,
            "authority": AUTHORITY,
            "fallbackTrace": [],
        },
        "methodsAttempted": methods_attempted,
        "methodsUsed": methods_used,
        "authority": AUTHORITY,
        "diagnostics": diagnostics,
        "negativeEvidenceAllowed": False,
    }
