"""Typed conflict detection for S5 ledger relations and affectedness evidence."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from app.ledger.repository import SQLiteLedgerRepository

SCHEMA_VERSION = "s5-relation-conflict-report-v1"
CONFLICT_EVIDENCE_SCHEMA = "s5-conflict-evidence-v1"
AFFECTED_STATUSES = {"affected"}
UNAFFECTED_STATUSES = {"not_affected", "known_not_affected", "unaffected"}
EXACT_ALIAS_SEMANTICS = {"SAME_AS_EXACT", "NATIVE_ID", "PACKAGE_IDENTITY"}
NON_EXACT_ALIAS_SEMANTICS = {
    "RELATED_PRODUCT_IDENTITY",
    "RELATED_SOURCE_COMPONENT",
    "AFFECTS_CPE_MATCH",
    "RELATED_ALIAS",
    "FUZZY_MATCH",
    "CURATED_RELATED",
}
OPPOSITE_PREDICATES = {
    frozenset({"affects_package", "does_not_affect_package"}),
    frozenset({"maps_to_weakness", "not_mapped_to_weakness"}),
    frozenset({"related_weakness", "not_related_weakness"}),
}
HARD_CONFLICT_KINDS = {
    "affectedness_status_conflict",
    "relation_predicate_conflict",
    "identity_alias_exact_conflict",
}
ISSUE_CODE_BY_KIND = {
    "affectedness_status_conflict": "AFFECTEDNESS_STATUS_CONFLICT",
    "affectedness_range_conflict": "AFFECTEDNESS_RANGE_CONFLICT",
    "relation_predicate_conflict": "RELATION_PREDICATE_CONFLICT",
    "identity_alias_exact_conflict": "IDENTITY_ALIAS_EXACT_CONFLICT",
}


def _loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _conflict_id(kind: str, *parts: Any) -> str:
    return f"conflict:{kind}:{_stable_hash([kind, *parts])}"


def _range_tuple(row: dict[str, Any]) -> tuple[str, str, str, str]:
    range_data = _loads(row.get("range_json"), {})
    events = range_data.get("events") if isinstance(range_data, dict) else None
    normalized_events = json.dumps(sorted(events, key=lambda item: json.dumps(item, sort_keys=True)) if isinstance(events, list) else [], sort_keys=True)
    return (
        str(row.get("introduced") or ""),
        str(row.get("fixed") or ""),
        str(range_data.get("range") or "") if isinstance(range_data, dict) else "",
        normalized_events,
    )


def _conflict_value(table: str, row_id_key: str, row: dict[str, Any], *, value: Any) -> dict[str, Any]:
    return {
        "ledgerTable": table,
        "ledgerId": row.get(row_id_key),
        "value": value,
        "provenance": _loads(row.get("provenance_json"), {}),
    }


def _base_conflict(kind: str, subject_id: str, values: list[dict[str, Any]], *, severity: str, stable_parts: list[Any]) -> dict[str, Any]:
    issue_code = ISSUE_CODE_BY_KIND[kind]
    involved_refs = [
        {"ledgerTable": value.get("ledgerTable"), "ledgerId": value.get("ledgerId")}
        for value in values
        if value.get("ledgerTable") and value.get("ledgerId")
    ]
    return {
        "conflictRecordId": _conflict_id(kind, subject_id, stable_parts),
        "conflictKind": kind,
        "subjectId": subject_id,
        "issueCode": issue_code,
        "severity": severity,
        "status": "open",
        "conflictingValues": values,
        "evidence": {
            "schemaVersion": CONFLICT_EVIDENCE_SCHEMA,
            "conflictFamily": kind,
            "issueCode": issue_code,
            "involvedLedgerRefs": involved_refs,
            "allowedEffects": ["quality_gate_reject" if severity == "hard" else "quality_gate_caveat", "conflict_visibility"],
            "forbiddenEffects": ["clean_pass", "negative_evidence", "s3_final_security_verdict", "service_health_change"],
        },
    }


def _active_affectedness_rows(repo: SQLiteLedgerRepository) -> list[dict[str, Any]]:
    rows = repo.fetch_all("affectedness_record") if "affectedness_record" in repo.list_tables() else []
    return [row for row in rows if str(row.get("decision_state") or "accepted") in {"accepted", "open"}]


def _affectedness_conflicts(repo: SQLiteLedgerRepository) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in _active_affectedness_rows(repo):
        groups[(str(row.get("advisory_id")), str(row.get("subject_kind")), str(row.get("subject_id")))].append(row)

    conflicts: list[dict[str, Any]] = []
    for (advisory_id, subject_kind, subject_id), rows in sorted(groups.items()):
        statuses = {str(row.get("affectedness_status")) for row in rows}
        has_affected = bool(statuses & AFFECTED_STATUSES)
        has_unaffected = bool(statuses & UNAFFECTED_STATUSES)
        if has_affected and has_unaffected:
            values = [
                _conflict_value("affectedness_record", "affectedness_id", row, value={"affectednessStatus": row.get("affectedness_status"), "rangeTuple": _range_tuple(row)})
                for row in sorted(rows, key=lambda item: str(item.get("affectedness_id")))
            ]
            conflicts.append(
                _base_conflict(
                    "affectedness_status_conflict",
                    f"{advisory_id}:{subject_kind}:{subject_id}",
                    values,
                    severity="hard",
                    stable_parts=[advisory_id, subject_kind, subject_id, sorted(statuses), sorted(row.get("affectedness_id") for row in rows)],
                )
            )
        range_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            range_groups[_range_tuple(row)].append(row)
        if len(range_groups) > 1:
            values = []
            for range_tuple, range_rows in sorted(range_groups.items(), key=lambda item: item[0]):
                for row in sorted(range_rows, key=lambda item: str(item.get("affectedness_id"))):
                    values.append(_conflict_value("affectedness_record", "affectedness_id", row, value={"rangeTuple": range_tuple}))
            conflicts.append(
                _base_conflict(
                    "affectedness_range_conflict",
                    f"{advisory_id}:{subject_kind}:{subject_id}",
                    values,
                    severity="soft",
                    stable_parts=[advisory_id, subject_kind, subject_id, sorted((row.get("affectedness_id"), _range_tuple(row)) for row in rows)],
                )
            )
    return conflicts


def _relation_predicate_conflicts(repo: SQLiteLedgerRepository) -> list[dict[str, Any]]:
    rows = repo.fetch_all("relation_record") if "relation_record" in repo.list_tables() else []
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    tracked_predicates = set().union(*(set(pair) for pair in OPPOSITE_PREDICATES))
    for row in rows:
        if row.get("predicate") in tracked_predicates:
            key = tuple(sorted([str(row.get("subject_id")), str(row.get("object_id"))]))
            groups[key].append(row)
    conflicts: list[dict[str, Any]] = []
    for key, group_rows in sorted(groups.items()):
        predicates = {str(row.get("predicate")) for row in group_rows}
        if not any(pair <= predicates for pair in OPPOSITE_PREDICATES):
            continue
        values = [
            _conflict_value("relation_record", "relation_record_id", row, value={"predicate": row.get("predicate"), "subjectId": row.get("subject_id"), "objectId": row.get("object_id")})
            for row in sorted(group_rows, key=lambda item: str(item.get("relation_record_id")))
        ]
        conflicts.append(
            _base_conflict(
                "relation_predicate_conflict",
                f"{key[0]}:{key[1]}",
                values,
                severity="hard",
                stable_parts=[key, sorted(predicates), sorted(row.get("relation_record_id") for row in group_rows)],
            )
        )
    return conflicts


def _alias_conflicts(repo: SQLiteLedgerRepository) -> list[dict[str, Any]]:
    rows = repo.fetch_all("identity_alias") if "identity_alias" in repo.list_tables() else []
    conflicts: list[dict[str, Any]] = []
    exact_by_alias: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_subject_alias: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        semantics = str(row.get("relation_semantics"))
        if semantics in EXACT_ALIAS_SEMANTICS:
            exact_by_alias[(str(row.get("alias_namespace")), str(row.get("alias_id")))].append(row)
        if semantics in EXACT_ALIAS_SEMANTICS | NON_EXACT_ALIAS_SEMANTICS:
            by_subject_alias[
                (
                    str(row.get("subject_kind")),
                    str(row.get("subject_namespace")),
                    str(row.get("subject_id")),
                    str(row.get("alias_namespace")),
                    str(row.get("alias_id")),
                )
            ].append(row)
    for (alias_namespace, alias_id), group_rows in sorted(exact_by_alias.items()):
        subject_ids = {str(row.get("subject_id")) for row in group_rows}
        if len(subject_ids) <= 1:
            continue
        values = [
            _conflict_value("identity_alias", "identity_alias_id", row, value={"relationSemantics": row.get("relation_semantics"), "subjectId": row.get("subject_id"), "aliasNamespace": alias_namespace, "aliasId": alias_id})
            for row in sorted(group_rows, key=lambda item: str(item.get("identity_alias_id")))
        ]
        conflicts.append(
            _base_conflict(
                "identity_alias_exact_conflict",
                f"{alias_namespace}:{alias_id}",
                values,
                severity="hard",
                stable_parts=[alias_namespace, alias_id, sorted(subject_ids), sorted(row.get("identity_alias_id") for row in group_rows)],
            )
        )
    for key, group_rows in sorted(by_subject_alias.items()):
        semantics = {str(row.get("relation_semantics")) for row in group_rows}
        if not (semantics & EXACT_ALIAS_SEMANTICS and semantics & NON_EXACT_ALIAS_SEMANTICS):
            continue
        values = [
            _conflict_value("identity_alias", "identity_alias_id", row, value={"relationSemantics": row.get("relation_semantics"), "subjectAliasKey": key})
            for row in sorted(group_rows, key=lambda item: str(item.get("identity_alias_id")))
        ]
        conflicts.append(
            _base_conflict(
                "identity_alias_exact_conflict",
                ":".join(key),
                values,
                severity="hard",
                stable_parts=[key, sorted(semantics), sorted(row.get("identity_alias_id") for row in group_rows)],
            )
        )
    return conflicts


def _record_conflict(repo: SQLiteLedgerRepository, conflict: dict[str, Any]) -> bool:
    before = any(row.get("conflict_record_id") == conflict["conflictRecordId"] for row in repo.fetch_all("conflict_record"))
    repo.upsert_conflict_record(
        conflict_record_id=conflict["conflictRecordId"],
        conflict_kind=conflict["conflictKind"],
        subject_id=conflict["subjectId"],
        conflicting_values=conflict["conflictingValues"],
        status=conflict["status"],
        evidence=conflict["evidence"],
    )
    return not before


def detect_relation_conflicts(repo: SQLiteLedgerRepository, *, record: bool = True) -> dict[str, Any]:
    """Detect typed contradictions and optionally persist conflict_record rows."""

    repo.initialize()
    conflicts = sorted(
        [*_affectedness_conflicts(repo), *_relation_predicate_conflicts(repo), *_alias_conflicts(repo)],
        key=lambda item: (item["conflictKind"], item["conflictRecordId"]),
    )
    newly_recorded = 0
    if record:
        for conflict in conflicts:
            if _record_conflict(repo, conflict):
                newly_recorded += 1
    hard = any(conflict["severity"] == "hard" for conflict in conflicts)
    quality_impact = "reject" if hard else "caveat" if conflicts else "none"
    return {
        "schemaVersion": SCHEMA_VERSION,
        "conflictCount": len(conflicts),
        "newlyRecordedConflictCount": newly_recorded,
        "qualityImpact": quality_impact,
        "conflictKinds": sorted({conflict["conflictKind"] for conflict in conflicts}),
        "conflicts": conflicts,
        "diagnostics": [
            {
                "code": conflict["issueCode"],
                "severity": conflict["severity"],
                "conflictRecordId": conflict["conflictRecordId"],
                "conflictKind": conflict["conflictKind"],
            }
            for conflict in conflicts
        ],
    }
