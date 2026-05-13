"""Deterministic affectedness query over the S5 ledger.

This module intentionally avoids GraphRAG/vector search. It answers the exact
package/version part of the S5 problem from source-backed affectedness records.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.identity import resolve_component_identity
from app.ledger.repository import SQLiteLedgerRepository


def _loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _version_key(version: str | None) -> tuple[int, ...]:
    if not version:
        return tuple()
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts[:8])


def _lt(left: str | None, right: str | None) -> bool:
    l_key = _version_key(left)
    r_key = _version_key(right)
    if not l_key or not r_key:
        return False
    width = max(len(l_key), len(r_key))
    return l_key + (0,) * (width - len(l_key)) < r_key + (0,) * (width - len(r_key))


def _gte(left: str | None, right: str | None) -> bool:
    if right in (None, "", "0"):
        return True
    return not _lt(left, right)


def _range_contains(version: str | None, record: dict[str, Any]) -> bool | None:
    range_data = _loads(record.get("range_json"), {})
    introduced = record.get("introduced") or range_data.get("introduced")
    fixed = record.get("fixed") or range_data.get("fixed")
    expression = str(range_data.get("range") or "")
    if expression.startswith("< "):
        return _lt(version, expression[2:].strip())
    if expression.startswith("<= "):
        boundary = expression[3:].strip()
        return _lt(version, boundary) or _version_key(version) == _version_key(boundary)
    if fixed:
        return _gte(version, introduced) and _lt(version, fixed)
    if introduced:
        return _gte(version, introduced)
    return None


def _advisory_payloads(repo: SQLiteLedgerRepository) -> dict[str, dict[str, Any]]:
    return {row["advisory_id"]: _loads(row.get("payload_json"), {}) for row in repo.fetch_all("vulnerability_advisory")}


def _risk_signals_for_advisory(repo: SQLiteLedgerRepository, advisory_id: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    aliases = {str(payload.get("externalId") or ""), *[str(alias) for alias in payload.get("aliases", [])]}
    signals: list[dict[str, Any]] = []
    for row in repo.fetch_all("risk_signal"):
        row_payload = _loads(row.get("payload_json"), {})
        cve = str(row_payload.get("cve") or row_payload.get("cveID") or "")
        if row.get("advisory_id") == advisory_id or cve in aliases:
            signals.append(
                {
                    "riskSignalId": row["risk_signal_id"],
                    "signalKind": row["signal_kind"],
                    "signalDate": row["signal_date"],
                    "signalValue": row["signal_value"],
                    "sourceKind": row["source_kind"],
                    "payload": row_payload,
                }
            )
    return sorted(signals, key=lambda item: (item["signalKind"], item["riskSignalId"]))


def query_affectedness(repo: SQLiteLedgerRepository, component: dict[str, Any]) -> dict[str, Any]:
    """Answer whether a concrete component/version is affected.

    Return states:
    - affected: at least one source-backed affectedness range contains version.
    - known_not_affected: package matched and source-backed ranges exclude version.
    - unknown: package/version evidence is insufficient or no source-backed ranges match.
    """

    repo.initialize()
    version = str(component.get("version") or "")
    identity_resolution = resolve_component_identity(repo, component)
    candidate_ids = set(identity_resolution["hardAffectednessPackageIds"])
    advisory_payloads = _advisory_payloads(repo)
    matches: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []

    for row in repo.fetch_all("affectedness_record"):
        if row.get("subject_kind") != "package_identity" or row.get("subject_id") not in candidate_ids:
            continue
        contains = _range_contains(version, row)
        payload = advisory_payloads.get(row["advisory_id"], {})
        evidence = {
            "affectednessId": row["affectedness_id"],
            "advisoryId": row["advisory_id"],
            "advisoryExternalId": payload.get("externalId"),
            "subjectId": row["subject_id"],
            "range": _loads(row.get("range_json"), {}),
            "introduced": row.get("introduced"),
            "fixed": row.get("fixed"),
            "confidence": row.get("confidence"),
            "sourceKind": (_loads(row.get("qualifiers_json"), {}) or {}).get("sourceKind"),
            "riskSignals": _risk_signals_for_advisory(repo, row["advisory_id"], payload),
        }
        if contains is True:
            matches.append(evidence)
        elif contains is False:
            exclusions.append(evidence)

    if matches:
        status = "affected"
        evidence_set = matches
        policy = "source_backed_affectedness"
    elif exclusions and candidate_ids:
        status = "known_not_affected"
        evidence_set = exclusions
        policy = "source_backed_range_exclusion"
    else:
        status = "unknown"
        evidence_set = []
        policy = "insufficient_identity_or_range_evidence"
    diagnostics = [] if status != "unknown" else [{"code": "AFFECTEDNESS_EVIDENCE_INSUFFICIENT"}]
    diagnostics.extend(identity_resolution.get("diagnostics") or [])

    return {
        "schemaVersion": "s5-affectedness-answer-v1",
        "component": component,
        "candidatePackageIdentityIds": sorted(candidate_ids),
        "identityResolution": identity_resolution,
        "affectedness": status,
        "consumerPolicy": policy,
        "evidence": evidence_set,
        "diagnostics": diagnostics,
    }
