"""Deterministic identity resolution for S5 affectedness.

The resolver keeps package, product/CPE, and source-component identities
separate.  Only hard-eligible package identity evidence may feed affectedness
range evaluation.
"""

from __future__ import annotations

import json
from typing import Any

from app.ledger.repository import SQLiteLedgerRepository

SCHEMA_VERSION = "s5-identity-resolution-v1"
HARD_AFFECTEDNESS_RELATION_ALLOWLIST = {"PACKAGE_IDENTITY", "NATIVE_ID", "EXACT_PACKAGE_IDENTITY"}
FORBIDDEN_HARD_PROOF_RELATIONS = {
    "RELATED_PRODUCT_IDENTITY",
    "RELATED_SOURCE_COMPONENT",
    "AFFECTS_CPE_MATCH",
}


def _loads(value: str | None, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _clean(value: Any, *, lower: bool = False) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned:
        return None
    return cleaned.lower() if lower else cleaned


def _input(component: dict[str, Any]) -> dict[str, str | None]:
    return {
        "packageIdentityId": _clean(component.get("packageIdentityId")),
        "purl": _clean(component.get("purl")),
        "name": _clean(component.get("name"), lower=True),
        "version": _clean(component.get("version")),
        "cpe": _clean(component.get("cpe")),
        "repoUrl": _clean(component.get("repoUrl")),
        "sourceComponentId": _clean(component.get("sourceComponentId")),
    }


def _match(
    *,
    identity_kind: str,
    identity_id: str,
    match_kind: str,
    confidence: float,
    hard_affectedness_eligible: bool,
    relation_semantics: str,
    evidence: dict[str, Any] | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "identityKind": identity_kind,
        "identityId": identity_id,
        "matchKind": match_kind,
        "confidence": confidence,
        "hardAffectednessEligible": hard_affectedness_eligible,
        "relationSemantics": relation_semantics,
        "evidence": evidence or {},
        "diagnostics": diagnostics or [],
    }


def _dedupe_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in matches:
        key = (item["identityKind"], item["identityId"], item["relationSemantics"])
        previous = best.get(key)
        if previous is None or (float(item["confidence"]), item["matchKind"]) > (float(previous["confidence"]), previous["matchKind"]):
            best[key] = item
    return sorted(best.values(), key=lambda item: (item["identityKind"], item["identityId"], item["matchKind"], item["relationSemantics"]))


def resolve_component_identity(repo: SQLiteLedgerRepository, component: dict[str, Any]) -> dict[str, Any]:
    repo.initialize()
    normalized = _input(component or {})
    matches: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []

    package_rows = repo.fetch_all("package_identity")
    product_rows = repo.fetch_all("product_identity")
    source_rows = repo.fetch_all("source_component_identity")
    alias_rows = repo.fetch_all("identity_alias")

    package_id = normalized["packageIdentityId"]
    purl = normalized["purl"]
    name = normalized["name"]
    cpe = normalized["cpe"]
    repo_url = normalized["repoUrl"]
    source_component_id = normalized["sourceComponentId"]

    for row in package_rows:
        aliases = [_clean(alias, lower=True) for alias in _loads(row.get("aliases_json"), [])]
        row_id = str(row["package_identity_id"])
        row_purl = _clean(row.get("purl"))
        row_name = _clean(row.get("canonical_name"), lower=True)
        if package_id and package_id == row_id:
            matches.append(
                _match(
                    identity_kind="package_identity",
                    identity_id=row_id,
                    match_kind="exact_package_identity_id",
                    confidence=1.0,
                    hard_affectedness_eligible=True,
                    relation_semantics="EXACT_PACKAGE_IDENTITY",
                    evidence={"table": "package_identity", "field": "package_identity_id"},
                )
            )
        if purl and purl == row_purl:
            matches.append(
                _match(
                    identity_kind="package_identity",
                    identity_id=row_id,
                    match_kind="exact_purl",
                    confidence=1.0,
                    hard_affectedness_eligible=True,
                    relation_semantics="PACKAGE_IDENTITY",
                    evidence={"table": "package_identity", "field": "purl"},
                )
            )
        if name and row_name and name == row_name:
            matches.append(
                _match(
                    identity_kind="package_identity",
                    identity_id=row_id,
                    match_kind="canonical_name",
                    confidence=0.92,
                    hard_affectedness_eligible=True,
                    relation_semantics="PACKAGE_IDENTITY",
                    evidence={"table": "package_identity", "field": "canonical_name"},
                )
            )
        if name and name in {alias for alias in aliases if alias}:
            matches.append(
                _match(
                    identity_kind="package_identity",
                    identity_id=row_id,
                    match_kind="package_alias",
                    confidence=0.9,
                    hard_affectedness_eligible=True,
                    relation_semantics="PACKAGE_IDENTITY",
                    evidence={"table": "package_identity", "field": "aliases"},
                )
            )
        if cpe and cpe == _clean(row.get("cpe")):
            matches.append(
                _match(
                    identity_kind="package_identity",
                    identity_id=row_id,
                    match_kind="package_cpe_column_related_only",
                    confidence=0.7,
                    hard_affectedness_eligible=False,
                    relation_semantics="RELATED_PRODUCT_IDENTITY",
                    evidence={"table": "package_identity", "field": "cpe"},
                    diagnostics=[{"code": "PACKAGE_CPE_COLUMN_NOT_AFFECTEDNESS_PROOF"}],
                )
            )
        if repo_url and repo_url == _clean(row.get("repo_url")):
            matches.append(
                _match(
                    identity_kind="package_identity",
                    identity_id=row_id,
                    match_kind="package_repo_related_only",
                    confidence=0.65,
                    hard_affectedness_eligible=False,
                    relation_semantics="RELATED_SOURCE_COMPONENT",
                    evidence={"table": "package_identity", "field": "repo_url"},
                    diagnostics=[{"code": "PACKAGE_REPO_NOT_AFFECTEDNESS_PROOF"}],
                )
            )

    for row in product_rows:
        row_id = str(row["product_identity_id"])
        if cpe and cpe == _clean(row.get("cpe")):
            matches.append(
                _match(
                    identity_kind="product_identity",
                    identity_id=row_id,
                    match_kind="exact_cpe",
                    confidence=1.0,
                    hard_affectedness_eligible=False,
                    relation_semantics="PRODUCT_IDENTITY",
                    evidence={"table": "product_identity", "field": "cpe"},
                    diagnostics=[{"code": "PRODUCT_IDENTITY_NOT_PACKAGE_PROOF"}],
                )
            )

    for row in source_rows:
        row_id = str(row["source_component_identity_id"])
        if source_component_id and source_component_id == row_id:
            matches.append(
                _match(
                    identity_kind="source_component_identity",
                    identity_id=row_id,
                    match_kind="exact_source_component_id",
                    confidence=1.0,
                    hard_affectedness_eligible=False,
                    relation_semantics="SOURCE_COMPONENT_IDENTITY",
                    evidence={"table": "source_component_identity", "field": "source_component_identity_id"},
                    diagnostics=[{"code": "SOURCE_COMPONENT_REQUIRES_PACKAGE_MAPPING"}],
                )
            )
        if repo_url and repo_url == _clean(row.get("repo_url")):
            matches.append(
                _match(
                    identity_kind="source_component_identity",
                    identity_id=row_id,
                    match_kind="exact_repo_url",
                    confidence=0.95,
                    hard_affectedness_eligible=False,
                    relation_semantics="SOURCE_COMPONENT_IDENTITY",
                    evidence={"table": "source_component_identity", "field": "repo_url"},
                    diagnostics=[{"code": "SOURCE_COMPONENT_REQUIRES_PACKAGE_MAPPING"}],
                )
            )

    for row in alias_rows:
        semantics = str(row.get("relation_semantics") or "")
        alias_id = _clean(row.get("alias_id"))
        if cpe and alias_id == cpe and row.get("alias_kind") == "product_identity":
            matches.append(
                _match(
                    identity_kind=str(row.get("alias_kind")),
                    identity_id=str(row.get("alias_id")),
                    match_kind="identity_alias_cpe",
                    confidence=float(row.get("confidence") or 0.0),
                    hard_affectedness_eligible=False,
                    relation_semantics=semantics,
                    evidence={"table": "identity_alias", "identityAliasId": row.get("identity_alias_id"), "subjectId": row.get("subject_id")},
                    diagnostics=[{"code": "PRODUCT_IDENTITY_NOT_PACKAGE_PROOF"}],
                )
            )
        if repo_url and row.get("alias_kind") == "source_component_identity" and semantics == "RELATED_SOURCE_COMPONENT":
            source_match = next((src for src in source_rows if str(src["source_component_identity_id"]) == str(row.get("alias_id")) and repo_url == _clean(src.get("repo_url"))), None)
            if source_match:
                matches.append(
                    _match(
                        identity_kind="source_component_identity",
                        identity_id=str(row.get("alias_id")),
                        match_kind="identity_alias_repo",
                        confidence=float(row.get("confidence") or 0.0),
                        hard_affectedness_eligible=False,
                        relation_semantics=semantics,
                        evidence={"table": "identity_alias", "identityAliasId": row.get("identity_alias_id"), "subjectId": row.get("subject_id")},
                        diagnostics=[{"code": "SOURCE_COMPONENT_REQUIRES_PACKAGE_MAPPING"}],
                    )
                )

    matches = _dedupe_matches(matches)
    hard_package_matches = [item for item in matches if item["identityKind"] == "package_identity" and item["hardAffectednessEligible"]]
    top_confidence = max((float(item["confidence"]) for item in hard_package_matches), default=0.0)
    top_hard_ids = sorted({item["identityId"] for item in hard_package_matches if float(item["confidence"]) == top_confidence})
    ambiguous = len(top_hard_ids) > 1
    hard_ids = [] if ambiguous else top_hard_ids

    if ambiguous:
        status = "ambiguous"
        diagnostics.append({"code": "IDENTITY_AMBIGUOUS", "candidatePackageIdentityIds": top_hard_ids})
    elif hard_ids:
        status = "resolved"
    elif any(item["identityKind"] == "product_identity" or item["relationSemantics"] in {"RELATED_PRODUCT_IDENTITY", "AFFECTS_CPE_MATCH"} for item in matches):
        status = "product_only"
        diagnostics.append({"code": "PRODUCT_IDENTITY_NOT_PACKAGE_PROOF"})
    elif any(item["identityKind"] == "source_component_identity" or item["relationSemantics"] == "RELATED_SOURCE_COMPONENT" for item in matches):
        status = "source_only"
        diagnostics.append({"code": "SOURCE_COMPONENT_REQUIRES_PACKAGE_MAPPING"})
    else:
        status = "unresolved"
        diagnostics.append({"code": "IDENTITY_UNRESOLVED"})

    for item in matches:
        if item["relationSemantics"] in FORBIDDEN_HARD_PROOF_RELATIONS and item["hardAffectednessEligible"]:
            diagnostics.append({"code": "FORBIDDEN_HARD_AFFECTEDNESS_RELATION", "relationSemantics": item["relationSemantics"]})

    return {
        "schemaVersion": SCHEMA_VERSION,
        "input": normalized,
        "matches": matches,
        "hardAffectednessPackageIds": hard_ids,
        "ambiguous": ambiguous,
        "status": status,
        "diagnostics": diagnostics,
        "hardAffectednessRelationAllowlist": sorted(HARD_AFFECTEDNESS_RELATION_ALLOWLIST),
    }
