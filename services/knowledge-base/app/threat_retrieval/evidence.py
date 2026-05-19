"""Threat KB retrieval evidence packet assembly for Judge answers.

This module is intentionally ledger-backed for v1.  It shapes Threat KB context
like GraphRAG/retrieval evidence without requiring live Neo4j/Qdrant writes, and
it never grants affectedness authority to keyword/vector/graph/risk evidence.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.graphrag.retrieval_policy import (
    build_retrieval_policy,
    build_score_breakdown,
    deterministic_reranker_policy,
)
from app.ledger.repository import SQLiteLedgerRepository

SCHEMA_VERSION = "s5-threat-retrieval-evidence-v1"
AUTHORITY = "contextual_support_not_affectedness_proof"
RISK_SIGNAL_AUTHORITY = "prioritization_signal_not_affectedness_proof"
CANDIDATE_POOL_PREVIEW_MIN_LIMIT = 10
EQUIVALENT_ADVISORY_LIMIT = 16
EQUIVALENT_ADVISORY_RESPONSE_LIMIT = 64
RISK_SIGNAL_RESPONSE_LIMIT = 32
SUPPRESSED_CANDIDATE_RESPONSE_LIMIT = 16
SEMANTIC_EXPANSION_RESPONSE_LIMIT = 32
SOURCE_KIND_TIEBREAK: dict[str, float] = {
    "NVD_CVE": 0.03,
    "GHSA": 0.02,
    "OSV": 0.01,
}
SECURITY_IDENTIFIER_TERM_RE = re.compile(r"^(cve-\d{4}-\d+|ghsa-[a-z0-9-]+|osv[-_:][a-z0-9_.:-]+|cwe-\d+|capec-\d+)$")
SECURITY_IDENTIFIER_TOKEN_RE = re.compile(r"(cve-\d{4}-\d+|ghsa-[a-z0-9-]+|osv[-_:][a-z0-9_.:-]+|cwe-\d+|capec-\d+)", re.IGNORECASE)
PACKAGE_IDENTITY_FIELD_NAMES = {
    "affectedPackage",
    "componentName",
    "cpe",
    "package",
    "packageIdentityId",
    "packageName",
    "product",
    "productName",
    "purl",
    "repoUrl",
}
SECURITY_IDENTIFIER_FIELD_NAMES = {
    "aliases",
    "capecId",
    "capecIds",
    "cve",
    "cveID",
    "cveId",
    "cwe",
    "cweId",
    "cweIds",
    "externalId",
    "ghsaId",
    "osvId",
}


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


def _security_identifier_terms(values: list[str] | None) -> list[str]:
    return [term for term in (_clean(value, lower=True) for value in (values or [])) if term and SECURITY_IDENTIFIER_TERM_RE.match(term)]


def _security_identifier_tokens(value: Any) -> set[str]:
    return {match.group(1).lower() for match in SECURITY_IDENTIFIER_TOKEN_RE.finditer(str(value or ""))}


def _collect_named_string_values(value: Any, field_names: set[str]) -> set[str]:
    values: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key) in field_names:
                if isinstance(item, list):
                    values.update(str(child) for child in item if child is not None)
                elif isinstance(item, dict):
                    values.update(str(child) for child in item.values() if child is not None and not isinstance(child, (dict, list)))
                elif item is not None:
                    values.add(str(item))
            values.update(_collect_named_string_values(item, field_names))
    elif isinstance(value, list):
        for item in value:
            values.update(_collect_named_string_values(item, field_names))
    return values


def _package_identity_variants(value: Any) -> set[str]:
    item = _clean(value, lower=True)
    if not item:
        return set()
    variants = {item}
    if item.startswith("pkg:"):
        without_version = item.split("@", 1)[0]
        variants.add(without_version)
        if "/" in without_version:
            variants.add(without_version.rsplit("/", 1)[-1])
    return {variant for variant in variants if variant}


def _payload_package_terms(payload: dict[str, Any]) -> set[str]:
    terms: set[str] = set()
    for value in _collect_named_string_values(payload, PACKAGE_IDENTITY_FIELD_NAMES):
        terms.update(_package_identity_variants(value))
    return terms


def _payload_security_terms(row: dict[str, Any], payload: dict[str, Any]) -> set[str]:
    terms: set[str] = set()
    for value in (row.get("external_id"), row.get("advisory_id")):
        terms.update(_security_identifier_tokens(value))
    for value in _collect_named_string_values(payload, SECURITY_IDENTIFIER_FIELD_NAMES):
        terms.update(_security_identifier_tokens(value))
    return terms


def _advisory_aliases(payload: dict[str, Any]) -> set[str]:
    return {str(item) for item in [payload.get("externalId"), *payload.get("aliases", [])] if item}


def _advisory_equivalence_aliases(row: dict[str, Any]) -> set[str]:
    payload = _loads(row.get("payload_json"), {})
    aliases = {_clean(alias, upper=True) for alias in _advisory_aliases(payload) if _clean(alias)}
    external = _clean(row.get("external_id"), upper=True)
    if external:
        aliases.add(external)
    return {alias for alias in aliases if alias}


def _advisory_exclude_keys(row: dict[str, Any], payload: dict[str, Any] | None = None) -> set[str]:
    payload = payload if payload is not None else _loads(row.get("payload_json"), {})
    keys = {
        _clean(row.get("advisory_id"), upper=True),
        _clean(row.get("external_id"), upper=True),
        *(_clean(alias, upper=True) for alias in _advisory_aliases(payload) if _clean(alias)),
    }
    return {key for key in keys if key}


def _equivalence_key(row: dict[str, Any]) -> str | None:
    aliases = sorted(_advisory_equivalence_aliases(row))
    return next((alias for alias in aliases if alias.startswith("CVE-")), aliases[0] if aliases else None)


def _equivalent_advisory_context(
    selected: dict[str, Any],
    *,
    all_advisory_rows: list[dict[str, Any]],
    ranked_rows: list[dict[str, Any]],
    used_advisory_ids: set[str],
    excludes: set[str],
    response_budget_remaining: int,
) -> dict[str, Any]:
    selected_row = selected["row"]
    selected_aliases = _advisory_equivalence_aliases(selected_row)
    ranked_by_id = {str(item["row"].get("advisory_id")): item for item in ranked_rows}
    equivalent_source_kinds = {str(selected_row.get("source_kind"))}
    equivalent_advisories: list[dict[str, Any]] = []
    for row in all_advisory_rows:
        if row.get("advisory_id") == selected_row.get("advisory_id"):
            continue
        row_aliases = _advisory_equivalence_aliases(row)
        if excludes & _advisory_exclude_keys(row):
            continue
        if not (selected_aliases & row_aliases):
            continue
        payload = _loads(row.get("payload_json"), {})
        ranked_item = ranked_by_id.get(str(row.get("advisory_id"))) or {}
        equivalent_source_kinds.add(str(row.get("source_kind")))
        equivalent_advisories.append(
            {
                "advisoryId": row.get("advisory_id"),
                "externalId": row.get("external_id"),
                "sourceKind": row.get("source_kind"),
                "aliases": payload.get("aliases", []),
                "usedForAffectedness": bool(ranked_item.get("used") or row.get("advisory_id") in used_advisory_ids),
                "suppressedByControls": False,
                "authority": AUTHORITY,
            }
        )
    equivalent_advisories.sort(key=lambda item: (str(item.get("sourceKind") or ""), str(item.get("externalId") or "")))
    total_count = len(equivalent_advisories) + 1
    per_candidate_limit = min(EQUIVALENT_ADVISORY_LIMIT, max(0, response_budget_remaining))
    returned_equivalents = equivalent_advisories[:per_candidate_limit]
    return {
        "equivalenceKey": _equivalence_key(selected_row),
        "equivalentSourceKinds": sorted(kind for kind in equivalent_source_kinds if kind),
        "equivalentAdvisoryCount": total_count,
        "equivalentAdvisoryLimit": EQUIVALENT_ADVISORY_LIMIT,
        "equivalentAdvisoriesTruncated": total_count > len(returned_equivalents) + 1,
        "equivalentAdvisories": returned_equivalents,
    }


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
                    "authority": RISK_SIGNAL_AUTHORITY,
                }
            )
    return sorted(out, key=lambda item: (item["signalKind"], item["riskSignalId"]))


def _advisory_matches_query_terms(row: dict[str, Any], payload: dict[str, Any], query_terms: list[str]) -> bool:
    terms = {_clean(term, lower=True) for term in query_terms if len(str(term)) >= 3}
    terms = {term for term in terms if term}
    if not terms:
        return False
    security_terms = {term for term in terms if SECURITY_IDENTIFIER_TERM_RE.match(term)}
    package_terms = {variant for term in terms - security_terms for variant in _package_identity_variants(term)}
    return bool((security_terms & _payload_security_terms(row, payload)) or (package_terms & _payload_package_terms(payload)))


def _max_risk_score(signals: list[dict[str, Any]]) -> float:
    scores: list[float] = []
    for signal in signals:
        value = signal.get("signalValue")
        if value is None and signal.get("signalKind") == "KEV":
            value = 1.0
        try:
            scores.append(float(value))
        except (TypeError, ValueError):
            continue
    return max(scores or [0.0])


def _candidate_from_advisory(
    row: dict[str, Any],
    *,
    used_for_affectedness: bool,
    suppressed: bool,
    retrieval_methods: list[str] | None = None,
    score_breakdown: dict[str, Any] | None = None,
    rerank_score: float | None = None,
    rank: int | None = None,
) -> dict[str, Any]:
    payload = _loads(row.get("payload_json"), {})
    candidate = {
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
    if rank is not None:
        candidate["rank"] = rank
    if retrieval_methods is not None:
        candidate["retrievalMethods"] = retrieval_methods
    if rerank_score is not None:
        candidate["rerankScore"] = rerank_score
    if score_breakdown is not None:
        candidate["scoreBreakdown"] = score_breakdown
    return candidate


def _rank_candidate_rows(
    repo: SQLiteLedgerRepository,
    rows: list[dict[str, Any]],
    *,
    used_advisory_ids: set[str],
    package_ids: set[str],
    product_context_advisory_ids: set[str],
    excludes: set[str],
    query_terms: list[str],
) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for row in rows:
        payload = _loads(row.get("payload_json"), {})
        suppressed = bool(excludes & _advisory_exclude_keys(row, payload))
        used = row["advisory_id"] in used_advisory_ids and not suppressed
        package_match = payload.get("packageIdentityId") in package_ids if package_ids else False
        product_context = row["advisory_id"] in product_context_advisory_ids
        keyword_match = _advisory_matches_query_terms(row, payload, query_terms)
        retrieval_methods: list[str] = []
        if used:
            retrieval_methods.append("affectedness_evidence")
        elif package_match:
            retrieval_methods.append("package_identity_context")
        if product_context:
            retrieval_methods.append("provider_range_eval")
        if keyword_match and not retrieval_methods:
            retrieval_methods.append("keyword_match")
        if not retrieval_methods:
            retrieval_methods.append("direct_source_relation")
        risk_signals = _risk_signals(repo, {str(row["advisory_id"])}, {str(alias) for alias in _advisory_aliases(payload)})
        base_score = _max_risk_score(risk_signals) + SOURCE_KIND_TIEBREAK.get(str(row.get("source_kind")), 0.0)
        primary_method = retrieval_methods[0]
        score_breakdown = build_score_breakdown(base_score=base_score, method=primary_method)
        ranked.append(
            {
                "row": row,
                "used": used,
                "suppressed": suppressed,
                "retrievalMethods": retrieval_methods,
                "scoreBreakdown": score_breakdown,
                "rerankScore": score_breakdown["finalRerankScore"],
                "sortKey": (
                    score_breakdown["finalRerankScore"],
                    _max_risk_score(risk_signals),
                    SOURCE_KIND_TIEBREAK.get(str(row.get("source_kind")), 0.0),
                    str(row.get("external_id") or ""),
                ),
            }
        )
    return sorted(ranked, key=lambda item: item["sortKey"], reverse=True)


def _candidate_pool_preview(
    candidate_pool: list[dict[str, Any]],
    *,
    selected_count: int,
    preview_limit: int,
) -> list[dict[str, Any]]:
    preview: list[dict[str, Any]] = []
    for candidate_pool_rank, item in enumerate(candidate_pool[:preview_limit], start=1):
        returned = candidate_pool_rank <= selected_count
        preview_item = _candidate_from_advisory(
            item["row"],
            used_for_affectedness=item["used"],
            suppressed=False,
            retrieval_methods=item["retrievalMethods"],
            score_breakdown=item["scoreBreakdown"],
            rerank_score=item["rerankScore"],
        )
        preview_item.update(
            {
                "candidatePoolRank": candidate_pool_rank,
                "returned": returned,
            }
        )
        if not returned:
            preview_item["unreturnedReason"] = "outside_final_top_k"
        preview.append(preview_item)
    return preview


def build_threat_retrieval_evidence(
    repo: SQLiteLedgerRepository,
    component: dict[str, Any],
    affectedness: dict[str, Any],
    identity_resolution: dict[str, Any] | None,
    controls: dict[str, Any] | None = None,
    query_terms_extra: list[str] | None = None,
) -> dict[str, Any]:
    repo.initialize()
    component = component or {}
    controls = controls or {}
    accepted = controls.get("accepted") or controls
    excludes = {_clean(item, upper=True) for item in accepted.get("exclude", []) if _clean(item)}
    query_terms = sorted(
        {
            term
            for term in [
                _clean(component.get("name"), lower=True),
                _clean(component.get("purl"), lower=True),
                _clean(component.get("packageIdentityId"), lower=True),
                _clean(component.get("cpe"), lower=True),
                _clean(component.get("repoUrl"), lower=True),
                *_security_identifier_terms(query_terms_extra),
            ]
            if term
        }
    )
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
    all_advisory_rows = repo.fetch_all("vulnerability_advisory")
    for row in all_advisory_rows:
        payload = _loads(row.get("payload_json"), {})
        package_match = payload.get("packageIdentityId") in package_ids if package_ids else False
        used = row["advisory_id"] in used_advisory_ids
        product_context = row["advisory_id"] in product_context_advisory_ids
        keyword_match = _advisory_matches_query_terms(row, payload, query_terms)
        suppressed = bool(excludes & _advisory_exclude_keys(row, payload))
        if (used or package_match or product_context or keyword_match or suppressed) and row["advisory_id"] not in seen_candidate_ids:
            candidate_rows.append(row)
            seen_candidate_ids.add(row["advisory_id"])
    if not candidate_rows:
        diagnostics.append({"code": "THREAT_RETRIEVAL_NO_CONTEXT", "negativeEvidenceAllowed": False})

    requested_controls = controls.get("requested") if isinstance(controls.get("requested"), dict) else {}
    requested_top_k = accepted.get("topK")
    if accepted.get("topK") is not None and isinstance(requested_controls.get("topK"), int):
        requested_top_k = requested_controls["topK"]

    retrieval_policy = build_retrieval_policy(
        query_intent="judge_threat_context",
        requested_top_k=requested_top_k,
        matched_terms=query_terms,
        lexical_signals=[],
        graph_depth=2,
    )
    ranked_rows = _rank_candidate_rows(
        repo,
        candidate_rows,
        used_advisory_ids=used_advisory_ids,
        package_ids=package_ids,
        product_context_advisory_ids=product_context_advisory_ids,
        excludes=excludes,
        query_terms=query_terms,
    )
    usable_ranked_rows = [item for item in ranked_rows if not item["suppressed"]]
    candidate_set_size = len(usable_ranked_rows)
    candidate_pool = usable_ranked_rows[:retrieval_policy.candidate_pool_k]
    candidate_pool_truncated = candidate_set_size > len(candidate_pool)
    selected_candidates = candidate_pool[:retrieval_policy.final_top_k]
    candidate_pool_preview_limit = max(CANDIDATE_POOL_PREVIEW_MIN_LIMIT, retrieval_policy.final_top_k)
    candidate_pool_preview = _candidate_pool_preview(
        candidate_pool,
        selected_count=len(selected_candidates),
        preview_limit=candidate_pool_preview_limit,
    )

    candidate_evidence = []
    suppressed_candidate_evidence = []
    advisory_ids: set[str] = set()
    advisory_alias_set: set[str] = set()
    cwe_ids: set[str] = set()
    equivalent_advisory_response_remaining = EQUIVALENT_ADVISORY_RESPONSE_LIMIT
    for rank, item in enumerate(selected_candidates, start=1):
        row = item["row"]
        payload = _loads(row.get("payload_json"), {})
        candidate = _candidate_from_advisory(
            row,
            used_for_affectedness=item["used"],
            suppressed=False,
            retrieval_methods=item["retrievalMethods"],
            score_breakdown=item["scoreBreakdown"],
            rerank_score=item["rerankScore"],
            rank=rank,
        )
        candidate.update(
            _equivalent_advisory_context(
                item,
                all_advisory_rows=all_advisory_rows,
                ranked_rows=ranked_rows,
                used_advisory_ids=used_advisory_ids,
                excludes=excludes,
                response_budget_remaining=equivalent_advisory_response_remaining,
            )
        )
        equivalent_advisory_response_remaining -= len(candidate.get("equivalentAdvisories") or [])
        candidate_evidence.append(candidate)
        advisory_ids.add(str(row["advisory_id"]))
        advisory_alias_set.update(str(alias) for alias in _advisory_aliases(payload))
        cwe_ids.update(str(cwe) for cwe in payload.get("cweIds", []) if cwe)
    for item in ranked_rows:
        if not item["suppressed"]:
            continue
        suppressed_candidate_evidence.append(
            _candidate_from_advisory(
                item["row"],
                used_for_affectedness=False,
                suppressed=True,
                retrieval_methods=item["retrievalMethods"],
                score_breakdown=item["scoreBreakdown"],
                rerank_score=item["rerankScore"],
            )
        )
    suppressed_candidate_total_count = len(suppressed_candidate_evidence)
    suppressed_candidate_evidence = suppressed_candidate_evidence[:SUPPRESSED_CANDIDATE_RESPONSE_LIMIT]

    relation_rows = _relation_rows(repo, advisory_ids)
    all_weakness_semantics = _weakness_semantics(repo, relation_rows, cwe_ids)
    weakness_semantic_total_count = len(all_weakness_semantics)
    weakness_semantics = all_weakness_semantics[:SEMANTIC_EXPANSION_RESPONSE_LIMIT]
    weakness_ids = {item["externalId"] for item in all_weakness_semantics}
    all_attack_semantics = _attack_semantics(repo, [*relation_rows, *_relation_rows(repo, set(), weakness_ids)], weakness_ids)
    attack_semantic_total_count = len(all_attack_semantics)
    attack_semantics = all_attack_semantics[:SEMANTIC_EXPANSION_RESPONSE_LIMIT]
    all_risk_signals = _risk_signals(repo, advisory_ids, advisory_alias_set)
    risk_signal_total_count = len(all_risk_signals)
    risk_signals = all_risk_signals[:RISK_SIGNAL_RESPONSE_LIMIT]
    methods_used = []
    if candidate_evidence:
        for method in ("affectedness_evidence", "package_identity_context", "provider_range_eval", "direct_source_relation"):
            if any(method in (item.get("retrievalMethods") or []) for item in candidate_evidence):
                methods_used.append(method)
    if weakness_semantics or attack_semantics:
        methods_used.append("graph_expansion")
    if risk_signals:
        methods_used.append("risk_signal_join")
    if any("keyword_match" in (item.get("retrievalMethods") or []) for item in candidate_evidence):
        methods_used.append("keyword_match")
    methods_attempted = ["direct_source_relation", "keyword_match", "graph_expansion", "risk_signal_join"]
    relation_methods: list[str] = []
    for item in ranked_rows:
        for method in item.get("retrievalMethods") or []:
            if method not in relation_methods:
                relation_methods.append(method)
    filters_applied = (
        [{"control": "exclude", "values": sorted(excludes), "method": "advisory_identifier_filter"}]
        if excludes
        else []
    )
    equivalent_advisory_returned_count = sum(len(item.get("equivalentAdvisories") or []) for item in candidate_evidence)

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
            "candidateSetSize": candidate_set_size,
            "candidateSetTotalCount": candidate_set_size,
            "candidatePoolSize": len(candidate_pool),
            "candidatePoolTruncated": candidate_pool_truncated,
            "candidatePoolTruncationReason": "candidate_pool_k_cap" if candidate_pool_truncated else None,
            "candidatePoolPreview": candidate_pool_preview,
            "candidatePoolPreviewCount": len(candidate_pool_preview),
            "candidatePoolPreviewLimit": candidate_pool_preview_limit,
            "candidatePoolPreviewTruncated": len(candidate_pool) > candidate_pool_preview_limit,
            "returnedCount": len(candidate_evidence),
            "equivalentAdvisoryReturnedCount": equivalent_advisory_returned_count,
            "equivalentAdvisoryResponseLimit": EQUIVALENT_ADVISORY_RESPONSE_LIMIT,
            "equivalentAdvisoryResponseTruncated": any(
                bool(item.get("equivalentAdvisoriesTruncated")) for item in candidate_evidence
            ),
            "riskSignalTotalCount": risk_signal_total_count,
            "riskSignalReturnedCount": len(risk_signals),
            "riskSignalResponseLimit": RISK_SIGNAL_RESPONSE_LIMIT,
            "riskSignalResponseTruncated": risk_signal_total_count > len(risk_signals),
            "suppressedCandidateTotalCount": suppressed_candidate_total_count,
            "suppressedCandidateReturnedCount": len(suppressed_candidate_evidence),
            "suppressedCandidateResponseLimit": SUPPRESSED_CANDIDATE_RESPONSE_LIMIT,
            "suppressedCandidateResponseTruncated": suppressed_candidate_total_count > len(suppressed_candidate_evidence),
            "weaknessSemanticTotalCount": weakness_semantic_total_count,
            "weaknessSemanticReturnedCount": len(weakness_semantics),
            "weaknessSemanticResponseLimit": SEMANTIC_EXPANSION_RESPONSE_LIMIT,
            "weaknessSemanticResponseTruncated": weakness_semantic_total_count > len(weakness_semantics),
            "attackSemanticTotalCount": attack_semantic_total_count,
            "attackSemanticReturnedCount": len(attack_semantics),
            "attackSemanticResponseLimit": SEMANTIC_EXPANSION_RESPONSE_LIMIT,
            "attackSemanticResponseTruncated": attack_semantic_total_count > len(attack_semantics),
            "topK": retrieval_policy.final_top_k,
            "topKPolicy": retrieval_policy.top_k_policy(),
            "candidatePoolPolicy": retrieval_policy.candidate_pool_policy(),
            "rerankerPolicy": deterministic_reranker_policy(),
            "rerankersApplied": ["method_trust", "risk_signal_score", "source_kind_tiebreaker"],
            "methodsAttempted": methods_attempted,
            "methodsUsed": methods_used,
            "methodsSucceeded": list(methods_used),
            "filtersApplied": filters_applied,
            "matchedTerms": list(query_terms),
            "relationMethods": relation_methods,
            "embeddingUsed": False,
            "embeddingScope": "none",
            "keywordUsed": any("keyword_match" in (item.get("retrievalMethods") or []) for item in candidate_evidence),
            "profileBoostsApplied": [],
            "projectionState": {"state": "not_applicable", "surface": "ledger_threat_retrieval"},
            "providerState": {"state": "not_applicable", "surface": "ledger_threat_retrieval"},
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
