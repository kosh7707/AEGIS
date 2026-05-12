"""Knowledge Corpus v1 manifest loader and validator.

G003 freezes machine-readable taxonomy/profile assets.  It intentionally does
not run ETL, write the future ledger, rebuild projections, or tune retrieval.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.contracts.acquisition import CONSUMER_POLICIES

DEFAULT_KNOWLEDGE_CORPUS_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "knowledge-corpus-v1" / "manifest.json"

REQUIRED_CORE_TAXONOMY_IDS = {
    "memory_safety",
    "command_execution",
    "input_validation",
    "path_file_access",
    "crypto_tls",
    "authn_authz",
    "network_protocol",
    "parser_serialization",
    "concurrency",
    "resource_lifecycle",
    "credential_secret_exposure",
    "information_exposure_logging",
    "third_party_component",
    "build_supply_chain",
    "firmware_boot_update",
    "os_kernel_driver",
    "rtos_embedded",
    "privilege_boundary",
}

REQUIRED_PROFILE_IDS = {
    "automotive-specialization",
    "embedded-system-specialization",
    "ics-ot-specialization",
}

REQUIRED_PROFILE_TAGS = {
    "automotive-specialization": {
        "can_bus",
        "ecu_gateway",
        "telematics",
        "ivi",
        "ota_vehicle",
        "adas_sensor",
        "charging_infra",
        "vehicle_key_auth",
        "diagnostic_service",
        "in_vehicle_network",
    },
    "embedded-system-specialization": {
        "rtos_tasking",
        "firmware_image",
        "bootloader",
        "secure_boot",
        "mcu_peripheral",
        "cross_compilation",
        "bare_metal",
        "resource_constrained_runtime",
    },
    "ics-ot-specialization": {
        "plc",
        "scada",
        "hmi",
        "modbus",
        "dnp3",
        "opc_ua",
        "iec_62443",
        "industrial_control_network",
    },
}

REQUIRED_RELATION_METHOD_IDS = {
    "exact_id_match",
    "curated_mapping",
    "direct_source_relation",
    "provider_range_eval",
    "graph_expansion",
    "keyword_match",
    "embedding_similarity",
    "constrained_embedding_rerank",
    "global_embedding_search",
    "profile_signal",
}

WEAK_SIGNAL_METHOD_IDS = {
    "keyword_match",
    "embedding_similarity",
    "constrained_embedding_rerank",
    "global_embedding_search",
}

CONTEXT_ONLY_SIGNAL_METHOD_IDS = {"profile_signal"}

REQUIRED_PROVENANCE_FIELDS = {
    "subjectId",
    "predicate",
    "objectId",
    "sourceKind",
    "sourceId",
    "sourceVersion",
    "sourceUrl",
    "method",
    "methodVersion",
    "confidence",
    "taxonomyFamily",
    "specializationProfiles",
    "matchedTerms",
    "score",
    "consumerPolicy",
    "createdAt",
    "freshness",
}

_AUTOMOTIVE_CORE_FORBIDDEN_TERMS = {
    "auto",
    "automotive",
    "vehicle",
    "car",
    "can_bus",
    "ecu",
    "telematics",
    "ivi",
}

_NEGATIVE_EVIDENCE_POLICIES = {"scoped_no_hit_record_only"}


def load_knowledge_corpus(path: Path | str = DEFAULT_KNOWLEDGE_CORPUS_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _objects(manifest: dict[str, Any], key: str) -> list[dict[str, Any]]:
    values = manifest.get(key)
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, dict)]


def _ids(manifest: dict[str, Any], key: str) -> set[str]:
    return {str(value.get("id")) for value in _objects(manifest, key) if value.get("id")}


def core_taxonomy_ids(manifest: dict[str, Any]) -> set[str]:
    return _ids(manifest, "coreTaxonomy")


def profile_ids(manifest: dict[str, Any]) -> set[str]:
    return _ids(manifest, "specializationProfiles")


def relation_method_ids(manifest: dict[str, Any]) -> set[str]:
    return _ids(manifest, "relationMethods")


def consumer_policy_ids(manifest: dict[str, Any]) -> set[str]:
    return _ids(manifest, "consumerPolicies")


def method_by_id(manifest: dict[str, Any], method_id: str) -> dict[str, Any] | None:
    return next((method for method in _objects(manifest, "relationMethods") if method.get("id") == method_id), None)


def profile_by_id(manifest: dict[str, Any], profile_id: str) -> dict[str, Any] | None:
    return next((profile for profile in _objects(manifest, "specializationProfiles") if profile.get("id") == profile_id), None)


def profile_is_context_only(manifest: dict[str, Any], profile_id: str) -> bool:
    profile = profile_by_id(manifest, profile_id) or {}
    return bool(profile.get("contextOnly")) and not bool(profile.get("canCreateVulnerabilityTruth"))


def _profile_tag_ids(profile: dict[str, Any]) -> set[str]:
    return {str(tag.get("id")) for tag in profile.get("tags", []) if isinstance(tag, dict) and tag.get("id")}


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if manifest.get("schemaVersion") != "s5-knowledge-corpus-v1":
        issues.append("schemaVersion must be s5-knowledge-corpus-v1")
    if manifest.get("corpusVersion") != "knowledge-corpus-v1":
        issues.append("corpusVersion must be knowledge-corpus-v1")

    missing_taxonomy = REQUIRED_CORE_TAXONOMY_IDS - core_taxonomy_ids(manifest)
    if missing_taxonomy:
        issues.append(f"missing core taxonomy ids: {sorted(missing_taxonomy)}")

    unexpected_profile_taxonomy = REQUIRED_PROFILE_IDS & core_taxonomy_ids(manifest)
    if unexpected_profile_taxonomy:
        issues.append(f"profile ids must not appear as core taxonomy ids: {sorted(unexpected_profile_taxonomy)}")

    for taxonomy in _objects(manifest, "coreTaxonomy"):
        taxonomy_id = str(taxonomy.get("id", ""))
        taxonomy_tokens = set(re.split(r"[_\\-\\s]+", taxonomy_id.lower()))
        if taxonomy_id.lower() in _AUTOMOTIVE_CORE_FORBIDDEN_TERMS or taxonomy_tokens & _AUTOMOTIVE_CORE_FORBIDDEN_TERMS:
            issues.append(f"automotive/domain profile term leaked into core taxonomy id: {taxonomy_id}")

    missing_profiles = REQUIRED_PROFILE_IDS - profile_ids(manifest)
    if missing_profiles:
        issues.append(f"missing specialization profile ids: {sorted(missing_profiles)}")

    automotive = profile_by_id(manifest, "automotive-specialization") or {}
    if automotive.get("role") != "primary-default" or not automotive.get("default"):
        issues.append("automotive-specialization must be the primary-default profile")

    for profile_id, required_tags in REQUIRED_PROFILE_TAGS.items():
        profile = profile_by_id(manifest, profile_id)
        if not profile:
            continue
        if not profile_is_context_only(manifest, profile_id):
            issues.append(f"{profile_id} must be additive context only and cannot create vulnerability truth")
        missing_tags = required_tags - _profile_tag_ids(profile)
        if missing_tags:
            issues.append(f"{profile_id} missing profile tags: {sorted(missing_tags)}")

    missing_methods = REQUIRED_RELATION_METHOD_IDS - relation_method_ids(manifest)
    if missing_methods:
        issues.append(f"missing relation method ids: {sorted(missing_methods)}")

    context_only_methods = CONTEXT_ONLY_SIGNAL_METHOD_IDS & relation_method_ids(manifest)

    for method in _objects(manifest, "relationMethods"):
        method_id = str(method.get("id", ""))
        policies = set(method.get("allowedConsumerPolicies", [])) if isinstance(method.get("allowedConsumerPolicies"), list) else set()
        if not policies:
            issues.append(f"{method_id}.allowedConsumerPolicies must be non-empty list")
        unknown_policies = policies - set(CONSUMER_POLICIES)
        if unknown_policies:
            issues.append(f"{method_id} references unknown consumer policies: {sorted(unknown_policies)}")
        if method_id in WEAK_SIGNAL_METHOD_IDS:
            if method.get("canSupportNoHit"):
                issues.append(f"weak signal method {method_id} cannot support no-hit")
            if method.get("canCreateVulnerabilityTruth"):
                issues.append(f"weak signal method {method_id} cannot create vulnerability truth")
            if policies & _NEGATIVE_EVIDENCE_POLICIES:
                issues.append(f"weak signal method {method_id} cannot allow negative-evidence policy")
            if method.get("signalStrength") not in {"weak", "low", "medium-low"}:
                issues.append(f"weak signal method {method_id} must have weak/low signalStrength")
        if method_id in context_only_methods:
            if method.get("canSupportNoHit"):
                issues.append(f"context-only signal method {method_id} cannot support no-hit")
            if method.get("canCreateVulnerabilityTruth"):
                issues.append(f"context-only signal method {method_id} cannot create vulnerability truth")
            if policies & _NEGATIVE_EVIDENCE_POLICIES:
                issues.append(f"context-only signal method {method_id} cannot allow negative-evidence policy")
            if method.get("signalStrength") != "context-only":
                issues.append(f"context-only signal method {method_id} must have context-only signalStrength")

    policy_ids = consumer_policy_ids(manifest)
    expected_policy_ids = set(CONSUMER_POLICIES)
    if policy_ids != expected_policy_ids:
        issues.append(f"consumer policy ids must match acquisition contract: missing={sorted(expected_policy_ids - policy_ids)} extra={sorted(policy_ids - expected_policy_ids)}")

    provenance_schema = manifest.get("relationProvenanceSchema")
    if not isinstance(provenance_schema, dict):
        issues.append("relationProvenanceSchema must be object")
    else:
        required = set(provenance_schema.get("requiredFields", [])) if isinstance(provenance_schema.get("requiredFields"), list) else set()
        missing_fields = REQUIRED_PROVENANCE_FIELDS - required
        if missing_fields:
            issues.append(f"relation provenance schema missing fields: {sorted(missing_fields)}")

    legacy = manifest.get("legacyCompatibility")
    if not isinstance(legacy, dict):
        issues.append("legacyCompatibility must be object")
    else:
        for field in ("threat_category", "attack_surfaces", "automotive_relevance"):
            detail = legacy.get(field)
            if not isinstance(detail, dict):
                issues.append(f"legacyCompatibility.{field} must be object")
            elif detail.get("sourceOfTruth") is not False:
                issues.append(f"legacyCompatibility.{field}.sourceOfTruth must be false")

    return issues
