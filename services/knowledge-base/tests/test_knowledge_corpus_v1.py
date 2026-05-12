from __future__ import annotations

from app.contracts.acquisition import CONSUMER_POLICIES
from app.corpus.knowledge_corpus import (
    CONTEXT_ONLY_SIGNAL_METHOD_IDS,
    REQUIRED_CORE_TAXONOMY_IDS,
    REQUIRED_PROFILE_IDS,
    REQUIRED_PROFILE_TAGS,
    REQUIRED_PROVENANCE_FIELDS,
    REQUIRED_RELATION_METHOD_IDS,
    WEAK_SIGNAL_METHOD_IDS,
    consumer_policy_ids,
    core_taxonomy_ids,
    load_knowledge_corpus,
    method_by_id,
    profile_by_id,
    profile_ids,
    profile_is_context_only,
    relation_method_ids,
    validate_manifest,
)


def test_knowledge_corpus_manifest_is_schema_valid():
    manifest = load_knowledge_corpus()

    assert validate_manifest(manifest) == []
    assert manifest["schemaVersion"] == "s5-knowledge-corpus-v1"
    assert manifest["corpusVersion"] == "knowledge-corpus-v1"


def test_core_native_system_taxonomy_is_complete_and_not_automotive_only():
    manifest = load_knowledge_corpus()
    ids = core_taxonomy_ids(manifest)

    assert REQUIRED_CORE_TAXONOMY_IDS <= ids
    assert "automotive-specialization" not in ids
    assert "automotive" not in ids
    assert "vehicle" not in ids
    assert "command_execution" in ids
    assert "memory_safety" in ids
    assert "rtos_embedded" in ids


def test_specialization_profiles_are_complete_context_only_and_automotive_default():
    manifest = load_knowledge_corpus()

    assert REQUIRED_PROFILE_IDS <= profile_ids(manifest)
    automotive = profile_by_id(manifest, "automotive-specialization")
    assert automotive is not None
    assert automotive["role"] == "primary-default"
    assert automotive["default"] is True

    for profile_id, required_tags in REQUIRED_PROFILE_TAGS.items():
        profile = profile_by_id(manifest, profile_id)
        tag_ids = {tag["id"] for tag in profile["tags"]}
        assert required_tags <= tag_ids
        assert profile_is_context_only(manifest, profile_id)
        assert profile["consumerPolicy"] == "contextual_only"


def test_relation_methods_and_weak_signal_policy_semantics_are_locked():
    manifest = load_knowledge_corpus()

    assert REQUIRED_RELATION_METHOD_IDS <= relation_method_ids(manifest)
    assert {"exact_id_match", "provider_range_eval", "direct_source_relation"} <= relation_method_ids(manifest)

    for method_id in WEAK_SIGNAL_METHOD_IDS:
        method = method_by_id(manifest, method_id)
        assert method is not None
        assert method["signalStrength"] in {"weak", "low", "medium-low"}
        assert method["canSupportNoHit"] is False
        assert method["canCreateVulnerabilityTruth"] is False
        assert "scoped_no_hit_record_only" not in method["allowedConsumerPolicies"]
        assert set(method["allowedConsumerPolicies"]) <= set(CONSUMER_POLICIES)

    for method_id in CONTEXT_ONLY_SIGNAL_METHOD_IDS:
        method = method_by_id(manifest, method_id)
        assert method is not None
        assert method["signalStrength"] == "context-only"
        assert method["canSupportNoHit"] is False
        assert method["canCreateVulnerabilityTruth"] is False
        assert "scoped_no_hit_record_only" not in method["allowedConsumerPolicies"]


def test_consumer_policies_match_acquisition_contract_exactly():
    manifest = load_knowledge_corpus()

    assert consumer_policy_ids(manifest) == set(CONSUMER_POLICIES)


def test_relation_provenance_schema_contains_s3_required_fields():
    manifest = load_knowledge_corpus()
    required = set(manifest["relationProvenanceSchema"]["requiredFields"])

    assert REQUIRED_PROVENANCE_FIELDS <= required
    assert manifest["relationProvenanceSchema"]["fieldNotes"]["specializationProfiles"].startswith("additive")


def test_legacy_automotive_fields_are_compatibility_only_not_truth():
    manifest = load_knowledge_corpus()
    legacy = manifest["legacyCompatibility"]

    assert legacy["threat_category"]["sourceOfTruth"] is False
    assert legacy["attack_surfaces"]["sourceOfTruth"] is False
    assert legacy["automotive_relevance"]["sourceOfTruth"] is False
    assert legacy["attack_surfaces"]["replacement"] == "specializationProfiles[].tags[]"


def test_validator_rejects_automotive_as_core_taxonomy():
    manifest = load_knowledge_corpus()
    manifest["coreTaxonomy"].append({"id": "automotive", "label": "Automotive as core"})

    issues = validate_manifest(manifest)

    assert any("automotive/domain profile term leaked into core taxonomy" in issue for issue in issues)


def test_validator_rejects_weak_signal_negative_evidence_policy():
    manifest = load_knowledge_corpus()
    method = method_by_id(manifest, "keyword_match")
    method["canSupportNoHit"] = True
    method["allowedConsumerPolicies"].append("scoped_no_hit_record_only")

    issues = validate_manifest(manifest)

    assert any("weak signal method keyword_match cannot support no-hit" in issue for issue in issues)
    assert any("weak signal method keyword_match cannot allow negative-evidence policy" in issue for issue in issues)


def test_semantic_guards_record_g003_boundaries():
    manifest = load_knowledge_corpus()
    guards = manifest["semanticGuards"]

    assert guards["automotiveIsProfileNotCore"] is True
    assert guards["profilesAreAdditiveContextOnly"] is True
    assert guards["profileSignalCannotCreateTruthOrNoHit"] is True
    assert guards["keywordOrEmbeddingMissCannotNoHit"] is True
    assert set(guards["weakMethodsCannotSupportNegativeEvidence"]) == WEAK_SIGNAL_METHOD_IDS
