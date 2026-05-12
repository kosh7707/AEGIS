"""Knowledge corpus v1 assets and validation."""

from .knowledge_corpus import (
    CONTEXT_ONLY_SIGNAL_METHOD_IDS,
    DEFAULT_KNOWLEDGE_CORPUS_PATH,
    REQUIRED_CORE_TAXONOMY_IDS,
    REQUIRED_PROFILE_IDS,
    REQUIRED_PROVENANCE_FIELDS,
    REQUIRED_RELATION_METHOD_IDS,
    WEAK_SIGNAL_METHOD_IDS,
    core_taxonomy_ids,
    consumer_policy_ids,
    load_knowledge_corpus,
    method_by_id,
    profile_ids,
    profile_is_context_only,
    relation_method_ids,
    validate_manifest,
)

__all__ = [
    "CONTEXT_ONLY_SIGNAL_METHOD_IDS",
    "DEFAULT_KNOWLEDGE_CORPUS_PATH",
    "REQUIRED_CORE_TAXONOMY_IDS",
    "REQUIRED_PROFILE_IDS",
    "REQUIRED_PROVENANCE_FIELDS",
    "REQUIRED_RELATION_METHOD_IDS",
    "WEAK_SIGNAL_METHOD_IDS",
    "core_taxonomy_ids",
    "consumer_policy_ids",
    "load_knowledge_corpus",
    "method_by_id",
    "profile_ids",
    "profile_is_context_only",
    "relation_method_ids",
    "validate_manifest",
]
