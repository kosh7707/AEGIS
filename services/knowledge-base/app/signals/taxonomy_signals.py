"""Transform-decision and taxonomy signal model v1.

G006 keeps matching signals explicit and evidence-safe.  Keyword/embedding
signals are candidate/context observations; misses do not become no-hit.  This
module validates fixture signal examples and persists them as ledger transform
_decision rows without rebuilding Neo4j/Qdrant projections.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.contracts.acquisition import CONSUMER_POLICIES, OFFLINE_QUALITY_VOCABULARY
from app.corpus.knowledge_corpus import (
    CONTEXT_ONLY_SIGNAL_METHOD_IDS,
    DEFAULT_KNOWLEDGE_CORPUS_PATH,
    WEAK_SIGNAL_METHOD_IDS,
    load_knowledge_corpus,
    method_by_id,
    relation_method_ids,
    validate_manifest as validate_knowledge_corpus,
)
from app.ledger.repository import SQLiteLedgerRepository

DEFAULT_SIGNAL_MANIFEST_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "transform-signals-v1" / "manifest.json"
SIGNAL_SCHEMA_VERSION = "s5-transform-signal-model-v1"
SIGNAL_MODEL_VERSION = "transform-signals-v1"

REQUIRED_SIGNAL_FIELDS = {
    "signalId",
    "observationKind",
    "inputId",
    "method",
    "confidence",
    "consumerPolicy",
    "sourceRefs",
    "taxonomyFamily",
    "specializationProfiles",
    "matchedTerms",
    "evidenceSpans",
    "allowedEffects",
    "forbiddenEffects",
    "runtimeObservation",
    "diagnostics",
}
REQUIRED_SOURCE_REF_FIELDS = {"sourceKind", "sourceId", "sourceVersion", "sourceUrl", "rawArtifactId"}
REQUIRED_RELATION_FIELDS = {"subjectId", "predicate", "objectId"}
WEAK_OR_CONTEXT_METHOD_IDS = WEAK_SIGNAL_METHOD_IDS | CONTEXT_ONLY_SIGNAL_METHOD_IDS
NO_HIT_FORBIDDEN_EFFECTS = {"completed_no_hit", "clean_pass", "negative_evidence", "vulnerability_truth"}
OFFLINE_QUALITY_ABBREVIATIONS = {"TP", "FP", "FN"}
WEAK_ALLOWED_EFFECTS = {
    "candidate_returned",
    "no_candidate_returned",
    "contextual_tag",
    "retrieval_candidate",
    "ranking_hint",
    "diagnostic_trace",
    "profile_boost",
}
_DIRECT_SOURCE_KINDS = {
    "CWE",
    "CAPEC",
    "ATTACK_ICS",
    "ATTACK_ENTERPRISE",
    "OSV",
    "NVD_CVE",
    "GHSA",
    "CISA_KEV",
    "FIRST_EPSS",
    "semgrep",
    "cppcheck",
    "clang-tidy",
    "gcc-fanalyzer",
    "scan-build",
    "flawfinder",
    "package-identity",
}


class SignalModelError(ValueError):
    """Raised when a transform signal manifest violates G006 safety rules."""


def load_signal_manifest(path: Path | str = DEFAULT_SIGNAL_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def signal_examples(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    values = manifest.get("signalExamples")
    return values if isinstance(values, list) else []


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _as_strings(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value}


def _walk_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        strings: list[str] = []
        for key, item in value.items():
            strings.append(str(key))
            strings.extend(_walk_strings(item))
        return strings
    if isinstance(value, list):
        strings = []
        for item in value:
            strings.extend(_walk_strings(item))
        return strings
    if isinstance(value, str):
        return [value]
    return []


def contains_offline_quality_language(value: Any) -> bool:
    strings = _walk_strings(value)
    haystack = "\n".join(strings).lower()
    if any(term.lower() in haystack for term in OFFLINE_QUALITY_VOCABULARY):
        return True
    token_pattern = re.compile(r"(?<![A-Za-z0-9_])(?:TP|FP|FN)(?![A-Za-z0-9_])")
    return any(token_pattern.search(item) for item in strings)


def method_trust(method_id: str, corpus: dict[str, Any] | None = None) -> str:
    corpus = corpus or load_knowledge_corpus(DEFAULT_KNOWLEDGE_CORPUS_PATH)
    method = method_by_id(corpus, method_id)
    if not method:
        return "unknown"
    return str(method.get("signalStrength", "unknown")).replace("-", "_")


def method_supports_no_hit(method_id: str, corpus: dict[str, Any] | None = None) -> bool:
    corpus = corpus or load_knowledge_corpus(DEFAULT_KNOWLEDGE_CORPUS_PATH)
    method = method_by_id(corpus, method_id)
    return bool(method and method.get("canSupportNoHit"))


def _relation_source_kind(signal: dict[str, Any]) -> str:
    refs = _objects(signal.get("sourceRefs"))
    if not refs:
        return ""
    return str(refs[0].get("sourceKind", ""))


def _validate_signal(signal: dict[str, Any], *, corpus: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    signal_id = str(signal.get("signalId", "<missing>"))
    missing = REQUIRED_SIGNAL_FIELDS - set(signal)
    if missing:
        issues.append(f"{signal_id} missing signal fields: {sorted(missing)}")

    method_id = str(signal.get("method", ""))
    method = method_by_id(corpus, method_id)
    if method is None:
        issues.append(f"{signal_id} references unknown method: {method_id}")
        return issues

    policy = str(signal.get("consumerPolicy", ""))
    if policy not in CONSUMER_POLICIES:
        issues.append(f"{signal_id} references unknown consumerPolicy: {policy}")
    allowed_policies = set(method.get("allowedConsumerPolicies", [])) if isinstance(method.get("allowedConsumerPolicies"), list) else set()
    if policy and policy not in allowed_policies:
        issues.append(f"{signal_id} policy {policy} is not allowed for method {method_id}")

    confidence = signal.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
        issues.append(f"{signal_id}.confidence must be a number in [0, 1]")
    score = signal.get("score")
    if score is not None and (not isinstance(score, (int, float)) or not 0 <= float(score) <= 1):
        issues.append(f"{signal_id}.score must be a number in [0, 1]")

    source_refs = _objects(signal.get("sourceRefs"))
    if not source_refs:
        issues.append(f"{signal_id}.sourceRefs must be a non-empty list")
    for idx, ref in enumerate(source_refs):
        missing_ref = REQUIRED_SOURCE_REF_FIELDS - set(ref)
        if missing_ref:
            issues.append(f"{signal_id}.sourceRefs[{idx}] missing fields: {sorted(missing_ref)}")

    allowed_effects = _as_strings(signal.get("allowedEffects"))
    forbidden_effects = _as_strings(signal.get("forbiddenEffects"))
    if method_id in WEAK_OR_CONTEXT_METHOD_IDS:
        forbidden_allowed = allowed_effects & NO_HIT_FORBIDDEN_EFFECTS
        if forbidden_allowed:
            issues.append(f"{signal_id} weak/context signal allows forbidden effects: {sorted(forbidden_allowed)}")
        unexpected_allowed = allowed_effects - WEAK_ALLOWED_EFFECTS
        if unexpected_allowed:
            issues.append(f"{signal_id} weak/context signal has unexpected allowed effects: {sorted(unexpected_allowed)}")
        missing_forbidden = NO_HIT_FORBIDDEN_EFFECTS - forbidden_effects
        if missing_forbidden:
            issues.append(f"{signal_id} weak/context signal must forbid: {sorted(missing_forbidden)}")
        if policy == "scoped_no_hit_record_only":
            issues.append(f"{signal_id} weak/context signal cannot use scoped no-hit policy")

    observation_kind = str(signal.get("observationKind", ""))
    if observation_kind not in {"hit", "miss"}:
        issues.append(f"{signal_id}.observationKind must be hit or miss")
    if observation_kind == "miss" and method_id in {"keyword_match", "embedding_similarity"}:
        missing_forbidden = NO_HIT_FORBIDDEN_EFFECTS - forbidden_effects
        if missing_forbidden:
            issues.append(f"{signal_id} keyword/embedding miss does not forbid all no-hit effects")
        if policy not in {"diagnostic_only", "do_not_use_as_negative_evidence"}:
            issues.append(f"{signal_id} keyword/embedding miss must be diagnostic or do-not-use-as-negative-evidence")

    if method_id == "graph_expansion":
        if _relation_source_kind(signal) != "projection_graph":
            issues.append(f"{signal_id} graph_expansion sourceKind must be projection_graph")
        if "relation" not in signal:
            issues.append(f"{signal_id} graph_expansion must include relation")
    if method_id in {"direct_source_relation", "curated_mapping"} and _relation_source_kind(signal) == "projection_graph":
        issues.append(f"{signal_id} direct/curated relation cannot use projection_graph sourceKind")
    if method_id == "provider_range_eval" and _relation_source_kind(signal) == "projection_graph":
        issues.append(f"{signal_id} provider_range_eval cannot use projection_graph sourceKind")

    if method_id == "profile_signal":
        if not signal.get("specializationProfiles"):
            issues.append(f"{signal_id} profile_signal must include specializationProfiles")
        if policy not in {"contextual_only", "diagnostic_only"}:
            issues.append(f"{signal_id} profile_signal must be contextual or diagnostic only")

    relation = signal.get("relation")
    if relation is not None:
        if not isinstance(relation, dict):
            issues.append(f"{signal_id}.relation must be object")
        else:
            missing_relation = REQUIRED_RELATION_FIELDS - set(relation)
            if missing_relation:
                issues.append(f"{signal_id}.relation missing fields: {sorted(missing_relation)}")

    return issues


def validate_signal_manifest(
    manifest: dict[str, Any],
    corpus: dict[str, Any] | None = None,
) -> list[str]:
    issues: list[str] = []
    if manifest.get("schemaVersion") != SIGNAL_SCHEMA_VERSION:
        issues.append(f"schemaVersion must be {SIGNAL_SCHEMA_VERSION}")
    if manifest.get("signalModelVersion") != SIGNAL_MODEL_VERSION:
        issues.append(f"signalModelVersion must be {SIGNAL_MODEL_VERSION}")
    if contains_offline_quality_language(manifest):
        issues.append("signal manifest must not contain offline quality metric vocabulary")

    corpus = corpus or load_knowledge_corpus(DEFAULT_KNOWLEDGE_CORPUS_PATH)
    corpus_issues = validate_knowledge_corpus(corpus)
    if corpus_issues:
        issues.extend(f"knowledge corpus invalid: {issue}" for issue in corpus_issues)

    examples = signal_examples(manifest)
    if not examples:
        issues.append("signalExamples must be a non-empty list")
        return issues

    methods_seen = {str(example.get("method")) for example in examples if isinstance(example, dict)}
    missing_required_examples = {
        "direct_source_relation",
        "provider_range_eval",
        "exact_id_match",
        "curated_mapping",
        "graph_expansion",
        "keyword_match",
        "embedding_similarity",
        "constrained_embedding_rerank",
        "global_embedding_search",
        "profile_signal",
    } - methods_seen
    if missing_required_examples:
        issues.append(f"signalExamples missing methods: {sorted(missing_required_examples)}")
    unknown_methods = methods_seen - relation_method_ids(corpus)
    if unknown_methods:
        issues.append(f"signalExamples reference unknown methods: {sorted(unknown_methods)}")

    miss_methods_seen = {str(example.get("method")) for example in examples if example.get("observationKind") == "miss"}
    if not {"keyword_match", "embedding_similarity"} <= miss_methods_seen:
        issues.append("keyword_match and embedding_similarity miss examples are required")

    for signal in examples:
        if not isinstance(signal, dict):
            issues.append("signalExamples entries must be objects")
            continue
        issues.extend(_validate_signal(signal, corpus=corpus))

    return issues


def normalize_transform_decision(signal: dict[str, Any], *, signal_model_version: str = SIGNAL_MODEL_VERSION) -> dict[str, Any]:
    signal_id = str(signal["signalId"])
    decision_json = {
        "schemaVersion": SIGNAL_SCHEMA_VERSION,
        "signalModelVersion": signal_model_version,
        "signalId": signal_id,
        "observationKind": signal.get("observationKind"),
        "method": signal.get("method"),
        "confidence": signal.get("confidence"),
        "score": signal.get("score"),
        "sourceRefs": signal.get("sourceRefs", []),
        "matchedTerms": signal.get("matchedTerms", []),
        "evidenceSpans": signal.get("evidenceSpans", []),
        "taxonomyFamily": signal.get("taxonomyFamily"),
        "specializationProfiles": signal.get("specializationProfiles", []),
        "consumerPolicy": signal.get("consumerPolicy"),
        "allowedEffects": signal.get("allowedEffects", []),
        "forbiddenEffects": signal.get("forbiddenEffects", []),
        "runtimeObservation": signal.get("runtimeObservation", {}),
        "relation": signal.get("relation"),
    }
    diagnostics = signal.get("diagnostics", [])
    return {
        "transformDecisionId": signal_id,
        "inputId": str(signal.get("inputId")),
        "outputId": signal.get("outputId"),
        "method": str(signal.get("method")),
        "decision": decision_json,
        "diagnostics": diagnostics if isinstance(diagnostics, list) else [diagnostics],
    }


def _relation_record_id(signal: dict[str, Any]) -> str:
    output_id = signal.get("outputId")
    if isinstance(output_id, str) and output_id.startswith("relation:"):
        return output_id
    return f"relation:{signal['signalId']}"


def _relation_source(method: str) -> str:
    if method == "graph_expansion":
        return "graph_expansion"
    if method == "provider_range_eval":
        return "provider_range_eval"
    if method == "curated_mapping":
        return "curated_mapping"
    if method == "profile_signal":
        return "profile_signal"
    return "direct_source"


def persist_signal_manifest(
    repo: SQLiteLedgerRepository,
    manifest_path: Path | str = DEFAULT_SIGNAL_MANIFEST_PATH,
    *,
    corpus_path: Path | str = DEFAULT_KNOWLEDGE_CORPUS_PATH,
) -> dict[str, Any]:
    repo.initialize()
    manifest = load_signal_manifest(manifest_path)
    corpus = load_knowledge_corpus(corpus_path)
    issues = validate_signal_manifest(manifest, corpus)
    if issues:
        raise SignalModelError(f"Invalid transform signal manifest: {issues}")

    decisions_written = 0
    relations_written = 0
    for signal in signal_examples(manifest):
        normalized = normalize_transform_decision(signal, signal_model_version=str(manifest["signalModelVersion"]))
        repo.upsert_transform_decision(
            transform_decision_id=normalized["transformDecisionId"],
            input_id=normalized["inputId"],
            output_id=normalized["outputId"],
            method=normalized["method"],
            decision=normalized["decision"],
            diagnostics=normalized["diagnostics"],
        )
        decisions_written += 1

        relation = signal.get("relation")
        if isinstance(relation, dict):
            method = str(signal["method"])
            repo.upsert_relation_record(
                relation_record_id=_relation_record_id(signal),
                subject_id=str(relation["subjectId"]),
                predicate=str(relation["predicate"]),
                object_id=str(relation["objectId"]),
                method=method,
                consumer_policy=str(signal["consumerPolicy"]),
                provenance={
                    "schemaVersion": SIGNAL_SCHEMA_VERSION,
                    "signalModelVersion": manifest["signalModelVersion"],
                    "signalId": signal["signalId"],
                    "relationSource": _relation_source(method),
                    "method": method,
                    "confidence": signal.get("confidence"),
                    "sourceRefs": signal.get("sourceRefs", []),
                    "taxonomyFamily": signal.get("taxonomyFamily"),
                    "specializationProfiles": signal.get("specializationProfiles", []),
                    "matchedTerms": signal.get("matchedTerms", []),
                    "score": signal.get("score"),
                    "consumerPolicy": signal.get("consumerPolicy"),
                },
            )
            relations_written += 1

    return {
        "schemaVersion": SIGNAL_SCHEMA_VERSION,
        "signalModelVersion": manifest["signalModelVersion"],
        "decisionsWritten": decisions_written,
        "relationsWritten": relations_written,
        "methodsCovered": sorted({str(signal.get("method")) for signal in signal_examples(manifest)}),
    }
