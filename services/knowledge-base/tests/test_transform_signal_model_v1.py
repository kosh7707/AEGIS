from __future__ import annotations

import copy
import json

import pytest

from app.signals.taxonomy_signals import (
    NO_HIT_FORBIDDEN_EFFECTS,
    SIGNAL_SCHEMA_VERSION,
    SignalModelError,
    contains_offline_quality_language,
    load_signal_manifest,
    method_supports_no_hit,
    method_trust,
    normalize_transform_decision,
    persist_signal_manifest,
    signal_examples,
    validate_signal_manifest,
)
from app.ledger.repository import SQLiteLedgerRepository


EXPECTED_METHODS = {
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
}


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    return repo


def _loads(row, field):
    return json.loads(row[field])


def test_signal_manifest_validates_and_covers_required_methods():
    manifest = load_signal_manifest()

    assert validate_signal_manifest(manifest) == []
    assert manifest["schemaVersion"] == SIGNAL_SCHEMA_VERSION
    assert {signal["method"] for signal in signal_examples(manifest)} >= EXPECTED_METHODS
    assert {signal["method"] for signal in signal_examples(manifest) if signal["observationKind"] == "miss"} >= {
        "keyword_match",
        "embedding_similarity",
    }


def test_method_trust_and_no_hit_support_are_corpus_driven():
    assert method_trust("direct_source_relation") == "strong"
    assert method_trust("provider_range_eval") == "strong_scoped"
    assert method_trust("graph_expansion") == "medium"
    assert method_trust("keyword_match") == "weak"
    assert method_trust("global_embedding_search") == "low"
    assert method_trust("profile_signal") == "context_only"

    assert method_supports_no_hit("provider_range_eval") is True
    assert method_supports_no_hit("keyword_match") is False
    assert method_supports_no_hit("embedding_similarity") is False
    assert method_supports_no_hit("profile_signal") is False


def test_keyword_and_embedding_hits_are_candidate_or_context_only():
    manifest = load_signal_manifest()
    weak_hits = [
        signal
        for signal in signal_examples(manifest)
        if signal["method"] in {"keyword_match", "embedding_similarity", "constrained_embedding_rerank", "global_embedding_search"}
        and signal["observationKind"] == "hit"
    ]

    assert weak_hits
    for signal in weak_hits:
        allowed = set(signal["allowedEffects"])
        forbidden = set(signal["forbiddenEffects"])
        assert "candidate_returned" in allowed
        assert not (allowed & NO_HIT_FORBIDDEN_EFFECTS)
        assert NO_HIT_FORBIDDEN_EFFECTS <= forbidden
        assert signal["consumerPolicy"] in {"contextual_only", "diagnostic_only", "do_not_use_as_negative_evidence"}
        assert signal["consumerPolicy"] != "scoped_no_hit_record_only"


def test_keyword_and_embedding_misses_cannot_become_no_hit_or_negative_evidence():
    manifest = load_signal_manifest()
    misses = [signal for signal in signal_examples(manifest) if signal["observationKind"] == "miss"]

    assert {signal["method"] for signal in misses} == {"keyword_match", "embedding_similarity"}
    for signal in misses:
        assert signal["consumerPolicy"] == "do_not_use_as_negative_evidence"
        assert set(signal["allowedEffects"]) == {"no_candidate_returned"}
        assert NO_HIT_FORBIDDEN_EFFECTS <= set(signal["forbiddenEffects"])
        assert signal["runtimeObservation"]["no_candidate_returned"] is True
        assert signal["runtimeObservation"]["candidate_count"] == 0


def test_profile_signal_is_context_only_and_not_vulnerability_truth():
    manifest = load_signal_manifest()
    profile = next(signal for signal in signal_examples(manifest) if signal["method"] == "profile_signal")

    assert profile["consumerPolicy"] == "contextual_only"
    assert profile["specializationProfiles"] == ["automotive-specialization:can_bus"]
    assert "profile_boost" in profile["allowedEffects"]
    assert NO_HIT_FORBIDDEN_EFFECTS <= set(profile["forbiddenEffects"])


def test_graph_relations_are_distinguishable_from_direct_and_provider_relations(tmp_path):
    repo = _repo(tmp_path)

    report = persist_signal_manifest(repo)

    assert report["decisionsWritten"] == len(signal_examples(load_signal_manifest()))
    assert report["relationsWritten"] == 4
    rows = repo.fetch_all("relation_record")
    methods = {row["method"] for row in rows}
    assert {"direct_source_relation", "curated_mapping", "graph_expansion", "profile_signal"} <= methods

    graph = next(row for row in rows if row["method"] == "graph_expansion")
    graph_provenance = _loads(graph, "provenance_json")
    assert graph_provenance["relationSource"] == "graph_expansion"
    assert graph_provenance["sourceRefs"][0]["sourceKind"] == "projection_graph"

    direct = next(row for row in rows if row["method"] == "direct_source_relation")
    direct_provenance = _loads(direct, "provenance_json")
    assert direct_provenance["relationSource"] == "direct_source"
    assert direct_provenance["sourceRefs"][0]["sourceKind"] == "OSV"


def test_transform_decisions_persist_with_source_refs_confidence_policy_and_diagnostics(tmp_path):
    repo = _repo(tmp_path)
    persist_signal_manifest(repo)

    decisions = repo.fetch_all("transform_decision")
    assert len(decisions) == len(signal_examples(load_signal_manifest()))
    keyword_miss = next(row for row in decisions if row["transform_decision_id"] == "signal:keyword-miss:not-no-hit")
    decision = _loads(keyword_miss, "decision_json")
    diagnostics = _loads(keyword_miss, "diagnostics_json")

    assert keyword_miss["method"] == "keyword_match"
    assert decision["sourceRefs"][0]["sourceKind"] == "runtime_query"
    assert decision["confidence"] == 0.0
    assert decision["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert diagnostics[0]["code"] == "KEYWORD_MISS_NOT_NO_HIT"


def test_invalid_weak_signal_scoped_no_hit_policy_is_rejected():
    manifest = load_signal_manifest()
    mutated = copy.deepcopy(manifest)
    weak_signal = next(signal for signal in mutated["signalExamples"] if signal["method"] == "keyword_match")
    weak_signal["consumerPolicy"] = "scoped_no_hit_record_only"
    weak_signal["allowedEffects"].append("completed_no_hit")

    issues = validate_signal_manifest(mutated)

    assert any("policy scoped_no_hit_record_only is not allowed for method keyword_match" in issue for issue in issues)
    assert any("weak/context signal allows forbidden effects" in issue for issue in issues)
    assert any("weak/context signal cannot use scoped no-hit policy" in issue for issue in issues)


def test_runtime_signal_fixture_has_no_offline_quality_metric_vocabulary():
    manifest = load_signal_manifest()

    assert contains_offline_quality_language(manifest) is False
    mutated = copy.deepcopy(manifest)
    mutated["signalExamples"][0]["runtimeObservation"]["Recall@k"] = 1.0
    assert contains_offline_quality_language(mutated) is True
    assert any("offline quality metric" in issue for issue in validate_signal_manifest(mutated))

    for abbreviation in ("TP", "FP", "FN"):
        abbreviated = copy.deepcopy(manifest)
        abbreviated["signalExamples"][0]["runtimeObservation"][abbreviation] = 1
        assert contains_offline_quality_language(abbreviated) is True
        assert any("offline quality metric" in issue for issue in validate_signal_manifest(abbreviated))

    lexical_false_positive = copy.deepcopy(manifest)
    lexical_false_positive["signalExamples"][0]["runtimeObservation"]["HTTPStatus"] = 200
    assert contains_offline_quality_language(lexical_false_positive) is False


def test_normalize_transform_decision_rejects_invalid_manifest_before_persist(tmp_path):
    manifest = load_signal_manifest()
    normalized = normalize_transform_decision(manifest["signalExamples"][0])

    assert normalized["transformDecisionId"] == manifest["signalExamples"][0]["signalId"]
    assert normalized["decision"]["sourceRefs"]

    repo = _repo(tmp_path)
    mutated = copy.deepcopy(manifest)
    mutated["schemaVersion"] = "bad"
    bad_path = tmp_path / "bad-manifest.json"
    bad_path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(SignalModelError):
        persist_signal_manifest(repo, bad_path)
