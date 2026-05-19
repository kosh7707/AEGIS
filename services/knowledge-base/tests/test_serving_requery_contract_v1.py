from __future__ import annotations

import json

from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.judge.models import JudgeQueryRequest
from app.judge.service import _decision_cache_revision_hash, build_judge_answer, validate_judge_answer
from app.ledger.repository import SQLiteLedgerRepository
from app.serving import reset_decision_cache
from app.serving.query_planner import build_canonical_query
from app.source_kg.models import SourceCodeKgIngestRequest
from app.source_kg.service import ingest_source_kg


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo)
    return repo


def _source_context(repo):
    payload = {
        "schemaVersion": "s5-source-code-kg-ingest-request-v1",
        "repositorySnapshot": {"repositoryUrl": "https://example/curl.git", "repositoryId": "curl", "commitHash": "c1", "treeHash": "t1"},
        "buildContext": {"projectId": "re100", "targetId": "re100:http", "buildTarget": "http", "dependencyGraph": {"libraries": [{"name": "curl", "version": "8.0.0"}]}},
        "analysisArtifactSet": {"analyzerName": "fixture", "artifactHashes": {"callgraph": "sha256:cg"}},
        "evidenceSnippets": [{"evidenceSnippetId": "snippet-curl", "filePath": "http.cpp", "snippetText": "curl_easy_perform(h);"}],
        "graphNodes": [{"nodeKind": "function", "stableId": "func:perform", "displayName": "perform", "evidenceSnippetId": "snippet-curl"}],
        "graphEdges": [],
        "richIrArtifacts": [{"artifactKind": "symbol_table", "checksumSha256": "sha256:" + "2" * 64}],
    }
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(payload)).model_dump(by_alias=True)
    return {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "graphNodeIds": result["ids"]["sourceGraphNodeIds"],
        "evidenceSnippetIds": result["ids"]["evidenceSnippetIds"],
        "richIrArtifactIds": result["ids"]["richIrArtifactIds"],
    }


def _request(question, source_context, *, controls=None, version="8.0.0"):
    return JudgeQueryRequest.model_validate({
        "schemaVersion": "s5-judge-query-v1",
        "question": question,
        "component": {"name": "curl", "version": version, "purl": f"pkg:generic/curl@{version}"},
        "sourceContext": source_context,
        "controls": controls or {},
    })


def test_canonical_query_normalizes_noisy_question_text():
    base = {
        "component": {"name": " CURL ", "version": " 8.0.0 ", "purl": " pkg:generic/curl@8.0.0 "},
        "sourceContext": {"repositorySnapshotId": " snap ", "buildContextId": " build ", "analysisArtifactSetId": " analysis "},
        "controls": {"answerMode": "evidence_grounded"},
    }
    q1 = build_canonical_query({**base, "question": "Please tell me if CURL 8.0.0 is affected in this build target"})
    q2 = build_canonical_query({**base, "question": "affected curl 8.0.0 build target please please"})

    assert q1["canonicalQueryId"] == q2["canonicalQueryId"]
    assert q1["decisionFragmentKey"] == q2["decisionFragmentKey"]
    assert q1["normalized"]["component"]["name"] == "curl"
    assert q1["normalized"]["sourceContext"]["repositorySnapshotId"] == "snap"


def test_decision_cache_revision_hash_uses_compact_table_summaries_not_full_fetch(tmp_path, monkeypatch):
    repo = _repo(tmp_path)

    def _fail_full_table_fetch(table):
        raise AssertionError(f"revision hash must not full-fetch table {table}")

    monkeypatch.setattr(repo, "fetch_all", _fail_full_table_fetch)

    revision_hash = _decision_cache_revision_hash(repo)

    assert revision_hash.startswith("sha256:")


def test_decision_cache_revision_hash_changes_when_revision_table_changes(tmp_path):
    repo = _repo(tmp_path)
    before = _decision_cache_revision_hash(repo)

    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-3131",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-3131",
        payload={"externalId": "CVE-2099-3131", "aliases": ["CVE-2099-3131"], "packageIdentityId": "pkg:generic/curl"},
        freshness={"fixture": True},
    )

    assert _decision_cache_revision_hash(repo) != before


def test_changed_exclude_control_changes_key_and_prevents_resurrection(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    normal = build_judge_answer(repo, _request("curl affected", source))
    excluded = build_judge_answer(repo, _request("curl affected", source, controls={"exclude": [" cve-2026-0001 "], "answerMode": "alternatives_without_excluded"}))

    assert normal["decisionFragmentKey"] != excluded["decisionFragmentKey"]
    assert normal["verdict"] == "affected"
    assert excluded["verdict"] == "unknown"
    assert excluded["evidence"]["affectedness"] == []
    assert excluded["evidence"]["suppressedAffectedness"]
    assert "CVE-2026-0001" in excluded["controlEffects"][0]["suppressedExternalIds"]
    assert validate_judge_answer(excluded) == []


def test_unsupported_controls_are_rejected_not_silently_dropped(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"prefer": ["magic"], "answerMode": "oracle_mode", "mysteryControl": True}))

    assert {item["control"] for item in answer["appliedControls"]["rejected"]} == {"prefer", "answerMode", "mysteryControl"}
    assert answer["fallbackTrace"]
    assert any(item["fallback"] == "unsupported_controls_rejected" for item in answer["fallbackTrace"])
    assert validate_judge_answer(answer) == []


def test_force_context_is_echoed_in_canonical_query_and_answer(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    controls = {"prefer": ["targetContext"], "forceContext": {"targetId": "re100:http", "repositorySnapshotId": source["repositorySnapshotId"]}, "answerMode": "strict_target_context"}
    answer = build_judge_answer(repo, _request("curl affected", source, controls=controls))

    assert answer["canonicalQuery"]["normalized"]["controls"]["forceContext"]["targetId"] == "re100:http"
    assert answer["appliedControls"]["accepted"]["forceContext"]["repositorySnapshotId"] == source["repositorySnapshotId"]
    assert answer["canonicalQuery"]["normalized"]["answerMode"] == "strict_target_context"


def test_topk_changes_decision_fragment_key_and_is_not_silently_dropped(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    top_one = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    top_two = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 2}))

    assert top_one["decisionFragmentKey"] != top_two["decisionFragmentKey"]
    assert top_one["canonicalQuery"]["normalized"]["controls"]["topK"] == 1
    assert top_two["canonicalQuery"]["normalized"]["controls"]["topK"] == 2
    assert top_one["appliedControls"]["accepted"]["topK"] == 1
    assert not any(item.get("fallback") == "unsupported_controls_rejected" for item in top_one["fallbackTrace"])
    assert len(top_one["evidence"]["threatRetrieval"]["candidateEvidence"]) == 1
    assert len(top_two["evidence"]["threatRetrieval"]["candidateEvidence"]) == 2


def test_invalid_topk_is_rejected_without_crashing(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 0}))

    assert answer["verdict"] == "affected"
    assert {item["control"] for item in answer["appliedControls"]["rejected"]} == {"topK"}
    assert any(item.get("fallback") == "unsupported_controls_rejected" for item in answer["fallbackTrace"])
    assert answer["evidence"]["threatRetrieval"]["retrievalTrace"]["topK"] == 5
    assert validate_judge_answer(answer) == []


def test_oversized_invalid_topk_rejection_does_not_echo_raw_control_value(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    oversized_top_k = "not-an-int-" + ("x" * 100_000)

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": oversized_top_k}))
    serialized = json.dumps(answer, ensure_ascii=False)

    assert answer["verdict"] == "affected"
    rejected = answer["appliedControls"]["rejected"]
    assert {item["control"] for item in rejected} == {"topK"}
    assert rejected[0]["value"] == {"redacted": True, "type": "str", "length": len(oversized_top_k)}
    assert oversized_top_k not in serialized
    assert len(serialized) < 100_000
    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row is not None
    assert oversized_top_k not in json.dumps(row["request"], ensure_ascii=False)
    assert oversized_top_k not in json.dumps(row["answer"], ensure_ascii=False)
    assert answer["evidence"]["threatRetrieval"]["retrievalTrace"]["topK"] == 5
    assert validate_judge_answer(answer) == []


def test_oversized_control_strings_are_rejected_or_redacted_across_control_echoes(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    huge = "control-" + ("x" * 100_000)
    controls = {
        "exclude": ["CVE-2026-0001", huge],
        "prefer": ["threatKb", huge],
        "forceContext": {"targetId": "re100:http", "note": huge},
        "answerMode": huge,
        "mysteryControl": huge,
    }

    answer = build_judge_answer(repo, _request("curl affected", source, controls=controls))
    serialized = json.dumps(answer, ensure_ascii=False)

    assert huge not in serialized
    assert len(serialized) < 100_000
    assert "CVE-2026-0001" in answer["appliedControls"]["accepted"]["exclude"]
    assert "threatKb" in answer["appliedControls"]["accepted"]["prefer"]
    assert answer["appliedControls"]["accepted"]["forceContext"] == {}
    rejected = answer["appliedControls"]["rejected"]
    assert {(item["control"], item["reason"]) for item in rejected} >= {
        ("exclude", "control_value_too_long"),
        ("prefer", "control_value_too_long"),
        ("forceContext", "control_value_too_long"),
        ("answerMode", "control_value_too_long"),
        ("mysteryControl", "unsupported_control"),
    }
    assert all(huge not in json.dumps(item, ensure_ascii=False) for item in rejected)
    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row is not None
    assert huge not in json.dumps(row["request"], ensure_ascii=False)
    assert huge not in json.dumps(row["answer"], ensure_ascii=False)
    assert validate_judge_answer(answer) == []


def test_oversized_control_object_keys_are_rejected_or_redacted_across_control_echoes(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    huge_key = "control-key-" + ("x" * 100_000)
    controls = {
        huge_key: "value",
        "forceContext": {huge_key: "value", "targetId": "re100:http"},
    }

    answer = build_judge_answer(repo, _request("curl affected", source, controls=controls))
    serialized = json.dumps(answer, ensure_ascii=False)

    assert huge_key not in serialized
    assert len(serialized) < 100_000
    assert answer["appliedControls"]["accepted"]["forceContext"] == {}
    rejected = answer["appliedControls"]["rejected"]
    assert any(item["reason"] == "unsupported_control" and item["control"]["redacted"] is True for item in rejected)
    assert any((item["control"], item["reason"]) == ("forceContext", "control_value_too_long") for item in rejected)
    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row is not None
    assert huge_key not in json.dumps(row["request"], ensure_ascii=False)
    assert huge_key not in json.dumps(row["answer"], ensure_ascii=False)
    assert validate_judge_answer(answer) == []


def test_many_small_unknown_control_echoes_are_byte_budgeted(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    def padded_value(index: int) -> str:
        prefix = f"unknown-control-byte-budget-{index:04d}-"
        return prefix + ("x" * (512 - len(prefix)))

    values = {f"k{index:03d}": padded_value(index) for index in range(128)}
    last_value = values["k127"]

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"unknownControl": values}))
    serialized = json.dumps(answer, ensure_ascii=False)

    assert len(serialized) < 50_000
    assert last_value not in serialized
    rejected = answer["appliedControls"]["rejected"]
    assert rejected == [
        {
            "control": "unknownControl",
            "value": {
                "redacted": True,
                "type": "object",
                "length": 128,
                "reason": "control_object_too_large",
            },
            "reason": "unsupported_control",
        }
    ]
    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row is not None
    assert last_value not in json.dumps(row["request"], ensure_ascii=False)
    assert last_value not in json.dumps(row["answer"], ensure_ascii=False)
    assert validate_judge_answer(answer) == []


def test_judge_decision_cache_is_namespaced_by_ledger_identity(tmp_path):
    reset_decision_cache()
    repo_a = _repo(tmp_path / "repo-a")
    source = _source_context(repo_a)
    first = build_judge_answer(repo_a, _request("curl affected", source))

    repo_b = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 'repo-b' / 's5-ledger.sqlite'}")
    repo_b.initialize()
    second = build_judge_answer(repo_b, _request("curl affected", source))

    assert first["verdict"] == "affected"
    assert first["cacheTrace"]["stored"] is True
    assert second["cacheTrace"]["hit"] is False
    assert second["verdict"] == "unknown"
    assert second["evidence"]["affectedness"] == []
    assert validate_judge_answer(second) == []


def test_decision_cache_hit_is_visible_on_repeat(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    first = build_judge_answer(repo, _request("curl affected", source))
    second = build_judge_answer(repo, _request("curl affected", source))

    assert first["cacheTrace"]["hit"] is False
    assert first["cacheTrace"]["stored"] is True
    assert second["cacheTrace"]["hit"] is True
    assert second["cacheTrace"]["stored"] is False
    assert second["cacheTrace"]["cacheScope"] == "ledger"
    assert second["cacheTrace"]["cacheRevisionHash"] == first["cacheTrace"]["cacheRevisionHash"]
    assert second["decisionFragmentKey"] == first["decisionFragmentKey"]
    assert second["qualityGate"]["scorePolicy"]["policyHash"].startswith("sha256:")


def test_decision_cache_misses_after_affectedness_row_update(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    first = build_judge_answer(repo, _request("curl affected", source))
    for affectedness_record in first["evidence"]["affectedness"]:
        repo.upsert_affectedness_record(
            affectedness_id=affectedness_record["affectednessId"],
            advisory_id=affectedness_record["advisoryId"],
            subject_kind="package_identity",
            subject_id=affectedness_record["subjectId"],
            affectedness_status="affected",
            introduced="9.0.0",
            fixed="10.0.0",
            range_data={"introduced": "9.0.0", "fixed": "10.0.0"},
            qualifiers={"sourceKind": "regression-fixture"},
            evidence={"source": "same-ledger-cache-invalidation-test"},
            confidence=0.95,
            decision_state="accepted",
            provenance={"source": "same-ledger-cache-invalidation-test"},
        )

    second = build_judge_answer(repo, _request("curl affected", source))

    assert first["verdict"] == "affected"
    assert second["cacheTrace"]["hit"] is False
    assert second["cacheTrace"]["cacheRevisionHash"] != first["cacheTrace"]["cacheRevisionHash"]
    assert second["verdict"] == "not_affected"
    assert {item["range"]["introduced"] for item in second["evidence"]["affectedness"]} == {"9.0.0"}
    assert validate_judge_answer(second) == []


def test_decision_cache_revision_changes_after_relation_record_update(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    first = build_judge_answer(repo, _request("curl affected", source))

    repo.upsert_relation_record(
        relation_record_id="relation:cache-revision:advisory-attack",
        subject_id=first["evidence"]["affectedness"][0]["advisoryId"],
        predicate="related_attack_pattern",
        object_id="T1059",
        method="critic-regression",
        consumer_policy="contextual_support_not_affectedness_proof",
        provenance={"source": "cache-revision-regression"},
    )

    second = build_judge_answer(repo, _request("curl affected", source))

    assert first["cacheTrace"]["stored"] is True
    assert second["cacheTrace"]["hit"] is False
    assert second["cacheTrace"]["cacheRevisionHash"] != first["cacheTrace"]["cacheRevisionHash"]
    assert validate_judge_answer(second) == []


def test_conflict_recording_does_not_self_invalidate_decision_cache_revision(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_affectedness_record(
        affectedness_id="affectedness:test:not-affected-cache",
        advisory_id="advisory:NVD_CVE:CVE-2026-0001",
        subject_kind="package_identity",
        subject_id="pkg:generic/curl",
        affectedness_status="known_not_affected",
        introduced="0",
        fixed="7.0.0",
        range_data={"range": "<7.0.0"},
        confidence=0.9,
        decision_state="accepted",
        provenance={"test": "conflict-cache-revision"},
    )

    first = build_judge_answer(repo, _request("curl affected", source))
    post_first_revision = _decision_cache_revision_hash(repo)
    second = build_judge_answer(repo, _request("curl affected", source))
    third = build_judge_answer(repo, _request("curl affected", source))

    assert first["qualityGate"]["gate"] == "rejected"
    assert first["uncertainty"]["conflicts"]
    assert first["cacheTrace"]["hit"] is False
    assert first["cacheTrace"]["cacheRevisionHash"] == post_first_revision
    assert second["cacheTrace"]["hit"] is True
    assert third["cacheTrace"]["hit"] is True
    assert {
        first["cacheTrace"]["cacheRevisionHash"],
        second["cacheTrace"]["cacheRevisionHash"],
        third["cacheTrace"]["cacheRevisionHash"],
    } == {post_first_revision}
    assert validate_judge_answer(third) == []


def test_unresolved_source_context_is_visible_fallback_and_grounded_unknown(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = {"repositorySnapshotId": "missing", "buildContextId": "missing", "analysisArtifactSetId": "missing"}
    answer = build_judge_answer(repo, _request("curl affected", source, version=""))

    assert answer["verdict"] == "unknown"
    assert answer["fallbackTrace"]
    assert any(item["fallback"] == "unresolved_context" for item in answer["fallbackTrace"])
    assert answer["cacheTrace"]["reason"] == "missing_inputs_not_cached"
    assert answer["cacheTrace"]["cacheScope"] == "ledger"
    assert answer["cacheTrace"]["cacheScopeHash"].startswith("sha256:")
    assert answer["cacheTrace"]["cacheRevisionHash"].startswith("sha256:")
    assert validate_judge_answer(answer) == []


def test_missing_inputs_keep_rejected_controls_visible_in_fallback_trace(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"answerMode": "oracle_mode", "unknownControl": "x"}, version=""))

    assert answer["verdict"] == "unknown"
    assert {item["control"] for item in answer["appliedControls"]["rejected"]} == {"answerMode", "unknownControl"}
    rejected_fallbacks = [item for item in answer["fallbackTrace"] if item.get("fallback") == "unsupported_controls_rejected"]
    assert rejected_fallbacks
    assert {item["control"] for item in rejected_fallbacks[0]["rejected"]} == {"answerMode", "unknownControl"}
    assert validate_judge_answer(answer) == []
