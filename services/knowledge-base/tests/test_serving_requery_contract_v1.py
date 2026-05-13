from __future__ import annotations

from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.judge.models import JudgeQueryRequest
from app.judge.service import build_judge_answer, validate_judge_answer
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
        "richIrArtifacts": [{"artifactKind": "symbol_table", "checksumSha256": "sha256:sym"}],
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
    assert second["decisionFragmentKey"] == first["decisionFragmentKey"]
    assert second["qualityGate"]["scorePolicy"]["policyHash"].startswith("sha256:")


def test_unresolved_source_context_is_visible_fallback_and_grounded_unknown(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = {"repositorySnapshotId": "missing", "buildContextId": "missing", "analysisArtifactSetId": "missing"}
    answer = build_judge_answer(repo, _request("curl affected", source, version=""))

    assert answer["verdict"] == "unknown"
    assert answer["fallbackTrace"]
    assert any(item["fallback"] == "unresolved_context" for item in answer["fallbackTrace"])
    assert answer["cacheTrace"]["reason"] == "missing_inputs_not_cached"
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
