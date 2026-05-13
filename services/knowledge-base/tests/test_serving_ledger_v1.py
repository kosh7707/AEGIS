from __future__ import annotations

from app.judge.service import build_judge_answer, validate_judge_answer
from app.ledger.repository import SCHEMA_VERSION, SQLiteLedgerRepository
from app.serving import reset_decision_cache

from tests.test_serving_requery_contract_v1 import _repo, _request, _source_context


def test_serving_ledger_schema_v4_is_present(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()

    assert repo.get_meta()["schemaVersion"] == SCHEMA_VERSION == 4
    assert repo.get_meta()["userVersion"] == 4
    assert "serving_query_run" in repo.list_tables()


def test_judge_records_affected_answer_in_serving_ledger(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    request = _request("curl affected", source)

    answer = build_judge_answer(repo, request)

    assert validate_judge_answer(answer) == []
    assert answer["servingLedger"]["recorded"] is True
    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row is not None
    assert row["servingRunId"] == answer["servingLedger"]["servingRunId"]
    assert row["canonicalQueryId"] == answer["canonicalQuery"]["canonicalQueryId"]
    assert row["decisionFragmentKey"] == answer["decisionFragmentKey"]
    assert row["answerSchemaVersion"] == "s5-judge-answer-v1"
    assert row["verdict"] == "affected"
    assert row["status"] == "complete"
    assert row["qualityGate"] == "accepted"
    assert row["component"]["name"] == "curl"
    assert row["sourceContext"]["analysisArtifactSetId"] == source["analysisArtifactSetId"]
    assert row["canonicalQuery"] == answer["canonicalQuery"]
    assert row["answer"]["servingLedger"] == answer["servingLedger"]
    assert row["appliedControls"] == answer["appliedControls"]
    assert row["cacheTrace"] == answer["cacheTrace"]
    assert row["fallbackTrace"] == []
    assert row["scoreVector"] == answer["scoreVector"]
    assert row["scorePolicy"] == answer["qualityGate"]["scorePolicy"]


def test_serving_ledger_records_requery_exclude_without_resurrection(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(
        repo,
        _request(
            "curl affected",
            source,
            controls={"exclude": [" cve-2026-0001 "], "answerMode": "alternatives_without_excluded"},
        ),
    )

    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert answer["verdict"] == "unknown"
    assert answer["evidence"]["affectedness"] == []
    assert "CVE-2026-0001" in answer["controlEffects"][0]["suppressedExternalIds"]
    assert row["controlEffects"] == answer["controlEffects"]
    assert row["appliedControls"]["accepted"]["exclude"] == ["CVE-2026-0001"]
    assert row["answer"]["evidence"]["suppressedAffectedness"]


def test_serving_ledger_records_grounded_unknown_with_rejected_controls(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(
        repo,
        _request("curl affected", source, controls={"answerMode": "oracle_mode", "unknownControl": "x"}, version=""),
    )

    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert answer["verdict"] == "unknown"
    assert answer["status"] == "requires_requery"
    assert {item["control"] for item in row["appliedControls"]["rejected"]} == {"answerMode", "unknownControl"}
    assert any(item.get("fallback") == "unsupported_controls_rejected" for item in row["fallbackTrace"])
    assert row["cacheTrace"]["reason"] == "missing_inputs_not_cached"
    assert row["answer"]["uncertainty"]["requiredInputs"] == ["component.version"]


def test_serving_ledger_records_repeated_runs_with_shared_decision_key_and_cache_hit(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    request = _request("curl affected", source)

    first = build_judge_answer(repo, request)
    second = build_judge_answer(repo, request)

    assert first["servingLedger"]["servingRunId"] != second["servingLedger"]["servingRunId"]
    assert first["decisionFragmentKey"] == second["decisionFragmentKey"]
    rows = repo.list_serving_query_runs(decision_fragment_key=first["decisionFragmentKey"])
    assert [row["servingRunId"] for row in rows] == [first["servingLedger"]["servingRunId"], second["servingLedger"]["servingRunId"]]
    assert rows[0]["cacheTrace"]["hit"] is False
    assert rows[0]["cacheTrace"]["stored"] is True
    assert rows[1]["cacheTrace"]["hit"] is True
    assert rows[1]["cacheTrace"]["stored"] is False
    canonical_rows = repo.list_serving_query_runs(canonical_query_id=first["canonicalQuery"]["canonicalQueryId"])
    assert len(canonical_rows) == 2
