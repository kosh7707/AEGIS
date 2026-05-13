from __future__ import annotations

from app.judge.models import JudgeQueryRequest
from app.judge.service import build_judge_answer, validate_judge_answer
from app.serving import reset_decision_cache

from tests.test_identity_resolution_v1 import _source_component_id
from tests.test_serving_requery_contract_v1 import _repo, _request, _source_context


def test_affected_answer_includes_threat_retrieval_context_and_risk_signals(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    answer = build_judge_answer(repo, _request("curl affected", source))

    threat = answer["evidence"]["threatRetrieval"]
    assert threat["schemaVersion"] == "s5-threat-retrieval-evidence-v1"
    assert threat["authority"] == "contextual_support_not_affectedness_proof"
    assert threat["negativeEvidenceAllowed"] is False
    assert threat["candidateEvidence"]
    assert any(item["externalId"] == "CVE-2026-0001" for item in threat["candidateEvidence"])
    assert any(item["externalId"] == "CWE-78" for item in threat["weaknessSemantics"])
    assert threat["attackSemantics"]
    assert threat["riskSignals"]
    assert all(item["authority"] == "prioritization_signal_not_affectedness_proof" for item in threat["riskSignals"])
    assert threat["retrievalTrace"]["embeddingUsed"] is False
    assert threat["retrievalTrace"]["negativeEvidenceAllowed"] is False
    assert any(step["step"] == "assemble_threat_kb_context" for step in answer["reasoningPath"])
    assert validate_judge_answer(answer) == []


def test_cpe_only_remains_unknown_even_with_contextual_threat_retrieval(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(
        repo,
        JudgeQueryRequest.model_validate(
            {
                "schemaVersion": "s5-judge-query-v1",
                "question": "is this CPE affected",
                "component": {"version": "8.0.0", "cpe": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"},
                "sourceContext": source,
                "controls": {},
            }
        ),
    )

    threat = answer["evidence"]["threatRetrieval"]
    assert answer["verdict"] == "unknown"
    assert answer["evidence"]["affectedness"] == []
    assert answer["evidence"]["identityResolution"]["status"] == "product_only"
    assert threat["negativeEvidenceAllowed"] is False
    assert threat["authority"] == "contextual_support_not_affectedness_proof"
    assert all(item["usedForAffectedness"] is False for item in threat["candidateEvidence"])


def test_source_only_or_unknown_context_does_not_turn_retrieval_no_hit_into_not_affected(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    source_component_id = _source_component_id(repo)
    source_only = build_judge_answer(
        repo,
        JudgeQueryRequest.model_validate(
            {
                "schemaVersion": "s5-judge-query-v1",
                "question": "is this source component affected",
                "component": {"version": "8.0.0", "repoUrl": "https://github.com/curl/curl", "sourceComponentId": source_component_id},
                "sourceContext": source,
                "controls": {},
            }
        ),
    )
    unknown = build_judge_answer(
        repo,
        JudgeQueryRequest.model_validate(
            {
                "schemaVersion": "s5-judge-query-v1",
                "question": "unknown native component",
                "component": {"name": "not-a-real-native-lib", "version": "1.0.0"},
                "sourceContext": source,
                "controls": {},
            }
        ),
    )

    assert source_only["verdict"] == "unknown"
    assert source_only["evidence"]["threatRetrieval"]["negativeEvidenceAllowed"] is False
    assert unknown["verdict"] == "unknown"
    assert unknown["evidence"]["threatRetrieval"]["candidateEvidence"] == []
    assert any(item["code"] == "THREAT_RETRIEVAL_NO_CONTEXT" for item in unknown["evidence"]["threatRetrieval"]["diagnostics"])


def test_risk_signals_do_not_change_affectedness_verdict(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    cpe_only = build_judge_answer(
        repo,
        JudgeQueryRequest.model_validate(
            {
                "schemaVersion": "s5-judge-query-v1",
                "question": "is this CPE affected",
                "component": {"version": "8.0.0", "cpe": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"},
                "sourceContext": source,
                "controls": {},
            }
        ),
    )

    assert cpe_only["evidence"]["threatRetrieval"]["riskSignals"]
    assert cpe_only["verdict"] == "unknown"
    assert cpe_only["status"] == "requires_requery"


def test_serving_ledger_preserves_threat_retrieval_packet(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source))

    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row["answer"]["evidence"]["threatRetrieval"] == answer["evidence"]["threatRetrieval"]


def test_excluded_cve_is_not_usable_threat_retrieval_evidence(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(
        repo,
        _request(
            "curl affected",
            source,
            controls={"exclude": ["CVE-2026-0001"], "answerMode": "alternatives_without_excluded"},
        ),
    )

    threat = answer["evidence"]["threatRetrieval"]
    assert answer["verdict"] == "unknown"
    assert threat["candidateEvidence"] == []
    assert threat["riskSignals"] == []
    assert threat["suppressedCandidateEvidence"]
    assert any(item["externalId"] == "CVE-2026-0001" for item in threat["suppressedCandidateEvidence"])


def test_version_present_identity_missing_unknown_includes_empty_threat_retrieval(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(
        repo,
        JudgeQueryRequest.model_validate(
            {
                "schemaVersion": "s5-judge-query-v1",
                "question": "version only native component",
                "component": {"version": "8.0.0"},
                "sourceContext": source,
                "controls": {},
            }
        ),
    )

    assert answer["verdict"] == "unknown"
    assert "threatRetrieval" in answer["evidence"]
    assert answer["evidence"]["threatRetrieval"]["candidateEvidence"] == []
    assert answer["evidence"]["threatRetrieval"]["negativeEvidenceAllowed"] is False
    assert any(step["step"] == "assemble_threat_kb_context" for step in answer["reasoningPath"])
