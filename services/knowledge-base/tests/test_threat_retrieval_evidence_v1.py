from __future__ import annotations

from copy import deepcopy

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


def test_threat_retrieval_trace_exposes_phase8_runtime_fields(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    answer = build_judge_answer(repo, _request("curl affected", source))
    threat = answer["evidence"]["threatRetrieval"]
    trace = threat["retrievalTrace"]

    assert trace["methodsSucceeded"] == trace["methodsUsed"]
    assert trace["filtersApplied"] == []
    assert trace["matchedTerms"] == threat["queryTerms"]
    assert "affectedness_evidence" in trace["relationMethods"]
    assert trace["embeddingScope"] == "none"
    assert trace["profileBoostsApplied"] == []
    assert trace["projectionState"] == {"state": "not_applicable", "surface": "ledger_threat_retrieval"}
    assert trace["providerState"] == {"state": "not_applicable", "surface": "ledger_threat_retrieval"}
    assert validate_judge_answer(answer) == []


def test_top_k_control_caps_threat_retrieval_after_deterministic_rerank(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    uncapped = build_judge_answer(repo, _request("curl affected", source))
    capped = build_judge_answer(
        repo,
        _request(
            "curl affected",
            source,
            controls={"topK": 1, "answerMode": "evidence_grounded"},
        ),
    )

    threat = capped["evidence"]["threatRetrieval"]
    trace = threat["retrievalTrace"]
    assert uncapped["decisionFragmentKey"] != capped["decisionFragmentKey"]
    assert capped["appliedControls"]["accepted"]["topK"] == 1
    assert capped["canonicalQuery"]["normalized"]["controls"]["topK"] == 1
    assert capped["verdict"] == "affected"
    assert len(capped["evidence"]["affectedness"]) >= 3
    assert len(threat["candidateEvidence"]) == 1
    assert threat["candidateEvidence"][0]["externalId"] == "CVE-2026-0001"
    assert threat["candidateEvidence"][0]["rank"] == 1
    assert threat["candidateEvidence"][0]["scoreBreakdown"]["methodWeight"] > 0
    assert trace["topK"] == 1
    assert trace["candidateSetSize"] >= 3
    assert trace["returnedCount"] == 1
    assert trace["topKPolicy"]["topKMeans"] == "final_returned_count"
    assert trace["candidatePoolPolicy"]["candidatePoolK"] > trace["topK"]
    assert trace["rerankerPolicy"]["name"] == "s5-deterministic-method-aware-reranker"
    assert trace["rerankersApplied"] == ["method_trust", "risk_signal_score", "source_kind_tiebreaker"]
    assert validate_judge_answer(capped) == []


def test_over_max_top_k_is_clamped_in_retrieval_trace_not_request_identity(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 999}))
    equivalent_over_cap = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1000}))

    trace = answer["evidence"]["threatRetrieval"]["retrievalTrace"]
    assert answer["appliedControls"]["requested"]["topK"] == 999
    assert answer["appliedControls"]["accepted"]["topK"] == 50
    assert answer["canonicalQuery"]["normalized"]["controls"]["topK"] == 50
    assert equivalent_over_cap["canonicalQuery"]["canonicalQueryId"] == answer["canonicalQuery"]["canonicalQueryId"]
    assert equivalent_over_cap["decisionFragmentKey"] == answer["decisionFragmentKey"]
    assert trace["topK"] == 50
    assert trace["topKPolicy"]["requestedTopK"] == 999
    assert trace["topKPolicy"]["finalTopK"] == 50
    assert trace["topKPolicy"]["acceptedControlTopK"] == 50
    assert trace["topKPolicy"]["topKMeans"] == "final_returned_count"
    assert len(answer["evidence"]["threatRetrieval"]["candidateEvidence"]) <= 50
    assert validate_judge_answer(answer) == []


def test_top_k_ranking_is_deterministic_and_exposes_rank_metadata(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    first = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 2}))
    second = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 2}))

    first_candidates = first["evidence"]["threatRetrieval"]["candidateEvidence"]
    second_candidates = second["evidence"]["threatRetrieval"]["candidateEvidence"]
    assert [item["externalId"] for item in first_candidates] == [item["externalId"] for item in second_candidates]
    assert [item["rank"] for item in first_candidates] == [1, 2]
    assert all(item["retrievalMethods"] for item in first_candidates)
    assert all("scoreBreakdown" in item for item in first_candidates)
    assert all(item["scoreBreakdown"]["finalRerankScore"] == item["rerankScore"] for item in first_candidates)


def test_top_k_prefers_verdict_linked_affectedness_over_higher_risk_same_package_context(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-9999",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-9999",
        payload={
            "externalId": "CVE-2099-9999",
            "aliases": ["CVE-2099-9999"],
            "packageIdentityId": "pkg:generic/curl",
            "cweIds": ["CWE-78"],
        },
        freshness={"fixture": True},
    )
    repo.upsert_risk_signal(
        risk_signal_id="risk:CVSS:CVE-2099-9999",
        advisory_id="advisory:NVD_CVE:CVE-2099-9999",
        signal_kind="CVSS",
        source_kind="NVD_CVE",
        signal_value=10.0,
        payload={"cve": "CVE-2099-9999", "baseScore": 10.0},
        provenance={"fixture": "higher-risk-context"},
    )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    candidate = answer["evidence"]["threatRetrieval"]["candidateEvidence"][0]

    assert answer["verdict"] == "affected"
    assert candidate["usedForAffectedness"] is True
    assert candidate["externalId"] != "CVE-2099-9999"
    assert candidate["retrievalMethods"][0] == "affectedness_evidence"
    assert candidate["scoreBreakdown"]["methodWeight"] > 100
    assert validate_judge_answer(answer) == []


def test_retrieval_trace_candidate_pool_preview_explains_unreturned_topk_context(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-9999",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-9999",
        payload={
            "externalId": "CVE-2099-9999",
            "aliases": ["CVE-2099-9999"],
            "packageIdentityId": "pkg:generic/curl",
            "cweIds": ["CWE-78"],
        },
        freshness={"fixture": True},
    )
    repo.upsert_risk_signal(
        risk_signal_id="risk:CVSS:CVE-2099-9999",
        advisory_id="advisory:NVD_CVE:CVE-2099-9999",
        signal_kind="CVSS",
        source_kind="NVD_CVE",
        signal_value=10.0,
        payload={"cve": "CVE-2099-9999", "baseScore": 10.0},
        provenance={"fixture": "higher-risk-context"},
    )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    trace = answer["evidence"]["threatRetrieval"]["retrievalTrace"]
    preview = trace["candidatePoolPreview"]

    assert trace["candidatePoolPreviewCount"] == len(preview)
    assert trace["candidatePoolPreviewLimit"] >= trace["topK"]
    assert preview[0]["externalId"] == "CVE-2026-0001"
    assert preview[0]["candidatePoolRank"] == 1
    assert preview[0]["returned"] is True
    high_risk = next(item for item in preview if item["externalId"] == "CVE-2099-9999")
    assert high_risk["returned"] is False
    assert high_risk["unreturnedReason"] == "outside_final_top_k"
    assert high_risk["retrievalMethods"][0] == "package_identity_context"
    assert high_risk["scoreBreakdown"]["methodWeight"] == 80
    assert validate_judge_answer(answer) == []


def test_query_terms_drive_keyword_threat_retrieval_context_without_affectedness_match(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-4242",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-4242",
        payload={
            "externalId": "CVE-2099-4242",
            "aliases": ["CVE-2099-4242"],
            "summary": "libfoo packet parser heap overflow",
            "packageName": "libfoo",
            "cweIds": ["CWE-120"],
        },
        freshness={"fixture": True},
    )
    request = JudgeQueryRequest.model_validate(
        {
            "schemaVersion": "s5-judge-query-v1",
            "question": "Show libfoo threat context",
            "component": {"name": "libfoo", "version": "1.2.3"},
            "sourceContext": source,
            "controls": {"topK": 1},
        }
    )

    answer = build_judge_answer(repo, request)
    threat = answer["evidence"]["threatRetrieval"]
    candidate = threat["candidateEvidence"][0]
    trace = threat["retrievalTrace"]

    assert answer["verdict"] == "unknown"
    assert candidate["externalId"] == "CVE-2099-4242"
    assert candidate["usedForAffectedness"] is False
    assert candidate["retrievalMethods"] == ["keyword_match"]
    assert candidate["authority"] == "contextual_support_not_affectedness_proof"
    assert trace["keywordUsed"] is True
    assert "keyword_match" in trace["methodsUsed"]
    assert "keyword_match" in trace["methodsAttempted"]
    assert validate_judge_answer(answer) == []


def test_keyword_match_uses_fielded_package_identity_not_incidental_payload_text(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-4242",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-4242",
        payload={
            "externalId": "CVE-2099-4242",
            "aliases": ["CVE-2099-4242"],
            "summary": "packet parser overflow",
            "packageName": "libfoo",
            "cweIds": ["CWE-120"],
        },
        freshness={"fixture": True},
    )
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-4243",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-4243",
        payload={
            "externalId": "CVE-2099-4243",
            "aliases": ["CVE-2099-4243"],
            "summary": "mentions libfoo only in a free-text description",
            "provenance": {"collectorNote": "libfoo appeared in the scraper note, not the affected package"},
            "packageName": "unrelated-package",
            "cweIds": ["CWE-120"],
        },
        freshness={"fixture": True},
    )
    request = JudgeQueryRequest.model_validate(
        {
            "schemaVersion": "s5-judge-query-v1",
            "question": "Show libfoo threat context",
            "component": {"name": "libfoo", "version": "1.2.3"},
            "sourceContext": source,
            "controls": {"topK": 10},
        }
    )

    answer = build_judge_answer(repo, request)
    threat = answer["evidence"]["threatRetrieval"]
    candidate_ids = {item["externalId"] for item in threat["candidateEvidence"]}

    assert answer["verdict"] == "unknown"
    assert "CVE-2099-4242" in candidate_ids
    assert "CVE-2099-4243" not in candidate_ids
    assert all(item["retrievalMethods"] == ["keyword_match"] for item in threat["candidateEvidence"])
    assert threat["retrievalTrace"]["keywordUsed"] is True
    assert validate_judge_answer(answer) == []


def test_keyword_match_requires_exact_security_identifier_not_substring(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-7777",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-7777",
        payload={
            "externalId": "CVE-2099-7777",
            "aliases": ["CVE-2099-7777"],
            "summary": "exact advisory requested by question term",
            "cweIds": ["CWE-20"],
        },
        freshness={"fixture": True},
    )
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-77777",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-77777",
        payload={
            "externalId": "CVE-2099-77777",
            "aliases": ["CVE-2099-77777"],
            "summary": "near-miss advisory must not match CVE-2099-7777 by substring",
            "cweIds": ["CWE-20"],
        },
        freshness={"fixture": True},
    )
    request = JudgeQueryRequest.model_validate(
        {
            "schemaVersion": "s5-judge-query-v1",
            "question": "Need context for CVE-2099-7777",
            "component": {"name": "unrelated-component", "version": "1.0.0"},
            "sourceContext": source,
            "controls": {"topK": 10},
        }
    )

    answer = build_judge_answer(repo, request)
    threat = answer["evidence"]["threatRetrieval"]
    candidate_ids = {item["externalId"] for item in threat["candidateEvidence"]}

    assert "cve-2099-7777" in threat["queryTerms"]
    assert "CVE-2099-7777" in candidate_ids
    assert "CVE-2099-77777" not in candidate_ids
    assert threat["retrievalTrace"]["keywordUsed"] is True
    assert validate_judge_answer(answer) == []


def test_question_terms_drive_keyword_threat_retrieval_context_without_component_match(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-7777",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-7777",
        payload={
            "externalId": "CVE-2099-7777",
            "aliases": ["CVE-2099-7777"],
            "summary": "standalone parsing issue requested by question term",
            "cweIds": ["CWE-20"],
        },
        freshness={"fixture": True},
    )
    request = JudgeQueryRequest.model_validate(
        {
            "schemaVersion": "s5-judge-query-v1",
            "question": "Need context for CVE-2099-7777",
            "component": {"name": "unrelated-component", "version": "1.0.0"},
            "sourceContext": source,
            "controls": {"topK": 1},
        }
    )

    answer = build_judge_answer(repo, request)
    threat = answer["evidence"]["threatRetrieval"]
    candidate = threat["candidateEvidence"][0]
    trace = threat["retrievalTrace"]

    assert answer["verdict"] == "unknown"
    assert "cve-2099-7777" in threat["queryTerms"]
    assert candidate["externalId"] == "CVE-2099-7777"
    assert candidate["retrievalMethods"] == ["keyword_match"]
    assert trace["keywordUsed"] is True
    assert validate_judge_answer(answer) == []


def test_missing_version_grounded_unknown_keeps_question_term_threat_context(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:NVD_CVE:CVE-2099-8888",
        source_id=None,
        source_kind="NVD_CVE",
        external_id="CVE-2099-8888",
        payload={
            "externalId": "CVE-2099-8888",
            "aliases": ["CVE-2099-8888"],
            "summary": "missing-version query should still surface conservative context",
            "cweIds": ["CWE-20"],
        },
        freshness={"fixture": True},
    )
    request = JudgeQueryRequest.model_validate(
        {
            "schemaVersion": "s5-judge-query-v1",
            "question": "Need context for CVE-2099-8888",
            "component": {"name": "unrelated-component"},
            "sourceContext": source,
            "controls": {"topK": 1},
        }
    )

    answer = build_judge_answer(repo, request)
    threat = answer["evidence"]["threatRetrieval"]
    candidate = threat["candidateEvidence"][0]

    assert answer["verdict"] == "unknown"
    assert "component.version" in answer["uncertainty"]["requiredInputs"]
    assert "cve-2099-8888" in threat["queryTerms"]
    assert candidate["externalId"] == "CVE-2099-8888"
    assert candidate["usedForAffectedness"] is False
    assert candidate["retrievalMethods"] == ["keyword_match"]
    assert threat["retrievalTrace"]["keywordUsed"] is True
    assert any(step["step"] == "assemble_threat_kb_context" for step in answer["reasoningPath"])
    assert validate_judge_answer(answer) == []


def test_retrieval_trace_exposes_internal_candidate_pool_cap_truncation(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    for index in range(160):
        repo.upsert_vulnerability_advisory(
            advisory_id=f"advisory:NVD_CVE:CVE-2099-{index:04d}",
            source_id=None,
            source_kind="NVD_CVE",
            external_id=f"CVE-2099-{index:04d}",
            payload={
                "externalId": f"CVE-2099-{index:04d}",
                "aliases": [f"CVE-2099-{index:04d}"],
                "packageIdentityId": "pkg:generic/curl",
                "cweIds": ["CWE-78"],
            },
            freshness={"fixture": True},
        )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    trace = answer["evidence"]["threatRetrieval"]["retrievalTrace"]

    assert trace["candidateSetSize"] > trace["candidatePoolSize"]
    assert trace["candidatePoolSize"] == trace["candidatePoolPolicy"]["candidatePoolK"]
    assert trace["candidatePoolPolicy"]["maxCandidatePoolK"] == 120
    assert trace["candidatePoolTruncated"] is True
    assert trace["candidatePoolTruncationReason"] == "candidate_pool_k_cap"
    assert trace["candidateSetTotalCount"] == trace["candidateSetSize"]
    assert validate_judge_answer(answer) == []


def test_top_k_candidate_includes_equivalent_advisories_by_alias(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    candidate = answer["evidence"]["threatRetrieval"]["candidateEvidence"][0]

    assert candidate["externalId"] == "CVE-2026-0001"
    assert candidate["equivalenceKey"] == "CVE-2026-0001"
    assert set(candidate["equivalentSourceKinds"]) >= {"NVD_CVE", "GHSA", "OSV"}
    assert {item["externalId"] for item in candidate["equivalentAdvisories"]} >= {"GHSA-aaaa-bbbb-cccc", "OSV-2026-CURL-0001"}
    assert all(item["authority"] == "contextual_support_not_affectedness_proof" for item in candidate["equivalentAdvisories"])
    assert validate_judge_answer(answer) == []


def test_top_k_candidate_fuses_alias_only_equivalent_advisory(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:GHSA:GHSA-alias-only",
        source_id=None,
        source_kind="GHSA",
        external_id="GHSA-alias-only",
        payload={
            "externalId": "GHSA-alias-only",
            "aliases": ["CVE-2026-0001"],
            "cweIds": ["CWE-78"],
        },
        freshness={"fixture": True},
    )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    candidate = answer["evidence"]["threatRetrieval"]["candidateEvidence"][0]

    assert candidate["externalId"] == "CVE-2026-0001"
    assert {item["externalId"] for item in candidate["equivalentAdvisories"]} >= {"GHSA-alias-only"}
    assert validate_judge_answer(answer) == []


def test_equivalent_advisories_are_bounded_with_truncation_metadata(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    for index in range(25):
        repo.upsert_vulnerability_advisory(
            advisory_id=f"advisory:GHSA:GHSA-extra-{index:02d}",
            source_id=None,
            source_kind="GHSA",
            external_id=f"GHSA-extra-{index:02d}",
            payload={
                "externalId": f"GHSA-extra-{index:02d}",
                "aliases": ["CVE-2026-0001"],
                "cweIds": ["CWE-78"],
            },
            freshness={"fixture": True},
        )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    candidate = answer["evidence"]["threatRetrieval"]["candidateEvidence"][0]

    assert candidate["equivalentAdvisoryCount"] >= 28
    assert len(candidate["equivalentAdvisories"]) == candidate["equivalentAdvisoryLimit"] == 16
    assert candidate["equivalentAdvisoriesTruncated"] is True
    assert validate_judge_answer(answer) == []


def test_equivalent_advisories_are_bounded_by_response_budget(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    for candidate_index in range(8):
        cve = f"CVE-2099-{candidate_index:04d}"
        repo.upsert_vulnerability_advisory(
            advisory_id=f"advisory:NVD_CVE:{cve}",
            source_id=None,
            source_kind="NVD_CVE",
            external_id=cve,
            payload={
                "externalId": cve,
                "aliases": [cve],
                "packageIdentityId": "pkg:generic/curl",
                "cweIds": ["CWE-78"],
            },
            freshness={"fixture": True},
        )
        for equivalent_index in range(12):
            repo.upsert_vulnerability_advisory(
                advisory_id=f"advisory:GHSA:GHSA-{candidate_index:04d}-{equivalent_index:02d}",
                source_id=None,
                source_kind="GHSA",
                external_id=f"GHSA-{candidate_index:04d}-{equivalent_index:02d}",
                payload={
                    "externalId": f"GHSA-{candidate_index:04d}-{equivalent_index:02d}",
                    "aliases": [cve],
                    "cweIds": ["CWE-78"],
                },
                freshness={"fixture": True},
            )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 50}))
    threat = answer["evidence"]["threatRetrieval"]
    trace = threat["retrievalTrace"]
    returned_equivalent_count = sum(len(item.get("equivalentAdvisories") or []) for item in threat["candidateEvidence"])

    assert trace["equivalentAdvisoryResponseLimit"] == 64
    assert trace["equivalentAdvisoryReturnedCount"] == returned_equivalent_count == 64
    assert trace["equivalentAdvisoryResponseTruncated"] is True
    assert any(item["equivalentAdvisoriesTruncated"] for item in threat["candidateEvidence"])
    assert validate_judge_answer(answer) == []


def test_risk_signals_are_bounded_by_response_budget(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    for index in range(50):
        repo.upsert_risk_signal(
            risk_signal_id=f"risk:EPSS:CVE-2026-0001:{index:02d}",
            advisory_id="advisory:NVD_CVE:CVE-2026-0001",
            signal_kind="EPSS",
            source_kind="EPSS",
            signal_value=0.5 + (index / 1000),
            payload={"cve": "CVE-2026-0001", "sample": index},
            provenance={"fixture": "risk-signal-budget"},
        )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    threat = answer["evidence"]["threatRetrieval"]
    trace = threat["retrievalTrace"]

    assert trace["riskSignalTotalCount"] >= 50
    assert trace["riskSignalResponseLimit"] == 32
    assert trace["riskSignalReturnedCount"] == len(threat["riskSignals"]) == 32
    assert trace["riskSignalResponseTruncated"] is True
    assert validate_judge_answer(answer) == []


def test_semantic_expansions_are_bounded_by_response_budget(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    for index in range(50):
        weakness_id = f"CWE-{9000 + index}"
        attack_id = f"T{9000 + index}"
        repo.upsert_weakness(
            weakness_id=weakness_id,
            external_id=weakness_id,
            taxonomy_family="CWE",
            payload={"name": f"weakness {index}"},
            provenance={"fixture": "semantic-budget"},
        )
        repo.upsert_attack_pattern(
            attack_pattern_id=attack_id,
            external_id=attack_id,
            source_kind="ATTACK",
            payload={"name": f"attack {index}"},
            provenance={"fixture": "semantic-budget"},
        )
        repo.upsert_relation_record(
            relation_record_id=f"relation:adv-cwe:{index}",
            subject_id="advisory:NVD_CVE:CVE-2026-0001",
            predicate="maps_to_weakness",
            object_id=weakness_id,
            method="fixture",
            consumer_policy="contextual_support_not_affectedness_proof",
            provenance={"fixture": "semantic-budget"},
        )
        repo.upsert_relation_record(
            relation_record_id=f"relation:attack-cwe:{index}",
            subject_id=attack_id,
            predicate="maps_to_weakness",
            object_id=weakness_id,
            method="fixture",
            consumer_policy="contextual_support_not_affectedness_proof",
            provenance={"fixture": "semantic-budget"},
        )

    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    threat = answer["evidence"]["threatRetrieval"]
    trace = threat["retrievalTrace"]

    assert trace["weaknessSemanticTotalCount"] >= 50
    assert trace["weaknessSemanticResponseLimit"] == 32
    assert trace["weaknessSemanticReturnedCount"] == len(threat["weaknessSemantics"]) == 32
    assert trace["weaknessSemanticResponseTruncated"] is True
    assert trace["attackSemanticTotalCount"] >= 50
    assert trace["attackSemanticResponseLimit"] == 32
    assert trace["attackSemanticReturnedCount"] == len(threat["attackSemantics"]) == 32
    assert trace["attackSemanticResponseTruncated"] is True
    assert validate_judge_answer(answer) == []


def test_judge_validator_rejects_threat_retrieval_rank_sequence_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 2}))
    tampered = deepcopy(answer)
    tampered["evidence"]["threatRetrieval"]["candidateEvidence"][0]["rank"] = 2

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_RANK_SEQUENCE_INVALID" for item in issues)


def test_judge_validator_rejects_threat_retrieval_authority_escalation(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source))

    threat_authority_escalation = deepcopy(answer)
    threat_authority_escalation["evidence"]["threatRetrieval"]["authority"] = "affectedness_proof"
    issues = validate_judge_answer(threat_authority_escalation)
    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.authority"
        for item in issues
    )

    trace_authority_escalation = deepcopy(answer)
    trace_authority_escalation["evidence"]["threatRetrieval"]["retrievalTrace"]["authority"] = "affectedness_proof"
    issues = validate_judge_answer(trace_authority_escalation)
    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.retrievalTrace.authority"
        for item in issues
    )

    risk_signal_escalation = deepcopy(answer)
    risk_signal_escalation["evidence"]["threatRetrieval"]["riskSignals"][0]["authority"] = "affectedness_proof"
    issues = validate_judge_answer(risk_signal_escalation)
    assert any(item["code"] == "THREAT_RETRIEVAL_RISK_SIGNAL_AUTHORITY_INVALID" for item in issues)

    credential_bearing_authority = "https://authority_user:authority_password@ids.example/risk?token=authority-secret"
    credential_bearing_escalation = deepcopy(answer)
    credential_bearing_escalation["evidence"]["threatRetrieval"]["riskSignals"][0]["authority"] = (
        credential_bearing_authority
    )
    issues = validate_judge_answer(credential_bearing_escalation)
    assert any(item["code"] == "THREAT_RETRIEVAL_RISK_SIGNAL_AUTHORITY_INVALID" for item in issues)
    assert "authority_user" not in str(issues)
    assert "authority_password" not in str(issues)
    assert "authority-secret" not in str(issues)

    negative_evidence_enabled = deepcopy(answer)
    negative_evidence_enabled["evidence"]["threatRetrieval"]["negativeEvidenceAllowed"] = True
    negative_evidence_enabled["evidence"]["threatRetrieval"]["retrievalTrace"]["negativeEvidenceAllowed"] = True
    issues = validate_judge_answer(negative_evidence_enabled)
    assert any(item["code"] == "THREAT_RETRIEVAL_NEGATIVE_EVIDENCE_ALLOWED" for item in issues)


def test_judge_validator_rejects_threat_retrieval_child_authority_escalation(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source))

    child_authority_escalation = deepcopy(answer)
    threat = child_authority_escalation["evidence"]["threatRetrieval"]
    threat["candidateEvidence"][0]["authority"] = "affectedness_proof"
    threat["retrievalTrace"]["candidatePoolPreview"][0]["authority"] = "affectedness_proof"
    threat["weaknessSemantics"][0]["authority"] = "affectedness_proof"
    threat["attackSemantics"][0]["authority"] = "affectedness_proof"

    issues = validate_judge_answer(child_authority_escalation)

    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.candidateEvidence[].authority"
        for item in issues
    )
    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].authority"
        for item in issues
    )
    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.weaknessSemantics[].authority"
        for item in issues
    )
    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.attackSemantics[].authority"
        for item in issues
    )

    credential_bearing_child_authority = deepcopy(answer)
    credential_bearing_candidate = credential_bearing_child_authority["evidence"]["threatRetrieval"]["candidateEvidence"][0]
    credential_bearing_candidate["authority"] = (
        "https://candidate_user:candidate_password@ids.example/candidate?token=candidate-secret"
    )
    credential_bearing_candidate["externalId"] = (
        "https://candidate_id_user:candidate_id_password@ids.example/candidate-id?token=candidate-id-secret"
    )
    issues = validate_judge_answer(credential_bearing_child_authority)
    authority_issues = [
        item
        for item in issues
        if item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.candidateEvidence[].authority"
    ]
    assert authority_issues
    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.candidateEvidence[].authority"
        for item in issues
    )
    assert "candidate_user" not in str(authority_issues)
    assert "candidate_password" not in str(authority_issues)
    assert "candidate-secret" not in str(authority_issues)
    assert "candidate_id_user" not in str(authority_issues)
    assert "candidate_id_password" not in str(authority_issues)
    assert "candidate-id-secret" not in str(authority_issues)

    suppressed_answer = build_judge_answer(
        repo,
        _request(
            "curl affected",
            source,
            controls={"exclude": ["CVE-2026-0001"], "answerMode": "alternatives_without_excluded"},
        ),
    )
    suppressed_authority_escalation = deepcopy(suppressed_answer)
    suppressed_candidate = suppressed_authority_escalation["evidence"]["threatRetrieval"]["suppressedCandidateEvidence"][0]
    suppressed_candidate["authority"] = "affectedness_proof"
    suppressed_candidate["externalId"] = (
        "https://suppressed_user:suppressed_password@ids.example/suppressed?token=suppressed-secret"
    )
    issues = validate_judge_answer(suppressed_authority_escalation)
    suppressed_authority_issues = [
        item
        for item in issues
        if item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.suppressedCandidateEvidence[].authority"
    ]
    assert suppressed_authority_issues
    assert any(
        item["code"] == "THREAT_RETRIEVAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.suppressedCandidateEvidence[].authority"
        for item in issues
    )
    assert "suppressed_user" not in str(suppressed_authority_issues)
    assert "suppressed_password" not in str(suppressed_authority_issues)
    assert "suppressed-secret" not in str(suppressed_authority_issues)


def test_judge_validator_rejects_threat_retrieval_method_weight_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    candidate = tampered["evidence"]["threatRetrieval"]["candidateEvidence"][0]
    candidate["retrievalMethods"] = ["package_identity_context"]

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_METHOD_WEIGHT_MISMATCH" for item in issues)


def test_judge_validator_rejects_threat_retrieval_rerank_order_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 2}))
    tampered = deepcopy(answer)
    lower_ranked = tampered["evidence"]["threatRetrieval"]["candidateEvidence"][1]
    lower_ranked["scoreBreakdown"]["baseScore"] = 999.0
    lower_ranked["scoreBreakdown"]["finalRerankScore"] = lower_ranked["scoreBreakdown"]["methodWeight"] + 999.0
    lower_ranked["rerankScore"] = lower_ranked["scoreBreakdown"]["finalRerankScore"]

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_RERANK_ORDER_INVALID" for item in issues)


def test_judge_validator_rejects_candidate_pool_preview_returned_flag_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    tampered["evidence"]["threatRetrieval"]["retrievalTrace"]["candidatePoolPreview"][0]["returned"] = False

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_MISMATCH" for item in issues)


def test_judge_validator_rejects_excluded_internal_advisory_in_candidate_evidence(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    excluded_advisory_id = "advisory:NVD_CVE:CVE-2026-0001"
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    tampered["appliedControls"]["accepted"]["exclude"] = [excluded_advisory_id]

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_EXCLUDED_CANDIDATE_RETURNED" for item in issues)


def test_judge_validator_rejects_equivalent_advisory_count_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    tampered["evidence"]["threatRetrieval"]["candidateEvidence"][0]["equivalentAdvisoryCount"] = 0

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_EQUIVALENT_COUNT_MISMATCH" for item in issues)


def test_judge_validator_rejects_equivalent_source_kinds_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    tampered["evidence"]["threatRetrieval"]["candidateEvidence"][0]["equivalentSourceKinds"] = ["NVD_CVE"]

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_EQUIVALENT_SOURCE_KINDS_MISMATCH" for item in issues)


def test_judge_validator_redacts_authority_issue_metadata_for_equivalent_and_risk_signal(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))

    equivalent_escalation = deepcopy(answer)
    equivalent = equivalent_escalation["evidence"]["threatRetrieval"]["candidateEvidence"][0]["equivalentAdvisories"][0]
    equivalent["authority"] = "https://equiv_user:equiv_password@ids.example/authority?token=equiv-secret"
    equivalent["externalId"] = "https://equiv_id_user:equiv_id_password@ids.example/external?token=equiv-id-secret"
    issues = validate_judge_answer(equivalent_escalation)
    assert any(
        item["code"] == "THREAT_RETRIEVAL_EQUIVALENT_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisories[].authority"
        for item in issues
    )
    assert "equiv_user" not in str(issues)
    assert "equiv_password" not in str(issues)
    assert "equiv-secret" not in str(issues)
    assert "equiv_id_user" not in str(issues)
    assert "equiv_id_password" not in str(issues)
    assert "equiv-id-secret" not in str(issues)

    risk_signal_escalation = deepcopy(answer)
    risk_signal = risk_signal_escalation["evidence"]["threatRetrieval"]["riskSignals"][0]
    risk_signal["authority"] = "affectedness_proof"
    risk_signal["riskSignalId"] = "https://risk_id_user:risk_id_password@ids.example/risk?token=risk-id-secret"
    issues = validate_judge_answer(risk_signal_escalation)
    assert any(
        item["code"] == "THREAT_RETRIEVAL_RISK_SIGNAL_AUTHORITY_INVALID"
        and item["field"] == "evidence.threatRetrieval.riskSignals[].authority"
        for item in issues
    )
    assert "risk_id_user" not in str(issues)
    assert "risk_id_password" not in str(issues)
    assert "risk-id-secret" not in str(issues)


def test_judge_validator_redacts_non_authority_threat_retrieval_issue_metadata(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 2}))

    candidate_rank_mismatch = deepcopy(answer)
    candidate = candidate_rank_mismatch["evidence"]["threatRetrieval"]["candidateEvidence"][0]
    candidate["rank"] = 99
    candidate["externalId"] = "https://rank_user:rank_password@ids.example/rank?token=rank-secret"
    issues = validate_judge_answer(candidate_rank_mismatch)
    rank_issues = [item for item in issues if item["code"] == "THREAT_RETRIEVAL_RANK_SEQUENCE_INVALID"]
    assert rank_issues
    assert rank_issues[0]["field"] == "evidence.threatRetrieval.candidateEvidence[].rank"
    assert "rank_user" not in str(rank_issues)
    assert "rank_password" not in str(rank_issues)
    assert "rank-secret" not in str(rank_issues)

    returned_count_mismatch = deepcopy(answer)
    returned_count_mismatch["evidence"]["threatRetrieval"]["retrievalTrace"]["returnedCount"] = 999
    issues = validate_judge_answer(returned_count_mismatch)
    returned_count_issues = [item for item in issues if item["code"] == "THREAT_RETRIEVAL_RETURNED_COUNT_MISMATCH"]
    assert returned_count_issues
    assert returned_count_issues[0]["field"] == "evidence.threatRetrieval.retrievalTrace.returnedCount"

    trace_field_missing = deepcopy(answer)
    trace_field_missing["evidence"]["threatRetrieval"]["retrievalTrace"]["methodsSucceeded"] = "not-a-list"
    issues = validate_judge_answer(trace_field_missing)
    trace_field_issues = [item for item in issues if item["code"] == "THREAT_RETRIEVAL_TRACE_FIELD_MISSING"]
    assert trace_field_issues
    assert trace_field_issues[0]["field"] == "evidence.threatRetrieval.retrievalTrace.methodsSucceeded"

    preview_returned_mismatch = deepcopy(answer)
    preview = preview_returned_mismatch["evidence"]["threatRetrieval"]["retrievalTrace"]["candidatePoolPreview"][0]
    preview["returned"] = False
    preview["externalId"] = "https://preview_user:preview_password@ids.example/preview?token=preview-secret"
    issues = validate_judge_answer(preview_returned_mismatch)
    preview_issues = [
        item for item in issues if item["code"] == "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_MISMATCH"
    ]
    assert preview_issues
    assert preview_issues[0]["field"] == "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].returned"
    assert "preview_user" not in str(preview_issues)
    assert "preview_password" not in str(preview_issues)
    assert "preview-secret" not in str(preview_issues)


def test_judge_validator_rejects_equivalent_advisory_response_budget_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    trace = tampered["evidence"]["threatRetrieval"]["retrievalTrace"]
    trace["equivalentAdvisoryResponseLimit"] = 1
    trace["equivalentAdvisoryReturnedCount"] = 999
    trace["equivalentAdvisoryResponseTruncated"] = False

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_EQUIVALENT_RESPONSE_BUDGET_MISMATCH" for item in issues)


def test_judge_validator_rejects_risk_signal_response_budget_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    trace = tampered["evidence"]["threatRetrieval"]["retrievalTrace"]
    trace["riskSignalTotalCount"] = 1
    trace["riskSignalResponseLimit"] = 1
    trace["riskSignalReturnedCount"] = 999
    trace["riskSignalResponseTruncated"] = False

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_RISK_SIGNAL_RESPONSE_BUDGET_MISMATCH" for item in issues)


def test_judge_validator_rejects_suppressed_candidate_response_budget_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"exclude": ["CVE-2026-0001"]}))
    tampered = deepcopy(answer)
    trace = tampered["evidence"]["threatRetrieval"]["retrievalTrace"]
    trace["suppressedCandidateTotalCount"] = 1
    trace["suppressedCandidateResponseLimit"] = 1
    trace["suppressedCandidateReturnedCount"] = 999
    trace["suppressedCandidateResponseTruncated"] = False

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_SUPPRESSED_RESPONSE_BUDGET_MISMATCH" for item in issues)


def test_judge_validator_rejects_semantic_response_budget_mismatch(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(repo, _request("curl affected", source, controls={"topK": 1}))
    tampered = deepcopy(answer)
    trace = tampered["evidence"]["threatRetrieval"]["retrievalTrace"]
    trace["weaknessSemanticTotalCount"] = 1
    trace["weaknessSemanticResponseLimit"] = 1
    trace["weaknessSemanticReturnedCount"] = 999
    trace["weaknessSemanticResponseTruncated"] = False
    trace["attackSemanticTotalCount"] = 1
    trace["attackSemanticResponseLimit"] = 1
    trace["attackSemanticReturnedCount"] = 999
    trace["attackSemanticResponseTruncated"] = False

    issues = validate_judge_answer(tampered)

    assert any(item["code"] == "THREAT_RETRIEVAL_SEMANTIC_RESPONSE_BUDGET_MISMATCH" for item in issues)
    assert {
        item["field"]
        for item in issues
        if item["code"] == "THREAT_RETRIEVAL_SEMANTIC_RESPONSE_BUDGET_MISMATCH"
    } == {
        "evidence.threatRetrieval.weaknessSemantics",
        "evidence.threatRetrieval.attackSemantics",
    }


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


def test_excluded_internal_advisory_id_is_suppressed_from_threat_retrieval(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    excluded_advisory_ids = [
        "advisory:NVD_CVE:CVE-2026-0001",
        "advisory:GHSA:GHSA-aaaa-bbbb-cccc",
        "advisory:OSV:OSV-2026-CURL-0001",
    ]
    answer = build_judge_answer(
        repo,
        _request(
            "curl affected",
            source,
            controls={
                "exclude": excluded_advisory_ids,
                "topK": 5,
                "answerMode": "alternatives_without_excluded",
            },
        ),
    )

    threat = answer["evidence"]["threatRetrieval"]
    assert answer["verdict"] == "unknown"
    assert threat["candidateEvidence"] == []
    assert threat["riskSignals"] == []
    assert threat["weaknessSemantics"] == []
    assert threat["attackSemantics"] == []
    assert set(item["advisoryId"] for item in threat["suppressedCandidateEvidence"]) >= set(excluded_advisory_ids)
    assert all(item.get("usedForAffectedness") is False for item in threat["suppressedCandidateEvidence"])
    assert all(excluded_id not in str(threat["candidateEvidence"]) for excluded_id in excluded_advisory_ids)
    assert validate_judge_answer(answer) == []


def test_top_k_and_exclude_do_not_resurrect_suppressed_threat_evidence(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    answer = build_judge_answer(
        repo,
        _request(
            "curl affected",
            source,
            controls={"exclude": ["CVE-2026-0001"], "topK": 5, "answerMode": "alternatives_without_excluded"},
        ),
    )

    threat = answer["evidence"]["threatRetrieval"]
    assert answer["verdict"] == "unknown"
    assert all(item["externalId"] != "CVE-2026-0001" for item in threat["candidateEvidence"])
    assert all(signal["advisoryId"] != "advisory:NVD_CVE:CVE-2026-0001" for signal in threat["riskSignals"])
    assert all(item["externalId"] != "CVE-2026-0001" for item in threat["weaknessSemantics"])
    assert any(item["externalId"] == "CVE-2026-0001" for item in threat["suppressedCandidateEvidence"])
    assert threat["retrievalTrace"]["topK"] == 5
    assert threat["retrievalTrace"]["returnedCount"] == 0


def test_excluded_high_rank_candidates_do_not_starve_non_excluded_alternatives(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    excluded_ids = ["CVE-2026-0001"]
    for index in range(30):
        cve = f"CVE-2099-{index:04d}"
        advisory_id = f"advisory:NVD_CVE:{cve}"
        excluded_ids.append(cve)
        repo.upsert_vulnerability_advisory(
            advisory_id=advisory_id,
            source_id=None,
            source_kind="NVD_CVE",
            external_id=cve,
            payload={"externalId": cve, "aliases": [cve], "packageIdentityId": "pkg:generic/curl", "cweIds": ["CWE-78"]},
            freshness={"fixture": True},
        )
        repo.upsert_risk_signal(
            risk_signal_id=f"risk:CVSS:{cve}",
            advisory_id=advisory_id,
            signal_kind="CVSS",
            source_kind="NVD_CVE",
            signal_value=10.0,
            payload={"cve": cve, "baseScore": 10.0},
            provenance={"fixture": "excluded-starvation"},
        )
    repo.upsert_vulnerability_advisory(
        advisory_id="advisory:OSV:OSV-ALT-CURL",
        source_id=None,
        source_kind="OSV",
        external_id="OSV-ALT-CURL",
        payload={"externalId": "OSV-ALT-CURL", "aliases": ["CVE-2099-9999"], "packageIdentityId": "pkg:generic/curl", "cweIds": ["CWE-78"]},
        freshness={"fixture": True},
    )
    repo.upsert_affectedness_record(
        affectedness_id="affectedness:OSV-ALT-CURL:0",
        advisory_id="advisory:OSV:OSV-ALT-CURL",
        subject_kind="package_identity",
        subject_id="pkg:generic/curl",
        affectedness_status="affected",
        introduced="0",
        fixed="9.0.0",
        range_data={"introduced": "0", "fixed": "9.0.0"},
        qualifiers={"sourceKind": "OSV"},
        confidence=0.8,
        provenance={"fixture": "excluded-starvation"},
    )

    answer = build_judge_answer(
        repo,
        _request(
            "curl affected",
            source,
            controls={"exclude": excluded_ids, "topK": 1, "answerMode": "alternatives_without_excluded"},
        ),
    )

    threat = answer["evidence"]["threatRetrieval"]
    assert answer["verdict"] == "affected"
    assert [item["externalId"] for item in threat["candidateEvidence"]] == ["OSV-ALT-CURL"]
    assert threat["candidateEvidence"][0]["suppressedByControls"] is False
    assert threat["retrievalTrace"]["suppressedCandidateTotalCount"] >= 30
    assert threat["retrievalTrace"]["suppressedCandidateResponseLimit"] == 16
    assert threat["retrievalTrace"]["suppressedCandidateReturnedCount"] == len(threat["suppressedCandidateEvidence"]) == 16
    assert threat["retrievalTrace"]["suppressedCandidateResponseTruncated"] is True
    assert threat["retrievalTrace"]["candidateSetSize"] >= 1
    assert threat["retrievalTrace"]["returnedCount"] == 1
    assert validate_judge_answer(answer) == []


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
