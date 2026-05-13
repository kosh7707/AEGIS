from __future__ import annotations

import json

from app.affectedness import query_affectedness
from app.identity import resolve_component_identity
from app.judge.models import JudgeQueryRequest
from app.judge.service import build_judge_answer, validate_judge_answer
from app.ledger.repository import SQLiteLedgerRepository
from app.serving import reset_decision_cache

from tests.test_serving_requery_contract_v1 import _repo, _source_context


def test_serving_query_planner_imports_without_judge_service_cycle():
    from app.serving.query_planner import build_canonical_query
    import app.serving as serving

    assert build_canonical_query is serving.build_canonical_query


def _source_component_id(repo: SQLiteLedgerRepository) -> str:
    return repo.fetch_all("source_component_identity")[0]["source_component_identity_id"]


def test_package_identity_resolves_exact_purl_and_affectedness(tmp_path):
    repo = _repo(tmp_path)

    resolution = resolve_component_identity(repo, {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"})
    affectedness = query_affectedness(repo, {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"})

    assert resolution["status"] == "resolved"
    assert resolution["hardAffectednessPackageIds"] == ["pkg:generic/curl"]
    assert any(item["matchKind"] == "exact_purl" and item["hardAffectednessEligible"] for item in resolution["matches"])
    assert affectedness["affectedness"] == "affected"
    assert affectedness["identityResolution"]["status"] == "resolved"


def test_package_identity_patched_version_remains_known_not_affected(tmp_path):
    repo = _repo(tmp_path)

    affectedness = query_affectedness(repo, {"name": "curl", "version": "8.1.0", "purl": "pkg:generic/curl@8.1.0"})

    assert affectedness["affectedness"] == "known_not_affected"
    assert affectedness["identityResolution"]["hardAffectednessPackageIds"] == ["pkg:generic/curl"]


def test_cpe_only_is_product_identity_not_package_affectedness_proof(tmp_path):
    repo = _repo(tmp_path)
    component = {"version": "8.0.0", "cpe": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"}

    resolution = resolve_component_identity(repo, component)
    affectedness = query_affectedness(repo, component)

    assert resolution["status"] == "product_only"
    assert resolution["hardAffectednessPackageIds"] == []
    assert any(item["relationSemantics"] == "RELATED_PRODUCT_IDENTITY" and item["hardAffectednessEligible"] is False for item in resolution["matches"])
    assert any(item["relationSemantics"] == "PRODUCT_IDENTITY" and item["hardAffectednessEligible"] is False for item in resolution["matches"])
    assert affectedness["affectedness"] == "unknown"
    assert any(item["code"] == "PRODUCT_IDENTITY_NOT_PACKAGE_PROOF" for item in affectedness["diagnostics"])


def test_source_component_only_is_not_package_affectedness_proof(tmp_path):
    repo = _repo(tmp_path)
    source_component_id = _source_component_id(repo)
    component = {"version": "8.0.0", "repoUrl": "https://github.com/curl/curl", "sourceComponentId": source_component_id}

    resolution = resolve_component_identity(repo, component)
    affectedness = query_affectedness(repo, component)

    assert resolution["status"] == "source_only"
    assert resolution["hardAffectednessPackageIds"] == []
    assert any(item["identityKind"] == "source_component_identity" for item in resolution["matches"])
    assert affectedness["affectedness"] == "unknown"
    assert any(item["code"] == "SOURCE_COMPONENT_REQUIRES_PACKAGE_MAPPING" for item in affectedness["diagnostics"])


def test_ambiguous_package_identity_blocks_hard_affectedness(tmp_path):
    repo = _repo(tmp_path)
    repo.upsert_package_identity(
        package_identity_id="pkg:generic/curl-fork",
        canonical_name="curl",
        ecosystem="generic",
        purl="pkg:generic/curl-fork@8.0.0",
        aliases=["libcurl-fork"],
        provenance={"source": "test"},
    )

    resolution = resolve_component_identity(repo, {"name": "curl", "version": "8.0.0"})
    affectedness = query_affectedness(repo, {"name": "curl", "version": "8.0.0"})

    assert resolution["status"] == "ambiguous"
    assert resolution["ambiguous"] is True
    assert set(item["identityId"] for item in resolution["matches"] if item["hardAffectednessEligible"]) >= {"pkg:generic/curl", "pkg:generic/curl-fork"}
    assert affectedness["affectedness"] == "unknown"
    assert affectedness["identityResolution"]["hardAffectednessPackageIds"] == []
    assert any(item["code"] == "IDENTITY_AMBIGUOUS" for item in affectedness["diagnostics"])


def test_canonical_query_keys_include_product_and_source_identity_fields(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    source_component_id = _source_component_id(repo)
    base = {
        "schemaVersion": "s5-judge-query-v1",
        "question": "is this affected",
        "sourceContext": source,
        "controls": {},
    }

    cpe_answer = build_judge_answer(
        repo,
        JudgeQueryRequest.model_validate({**base, "component": {"version": "8.0.0", "cpe": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"}}),
    )
    source_answer = build_judge_answer(
        repo,
        JudgeQueryRequest.model_validate({**base, "component": {"version": "8.0.0", "repoUrl": "https://github.com/curl/curl", "sourceComponentId": source_component_id}}),
    )

    assert cpe_answer["canonicalQuery"]["normalized"]["component"]["cpe"] == "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"
    assert source_answer["canonicalQuery"]["normalized"]["component"]["repoUrl"] == "https://github.com/curl/curl"
    assert source_answer["canonicalQuery"]["normalized"]["component"]["sourceComponentId"] == source_component_id
    assert cpe_answer["decisionFragmentKey"] != source_answer["decisionFragmentKey"]
    cpe_row = repo.get_serving_query_run(cpe_answer["servingLedger"]["servingRunId"])
    source_row = repo.get_serving_query_run(source_answer["servingLedger"]["servingRunId"])
    assert cpe_row["component"]["cpe"] == "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"
    assert source_row["component"]["sourceComponentId"] == source_component_id


def test_judge_cpe_only_grounded_unknown_is_recorded(tmp_path):
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

    assert answer["verdict"] == "unknown"
    assert answer["evidence"]["affectedness"] == []
    assert answer["evidence"]["identityResolution"]["status"] == "product_only"
    assert any(item["code"] == "PRODUCT_IDENTITY_NOT_PACKAGE_PROOF" for item in answer["qualityGate"]["diagnostics"])
    assert answer["followUpAffordances"]
    assert validate_judge_answer(answer) == []
    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row["answer"]["evidence"]["identityResolution"]["status"] == "product_only"


def test_judge_source_only_grounded_unknown_is_recorded(tmp_path):
    reset_decision_cache()
    repo = _repo(tmp_path)
    source = _source_context(repo)
    source_component_id = _source_component_id(repo)
    answer = build_judge_answer(
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

    assert answer["verdict"] == "unknown"
    assert answer["evidence"]["affectedness"] == []
    assert answer["evidence"]["identityResolution"]["status"] == "source_only"
    assert any(item["code"] == "SOURCE_COMPONENT_REQUIRES_PACKAGE_MAPPING" for item in answer["qualityGate"]["diagnostics"])
    assert answer["followUpAffordances"]
    assert validate_judge_answer(answer) == []
    row = repo.get_serving_query_run(answer["servingLedger"]["servingRunId"])
    assert row["answer"]["evidence"]["identityResolution"]["status"] == "source_only"
