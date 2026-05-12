"""S5 acquisition contract v1 freeze tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from app.contracts.acquisition import (
    ACQUISITION_READINESS_CONTRACT_VERSION,
    KNOWLEDGE_COVERAGE_CONTRACT_VERSION,
    apply_no_hit_safety,
    contract_snapshot,
    evaluate_no_hit_eligibility,
)
from app.ledger.repository import SQLiteLedgerRepository
from app.main import app
from app.routers import target_context_api
from app.target_context_service import TargetContextService

client = TestClient(app, raise_server_exceptions=False)
_HEADERS = {"X-Timeout-Ms": "30000", "X-Request-Id": "req-contract-test"}


@pytest.fixture(autouse=True)
def _reset_target_context_state(tmp_path):
    old = {
        "target": target_context_api._target_context_service,
        "code_graph": target_context_api._code_graph_service,
        "code_vec": target_context_api._code_vector_search,
        "code_asm": target_context_api._code_assembler,
        "knowledge_asm": target_context_api._knowledge_assembler,
        "nvd": target_context_api._nvd_client,
    }
    ledger = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    target_context_api.set_target_context_service(
        TargetContextService(
            str(tmp_path / "target-contexts.json"),
            ledger_repository=ledger,
        )
    )
    target_context_api.set_code_graph_service(None)
    target_context_api.set_code_vector_search(None)
    target_context_api.set_code_assembler(None)
    target_context_api.set_knowledge_assembler(None)
    target_context_api.set_nvd_client(None)
    yield
    target_context_api.set_target_context_service(old["target"])
    target_context_api.set_code_graph_service(old["code_graph"])
    target_context_api.set_code_vector_search(old["code_vec"])
    target_context_api.set_code_assembler(old["code_asm"])
    target_context_api.set_knowledge_assembler(old["knowledge_asm"])
    target_context_api.set_nvd_client(old["nvd"])


@pytest.fixture()
def target_bundle():
    return {
        "schemaVersion": "target-context-v1",
        "projectId": "re100",
        "target": {
            "targetId": "re100:gateway-webserver",
            "path": "gateway-webserver",
            "buildUnitId": "re100-gateway-webserver",
        },
        "provenance": {
            "buildSnapshotId": "bsnap-contract",
            "buildUnitId": "re100-gateway-webserver",
        },
        "codeGraph": {"projectId": "re100-gateway-webserver", "functions": []},
        "libraries": [],
    }


class EmptyCodeAssembler:
    def search(self, project_id, query, **kwargs):
        return {"query": query, "hits": [], "total": 0, "match_type_counts": {}}


def _ingest(bundle):
    resp = client.post("/v1/target-contexts", json=bundle, headers=_HEADERS)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_contract_snapshot_freezes_coverage_and_readiness_vocabularies():
    snapshot = contract_snapshot()

    assert snapshot["knowledgeCoverageContractVersion"] == KNOWLEDGE_COVERAGE_CONTRACT_VERSION
    assert snapshot["acquisitionReadinessContractVersion"] == ACQUISITION_READINESS_CONTRACT_VERSION

    provided = set(snapshot["knowledgeCoverage"]["providedSurfaces"])
    for surface in {
        "weaknessTaxonomy",
        "publicVulnerabilityKnowledge",
        "cveCandidateEvaluation",
        "cveDiscovery",
        "semanticThreatRetrieval",
        "semanticCodeRetrieval",
        "structuralCodeProjection",
        "dangerousCallerTraversal",
        "providerFreshness",
        "projectionState",
    }:
        assert surface in provided

    assert set(snapshot["knowledgeCoverage"]["notProvidedSurfaces"]) >= {
        "finalSecurityVerdict",
        "cleanPass",
        "runtimeBehavior",
        "exploitabilityJudgment",
        "completeProjectSafety",
    }


def test_runtime_offline_and_s3_final_claim_vocabularies_are_separate():
    vocab = contract_snapshot()["vocabulary"]

    runtime = set(vocab["runtimeAcquisition"])
    offline = set(vocab["offlineQualityEvaluation"])
    s3_final = vocab["s3FinalClaimQuality"]

    assert {"candidate_returned", "no_candidate_returned", "consumerPolicy", "retrievalTrace"} <= runtime
    assert not runtime.intersection({"true_positive", "false_positive", "false_negative", "recall", "precision", "NDCG", "MRR"})
    assert {"true_positive", "false_positive", "false_negative", "recall", "precision", "NDCG", "MRR"} <= offline
    assert s3_final["owner"] == "s3"
    assert "accepted_claim" in s3_final["notS5Outputs"]
    assert "clean_pass" in s3_final["notS5Outputs"]


def test_readiness_schema_has_s3_required_fields_for_every_surface():
    readiness = contract_snapshot()["acquisitionReadiness"]
    required_fields = set(readiness["requiredFields"])
    expected = {
        "scope",
        "requiredInputs",
        "missingInputs",
        "providerState",
        "projectionState",
        "methodsRequiredForNoHit",
        "methodsAttempted",
        "methodsSucceeded",
        "fallbackPolicy",
        "retryGuidance",
        "diagnostics",
    }
    assert expected <= required_fields

    for surface, schema in readiness["surfaces"].items():
        assert surface
        assert expected <= set(schema)


def test_cve_candidate_evaluation_and_discovery_are_distinct_with_oracles():
    snapshot = contract_snapshot()
    cve = snapshot["knowledgeCoverage"]["cveSurfaces"]

    assert cve["cveCandidateEvaluation"]["question"] != cve["cveDiscovery"]["question"]
    assert cve["cveCandidateEvaluation"]["versionMatchFalseMeaning"] == "specific_candidate_range_out_only"
    assert cve["cveDiscovery"]["canCoexistWithCandidateRangeOut"] is True

    oracle_ids = {oracle["id"] for oracle in snapshot["cveSplitOracles"]}
    assert {
        "candidate-range-out-discovery-no-hit",
        "candidate-range-out-discovery-hit",
        "unknown-version-input-insufficient",
        "keyword-only-no-result-not-no-hit",
        "provider-timeout-error-envelope",
        "stale-cache-only-diagnostic",
        "projection-debt-empty-code-not-no-caller",
        "no-hit-plus-failure-not-partial-hit",
    } <= oracle_ids


def test_consumer_policy_mapping_is_evidencecatalog_safe():
    policies = contract_snapshot()["consumerPolicies"]

    assert policies["contextual_only"]["claimSupportAllowed"] is False
    assert policies["contextual_only"]["s3EvidenceRole"] == "knowledge_context_only"
    assert policies["s3_may_derive_local_support_if_refs_validate"]["claimSupportAllowed"] == "only_after_s3_validates_source_local_refs"
    assert policies["do_not_use_as_negative_evidence"]["negativeEvidenceAllowed"] is False
    assert policies["diagnostic_only"]["claimSupportAllowed"] is False


def test_no_hit_validator_downgrades_unsafe_records():
    unsafe = {
        "acquisitionStatus": "completed_no_hit",
        "acquisitionQualityGate": "accepted",
        "consumerPolicy": "scoped_no_hit_record_only",
        "scope": {"query": "popen", "noHitBasis": "keyword_only_no_result"},
        "methodsAttempted": ["keyword_match"],
        "methodsSucceeded": ["keyword_match"],
        "providerState": {"state": "ready"},
        "projectionState": {"state": "ready"},
        "diagnostics": [],
    }

    eligible, reasons = evaluate_no_hit_eligibility(unsafe)
    assert eligible is False
    assert any(reason.startswith("NO_HIT_REQUIRED_METHODS_MISSING") for reason in reasons)
    assert any(reason.startswith("NO_HIT_BASIS_UNSAFE") for reason in reasons)

    downgraded = apply_no_hit_safety(unsafe)
    assert downgraded["acquisitionStatus"] == "incomplete_acquisition"
    assert downgraded["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert downgraded["diagnostics"][-1]["code"] == "UNSAFE_COMPLETED_NO_HIT_DOWNGRADED"


def test_no_hit_validator_allows_explicit_complete_scope():
    safe = {
        "acquisitionStatus": "completed_no_hit",
        "acquisitionQualityGate": "accepted",
        "consumerPolicy": "scoped_no_hit_record_only",
        "scope": {
            "query": "popen",
            "methodsRequiredForNoHit": ["name_exact", "vector_semantic", "graph_neighbor"],
            "noHitBasis": "completed_required_methods",
        },
        "methodsAttempted": ["name_exact", "vector_semantic", "graph_neighbor"],
        "methodsSucceeded": ["name_exact", "vector_semantic", "graph_neighbor"],
        "providerState": {"state": "not_applicable"},
        "projectionState": {"state": "ready"},
    }

    assert evaluate_no_hit_eligibility(safe) == (True, [])
    assert apply_no_hit_safety(safe)["acquisitionStatus"] == "completed_no_hit"


def test_contract_endpoint_returns_code_snapshot_exactly():
    resp = client.get("/v1/contracts/acquisition", headers={"X-Request-Id": "req-contract"})

    assert resp.status_code == 200, resp.text
    assert resp.json() == contract_snapshot()
    assert resp.headers["X-Request-Id"] == "req-contract"


def test_target_context_envelopes_include_contract_metadata(target_bundle):
    body = _ingest(target_bundle)

    assert body["coverageContractVersion"] == KNOWLEDGE_COVERAGE_CONTRACT_VERSION
    assert body["readinessContractVersion"] == ACQUISITION_READINESS_CONTRACT_VERSION
    assert body["runtimeSemantics"]["layer"] == "runtime_acquisition"
    assert body["runtimeSemantics"]["offlineQualityVocabularyPolicy"] == "forbidden_not_enumerated_in_runtime_envelopes"
    assert "offlineQualityVocabularyForbidden" not in body["runtimeSemantics"]
    serialized = str(body["runtimeSemantics"])
    for forbidden in ("true_positive", "false_positive", "false_negative", "recall", "precision", "NDCG", "MRR"):
        assert forbidden not in serialized
    assert "readiness" in body
    assert "providerState" in body["readiness"]
    assert "projectionState" in body["readiness"]


def test_existing_code_search_no_hit_carries_no_hit_eligibility_fields(target_bundle):
    target_context_api.set_code_assembler(EmptyCodeAssembler())
    ingest = _ingest(target_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/code-search",
        json={"query": "missing dangerous caller"},
        headers=_HEADERS,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["acquisitionStatus"] == "incomplete_acquisition"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert body["scope"]["methodsRequiredForNoHit"] == [
        "exact_id_match",
        "constrained_embedding_rerank",
        "graph_expansion",
    ]
    assert body["methodsSucceeded"] == []
    assert body["projectionState"]["state"] == "ready"
    reason_text = " ".join(body["diagnostics"][-1]["reasons"])
    assert "NO_HIT_METHODS_NOT_SUCCEEDED" in reason_text
    assert any(diagnostic["code"] == "NO_HIT_TRACE_MISSING" for diagnostic in body["diagnostics"])
