"""Target-context acquisition contract tests for S5 one-track S3 flow."""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ledger.repository import SQLiteLedgerRepository
from app.projections.ledger_projection import NEO4J_THREAT_PROJECTION, QDRANT_THREAT_PROJECTION, SCOPE_KEY
from app.routers import target_context_api
from app.target_context_service import TargetContextService

_HEADERS = {"X-Timeout-Ms": "30000", "X-Request-Id": "req-target-context-test"}
client = TestClient(app, raise_server_exceptions=False)


class FakeCodeGraphService:
    def __init__(self):
        self.ingests = []

    def ingest(self, project_id, functions, *, provenance=None):
        self.ingests.append((project_id, functions, provenance))
        return {
            "project_id": project_id,
            "nodeCount": len(functions),
            "edgeCount": sum(len(f.get("calls", [])) for f in functions),
            "files": sorted({f.get("file") for f in functions if f.get("file")}),
        }

    def find_dangerous_callers(self, project_id, dangerous_functions, *, build_snapshot_id=None):
        return [
            {
                "name": "postJson",
                "file": "src/http_client.cpp",
                "line": 8,
                "dangerous_calls": ["popen"],
                "provenance": {"buildSnapshotId": build_snapshot_id},
            }
        ]


class EmptyDangerousCodeGraphService(FakeCodeGraphService):
    def find_dangerous_callers(self, project_id, dangerous_functions, *, build_snapshot_id=None):
        return []


class FakeCodeVectorSearch:
    def __init__(self):
        self.ingests = []

    def ingest(self, project_id, functions, *, provenance=None):
        self.ingests.append((project_id, functions, provenance))
        return len(functions)


class SlowCodeGraphService(FakeCodeGraphService):
    def ingest(self, project_id, functions, *, provenance=None):
        time.sleep(0.2)
        return super().ingest(project_id, functions, provenance=provenance)


class SlowTargetContextService:
    def __init__(self, delegate):
        self.delegate = delegate

    def ingest(self, bundle):
        time.sleep(0.08)
        return self.delegate.ingest(bundle)

    def get(self, *args, **kwargs):
        return self.delegate.get(*args, **kwargs)

    def list_contexts(self, *args, **kwargs):
        return self.delegate.list_contexts(*args, **kwargs)


class FakeNvdClient:
    async def batch_lookup(self, libraries):
        results = []
        for lib in libraries:
            name = lib["name"]
            version = lib["version"]
            if name == "badlib":
                results.append({"library": name, "version": version, "cves": [], "total": 0, "error": "provider timeout"})
            elif name == "hitlib":
                results.append({
                    "library": name,
                    "version": version,
                    "cves": [{"id": "CVE-2026-0001", "version_match": True, "source": "nvd"}],
                    "total": 1,
                    "cached": False,
                })
            elif name == "stalelib":
                results.append({
                    "library": name,
                    "version": version,
                    "cves": [],
                    "total": 0,
                    "cached": True,
                    "cacheInfo": {"stale": True, "ttlSeconds": 86400},
                })
            elif name == "rangeoutlib":
                results.append({
                    "library": name,
                    "version": version,
                    "cves": [
                        {"id": "CVE-2026-0001", "version_match": False, "source": "nvd"},
                        {"id": "CVE-2026-0002", "version_match": True, "source": "nvd"},
                    ],
                    "total": 2,
                    "cached": False,
                })
            elif name == "unknownmatchlib":
                results.append({
                    "library": name,
                    "version": version,
                    "cves": [{"id": "CVE-2026-0003", "version_match": None, "source": "nvd"}],
                    "total": 1,
                    "cached": False,
                })
            elif name == "absentcandidate":
                results.append({
                    "library": name,
                    "version": version,
                    "cves": [{"id": "CVE-2026-0004", "version_match": True, "source": "nvd"}],
                    "total": 1,
                    "cached": False,
                })
            else:
                results.append({"library": name, "version": version, "cves": [], "total": 0, "cached": False})
        return results


class SlowNvdClient:
    async def batch_lookup(self, libraries):
        await asyncio.sleep(0.2)
        return []


class ErrorNvdClient:
    async def batch_lookup(self, libraries):
        raise RuntimeError("provider exploded")


class FakeCodeAssembler:
    def search(self, project_id, query, **kwargs):
        return {"query": query, "hits": [], "total": 0, "match_type_counts": {}}


class FakeKnowledgeAssembler:
    def assemble(self, query, **kwargs):
        return {"query": query, "hits": [{"id": "CWE-78"}], "total": 1, "match_type_counts": {}}


@pytest.fixture(autouse=True)
def _reset_state(tmp_path):
    old = {
        "target": target_context_api._target_context_service,
        "code_graph": target_context_api._code_graph_service,
        "code_vec": target_context_api._code_vector_search,
        "code_asm": target_context_api._code_assembler,
        "knowledge_asm": target_context_api._knowledge_assembler,
        "nvd": target_context_api._nvd_client,
        "ledger": target_context_api._ledger_repository,
    }
    ledger = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    service = TargetContextService(
        str(tmp_path / "target-contexts.json"),
        ledger_repository=ledger,
    )
    target_context_api.set_target_context_service(service)
    target_context_api.set_ledger_repository(ledger)
    target_context_api.set_code_graph_service(None)
    target_context_api.set_code_vector_search(None)
    target_context_api.set_code_assembler(None)
    target_context_api.set_knowledge_assembler(None)
    target_context_api.set_nvd_client(None)
    yield service
    target_context_api.set_target_context_service(old["target"])
    target_context_api.set_ledger_repository(old["ledger"])
    target_context_api.set_code_graph_service(old["code_graph"])
    target_context_api.set_code_vector_search(old["code_vec"])
    target_context_api.set_code_assembler(old["code_asm"])
    target_context_api.set_knowledge_assembler(old["knowledge_asm"])
    target_context_api.set_nvd_client(old["nvd"])


@pytest.fixture()
def full_bundle():
    return {
        "schemaVersion": "target-context-v1",
        "projectId": "re100",
        "target": {
            "targetId": "re100:gateway-webserver",
            "name": "gateway-webserver",
            "path": "gateway-webserver",
            "buildUnitId": "re100-gateway-webserver",
            "targetKind": "application",
        },
        "provenance": {
            "snapshotSchemaVersion": "build-snapshot-v1",
            "buildSnapshotId": "bsnap-123",
            "buildUnitId": "re100-gateway-webserver",
            "sourceBuildAttemptId": "attempt-789",
        },
        "buildProfile": {
            "compiler": "arm-linux-gnueabihf-gcc",
            "targetArch": "armv7",
            "domainTags": ["automotive", "embedded"],
            "exposedSurfaces": ["network"],
        },
        "libraries": [
            {
                "name": "hitlib",
                "version": "1.0.0",
                "repoUrl": "https://github.com/org/hitlib.git",
                "commit": "abc123",
                "versionStatus": "known",
                "cveLookupEligible": True,
                "evidenceRefId": "eref-lib-hit",
            },
            {"name": "keywordlib", "version": "2.0.0", "versionStatus": "known"},
            {"name": "versionless", "versionStatus": "unknown", "cveLookupEligible": False},
            {"name": "badlib", "version": "3.0.0", "repoUrl": "https://github.com/org/badlib.git"},
        ],
        "codeGraph": {
            "mode": "embedded-normalized-functions",
            "projectId": "re100-gateway-webserver",
            "functions": [
                {
                    "name": "postJson",
                    "file": "src/http_client.cpp",
                    "line": 8,
                    "calls": ["popen", "fgets"],
                    "evidenceRefId": "eref-sast-postjson",
                }
            ],
        },
        "evidenceRefs": ["eref-sast-postjson"],
    }


def _ingest(bundle):
    resp = client.post("/v1/target-contexts", json=bundle, headers=_HEADERS)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _assert_no_offline_quality_vocab_leak(body):
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                yield str(key)
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)
        else:
            yield str(value)

    atoms = set(walk(body))
    serialized = " ".join(atoms)
    forbidden = [
        "true_positive",
        "false_positive",
        "false_negative",
        "Precision@k",
        "Recall@k",
        "NDCG@k",
        "recall",
        "precision",
        "NDCG",
        "MRR",
    ]
    assert not [token for token in forbidden if token in atoms or token.lower() in serialized.lower()]


def test_target_context_ingest_returns_durable_ids_and_persists_code_graph(full_bundle):
    code_graph = FakeCodeGraphService()
    target_context_api.set_code_graph_service(code_graph)
    target_context_api.set_code_vector_search(FakeCodeVectorSearch())

    body = _ingest(full_bundle)

    assert body["schemaVersion"] == "acquisition-envelope-v1"
    assert body["surface"] == "target-context-ingest"
    assert body["acquisitionStatus"] == "completed_hit"
    assert body["acquisitionQualityGate"] == "accepted"
    assert body["targetKnowledgeId"].startswith("tctx-")
    assert body["targetContextVersion"] == 1
    assert body["results"]["targetContextInputHash"].startswith("sha256:")
    assert body["results"]["reused"] is False
    assert body["itemAcquisitions"][0]["itemType"] == "codeGraph"
    assert body["itemAcquisitions"][0]["consumerPolicy"] == "s3_may_derive_local_support_if_refs_validate"
    assert code_graph.ingests[0][0] == "re100-gateway-webserver"


def test_target_context_ingest_exposes_vector_index_caveat_without_silent_fallback(full_bundle):
    target_context_api.set_code_graph_service(FakeCodeGraphService())

    body = _ingest(full_bundle)

    assert body["acquisitionStatus"] == "completed_hit"
    assert body["acquisitionQualityGate"] == "accepted_with_caveats"
    assert body["results"]["projectionReady"] is False
    item = body["itemAcquisitions"][0]
    assert item["acquisitionQualityGate"] == "accepted_with_caveats"
    assert item["diagnostics"][0]["code"] == "CODE_VECTOR_UNAVAILABLE"


def test_target_context_ingest_graph_projection_timeout_returns_envelope(full_bundle):
    vector_search = FakeCodeVectorSearch()
    target_context_api.set_code_graph_service(SlowCodeGraphService())
    target_context_api.set_code_vector_search(vector_search)

    resp = client.post(
        "/v1/target-contexts",
        json=full_bundle,
        headers={**_HEADERS, "X-Timeout-Ms": "50"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["schemaVersion"] == "acquisition-envelope-v1"
    assert body["surface"] == "target-context-ingest"
    assert body["targetKnowledgeId"].startswith("tctx-")
    assert body["acquisitionStatus"] == "timeout"
    assert body["acquisitionQualityGate"] == "inconclusive"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert body["results"]["projectionReady"] is False
    item = body["itemAcquisitions"][0]
    assert item["acquisitionStatus"] == "timeout"
    assert item["scope"]["graphProjectionReady"] is False
    assert item["diagnostics"][0]["code"] == "TARGET_CONTEXT_GRAPH_PROJECTION_TIMEOUT"
    assert vector_search.ingests == []


def test_target_context_durable_ingest_does_not_false_408_before_projection_timeout(full_bundle, _reset_state):
    vector_search = FakeCodeVectorSearch()
    target_context_api.set_target_context_service(SlowTargetContextService(_reset_state))
    target_context_api.set_code_graph_service(FakeCodeGraphService())
    target_context_api.set_code_vector_search(vector_search)

    resp = client.post(
        "/v1/target-contexts",
        json=full_bundle,
        headers={**_HEADERS, "X-Timeout-Ms": "50"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["schemaVersion"] == "acquisition-envelope-v1"
    assert body["surface"] == "target-context-ingest"
    assert body["targetKnowledgeId"].startswith("tctx-")
    assert body["acquisitionStatus"] == "timeout"
    assert body["acquisitionQualityGate"] == "inconclusive"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert body["itemAcquisitions"][0]["diagnostics"][0]["code"] == "TARGET_CONTEXT_GRAPH_PROJECTION_TIMEOUT"
    assert vector_search.ingests == []


def test_target_context_ingest_is_idempotent_for_same_hash(full_bundle):
    first = _ingest(full_bundle)
    second = _ingest(full_bundle)

    assert second["targetKnowledgeId"] == first["targetKnowledgeId"]
    assert second["targetContextVersion"] == 1
    assert second["results"]["reused"] is True
    assert second["results"]["targetContextInputHash"] == first["results"]["targetContextInputHash"]


def test_target_context_changed_input_creates_new_version(full_bundle):
    first = _ingest(full_bundle)
    changed = {**full_bundle, "buildProfile": {**full_bundle["buildProfile"], "osFamily": "linux"}}
    second = _ingest(changed)

    assert second["targetKnowledgeId"] == first["targetKnowledgeId"]
    assert second["targetContextVersion"] == 2
    assert second["results"]["reused"] is False


def test_target_context_insufficient_identity_is_diagnostic_not_global_fallback():
    body = _ingest({"schemaVersion": "target-context-v1", "projectId": "re100"})

    assert body["acquisitionStatus"] == "input_insufficient"
    assert body["acquisitionQualityGate"] == "rejected"
    assert body["consumerPolicy"] == "do_not_use"
    assert body["targetKnowledgeId"] is None
    assert body["diagnostics"][0]["code"] == "TARGET_IDENTITY_INSUFFICIENT"
    assert "target.targetId|target.path|target.name" in body["diagnostics"][0]["missingFields"]


def test_target_scoped_cve_acquire_returns_per_item_acquisition_diagnostics(full_bundle, _reset_state):
    target_context_api.set_nvd_client(FakeNvdClient())
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/cve",
        json={},
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["schemaVersion"] == "acquisition-envelope-v1"
    assert body["surface"] == "cve"
    assert body["acquisitionStatus"] == "partial_hit"
    assert body["acquisitionQualityGate"] == "inconclusive"
    assert len(body["itemAcquisitions"]) == 4

    items = {item["itemKey"]: item for item in body["itemAcquisitions"]}
    assert items["hitlib@1.0.0"]["acquisitionStatus"] == "completed_hit"
    assert items["hitlib@1.0.0"]["results"]["cves"][0]["versionMatchReason"] == "matched_nvd_cpe_range"
    assert items["keywordlib@2.0.0"]["acquisitionStatus"] == "incomplete_acquisition"
    assert items["keywordlib@2.0.0"]["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert items["keywordlib@2.0.0"]["fallbackTrace"][0]["to"] == "nvd_keyword"
    assert items["versionless@<unknown>"]["acquisitionStatus"] == "input_insufficient"
    assert items["badlib@3.0.0"]["acquisitionStatus"] == "incomplete_acquisition"
    _assert_no_offline_quality_vocab_leak(body)

    compat_obs = {
        obs["subjectKey"]: obs
        for obs in _reset_state._ledger.list_provider_observations("target_context_cve_compat")
    }
    assert compat_obs["hitlib@1.0.0"]["payload"]["providerState"]["state"] == "ready"
    assert compat_obs["versionless@<unknown>"]["payload"]["providerState"]["state"] == "input_insufficient"
    assert compat_obs["badlib@3.0.0"]["payload"]["providerState"]["state"] == "incomplete_acquisition"


def test_target_scoped_cve_not_ready_is_not_no_hit(full_bundle):
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/cve",
        json={"libraries": [{"name": "hitlib", "version": "1.0.0"}]},
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["acquisitionStatus"] == "not_ready"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    item = body["itemAcquisitions"][0]
    assert item["acquisitionStatus"] == "not_ready"
    assert item["diagnostics"][0]["code"] == "NVD_CLIENT_NOT_READY"


def test_target_scoped_cve_provider_timeout_returns_acquisition_envelope(full_bundle):
    target_context_api.set_nvd_client(SlowNvdClient())
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/cve",
        json={"libraries": [{"name": "hitlib", "version": "1.0.0", "repoUrl": "https://github.com/org/hitlib.git"}]},
        headers={**_HEADERS, "X-Timeout-Ms": "50"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["schemaVersion"] == "acquisition-envelope-v1"
    assert body["acquisitionStatus"] == "timeout"
    assert body["acquisitionQualityGate"] == "inconclusive"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    item = body["itemAcquisitions"][0]
    assert item["acquisitionStatus"] == "timeout"
    assert item["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert item["diagnostics"][0]["code"] == "CVE_PROVIDER_TIMEOUT"


def test_target_scoped_cve_provider_error_returns_acquisition_envelope(full_bundle):
    target_context_api.set_nvd_client(ErrorNvdClient())
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/cve",
        json={"libraries": [{"name": "hitlib", "version": "1.0.0", "repoUrl": "https://github.com/org/hitlib.git"}]},
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["schemaVersion"] == "acquisition-envelope-v1"
    assert body["acquisitionStatus"] == "error"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    item = body["itemAcquisitions"][0]
    assert item["acquisitionStatus"] == "error"
    assert item["diagnostics"][0]["code"] == "CVE_PROVIDER_ERROR"


def test_target_scoped_cve_no_hit_plus_input_insufficient_is_not_partial_hit(full_bundle):
    target_context_api.set_nvd_client(FakeNvdClient())
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/cve",
        json={"libraries": [
            {"name": "rangemiss", "version": "1.0.0", "repoUrl": "https://github.com/org/rangemiss.git"},
            {"name": "versionless"},
        ]},
        headers=_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["acquisitionStatus"] == "incomplete_acquisition"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    items = {item["itemKey"]: item for item in body["itemAcquisitions"]}
    assert items["rangemiss@1.0.0"]["acquisitionStatus"] == "completed_no_hit"
    assert items["versionless@<unknown>"]["acquisitionStatus"] == "input_insufficient"


def test_target_scoped_cve_stale_cache_only_is_not_no_hit(full_bundle):
    target_context_api.set_nvd_client(FakeNvdClient())
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/cve",
        json={"libraries": [{"name": "stalelib", "version": "4.0.0"}]},
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["acquisitionStatus"] == "stale_cache_only"
    item = body["itemAcquisitions"][0]
    assert item["acquisitionStatus"] == "stale_cache_only"
    assert item["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert "STALE_CACHE_ONLY" in {diag["code"] for diag in item["diagnostics"]}
    assert "cache" in {trace["to"] for trace in item["fallbackTrace"]}
    assert item["results"]["lookupMethodsSucceeded"] == ["cache"]


def test_target_scoped_cve_conflicting_version_evidence_is_not_no_hit(full_bundle):
    target_context_api.set_nvd_client(FakeNvdClient())
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/cve",
        json={
            "libraries": [{
                "name": "conflictlib",
                "version": "5.0.0",
                "versionStatus": "conflicting",
                "evidenceRefId": "eref-conflict-lib",
            }]
        },
        headers=_HEADERS,
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["acquisitionStatus"] == "conflicting_evidence"
    item = body["itemAcquisitions"][0]
    assert item["acquisitionStatus"] == "conflicting_evidence"
    assert item["acquisitionQualityGate"] == "inconclusive"
    assert item["sourceEvidenceRefs"] == ["eref-conflict-lib"]
    assert item["diagnostics"][0]["code"] == "CONFLICTING_VERSION_EVIDENCE"


def test_cve_aggregate_status_does_not_count_no_hit_as_hit():
    def item(status):
        return {"acquisitionStatus": status}

    assert target_context_api._aggregate_status([item("completed_no_hit")])[0] == "completed_no_hit"
    assert target_context_api._aggregate_status([item("input_insufficient")])[0] == "input_insufficient"
    assert target_context_api._aggregate_status([item("timeout")])[0] == "timeout"
    assert target_context_api._aggregate_status([item("not_ready")])[0] == "not_ready"
    assert target_context_api._aggregate_status([item("completed_hit"), item("timeout")])[0] == "partial_hit"
    assert target_context_api._aggregate_status([item("completed_no_hit"), item("timeout")])[0] == "incomplete_acquisition"
    assert target_context_api._aggregate_status([item("completed_no_hit"), item("input_insufficient")])[0] == "incomplete_acquisition"
    assert target_context_api._aggregate_status([item("completed_hit"), item("completed_no_hit")])[0] == "partial_hit"


def test_cve_candidate_range_out_is_scoped_and_other_discovery_hits_coexist(full_bundle, _reset_state):
    target_context_api.set_nvd_client(FakeNvdClient())
    ingest = _ingest(full_bundle)
    target_id = ingest["targetKnowledgeId"]
    library = {
        "name": "rangeoutlib",
        "version": "2.0.0",
        "repoUrl": "https://github.com/org/rangeoutlib.git",
        "evidenceRefId": "eref-rangeout-lib",
    }

    candidate_resp = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-candidate-evaluation",
        json={"candidateCveId": "CVE-2026-0001", "library": library},
        headers=_HEADERS,
    )
    assert candidate_resp.status_code == 200, candidate_resp.text
    candidate = candidate_resp.json()

    assert candidate["surface"] == "cveCandidateEvaluation"
    assert candidate["acquisitionStatus"] == "completed_no_hit"
    assert candidate["consumerPolicy"] == "scoped_no_hit_record_only"
    assert candidate["scope"]["candidateCveId"] == "CVE-2026-0001"
    assert candidate["results"]["candidateEvaluation"]["versionMatch"] is False
    assert set(candidate["results"]["candidateEvaluation"]["forbiddenInferences"]) >= {
        "library_safe",
        "no_other_cves",
        "target_clean",
    }
    companion_ids = {
        cve["id"]
        for cve in candidate["results"]["discoveryCompanion"]["otherCveCandidates"]
    }
    assert companion_ids == {"CVE-2026-0002"}
    assert "nvd_cpe" in candidate["methodsSucceeded"]
    _assert_no_offline_quality_vocab_leak(candidate)

    discovery_resp = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-discovery",
        json={"libraries": [library]},
        headers=_HEADERS,
    )
    assert discovery_resp.status_code == 200, discovery_resp.text
    discovery = discovery_resp.json()
    assert discovery["surface"] == "cveDiscovery"
    assert discovery["acquisitionStatus"] == "completed_hit"
    assert discovery["consumerPolicy"] == "contextual_only"
    cve_ids = {cve["id"] for cve in discovery["itemAcquisitions"][0]["results"]["cves"]}
    assert {"CVE-2026-0001", "CVE-2026-0002"} <= cve_ids
    _assert_no_offline_quality_vocab_leak(discovery)

    runs = _reset_state._ledger.list_acquisition_runs()
    assert {run["surface"] for run in runs} >= {"cveCandidateEvaluation", "cveDiscovery"}
    candidate_obs = _reset_state._ledger.list_provider_observations("target_context_cve_candidate")
    discovery_obs = _reset_state._ledger.list_provider_observations("target_context_cve_discovery")
    assert candidate_obs and candidate_obs[0]["acquisitionId"] == candidate["acquisitionId"]
    assert candidate_obs[0]["subjectKey"] == "rangeoutlib@2.0.0|CVE-2026-0001"
    assert candidate_obs[0]["payload"]["candidateCveId"] == "CVE-2026-0001"
    assert "CVE-2026-0002" in candidate_obs[0]["payload"]["cveIds"]
    assert candidate_obs[0]["payload"]["providerState"]["state"] == "ready"
    assert candidate_obs[0]["payload"]["cacheFreshness"]["status"] == "current"
    assert candidate_obs[0]["payload"]["scope"]["candidateCveId"] == "CVE-2026-0001"
    assert "nvd_cpe" in candidate_obs[0]["payload"]["methodsSucceeded"]
    assert discovery_obs and discovery_obs[0]["acquisitionId"] == discovery["acquisitionId"]
    assert discovery_obs[0]["payload"]["providerState"]["state"] == "ready"
    assert "scope" in discovery_obs[0]["payload"]


def test_cve_candidate_unknown_keyword_and_absent_candidate_are_not_no_hit(full_bundle):
    target_context_api.set_nvd_client(FakeNvdClient())
    ingest = _ingest(full_bundle)
    target_id = ingest["targetKnowledgeId"]

    unknown = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-candidate-evaluation",
        json={
            "candidateCveId": "CVE-2026-0003",
            "library": {
                "name": "unknownmatchlib",
                "version": "9.9.9",
                "repoUrl": "https://github.com/org/unknownmatchlib.git",
            },
        },
        headers=_HEADERS,
    ).json()
    assert unknown["acquisitionStatus"] == "input_insufficient"
    assert unknown["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert unknown["diagnostics"][0]["code"] == "CVE_VERSION_MATCH_UNKNOWN"

    keyword_only = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-candidate-evaluation",
        json={"candidateCveId": "CVE-2026-9999", "library": {"name": "keywordonly", "version": "1.0.0"}},
        headers=_HEADERS,
    ).json()
    assert keyword_only["acquisitionStatus"] == "incomplete_acquisition"
    assert keyword_only["consumerPolicy"] == "do_not_use_as_negative_evidence"
    keyword_codes = {diag["code"] for diag in keyword_only["diagnostics"]}
    assert "CANDIDATE_NOT_RETURNED_KEYWORD_ONLY" in keyword_codes
    assert "KEYWORD_ONLY_FALLBACK" in keyword_codes

    absent = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-candidate-evaluation",
        json={
            "candidateCveId": "CVE-2026-9999",
            "library": {
                "name": "absentcandidate",
                "version": "1.2.3",
                "repoUrl": "https://github.com/org/absentcandidate.git",
            },
        },
        headers=_HEADERS,
    ).json()
    assert absent["acquisitionStatus"] == "incomplete_acquisition"
    assert absent["diagnostics"][0]["code"] == "CANDIDATE_NOT_RETURNED_NO_EXPLICIT_RANGE_EVAL"
    for body in (unknown, keyword_only, absent):
        _assert_no_offline_quality_vocab_leak(body)


def test_cve_split_provider_timeout_error_and_stale_are_diagnostic(full_bundle):
    ingest = _ingest(full_bundle)
    target_id = ingest["targetKnowledgeId"]
    library = {"name": "hitlib", "version": "1.0.0", "repoUrl": "https://github.com/org/hitlib.git"}

    target_context_api.set_nvd_client(SlowNvdClient())
    timeout = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-candidate-evaluation",
        json={"candidateCveId": "CVE-2026-0001", "library": library},
        headers={**_HEADERS, "X-Timeout-Ms": "50"},
    ).json()
    assert timeout["surface"] == "cveCandidateEvaluation"
    assert timeout["acquisitionStatus"] == "timeout"
    assert timeout["consumerPolicy"] == "do_not_use_as_negative_evidence"

    target_context_api.set_nvd_client(ErrorNvdClient())
    error = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-discovery",
        json={"libraries": [library]},
        headers=_HEADERS,
    ).json()
    assert error["surface"] == "cveDiscovery"
    assert error["acquisitionStatus"] == "error"
    assert error["consumerPolicy"] == "do_not_use_as_negative_evidence"

    target_context_api.set_nvd_client(FakeNvdClient())
    stale = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-discovery",
        json={"libraries": [{"name": "stalelib", "version": "4.0.0"}]},
        headers=_HEADERS,
    ).json()
    assert stale["surface"] == "cveDiscovery"
    assert stale["acquisitionStatus"] == "stale_cache_only"
    assert stale["consumerPolicy"] == "do_not_use_as_negative_evidence"

    for body in (timeout, error, stale):
        _assert_no_offline_quality_vocab_leak(body)


def test_cve_candidate_failure_paths_keep_candidate_method_scope(full_bundle):
    ingest = _ingest(full_bundle)
    target_id = ingest["targetKnowledgeId"]

    not_ready = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-candidate-evaluation",
        json={
            "candidateCveId": "CVE-2026-0001",
            "library": {"name": "hitlib", "version": "1.0.0", "repoUrl": "https://github.com/org/hitlib.git"},
        },
        headers=_HEADERS,
    ).json()
    item = not_ready["itemAcquisitions"][0]
    assert item["itemType"] == "candidateCve"
    assert item["itemKey"] == "hitlib@1.0.0|CVE-2026-0001"
    assert {"exact_id_match", "provider_range_eval", "nvd_cpe"} <= set(item["scope"]["methodsRequiredForNoHit"])
    assert {"exact_id_match", "provider_range_eval", "nvd_cpe", "nvd_keyword"} <= set(item["methodsAttempted"])

    target_context_api.set_nvd_client(SlowNvdClient())
    timeout = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-candidate-evaluation",
        json={
            "candidateCveId": "CVE-2026-0001",
            "library": {"name": "hitlib", "version": "1.0.0", "repoUrl": "https://github.com/org/hitlib.git"},
        },
        headers={**_HEADERS, "X-Timeout-Ms": "50"},
    ).json()
    timeout_item = timeout["itemAcquisitions"][0]
    assert timeout_item["itemType"] == "candidateCve"
    assert {"exact_id_match", "provider_range_eval", "nvd_cpe"} <= set(timeout_item["scope"]["methodsRequiredForNoHit"])


def test_cve_discovery_and_compat_no_libraries_persist_diagnostic_item_and_observation(full_bundle, _reset_state):
    target_context_api.set_nvd_client(FakeNvdClient())
    no_lib_bundle = {**full_bundle, "libraries": []}
    ingest = _ingest(no_lib_bundle)
    target_id = ingest["targetKnowledgeId"]

    compat = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve",
        json={},
        headers=_HEADERS,
    ).json()
    discovery = client.post(
        f"/v1/target-contexts/{target_id}/acquire/cve-discovery",
        json={},
        headers=_HEADERS,
    ).json()

    assert compat["surface"] == "cve"
    assert compat["itemAcquisitions"][0]["itemKey"] == "cve:no-libraries"
    assert discovery["surface"] == "cveDiscovery"
    assert discovery["itemAcquisitions"][0]["itemKey"] == "cveDiscovery:no-libraries"

    compat_obs = _reset_state._ledger.list_provider_observations("target_context_cve_compat")
    discovery_obs = _reset_state._ledger.list_provider_observations("target_context_cve_discovery")
    assert compat_obs and compat_obs[0]["acquisitionId"] == compat["acquisitionId"]
    assert compat_obs[0]["status"] == "input_insufficient"
    assert compat_obs[0]["payload"]["scope"]["noHitBasis"] == "input_insufficient"
    assert discovery_obs and discovery_obs[0]["acquisitionId"] == discovery["acquisitionId"]
    assert discovery_obs[0]["status"] == "input_insufficient"


def test_target_scoped_code_and_threat_surfaces_return_acquisition_envelope(full_bundle):
    target_context_api.set_code_assembler(FakeCodeAssembler())
    target_context_api.set_knowledge_assembler(FakeKnowledgeAssembler())
    ingest = _ingest(full_bundle)
    target_id = ingest["targetKnowledgeId"]

    code_resp = client.post(
        f"/v1/target-contexts/{target_id}/acquire/code-search",
        json={"query": "network command execution"},
        headers=_HEADERS,
    )
    threat_resp = client.post(
        f"/v1/target-contexts/{target_id}/acquire/threat-search",
        json={"query": "CWE-78"},
        headers=_HEADERS,
    )

    assert code_resp.status_code == 200
    assert code_resp.json()["surface"] == "code-search"
    assert code_resp.json()["acquisitionStatus"] == "incomplete_acquisition"
    assert code_resp.json()["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert any(diagnostic["code"] == "NO_HIT_TRACE_MISSING" for diagnostic in code_resp.json()["diagnostics"])

    assert threat_resp.status_code == 200
    assert threat_resp.json()["surface"] == "threat-search"
    assert threat_resp.json()["acquisitionStatus"] == "completed_hit"
    assert threat_resp.json()["consumerPolicy"] == "contextual_only"


def test_target_scoped_threat_search_forwards_typed_retrieval_request_and_scope_trace(full_bundle):
    class CaptureKnowledgeAssembler:
        def __init__(self):
            self.kwargs = {}

        def assemble(self, query, **kwargs):
            self.kwargs = kwargs
            return {
                "query": query,
                "hits": [{"id": "CVE-2026-0001"}],
                "total": 1,
                "match_type_counts": {},
                "retrievalTrace": {
                    "queryIntent": "cve_discovery",
                    "corpusPartitionsSearched": ["public_vulnerability"],
                    "embeddingScope": "constrained",
                    "methodsAttempted": ["constrained_embedding_rerank"],
                    "methodsSucceeded": ["constrained_embedding_rerank"],
                    "methodsUsed": ["constrained_embedding_rerank"],
                    "returnedCount": 1,
                    "topK": 5,
                    "minScore": 0.35,
                    "globalEmbeddingPolicy": {
                        "allowed": False,
                        "trust": "low",
                        "negativeEvidenceAllowed": False,
                    },
                },
            }

    assembler = CaptureKnowledgeAssembler()
    target_context_api.set_knowledge_assembler(assembler)
    ingest = _ingest(full_bundle)
    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/threat-search",
        json={
            "query": "openssl vulnerabilities",
            "queryIntent": "cve_discovery",
            "corpusPartitions": ["public_vulnerability_knowledge"],
            "profiles": ["embedded-system"],
            "allowGlobalEmbedding": False,
        },
        headers=_HEADERS,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert assembler.kwargs["query_intent"] == "cve_discovery"
    assert assembler.kwargs["corpus_partitions"] == ["public_vulnerability_knowledge"]
    assert assembler.kwargs["profiles"] == ["embedded-system"]
    assert assembler.kwargs["allow_global_embedding"] is False
    assert body["scope"]["retrievalTrace"]["queryIntent"] == "cve_discovery"
    assert body["methodsAttempted"] == ["constrained_embedding_rerank"]


def test_target_scoped_global_embedding_no_hit_is_downgraded(full_bundle):
    class GlobalNoHitKnowledgeAssembler:
        def assemble(self, query, **kwargs):
            return {
                "query": query,
                "hits": [],
                "total": 0,
                "match_type_counts": {},
                "retrievalTrace": {
                    "queryIntent": "project_memory_context",
                    "corpusPartitionsSearched": [],
                    "embeddingScope": "global",
                    "methodsAttempted": ["global_embedding_search"],
                    "methodsSucceeded": ["global_embedding_search"],
                    "methodsUsed": [],
                    "returnedCount": 0,
                    "globalEmbeddingPolicy": {
                        "allowed": True,
                        "trust": "low",
                        "negativeEvidenceAllowed": False,
                    },
                },
            }

    target_context_api.set_knowledge_assembler(GlobalNoHitKnowledgeAssembler())
    ingest = _ingest(full_bundle)
    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/threat-search",
        json={
            "query": "broad legacy context",
            "queryIntent": "project_memory_context",
            "allowGlobalEmbedding": True,
        },
        headers=_HEADERS,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["surface"] == "threat-search"
    assert body["scope"]["noHitBasis"] == "global_embedding_only_no_result"
    assert body["acquisitionStatus"] == "incomplete_acquisition"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert "NO_HIT_BASIS_UNSAFE:global_embedding_only_no_result" in body["diagnostics"][-1]["reasons"]


def test_target_scoped_code_no_hit_is_downgraded_when_ledger_projection_is_debt(full_bundle, _reset_state):
    target_context_api.set_code_assembler(FakeCodeAssembler())
    ingest = _ingest(full_bundle)
    target_id = ingest["targetKnowledgeId"]
    project_id = full_bundle["codeGraph"]["projectId"]
    _reset_state._ledger.record_projection_state(
        projection_name="neo4j-code-graph",
        scope_key=project_id,
        state="debt",
        source_hash="sha256:code",
        projection_version="code-projection-v1",
        debt={"reason": "not_projected"},
        freshness={"status": "debt"},
    )

    resp = client.post(
        f"/v1/target-contexts/{target_id}/acquire/code-search",
        json={"query": "network command execution"},
        headers=_HEADERS,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["surface"] == "code-search"
    assert body["projectionState"]["state"] == "debt"
    assert body["acquisitionStatus"] == "incomplete_acquisition"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert "NO_HIT_PROJECTION_STATE_UNSAFE:debt" in body["diagnostics"][-1]["reasons"]


def test_target_scoped_threat_no_hit_is_downgraded_when_ledger_projection_is_debt(full_bundle, _reset_state):
    class EmptyKnowledgeAssembler:
        def assemble(self, query, **kwargs):
            return {"query": query, "hits": [], "total": 0, "match_type_counts": {}}

    target_context_api.set_knowledge_assembler(EmptyKnowledgeAssembler())
    ingest = _ingest(full_bundle)
    _reset_state._ledger.record_projection_state(
        projection_name=NEO4J_THREAT_PROJECTION,
        scope_key=SCOPE_KEY,
        state="debt",
        source_hash="sha256:threat",
        projection_version="ledger-projection-v1",
        debt={"reason": "neo4j_not_projected"},
        freshness={"status": "debt"},
    )
    _reset_state._ledger.record_projection_state(
        projection_name=QDRANT_THREAT_PROJECTION,
        scope_key=SCOPE_KEY,
        state="ready",
        source_hash="sha256:threat",
        projection_version="ledger-projection-v1",
        debt={},
        freshness={"status": "current"},
    )

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/threat-search",
        json={"query": "CWE-78"},
        headers=_HEADERS,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["surface"] == "threat-search"
    assert body["projectionState"]["state"] == "debt"
    assert body["acquisitionStatus"] == "incomplete_acquisition"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"


def test_target_scoped_dangerous_callers_no_hit_is_downgraded_when_ledger_projection_is_failed(full_bundle, _reset_state):
    target_context_api.set_code_graph_service(EmptyDangerousCodeGraphService())
    ingest = _ingest(full_bundle)
    project_id = full_bundle["codeGraph"]["projectId"]
    _reset_state._ledger.record_projection_state(
        projection_name="neo4j-code-graph",
        scope_key=project_id,
        state="failed",
        source_hash="sha256:code",
        projection_version="code-projection-v1",
        debt={"reason": "neo4j_failure"},
        freshness={"status": "failed"},
    )

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/dangerous-callers",
        json={"dangerous_functions": ["popen"]},
        headers=_HEADERS,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["surface"] == "dangerous-callers"
    assert body["projectionState"]["state"] == "failed"
    assert body["acquisitionStatus"] == "incomplete_acquisition"
    assert body["consumerPolicy"] == "do_not_use_as_negative_evidence"


def test_target_scoped_dangerous_callers_can_derive_local_support_when_refs_validate(full_bundle):
    target_context_api.set_code_graph_service(FakeCodeGraphService())
    ingest = _ingest(full_bundle)

    resp = client.post(
        f"/v1/target-contexts/{ingest['targetKnowledgeId']}/acquire/dangerous-callers",
        json={"dangerous_functions": ["popen"]},
        headers=_HEADERS,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["surface"] == "dangerous-callers"
    assert body["acquisitionStatus"] == "completed_hit"
    assert body["consumerPolicy"] == "s3_may_derive_local_support_if_refs_validate"
    assert body["results"]["results"][0]["dangerous_calls"] == ["popen"]
