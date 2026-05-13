from __future__ import annotations

from fastapi.testclient import TestClient

from app.contracts.source_kg import source_code_kg_contract_snapshot
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_source_code_kg_contract_snapshot_declares_s5_owned_producer_contract():
    contract = source_code_kg_contract_snapshot()

    assert contract["schemaVersion"] == "s5-source-code-kg-contracts-v1"
    assert contract["sourceCodeKgContractVersion"] == "source-code-kg-ingest-v1"
    assert contract["endpoint"] == {
        "method": "POST",
        "path": "/v1/source-code-kg/ingest",
        "requestSchemaVersion": "s5-source-code-kg-ingest-request-v1",
        "resultSchemaVersion": "s5-source-code-kg-ingest-result-v1",
    }
    assert contract["consumerBoundary"]["owner"] == "s5"
    assert contract["consumerBoundary"]["producers"] == ["s3", "s4"]
    assert contract["consumerBoundary"]["storageTruth"] == "s5_sql_ledger"
    assert contract["consumerBoundary"]["projectionTruth"] is False
    assert contract["consumerBoundary"]["productionWritesDefault"] == {"neo4j": False, "qdrant": False}
    assert contract["consumerBoundary"]["notFinalSecurityVerdict"] is True
    assert "commitHash" in contract["producerRequirements"]["repositorySnapshot"]
    assert "richIrArtifacts" in contract["producerRequirements"]
    assert "sourceArtifacts" in contract["producerRequirements"]


def test_source_code_kg_contract_includes_request_and_result_json_schemas():
    contract = source_code_kg_contract_snapshot()
    request_schema = contract["requestJsonSchema"]
    result_schema = contract["resultJsonSchema"]

    assert request_schema["properties"]["repositorySnapshot"]
    assert request_schema["properties"]["sourceArtifacts"]
    assert request_schema["properties"]["evidenceSnippets"]
    assert request_schema["properties"]["graphNodes"]
    assert request_schema["properties"]["graphEdges"]
    assert request_schema["properties"]["richIrArtifacts"]
    assert "repositorySnapshot" in request_schema["required"]
    assert "buildContext" in request_schema["required"]
    assert "analysisArtifactSet" in request_schema["required"]

    assert result_schema["properties"]["ledgerOnly"]
    assert result_schema["properties"]["productionWrites"]
    assert result_schema["properties"]["repositorySnapshotId"]


def test_source_code_kg_contract_endpoint_is_read_only_and_request_id_safe():
    response = client.get("/v1/contracts/source-code-kg", headers={"X-Request-Id": "req-source-kg-contract"})

    assert response.status_code == 200
    body = response.json()
    assert body["sourceCodeKgContractVersion"] == "source-code-kg-ingest-v1"
    assert body["endpoint"]["path"] == "/v1/source-code-kg/ingest"
    assert body["consumerBoundary"]["routineAnswersShouldExposeSnippetsNotFullSource"] is True
    assert any("ledger-only" in guardrail for guardrail in body["guardrails"])
