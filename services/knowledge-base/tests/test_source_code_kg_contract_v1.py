from __future__ import annotations

import ast
import inspect

from fastapi.testclient import TestClient

from app.contracts.source_kg import source_code_kg_contract_snapshot
from app.ledger import repository as ledger_repository
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


def _source_kg_context_diagnostic_literals(source: str) -> set[str]:
    tree = ast.parse(source)
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("SOURCE_KG_CONTEXT_")
    }


def test_source_code_kg_contract_snapshot_declares_s5_owned_producer_contract():
    contract = source_code_kg_contract_snapshot()

    assert contract["schemaVersion"] == "s5-source-code-kg-contracts-v1"
    assert contract["sourceCodeKgContractVersion"] == "source-code-kg-ingest-v1"
    assert contract["endpoint"] == {
        "method": "POST",
        "path": "/v1/source-code-kg/ingest",
        "requestSchemaVersion": "s5-source-code-kg-ingest-request-v1",
        "resultSchemaVersion": "s5-source-code-kg-ingest-result-v1",
        "timeoutHeaderRequired": True,
        "ledgerOnly": True,
        "timeoutFailurePolicy": {
            "reason": "deadline_exceeded_before_ledger_ingest_completed",
            "ledgerWriteOnTimeout": False,
            "timeoutPhase": "pre_start_only_for_durable_write",
            "postStartTimeoutResponse": "wait_for_completion_and_return_result",
            "minimumSafeStartBudgetMs": 10,
        },
        "errors": {
            "400": ["timeout_header_missing_or_invalid"],
            "422": [
                "request_schema_invalid",
                "ingest_collection_limit_exceeded",
                "ingest_value_too_large",
                "duplicate_source_graph_node_identity",
                "duplicate_source_kg_identity",
                "source_kg_identity_content_conflict",
                "source_kg_lineage_rebind_forbidden",
                "build_context_references_unknown_source_artifact",
                "graph_node_references_unknown_evidence_snippet",
                "graph_edge_references_unknown_node",
            ],
            "503": ["ledger_not_initialized"],
            "408": ["deadline_exceeded_before_ledger_ingest_completed"],
        },
    }
    assert contract["contextEndpoint"] == {
        "method": "POST",
        "path": "/v1/source-code-kg/context",
        "requestSchemaVersion": "s5-source-code-kg-context-request-v1",
        "resultSchemaVersion": "s5-source-code-kg-context-result-v1",
        "timeoutHeaderRequired": True,
        "ledgerOnly": True,
        "errors": {
            "400": ["timeout_header_missing_or_invalid"],
            "422": [
                "request_schema_invalid",
                "no_context_selector",
                "explicit_selector_limit_exceeded",
                "selector_value_too_long",
            ],
            "503": ["ledger_not_initialized"],
            "408": ["deadline_exceeded_before_context_resolution_completed"],
        },
    }
    assert contract["consumerBoundary"]["owner"] == "s5"
    assert contract["consumerBoundary"]["producers"] == ["s3", "s4"]
    assert contract["consumerBoundary"]["storageTruth"] == "s5_sql_ledger"
    assert contract["consumerBoundary"]["projectionTruth"] is False
    assert contract["consumerBoundary"]["productionWritesDefault"] == {"neo4j": False, "qdrant": False}
    assert contract["consumerBoundary"]["notFinalSecurityVerdict"] is True
    assert contract["consumerBoundary"]["contextResolutionRequiredForServing"] is True
    assert "commitHash" in contract["producerRequirements"]["repositorySnapshot"]
    assert "richIrArtifacts" in contract["producerRequirements"]
    assert "sourceArtifacts" in contract["producerRequirements"]
    assert contract["referencePolicy"]["generatedGraphNodeIdsRequireStableIdEdgeRefs"] is True
    assert contract["producerIdentityPolicy"] == {
        "duplicateGraphNodeStableIdsAllowed": False,
        "duplicateExplicitGraphNodeIdsAllowed": False,
        "duplicateExplicitSourceArtifactIdsAllowed": False,
        "duplicateExplicitEvidenceSnippetIdsAllowed": False,
        "duplicateExplicitGraphEdgeIdsAllowed": False,
        "duplicateExplicitRichIrArtifactIdsAllowed": False,
        "duplicateGeneratedSourceArtifactIdsAllowed": False,
            "duplicateGeneratedEvidenceSnippetIdsAllowed": False,
            "duplicateGeneratedGraphEdgeIdsAllowed": False,
            "duplicateGeneratedRichIrArtifactIdsAllowed": False,
            "sameLineageExplicitIdContentMutationAllowed": False,
            "contentIdentityTables": [
                "sourceRepositoryArtifact",
                "sourceBuildContext",
                "sourceAnalysisArtifactSet",
                "sourceEvidenceSnippet",
                "sourceGraphNode",
                "sourceGraphEdge",
                "sourceRichIrArtifact",
            ],
            "generatedIdentityValidationPhase": "after_id_generation_before_ledger_write",
            "contentIdentityValidationPhase": "after_id_generation_before_ledger_write",
            "graphNodeErrorReason": "duplicate_source_graph_node_identity",
            "genericErrorReason": "duplicate_source_kg_identity",
            "contentConflictErrorReason": "source_kg_identity_content_conflict",
            "validationPhase": "pre_ledger_write",
        }
    assert contract["lineageRebindPolicy"] == {
        "explicitRepositorySnapshotIdMayRebindSourceVersion": False,
        "checkedRootIds": ["repositorySnapshotId"],
        "repositorySnapshotIdVersionFields": [
            "repositoryUrl",
            "repositoryId",
            "commitHash",
            "treeHash",
            "submoduleHashes",
        ],
        "explicitContainerIdsMayRebindLineage": False,
        "checkedContainerIds": ["sourceRepositoryArtifactId", "buildContextId", "analysisArtifactSetId"],
        "sourceRepositoryArtifactIdLineage": "repositorySnapshotId",
        "buildContextIdLineage": "repositorySnapshotId",
        "analysisArtifactSetIdLineage": "buildContextId",
        "errorReason": "source_kg_lineage_rebind_forbidden",
        "validationPhase": "pre_ledger_write",
    }
    assert contract["atomicIngestPolicy"] == {
        "transactionScope": "single_sqlite_transaction",
        "partialRowsOnValidationFailure": False,
        "partialRowsOnLateWriteFailure": False,
        "compileCommandsArtifactReferenceErrorReason": "build_context_references_unknown_source_artifact",
    }
    assert contract["servingContextResolution"]["schemaVersion"] == "s5-source-kg-context-resolution-v1"
    assert {"sourceArtifacts", "graphNodes", "evidenceSnippets", "richIrArtifacts"} <= set(contract["servingContextResolution"]["trackedCollections"])
    assert "SOURCE_KG_CONTEXT_PARTIAL" in contract["servingContextResolution"]["diagnosticCodes"]
    assert "SOURCE_KG_CONTEXT_INCONSISTENT" in contract["servingContextResolution"]["diagnosticCodes"]
    assert "SOURCE_KG_CONTEXT_TRUNCATED" in contract["servingContextResolution"]["diagnosticCodes"]
    assert "SOURCE_KG_CONTEXT_REDACTED" in contract["servingContextResolution"]["diagnosticCodes"]
    assert "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED" in contract["servingContextResolution"]["diagnosticCodes"]
    assert contract["servingContextResolution"]["diagnosticCodeCoverage"] == {
        "coverage": "all_known_source_kg_serving_context_diagnostic_codes",
        "knownDiagnosticCodeCount": 5,
    }
    assert contract["servingContextResolution"]["maxWholeAnalysisGraphNodes"] == 64
    assert contract["servingContextResolution"]["maxWholeAnalysisRichIrArtifacts"] == 32
    assert contract["servingContextResolution"]["partialResolutionEchoPolicy"] == {
        "redactCredentialBearingRequestedIds": True,
        "redactCredentialBearingMissingIds": True,
        "storedLedgerValuesRemainRaw": True,
    }
    assert contract["servingContextResolution"]["outOfLineageCollectionPolicy"] == {
        "diagnosticCode": "SOURCE_KG_CONTEXT_INCONSISTENT",
        "redactReturnedRows": True,
        "redactedIdsReportedAsMissing": True,
        "outOfLineageRowsMayBeReturned": False,
        "missingRequestedContainerRowsMayBeReturned": False,
    }
    assert contract["servingContextResolution"]["richIrPayloadPolicy"] == {
        "maxInlineBytes": 2048,
        "payloadRedactedWhenOverLimit": True,
        "payloadTruncatedMetadataFields": ["payloadByteLength", "payloadMaxInlineBytes", "payloadTruncated", "payloadRedacted"],
    }
    assert contract["servingContextResolution"]["sourceSnippetTextPolicy"] == {
        "maxInlineBytes": 2048,
        "truncateWhenOverLimit": True,
        "truncationMetadataFields": ["snippetTextByteLength", "snippetTextMaxInlineBytes", "snippetTextTruncated"],
    }
    assert contract["servingContextResolution"]["nestedObjectPolicy"] == {
        "maxInlineBytes": 2048,
        "redactWhenOverLimit": True,
        "redactedFields": [
            "repositorySnapshot.submoduleHashes",
            "repositorySnapshot.metadata",
            "repositorySnapshot.provenance",
            "sourceArtifacts[].metadata",
            "sourceArtifacts[].provenance",
            "buildContext.toolchain",
            "buildContext.dependencyGraph",
            "buildContext.buildMetadata",
            "buildContext.provenance",
            "analysisArtifactSet.analysisConfig",
            "analysisArtifactSet.artifactHashes",
            "analysisArtifactSet.provenance",
            "graphNodes[].symbol",
            "graphNodes[].metadata",
            "graphEdges[].evidence",
            "graphEdges[].metadata",
            "evidenceSnippets[].provenance",
            "richIrArtifacts[].provenance",
        ],
        "redactionMetadataSuffixes": ["ByteLength", "MaxInlineBytes", "Truncated", "Redacted"],
        "nestedUrlRedaction": {
            "redactStringValues": True,
            "redactStringKeys": True,
            "redactUserinfoAndSensitiveQuery": True,
            "byteBudgetMeasuredBeforeUrlRedaction": True,
        },
        "storedLedgerValuesRemainRaw": True,
    }
    assert contract["servingContextResolution"]["compileCommandsArtifactPolicy"] == {
        "includeReferencedArtifactWhenBuildContextSelected": True,
        "redactArtifactUriUserinfoAndSensitiveQuery": True,
        "storedLedgerValuesRemainRaw": True,
        "servedFields": [
            "sourceRepositoryArtifactId",
            "repositorySnapshotId",
            "artifactUri",
            "mediaType",
            "checksumSha256",
            "storageMode",
            "metadata",
            "provenance",
        ],
        "resolutionAccounting": {
            "collection": "sourceArtifacts",
            "resolvedVia": "buildContext.compileCommandsArtifactId",
            "includedOnlyWhenBuildContextResolved": True,
            "contextResolutionEntry": "sourceArtifacts",
            "missingDiagnosticField": "sourceArtifactIds",
        },
    }
    assert contract["servingContextResolution"]["projectionDiagnosticPolicy"] == {
        "redactedDiagnosticCode": "SOURCE_KG_CONTEXT_REDACTED",
        "truncatedDiagnosticCode": "SOURCE_KG_CONTEXT_TRUNCATED",
        "diagnosticsTruncatedCode": "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED",
        "maxProjectionDiagnostics": 64,
        "redactedOrTruncatedProjectionMakesContextComplete": False,
        "redactedOrTruncatedProjectionMakesContextPartial": True,
        "diagnosticMetadataFields": ["field", "redacted", "truncated", "byteLength", "maxInlineBytes"],
        "diagnosticTruncationMetadataFields": ["field", "totalCount", "returnedCount", "maxCount"],
        "judgeMustTreatAsDegradedSourceContext": True,
    }
    assert contract["servingContextResolution"]["urlRedactionPolicy"] == {
        "redactRepositoryUrlUserinfoAndSensitiveQuery": True,
        "redactSourceArtifactUriUserinfoAndSensitiveQuery": True,
        "redactRichIrUriUserinfoAndSensitiveQuery": True,
        "storedLedgerValuesRemainRaw": True,
        "redactedFields": ["repositorySnapshot.repositoryUrl", "sourceArtifacts[].artifactUri", "richIrArtifacts[].uri"],
    }


def test_source_code_kg_contract_covers_every_serving_context_diagnostic_code():
    contract = source_code_kg_contract_snapshot()
    emitted_codes = _source_kg_context_diagnostic_literals(inspect.getsource(ledger_repository))
    contract_codes = set(contract["servingContextResolution"]["diagnosticCodes"])

    assert emitted_codes == contract_codes
    assert contract["servingContextResolution"]["diagnosticCodeCoverage"] == {
        "coverage": "all_known_source_kg_serving_context_diagnostic_codes",
        "knownDiagnosticCodeCount": len(emitted_codes),
    }
    assert contract["servingContextResolution"]["explicitSelectorLimitPolicy"] == {
        "maxGraphNodeIds": 256,
        "maxEvidenceSnippetIds": 256,
        "maxRichIrArtifactIds": 128,
        "maxSelectorValueLength": 512,
        "errorReason": "explicit_selector_limit_exceeded",
        "valueTooLongErrorReason": "selector_value_too_long",
    }
    assert contract["ingestSizePolicy"] == {
        "maxSourceArtifacts": 1024,
        "maxEvidenceSnippets": 4096,
        "maxGraphNodes": 8192,
        "maxGraphEdges": 16384,
        "maxRichIrArtifacts": 2048,
        "maxProducerOrReferenceIdLength": 512,
        "maxSnippetTextChars": 65536,
        "maxNestedObjectBytes": 65536,
        "maxTotalNestedObjectBytes": 1048576,
        "nestedObjectFields": [
            "repositorySnapshot.submoduleHashes",
            "repositorySnapshot.metadata",
            "repositorySnapshot.provenance",
            "sourceArtifacts[].metadata",
            "sourceArtifacts[].provenance",
            "buildContext.toolchain",
            "buildContext.dependencyGraph",
            "buildContext.buildMetadata",
            "buildContext.provenance",
            "analysisArtifactSet.analysisConfig",
            "analysisArtifactSet.artifactHashes",
            "analysisArtifactSet.provenance",
            "evidenceSnippets[].provenance",
            "graphNodes[].symbol",
            "graphNodes[].metadata",
            "graphEdges[].evidence",
            "graphEdges[].metadata",
            "richIrArtifacts[].provenance",
        ],
        "maxRichIrPayloadBytes": 262144,
        "collectionLimitErrorReason": "ingest_collection_limit_exceeded",
        "valueTooLargeErrorReason": "ingest_value_too_large",
    }


def test_source_code_kg_contract_includes_request_and_result_json_schemas():
    contract = source_code_kg_contract_snapshot()
    request_schema = contract["requestJsonSchema"]
    result_schema = contract["resultJsonSchema"]

    assert request_schema["properties"]["repositorySnapshot"]
    assert request_schema["properties"]["sourceArtifacts"]
    assert request_schema["properties"]["sourceArtifacts"]["maxItems"] == 1024
    assert request_schema["properties"]["evidenceSnippets"]
    assert request_schema["properties"]["evidenceSnippets"]["maxItems"] == 4096
    assert request_schema["properties"]["graphNodes"]
    assert request_schema["properties"]["graphNodes"]["maxItems"] == 8192
    assert request_schema["properties"]["graphEdges"]
    assert request_schema["properties"]["graphEdges"]["maxItems"] == 16384
    assert request_schema["properties"]["richIrArtifacts"]
    assert request_schema["properties"]["richIrArtifacts"]["maxItems"] == 2048
    assert request_schema["$defs"]["SourceGraphEdge"]["properties"]["sourceGraphNodeId"]["anyOf"][0]["maxLength"] == 512
    assert request_schema["$defs"]["SourceGraphEdge"]["properties"]["targetGraphNodeId"]["anyOf"][0]["maxLength"] == 512
    assert request_schema["$defs"]["SourceGraphNode"]["properties"]["stableId"]["maxLength"] == 512
    assert request_schema["$defs"]["SourceEvidenceSnippet"]["properties"]["snippetText"]["maxLength"] == 65536
    assert "repositorySnapshot" in request_schema["required"]
    assert "buildContext" in request_schema["required"]
    assert "analysisArtifactSet" in request_schema["required"]

    assert result_schema["properties"]["ledgerOnly"]
    assert result_schema["properties"]["productionWrites"]
    assert result_schema["properties"]["repositorySnapshotId"]

    context_request_schema = contract["contextRequestJsonSchema"]
    context_result_schema = contract["contextResultJsonSchema"]
    assert context_request_schema["properties"]["repositorySnapshotId"]["anyOf"][0]["maxLength"] == 512
    assert context_request_schema["properties"]["buildContextId"]["anyOf"][0]["maxLength"] == 512
    assert context_request_schema["properties"]["analysisArtifactSetId"]["anyOf"][0]["maxLength"] == 512
    assert context_request_schema["properties"]["graphNodeIds"]
    assert context_request_schema["properties"]["graphNodeIds"]["maxItems"] == 256
    assert context_request_schema["properties"]["graphNodeIds"]["items"]["maxLength"] == 512
    assert context_request_schema["properties"]["evidenceSnippetIds"]["maxItems"] == 256
    assert context_request_schema["properties"]["evidenceSnippetIds"]["items"]["maxLength"] == 512
    assert context_request_schema["properties"]["richIrArtifactIds"]["maxItems"] == 128
    assert context_request_schema["properties"]["richIrArtifactIds"]["items"]["maxLength"] == 512
    assert context_request_schema["properties"]["analysisArtifactSetId"]
    assert context_result_schema["properties"]["contextResolution"]
    assert context_result_schema["properties"]["resolved"]
    assert context_result_schema["properties"]["sourceArtifacts"]


def test_source_code_kg_contract_endpoint_is_read_only_and_request_id_safe():
    response = client.get("/v1/contracts/source-code-kg", headers={"X-Request-Id": "req-source-kg-contract"})

    assert response.status_code == 200
    body = response.json()
    assert body["sourceCodeKgContractVersion"] == "source-code-kg-ingest-v1"
    assert body["endpoint"]["path"] == "/v1/source-code-kg/ingest"
    assert body["consumerBoundary"]["routineAnswersShouldExposeSnippetsNotFullSource"] is True
    assert any("ledger-only" in guardrail for guardrail in body["guardrails"])
