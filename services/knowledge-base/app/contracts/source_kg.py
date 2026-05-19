"""Machine-readable Source Code KG producer contract.

This contract turns the S5 interview decision into a code-owned surface: S5 owns
what source/build graph facts it expects from S3/S4 producers.  The endpoint is
read-only and does not ingest or project data by itself.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.ledger.repository import (
    MAX_SOURCE_CONTEXT_GRAPH_EDGES,
    MAX_SOURCE_CONTEXT_GRAPH_NODES,
    MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS,
    MAX_SOURCE_CONTEXT_RICH_IR_ARTIFACTS,
    MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES,
    MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES,
    MAX_SOURCE_RICH_IR_PAYLOAD_INLINE_BYTES,
)
from app.source_kg.models import (
    MAX_INGEST_EVIDENCE_SNIPPETS,
    MAX_INGEST_GRAPH_EDGES,
    MAX_INGEST_GRAPH_NODES,
    MAX_INGEST_ID_LENGTH,
    MAX_INGEST_NESTED_OBJECT_BYTES,
    MAX_INGEST_RICH_IR_ARTIFACTS,
    MAX_INGEST_RICH_IR_PAYLOAD_BYTES,
    MAX_INGEST_SNIPPET_TEXT_CHARS,
    MAX_INGEST_SOURCE_ARTIFACTS,
    MAX_INGEST_TOTAL_NESTED_OBJECT_BYTES,
    MAX_CONTEXT_EVIDENCE_SNIPPET_IDS,
    MAX_CONTEXT_GRAPH_NODE_IDS,
    MAX_CONTEXT_RICH_IR_ARTIFACT_IDS,
    MAX_CONTEXT_SELECTOR_ID_LENGTH,
    SourceCodeKgContextRequest,
    SourceCodeKgContextResult,
    SourceCodeKgIngestRequest,
    SourceCodeKgIngestResult,
)
from app.timeout import MIN_SYNC_THREAD_DEADLINE_SECONDS

SOURCE_CODE_KG_CONTRACT_VERSION = "source-code-kg-ingest-v1"

SOURCE_KG_REQUIRED_PRODUCER_FIELDS = {
    "repositorySnapshot": [
        "repositoryUrl or repositoryId",
        "commitHash",
        "treeHash when available",
        "submoduleHashes when available",
        "provenance",
    ],
    "buildContext": [
        "projectId",
        "targetId",
        "buildTarget when available",
        "toolchain",
        "compileCommandsArtifactId when available",
        "dependencyGraph",
        "buildMetadata",
        "provenance",
    ],
    "analysisArtifactSet": [
        "analyzerName",
        "analyzerVersion when available",
        "analysisConfig",
        "artifactHashes",
        "provenance",
    ],
    "graphNodes": [
        "nodeKind",
        "stableId",
        "filePath/line spans when source-local",
        "symbol metadata when available",
        "evidenceSnippetId when source evidence exists",
    ],
    "graphEdges": [
        "edgeKind",
        "sourceGraphNodeId or sourceStableId",
        "targetGraphNodeId or targetStableId",
        "evidence",
        "metadata",
    ],
    "evidenceSnippets": [
        "filePath",
        "lineStart/lineEnd when available",
        "snippetText",
        "checksumSha256 or deterministic S5 checksum",
        "provenance",
    ],
    "richIrArtifacts": [
        "artifactKind such as ast_fragment/cfg/pdg/taint_trace/symbol_table/macro_expansion/compile_commands",
        "checksumSha256",
        "uri or payload",
        "provenance",
    ],
    "sourceArtifacts": [
        "artifactUri",
        "checksumSha256",
        "storageMode",
        "mediaType",
        "provenance",
    ],
}

SOURCE_KG_CONSUMER_BOUNDARY = {
    "owner": "s5",
    "producers": ["s3", "s4"],
    "storageTruth": "s5_sql_ledger",
    "projectionTruth": False,
    "productionWritesDefault": {"neo4j": False, "qdrant": False},
    "notFinalSecurityVerdict": True,
    "sourceRetrievalIsNotAffectednessProof": True,
    "routineAnswersShouldExposeSnippetsNotFullSource": True,
    "contextResolutionRequiredForServing": True,
}

SOURCE_KG_GUARDRAILS = [
    "S5 owns durable Source Code KG storage and the producer contract; S3/S4 produce facts.",
    "Repository commitHash is mandatory because source graph facts are versioned by repository snapshot.",
    "Full source artifacts may be retained/referenced for replay and dataset construction, but routine answers should expose only snippets, hashes, line ranges, and artifact IDs.",
    "Source Code KG ingest is ledger-only by default; production Neo4j/Qdrant writes require an explicit projection workflow.",
    "Serving projections redact oversized nested objects while preserving byte-length and max-inline metadata; ledger values remain raw for replay.",
    "Fuzzy source/code retrieval must not invent source-analysis facts or become affectedness proof.",
    "Grounded unknown is a valid answer status when source/build context is insufficient but explicitly diagnosed.",
    "When producers omit generated graph node IDs, graph edges should reference sourceStableId/targetStableId; direct graph-node-ID references require explicit producer IDs.",
    "Serving consumers must expose partial Source KG context resolution with missing IDs and non-silent fallback diagnostics.",
]

SOURCE_KG_REFERENCE_POLICY = {
    "generatedGraphNodeIdsRequireStableIdEdgeRefs": True,
    "explicitGraphNodeIdRefsRequireProducerIds": True,
    "stableIdEdgeRefsSupported": True,
}

SOURCE_KG_PRODUCER_IDENTITY_POLICY = {
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

SOURCE_KG_LINEAGE_REBIND_POLICY = {
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

SOURCE_KG_ATOMIC_INGEST_POLICY = {
    "transactionScope": "single_sqlite_transaction",
    "partialRowsOnValidationFailure": False,
    "partialRowsOnLateWriteFailure": False,
    "compileCommandsArtifactReferenceErrorReason": "build_context_references_unknown_source_artifact",
}

SOURCE_KG_INGEST_SIZE_POLICY = {
    "maxSourceArtifacts": MAX_INGEST_SOURCE_ARTIFACTS,
    "maxEvidenceSnippets": MAX_INGEST_EVIDENCE_SNIPPETS,
    "maxGraphNodes": MAX_INGEST_GRAPH_NODES,
    "maxGraphEdges": MAX_INGEST_GRAPH_EDGES,
    "maxRichIrArtifacts": MAX_INGEST_RICH_IR_ARTIFACTS,
    "maxProducerOrReferenceIdLength": MAX_INGEST_ID_LENGTH,
    "maxSnippetTextChars": MAX_INGEST_SNIPPET_TEXT_CHARS,
    "maxNestedObjectBytes": MAX_INGEST_NESTED_OBJECT_BYTES,
    "maxTotalNestedObjectBytes": MAX_INGEST_TOTAL_NESTED_OBJECT_BYTES,
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
    "maxRichIrPayloadBytes": MAX_INGEST_RICH_IR_PAYLOAD_BYTES,
    "collectionLimitErrorReason": "ingest_collection_limit_exceeded",
    "valueTooLargeErrorReason": "ingest_value_too_large",
}

SOURCE_KG_SERVING_CONTEXT_RESOLUTION = {
    "schemaVersion": "s5-source-kg-context-resolution-v1",
    "trackedScalars": ["repositorySnapshotId", "buildContextId", "analysisArtifactSetId"],
    "trackedCollections": ["sourceArtifacts", "graphNodes", "evidenceSnippets", "richIrArtifacts"],
    "diagnosticCodes": [
        "SOURCE_KG_CONTEXT_PARTIAL",
        "SOURCE_KG_CONTEXT_INCONSISTENT",
        "SOURCE_KG_CONTEXT_TRUNCATED",
        "SOURCE_KG_CONTEXT_REDACTED",
        "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED",
    ],
    "diagnosticCodeCoverage": {
        "coverage": "all_known_source_kg_serving_context_diagnostic_codes",
        "knownDiagnosticCodeCount": 5,
    },
    "maxWholeAnalysisGraphNodes": MAX_SOURCE_CONTEXT_GRAPH_NODES,
    "maxWholeAnalysisGraphEdges": MAX_SOURCE_CONTEXT_GRAPH_EDGES,
    "maxWholeAnalysisRichIrArtifacts": MAX_SOURCE_CONTEXT_RICH_IR_ARTIFACTS,
    "partialFallback": "partial_context_resolution",
    "silentPartialContextAllowed": False,
    "partialResolutionEchoPolicy": {
        "redactCredentialBearingRequestedIds": True,
        "redactCredentialBearingMissingIds": True,
        "storedLedgerValuesRemainRaw": True,
    },
    "outOfLineageCollectionPolicy": {
        "diagnosticCode": "SOURCE_KG_CONTEXT_INCONSISTENT",
        "redactReturnedRows": True,
        "redactedIdsReportedAsMissing": True,
        "outOfLineageRowsMayBeReturned": False,
        "missingRequestedContainerRowsMayBeReturned": False,
    },
    "richIrPayloadPolicy": {
        "maxInlineBytes": MAX_SOURCE_RICH_IR_PAYLOAD_INLINE_BYTES,
        "payloadRedactedWhenOverLimit": True,
        "payloadTruncatedMetadataFields": [
            "payloadByteLength",
            "payloadMaxInlineBytes",
            "payloadTruncated",
            "payloadRedacted",
        ],
    },
    "sourceSnippetTextPolicy": {
        "maxInlineBytes": MAX_SOURCE_SNIPPET_TEXT_INLINE_BYTES,
        "truncateWhenOverLimit": True,
        "truncationMetadataFields": [
            "snippetTextByteLength",
            "snippetTextMaxInlineBytes",
            "snippetTextTruncated",
        ],
    },
    "nestedObjectPolicy": {
        "maxInlineBytes": MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES,
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
    },
    "compileCommandsArtifactPolicy": {
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
    },
    "projectionDiagnosticPolicy": {
        "redactedDiagnosticCode": "SOURCE_KG_CONTEXT_REDACTED",
        "truncatedDiagnosticCode": "SOURCE_KG_CONTEXT_TRUNCATED",
        "diagnosticsTruncatedCode": "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED",
        "maxProjectionDiagnostics": MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS,
        "redactedOrTruncatedProjectionMakesContextComplete": False,
        "redactedOrTruncatedProjectionMakesContextPartial": True,
        "diagnosticMetadataFields": ["field", "redacted", "truncated", "byteLength", "maxInlineBytes"],
        "diagnosticTruncationMetadataFields": ["field", "totalCount", "returnedCount", "maxCount"],
        "judgeMustTreatAsDegradedSourceContext": True,
    },
    "urlRedactionPolicy": {
        "redactRepositoryUrlUserinfoAndSensitiveQuery": True,
        "redactSourceArtifactUriUserinfoAndSensitiveQuery": True,
        "redactRichIrUriUserinfoAndSensitiveQuery": True,
        "storedLedgerValuesRemainRaw": True,
        "redactedFields": ["repositorySnapshot.repositoryUrl", "sourceArtifacts[].artifactUri", "richIrArtifacts[].uri"],
    },
    "explicitSelectorLimitPolicy": {
        "maxGraphNodeIds": MAX_CONTEXT_GRAPH_NODE_IDS,
        "maxEvidenceSnippetIds": MAX_CONTEXT_EVIDENCE_SNIPPET_IDS,
        "maxRichIrArtifactIds": MAX_CONTEXT_RICH_IR_ARTIFACT_IDS,
        "maxSelectorValueLength": MAX_CONTEXT_SELECTOR_ID_LENGTH,
        "errorReason": "explicit_selector_limit_exceeded",
        "valueTooLongErrorReason": "selector_value_too_long",
    },
}


def _contract() -> dict[str, Any]:
    return {
        "schemaVersion": "s5-source-code-kg-contracts-v1",
        "sourceCodeKgContractVersion": SOURCE_CODE_KG_CONTRACT_VERSION,
        "endpoint": {
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
                "minimumSafeStartBudgetMs": int(MIN_SYNC_THREAD_DEADLINE_SECONDS * 1000),
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
        },
        "contextEndpoint": {
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
        },
        "producerRequirements": SOURCE_KG_REQUIRED_PRODUCER_FIELDS,
        "consumerBoundary": SOURCE_KG_CONSUMER_BOUNDARY,
        "referencePolicy": SOURCE_KG_REFERENCE_POLICY,
        "producerIdentityPolicy": SOURCE_KG_PRODUCER_IDENTITY_POLICY,
        "lineageRebindPolicy": SOURCE_KG_LINEAGE_REBIND_POLICY,
        "atomicIngestPolicy": SOURCE_KG_ATOMIC_INGEST_POLICY,
        "ingestSizePolicy": SOURCE_KG_INGEST_SIZE_POLICY,
        "servingContextResolution": SOURCE_KG_SERVING_CONTEXT_RESOLUTION,
        "guardrails": SOURCE_KG_GUARDRAILS,
        "requestJsonSchema": SourceCodeKgIngestRequest.model_json_schema(by_alias=True),
        "resultJsonSchema": SourceCodeKgIngestResult.model_json_schema(by_alias=True),
        "contextRequestJsonSchema": SourceCodeKgContextRequest.model_json_schema(by_alias=True),
        "contextResultJsonSchema": SourceCodeKgContextResult.model_json_schema(by_alias=True),
    }


def source_code_kg_contract_snapshot() -> dict[str, Any]:
    """Return a deep-copy contract snapshot safe for API response use."""
    return deepcopy(_contract())
