"""Machine-readable Source Code KG producer contract.

This contract turns the S5 interview decision into a code-owned surface: S5 owns
what source/build graph facts it expects from S3/S4 producers.  The endpoint is
read-only and does not ingest or project data by itself.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.source_kg.models import SourceCodeKgIngestRequest, SourceCodeKgIngestResult

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
}

SOURCE_KG_GUARDRAILS = [
    "S5 owns durable Source Code KG storage and the producer contract; S3/S4 produce facts.",
    "Repository commitHash is mandatory because source graph facts are versioned by repository snapshot.",
    "Full source artifacts may be retained/referenced for replay and dataset construction, but routine answers should expose only snippets, hashes, line ranges, and artifact IDs.",
    "Source Code KG ingest is ledger-only by default; production Neo4j/Qdrant writes require an explicit projection workflow.",
    "Fuzzy source/code retrieval must not invent source-analysis facts or become affectedness proof.",
    "Grounded unknown is a valid answer status when source/build context is insufficient but explicitly diagnosed.",
]


def _contract() -> dict[str, Any]:
    return {
        "schemaVersion": "s5-source-code-kg-contracts-v1",
        "sourceCodeKgContractVersion": SOURCE_CODE_KG_CONTRACT_VERSION,
        "endpoint": {
            "method": "POST",
            "path": "/v1/source-code-kg/ingest",
            "requestSchemaVersion": "s5-source-code-kg-ingest-request-v1",
            "resultSchemaVersion": "s5-source-code-kg-ingest-result-v1",
        },
        "producerRequirements": SOURCE_KG_REQUIRED_PRODUCER_FIELDS,
        "consumerBoundary": SOURCE_KG_CONSUMER_BOUNDARY,
        "guardrails": SOURCE_KG_GUARDRAILS,
        "requestJsonSchema": SourceCodeKgIngestRequest.model_json_schema(by_alias=True),
        "resultJsonSchema": SourceCodeKgIngestResult.model_json_schema(by_alias=True),
    }


def source_code_kg_contract_snapshot() -> dict[str, Any]:
    """Return a deep-copy contract snapshot safe for API response use."""
    return deepcopy(_contract())
