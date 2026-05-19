from __future__ import annotations

import ast
import inspect
import json
import time

from fastapi.testclient import TestClient

from app.analyst.brief import BASELINE_FORBIDDEN_INFERENCES
from app.contracts import judge as judge_contract
from app.ingestion.corpus_ingestion import ingest_fixture_corpus
from app.judge import service as judge_service
from app.ledger import repository as ledger_repository
from app.ledger.repository import SQLiteLedgerRepository
from app.main import app
from app.relations import conflict_model
from app.routers import judge_api
from app.source_kg.models import SourceCodeKgIngestRequest
from app.source_kg.service import ingest_source_kg
from app.threat_retrieval import evidence as threat_retrieval_evidence
from tests import test_judge_answer_contract_v1 as judge_answer_contract_tests

client = TestClient(app, raise_server_exceptions=False)
_HEADERS = {"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-api-test"}
_OFFLINE_METRIC_TERMS = {"true_positive", "false_positive", "false_negative", "precision", "recall", "ndcg", "mrr"}


def _threat_retrieval_issue_literal_codes(source: str) -> set[str]:
    return _string_literal_codes(source, prefix="THREAT_RETRIEVAL_")


def _source_kg_issue_literal_codes(source: str) -> set[str]:
    return _string_literal_codes(source, prefix="SOURCE_KG_")


def _source_kg_context_diagnostic_literal_codes(source: str) -> set[str]:
    return _string_literal_codes(source, prefix="SOURCE_KG_CONTEXT_")


def _dict_string_values_for_key(source: str, *, key: str) -> set[str]:
    tree = ast.parse(source)
    values = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for item_key, item_value in zip(node.keys, node.values, strict=False):
            if (
                isinstance(item_key, ast.Constant)
                and item_key.value == key
                and isinstance(item_value, ast.Constant)
                and isinstance(item_value.value, str)
            ):
                values.add(item_value.value)
    return values


def _string_literal_codes(source: str, *, prefix: str) -> set[str]:
    tree = ast.parse(source)
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith(prefix)
    }


def _broad_malformed_packet_mutation_paths_from_test() -> list[str]:
    source = inspect.getsource(judge_answer_contract_tests.test_judge_validator_tolerates_broad_malformed_packet_containers)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "mutation_paths" for target in node.targets):
            continue
        paths = ast.literal_eval(node.value)
        return [".".join(str(part) for part in path) for path in paths]
    raise AssertionError("mutation_paths assignment not found")


def _repo(tmp_path):
    repo = SQLiteLedgerRepository(f"sqlite:///{tmp_path / 's5-ledger.sqlite'}")
    repo.initialize()
    ingest_fixture_corpus(repo)
    return repo


def _source_payload():
    return {
        "schemaVersion": "s5-source-code-kg-ingest-request-v1",
        "repositorySnapshot": {
            "repositoryUrl": "https://github.com/aegis-fixtures/curl-vuln.git",
            "repositoryId": "fixture-curl-vuln",
            "commitHash": "curl-commit-800",
            "treeHash": "curl-tree-800",
        },
        "buildContext": {
            "projectId": "re100",
            "targetId": "re100:http-client",
            "buildTarget": "http-client",
            "toolchain": {"compiler": "gcc", "targetArch": "armv7"},
            "dependencyGraph": {"libraries": [{"name": "curl", "version": "8.0.0"}]},
        },
        "analysisArtifactSet": {
            "analyzerName": "s4-static-fixture",
            "analyzerVersion": "1.0",
            "analysisConfig": {"enabled": ["callgraph"]},
            "artifactHashes": {"callgraph": "sha256:curl-callgraph"},
        },
        "evidenceSnippets": [
            {
                "evidenceSnippetId": "snippet-curl-call",
                "filePath": "src/http_client.cpp",
                "lineStart": 42,
                "lineEnd": 44,
                "language": "cpp",
                "snippetText": "curl_easy_perform(handle);",
            }
        ],
        "graphNodes": [
            {
                "nodeKind": "function",
                "stableId": "func:perform_request",
                "displayName": "perform_request",
                "filePath": "src/http_client.cpp",
                "lineStart": 40,
                "lineEnd": 50,
                "metadata": {"component": "curl", "reachable": True},
                "evidenceSnippetId": "snippet-curl-call",
            }
        ],
        "graphEdges": [],
        "richIrArtifacts": [],
    }


def _ingest_source_context(repo):
    result = ingest_source_kg(repo, SourceCodeKgIngestRequest.model_validate(_source_payload())).model_dump(by_alias=True)
    return {
        "repositorySnapshotId": result["repositorySnapshotId"],
        "buildContextId": result["buildContextId"],
        "analysisArtifactSetId": result["analysisArtifactSetId"],
        "graphNodeIds": result["ids"]["sourceGraphNodeIds"],
        "evidenceSnippetIds": result["ids"]["evidenceSnippetIds"],
    }


def _judge_payload(source_context=None):
    return {
        "schemaVersion": "s5-judge-query-v1",
        "question": "Is this component affected in the current build target?",
        "component": {"name": "curl", "version": "8.0.0", "purl": "pkg:generic/curl@8.0.0"},
        "sourceContext": source_context,
        "controls": {},
    }


def _score_policy(gate: str, *, hard_fail: bool = False) -> dict:
    return {
        "schemaVersion": "s5-score-policy-evaluation-v1",
        "phase": "serving",
        "requestedProfile": None,
        "appliedProfile": "balanced",
        "rejectedProfiles": [],
        "policyId": "test-score-policy",
        "policyVersion": "1",
        "policyHash": "sha256:" + "0" * 64,
        "policySource": "test",
        "policyPath": "tests/test_judge_api_contract_v1.py",
        "gate": gate,
        "hardFail": hard_fail,
        "failedThresholds": [],
        "thresholds": {},
        "diagnostics": [],
    }


def test_judge_contract_endpoint_freezes_runtime_boundary():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-contract"})

    assert resp.status_code == 200
    assert resp.headers["X-Request-Id"] == "req-judge-contract"
    body = resp.json()
    assert body["schemaVersion"] == "s5-judge-contract-v1"
    assert body["endpoint"] == {"method": "POST", "path": "/v1/judge/query"}
    assert body["request"]["schemaVersion"] == "s5-judge-query-v1"
    assert body["request"]["timeoutFailurePolicy"] == {
        "reason": "deadline_exceeded_before_judge_query_completed",
        "servingLedgerWriteOnTimeout": False,
        "timeoutPhase": "pre_start_only_for_durable_write",
        "postStartTimeoutResponse": "wait_for_completion_and_return_result",
        "minimumSafeStartBudgetMs": 10,
    }
    assert body["request"]["controlEchoPolicy"] == {
        "maxStringEchoChars": 512,
        "maxListItems": 128,
        "maxForceContextRootKeys": 128,
        "maxForceContextTotalItems": 512,
        "maxForceContextEchoBytes": 16384,
        "maxForceContextDepth": 8,
        "maxUnsupportedControlEchoItems": 128,
        "maxControlEchoTotalItems": 512,
        "maxControlEchoBytes": 16384,
        "oversizedStringRedaction": {"redacted": True, "type": "str", "length": "original_length"},
        "oversizedControlNameRedaction": {"redacted": True, "type": "control", "length": "original_length"},
        "oversizedObjectKeyRedaction": "<redacted-key:original_length>",
        "oversizedObjectRedaction": {
            "redacted": True,
            "type": "list|object",
            "length": "original_length",
            "reason": "control_object_too_large",
        },
        "credentialBearingUrlRedaction": True,
        "tooLongRejectionReason": "control_value_too_long",
        "listTooLongRejectionReason": "control_list_too_long",
        "objectTooLargeRejectionReason": "control_object_too_large",
        "appliesTo": [
            "appliedControls.requested",
            "appliedControls.accepted",
            "appliedControls.rejected",
            "canonicalQuery.controlSummary",
            "servingLedger.requestPacket",
            "servingLedger.answerPacket",
        ],
        "preLedgerRejectedControls": ["exclude", "prefer", "forceContext"],
    }
    assert body["request"]["questionEchoPolicy"] == {
        "credentialBearingUrlRedaction": True,
        "appliesTo": [
            "queryContext.question",
            "canonicalQuery.normalized.questionTerms",
            "servingLedger.requestPacket.question",
            "servingLedger.answerPacket",
        ],
    }
    controls_schema = body["request"]["jsonSchema"]["$defs"]["JudgeControls"]["properties"]
    source_context_schema = body["request"]["jsonSchema"]["$defs"]["JudgeSourceContext"]["properties"]
    assert "topK" in controls_schema
    assert controls_schema["exclude"]["maxItems"] == 128
    assert controls_schema["prefer"]["maxItems"] == 128
    assert source_context_schema["repositorySnapshotId"]["anyOf"][0]["maxLength"] == 512
    assert source_context_schema["buildContextId"]["anyOf"][0]["maxLength"] == 512
    assert source_context_schema["analysisArtifactSetId"]["anyOf"][0]["maxLength"] == 512
    assert source_context_schema["graphNodeIds"]["maxItems"] == 256
    assert source_context_schema["graphNodeIds"]["items"]["maxLength"] == 512
    assert source_context_schema["evidenceSnippetIds"]["maxItems"] == 256
    assert source_context_schema["evidenceSnippetIds"]["items"]["maxLength"] == 512
    assert source_context_schema["richIrArtifactIds"]["maxItems"] == 128
    assert source_context_schema["richIrArtifactIds"]["items"]["maxLength"] == 512
    assert body["answer"]["schemaVersion"] == "s5-judge-answer-v1"
    assert body["answer"]["notFinalSecurityVerdict"] is True
    assert body["answer"]["verdictAuthority"] == "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict"
    assert body["answer"]["threatRetrievalPolicies"] == {
        "topKPolicy": "s5-top-k-policy-v1",
        "candidatePoolPolicy": "s5-candidate-pool-policy-v1",
        "rerankerPolicy": "s5-deterministic-method-aware-reranker",
        "candidatePoolPreview": {
            "location": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview",
            "bounded": True,
            "minimumLimit": 10,
            "returnedFlagRequired": True,
            "unreturnedReason": "outside_final_top_k",
        },
        "candidatePoolTruncation": {
            "location": "evidence.threatRetrieval.retrievalTrace",
            "bounded": True,
            "candidateSetTotalCountField": "candidateSetTotalCount",
            "candidatePoolSizeField": "candidatePoolSize",
            "truncatedField": "candidatePoolTruncated",
            "truncationReason": "candidate_pool_k_cap",
        },
        "keywordMatchDiscovery": {
            "method": "keyword_match",
            "matchPolicy": "fielded_exact_identifier_or_package_identity",
            "queryTerms": "normalized component identifiers and security-identifier canonical questionTerms",
            "questionTermAllowlist": ["CVE", "GHSA", "OSV", "CWE", "CAPEC"],
            "payloadJsonSubstringMatchAllowed": False,
            "matchedFieldFamilies": ["advisory_identifiers", "security_taxonomy_ids", "package_identity_fields"],
            "authority": "contextual_support_not_affectedness_proof",
            "negativeEvidenceAllowed": False,
        },
        "missingInputContextDiscovery": {
            "missingVersionStillBuildsThreatRetrieval": True,
            "affectednessAuthority": False,
            "allowedDiscoveryTerms": "normalized component identifiers and security-identifier canonical questionTerms",
            "requiredVerdict": "unknown",
        },
        "runtimeDiagnostics": {
            "location": "evidence.threatRetrieval.diagnostics",
            "consumerPolicy": "diagnostic_not_negative_evidence",
            "negativeEvidenceAllowed": False,
            "diagnosticCodeCoverage": {
                "coverage": "all_known_threat_retrieval_runtime_diagnostic_codes",
                "knownDiagnosticCodeCount": 1,
            },
            "diagnosticCodes": {
                "THREAT_RETRIEVAL_NO_CONTEXT": {
                    "meaning": "no candidate advisory/context rows were discovered for the current normalized component and security question terms",
                    "verdictAuthority": "unknown_only",
                    "negativeEvidenceAllowed": False,
                    "requiredConsumerBehavior": "treat_as_inconclusive_context_gap_not_component_safe",
                },
            },
        },
        "equivalentAdvisoryResponseBudget": {
            "location": "evidence.threatRetrieval.retrievalTrace",
            "bounded": True,
            "responseLimit": 64,
            "returnedCountField": "equivalentAdvisoryReturnedCount",
            "truncatedField": "equivalentAdvisoryResponseTruncated",
        },
        "riskSignalResponseBudget": {
            "location": "evidence.threatRetrieval.retrievalTrace",
            "bounded": True,
            "responseLimit": 32,
            "returnedCountField": "riskSignalReturnedCount",
            "truncatedField": "riskSignalResponseTruncated",
        },
            "authorityBoundaryValidation": {
            "contextAuthority": "contextual_support_not_affectedness_proof",
            "riskSignalAuthority": "prioritization_signal_not_affectedness_proof",
            "negativeEvidenceAllowed": False,
            "credentialBearingAuthorityRedaction": True,
            "credentialBearingDiagnosticMetadataRedaction": True,
            "validatedContextAuthorityFields": [
                "evidence.threatRetrieval.authority",
                "evidence.threatRetrieval.retrievalTrace.authority",
                "evidence.threatRetrieval.candidateEvidence[].authority",
                "evidence.threatRetrieval.suppressedCandidateEvidence[].authority",
                "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].authority",
                "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisories[].authority",
                "evidence.threatRetrieval.weaknessSemantics[].authority",
                "evidence.threatRetrieval.attackSemantics[].authority",
            ],
            "validatedRiskSignalAuthorityFields": [
                "evidence.threatRetrieval.riskSignals[].authority",
            ],
            "issueCodes": [
                "THREAT_RETRIEVAL_AUTHORITY_INVALID",
                "THREAT_RETRIEVAL_EQUIVALENT_AUTHORITY_INVALID",
                "THREAT_RETRIEVAL_NEGATIVE_EVIDENCE_ALLOWED",
                "THREAT_RETRIEVAL_RISK_SIGNAL_AUTHORITY_INVALID",
            ],
        },
        "validatorDiagnosticMetadataRedaction": {
            "credentialBearingIdRedaction": True,
            "redactedFields": [
                "externalId",
                "expectedExternalId",
                "actualExternalId",
                "previousExternalId",
                "currentExternalId",
                "riskSignalId",
                "advisoryId",
            ],
        },
        "validatorIssueFieldPathPolicy": {
            "fieldRequired": True,
            "explicitRelativeFieldNormalization": True,
            "issueCodeCoverage": {
                "coverage": "all_known_threat_retrieval_validator_issue_codes",
                "knownIssueCodeCount": 43,
                "staticFieldIssueCodeCount": 37,
                "dynamicFieldIssueCodeCount": 6,
            },
            "representativeFieldByIssueCode": {
                "THREAT_RETRIEVAL_RETURNED_COUNT_MISMATCH": "evidence.threatRetrieval.retrievalTrace.returnedCount",
                "THREAT_RETRIEVAL_RANK_SEQUENCE_INVALID": "evidence.threatRetrieval.candidateEvidence[].rank",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].returned",
            },
            "issueFieldsByCode": {
                "THREAT_RETRIEVAL_CANDIDATE_POOL_ACCOUNTING_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolSize",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_COUNT_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreviewCount",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_LIMIT_OVERFLOW": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreviewLimit",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_METHOD_WEIGHT_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].scoreBreakdown.methodWeight",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_MISSING": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_ORDER_INVALID": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].rerankScore",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RANK_SEQUENCE_INVALID": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].candidatePoolRank",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RERANK_SCORE_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].rerankScore",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_ID_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].externalId",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].returned",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_SCORE_BREAKDOWN_INVALID": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].scoreBreakdown",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_SCORE_BREAKDOWN_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].scoreBreakdown",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_TRUNCATION_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreviewTruncated",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_UNRETURNED_REASON_MISSING": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[].unreturnedReason",
                "THREAT_RETRIEVAL_CANDIDATE_POOL_TRUNCATION_MISMATCH": "evidence.threatRetrieval.retrievalTrace.candidatePoolTruncated",
                "THREAT_RETRIEVAL_EMBEDDING_SCOPE_MISMATCH": "evidence.threatRetrieval.retrievalTrace.embeddingScope",
                "THREAT_RETRIEVAL_EQUIVALENT_COUNT_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisoryCount",
                "THREAT_RETRIEVAL_EQUIVALENT_LIMIT_OVERFLOW": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisories",
                "THREAT_RETRIEVAL_EQUIVALENT_RESPONSE_BUDGET_MISMATCH": "evidence.threatRetrieval.retrievalTrace.equivalentAdvisoryReturnedCount",
                "THREAT_RETRIEVAL_EQUIVALENT_SOURCE_KINDS_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].equivalentSourceKinds",
                "THREAT_RETRIEVAL_EQUIVALENT_TRUNCATION_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisoriesTruncated",
                "THREAT_RETRIEVAL_EXCLUDED_CANDIDATE_RETURNED": "evidence.threatRetrieval.candidateEvidence[]",
                "THREAT_RETRIEVAL_EXCLUDED_EQUIVALENT_RETURNED": "evidence.threatRetrieval.candidateEvidence[].equivalentAdvisories[]",
                "THREAT_RETRIEVAL_EXCLUDED_PREVIEW_RETURNED": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview[]",
                "THREAT_RETRIEVAL_EXCLUDED_RISK_SIGNAL_RETURNED": "evidence.threatRetrieval.riskSignals[]",
                "THREAT_RETRIEVAL_MATCHED_TERMS_MISMATCH": "evidence.threatRetrieval.retrievalTrace.matchedTerms",
                "THREAT_RETRIEVAL_METHODS_SUCCEEDED_MISMATCH": "evidence.threatRetrieval.retrievalTrace.methodsSucceeded",
                "THREAT_RETRIEVAL_METHOD_WEIGHT_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].scoreBreakdown.methodWeight",
                "THREAT_RETRIEVAL_RANK_SEQUENCE_INVALID": "evidence.threatRetrieval.candidateEvidence[].rank",
                "THREAT_RETRIEVAL_RERANK_ORDER_INVALID": "evidence.threatRetrieval.candidateEvidence[].rerankScore",
                "THREAT_RETRIEVAL_RERANK_SCORE_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].rerankScore",
                "THREAT_RETRIEVAL_RETURNED_COUNT_MISMATCH": "evidence.threatRetrieval.retrievalTrace.returnedCount",
                "THREAT_RETRIEVAL_RISK_SIGNAL_RESPONSE_BUDGET_MISMATCH": "evidence.threatRetrieval.retrievalTrace.riskSignalReturnedCount",
                "THREAT_RETRIEVAL_SCORE_BREAKDOWN_INVALID": "evidence.threatRetrieval.candidateEvidence[].scoreBreakdown",
                "THREAT_RETRIEVAL_SCORE_BREAKDOWN_MISMATCH": "evidence.threatRetrieval.candidateEvidence[].scoreBreakdown",
                "THREAT_RETRIEVAL_SUPPRESSED_RESPONSE_BUDGET_MISMATCH": "evidence.threatRetrieval.retrievalTrace.suppressedCandidateReturnedCount",
                "THREAT_RETRIEVAL_TOPK_OVERFLOW": "evidence.threatRetrieval.candidateEvidence",
            },
            "dynamicFieldIssueCodes": {
                "THREAT_RETRIEVAL_TRACE_FIELD_MISSING": {
                    "fieldSource": "answer.threatRetrievalPolicies.runtimeTraceFields",
                    "fieldPrefix": "evidence.threatRetrieval.retrievalTrace.",
                },
                "THREAT_RETRIEVAL_SEMANTIC_RESPONSE_BUDGET_MISMATCH": {
                    "fields": [
                        "evidence.threatRetrieval.weaknessSemantics",
                        "evidence.threatRetrieval.attackSemantics",
                    ],
                },
                "THREAT_RETRIEVAL_AUTHORITY_INVALID": {
                    "fieldSource": "answer.threatRetrievalPolicies.authorityBoundaryValidation.validatedContextAuthorityFields",
                },
                "THREAT_RETRIEVAL_NEGATIVE_EVIDENCE_ALLOWED": {
                    "fields": [
                        "evidence.threatRetrieval.negativeEvidenceAllowed",
                        "evidence.threatRetrieval.retrievalTrace.negativeEvidenceAllowed",
                    ],
                },
                "THREAT_RETRIEVAL_EQUIVALENT_AUTHORITY_INVALID": {
                    "fieldSource": "answer.threatRetrievalPolicies.authorityBoundaryValidation.validatedContextAuthorityFields",
                },
                "THREAT_RETRIEVAL_RISK_SIGNAL_AUTHORITY_INVALID": {
                    "fieldSource": "answer.threatRetrievalPolicies.authorityBoundaryValidation.validatedRiskSignalAuthorityFields",
                },
            },
        },
        "suppressedCandidateResponseBudget": {
            "location": "evidence.threatRetrieval.retrievalTrace",
            "bounded": True,
            "responseLimit": 16,
            "returnedCountField": "suppressedCandidateReturnedCount",
            "truncatedField": "suppressedCandidateResponseTruncated",
        },
            "semanticExpansionResponseBudget": {
                "location": "evidence.threatRetrieval.retrievalTrace",
                "bounded": True,
                "weaknessResponseLimit": 32,
                "attackResponseLimit": 32,
            },
            "runtimeTraceFields": [
                "methodsSucceeded",
                "filtersApplied",
                "matchedTerms",
                "relationMethods",
                "embeddingScope",
                "profileBoostsApplied",
                "projectionState",
                "providerState",
            ],
            "topKControlCanonicalization": {
                "acceptedControlUsesFinalTopK": True,
                "requestedTopKPreservedInTrace": True,
                "overCapRequestsShareCanonicalQuery": True,
            },
            "verdictLinkedEvidenceTier": "affectedness_evidence",
            "contextualPackageTier": "package_identity_context",
            "verdictLinkedEvidenceOutranksRiskOnlyContext": True,
        }
    assert body["answer"]["sourceCodeKgContextResolution"] == {
        "schemaVersion": "s5-source-kg-context-resolution-v1",
        "partialFallback": "partial_context_resolution",
        "partialDiagnostic": "SOURCE_KG_CONTEXT_PARTIAL",
        "silentPartialContextAllowed": False,
        "degradedStatus": "degraded_quality",
        "requiredInputOnDegradation": "complete_or_consistent_source_code_kg_context",
        "selectorPolicy": {
            "maxGraphNodeIds": 256,
            "maxEvidenceSnippetIds": 256,
            "maxRichIrArtifactIds": 128,
            "maxSelectorValueLength": 512,
            "limitErrorReason": "explicit_selector_limit_exceeded",
            "valueTooLongErrorReason": "selector_value_too_long",
        },
        "queryContextSourceContextEchoPolicy": {
            "redactCredentialBearingSelectorValues": True,
            "appliesTo": [
                "queryContext.sourceContext",
                "canonicalQuery.normalized.sourceContext",
                "servingLedger.requestPacket.sourceContext",
            ],
            "storedLedgerAnswerUsesRedactedEcho": True,
            "storedLedgerRequestPacketUsesRedactedEcho": True,
            "rawSelectorValuesRemainAvailableOnlyForResolution": True,
        },
        "issueAndDiagnosticCatalog": {
            "coverage": "all_known_judge_source_kg_issue_and_diagnostic_codes",
            "knownCodeCount": 12,
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "source_kg_context_issues_are_inconclusive_context_diagnostics_not_negative_security_evidence",
            "codesByFamily": {
                "contextQualityDiagnostics": [
                    "SOURCE_KG_CONTEXT_DEGRADED",
                ],
                "nonSilentFallbackValidation": [
                    "SOURCE_KG_CONTEXT_DEGRADED_STATUS_MISSING",
                    "SOURCE_KG_CONTEXT_FOLLOWUP_MISSING",
                    "SOURCE_KG_CONTEXT_IGNORED",
                    "SOURCE_KG_CONTEXT_REQUIRED_INPUT_MISSING",
                    "SOURCE_KG_PARTIAL_CONTEXT_SILENT",
                ],
                "projectionRedactionValidation": [
                    "SOURCE_KG_NESTED_OBJECT_REDACTION_INVALID",
                    "SOURCE_KG_RICH_IR_PAYLOAD_REDACTION_INVALID",
                    "SOURCE_KG_SNIPPET_TEXT_TRUNCATION_INVALID",
                    "SOURCE_KG_URL_REDACTION_INVALID",
                ],
                "contextResolutionIntegrityValidation": [
                    "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID",
                    "SOURCE_KG_CONTEXT_RESOLUTION_INVALID",
                ],
            },
        },
        "servingContextDiagnosticCatalog": {
            "location": "evidence.sourceCodeKg.contextResolution.diagnostics",
            "coverage": "all_known_source_kg_serving_context_diagnostic_codes",
            "knownDiagnosticCodeCount": 5,
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "source_kg_context_diagnostics_are_inconclusive_context_diagnostics_not_negative_security_evidence",
            "diagnosticCodes": [
                "SOURCE_KG_CONTEXT_PARTIAL",
                "SOURCE_KG_CONTEXT_INCONSISTENT",
                "SOURCE_KG_CONTEXT_TRUNCATED",
                "SOURCE_KG_CONTEXT_REDACTED",
                "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED",
            ],
        },
        "validatorDiagnosticPayloadRedaction": {
            "enabled": True,
            "credentialBearingUrlLikeValues": True,
            "recursiveForStructuredValues": True,
            "maxStringEchoChars": 512,
            "maxStructuredEchoItems": 512,
            "maxStructuredEchoBytes": 16384,
            "maxStructuredEchoDepth": 8,
            "appliesToIssueCodes": [
                "SOURCE_KG_RICH_IR_PAYLOAD_REDACTION_INVALID",
                "SOURCE_KG_SNIPPET_TEXT_TRUNCATION_INVALID",
                "SOURCE_KG_URL_REDACTION_INVALID",
                "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID",
                "SOURCE_KG_CONTEXT_RESOLUTION_INVALID",
                "SOURCE_KG_NESTED_OBJECT_REDACTION_INVALID",
            ],
        },
            "nestedObjectRedactionValidation": {
                "enabled": True,
                "issueCode": "SOURCE_KG_NESTED_OBJECT_REDACTION_INVALID",
                "maxInlineBytes": 2048,
                "validatedFields": [
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
            "requiredMetadataSuffixes": ["ByteLength", "MaxInlineBytes", "Truncated", "Redacted"],
        },
            "urlRedactionValidation": {
                "enabled": True,
                "issueCode": "SOURCE_KG_URL_REDACTION_INVALID",
                "validatedFields": [
                    "repositorySnapshot.repositoryUrl",
                    "sourceArtifacts[].artifactUri",
                    "richIrArtifacts[].uri",
                ],
                "validatedNestedObjectFields": [
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
                "checksNestedObjectStringValuesAndKeys": True,
                "safeIssuePayloadOnly": True,
                "storedLedgerValuesRemainRaw": True,
            },
            "projectionDiagnosticPolicy": {
                "redactedDiagnosticCode": "SOURCE_KG_CONTEXT_REDACTED",
            "truncatedDiagnosticCode": "SOURCE_KG_CONTEXT_TRUNCATED",
            "diagnosticsTruncatedCode": "SOURCE_KG_CONTEXT_DIAGNOSTICS_TRUNCATED",
            "maxProjectionDiagnostics": 64,
            "statusWhenAffectednessOtherwiseComplete": "degraded_quality",
            "qualityGateWhenOtherwiseAccepted": "accepted_with_caveats",
            "fallbackTraceStage": "source_code_kg_context",
            "fallbackTraceSilent": False,
            "requiredInputOnDegradation": "complete_or_consistent_source_code_kg_context",
            },
            "compileCommandsArtifactProjectionPolicy": {
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
            "compileCommandsArtifactValidation": {
                "enabled": True,
                "issueCode": "SOURCE_KG_COMPILE_COMMANDS_ARTIFACT_CONTEXT_INVALID",
                "invalidIdReason": "compile_commands_artifact_id_invalid",
                "validatedFields": [
                    "buildContext.compileCommandsArtifactId",
                    "sourceArtifacts[].sourceRepositoryArtifactId",
                    "contextResolution.sourceArtifacts.requestedIds",
                    "contextResolution.sourceArtifacts.resolvedIds",
                    "contextResolution.sourceArtifacts.missingIds",
                ],
            },
            "contextResolutionIntegrityValidation": {
                "enabled": True,
                "issueCode": "SOURCE_KG_CONTEXT_RESOLUTION_INVALID",
                "reasonCodes": [
                    "resolution_entry_missing",
                    "requested_id_invalid",
                    "requested_ids_invalid",
                    "resolved_id_invalid",
                    "resolved_ids_invalid",
                    "missing_ids_invalid",
                    "resolved_id_does_not_match_served_id",
                    "resolved_ids_do_not_match_served_ids",
                    "served_id_marked_missing",
                ],
                "scalarFields": {
                    "repositorySnapshot": "repositorySnapshotId",
                    "buildContext": "buildContextId",
                    "analysisArtifactSet": "analysisArtifactSetId",
                },
                "collectionFields": {
                    "sourceArtifacts": "sourceRepositoryArtifactId",
                    "graphNodes": "sourceGraphNodeId",
                    "evidenceSnippets": "evidenceSnippetId",
                    "richIrArtifacts": "richIrArtifactId",
                },
                "credentialBearingIdRedaction": True,
                "safeIssuePayloadOnly": True,
            },
        }
    assert body["answer"]["decisionCachePolicy"] == {
        "schemaVersion": "s5-decision-cache-policy-v1",
        "publicKey": "decisionFragmentKey",
        "storageScope": "ledger",
        "scopeTraceField": "cacheTrace.cacheScopeHash",
        "revisionTraceField": "cacheTrace.cacheRevisionHash",
        "revisionHashMode": "compact_table_revision_summary",
        "revisionTables": [
            "package_identity",
            "product_identity",
            "source_component_identity",
            "identity_alias",
            "vulnerability_advisory",
            "risk_signal",
            "affectedness_record",
            "relation_record",
            "conflict_record",
        ],
        "crossLedgerReuseAllowed": False,
        "staleLedgerRevisionReuseAllowed": False,
    }
    assert body["answer"]["relationConflictVisibility"] == {
        "schemaVersion": "s5-judge-conflict-summary-v1",
        "location": "uncertainty.conflicts",
        "qualityDiagnosticRequired": True,
        "consumerPolicy": "conflicting_evidence_not_negative_evidence",
        "negativeEvidenceAllowed": False,
        "conflictingValuesBounded": True,
        "maxConflictingValues": 8,
        "hardConflictGate": "rejected",
        "softConflictGate": "accepted_with_caveats",
        "issueCodeCatalog": {
            "coverage": "all_known_relation_conflict_issue_codes",
            "knownIssueCodeCount": 4,
            "negativeEvidenceAllowed": False,
            "codesByKind": {
                "affectedness_range_conflict": "AFFECTEDNESS_RANGE_CONFLICT",
                "affectedness_status_conflict": "AFFECTEDNESS_STATUS_CONFLICT",
                "identity_alias_exact_conflict": "IDENTITY_ALIAS_EXACT_CONFLICT",
                "relation_predicate_conflict": "RELATION_PREDICATE_CONFLICT",
            },
            "hardConflictKinds": [
                "affectedness_status_conflict",
                "identity_alias_exact_conflict",
                "relation_predicate_conflict",
            ],
        },
    }
    assert body["forbiddenInferencePolicy"] == {
        "coverage": "all_baseline_s5_forbidden_inferences",
        "source": "app.analyst.brief.BASELINE_FORBIDDEN_INFERENCES",
        "forbiddenInferenceCount": 5,
        "s3FinalAuthorityBoundary": True,
        "consumerPolicy": "forbidden_inferences_must_not_be_promoted_to_s3_final_claims",
    }
    assert body["forbiddenInferences"] == BASELINE_FORBIDDEN_INFERENCES
    assert body["answer"]["runtimeVocabularyPolicy"] == {
        "coverage": "s5_judge_runtime_vocabulary",
        "runtimeVocabularyCount": len(body["answer"]["runtimeVocabulary"]),
        "offlineQualityVocabularyForbidden": True,
        "offlineQualityMetricTerms": sorted(_OFFLINE_METRIC_TERMS),
        "consumerPolicy": "runtime_vocabulary_terms_are_not_offline_quality_labels_or_s3_final_claims",
    }
    assert not (_OFFLINE_METRIC_TERMS & {term.lower() for term in body["answer"]["runtimeVocabulary"]})
    assert body["answer"]["qualityGatePolicy"] == {
        "location": "qualityGate",
        "allowedGates": ["accepted", "accepted_with_caveats", "rejected"],
        "mergePrecedence": ["rejected", "accepted_with_caveats", "accepted"],
        "scorePolicyLocation": "qualityGate.scorePolicy",
        "diagnosticsLocation": "qualityGate.diagnostics",
        "hardFailPolicy": "true_when_score_policy_hard_fails_or_base_gate_rejected",
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "quality_gate_is_s5_runtime_quality_not_s3_final_security_verdict",
    }
    assert body["answer"]["answerStatusPolicy"] == {
        "location": "status",
        "allowedStatuses": ["complete", "degraded_quality", "requires_requery", "insufficient_input"],
        "reservedRuntimeVocabulary": ["stale_cache", "policy_blocked"],
        "degradedStatus": "degraded_quality",
        "missingInputStatus": "requires_requery",
        "emptyRequiredInputStatus": "insufficient_input",
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "non_complete_statuses_are_requery_or_quality_signals_not_negative_evidence",
    }
    assert body["answer"]["verdictPolicy"] == {
        "location": "verdict",
        "allowedVerdicts": ["affected", "not_affected", "unknown"],
        "reservedRuntimeVocabulary": ["conflicting"],
        "conflictRepresentation": "uncertainty.conflicts_and_qualityGate_rejected_not_verdict_conflicting",
        "notAffectedPolicy": "scope_bound_evidence_verdict_not_clean_pass",
        "unknownPolicy": "requires_more_context_not_no_hit_or_safe",
        "s3FinalAuthorityBoundary": True,
        "consumerPolicy": "judge_verdict_is_s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict",
    }
    assert body["answer"]["uncertaintyPolicy"] == {
        "location": "uncertainty",
        "requiredFields": ["reason", "evidenceGaps", "requiredInputs", "conflicts"],
        "requiredInputVocabulary": [
            "component.version",
            "component.identity",
            "sourceContext",
            "additional affectedness evidence or re-query controls",
            "complete_or_consistent_source_code_kg_context",
        ],
        "conflictLocation": "uncertainty.conflicts",
        "fieldShapePolicy": {
            "reason": "string_or_null_non_empty_when_unknown_or_non_complete",
            "evidenceGaps": "list_of_strings",
            "requiredInputs": "list_of_known_required_input_vocabulary",
            "conflicts": "list_of_objects",
        },
        "followUpAffordancesLocation": "followUpAffordances",
        "followUpRequestKinds": [
            "library_version_lookup",
            "source_diff_or_vendored_patch_check",
            "source_context_enrichment",
        ],
        "ownerLanes": ["S3/S4", "S4"],
        "nonEmptyOnUnknownOrDegraded": True,
        "validatorIssueCatalog": {
            "coverage": "all_known_uncertainty_followup_validator_issue_codes",
            "issueCodes": [
                "FOLLOW_UP_AFFORDANCE_INVALID",
                "FOLLOW_UP_OWNER_LANE_UNKNOWN",
                "FOLLOW_UP_REASON_MISSING",
                "FOLLOW_UP_REQUEST_KIND_UNKNOWN",
                "UNCERTAINTY_FIELD_INVALID",
                "UNCERTAINTY_FIELD_MISSING",
                "UNCERTAINTY_REASON_MISSING",
                "UNCERTAINTY_REQUIRED_INPUT_UNKNOWN",
            ],
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "uncertainty_followup_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "uncertainty_and_followups_are_requery_guidance_not_negative_evidence",
    }
    assert body["answer"]["answerFieldPolicy"] == {
        "location": "answer",
        "topLevelContainerShapePolicy": {
            "cacheTrace": "dict_when_present",
            "queryContext": "dict_when_present",
            "evidence": "dict_when_present",
            "evidence.sourceCodeKg": "dict_when_present",
            "appliedControls": "dict_when_present",
        },
        "cacheTraceRequiredFields": ["cacheScope", "cacheScopeHash", "cacheRevisionHash"],
        "malformedPacketRobustnessPolicy": {
            "coverage": "representative_core_answer_packet_containers",
            "validatorMustNotRaise": True,
            "representativeMutationPathCount": 45,
            "malformedValueKinds": ["int", "string", "list", "object", "null"],
            "representativeMutationPaths": [
                "canonicalQuery",
                "cacheTrace",
                "qualityGate.diagnostics",
                "forbiddenInferences",
                "controlEffects",
                "appliedControls.accepted.exclude",
                "queryContext.sourceContext",
                "uncertainty.requiredInputs",
                "followUpAffordances",
                "evidence.suppressedAffectedness",
                "evidence.suppressedAffectedness.0.riskSignals",
                "evidence.sourceCodeKg.contextResolution",
                "evidence.sourceCodeKg.sourceArtifacts",
                "evidence.threatRetrieval.candidateEvidence",
                "evidence.threatRetrieval.retrievalTrace",
            ],
        },
        "validatorIssueCatalog": {
            "coverage": "all_known_answer_field_validator_issue_codes",
            "issueCodes": ["JUDGE_ANSWER_FIELD_INVALID"],
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "answer_field_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "answer_packet_field_shapes_are_contract_quality_not_security_evidence",
    }
    assert body["answer"]["controlEffectsPolicy"] == {
        "location": "controlEffects",
        "appliedControlsLocation": "appliedControls",
        "requestedControlsLocation": "appliedControls.requested",
        "acceptedControlsLocation": "appliedControls.accepted",
        "rejectedControlsLocation": "appliedControls.rejected",
        "ignoredControlsLocation": "appliedControls.ignored",
        "excludeSuppression": {
            "acceptedControl": "exclude",
            "affectednessSuppressedLocation": "evidence.suppressedAffectedness",
            "threatRetrievalSuppressedLocation": "evidence.threatRetrieval.suppressedCandidateEvidence",
            "controlEffectFields": ["control", "suppressedAdvisoryIds", "suppressedExternalIds"],
            "controlEffectsTraceRequiredFor": ["evidence.suppressedAffectedness"],
            "threatRetrievalSuppressionTraceOwner": "answer.threatRetrievalPolicies.suppressedCandidateResponseBudget",
            "traceAlignment": {
                "sourceLocation": "evidence.suppressedAffectedness",
                "advisoryIdField": "advisoryId",
                "externalIdField": "advisoryExternalId",
                "effectAdvisoryIdsField": "suppressedAdvisoryIds",
                "effectExternalIdsField": "suppressedExternalIds",
                "match": "exact_set_union",
                },
                "acceptedControlAlignment": {
                    "sourceLocation": "appliedControls.accepted.exclude",
                    "normalizedKeyFields": [
                        "evidence.suppressedAffectedness[].advisoryId",
                        "evidence.suppressedAffectedness[].advisoryExternalId",
                        "evidence.suppressedAffectedness[].riskSignals[].payload.cve",
                        "evidence.suppressedAffectedness[].riskSignals[].payload.cveID",
                    ],
                    "match": "each_suppressed_affectedness_has_at_least_one_normalized_key_in_accepted_exclude",
                },
            "resultWhenAllAffectednessSuppressed": {"verdict": "unknown", "status": "requires_requery"},
            "suppressionDoesNotProveNotAffected": True,
        },
        "validatorIssueCatalog": {
            "coverage": "all_known_control_effect_validator_issue_codes",
            "allowedControls": ["exclude"],
            "requiredFields": ["control", "suppressedAdvisoryIds", "suppressedExternalIds"],
            "issueCodes": [
                "CONTROL_EFFECT_ACCEPTED_CONTROL_MISMATCH",
                "CONTROL_EFFECT_CONTROL_UNKNOWN",
                "CONTROL_EFFECT_ENTRY_INVALID",
                "CONTROL_EFFECT_FIELD_MISSING",
                "CONTROL_EFFECT_SUPPRESSED_AFFECTEDNESS_MISMATCH",
                "CONTROL_EFFECT_SUPPRESSION_TRACE_MISSING",
                "CONTROL_EFFECT_SUPPRESSION_VERDICT_INVALID",
                "CONTROL_EFFECTS_INVALID",
            ],
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "control_effect_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "caller_controls_shape_response_scope_but_do_not_create_negative_evidence",
    }
    assert body["answer"]["fallbackTracePolicy"] == {
        "location": "fallbackTrace",
        "requiredFields": ["stage", "fallback", "silent"],
        "stageCatalog": {
            "source_code_kg_context": ["unresolved_context", "partial_context_resolution"],
            "control_validation": ["unsupported_controls_rejected"],
        },
        "silentFallbackAllowed": False,
        "diagnosticsLocationByFallback": {
            "partial_context_resolution": "fallbackTrace[].diagnostics",
            "unsupported_controls_rejected": "fallbackTrace[].rejected",
        },
        "payloadCardinalityByFallback": {
            "partial_context_resolution": {"field": "diagnostics", "minItems": 1},
            "unsupported_controls_rejected": {"field": "rejected", "minItems": 1},
        },
        "validatorIssueCatalog": {
            "coverage": "all_known_fallback_trace_validator_issue_codes",
            "issueCodes": [
                "FALLBACK_TRACE_DIAGNOSTICS_MISSING",
                "FALLBACK_TRACE_ENTRY_INVALID",
                "FALLBACK_TRACE_FALLBACK_UNKNOWN",
                "FALLBACK_TRACE_FIELD_MISSING",
                "FALLBACK_TRACE_INVALID",
                "FALLBACK_TRACE_REJECTED_CONTROLS_MISSING",
                "FALLBACK_TRACE_SILENT",
                "FALLBACK_TRACE_STAGE_UNKNOWN",
            ],
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "fallback_trace_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "fallback_trace_entries_are_non_silent_requery_or_scope_diagnostics_not_negative_evidence",
    }
    assert body["answer"]["reasoningPathPolicy"] == {
        "location": "reasoningPath",
        "requiredFields": ["step", "status"],
        "stepCatalog": [
            "resolve_source_code_kg_context",
            "load_decision_fragment_cache",
            "resolve_component_identity",
            "evaluate_package_version_affectedness",
            "apply_exclude_controls",
            "assemble_threat_kb_context",
            "check_required_component_inputs",
        ],
        "cacheStep": "load_decision_fragment_cache",
        "sourceContextStep": "resolve_source_code_kg_context",
        "affectednessSteps": ["resolve_component_identity", "evaluate_package_version_affectedness"],
        "controlEffectStep": "apply_exclude_controls",
        "threatRetrievalStep": "assemble_threat_kb_context",
        "missingInputStep": "check_required_component_inputs",
        "stepCatalogSemantics": "allowed_vocabulary_not_required_per_response_sequence",
        "perResponseSequenceRequired": False,
        "cacheHitMayOmitAffectednessSteps": True,
        "validatorIssueCatalog": {
            "coverage": "all_known_reasoning_path_validator_issue_codes",
            "issueCodes": [
                "REASONING_PATH_ENTRY_INVALID",
                "REASONING_PATH_FIELD_MISSING",
                "REASONING_PATH_MISSING",
                "REASONING_PATH_STEP_UNKNOWN",
            ],
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "reasoning_path_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "reasoning_path_is_explainability_trace_not_security_verdict",
    }


def test_judge_contract_covers_every_threat_retrieval_validator_issue_code():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-contract-coverage"})

    assert resp.status_code == 200
    policy = resp.json()["answer"]["threatRetrievalPolicies"]["validatorIssueFieldPathPolicy"]
    static_codes = set(policy["issueFieldsByCode"])
    dynamic_codes = set(policy["dynamicFieldIssueCodes"])
    emitted_codes = _threat_retrieval_issue_literal_codes(inspect.getsource(judge_service))

    assert emitted_codes == static_codes | dynamic_codes
    assert not (static_codes & dynamic_codes)
    assert policy["issueCodeCoverage"] == {
        "coverage": "all_known_threat_retrieval_validator_issue_codes",
        "knownIssueCodeCount": len(emitted_codes),
        "staticFieldIssueCodeCount": len(static_codes),
        "dynamicFieldIssueCodeCount": len(dynamic_codes),
    }


def test_judge_contract_covers_every_threat_retrieval_runtime_diagnostic_code():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-contract-runtime-diagnostics"})

    assert resp.status_code == 200
    diagnostics = resp.json()["answer"]["threatRetrievalPolicies"]["runtimeDiagnostics"]
    emitted_codes = _threat_retrieval_issue_literal_codes(inspect.getsource(threat_retrieval_evidence))
    contract_codes = set(diagnostics["diagnosticCodes"])

    assert emitted_codes == contract_codes
    assert diagnostics["diagnosticCodeCoverage"] == {
        "coverage": "all_known_threat_retrieval_runtime_diagnostic_codes",
        "knownDiagnosticCodeCount": len(emitted_codes),
    }


def test_judge_contract_covers_every_judge_source_kg_issue_and_diagnostic_code():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-source-kg-catalog"})

    assert resp.status_code == 200
    catalog = resp.json()["answer"]["sourceCodeKgContextResolution"]["issueAndDiagnosticCatalog"]
    contract_codes = {
        code
        for codes in catalog["codesByFamily"].values()
        for code in codes
    }
    emitted_codes = _source_kg_issue_literal_codes(inspect.getsource(judge_service))

    assert emitted_codes == contract_codes
    assert catalog["knownCodeCount"] == len(emitted_codes)
    assert catalog["negativeEvidenceAllowed"] is False


def test_judge_contract_source_kg_payload_redaction_policy_covers_validator_payload_issues():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-source-kg-redaction-policy"})

    assert resp.status_code == 200
    source_kg_policy = resp.json()["answer"]["sourceCodeKgContextResolution"]
    catalog = source_kg_policy["issueAndDiagnosticCatalog"]["codesByFamily"]
    payload_redaction = source_kg_policy["validatorDiagnosticPayloadRedaction"]
    payload_issue_codes = set(catalog["projectionRedactionValidation"]) | set(
        catalog["contextResolutionIntegrityValidation"]
    )

    assert payload_redaction["enabled"] is True
    assert payload_redaction["credentialBearingUrlLikeValues"] is True
    assert payload_redaction["recursiveForStructuredValues"] is True
    assert set(payload_redaction["appliesToIssueCodes"]) == payload_issue_codes


def test_judge_contract_covers_every_source_kg_serving_context_diagnostic_code():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-source-kg-serving-diagnostics"})

    assert resp.status_code == 200
    catalog = resp.json()["answer"]["sourceCodeKgContextResolution"]["servingContextDiagnosticCatalog"]
    emitted_codes = _source_kg_context_diagnostic_literal_codes(inspect.getsource(ledger_repository))
    contract_codes = set(catalog["diagnosticCodes"])

    assert emitted_codes == contract_codes
    assert catalog["knownDiagnosticCodeCount"] == len(emitted_codes)
    assert catalog["negativeEvidenceAllowed"] is False


def test_judge_contract_covers_every_relation_conflict_issue_code():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-conflict-catalog"})

    assert resp.status_code == 200
    catalog = resp.json()["answer"]["relationConflictVisibility"]["issueCodeCatalog"]
    contract_codes = set(catalog["codesByKind"].values())

    assert contract_codes == set(conflict_model.ISSUE_CODE_BY_KIND.values())
    assert set(catalog["hardConflictKinds"]) == conflict_model.HARD_CONFLICT_KINDS
    assert catalog["knownIssueCodeCount"] == len(contract_codes)
    assert catalog["negativeEvidenceAllowed"] is False


def test_judge_contract_forbidden_inferences_match_analyst_brief_baseline():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-forbidden-inferences"})

    assert resp.status_code == 200
    body = resp.json()

    assert body["forbiddenInferences"] == BASELINE_FORBIDDEN_INFERENCES
    assert body["forbiddenInferencePolicy"]["forbiddenInferenceCount"] == len(BASELINE_FORBIDDEN_INFERENCES)
    assert body["forbiddenInferencePolicy"]["s3FinalAuthorityBoundary"] is True


def test_judge_contract_runtime_vocabulary_excludes_offline_quality_terms():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-runtime-vocabulary"})

    assert resp.status_code == 200
    answer = resp.json()["answer"]

    assert not (_OFFLINE_METRIC_TERMS & {term.lower() for term in answer["runtimeVocabulary"]})
    assert answer["runtimeVocabularyPolicy"]["runtimeVocabularyCount"] == len(answer["runtimeVocabulary"])
    assert answer["runtimeVocabularyPolicy"]["offlineQualityMetricTerms"] == sorted(_OFFLINE_METRIC_TERMS)
    assert answer["offlineQualityVocabularyForbiddenInRuntime"] is True


def test_judge_contract_quality_gate_policy_matches_runtime_merge_precedence():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-quality-gate-policy"})

    assert resp.status_code == 200
    policy = resp.json()["answer"]["qualityGatePolicy"]
    observed_gates = {
        judge_service._quality_gate("accepted", [], _score_policy("accepted"))["gate"],
        judge_service._quality_gate("accepted", [], _score_policy("accepted_with_caveats"))["gate"],
        judge_service._quality_gate("accepted_with_caveats", [], _score_policy("accepted"))["gate"],
        judge_service._quality_gate("accepted", [], _score_policy("rejected", hard_fail=True))["gate"],
    }

    assert policy["allowedGates"] == ["accepted", "accepted_with_caveats", "rejected"]
    assert set(policy["allowedGates"]) == observed_gates
    assert policy["mergePrecedence"] == ["rejected", "accepted_with_caveats", "accepted"]
    assert policy["negativeEvidenceAllowed"] is False


def test_judge_contract_answer_status_policy_matches_runtime_status_paths():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-answer-status-policy"})

    assert resp.status_code == 200
    answer = resp.json()["answer"]
    policy = answer["answerStatusPolicy"]
    observed_statuses = {
        "complete",
        judge_service._degrade_status_for_source_context("complete", degraded=True),
        "requires_requery",
        "insufficient_input",
    }

    assert policy["allowedStatuses"] == ["complete", "degraded_quality", "requires_requery", "insufficient_input"]
    assert set(policy["allowedStatuses"]) == observed_statuses
    assert set(policy["reservedRuntimeVocabulary"]) <= set(answer["runtimeVocabulary"])
    assert not set(policy["reservedRuntimeVocabulary"]) & set(policy["allowedStatuses"])
    assert policy["negativeEvidenceAllowed"] is False


def test_judge_contract_verdict_policy_preserves_s3_final_authority_boundary():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-verdict-policy"})

    assert resp.status_code == 200
    body = resp.json()
    answer = body["answer"]
    policy = answer["verdictPolicy"]

    assert policy["allowedVerdicts"] == ["affected", "not_affected", "unknown"]
    assert set(policy["allowedVerdicts"]) <= set(answer["runtimeVocabulary"])
    assert set(policy["reservedRuntimeVocabulary"]) <= set(answer["runtimeVocabulary"])
    assert not set(policy["reservedRuntimeVocabulary"]) & set(policy["allowedVerdicts"])
    assert policy["s3FinalAuthorityBoundary"] is True
    assert body["consumerBoundary"]["s3FinalClaimAuthority"] is False


def test_judge_contract_uncertainty_policy_matches_runtime_followup_vocabulary():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-uncertainty-policy"})

    assert resp.status_code == 200
    policy = resp.json()["answer"]["uncertaintyPolicy"]
    observed_required_inputs = {
        *judge_service._required_inputs("unknown", source_resolved=False, source_context_degraded=False),
        *judge_service._required_inputs("unknown", source_resolved=True, source_context_degraded=False),
        *judge_service._required_inputs("affected", source_resolved=True, source_context_degraded=True),
    }
    observed_followups = {
        item["requestKind"]
        for item in [
            *judge_service._follow_up_affordances(
                "unknown",
                missing_inputs=["component.version"],
                source_resolved=True,
                source_context_degraded=True,
            ),
            *judge_service._follow_up_affordances(
                "unknown",
                missing_inputs=[],
                source_resolved=False,
                source_context_degraded=False,
            ),
        ]
    }

    assert set(policy["requiredInputVocabulary"]) == observed_required_inputs
    assert set(policy["followUpRequestKinds"]) == observed_followups
    assert policy["requiredFields"] == ["reason", "evidenceGaps", "requiredInputs", "conflicts"]
    assert set(policy["validatorIssueCatalog"]["issueCodes"]) == _string_literal_codes(
        inspect.getsource(judge_service),
        prefix=("UNCERTAINTY_", "FOLLOW_UP_"),
    )
    assert policy["negativeEvidenceAllowed"] is False


def test_judge_contract_answer_field_policy_matches_runtime_validator_issue_codes():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-answer-field-policy"})

    assert resp.status_code == 200
    policy = resp.json()["answer"]["answerFieldPolicy"]

    assert set(policy["topLevelContainerShapePolicy"]) == {
        "cacheTrace",
        "queryContext",
        "evidence",
        "evidence.sourceCodeKg",
        "appliedControls",
    }
    robustness_policy = policy["malformedPacketRobustnessPolicy"]
    observed_mutation_paths = _broad_malformed_packet_mutation_paths_from_test()
    assert robustness_policy["validatorMustNotRaise"] is True
    assert robustness_policy["representativeMutationPathCount"] == len(observed_mutation_paths)
    assert "evidence.suppressedAffectedness.0.riskSignals" in robustness_policy["representativeMutationPaths"]
    assert "appliedControls.accepted.exclude" in robustness_policy["representativeMutationPaths"]
    assert set(judge_contract.JUDGE_ANSWER_FIELD_ROBUSTNESS_REPRESENTATIVE_MUTATION_PATHS) <= set(
        observed_mutation_paths
    )
    assert set(robustness_policy["representativeMutationPaths"]) <= set(observed_mutation_paths)
    assert set(policy["validatorIssueCatalog"]["issueCodes"]) == _string_literal_codes(
        inspect.getsource(judge_service),
        prefix=("JUDGE_ANSWER_",),
    )
    assert policy["validatorIssueCatalog"]["negativeEvidenceAllowed"] is False
    assert policy["negativeEvidenceAllowed"] is False


def test_judge_contract_control_effects_policy_matches_exclude_runtime_locations(tmp_path):
    contract_resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-control-effects-policy"})
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    payload = _judge_payload(source_context)
    payload["controls"] = {"exclude": ["CVE-2026-0001"]}

    assert contract_resp.status_code == 200
    policy = contract_resp.json()["answer"]["controlEffectsPolicy"]

    judge_api.set_ledger_repository(repo)
    try:
        answer_resp = client.post(
            "/v1/judge/query",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-control-effects-runtime"},
        )

        assert answer_resp.status_code == 200, answer_resp.text
        answer = answer_resp.json()
        expected = policy["excludeSuppression"]["resultWhenAllAffectednessSuppressed"]
        assert answer["verdict"] == expected["verdict"]
        assert answer["status"] == expected["status"]
        assert answer["appliedControls"]["accepted"]["exclude"] == ["CVE-2026-0001"]
        assert answer["evidence"]["affectedness"] == []
        assert answer["evidence"]["suppressedAffectedness"]
        assert answer["controlEffects"][0]["control"] == policy["excludeSuppression"]["acceptedControl"]
        assert set(policy["excludeSuppression"]["controlEffectFields"]) <= set(answer["controlEffects"][0])
        assert "CVE-2026-0001" in answer["controlEffects"][0]["suppressedExternalIds"]
        assert policy["negativeEvidenceAllowed"] is False
        assert policy["excludeSuppression"]["suppressionDoesNotProveNotAffected"] is True
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_contract_control_effects_policy_covers_validator_issue_codes():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-control-effect-issue-catalog"})

    assert resp.status_code == 200
    catalog = resp.json()["answer"]["controlEffectsPolicy"]["validatorIssueCatalog"]
    emitted_codes = _string_literal_codes(inspect.getsource(judge_service), prefix="CONTROL_EFFECT")

    assert catalog["coverage"] == "all_known_control_effect_validator_issue_codes"
    assert set(catalog["issueCodes"]) == emitted_codes
    assert catalog["allowedControls"] == ["exclude"]
    assert catalog["requiredFields"] == ["control", "suppressedAdvisoryIds", "suppressedExternalIds"]
    assert catalog["negativeEvidenceAllowed"] is False


def test_judge_contract_control_effects_policy_scopes_trace_requirement_to_affectedness_suppression():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-control-effect-scope"})

    assert resp.status_code == 200
    policy = resp.json()["answer"]["controlEffectsPolicy"]["excludeSuppression"]

    assert policy["affectednessSuppressedLocation"] == "evidence.suppressedAffectedness"
    assert policy["threatRetrievalSuppressedLocation"] == "evidence.threatRetrieval.suppressedCandidateEvidence"
    assert policy["controlEffectsTraceRequiredFor"] == ["evidence.suppressedAffectedness"]
    assert policy["threatRetrievalSuppressionTraceOwner"] == "answer.threatRetrievalPolicies.suppressedCandidateResponseBudget"


def test_judge_contract_control_effects_policy_requires_exact_affectedness_trace_alignment():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-control-effect-alignment"})

    assert resp.status_code == 200
    alignment = resp.json()["answer"]["controlEffectsPolicy"]["excludeSuppression"]["traceAlignment"]

    assert alignment == {
        "sourceLocation": "evidence.suppressedAffectedness",
        "advisoryIdField": "advisoryId",
        "externalIdField": "advisoryExternalId",
        "effectAdvisoryIdsField": "suppressedAdvisoryIds",
        "effectExternalIdsField": "suppressedExternalIds",
        "match": "exact_set_union",
    }


def test_judge_contract_control_effects_policy_requires_accepted_control_alignment():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-control-effect-accepted-alignment"})

    assert resp.status_code == 200
    alignment = resp.json()["answer"]["controlEffectsPolicy"]["excludeSuppression"]["acceptedControlAlignment"]

    assert alignment == {
        "sourceLocation": "appliedControls.accepted.exclude",
        "normalizedKeyFields": [
            "evidence.suppressedAffectedness[].advisoryId",
            "evidence.suppressedAffectedness[].advisoryExternalId",
            "evidence.suppressedAffectedness[].riskSignals[].payload.cve",
            "evidence.suppressedAffectedness[].riskSignals[].payload.cveID",
        ],
        "match": "each_suppressed_affectedness_has_at_least_one_normalized_key_in_accepted_exclude",
    }


def test_judge_contract_fallback_trace_policy_matches_runtime_fallbacks(tmp_path):
    contract_resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-fallback-policy"})
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    source_context["graphNodeIds"] = [source_context["graphNodeIds"][0], "missing-node"]
    payload = _judge_payload(source_context)
    payload["controls"] = {"mysteryControl": "use-runtime-fallback"}

    assert contract_resp.status_code == 200
    policy = contract_resp.json()["answer"]["fallbackTracePolicy"]

    judge_api.set_ledger_repository(repo)
    try:
        answer_resp = client.post(
            "/v1/judge/query",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-fallback-runtime"},
        )

        assert answer_resp.status_code == 200, answer_resp.text
        fallbacks = answer_resp.json()["fallbackTrace"]
        observed_by_stage = {}
        observed_by_fallback = {}
        for item in fallbacks:
            observed_by_stage.setdefault(item["stage"], set()).add(item["fallback"])
            observed_by_fallback[item["fallback"]] = item
            assert set(policy["requiredFields"]) <= set(item)
            assert item["silent"] is policy["silentFallbackAllowed"]

        assert "partial_context_resolution" in observed_by_stage["source_code_kg_context"]
        assert "unsupported_controls_rejected" in observed_by_stage["control_validation"]
        assert observed_by_fallback["partial_context_resolution"]["diagnostics"]
        assert observed_by_fallback["unsupported_controls_rejected"]["rejected"]
        assert observed_by_stage["source_code_kg_context"] <= set(policy["stageCatalog"]["source_code_kg_context"])
        assert observed_by_stage["control_validation"] <= set(policy["stageCatalog"]["control_validation"])
        assert policy["diagnosticsLocationByFallback"]["partial_context_resolution"] == "fallbackTrace[].diagnostics"
        assert policy["diagnosticsLocationByFallback"]["unsupported_controls_rejected"] == "fallbackTrace[].rejected"
        assert policy["negativeEvidenceAllowed"] is False
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_contract_fallback_trace_policy_covers_validator_issue_codes():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-fallback-issue-catalog"})

    assert resp.status_code == 200
    catalog = resp.json()["answer"]["fallbackTracePolicy"]["validatorIssueCatalog"]
    emitted_codes = _string_literal_codes(inspect.getsource(judge_service), prefix="FALLBACK_TRACE_")

    assert catalog["coverage"] == "all_known_fallback_trace_validator_issue_codes"
    assert set(catalog["issueCodes"]) == emitted_codes
    assert catalog["negativeEvidenceAllowed"] is False


def test_judge_contract_reasoning_path_policy_covers_runtime_step_literals():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-reasoning-path-policy"})

    assert resp.status_code == 200
    policy = resp.json()["answer"]["reasoningPathPolicy"]
    emitted_steps = _dict_string_values_for_key(inspect.getsource(judge_service), key="step")

    assert set(policy["stepCatalog"]) == emitted_steps
    assert policy["requiredFields"] == ["step", "status"]
    assert policy["cacheStep"] in emitted_steps
    assert set(policy["affectednessSteps"]) <= emitted_steps
    assert policy["perResponseSequenceRequired"] is False
    assert policy["cacheHitMayOmitAffectednessSteps"] is True
    assert policy["negativeEvidenceAllowed"] is False


def test_judge_contract_reasoning_path_policy_covers_validator_issue_codes():
    resp = client.get("/v1/contracts/judge", headers={"X-Request-Id": "req-judge-reasoning-path-issue-catalog"})

    assert resp.status_code == 200
    catalog = resp.json()["answer"]["reasoningPathPolicy"]["validatorIssueCatalog"]
    emitted_codes = _string_literal_codes(inspect.getsource(judge_service), prefix="REASONING_PATH_")

    assert catalog["coverage"] == "all_known_reasoning_path_validator_issue_codes"
    assert set(catalog["issueCodes"]) == emitted_codes
    assert catalog["negativeEvidenceAllowed"] is False


def test_threat_retrieval_issue_literal_extractor_covers_python_string_quote_styles():
    source = """
ISSUE_DOUBLE = "THREAT_RETRIEVAL_DOUBLE_QUOTED_LITERAL"
ISSUE_SINGLE = 'THREAT_RETRIEVAL_SINGLE_QUOTED_LITERAL'
not_an_issue = "SOURCE_KG_DIAGNOSTIC"
"""

    assert _threat_retrieval_issue_literal_codes(source) == {
        "THREAT_RETRIEVAL_DOUBLE_QUOTED_LITERAL",
        "THREAT_RETRIEVAL_SINGLE_QUOTED_LITERAL",
    }


def test_judge_api_returns_evidence_grounded_answer_and_serving_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    try:
        resp = client.post("/v1/judge/query", json=_judge_payload(source_context), headers=_HEADERS)

        assert resp.status_code == 200, resp.text
        assert resp.headers["X-Request-Id"] == "req-judge-api-test"
        body = resp.json()
        assert body["schemaVersion"] == "s5-judge-answer-v1"
        assert body["verdictAuthority"] == "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict"
        assert body["verdict"] == "affected"
        assert body["status"] == "complete"
        assert body["servingLedger"]["recorded"] is True
        assert repo.get_serving_query_run(body["servingLedger"]["servingRunId"]) is not None
        assert body["evidence"]["sourceCodeKg"]["resolved"] is True
        assert body["evidence"]["sourceCodeKg"]["repositorySnapshot"]["commitHash"] == "curl-commit-800"
        serialized = str(body).lower()
        assert all(term not in serialized for term in _OFFLINE_METRIC_TERMS)
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_redacts_credential_bearing_question_urls_from_response_and_serving_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    leaky_question_url = "https://question_user:question_password@questions.example/path?api_key=question-secret"
    payload = _judge_payload(source_context)
    payload["question"] = f"Is curl affected? Evidence URL: {leaky_question_url}"
    try:
        resp = client.post(
            "/v1/judge/query",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-question-url-redaction"},
        )

        assert resp.status_code == 200, resp.text[:1000]
        body = resp.json()
        assert body["queryContext"]["question"] == (
            "Is curl affected? Evidence URL: https://***:***@questions.example/path?api_key=***"
        )
        body_text = json.dumps(body, ensure_ascii=False)
        for secret in ["question_user", "question_password", "question-secret"]:
            assert secret not in body_text
        assert "question_user:question_password" not in " ".join(body["canonicalQuery"]["normalized"]["questionTerms"])
        row = repo.get_serving_query_run(body["servingLedger"]["servingRunId"])
        assert row is not None
        row_text = json.dumps(row, ensure_ascii=False)
        for secret in ["question_user", "question_password", "question-secret"]:
            assert secret not in row_text
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_accepts_topk_control_and_caps_threat_candidates(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    try:
        payload = _judge_payload(source_context)
        payload["controls"] = {"topK": 1, "answerMode": "evidence_grounded"}
        resp = client.post("/v1/judge/query", json=payload, headers=_HEADERS)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        threat = body["evidence"]["threatRetrieval"]
        assert body["verdict"] == "affected"
        assert body["appliedControls"]["accepted"]["topK"] == 1
        assert body["canonicalQuery"]["normalized"]["controls"]["topK"] == 1
        assert len(threat["candidateEvidence"]) == 1
        assert threat["retrievalTrace"]["topK"] == 1
        assert threat["retrievalTrace"]["returnedCount"] == 1
        assert threat["retrievalTrace"]["topKPolicy"]["topKMeans"] == "final_returned_count"
        assert threat["retrievalTrace"]["candidatePoolPolicy"]["candidatePoolK"] > 1
        assert threat["retrievalTrace"]["rerankerPolicy"]["modelBacked"] is False
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_exposes_partial_source_kg_context_in_answer_and_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    leaky_missing_node = "https://node_user:node_password@ids.example/missing-node?token=node-secret"
    source_context["graphNodeIds"] = [source_context["graphNodeIds"][0], leaky_missing_node]
    judge_api.set_ledger_repository(repo)
    try:
        resp = client.post("/v1/judge/query", json=_judge_payload(source_context), headers=_HEADERS)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        resolution = body["evidence"]["sourceCodeKg"]["contextResolution"]
        safe_missing_node = "https://***:***@ids.example/missing-node?token=***"
        assert body["evidence"]["sourceCodeKg"]["resolved"] is True
        assert resolution["partial"] is True
        assert resolution["graphNodes"]["missingIds"] == [safe_missing_node]
        assert body["queryContext"]["sourceContext"]["graphNodeIds"] == [
            source_context["graphNodeIds"][0],
            safe_missing_node,
        ]
        assert set(body["canonicalQuery"]["normalized"]["sourceContext"]["graphNodeIds"]) == {
            source_context["graphNodeIds"][0],
            safe_missing_node,
        }
        assert any(item["fallback"] == "partial_context_resolution" and item["silent"] is False for item in body["fallbackTrace"])
        assert any(item["code"] == "SOURCE_KG_CONTEXT_PARTIAL" for item in body["qualityGate"]["diagnostics"])
        assert "node_user" not in str(body)
        assert "node_password" not in str(body)
        assert "node-secret" not in str(body)
        row = repo.get_serving_query_run(body["servingLedger"]["servingRunId"])
        assert row["answer"]["evidence"]["sourceCodeKg"]["contextResolution"] == resolution
        assert row["request"]["sourceContext"]["graphNodeIds"] == body["queryContext"]["sourceContext"]["graphNodeIds"]
        assert row["answer"]["queryContext"]["sourceContext"] == body["queryContext"]["sourceContext"]
        assert row["answer"]["canonicalQuery"]["normalized"]["sourceContext"] == body["canonicalQuery"]["normalized"]["sourceContext"]
        assert "node_user" not in str(row["request"])
        assert "node_password" not in str(row["request"])
        assert "node-secret" not in str(row["request"])
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_rejects_over_limit_source_context_selectors(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    judge_api.set_ledger_repository(repo)
    try:
        over_limit_source_contexts = [
            {"graphNodeIds": [f"node-{index}" for index in range(257)]},
            {"evidenceSnippetIds": [f"snippet-{index}" for index in range(257)]},
            {"richIrArtifactIds": [f"rich-ir-{index}" for index in range(129)]},
        ]
        for source_context in over_limit_source_contexts:
            payload = _judge_payload(source_context)
            resp = client.post(
                "/v1/judge/query",
                json=payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-over-limit-source-context"},
            )

            assert resp.status_code == 422
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "explicit_selector_limit_exceeded"
            assert body["errorDetail"]["requestId"] == "req-judge-over-limit-source-context"
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_rejects_oversized_source_context_selector_without_echo_or_serving_write(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    judge_api.set_ledger_repository(repo)
    oversized_id = "node-" + ("x" * 100_000)
    try:
        oversized_source_contexts = [
            {"repositorySnapshotId": oversized_id},
            {"graphNodeIds": [oversized_id]},
        ]
        for source_context in oversized_source_contexts:
            resp = client.post(
                "/v1/judge/query",
                json=_judge_payload(source_context),
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-oversized-selector"},
            )

            assert resp.status_code == 422
            body_text = resp.text
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "selector_value_too_long"
            assert len(body_text) < 4096
            assert oversized_id not in body_text
        assert repo.count_rows("serving_query_run") == 0
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_redacts_oversized_accepted_control_values_from_response_and_serving_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    huge = "control-" + ("x" * 100_000)
    payload = _judge_payload(source_context)
    payload["controls"] = {
        "exclude": ["CVE-2026-0001", huge],
        "prefer": ["threatKb", huge],
        "forceContext": {"targetId": "re100:http-client", "note": huge},
        "answerMode": huge,
        "mysteryControl": huge,
    }
    try:
        resp = client.post(
            "/v1/judge/query",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-oversized-controls"},
        )

        assert resp.status_code == 200, resp.text[:1000]
        body_text = resp.text
        body = resp.json()
        assert huge not in body_text
        assert len(body_text) < 100_000
        assert "CVE-2026-0001" in body["appliedControls"]["accepted"]["exclude"]
        assert "threatKb" in body["appliedControls"]["accepted"]["prefer"]
        assert body["appliedControls"]["accepted"]["forceContext"] == {}
        assert {(item["control"], item["reason"]) for item in body["appliedControls"]["rejected"]} >= {
            ("exclude", "control_value_too_long"),
            ("prefer", "control_value_too_long"),
            ("forceContext", "control_value_too_long"),
            ("answerMode", "control_value_too_long"),
            ("mysteryControl", "unsupported_control"),
        }
        row = repo.get_serving_query_run(body["servingLedger"]["servingRunId"])
        assert row is not None
        assert huge not in json.dumps(row["request"], ensure_ascii=False)
        assert huge not in json.dumps(row["answer"], ensure_ascii=False)
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_redacts_credential_bearing_control_echoes_from_response_and_serving_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    leaky_force_context = "https://ctrl_user:ctrl_password@controls.example/artifact?token=ctrl-secret"
    leaky_unknown_control = "https://bad_user:bad_password@controls.example/control?api_key=bad-secret"
    payload = _judge_payload(source_context)
    payload["controls"] = {
        "forceContext": {"artifactUrl": leaky_force_context},
        "mysteryControl": leaky_unknown_control,
        "https://key_user:key_password@controls.example/control?token=key-secret": "safe-value",
    }
    try:
        resp = client.post(
            "/v1/judge/query",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-control-url-redaction"},
        )

        assert resp.status_code == 200, resp.text[:1000]
        body = resp.json()
        safe_force_context = "https://***:***@controls.example/artifact?token=***"
        safe_unknown_control = "https://***:***@controls.example/control?api_key=***"
        assert body["appliedControls"]["requested"]["forceContext"]["artifactUrl"] == safe_force_context
        assert body["appliedControls"]["accepted"]["forceContext"]["artifactUrl"] == safe_force_context
        assert body["appliedControls"]["rejected"] == [
            {
                "control": "https://***:***@controls.example/control?token=***",
                "value": "safe-value",
                "reason": "unsupported_control",
            },
            {"control": "mysteryControl", "value": safe_unknown_control, "reason": "unsupported_control"},
        ]
        assert body["canonicalQuery"]["controlSummary"]["requested"]["forceContext"]["artifactUrl"] == safe_force_context
        assert body["canonicalQuery"]["controlSummary"]["accepted"]["forceContext"]["artifactUrl"] == safe_force_context
        assert body["canonicalQuery"]["controlSummary"]["rejected"] == body["appliedControls"]["rejected"]
        for secret in [
            "ctrl_user",
            "ctrl_password",
            "ctrl-secret",
            "bad_user",
            "bad_password",
            "bad-secret",
            "key_user",
            "key_password",
            "key-secret",
        ]:
            assert secret not in resp.text
        row = repo.get_serving_query_run(body["servingLedger"]["servingRunId"])
        assert row is not None
        row_text = json.dumps(row, ensure_ascii=False)
        for secret in [
            "ctrl_user",
            "ctrl_password",
            "ctrl-secret",
            "bad_user",
            "bad_password",
            "bad-secret",
            "key_user",
            "key_password",
            "key-secret",
        ]:
            assert secret not in row_text
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_rejects_over_limit_control_lists_before_serving_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    try:
        for control_name, values in {
            "exclude": [f"CVE-2026-{index:04d}" for index in range(129)],
            "prefer": ["threatKb" for _ in range(129)],
        }.items():
            payload = _judge_payload(source_context)
            payload["controls"] = {control_name: values}
            resp = client.post(
                "/v1/judge/query",
                json=payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-judge-control-list-{control_name}"},
            )

            assert resp.status_code == 422
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "control_list_too_long"
            assert body["errorDetail"]["requestId"] == f"req-judge-control-list-{control_name}"
            assert len(resp.text) < 4096
        assert repo.count_rows("serving_query_run") == 0
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_rejects_over_budget_force_context_before_serving_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    try:
        force_context_cases = [
            {"k%03d" % index: "v" for index in range(129)},
            {"nested": [f"ctx-{index:03d}" for index in range(513)]},
        ]
        for index, force_context in enumerate(force_context_cases):
            payload = _judge_payload(source_context)
            payload["controls"] = {"forceContext": force_context}
            resp = client.post(
                "/v1/judge/query",
                json=payload,
                headers={"X-Timeout-Ms": "30000", "X-Request-Id": f"req-judge-force-context-{index}"},
            )

            assert resp.status_code == 422
            body = resp.json()
            assert body["success"] is False
            assert body["errorDetail"]["reason"] == "control_object_too_large"
            assert body["errorDetail"]["requestId"] == f"req-judge-force-context-{index}"
            assert len(resp.text) < 4096
            assert "ctx-512" not in resp.text
        assert repo.count_rows("serving_query_run") == 0
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_bounds_many_small_unknown_control_echoes_in_response_and_serving_ledger(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)
    values = [f"unknown-control-value-{index:04d}" for index in range(5000)]
    payload = _judge_payload(source_context)
    payload["controls"] = {"unknownControl": values}
    try:
        resp = client.post(
            "/v1/judge/query",
            json=payload,
            headers={"X-Timeout-Ms": "30000", "X-Request-Id": "req-judge-unknown-control-bloat"},
        )

        assert resp.status_code == 200, resp.text[:1000]
        body_text = resp.text
        body = resp.json()
        assert len(body_text) < 50_000
        assert "unknown-control-value-4999" not in body_text
        rejected = body["appliedControls"]["rejected"]
        assert rejected == [
            {
                "control": "unknownControl",
                "value": {
                    "redacted": True,
                    "type": "list",
                    "length": 5000,
                    "reason": "control_object_too_large",
                },
                "reason": "unsupported_control",
            }
        ]
        row = repo.get_serving_query_run(body["servingLedger"]["servingRunId"])
        assert row is not None
        assert "unknown-control-value-4999" not in json.dumps(row["request"], ensure_ascii=False)
        assert "unknown-control-value-4999" not in json.dumps(row["answer"], ensure_ascii=False)
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_requires_timeout_header(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    judge_api.set_ledger_repository(repo)
    try:
        resp = client.post("/v1/judge/query", json=_judge_payload(), headers={"X-Request-Id": "req-no-timeout"})

        assert resp.status_code == 400
        assert resp.json()["errorDetail"]["code"] == "BAD_REQUEST"
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_uninitialized_ledger_returns_kb_not_ready():
    old = judge_api._ledger_repository
    judge_api.set_ledger_repository(None)
    try:
        resp = client.post("/v1/judge/query", json=_judge_payload(), headers=_HEADERS)

        assert resp.status_code == 503
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "KB_NOT_READY"
        assert body["errorDetail"]["retryable"] is True
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_timeout_does_not_write_serving_ledger_after_408(tmp_path, monkeypatch):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)

    def _slow_writing_query(repo_arg, req):
        time.sleep(0.05)
        from app.judge.service import build_judge_answer

        return build_judge_answer(repo_arg, req)

    monkeypatch.setattr(judge_api, "_query_sync", _slow_writing_query)
    try:
        resp = client.post(
            "/v1/judge/query",
            json=_judge_payload(source_context),
            headers={"X-Timeout-Ms": "1", "X-Request-Id": "req-judge-timeout-no-write"},
        )
        time.sleep(0.1)

        assert resp.status_code == 408
        assert resp.json()["errorDetail"]["reason"] == "deadline_exceeded_before_judge_query_completed"
        assert repo.count_rows("serving_query_run") == 0
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_started_write_is_not_reported_as_timeout_with_late_serving_row(tmp_path, monkeypatch):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    source_context = _ingest_source_context(repo)
    judge_api.set_ledger_repository(repo)

    def _slow_started_query(repo_arg, req):
        time.sleep(0.05)
        from app.judge.service import build_judge_answer

        return build_judge_answer(repo_arg, req)

    monkeypatch.setattr(judge_api, "_query_sync", _slow_started_query)
    try:
        resp = client.post(
            "/v1/judge/query",
            json=_judge_payload(source_context),
            headers={"X-Timeout-Ms": "20", "X-Request-Id": "req-judge-started-write"},
        )
        time.sleep(0.1)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["servingLedger"]["recorded"] is True
        assert repo.count_rows("serving_query_run") == 1
    finally:
        judge_api.set_ledger_repository(old)


def test_judge_api_validation_errors_use_s5_error_envelope(tmp_path):
    old = judge_api._ledger_repository
    repo = _repo(tmp_path)
    judge_api.set_ledger_repository(repo)
    try:
        invalid = _judge_payload()
        invalid["unexpected"] = "field"
        resp = client.post("/v1/judge/query", json=invalid, headers=_HEADERS)

        assert resp.status_code == 422
        body = resp.json()
        assert body["success"] is False
        assert body["errorDetail"]["code"] == "INVALID_INPUT"
        assert body["errorDetail"]["retryable"] is False
    finally:
        judge_api.set_ledger_repository(old)
