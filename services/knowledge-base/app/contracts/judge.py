"""Machine-readable Evidence-Grounded Judge contract snapshot."""

from __future__ import annotations

from app.analyst.brief import BASELINE_FORBIDDEN_INFERENCES
from app.contracts.source_kg import SOURCE_KG_SERVING_CONTEXT_RESOLUTION
from app.judge.models import JudgeQueryRequest
from app.judge.service import CONFLICT_CONSUMER_POLICY
from app.judge.service import DECISION_CACHE_REVISION_TABLES
from app.judge.service import JUDGE_CONTROL_EFFECT_CONTROLS
from app.judge.service import JUDGE_CONTROL_EFFECT_REQUIRED_FIELDS
from app.judge.service import JUDGE_CONTROL_EFFECT_VALIDATOR_ISSUE_CODES
from app.judge.service import JUDGE_FALLBACK_TRACE_STAGE_CATALOG
from app.judge.service import JUDGE_FALLBACK_TRACE_VALIDATOR_ISSUE_CODES
from app.judge.service import JUDGE_FOLLOW_UP_OWNER_LANES
from app.judge.service import JUDGE_FOLLOW_UP_REQUEST_KINDS
from app.judge.service import JUDGE_ANSWER_FIELD_VALIDATOR_ISSUE_CODES
from app.judge.service import JUDGE_REASONING_PATH_STEPS
from app.judge.service import JUDGE_REASONING_PATH_VALIDATOR_ISSUE_CODES
from app.judge.service import JUDGE_UNCERTAINTY_FOLLOWUP_VALIDATOR_ISSUE_CODES
from app.judge.service import JUDGE_UNCERTAINTY_REQUIRED_FIELDS
from app.judge.service import JUDGE_UNCERTAINTY_REQUIRED_INPUT_VOCABULARY
from app.judge.service import MAX_CONFLICTING_VALUES_IN_SUMMARY
from app.judge.service import SCHEMA_VERSION as ANSWER_SCHEMA_VERSION
from app.judge.service import THREAT_RETRIEVAL_DIAGNOSTIC_METADATA_REDACTION_FIELDS
from app.judge.service import THREAT_RETRIEVAL_VALIDATOR_ISSUE_FIELDS
from app.judge.service import VERDICT_AUTHORITY
from app.ledger.repository import MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS
from app.ledger.repository import MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES
from app.relations.conflict_model import HARD_CONFLICT_KINDS
from app.relations.conflict_model import ISSUE_CODE_BY_KIND
from app.source_kg.models import (
    MAX_CONTEXT_EVIDENCE_SNIPPET_IDS,
    MAX_CONTEXT_GRAPH_NODE_IDS,
    MAX_CONTEXT_RICH_IR_ARTIFACT_IDS,
    MAX_CONTEXT_SELECTOR_ID_LENGTH,
)
from app.serving.query_planner import (
    CONTROL_LIST_TOO_LONG_REASON,
    CONTROL_OBJECT_TOO_LARGE_REASON,
    MAX_CONTROL_LIST_ITEMS,
    MAX_CONTROL_VALUE_ECHO_CHARS,
    MAX_FORCE_CONTEXT_DEPTH,
    MAX_FORCE_CONTEXT_ECHO_BYTES,
    MAX_FORCE_CONTEXT_ROOT_KEYS,
    MAX_FORCE_CONTEXT_TOTAL_ITEMS,
    MAX_CONTROL_ECHO_TOTAL_ITEMS,
    MAX_CONTROL_ECHO_BYTES,
    MAX_UNSUPPORTED_CONTROL_ECHO_ITEMS,
)
from app.threat_retrieval import AUTHORITY as THREAT_RETRIEVAL_AUTHORITY
from app.threat_retrieval import CANDIDATE_POOL_PREVIEW_MIN_LIMIT
from app.threat_retrieval import EQUIVALENT_ADVISORY_RESPONSE_LIMIT
from app.threat_retrieval import RISK_SIGNAL_AUTHORITY
from app.threat_retrieval import RISK_SIGNAL_RESPONSE_LIMIT
from app.threat_retrieval import SEMANTIC_EXPANSION_RESPONSE_LIMIT
from app.threat_retrieval import SUPPRESSED_CANDIDATE_RESPONSE_LIMIT
from app.timeout import MIN_SYNC_THREAD_DEADLINE_SECONDS

CONTRACT_SCHEMA_VERSION = "s5-judge-contract-v1"

JUDGE_RUNTIME_VOCABULARY = (
    "affected",
    "not_affected",
    "unknown",
    "conflicting",
    "complete",
    "requires_requery",
    "insufficient_input",
    "degraded_quality",
    "stale_cache",
    "policy_blocked",
    "servingLedger",
    "sourceCodeKg",
    "threatRetrieval",
    "identityResolution",
    "affectedness",
    "scoreVector",
    "qualityGate",
    "fallbackTrace",
    "forbiddenInferences",
)

JUDGE_QUALITY_GATE_ALLOWED_GATES = (
    "accepted",
    "accepted_with_caveats",
    "rejected",
)

JUDGE_QUALITY_GATE_MERGE_PRECEDENCE = (
    "rejected",
    "accepted_with_caveats",
    "accepted",
)

JUDGE_ANSWER_STATUS_ALLOWED = (
    "complete",
    "degraded_quality",
    "requires_requery",
    "insufficient_input",
)

JUDGE_ANSWER_STATUS_RESERVED_RUNTIME_VOCABULARY = (
    "stale_cache",
    "policy_blocked",
)

JUDGE_VERDICT_ALLOWED = (
    "affected",
    "not_affected",
    "unknown",
)

JUDGE_VERDICT_RESERVED_RUNTIME_VOCABULARY = (
    "conflicting",
)

OFFLINE_QUALITY_METRIC_TERMS = (
    "false_negative",
    "false_positive",
    "mrr",
    "ndcg",
    "precision",
    "recall",
    "true_positive",
)

THREAT_RETRIEVAL_DYNAMIC_VALIDATOR_ISSUE_FIELD_POLICY = {
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
}

THREAT_RETRIEVAL_RUNTIME_DIAGNOSTIC_CODES = {
    "THREAT_RETRIEVAL_NO_CONTEXT": {
        "meaning": (
            "no candidate advisory/context rows were discovered for the current normalized "
            "component and security question terms"
        ),
        "verdictAuthority": "unknown_only",
        "negativeEvidenceAllowed": False,
        "requiredConsumerBehavior": "treat_as_inconclusive_context_gap_not_component_safe",
    },
}

JUDGE_SOURCE_KG_ISSUE_AND_DIAGNOSTIC_CODES_BY_FAMILY = {
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
}

JUDGE_ANSWER_FIELD_ROBUSTNESS_REPRESENTATIVE_MUTATION_PATHS = (
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
)


def _threat_retrieval_validator_issue_code_coverage() -> dict:
    static_codes = set(THREAT_RETRIEVAL_VALIDATOR_ISSUE_FIELDS)
    dynamic_codes = set(THREAT_RETRIEVAL_DYNAMIC_VALIDATOR_ISSUE_FIELD_POLICY)
    return {
        "coverage": "all_known_threat_retrieval_validator_issue_codes",
        "knownIssueCodeCount": len(static_codes | dynamic_codes),
        "staticFieldIssueCodeCount": len(static_codes),
        "dynamicFieldIssueCodeCount": len(dynamic_codes),
    }


def _threat_retrieval_runtime_diagnostic_code_coverage() -> dict:
    return {
        "coverage": "all_known_threat_retrieval_runtime_diagnostic_codes",
        "knownDiagnosticCodeCount": len(THREAT_RETRIEVAL_RUNTIME_DIAGNOSTIC_CODES),
    }


def _judge_source_kg_issue_and_diagnostic_catalog() -> dict:
    known_codes = {
        code
        for codes in JUDGE_SOURCE_KG_ISSUE_AND_DIAGNOSTIC_CODES_BY_FAMILY.values()
        for code in codes
    }
    return {
        "coverage": "all_known_judge_source_kg_issue_and_diagnostic_codes",
        "knownCodeCount": len(known_codes),
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "source_kg_context_issues_are_inconclusive_context_diagnostics_not_negative_security_evidence",
        "codesByFamily": JUDGE_SOURCE_KG_ISSUE_AND_DIAGNOSTIC_CODES_BY_FAMILY,
    }


def _judge_source_kg_serving_context_diagnostic_catalog() -> dict:
    coverage = SOURCE_KG_SERVING_CONTEXT_RESOLUTION["diagnosticCodeCoverage"]
    return {
        "location": "evidence.sourceCodeKg.contextResolution.diagnostics",
        "coverage": coverage["coverage"],
        "knownDiagnosticCodeCount": coverage["knownDiagnosticCodeCount"],
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "source_kg_context_diagnostics_are_inconclusive_context_diagnostics_not_negative_security_evidence",
        "diagnosticCodes": list(SOURCE_KG_SERVING_CONTEXT_RESOLUTION["diagnosticCodes"]),
    }


def _relation_conflict_issue_code_catalog() -> dict:
    codes_by_kind = dict(sorted(ISSUE_CODE_BY_KIND.items()))
    return {
        "coverage": "all_known_relation_conflict_issue_codes",
        "knownIssueCodeCount": len(set(codes_by_kind.values())),
        "negativeEvidenceAllowed": False,
        "codesByKind": codes_by_kind,
        "hardConflictKinds": sorted(HARD_CONFLICT_KINDS),
    }


def _forbidden_inference_policy() -> dict:
    return {
        "coverage": "all_baseline_s5_forbidden_inferences",
        "source": "app.analyst.brief.BASELINE_FORBIDDEN_INFERENCES",
        "forbiddenInferenceCount": len(BASELINE_FORBIDDEN_INFERENCES),
        "s3FinalAuthorityBoundary": True,
        "consumerPolicy": "forbidden_inferences_must_not_be_promoted_to_s3_final_claims",
    }


def _runtime_vocabulary_policy() -> dict:
    return {
        "coverage": "s5_judge_runtime_vocabulary",
        "runtimeVocabularyCount": len(JUDGE_RUNTIME_VOCABULARY),
        "offlineQualityVocabularyForbidden": True,
        "offlineQualityMetricTerms": list(OFFLINE_QUALITY_METRIC_TERMS),
        "consumerPolicy": "runtime_vocabulary_terms_are_not_offline_quality_labels_or_s3_final_claims",
    }


def _quality_gate_policy() -> dict:
    return {
        "location": "qualityGate",
        "allowedGates": list(JUDGE_QUALITY_GATE_ALLOWED_GATES),
        "mergePrecedence": list(JUDGE_QUALITY_GATE_MERGE_PRECEDENCE),
        "scorePolicyLocation": "qualityGate.scorePolicy",
        "diagnosticsLocation": "qualityGate.diagnostics",
        "hardFailPolicy": "true_when_score_policy_hard_fails_or_base_gate_rejected",
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "quality_gate_is_s5_runtime_quality_not_s3_final_security_verdict",
    }


def _answer_status_policy() -> dict:
    return {
        "location": "status",
        "allowedStatuses": list(JUDGE_ANSWER_STATUS_ALLOWED),
        "reservedRuntimeVocabulary": list(JUDGE_ANSWER_STATUS_RESERVED_RUNTIME_VOCABULARY),
        "degradedStatus": "degraded_quality",
        "missingInputStatus": "requires_requery",
        "emptyRequiredInputStatus": "insufficient_input",
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "non_complete_statuses_are_requery_or_quality_signals_not_negative_evidence",
    }


def _verdict_policy() -> dict:
    return {
        "location": "verdict",
        "allowedVerdicts": list(JUDGE_VERDICT_ALLOWED),
        "reservedRuntimeVocabulary": list(JUDGE_VERDICT_RESERVED_RUNTIME_VOCABULARY),
        "conflictRepresentation": "uncertainty.conflicts_and_qualityGate_rejected_not_verdict_conflicting",
        "notAffectedPolicy": "scope_bound_evidence_verdict_not_clean_pass",
        "unknownPolicy": "requires_more_context_not_no_hit_or_safe",
        "s3FinalAuthorityBoundary": True,
        "consumerPolicy": "judge_verdict_is_s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict",
    }


def _uncertainty_policy() -> dict:
    return {
        "location": "uncertainty",
        "requiredFields": list(JUDGE_UNCERTAINTY_REQUIRED_FIELDS),
        "requiredInputVocabulary": list(JUDGE_UNCERTAINTY_REQUIRED_INPUT_VOCABULARY),
        "conflictLocation": "uncertainty.conflicts",
        "fieldShapePolicy": {
            "reason": "string_or_null_non_empty_when_unknown_or_non_complete",
            "evidenceGaps": "list_of_strings",
            "requiredInputs": "list_of_known_required_input_vocabulary",
            "conflicts": "list_of_objects",
        },
        "followUpAffordancesLocation": "followUpAffordances",
        "followUpRequestKinds": list(JUDGE_FOLLOW_UP_REQUEST_KINDS),
        "ownerLanes": list(JUDGE_FOLLOW_UP_OWNER_LANES),
        "nonEmptyOnUnknownOrDegraded": True,
        "validatorIssueCatalog": {
            "coverage": "all_known_uncertainty_followup_validator_issue_codes",
            "issueCodes": list(JUDGE_UNCERTAINTY_FOLLOWUP_VALIDATOR_ISSUE_CODES),
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "uncertainty_followup_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "uncertainty_and_followups_are_requery_guidance_not_negative_evidence",
    }


def _control_effects_policy() -> dict:
    return {
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
            "controlEffectFields": list(JUDGE_CONTROL_EFFECT_REQUIRED_FIELDS),
            "controlEffectsTraceRequiredFor": ["evidence.suppressedAffectedness"],
            "threatRetrievalSuppressionTraceOwner": (
                "answer.threatRetrievalPolicies.suppressedCandidateResponseBudget"
            ),
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
            "allowedControls": list(JUDGE_CONTROL_EFFECT_CONTROLS),
            "requiredFields": list(JUDGE_CONTROL_EFFECT_REQUIRED_FIELDS),
            "issueCodes": list(JUDGE_CONTROL_EFFECT_VALIDATOR_ISSUE_CODES),
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "control_effect_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "caller_controls_shape_response_scope_but_do_not_create_negative_evidence",
    }


def _answer_field_policy() -> dict:
    return {
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
            "representativeMutationPaths": list(JUDGE_ANSWER_FIELD_ROBUSTNESS_REPRESENTATIVE_MUTATION_PATHS),
        },
        "validatorIssueCatalog": {
            "coverage": "all_known_answer_field_validator_issue_codes",
            "issueCodes": list(JUDGE_ANSWER_FIELD_VALIDATOR_ISSUE_CODES),
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "answer_field_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "answer_packet_field_shapes_are_contract_quality_not_security_evidence",
    }


def _fallback_trace_policy() -> dict:
    return {
        "location": "fallbackTrace",
        "requiredFields": ["stage", "fallback", "silent"],
        "stageCatalog": {stage: list(fallbacks) for stage, fallbacks in JUDGE_FALLBACK_TRACE_STAGE_CATALOG.items()},
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
            "issueCodes": list(JUDGE_FALLBACK_TRACE_VALIDATOR_ISSUE_CODES),
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "fallback_trace_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "fallback_trace_entries_are_non_silent_requery_or_scope_diagnostics_not_negative_evidence",
    }


def _reasoning_path_policy() -> dict:
    return {
        "location": "reasoningPath",
        "requiredFields": ["step", "status"],
        "stepCatalog": list(JUDGE_REASONING_PATH_STEPS),
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
            "issueCodes": list(JUDGE_REASONING_PATH_VALIDATOR_ISSUE_CODES),
            "negativeEvidenceAllowed": False,
            "consumerPolicy": "reasoning_path_validator_issues_are_contract_quality_failures_not_security_evidence",
        },
        "negativeEvidenceAllowed": False,
        "consumerPolicy": "reasoning_path_is_explainability_trace_not_security_verdict",
    }


def judge_contract_snapshot() -> dict:
    """Return the S5 Judge runtime contract.

    This contract intentionally exposes S5's answerability boundary without
    promoting S5 output into S3 final claim/security-verdict authority.
    """

    return {
        "schemaVersion": CONTRACT_SCHEMA_VERSION,
        "endpoint": {"method": "POST", "path": "/v1/judge/query"},
        "request": {
            "schemaVersion": "s5-judge-query-v1",
            "jsonSchema": JudgeQueryRequest.model_json_schema(),
            "timeoutHeaderRequired": True,
            "timeoutFailurePolicy": {
                "reason": "deadline_exceeded_before_judge_query_completed",
                "servingLedgerWriteOnTimeout": False,
                "timeoutPhase": "pre_start_only_for_durable_write",
                "postStartTimeoutResponse": "wait_for_completion_and_return_result",
                "minimumSafeStartBudgetMs": int(MIN_SYNC_THREAD_DEADLINE_SECONDS * 1000),
            },
            "controlEchoPolicy": {
                "maxStringEchoChars": MAX_CONTROL_VALUE_ECHO_CHARS,
                "maxListItems": MAX_CONTROL_LIST_ITEMS,
                "maxForceContextRootKeys": MAX_FORCE_CONTEXT_ROOT_KEYS,
                "maxForceContextTotalItems": MAX_FORCE_CONTEXT_TOTAL_ITEMS,
                "maxForceContextEchoBytes": MAX_FORCE_CONTEXT_ECHO_BYTES,
                "maxForceContextDepth": MAX_FORCE_CONTEXT_DEPTH,
                "maxUnsupportedControlEchoItems": MAX_UNSUPPORTED_CONTROL_ECHO_ITEMS,
                "maxControlEchoTotalItems": MAX_CONTROL_ECHO_TOTAL_ITEMS,
                "maxControlEchoBytes": MAX_CONTROL_ECHO_BYTES,
                "oversizedStringRedaction": {"redacted": True, "type": "str", "length": "original_length"},
                "oversizedControlNameRedaction": {"redacted": True, "type": "control", "length": "original_length"},
                "oversizedObjectKeyRedaction": "<redacted-key:original_length>",
                "oversizedObjectRedaction": {
                    "redacted": True,
                    "type": "list|object",
                    "length": "original_length",
                    "reason": CONTROL_OBJECT_TOO_LARGE_REASON,
                },
                "credentialBearingUrlRedaction": True,
                "tooLongRejectionReason": "control_value_too_long",
                "listTooLongRejectionReason": CONTROL_LIST_TOO_LONG_REASON,
                "objectTooLargeRejectionReason": CONTROL_OBJECT_TOO_LARGE_REASON,
                "appliesTo": [
                    "appliedControls.requested",
                    "appliedControls.accepted",
                    "appliedControls.rejected",
                    "canonicalQuery.controlSummary",
                    "servingLedger.requestPacket",
                    "servingLedger.answerPacket",
                ],
                "preLedgerRejectedControls": ["exclude", "prefer", "forceContext"],
            },
            "questionEchoPolicy": {
                "credentialBearingUrlRedaction": True,
                "appliesTo": [
                    "queryContext.question",
                    "canonicalQuery.normalized.questionTerms",
                    "servingLedger.requestPacket.question",
                    "servingLedger.answerPacket",
                ],
            },
        },
        "answer": {
            "schemaVersion": ANSWER_SCHEMA_VERSION,
            "notFinalSecurityVerdict": True,
            "verdictAuthority": VERDICT_AUTHORITY,
            "threatRetrievalPolicies": {
                "topKPolicy": "s5-top-k-policy-v1",
                "candidatePoolPolicy": "s5-candidate-pool-policy-v1",
                "rerankerPolicy": "s5-deterministic-method-aware-reranker",
                "candidatePoolPreview": {
                    "location": "evidence.threatRetrieval.retrievalTrace.candidatePoolPreview",
                    "bounded": True,
                    "minimumLimit": CANDIDATE_POOL_PREVIEW_MIN_LIMIT,
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
                    "diagnosticCodeCoverage": _threat_retrieval_runtime_diagnostic_code_coverage(),
                    "diagnosticCodes": dict(sorted(THREAT_RETRIEVAL_RUNTIME_DIAGNOSTIC_CODES.items())),
                },
                "equivalentAdvisoryResponseBudget": {
                    "location": "evidence.threatRetrieval.retrievalTrace",
                    "bounded": True,
                    "responseLimit": EQUIVALENT_ADVISORY_RESPONSE_LIMIT,
                    "returnedCountField": "equivalentAdvisoryReturnedCount",
                    "truncatedField": "equivalentAdvisoryResponseTruncated",
                },
                "riskSignalResponseBudget": {
                    "location": "evidence.threatRetrieval.retrievalTrace",
                    "bounded": True,
                    "responseLimit": RISK_SIGNAL_RESPONSE_LIMIT,
                    "returnedCountField": "riskSignalReturnedCount",
                    "truncatedField": "riskSignalResponseTruncated",
                },
                "authorityBoundaryValidation": {
                    "contextAuthority": THREAT_RETRIEVAL_AUTHORITY,
                    "riskSignalAuthority": RISK_SIGNAL_AUTHORITY,
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
                    "redactedFields": list(THREAT_RETRIEVAL_DIAGNOSTIC_METADATA_REDACTION_FIELDS),
                },
                "validatorIssueFieldPathPolicy": {
                    "fieldRequired": True,
                    "explicitRelativeFieldNormalization": True,
                    "issueCodeCoverage": _threat_retrieval_validator_issue_code_coverage(),
                    "representativeFieldByIssueCode": {
                        code: THREAT_RETRIEVAL_VALIDATOR_ISSUE_FIELDS[code]
                        for code in (
                            "THREAT_RETRIEVAL_RETURNED_COUNT_MISMATCH",
                            "THREAT_RETRIEVAL_RANK_SEQUENCE_INVALID",
                            "THREAT_RETRIEVAL_CANDIDATE_POOL_PREVIEW_RETURNED_MISMATCH",
                        )
                    },
                    "issueFieldsByCode": dict(sorted(THREAT_RETRIEVAL_VALIDATOR_ISSUE_FIELDS.items())),
                    "dynamicFieldIssueCodes": dict(sorted(THREAT_RETRIEVAL_DYNAMIC_VALIDATOR_ISSUE_FIELD_POLICY.items())),
                },
                "suppressedCandidateResponseBudget": {
                    "location": "evidence.threatRetrieval.retrievalTrace",
                    "bounded": True,
                    "responseLimit": SUPPRESSED_CANDIDATE_RESPONSE_LIMIT,
                    "returnedCountField": "suppressedCandidateReturnedCount",
                    "truncatedField": "suppressedCandidateResponseTruncated",
                },
                "semanticExpansionResponseBudget": {
                    "location": "evidence.threatRetrieval.retrievalTrace",
                    "bounded": True,
                    "weaknessResponseLimit": SEMANTIC_EXPANSION_RESPONSE_LIMIT,
                    "attackResponseLimit": SEMANTIC_EXPANSION_RESPONSE_LIMIT,
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
            },
            "sourceCodeKgContextResolution": {
                "schemaVersion": "s5-source-kg-context-resolution-v1",
                "partialFallback": "partial_context_resolution",
                "partialDiagnostic": "SOURCE_KG_CONTEXT_PARTIAL",
                "silentPartialContextAllowed": False,
                "degradedStatus": "degraded_quality",
                "requiredInputOnDegradation": "complete_or_consistent_source_code_kg_context",
                "selectorPolicy": {
                    "maxGraphNodeIds": MAX_CONTEXT_GRAPH_NODE_IDS,
                    "maxEvidenceSnippetIds": MAX_CONTEXT_EVIDENCE_SNIPPET_IDS,
                    "maxRichIrArtifactIds": MAX_CONTEXT_RICH_IR_ARTIFACT_IDS,
                    "maxSelectorValueLength": MAX_CONTEXT_SELECTOR_ID_LENGTH,
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
                "issueAndDiagnosticCatalog": _judge_source_kg_issue_and_diagnostic_catalog(),
                "servingContextDiagnosticCatalog": _judge_source_kg_serving_context_diagnostic_catalog(),
                "validatorDiagnosticPayloadRedaction": {
                    "enabled": True,
                    "credentialBearingUrlLikeValues": True,
                    "recursiveForStructuredValues": True,
                    "maxStringEchoChars": MAX_CONTROL_VALUE_ECHO_CHARS,
                    "maxStructuredEchoItems": MAX_CONTROL_ECHO_TOTAL_ITEMS,
                    "maxStructuredEchoBytes": MAX_CONTROL_ECHO_BYTES,
                    "maxStructuredEchoDepth": MAX_FORCE_CONTEXT_DEPTH,
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
                    "maxInlineBytes": MAX_SOURCE_NESTED_OBJECT_INLINE_BYTES,
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
                    "maxProjectionDiagnostics": MAX_SOURCE_CONTEXT_PROJECTION_DIAGNOSTICS,
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
            },
            "decisionCachePolicy": {
                "schemaVersion": "s5-decision-cache-policy-v1",
                "publicKey": "decisionFragmentKey",
                "storageScope": "ledger",
                "scopeTraceField": "cacheTrace.cacheScopeHash",
                "revisionTraceField": "cacheTrace.cacheRevisionHash",
                "revisionHashMode": "compact_table_revision_summary",
                "revisionTables": list(DECISION_CACHE_REVISION_TABLES),
                "crossLedgerReuseAllowed": False,
                "staleLedgerRevisionReuseAllowed": False,
            },
            "relationConflictVisibility": {
                "schemaVersion": "s5-judge-conflict-summary-v1",
                "location": "uncertainty.conflicts",
                "qualityDiagnosticRequired": True,
                "consumerPolicy": CONFLICT_CONSUMER_POLICY,
                "negativeEvidenceAllowed": False,
                "conflictingValuesBounded": True,
                "maxConflictingValues": MAX_CONFLICTING_VALUES_IN_SUMMARY,
                "hardConflictGate": "rejected",
                "softConflictGate": "accepted_with_caveats",
                "issueCodeCatalog": _relation_conflict_issue_code_catalog(),
            },
            "runtimeVocabulary": list(JUDGE_RUNTIME_VOCABULARY),
            "runtimeVocabularyPolicy": _runtime_vocabulary_policy(),
            "qualityGatePolicy": _quality_gate_policy(),
            "answerStatusPolicy": _answer_status_policy(),
            "verdictPolicy": _verdict_policy(),
            "uncertaintyPolicy": _uncertainty_policy(),
            "answerFieldPolicy": _answer_field_policy(),
            "controlEffectsPolicy": _control_effects_policy(),
            "fallbackTracePolicy": _fallback_trace_policy(),
            "reasoningPathPolicy": _reasoning_path_policy(),
            "servingLedgerRequired": True,
            "sourceCodeKgResolutionMustBeExplicit": True,
            "offlineQualityVocabularyForbiddenInRuntime": True,
        },
        "forbiddenInferences": list(BASELINE_FORBIDDEN_INFERENCES),
        "forbiddenInferencePolicy": _forbidden_inference_policy(),
        "consumerBoundary": {
            "owner": "s5",
            "s3FinalClaimAuthority": False,
            "s5MayEmit": "evidence-grounded knowledge verdict over supplied component/source context",
            "s5MustNotEmit": [
                "final security verdict",
                "clean pass",
                "accepted S3 claim",
                "exploitability judgment",
                "complete project safety",
            ],
        },
    }
