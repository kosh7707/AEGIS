"""Machine-readable Analyst Brief contract snapshot."""

from __future__ import annotations

from app.analyst.brief import ACQUISITION_DIAGNOSTIC_CODE_ECHO_LIMIT
from app.analyst.brief import ACQUISITION_DIAGNOSTIC_CODE_MAX_CHARS
from app.analyst.brief import ACQUISITION_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import ACQUISITION_DIAGNOSTIC_CODE_REDACTION_WARNING
from app.analyst.brief import ACQUISITION_DIAGNOSTIC_CODE_TRUNCATION_WARNING
from app.analyst.brief import ACQUISITION_DIAGNOSTIC_WARNING_PREVIEW_LIMIT
from app.analyst.brief import ACQUISITION_DERIVED_EVIDENCE_REF_TRUNCATION_WARNING
from app.analyst.brief import ACQUISITION_EVIDENCE_REF_ECHO_LIMIT
from app.analyst.brief import ACQUISITION_EVIDENCE_REF_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import ACQUISITION_EVIDENCE_REF_VALUE_MAX_CHARS
from app.analyst.brief import ACQUISITION_EVIDENCE_REF_VALUE_REDACTION_WARNING
from app.analyst.brief import ACQUISITION_IDENTITY_ECHO_FIELDS
from app.analyst.brief import ACQUISITION_IDENTITY_MAX_CHARS
from app.analyst.brief import ACQUISITION_IDENTITY_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import ACQUISITION_IDENTITY_REDACTION_WARNING
from app.analyst.brief import ACQUISITION_METHOD_ECHO_FIELDS
from app.analyst.brief import ACQUISITION_METHOD_ECHO_LIMIT
from app.analyst.brief import ACQUISITION_METHOD_MAX_CHARS
from app.analyst.brief import ACQUISITION_METHOD_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import ACQUISITION_METHOD_REDACTION_WARNING
from app.analyst.brief import ACQUISITION_METHOD_TRUNCATION_WARNING
from app.analyst.brief import ACQUISITION_STATE_ECHO_FIELDS
from app.analyst.brief import ACQUISITION_STATE_MAX_CHARS
from app.analyst.brief import ACQUISITION_STATE_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import ACQUISITION_STATE_REDACTION_WARNING
from app.analyst.brief import ACQUISITION_REQUIRED_INPUT_ECHO_LIMIT
from app.analyst.brief import ACQUISITION_REQUIRED_INPUT_MAX_CHARS
from app.analyst.brief import ACQUISITION_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import ACQUISITION_REQUIRED_INPUT_REDACTION_WARNING
from app.analyst.brief import ACQUISITION_REQUIRED_INPUT_TRUNCATION_WARNING
from app.analyst.brief import ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_ECHO_LIMIT
from app.analyst.brief import ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_FIELD
from app.analyst.brief import ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_MAX_CHARS
from app.analyst.brief import ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_REDACTION_WARNING
from app.analyst.brief import ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_TRUNCATION_WARNING
from app.analyst.brief import ACQUISITION_SOURCE_EVIDENCE_REF_TRUNCATION_WARNING
from app.analyst.brief import BASELINE_FORBIDDEN_INFERENCES
from app.analyst.brief import JUDGE_ANSWER_BOUNDARY_WARNING
from app.analyst.brief import JUDGE_ANSWER_CONFLICT_PRESENCE_ONLY
from app.analyst.brief import JUDGE_ANSWER_CONFLICT_QUALITY_WARNING
from app.analyst.brief import JUDGE_ANSWER_CONFLICT_RAW_FIELDS_ECHOED
from app.analyst.brief import JUDGE_ANSWER_CONSUMER_POLICY
from app.analyst.brief import JUDGE_ANSWER_DIAGNOSTIC_TRIGGERS
from app.analyst.brief import JUDGE_ANSWER_DIAGNOSTIC_CODE_ECHO_LIMIT
from app.analyst.brief import JUDGE_ANSWER_DIAGNOSTIC_CODE_MAX_CHARS
from app.analyst.brief import JUDGE_ANSWER_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import JUDGE_ANSWER_DIAGNOSTIC_CODE_REDACTION_WARNING
from app.analyst.brief import JUDGE_ANSWER_DIAGNOSTIC_CODE_TRUNCATION_WARNING
from app.analyst.brief import JUDGE_ANSWER_DIAGNOSTIC_WARNING_PREVIEW_LIMIT
from app.analyst.brief import JUDGE_ANSWER_REQUIRED_VERDICT_AUTHORITY
from app.analyst.brief import JUDGE_ANSWER_FOLLOW_UP_ACTION_TYPE
from app.analyst.brief import JUDGE_ANSWER_FOLLOW_UP_PRESENCE_ONLY
from app.analyst.brief import JUDGE_ANSWER_FOLLOW_UP_QUALITY_WARNING
from app.analyst.brief import JUDGE_ANSWER_FOLLOW_UP_RAW_FIELDS_ECHOED
from app.analyst.brief import JUDGE_ANSWER_REQUIRED_INPUT_ECHO_LIMIT
from app.analyst.brief import JUDGE_ANSWER_REQUIRED_INPUT_MAX_CHARS
from app.analyst.brief import JUDGE_ANSWER_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import JUDGE_ANSWER_REQUIRED_INPUT_REDACTION_WARNING
from app.analyst.brief import JUDGE_ANSWER_REQUIRED_INPUT_TRUNCATION_WARNING
from app.analyst.brief import JUDGE_ANSWER_SCALAR_ECHO_FIELDS
from app.analyst.brief import JUDGE_ANSWER_SCALAR_MAX_CHARS
from app.analyst.brief import JUDGE_ANSWER_SCALAR_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import JUDGE_ANSWER_SCALAR_REDACTION_WARNING
from app.analyst.brief import JUDGE_ANSWER_SOURCE_REF_ECHO_LIMIT
from app.analyst.brief import JUDGE_ANSWER_SOURCE_REF_OVERSIZED_REDACTION_TEMPLATE
from app.analyst.brief import JUDGE_ANSWER_SOURCE_REF_TRUNCATION_WARNING
from app.analyst.brief import JUDGE_ANSWER_SOURCE_REF_VALUE_MAX_CHARS
from app.analyst.brief import JUDGE_ANSWER_SOURCE_REF_VALUE_REDACTION_WARNING
from app.analyst.brief import JUDGE_ANSWER_SOURCE_ARTIFACT_REF_FIELDS
from app.analyst.brief import SCHEMA_VERSION as ANALYST_BRIEF_SCHEMA_VERSION
from app.analyst.brief import SUPPORTED_AUDIENCES
from app.analyst.brief import SUPPORTED_LANGUAGES

CONTRACT_SCHEMA_VERSION = "s5-analyst-brief-contract-v1"


def analyst_brief_contract_snapshot() -> dict:
    """Return the S5 Analyst Brief contract.

    Analyst Brief is a deterministic consumer-guidance helper. It does not
    promote S5 acquisition or Judge packets into S3 final security authority.
    """

    return {
        "schemaVersion": CONTRACT_SCHEMA_VERSION,
        "endpoint": {"method": "POST", "path": "/v1/analyst-brief"},
        "answer": {"schemaVersion": ANALYST_BRIEF_SCHEMA_VERSION},
        "supportedAudiences": sorted(SUPPORTED_AUDIENCES),
        "supportedLanguages": sorted(SUPPORTED_LANGUAGES),
        "acceptedArtifactSchemaVersions": [
            "acquisition-envelope-v1",
            "s5-judge-answer-v1",
        ],
        "acquisitionArtifactPolicy": {
            "schemaVersion": "acquisition-envelope-v1",
            "diagnosticCodeEchoPolicy": {
                "maxCodeEchoChars": ACQUISITION_DIAGNOSTIC_CODE_MAX_CHARS,
                "maxCodeEchoCount": ACQUISITION_DIAGNOSTIC_CODE_ECHO_LIMIT,
                "warningPreviewCount": ACQUISITION_DIAGNOSTIC_WARNING_PREVIEW_LIMIT,
                "oversizedCodeRedaction": ACQUISITION_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": ACQUISITION_DIAGNOSTIC_CODE_REDACTION_WARNING,
                "truncationWarning": ACQUISITION_DIAGNOSTIC_CODE_TRUNCATION_WARNING,
                "countFields": {
                    "total": "evidencePlacement.diagnosticCodeTotalCount",
                    "returned": "evidencePlacement.diagnosticCodeReturnedCount",
                    "truncated": "evidencePlacement.diagnosticCodesTruncated",
                },
            },
            "missingInputEchoPolicy": {
                "maxInputEchoChars": ACQUISITION_REQUIRED_INPUT_MAX_CHARS,
                "maxInputEchoCount": ACQUISITION_REQUIRED_INPUT_ECHO_LIMIT,
                "oversizedInputRedaction": ACQUISITION_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": ACQUISITION_REQUIRED_INPUT_REDACTION_WARNING,
                "truncationWarning": ACQUISITION_REQUIRED_INPUT_TRUNCATION_WARNING,
                "countFields": {
                    "total": "evidencePlacement.requiredInputTotalCount",
                    "returned": "evidencePlacement.requiredInputReturnedCount",
                    "truncated": "evidencePlacement.requiredInputsTruncated",
                },
            },
            "evidenceRefEchoPolicy": {
                "maxRefEchoChars": ACQUISITION_EVIDENCE_REF_VALUE_MAX_CHARS,
                "maxRefsPerField": ACQUISITION_EVIDENCE_REF_ECHO_LIMIT,
                "oversizedRefRedaction": ACQUISITION_EVIDENCE_REF_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": ACQUISITION_EVIDENCE_REF_VALUE_REDACTION_WARNING,
                "sourceTruncationWarning": ACQUISITION_SOURCE_EVIDENCE_REF_TRUNCATION_WARNING,
                "derivedTruncationWarning": ACQUISITION_DERIVED_EVIDENCE_REF_TRUNCATION_WARNING,
                "countFields": {
                    "sourceTotal": "evidencePlacement.sourceEvidenceRefTotalCount",
                    "sourceReturned": "evidencePlacement.sourceEvidenceRefReturnedCount",
                    "sourceTruncated": "evidencePlacement.sourceEvidenceRefsTruncated",
                    "derivedTotal": "evidencePlacement.derivedFromEvidenceRefTotalCount",
                    "derivedReturned": "evidencePlacement.derivedFromEvidenceRefReturnedCount",
                    "derivedTruncated": "evidencePlacement.derivedFromEvidenceRefsTruncated",
                },
            },
            "identityEchoPolicy": {
                "maxIdentityEchoChars": ACQUISITION_IDENTITY_MAX_CHARS,
                "oversizedIdentityRedaction": ACQUISITION_IDENTITY_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": ACQUISITION_IDENTITY_REDACTION_WARNING,
                "fields": list(ACQUISITION_IDENTITY_ECHO_FIELDS),
            },
            "stateEchoPolicy": {
                "maxStateEchoChars": ACQUISITION_STATE_MAX_CHARS,
                "oversizedStateRedaction": ACQUISITION_STATE_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": ACQUISITION_STATE_REDACTION_WARNING,
                "fields": list(ACQUISITION_STATE_ECHO_FIELDS),
            },
            "methodEchoPolicy": {
                "maxMethodEchoChars": ACQUISITION_METHOD_MAX_CHARS,
                "maxMethodEchoCount": ACQUISITION_METHOD_ECHO_LIMIT,
                "oversizedMethodRedaction": ACQUISITION_METHOD_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": ACQUISITION_METHOD_REDACTION_WARNING,
                "truncationWarning": ACQUISITION_METHOD_TRUNCATION_WARNING,
                "fields": list(ACQUISITION_METHOD_ECHO_FIELDS),
            },
            "scopeForbiddenInferenceEchoPolicy": {
                "maxInferenceEchoChars": ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_MAX_CHARS,
                "maxInferenceEchoCount": ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_ECHO_LIMIT,
                "oversizedInferenceRedaction": (
                    ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_OVERSIZED_REDACTION_TEMPLATE.format(
                        length="original_length"
                    )
                ),
                "valueRedactionWarning": (
                    ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_REDACTION_WARNING
                ),
                "truncationWarning": (
                    ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_TRUNCATION_WARNING
                ),
                "field": ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_FIELD,
            },
        },
        "judgeAnswerArtifactPolicy": {
            "schemaVersion": "s5-judge-answer-v1",
            "consumerPolicy": JUDGE_ANSWER_CONSUMER_POLICY,
            "requiredBoundary": {
                "notFinalSecurityVerdict": True,
                "verdictAuthority": JUDGE_ANSWER_REQUIRED_VERDICT_AUTHORITY,
            },
            "boundaryFailure": {
                "stance": "blocked",
                "recommendedRole": "do_not_use",
                "actionType": "send_valid_judge_answer",
                "qualityWarning": JUDGE_ANSWER_BOUNDARY_WARNING,
            },
            "verdictMapping": {
                "affected": {
                    "stance": "contextual",
                    "forbiddenInferences": [
                        "treat_judge_verdict_as_s3_final_verdict",
                        "accepted_claim",
                    ],
                },
                "not_affected": {
                    "stance": "contextual",
                    "forbiddenInferences": [
                        "s5_clean_pass",
                        "target_safe",
                        "complete_project_safety",
                    ],
                },
                "unknown": {
                    "stance": "diagnostic",
                    "forbiddenInferences": [
                        "absence_of_vulnerability",
                        "negative_absence_claim",
                    ],
                },
            },
            "diagnosticTriggers": list(JUDGE_ANSWER_DIAGNOSTIC_TRIGGERS),
            "scalarEchoPolicy": {
                "maxScalarEchoChars": JUDGE_ANSWER_SCALAR_MAX_CHARS,
                "oversizedScalarRedaction": JUDGE_ANSWER_SCALAR_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": JUDGE_ANSWER_SCALAR_REDACTION_WARNING,
                "fields": list(JUDGE_ANSWER_SCALAR_ECHO_FIELDS),
            },
            "sourceRefExtraction": {
                "sourceArtifacts": list(JUDGE_ANSWER_SOURCE_ARTIFACT_REF_FIELDS),
                "graphNodes": ["sourceGraphNodeId", "graphNodeId", "stableId"],
                "evidenceSnippets": ["evidenceSnippetId", "snippetId"],
                "maxEchoRefs": JUDGE_ANSWER_SOURCE_REF_ECHO_LIMIT,
                "maxRefEchoChars": JUDGE_ANSWER_SOURCE_REF_VALUE_MAX_CHARS,
                "oversizedRefRedaction": JUDGE_ANSWER_SOURCE_REF_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "truncationWarning": JUDGE_ANSWER_SOURCE_REF_TRUNCATION_WARNING,
                "valueRedactionWarning": JUDGE_ANSWER_SOURCE_REF_VALUE_REDACTION_WARNING,
                "countFields": {
                    "total": "evidencePlacement.sourceEvidenceRefTotalCount",
                    "returned": "evidencePlacement.sourceEvidenceRefReturnedCount",
                    "truncated": "evidencePlacement.sourceEvidenceRefsTruncated",
                },
                "actionType": "validate_source_evidence_refs",
            },
            "diagnosticCodeEchoPolicy": {
                "maxCodeEchoChars": JUDGE_ANSWER_DIAGNOSTIC_CODE_MAX_CHARS,
                "maxCodeEchoCount": JUDGE_ANSWER_DIAGNOSTIC_CODE_ECHO_LIMIT,
                "warningPreviewCount": JUDGE_ANSWER_DIAGNOSTIC_WARNING_PREVIEW_LIMIT,
                "oversizedCodeRedaction": JUDGE_ANSWER_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": JUDGE_ANSWER_DIAGNOSTIC_CODE_REDACTION_WARNING,
                "truncationWarning": JUDGE_ANSWER_DIAGNOSTIC_CODE_TRUNCATION_WARNING,
                "countFields": {
                    "total": "evidencePlacement.diagnosticCodeTotalCount",
                    "returned": "evidencePlacement.diagnosticCodeReturnedCount",
                    "truncated": "evidencePlacement.diagnosticCodesTruncated",
                },
            },
            "requiredInputEchoPolicy": {
                "maxInputEchoChars": JUDGE_ANSWER_REQUIRED_INPUT_MAX_CHARS,
                "maxInputEchoCount": JUDGE_ANSWER_REQUIRED_INPUT_ECHO_LIMIT,
                "oversizedInputRedaction": JUDGE_ANSWER_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE.format(
                    length="original_length"
                ),
                "valueRedactionWarning": JUDGE_ANSWER_REQUIRED_INPUT_REDACTION_WARNING,
                "truncationWarning": JUDGE_ANSWER_REQUIRED_INPUT_TRUNCATION_WARNING,
                "countFields": {
                    "total": "evidencePlacement.requiredInputTotalCount",
                    "returned": "evidencePlacement.requiredInputReturnedCount",
                    "truncated": "evidencePlacement.requiredInputsTruncated",
                },
            },
            "followUpEchoPolicy": {
                "rawFieldsEchoed": JUDGE_ANSWER_FOLLOW_UP_RAW_FIELDS_ECHOED,
                "presenceOnly": JUDGE_ANSWER_FOLLOW_UP_PRESENCE_ONLY,
                "actionType": JUDGE_ANSWER_FOLLOW_UP_ACTION_TYPE,
                "qualityWarning": JUDGE_ANSWER_FOLLOW_UP_QUALITY_WARNING,
            },
            "conflictEchoPolicy": {
                "rawFieldsEchoed": JUDGE_ANSWER_CONFLICT_RAW_FIELDS_ECHOED,
                "presenceOnly": JUDGE_ANSWER_CONFLICT_PRESENCE_ONLY,
                "qualityWarning": JUDGE_ANSWER_CONFLICT_QUALITY_WARNING,
            },
            "baselineForbiddenInferences": list(BASELINE_FORBIDDEN_INFERENCES),
            "negativeEvidenceAllowed": False,
            "s3FinalAuthorityBoundary": True,
        },
    }
