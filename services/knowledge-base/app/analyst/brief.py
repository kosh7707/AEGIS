"""Deterministic S5 analyst brief builder.

This module intentionally does not call LLMs, providers, Neo4j, or Qdrant.
It translates an acquisition artifact into a S3-consumable explanation while
preserving the S5/S3 authority boundary: S5 may explain acquisition usability,
but S5 must not emit final vulnerability/security verdicts.
"""

from __future__ import annotations

from typing import Any

SCHEMA_VERSION = "s5-analyst-brief-v1"
SUPPORTED_AUDIENCES = {"s3"}
SUPPORTED_LANGUAGES = {"ko", "en"}
ACQUISITION_DIAGNOSTIC_CODE_MAX_CHARS = 128
ACQUISITION_DIAGNOSTIC_CODE_ECHO_LIMIT = 64
ACQUISITION_DIAGNOSTIC_WARNING_PREVIEW_LIMIT = 8
ACQUISITION_DIAGNOSTIC_CODE_REDACTION_WARNING = "acquisition_diagnostic_code_value_redacted"
ACQUISITION_DIAGNOSTIC_CODE_TRUNCATION_WARNING = "acquisition_diagnostic_codes_truncated"
ACQUISITION_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE = (
    "<redacted-acquisition-diagnostic-code:{length}>"
)
ACQUISITION_REQUIRED_INPUT_MAX_CHARS = 128
ACQUISITION_REQUIRED_INPUT_ECHO_LIMIT = 16
ACQUISITION_REQUIRED_INPUT_REDACTION_WARNING = "acquisition_required_input_value_redacted"
ACQUISITION_REQUIRED_INPUT_TRUNCATION_WARNING = "acquisition_required_inputs_truncated"
ACQUISITION_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE = (
    "<redacted-acquisition-required-input:{length}>"
)
ACQUISITION_EVIDENCE_REF_VALUE_MAX_CHARS = 512
ACQUISITION_EVIDENCE_REF_ECHO_LIMIT = 64
ACQUISITION_EVIDENCE_REF_VALUE_REDACTION_WARNING = "acquisition_evidence_ref_value_redacted"
ACQUISITION_SOURCE_EVIDENCE_REF_TRUNCATION_WARNING = "acquisition_source_evidence_refs_truncated"
ACQUISITION_DERIVED_EVIDENCE_REF_TRUNCATION_WARNING = "acquisition_derived_evidence_refs_truncated"
ACQUISITION_EVIDENCE_REF_OVERSIZED_REDACTION_TEMPLATE = (
    "<redacted-acquisition-evidence-ref:{length}>"
)
ACQUISITION_IDENTITY_MAX_CHARS = 128
ACQUISITION_IDENTITY_REDACTION_WARNING = "acquisition_identity_value_redacted"
ACQUISITION_IDENTITY_OVERSIZED_REDACTION_TEMPLATE = "<redacted-acquisition-identity:{length}>"
ACQUISITION_IDENTITY_ECHO_FIELDS = (
    "surface",
    "targetKnowledgeId",
    "acquisitionStatus",
    "acquisitionQualityGate",
    "consumerPolicy",
)
ACQUISITION_STATE_MAX_CHARS = 128
ACQUISITION_STATE_REDACTION_WARNING = "acquisition_state_value_redacted"
ACQUISITION_STATE_OVERSIZED_REDACTION_TEMPLATE = "<redacted-acquisition-state:{length}>"
ACQUISITION_STATE_ECHO_FIELDS = (
    "providerState.state",
    "projectionState.state",
)
ACQUISITION_METHOD_MAX_CHARS = 128
ACQUISITION_METHOD_ECHO_LIMIT = 32
ACQUISITION_METHOD_REDACTION_WARNING = "acquisition_method_value_redacted"
ACQUISITION_METHOD_TRUNCATION_WARNING = "acquisition_methods_truncated"
ACQUISITION_METHOD_OVERSIZED_REDACTION_TEMPLATE = "<redacted-acquisition-method:{length}>"
ACQUISITION_METHOD_ECHO_FIELDS = (
    "methodsSucceeded",
    "methodsRequiredForNoHit",
)
ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_MAX_CHARS = 128
ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_ECHO_LIMIT = 32
ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_REDACTION_WARNING = (
    "acquisition_scope_forbidden_inference_value_redacted"
)
ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_TRUNCATION_WARNING = (
    "acquisition_scope_forbidden_inferences_truncated"
)
ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_OVERSIZED_REDACTION_TEMPLATE = (
    "<redacted-acquisition-scope-forbidden-inference:{length}>"
)
ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_FIELD = "scope.forbiddenInferences"
JUDGE_ANSWER_CONSUMER_POLICY = "judge_verdict_context_only"
JUDGE_ANSWER_REQUIRED_VERDICT_AUTHORITY = "s5_evidence_grounded_knowledge_verdict_not_s3_final_security_verdict"
JUDGE_ANSWER_BOUNDARY_WARNING = "judge_final_verdict_boundary_missing"
JUDGE_ANSWER_SOURCE_ARTIFACT_REF_FIELDS = (
    "sourceRepositoryArtifactId",
    "sourceArtifactId",
    "artifactId",
)
JUDGE_ANSWER_SOURCE_REF_ECHO_LIMIT = 64
JUDGE_ANSWER_SOURCE_REF_VALUE_MAX_CHARS = 512
JUDGE_ANSWER_SOURCE_REF_TRUNCATION_WARNING = "source_evidence_refs_truncated"
JUDGE_ANSWER_SOURCE_REF_VALUE_REDACTION_WARNING = "source_evidence_ref_value_redacted"
JUDGE_ANSWER_SOURCE_REF_OVERSIZED_REDACTION_TEMPLATE = "<redacted-source-ref:{length}>"
JUDGE_ANSWER_DIAGNOSTIC_CODE_MAX_CHARS = 128
JUDGE_ANSWER_DIAGNOSTIC_CODE_ECHO_LIMIT = 64
JUDGE_ANSWER_DIAGNOSTIC_WARNING_PREVIEW_LIMIT = 8
JUDGE_ANSWER_DIAGNOSTIC_CODE_REDACTION_WARNING = "diagnostic_code_value_redacted"
JUDGE_ANSWER_DIAGNOSTIC_CODE_TRUNCATION_WARNING = "diagnostic_codes_truncated"
JUDGE_ANSWER_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE = "<redacted-diagnostic-code:{length}>"
JUDGE_ANSWER_REQUIRED_INPUT_MAX_CHARS = 128
JUDGE_ANSWER_REQUIRED_INPUT_ECHO_LIMIT = 16
JUDGE_ANSWER_REQUIRED_INPUT_REDACTION_WARNING = "required_input_value_redacted"
JUDGE_ANSWER_REQUIRED_INPUT_TRUNCATION_WARNING = "required_inputs_truncated"
JUDGE_ANSWER_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE = "<redacted-required-input:{length}>"
JUDGE_ANSWER_SCALAR_MAX_CHARS = 128
JUDGE_ANSWER_SCALAR_REDACTION_WARNING = "judge_answer_scalar_value_redacted"
JUDGE_ANSWER_SCALAR_OVERSIZED_REDACTION_TEMPLATE = "<redacted-judge-answer-scalar:{length}>"
JUDGE_ANSWER_SCALAR_ECHO_FIELDS = (
    "verdict",
    "status",
    "qualityGate.gate",
)
JUDGE_ANSWER_ALLOWED_STATUSES = (
    "complete",
    "degraded_quality",
    "requires_requery",
    "insufficient_input",
    "unknown",
)
JUDGE_ANSWER_ALLOWED_QUALITY_GATES = (
    "accepted",
    "accepted_with_caveats",
    "rejected",
    "unknown",
)
JUDGE_ANSWER_FOLLOW_UP_RAW_FIELDS_ECHOED = False
JUDGE_ANSWER_FOLLOW_UP_PRESENCE_ONLY = True
JUDGE_ANSWER_FOLLOW_UP_ACTION_TYPE = "follow_judge_affordance"
JUDGE_ANSWER_FOLLOW_UP_QUALITY_WARNING = (
    "Judge follow-up affordances are present and should be routed before promotion."
)
JUDGE_ANSWER_CONFLICT_RAW_FIELDS_ECHOED = False
JUDGE_ANSWER_CONFLICT_PRESENCE_ONLY = True
JUDGE_ANSWER_CONFLICT_QUALITY_WARNING = (
    "Judge uncertainty conflicts are present; do not collapse them into a single claim."
)
JUDGE_ANSWER_DIAGNOSTIC_TRIGGERS = (
    "verdict_unknown",
    "verdict_unsupported",
    "status_unknown",
    "status_unsupported",
    "status_requires_requery",
    "status_degraded_quality",
    "quality_gate_rejected",
    "quality_gate_accepted_with_caveats",
    "quality_gate_unsupported",
    "uncertainty_required_inputs_present",
    "uncertainty_conflicts_present",
    "follow_up_affordances_present",
)

BASELINE_FORBIDDEN_INFERENCES = [
    "s5_final_security_verdict",
    "s5_clean_pass",
    "s5_accepted_claim",
    "s5_exploitability_judgment",
    "complete_project_safety",
]

DIAGNOSTIC_STATUSES = {
    "incomplete_acquisition",
    "stale_cache_only",
    "conflicting_evidence",
    "timeout",
    "not_ready",
    "error",
}
PROVIDER_PROBLEM_STATES = {
    "timeout",
    "error",
    "failed",
    "unavailable",
    "not_ready",
    "stale",
    "stale_cache_only",
}
PROJECTION_PROBLEM_STATES = {
    "timeout",
    "error",
    "failed",
    "unavailable",
    "not_ready",
    "stale",
    "debt",
    "projection_debt",
    "partial",
}
UNSAFE_NO_HIT_BASIS = {
    "keyword_only",
    "embedding_only",
    "global_embedding_only",
    "keyword_only_no_result",
    "embedding_only_no_result",
    "global_embedding_no_result",
    "unknown",
    "",
}


def build_analyst_brief(
    artifact: dict[str, Any] | None,
    *,
    audience: str = "s3",
    language: str = "ko",
) -> dict[str, Any]:
    """Build a deterministic S3-facing analyst brief from an acquisition artifact."""

    if audience not in SUPPORTED_AUDIENCES:
        raise ValueError(f"unsupported audience: {audience}")
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"unsupported language: {language}")

    if not isinstance(artifact, dict) or not artifact:
        return _malformed_brief(audience=audience, language=language)

    if artifact.get("schemaVersion") == "s5-judge-answer-v1":
        return _judge_answer_brief(artifact, audience=audience, language=language)

    view = _ArtifactView(artifact)
    stance = _classify_stance(view)
    role = _recommended_role(stance, view.consumer_policy)
    raw_diagnostic_codes = _diagnostic_code_values(artifact)
    diagnostic_codes = [
        _sanitize_acquisition_diagnostic_code(value)
        for value in raw_diagnostic_codes[:ACQUISITION_DIAGNOSTIC_CODE_ECHO_LIMIT]
    ]
    diagnostic_code_total_count = len(raw_diagnostic_codes)
    diagnostic_codes_truncated = diagnostic_code_total_count > ACQUISITION_DIAGNOSTIC_CODE_ECHO_LIMIT
    diagnostic_code_redacted = any(
        code.startswith("<redacted-acquisition-diagnostic-code:")
        for code in diagnostic_codes
    )
    raw_missing_inputs = _missing_input_values(artifact)
    missing_inputs = [
        _sanitize_acquisition_required_input(value)
        for value in raw_missing_inputs[:ACQUISITION_REQUIRED_INPUT_ECHO_LIMIT]
    ]
    missing_input_total_count = len(raw_missing_inputs)
    missing_inputs_truncated = missing_input_total_count > ACQUISITION_REQUIRED_INPUT_ECHO_LIMIT
    missing_input_redacted = any(
        value.startswith("<redacted-acquisition-required-input:")
        for value in missing_inputs
    )
    source_refs = _unique(_string_list(artifact.get("sourceEvidenceRefs")))
    derived_refs = _unique(_string_list(artifact.get("derivedFromEvidenceRefs")))
    echoed_source_refs = [
        _sanitize_acquisition_evidence_ref(value)
        for value in source_refs[:ACQUISITION_EVIDENCE_REF_ECHO_LIMIT]
    ]
    echoed_derived_refs = [
        _sanitize_acquisition_evidence_ref(value)
        for value in derived_refs[:ACQUISITION_EVIDENCE_REF_ECHO_LIMIT]
    ]
    source_refs_truncated = len(source_refs) > ACQUISITION_EVIDENCE_REF_ECHO_LIMIT
    derived_refs_truncated = len(derived_refs) > ACQUISITION_EVIDENCE_REF_ECHO_LIMIT
    evidence_ref_redacted = any(
        len(value) > ACQUISITION_EVIDENCE_REF_VALUE_MAX_CHARS
        for value in source_refs[:ACQUISITION_EVIDENCE_REF_ECHO_LIMIT] + derived_refs[:ACQUISITION_EVIDENCE_REF_ECHO_LIMIT]
    )
    identity_redacted = view.identity_redacted or _acquisition_identity_redacted(artifact.get("targetKnowledgeId"))
    quality_warnings = _quality_warnings(
        view,
        diagnostic_codes,
        missing_inputs,
        diagnostic_code_redacted=diagnostic_code_redacted,
        diagnostic_codes_truncated=diagnostic_codes_truncated,
        missing_input_redacted=missing_input_redacted,
        missing_inputs_truncated=missing_inputs_truncated,
        evidence_ref_redacted=evidence_ref_redacted,
        source_refs_truncated=source_refs_truncated,
        derived_refs_truncated=derived_refs_truncated,
        identity_redacted=identity_redacted,
        state_redacted=view.state_redacted,
        method_redacted=view.method_redacted,
        methods_truncated=view.methods_truncated,
        scope_forbidden_inference_redacted=view.scope_forbidden_inference_redacted,
        scope_forbidden_inferences_truncated=view.scope_forbidden_inferences_truncated,
    )

    forbidden = _unique(BASELINE_FORBIDDEN_INFERENCES + _stance_forbidden_inferences(stance, view))
    allowed = _allowed_uses(stance, view)
    next_actions = _next_actions(stance, view, missing_inputs, diagnostic_codes)
    human_questions = _human_questions(stance, view, missing_inputs)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "audience": audience,
        "language": language,
        "stance": stance,
        "headline": _headline(stance, language),
        "plainLanguageSummary": _summary(stance, view, language),
        "readinessNarrative": _readiness_narrative(view),
        "whatS5Knows": _what_s5_knows(view),
        "whatS5DoesNotKnow": _what_s5_does_not_know(view, missing_inputs),
        "whyThisMattersForS3": _why_this_matters_for_s3(stance, view),
        "allowedUses": allowed,
        "forbiddenInferences": forbidden,
        "nextActions": next_actions,
        "qualityWarnings": quality_warnings,
        "humanQuestions": human_questions,
        "evidencePlacement": {
            "recommendedRole": role,
            "consumerPolicy": view.consumer_policy,
            "acquisitionStatus": view.status,
            "acquisitionQualityGate": view.quality_gate,
            "sourceEvidenceRefs": echoed_source_refs,
            "sourceEvidenceRefTotalCount": len(source_refs),
            "sourceEvidenceRefReturnedCount": len(echoed_source_refs),
            "sourceEvidenceRefsTruncated": source_refs_truncated,
            "derivedFromEvidenceRefs": echoed_derived_refs,
            "derivedFromEvidenceRefTotalCount": len(derived_refs),
            "derivedFromEvidenceRefReturnedCount": len(echoed_derived_refs),
            "derivedFromEvidenceRefsTruncated": derived_refs_truncated,
            "diagnosticCodes": diagnostic_codes,
            "diagnosticCodeTotalCount": diagnostic_code_total_count,
            "diagnosticCodeReturnedCount": len(diagnostic_codes),
            "diagnosticCodesTruncated": diagnostic_codes_truncated,
            "requiredInputTotalCount": missing_input_total_count,
            "requiredInputReturnedCount": len(missing_inputs),
            "requiredInputsTruncated": missing_inputs_truncated,
        },
        "contractRefs": [
            "acquisition-envelope-v1",
            "knowledge-coverage-v1",
            "acquisition-readiness-v1",
        ],
    }


class _ArtifactView:
    def __init__(self, artifact: dict[str, Any]) -> None:
        self.artifact = artifact
        self.schema_version = str(artifact.get("schemaVersion") or "")
        raw_surface = str(artifact.get("surface") or "unknown")
        raw_status = str(artifact.get("acquisitionStatus") or "unknown")
        raw_quality_gate = str(artifact.get("acquisitionQualityGate") or "unknown")
        raw_consumer_policy = str(artifact.get("consumerPolicy") or "unknown")
        self.identity_redacted = any(
            _acquisition_identity_redacted(value)
            for value in (raw_surface, raw_status, raw_quality_gate, raw_consumer_policy)
        )
        self.surface = _sanitize_acquisition_identity(raw_surface)
        self.status = _sanitize_acquisition_identity(raw_status)
        self.quality_gate = _sanitize_acquisition_identity(raw_quality_gate)
        self.consumer_policy = _sanitize_acquisition_identity(raw_consumer_policy)
        self.scope = _as_dict(artifact.get("scope"))
        self.readiness = _as_dict(artifact.get("readiness"))
        self.results = _as_dict(artifact.get("results"))
        raw_provider_state = _state_name(
            artifact.get("providerState")
            or self.readiness.get("providerState")
            or self.scope.get("providerState")
        )
        raw_projection_state = _state_name(
            artifact.get("projectionState")
            or self.readiness.get("projectionState")
            or self.scope.get("projectionState")
        )
        self.state_redacted = any(
            _acquisition_state_redacted(value)
            for value in (raw_provider_state, raw_projection_state)
        )
        self.provider_state = _sanitize_acquisition_state(raw_provider_state)
        self.projection_state = _sanitize_acquisition_state(raw_projection_state)
        raw_methods_attempted = _string_list(
            artifact.get("methodsAttempted")
            or self.readiness.get("methodsAttempted")
            or self.scope.get("methodsAttempted")
        )
        raw_methods_required = _string_list(
            self.readiness.get("methodsRequiredForNoHit")
            or self.scope.get("methodsRequiredForNoHit")
        )
        raw_methods_succeeded = _string_list(
            artifact.get("methodsSucceeded")
            or self.readiness.get("methodsSucceeded")
        )
        self.raw_methods_attempted = raw_methods_attempted
        self.raw_methods_required = raw_methods_required
        self.raw_methods_succeeded = raw_methods_succeeded
        raw_scope_forbidden_inferences = _string_list(
            self.scope.get("forbiddenInferences")
        )
        self.scope_forbidden_inferences = [
            _sanitize_acquisition_scope_forbidden_inference(value)
            for value in raw_scope_forbidden_inferences[
                :ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_ECHO_LIMIT
            ]
        ]
        self.scope_forbidden_inference_redacted = any(
            _acquisition_scope_forbidden_inference_redacted(value)
            for value in raw_scope_forbidden_inferences[
                :ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_ECHO_LIMIT
            ]
        )
        self.scope_forbidden_inferences_truncated = (
            len(raw_scope_forbidden_inferences)
            > ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_ECHO_LIMIT
        )
        self.methods_required = [
            _sanitize_acquisition_method(value)
            for value in raw_methods_required[:ACQUISITION_METHOD_ECHO_LIMIT]
        ]
        self.methods_succeeded = [
            _sanitize_acquisition_method(value)
            for value in raw_methods_succeeded[:ACQUISITION_METHOD_ECHO_LIMIT]
        ]
        echoed_method_values = (
            raw_methods_required[:ACQUISITION_METHOD_ECHO_LIMIT]
            + raw_methods_succeeded[:ACQUISITION_METHOD_ECHO_LIMIT]
        )
        self.method_redacted = any(
            _acquisition_method_redacted(value)
            for value in echoed_method_values
        )
        self.methods_truncated = (
            len(raw_methods_required) > ACQUISITION_METHOD_ECHO_LIMIT
            or len(raw_methods_succeeded) > ACQUISITION_METHOD_ECHO_LIMIT
        )
        self.no_hit_basis = str(self.scope.get("noHitBasis") or "")
        self.item_acquisitions = _as_list(artifact.get("itemAcquisitions"))
        self.fallback_trace = _as_list(artifact.get("fallbackTrace"))

    @property
    def provider_problem(self) -> bool:
        return self.provider_state in PROVIDER_PROBLEM_STATES

    @property
    def projection_problem(self) -> bool:
        return self.projection_state in PROJECTION_PROBLEM_STATES

    @property
    def malformed(self) -> bool:
        return (
            self.schema_version != "acquisition-envelope-v1"
            or self.status == "unknown"
            or self.consumer_policy == "unknown"
        )


def _malformed_brief(*, audience: str, language: str) -> dict[str, Any]:
    artifact = {
        "schemaVersion": "unknown",
        "surface": "unknown",
        "acquisitionStatus": "input_insufficient",
        "acquisitionQualityGate": "rejected",
        "consumerPolicy": "do_not_use",
        "diagnostics": [
            {
                "code": "ANALYST_BRIEF_ARTIFACT_REQUIRED",
                "message": "artifact must be a non-empty acquisition object",
            },
        ],
        "readiness": {"missingInputs": ["artifact"]},
    }
    return build_analyst_brief(artifact, audience=audience, language=language)


def _judge_answer_brief(
    answer: dict[str, Any],
    *,
    audience: str,
    language: str,
) -> dict[str, Any]:
    """Build a S3-safe brief for a Judge answer packet.

    Judge answers are S5 evidence-grounded knowledge verdicts, not S3 final
    vulnerability/security decisions. This branch preserves the Analyst Brief
    shape while making the Judge authority boundary explicit.
    """

    raw_verdict = str(answer.get("verdict") or "unknown")
    raw_status = str(answer.get("status") or "unknown")
    raw_quality_gate = str(_as_dict(answer.get("qualityGate")).get("gate") or "unknown")
    scalar_redacted = any(
        _judge_answer_scalar_redacted(value)
        for value in (raw_verdict, raw_status, raw_quality_gate)
    )
    verdict = _sanitize_judge_answer_scalar(raw_verdict)
    status = _sanitize_judge_answer_scalar(raw_status)
    quality_gate = _sanitize_judge_answer_scalar(raw_quality_gate)
    uncertainty = _as_dict(answer.get("uncertainty"))
    raw_required_inputs = _unique(_string_list(uncertainty.get("requiredInputs")))
    required_inputs = [
        _sanitize_required_input(value)
        for value in raw_required_inputs[:JUDGE_ANSWER_REQUIRED_INPUT_ECHO_LIMIT]
    ]
    required_input_total_count = len(raw_required_inputs)
    required_inputs_truncated = required_input_total_count > JUDGE_ANSWER_REQUIRED_INPUT_ECHO_LIMIT
    required_input_redacted = any(
        value.startswith("<redacted-required-input:")
        for value in required_inputs
    )
    conflicts = _as_list(uncertainty.get("conflicts"))
    followups = _as_list(answer.get("followUpAffordances"))
    raw_diagnostic_codes = _judge_answer_diagnostic_code_values(answer)
    diagnostic_codes = [
        _sanitize_diagnostic_code(value)
        for value in raw_diagnostic_codes[:JUDGE_ANSWER_DIAGNOSTIC_CODE_ECHO_LIMIT]
    ]
    diagnostic_code_total_count = len(raw_diagnostic_codes)
    diagnostic_codes_truncated = diagnostic_code_total_count > JUDGE_ANSWER_DIAGNOSTIC_CODE_ECHO_LIMIT
    diagnostic_code_redacted = any(
        code.startswith("<redacted-diagnostic-code:")
        for code in diagnostic_codes
    )
    boundary_ok = (
        answer.get("notFinalSecurityVerdict") is True
        and str(answer.get("verdictAuthority") or "") == JUDGE_ANSWER_REQUIRED_VERDICT_AUTHORITY
    )
    source_refs = _judge_answer_source_refs(answer)
    source_refs_value_redacted = any(
        len(ref) > JUDGE_ANSWER_SOURCE_REF_VALUE_MAX_CHARS
        for ref in source_refs
    )
    source_refs_truncated = len(source_refs) > JUDGE_ANSWER_SOURCE_REF_ECHO_LIMIT
    echoed_source_refs = [
        _sanitize_source_ref(ref)
        for ref in source_refs[:JUDGE_ANSWER_SOURCE_REF_ECHO_LIMIT]
    ]
    has_source_refs = bool(source_refs)

    supported_verdict = verdict in {"affected", "not_affected", "unknown"}
    supported_status = status in JUDGE_ANSWER_ALLOWED_STATUSES
    supported_quality_gate = quality_gate in JUDGE_ANSWER_ALLOWED_QUALITY_GATES

    if not boundary_ok:
        stance = "blocked"
    elif status == "insufficient_input":
        stance = "blocked"
    elif (
        verdict == "unknown"
        or not supported_verdict
        or not supported_status
        or status in {"unknown", "requires_requery", "degraded_quality"}
        or not supported_quality_gate
        or quality_gate in {"rejected", "accepted_with_caveats"}
        or required_inputs
        or conflicts
        or followups
    ):
        stance = "diagnostic"
    else:
        stance = "contextual"

    role = "knowledge_context" if stance == "contextual" else "operational_diagnostic"
    if stance == "blocked":
        role = "do_not_use"

    forbidden = _unique(
        BASELINE_FORBIDDEN_INFERENCES
        + [
            "claim_support_without_s3_validation",
            "treat_judge_verdict_as_s3_final_verdict",
            "accepted_claim",
            "derived_local_support",
        ]
        + (["absence_of_vulnerability", "negative_absence_claim"] if verdict == "unknown" else [])
        + (
            ["target_safe", "library_safe", "clean_pass"]
            if verdict == "not_affected" and supported_status and supported_quality_gate
            else []
        )
    )
    allowed = ["use_as_knowledge_context", "use_for_follow_up_planning"]
    if stance == "diagnostic":
        allowed = ["use_for_retry_planning", "use_as_operational_diagnostic"]
    elif stance == "blocked":
        allowed = ["use_to_fix_input_contract", "do_not_attach_to_evidence_catalog"]

    next_actions = _judge_answer_next_actions(
        stance=stance,
        required_inputs=required_inputs,
        followups=followups,
        has_source_refs=has_source_refs,
        boundary_ok=boundary_ok,
    )
    quality_warnings = _judge_answer_quality_warnings(
        verdict=verdict,
        status=status,
        quality_gate=quality_gate,
        required_inputs=required_inputs,
        conflicts=conflicts,
        followups=followups,
        diagnostic_codes=diagnostic_codes,
        diagnostic_code_redacted=diagnostic_code_redacted,
        diagnostic_codes_truncated=diagnostic_codes_truncated,
        required_input_redacted=required_input_redacted,
        required_inputs_truncated=required_inputs_truncated,
        boundary_ok=boundary_ok,
        source_refs_truncated=source_refs_truncated,
        source_refs_value_redacted=source_refs_value_redacted,
        scalar_redacted=scalar_redacted,
        supported_status=supported_status,
        supported_quality_gate=supported_quality_gate,
    )

    return {
        "schemaVersion": SCHEMA_VERSION,
        "audience": audience,
        "language": language,
        "stance": stance,
        "headline": _headline(stance, language),
        "plainLanguageSummary": _judge_answer_summary(verdict, status, quality_gate, stance, language),
        "readinessNarrative": (
            f"judgeStatus={status}; judgeVerdict={verdict}; qualityGate={quality_gate}; "
            f"consumerPolicy={JUDGE_ANSWER_CONSUMER_POLICY}"
        ),
        "whatS5Knows": [
            f"S5 Judge returned verdict `{verdict}` with status `{status}`.",
            f"Judge quality gate is `{quality_gate}`.",
            "The Judge verdict authority is S5 evidence-grounded knowledge, not S3 final security verdict authority.",
        ],
        "whatS5DoesNotKnow": _unique([
            "S5 does not decide S3 accepted claims, clean pass, exploitability, or final vulnerability verdict.",
            "S5 does not validate local source-code evidence refs on S3's behalf.",
            *([f"S5 is missing required input(s): {', '.join(required_inputs)}."] if required_inputs else []),
        ]),
        "whyThisMattersForS3": _judge_answer_s3_guidance(stance, verdict),
        "allowedUses": allowed,
        "forbiddenInferences": forbidden,
        "nextActions": next_actions,
        "qualityWarnings": quality_warnings,
        "humanQuestions": _judge_answer_human_questions(stance, required_inputs, has_source_refs),
        "evidencePlacement": {
            "recommendedRole": role,
            "consumerPolicy": JUDGE_ANSWER_CONSUMER_POLICY,
            "acquisitionStatus": status,
            "acquisitionQualityGate": quality_gate,
            "sourceEvidenceRefs": echoed_source_refs,
            "sourceEvidenceRefTotalCount": len(source_refs),
            "sourceEvidenceRefReturnedCount": len(echoed_source_refs),
            "sourceEvidenceRefsTruncated": source_refs_truncated,
            "derivedFromEvidenceRefs": [],
            "diagnosticCodes": diagnostic_codes,
            "diagnosticCodeTotalCount": diagnostic_code_total_count,
            "diagnosticCodeReturnedCount": len(diagnostic_codes),
            "diagnosticCodesTruncated": diagnostic_codes_truncated,
            "requiredInputTotalCount": required_input_total_count,
            "requiredInputReturnedCount": len(required_inputs),
            "requiredInputsTruncated": required_inputs_truncated,
        },
        "contractRefs": [
            "s5-judge-answer-v1",
            "s5-judge-contract-v1",
            "knowledge-coverage-v1",
        ],
    }


def _judge_answer_summary(verdict: str, status: str, quality_gate: str, stance: str, language: str) -> str:
    if language == "en":
        return (
            f"Judge verdict={verdict}, status={status}, qualityGate={quality_gate}. "
            f"Use this as stance={stance}; S3 remains responsible for final evidence promotion."
        )
    return (
        f"Judge verdict={verdict}, status={status}, qualityGate={quality_gate}입니다. "
        f"이 결과는 stance={stance}로만 소비해야 하며, 최종 증거 승격은 S3 책임입니다."
    )


def _judge_answer_s3_guidance(stance: str, verdict: str) -> list[str]:
    if stance == "contextual":
        guidance = [
            "S3 may use the Judge answer as evidence-grounded knowledge context.",
            "S3 must keep Judge verdicts separate from final claim adjudication.",
        ]
        if verdict == "not_affected":
            guidance.append("A not_affected Judge verdict is not a clean pass or target-safety proof.")
        return guidance
    if stance == "blocked":
        return [
            "S3 must not consume this Judge answer because the final-verdict authority boundary is missing or input is insufficient.",
            "S3 should request a valid Judge answer packet before attaching evidence.",
        ]
    return [
        "S3 should treat this Judge answer as requery or operational diagnostic guidance.",
        "Unknown/degraded/requery Judge states must not become negative evidence or absence claims.",
    ]


def _judge_answer_next_actions(
    *,
    stance: str,
    required_inputs: list[str],
    followups: list[Any],
    has_source_refs: bool,
    boundary_ok: bool,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if not boundary_ok:
        actions.append({
            "priority": "high",
            "actionType": "send_valid_judge_answer",
            "surface": "judge-query",
            "reason": "Judge answer must explicitly preserve the S5/S3 final-verdict authority boundary.",
            "requiredInputs": ["notFinalSecurityVerdict", "verdictAuthority"],
        })
    if required_inputs:
        actions.append({
            "priority": "high",
            "actionType": "provide_missing_inputs",
            "surface": "judge-query",
            "reason": "Judge answer requires deterministic follow-up input before safe conclusion.",
            "requiredInputs": required_inputs,
        })
        actions.append({
            "priority": "high",
            "actionType": "rerun_judge_with_required_inputs",
            "surface": "judge-query",
            "reason": "Re-run Judge after the required inputs are supplied.",
            "requiredInputs": required_inputs,
        })
    if followups:
        actions.append({
            "priority": "medium",
            "actionType": JUDGE_ANSWER_FOLLOW_UP_ACTION_TYPE,
            "surface": "judge-query",
            "reason": "Judge exposed follow-up affordances that S3/S4 should route before promotion.",
            "requiredInputs": [],
        })
    if has_source_refs:
        actions.append({
            "priority": "high",
            "actionType": "validate_source_evidence_refs",
            "surface": "judge-query",
            "reason": "S3 must validate local/source refs before promoting any local support.",
            "requiredInputs": ["sourceCodeKg.sourceArtifacts_or_graphNodes_or_evidenceSnippets"],
        })
    if stance == "contextual":
        actions.append({
            "priority": "medium",
            "actionType": "attach_as_context_only",
            "surface": "judge-query",
            "reason": "Judge output is knowledge context, not S3 final claim support.",
            "requiredInputs": [],
        })
    elif stance == "diagnostic" and not actions:
        actions.append({
            "priority": "high",
            "actionType": "rerun_judge_with_complete_context",
            "surface": "judge-query",
            "reason": "Current Judge state is diagnostic and cannot support safe S3 consumption.",
            "requiredInputs": [],
        })
    return _unique_actions(actions)


def _judge_answer_quality_warnings(
    *,
    verdict: str,
    status: str,
    quality_gate: str,
    required_inputs: list[str],
    conflicts: list[Any],
    followups: list[Any],
    diagnostic_codes: list[str],
    diagnostic_code_redacted: bool,
    diagnostic_codes_truncated: bool,
    required_input_redacted: bool,
    required_inputs_truncated: bool,
    boundary_ok: bool,
    source_refs_truncated: bool,
    source_refs_value_redacted: bool,
    scalar_redacted: bool,
    supported_status: bool,
    supported_quality_gate: bool,
) -> list[str]:
    warnings: list[str] = []
    if not boundary_ok:
        warnings.append(JUDGE_ANSWER_BOUNDARY_WARNING)
    if verdict not in {"affected", "not_affected", "unknown"}:
        warnings.append("unsupported_judge_verdict")
    if not supported_status:
        warnings.append("unsupported_judge_status")
    if not supported_quality_gate:
        warnings.append("unsupported_judge_quality_gate")
    if quality_gate in {"accepted_with_caveats", "rejected", "unknown"} or not supported_quality_gate:
        warnings.append(f"Judge quality gate is `{quality_gate}`.")
    if (
        status in {"degraded_quality", "requires_requery", "insufficient_input", "unknown"}
        or not supported_status
    ):
        warnings.append(f"Judge status is `{status}`.")
    if required_inputs:
        warnings.append("Judge required inputs are missing; do not synthesize a fallback answer.")
    if conflicts:
        warnings.append(JUDGE_ANSWER_CONFLICT_QUALITY_WARNING)
    if followups:
        warnings.append(JUDGE_ANSWER_FOLLOW_UP_QUALITY_WARNING)
    if diagnostic_codes:
        warnings.append(_diagnostic_codes_warning(diagnostic_codes))
    if diagnostic_code_redacted:
        warnings.append(JUDGE_ANSWER_DIAGNOSTIC_CODE_REDACTION_WARNING)
    if diagnostic_codes_truncated:
        warnings.append(JUDGE_ANSWER_DIAGNOSTIC_CODE_TRUNCATION_WARNING)
    if required_input_redacted:
        warnings.append(JUDGE_ANSWER_REQUIRED_INPUT_REDACTION_WARNING)
    if required_inputs_truncated:
        warnings.append(JUDGE_ANSWER_REQUIRED_INPUT_TRUNCATION_WARNING)
    if source_refs_truncated:
        warnings.append(JUDGE_ANSWER_SOURCE_REF_TRUNCATION_WARNING)
    if source_refs_value_redacted:
        warnings.append(JUDGE_ANSWER_SOURCE_REF_VALUE_REDACTION_WARNING)
    if scalar_redacted:
        warnings.append(JUDGE_ANSWER_SCALAR_REDACTION_WARNING)
    return _unique(warnings)


def _diagnostic_codes_warning(
    diagnostic_codes: list[str],
    *,
    preview_limit: int = JUDGE_ANSWER_DIAGNOSTIC_WARNING_PREVIEW_LIMIT,
) -> str:
    preview = diagnostic_codes[:preview_limit]
    remaining = len(diagnostic_codes) - len(preview)
    suffix = f" (+{remaining} more returned codes)" if remaining > 0 else ""
    return f"Diagnostics present: {', '.join(preview)}{suffix}."


def _judge_answer_human_questions(stance: str, required_inputs: list[str], has_source_refs: bool) -> list[str]:
    questions: list[str] = []
    if required_inputs:
        questions.append(f"Can S3/S4 provide Judge required input(s): {', '.join(required_inputs)}?")
    if has_source_refs:
        questions.append("Which Source KG refs can S3 validate before promoting any local support candidate?")
    if stance == "diagnostic":
        questions.append("Should S3 retry Judge after Source KG/Threat KB context is complete?")
    if stance == "blocked":
        questions.append("Can S5 resend a Judge answer with the final-verdict authority boundary intact?")
    return questions


def _judge_answer_diagnostic_code_values(answer: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    quality_gate = _as_dict(answer.get("qualityGate"))
    for diag in _as_list(quality_gate.get("diagnostics")):
        code = _as_dict(diag).get("code")
        if code:
            codes.append(str(code))
    for trace in _as_list(answer.get("fallbackTrace")):
        trace_dict = _as_dict(trace)
        for diag in _as_list(trace_dict.get("diagnostics")):
            code = _as_dict(diag).get("code")
            if code:
                codes.append(str(code))
        for rejected in _as_list(trace_dict.get("rejected")):
            code = _as_dict(rejected).get("code")
            if code:
                codes.append(str(code))
    return _unique(codes)


def _judge_answer_source_refs(answer: dict[str, Any]) -> list[str]:
    source_kg = _as_dict(_as_dict(answer.get("evidence")).get("sourceCodeKg"))
    refs: list[str] = []
    for item in _as_list(source_kg.get("sourceArtifacts")):
        item_dict = _as_dict(item)
        refs.extend(_string_list(_first_present(item_dict, JUDGE_ANSWER_SOURCE_ARTIFACT_REF_FIELDS)))
    for item in _as_list(source_kg.get("graphNodes")):
        item_dict = _as_dict(item)
        refs.extend(_string_list(item_dict.get("sourceGraphNodeId") or item_dict.get("graphNodeId") or item_dict.get("stableId")))
    for item in _as_list(source_kg.get("evidenceSnippets")):
        item_dict = _as_dict(item)
        refs.extend(_string_list(item_dict.get("evidenceSnippetId") or item_dict.get("snippetId")))
    return _unique(refs)


def _judge_answer_has_source_refs(answer: dict[str, Any]) -> bool:
    return bool(_judge_answer_source_refs(answer))


def _classify_stance(view: _ArtifactView) -> str:
    if view.malformed:
        return "blocked"
    if view.status == "input_insufficient":
        return "blocked"
    if view.consumer_policy == "do_not_use":
        return "blocked"
    if view.status in DIAGNOSTIC_STATUSES:
        return "diagnostic"
    if view.consumer_policy in {"diagnostic_only", "do_not_use_as_negative_evidence"}:
        return "diagnostic"

    if view.status == "completed_no_hit":
        if _safe_scoped_no_hit(view):
            return "scoped_negative_record"
        return "diagnostic"

    if view.status in {"completed_hit", "partial_hit"}:
        if view.consumer_policy == "s3_may_derive_local_support_if_refs_validate":
            return "local_support_candidate"
        if view.consumer_policy == "contextual_only":
            return "contextual"
        return "diagnostic"

    return "diagnostic"


def _safe_scoped_no_hit(view: _ArtifactView) -> bool:
    if view.consumer_policy != "scoped_no_hit_record_only":
        return False
    if view.provider_problem or view.projection_problem:
        return False
    if not view.raw_methods_required:
        return False
    if not set(view.raw_methods_required).issubset(set(view.raw_methods_attempted)):
        return False
    if not set(view.raw_methods_required).issubset(set(view.raw_methods_succeeded)):
        return False
    if view.no_hit_basis in UNSAFE_NO_HIT_BASIS:
        return False
    return True


def _recommended_role(stance: str, consumer_policy: str) -> str:
    if stance == "contextual":
        return "knowledge_context"
    if stance == "local_support_candidate":
        return "derived_local_candidate"
    if stance == "scoped_negative_record":
        return "scoped_acquisition_record"
    if stance == "blocked" or consumer_policy == "do_not_use":
        return "do_not_use"
    return "operational_diagnostic"


def _headline(stance: str, language: str) -> str:
    ko = {
        "contextual": "S5는 관련 지식 맥락을 찾았지만, 이것은 S3의 최종 증거 판정이 아닙니다.",
        "local_support_candidate": "S5는 S3가 local ref 검증 후 증거 후보로 삼을 수 있는 항목을 찾았습니다.",
        "scoped_negative_record": "S5는 명시 scope 안에서만 no-hit acquisition 기록을 만들었습니다.",
        "diagnostic": "S5 결과는 현재 진단 정보이며 부재/안전 증거로 쓰면 안 됩니다.",
        "blocked": "S5는 입력이 부족하거나 artifact가 부적절해 답변을 차단했습니다.",
    }
    en = {
        "contextual": "S5 found relevant knowledge context, not a final S3 evidence decision.",
        "local_support_candidate": "S5 found a candidate that S3 may use only after validating local refs.",
        "scoped_negative_record": "S5 produced a no-hit acquisition record for the explicit scope only.",
        "diagnostic": "This S5 result is diagnostic and must not be used as absence or safety evidence.",
        "blocked": "S5 blocked the answer because the input or artifact is insufficient.",
    }
    return (ko if language == "ko" else en).get(stance, en["diagnostic"])


def _summary(stance: str, view: _ArtifactView, language: str) -> str:
    if language == "en":
        return (
            f"surface={view.surface}, acquisitionStatus={view.status}, "
            f"consumerPolicy={view.consumer_policy}. "
            f"Use this brief according to stance={stance}; S3 remains responsible for final evidence promotion."
        )
    return (
        f"surface={view.surface}, acquisitionStatus={view.status}, "
        f"consumerPolicy={view.consumer_policy}입니다. "
        f"이 brief는 stance={stance}에 맞춰 소비해야 하며, 최종 증거 승격은 S3 책임입니다."
    )


def _readiness_narrative(view: _ArtifactView) -> str:
    parts = [
        f"acquisitionStatus={view.status}",
        f"consumerPolicy={view.consumer_policy}",
        f"qualityGate={view.quality_gate}",
        f"providerState={view.provider_state}",
        f"projectionState={view.projection_state}",
    ]
    if view.methods_required:
        parts.append(f"methodsRequiredForNoHit={','.join(view.methods_required)}")
    if view.methods_succeeded:
        parts.append(f"methodsSucceeded={','.join(view.methods_succeeded)}")
    return "; ".join(parts)


def _what_s5_knows(view: _ArtifactView) -> list[str]:
    knows = [
        f"S5 observed surface `{view.surface}` with acquisitionStatus `{view.status}`.",
        f"S5 assigned consumerPolicy `{view.consumer_policy}` and acquisitionQualityGate `{view.quality_gate}`.",
    ]
    if view.artifact.get("targetKnowledgeId"):
        knows.append(
            "Target context is linked by targetKnowledgeId "
            f"`{_sanitize_acquisition_identity(str(view.artifact.get('targetKnowledgeId')))}`."
        )
    total = _candidate_count(view)
    if total is not None:
        knows.append(f"The artifact reports candidate/result count `{total}` for this acquisition result.")
    if view.methods_succeeded:
        knows.append(f"Completed methods reported by S5: {', '.join(view.methods_succeeded)}.")
    return knows


def _what_s5_does_not_know(view: _ArtifactView, missing_inputs: list[str]) -> list[str]:
    unknowns = [
        "S5 does not decide S3 accepted claims, clean pass, exploitability, or final vulnerability verdict.",
        "S5 does not validate local source-code evidence refs on S3's behalf.",
    ]
    if missing_inputs:
        unknowns.append(f"S5 is missing required input(s): {', '.join(missing_inputs)}.")
    if view.provider_problem:
        unknowns.append(f"Provider state `{view.provider_state}` prevents reliable absence reasoning.")
    if view.projection_problem:
        unknowns.append(f"Projection state `{view.projection_state}` prevents reliable graph/path absence reasoning.")
    return unknowns


def _why_this_matters_for_s3(stance: str, view: _ArtifactView) -> list[str]:
    if stance == "contextual":
        return [
            "S3 may use this to enrich analysis narrative or choose follow-up queries.",
            "S3 must keep it separate from local source evidence and final claim adjudication.",
        ]
    if stance == "local_support_candidate":
        return [
            "S3 may promote this only after validating source/local refs in its own evidence ledger.",
            "Until validation, this is a candidate pointer rather than claim support.",
        ]
    if stance == "scoped_negative_record":
        return [
            "S3 may record that S5 completed required acquisition methods for this exact scope.",
            "The record cannot be broadened to library safety, target safety, or project clean pass.",
        ]
    if stance == "blocked":
        return [
            "S3 must provide the missing deterministic context before S5 can answer safely.",
            "S5 intentionally refused a global/default fallback answer.",
        ]
    return [
        "S3 should treat this as an operational or acquisition diagnostic.",
        "Missing candidates under this state must not be interpreted as absence of vulnerability or path.",
    ]


def _allowed_uses(stance: str, view: _ArtifactView) -> list[str]:
    if stance == "contextual":
        return ["use_as_knowledge_context", "use_for_follow_up_planning"]
    if stance == "local_support_candidate":
        return ["use_as_local_support_candidate_after_s3_ref_validation", "use_for_evidence_reattachment_planning"]
    if stance == "scoped_negative_record":
        return ["record_scoped_acquisition_no_hit", "exclude_only_the_explicit_candidate_or_scope_if_s3_policy_allows"]
    if stance == "blocked":
        return ["use_to_fix_input_contract", "do_not_attach_to_evidence_catalog"]
    if view.consumer_policy == "do_not_use":
        return ["do_not_use"]
    return ["use_for_retry_planning", "use_as_operational_diagnostic"]


def _stance_forbidden_inferences(stance: str, view: _ArtifactView) -> list[str]:
    forbidden = ["claim_support_without_s3_validation"]
    if stance == "contextual":
        forbidden.extend(["accepted_claim", "derived_local_support"])
    elif stance == "local_support_candidate":
        forbidden.extend(["claim_support_before_local_ref_validation", "accepted_claim_without_s3_validation"])
    elif stance == "scoped_negative_record":
        forbidden.extend(["library_safe", "target_safe", "no_other_cves", "no_other_paths"])
    elif stance == "blocked":
        forbidden.extend(["global_default_answer", "fallback_answer", "evidence_catalog_attachment"])
    else:
        forbidden.extend(["absence_of_vulnerability", "no_caller_or_path", "negative_absence_claim"])

    return forbidden + view.scope_forbidden_inferences


def _next_actions(
    stance: str,
    view: _ArtifactView,
    missing_inputs: list[str],
    diagnostic_codes: list[str],
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if missing_inputs:
        actions.append({
            "priority": "high",
            "actionType": "provide_missing_inputs",
            "surface": view.surface,
            "reason": "S5 cannot safely answer without the missing deterministic target/acquisition inputs.",
            "requiredInputs": missing_inputs,
        })
    if view.provider_problem:
        actions.append({
            "priority": "high",
            "actionType": "retry_or_refresh_provider",
            "surface": view.surface,
            "reason": f"providerState is `{view.provider_state}`.",
            "requiredInputs": [],
        })
    if view.projection_problem:
        actions.append({
            "priority": "high",
            "actionType": "sync_or_rebuild_projection",
            "surface": view.surface,
            "reason": f"projectionState is `{view.projection_state}`.",
            "requiredInputs": [],
        })
    if view.fallback_trace:
        actions.append({
            "priority": "medium",
            "actionType": "inspect_fallback_trace",
            "surface": view.surface,
            "reason": "Fallback occurred and must remain visible to S3.",
            "requiredInputs": [],
        })
    if view.item_acquisitions:
        actions.append({
            "priority": "high",
            "actionType": "consume_item_acquisitions_individually",
            "surface": view.surface,
            "reason": "Mixed item outcomes must not be collapsed into one evidence decision.",
            "requiredInputs": [],
        })
    if view.malformed:
        actions.append({
            "priority": "high",
            "actionType": "send_valid_acquisition_artifact",
            "surface": view.surface,
            "reason": "Analyst Brief v1 requires an AcquisitionEnvelopeV1 artifact with status and consumer policy.",
            "requiredInputs": ["schemaVersion", "acquisitionStatus", "consumerPolicy"],
        })
    if stance == "local_support_candidate":
        actions.append({
            "priority": "high",
            "actionType": "validate_source_evidence_refs",
            "surface": view.surface,
            "reason": "S3 may derive local support only after validating local/source refs.",
            "requiredInputs": ["sourceEvidenceRefs_or_local_refs"],
        })
    elif stance == "contextual":
        actions.append({
            "priority": "medium",
            "actionType": "attach_as_context_only",
            "surface": view.surface,
            "reason": "This enriches the analysis narrative but is not final evidence.",
            "requiredInputs": [],
        })
    elif stance == "scoped_negative_record":
        actions.append({
            "priority": "medium",
            "actionType": "record_scoped_no_hit_only",
            "surface": view.surface,
            "reason": "The no-hit record is scoped and must not become a clean pass.",
            "requiredInputs": [],
        })
    elif stance in {"diagnostic", "blocked"} and not actions:
        actions.append({
            "priority": "high",
            "actionType": "retry_with_complete_target_context",
            "surface": view.surface,
            "reason": "Current artifact cannot support safe S3 consumption.",
            "requiredInputs": [],
        })
    if any(code.startswith("NO_HIT_TRACE") for code in diagnostic_codes):
        actions.append({
            "priority": "high",
            "actionType": "rerun_with_retrieval_trace",
            "surface": view.surface,
            "reason": "No-hit consumption requires an explicit retrieval trace.",
            "requiredInputs": ["retrievalTrace"],
        })
    return _unique_actions(actions)


def _human_questions(stance: str, view: _ArtifactView, missing_inputs: list[str]) -> list[str]:
    questions: list[str] = []
    if missing_inputs:
        questions.append(f"Can S3 resend the target context with: {', '.join(missing_inputs)}?")
    if stance == "local_support_candidate":
        questions.append("Which local source/evidence refs can S3 validate before promoting this candidate?")
    if stance == "scoped_negative_record":
        questions.append("Is S3 consuming this only for the explicit scope, not as target or project safety?")
    if stance == "diagnostic":
        questions.append("Should S3 retry after provider/projection/readiness recovery before drawing conclusions?")
    if view.item_acquisitions:
        questions.append("Which item acquisition is S3 trying to consume for this claim?")
    return questions


def _quality_warnings(
    view: _ArtifactView,
    diagnostic_codes: list[str],
    missing_inputs: list[str],
    *,
    diagnostic_code_redacted: bool,
    diagnostic_codes_truncated: bool,
    missing_input_redacted: bool,
    missing_inputs_truncated: bool,
    evidence_ref_redacted: bool,
    source_refs_truncated: bool,
    derived_refs_truncated: bool,
    identity_redacted: bool,
    state_redacted: bool,
    method_redacted: bool,
    methods_truncated: bool,
    scope_forbidden_inference_redacted: bool,
    scope_forbidden_inferences_truncated: bool,
) -> list[str]:
    warnings: list[str] = []
    if view.quality_gate in {"accepted_with_caveats", "inconclusive", "rejected"}:
        warnings.append(f"Acquisition quality gate is `{view.quality_gate}`.")
    if missing_inputs:
        warnings.append("Required inputs are missing; S5 did not synthesize a fallback answer.")
    if view.malformed:
        warnings.append("Artifact is missing required AcquisitionEnvelopeV1 identity/status/policy fields.")
    if view.provider_problem:
        warnings.append(f"Provider state `{view.provider_state}` makes absence reasoning unsafe.")
    if view.projection_problem:
        warnings.append(f"Projection state `{view.projection_state}` makes graph/path absence reasoning unsafe.")
    if view.status == "completed_no_hit" and not _safe_scoped_no_hit(view):
        warnings.append("No-hit safety conditions are incomplete; treat as diagnostic rather than absence.")
    if view.fallback_trace:
        warnings.append("Fallback trace is present; S3 must inspect specificity-loss caveats.")
    if view.item_acquisitions:
        warnings.append("Item acquisitions are present; S3 must consume them item-by-item.")
    if diagnostic_codes:
        warnings.append(
            _diagnostic_codes_warning(
                diagnostic_codes,
                preview_limit=ACQUISITION_DIAGNOSTIC_WARNING_PREVIEW_LIMIT,
            )
        )
    if diagnostic_code_redacted:
        warnings.append(ACQUISITION_DIAGNOSTIC_CODE_REDACTION_WARNING)
    if diagnostic_codes_truncated:
        warnings.append(ACQUISITION_DIAGNOSTIC_CODE_TRUNCATION_WARNING)
    if missing_input_redacted:
        warnings.append(ACQUISITION_REQUIRED_INPUT_REDACTION_WARNING)
    if missing_inputs_truncated:
        warnings.append(ACQUISITION_REQUIRED_INPUT_TRUNCATION_WARNING)
    if evidence_ref_redacted:
        warnings.append(ACQUISITION_EVIDENCE_REF_VALUE_REDACTION_WARNING)
    if source_refs_truncated:
        warnings.append(ACQUISITION_SOURCE_EVIDENCE_REF_TRUNCATION_WARNING)
    if derived_refs_truncated:
        warnings.append(ACQUISITION_DERIVED_EVIDENCE_REF_TRUNCATION_WARNING)
    if identity_redacted:
        warnings.append(ACQUISITION_IDENTITY_REDACTION_WARNING)
    if state_redacted:
        warnings.append(ACQUISITION_STATE_REDACTION_WARNING)
    if method_redacted:
        warnings.append(ACQUISITION_METHOD_REDACTION_WARNING)
    if methods_truncated:
        warnings.append(ACQUISITION_METHOD_TRUNCATION_WARNING)
    if scope_forbidden_inference_redacted:
        warnings.append(ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_REDACTION_WARNING)
    if scope_forbidden_inferences_truncated:
        warnings.append(ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_TRUNCATION_WARNING)
    return _unique(warnings)


def _diagnostic_code_values(artifact: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    for diag in _as_list(artifact.get("diagnostics")):
        code = _as_dict(diag).get("code")
        if code:
            codes.append(str(code))
    for item in _as_list(artifact.get("itemAcquisitions")):
        item_dict = _as_dict(item)
        for diag in _as_list(item_dict.get("diagnostics")):
            code = _as_dict(diag).get("code")
            if code:
                codes.append(str(code))
    return _unique(codes)


def _missing_input_values(artifact: dict[str, Any]) -> list[str]:
    readiness = _as_dict(artifact.get("readiness"))
    results = _as_dict(artifact.get("results"))
    missing = _string_list(readiness.get("missingInputs"))
    missing.extend(_string_list(results.get("missingFields")))
    return _unique(missing)


def _candidate_count(view: _ArtifactView) -> int | None:
    for source in (view.results, view.artifact):
        for key in ("candidate_count", "candidateCount", "returnedCount", "total", "itemCount"):
            value = source.get(key)
            if isinstance(value, int):
                return value
    hits = view.results.get("hits")
    if isinstance(hits, list):
        return len(hits)
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if value in (None, ""):
        return []
    return [str(value)]


def _sanitize_source_ref(value: str) -> str:
    if len(value) <= JUDGE_ANSWER_SOURCE_REF_VALUE_MAX_CHARS:
        return value
    return JUDGE_ANSWER_SOURCE_REF_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _sanitize_judge_answer_scalar(value: str) -> str:
    if len(value) <= JUDGE_ANSWER_SCALAR_MAX_CHARS:
        return value
    return JUDGE_ANSWER_SCALAR_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _judge_answer_scalar_redacted(value: Any) -> bool:
    return len(str(value or "")) > JUDGE_ANSWER_SCALAR_MAX_CHARS


def _sanitize_acquisition_diagnostic_code(value: str) -> str:
    if len(value) <= ACQUISITION_DIAGNOSTIC_CODE_MAX_CHARS:
        return value
    return ACQUISITION_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _sanitize_acquisition_required_input(value: str) -> str:
    if len(value) <= ACQUISITION_REQUIRED_INPUT_MAX_CHARS:
        return value
    return ACQUISITION_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _sanitize_acquisition_evidence_ref(value: str) -> str:
    if len(value) <= ACQUISITION_EVIDENCE_REF_VALUE_MAX_CHARS:
        return value
    return ACQUISITION_EVIDENCE_REF_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _sanitize_acquisition_identity(value: str) -> str:
    if len(value) <= ACQUISITION_IDENTITY_MAX_CHARS:
        return value
    return ACQUISITION_IDENTITY_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _acquisition_identity_redacted(value: Any) -> bool:
    return len(str(value or "")) > ACQUISITION_IDENTITY_MAX_CHARS


def _sanitize_acquisition_state(value: str) -> str:
    if len(value) <= ACQUISITION_STATE_MAX_CHARS:
        return value
    return ACQUISITION_STATE_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _acquisition_state_redacted(value: Any) -> bool:
    return len(str(value or "")) > ACQUISITION_STATE_MAX_CHARS


def _sanitize_acquisition_method(value: str) -> str:
    if len(value) <= ACQUISITION_METHOD_MAX_CHARS:
        return value
    return ACQUISITION_METHOD_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _acquisition_method_redacted(value: Any) -> bool:
    return len(str(value or "")) > ACQUISITION_METHOD_MAX_CHARS


def _sanitize_acquisition_scope_forbidden_inference(value: str) -> str:
    if len(value) <= ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_MAX_CHARS:
        return value
    return ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_OVERSIZED_REDACTION_TEMPLATE.format(
        length=len(value)
    )


def _acquisition_scope_forbidden_inference_redacted(value: Any) -> bool:
    return len(str(value or "")) > ACQUISITION_SCOPE_FORBIDDEN_INFERENCE_MAX_CHARS


def _sanitize_diagnostic_code(value: str) -> str:
    if len(value) <= JUDGE_ANSWER_DIAGNOSTIC_CODE_MAX_CHARS:
        return value
    return JUDGE_ANSWER_DIAGNOSTIC_CODE_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _sanitize_required_input(value: str) -> str:
    if len(value) <= JUDGE_ANSWER_REQUIRED_INPUT_MAX_CHARS:
        return value
    return JUDGE_ANSWER_REQUIRED_INPUT_OVERSIZED_REDACTION_TEMPLATE.format(length=len(value))


def _state_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("state") or "not_applicable")
    if value in (None, ""):
        return "not_applicable"
    return str(value)


def _first_present(mapping: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _unique_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for action in actions:
        key = (str(action.get("actionType")), str(action.get("surface")))
        if key not in seen:
            out.append(action)
            seen.add(key)
    return out
