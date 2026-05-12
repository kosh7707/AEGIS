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

    view = _ArtifactView(artifact)
    stance = _classify_stance(view)
    role = _recommended_role(stance, view.consumer_policy)
    diagnostic_codes = _diagnostic_codes(artifact)
    missing_inputs = _missing_inputs(artifact)
    quality_warnings = _quality_warnings(view, diagnostic_codes, missing_inputs)

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
            "sourceEvidenceRefs": _string_list(artifact.get("sourceEvidenceRefs")),
            "derivedFromEvidenceRefs": _string_list(artifact.get("derivedFromEvidenceRefs")),
            "diagnosticCodes": diagnostic_codes,
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
        self.surface = str(artifact.get("surface") or "unknown")
        self.status = str(artifact.get("acquisitionStatus") or "unknown")
        self.quality_gate = str(artifact.get("acquisitionQualityGate") or "unknown")
        self.consumer_policy = str(artifact.get("consumerPolicy") or "unknown")
        self.scope = _as_dict(artifact.get("scope"))
        self.readiness = _as_dict(artifact.get("readiness"))
        self.results = _as_dict(artifact.get("results"))
        self.provider_state = _state_name(
            artifact.get("providerState")
            or self.readiness.get("providerState")
            or self.scope.get("providerState")
        )
        self.projection_state = _state_name(
            artifact.get("projectionState")
            or self.readiness.get("projectionState")
            or self.scope.get("projectionState")
        )
        self.methods_required = _string_list(
            self.readiness.get("methodsRequiredForNoHit")
            or self.scope.get("methodsRequiredForNoHit")
        )
        self.methods_succeeded = _string_list(
            artifact.get("methodsSucceeded")
            or self.readiness.get("methodsSucceeded")
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
    if not view.methods_required:
        return False
    if not set(view.methods_required).issubset(set(view.methods_succeeded)):
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
        knows.append(f"Target context is linked by targetKnowledgeId `{view.artifact.get('targetKnowledgeId')}`.")
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

    scope_forbidden = _string_list(view.scope.get("forbiddenInferences"))
    return forbidden + scope_forbidden


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
        warnings.append(f"Diagnostics present: {', '.join(diagnostic_codes)}.")
    return _unique(warnings)


def _diagnostic_codes(artifact: dict[str, Any]) -> list[str]:
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


def _missing_inputs(artifact: dict[str, Any]) -> list[str]:
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


def _state_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("state") or "not_applicable")
    if value in (None, ""):
        return "not_applicable"
    return str(value)


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
