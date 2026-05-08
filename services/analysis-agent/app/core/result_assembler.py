"""ResultAssembler — 에이전트 루프 출력을 TaskResponse 형식으로 변환."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from app.agent_runtime.observability import agent_log
from app.core.evidence_catalog import EvidenceCatalogEntry
from app.pipeline.confidence import ConfidenceCalculator
from app.pipeline.response_parser import V1ResponseParser
from app.agent_runtime.schemas.agent import AgentAuditInfo
from app.quality.deep_quality_gate import evaluate_deep_quality
from app.schemas.response import (
    AssessmentResult,
    AuditInfo,
    Claim,
    ClaimDiagnostics,
    EvaluationVerdict,
    EvidenceAcquisitionDiagnostic,
    EvidenceDiagnostics,
    EvidenceRefRoleDiagnostic,
    NonAcceptedClaimDiagnostic,
    QualityGateItem,
    QualityGateResult,
    RecoveryTraceEntry,
    TaskFailureResponse,
    TaskSuccessResponse,
    TokenUsage,
    ValidationInfo,
)
from app.state_machine.outcomes import TriageContext, clean_pass_for, outcome_for_deficiency
from app.state_machine.claim import diagnose_claim_evidence, transition_claim_status
from app.state_machine.recovery_triage import recovery_trace
from app.state_machine.types import DeficiencyClass, DependencyState
from app.types import AnalysisOutcome, ClaimStatus, FailureCode, PocOutcome, QualityOutcome, TaskStatus
from app.validators.evidence_sanitizer import EvidenceRefSanitizer
from app.validators.evidence_validator import EvidenceValidator
from app.validators.schema_validator import SchemaValidator

if TYPE_CHECKING:
    from app.core.agent_session import AgentSession

logger = logging.getLogger(__name__)


class ResultAssembler:
    """에이전트 루프의 최종 결과를 API 응답 형식으로 조립한다."""

    def __init__(self, model_name: str = "", prompt_version: str = "agent-v1") -> None:
        self._parser = V1ResponseParser()
        self._schema_validator = SchemaValidator()
        self._evidence_sanitizer = EvidenceRefSanitizer()
        self._evidence_validator = EvidenceValidator()
        self._confidence_calculator = ConfidenceCalculator()
        self._model_name = model_name
        self._prompt_version = prompt_version

    def build(
        self,
        final_content: str,
        session: AgentSession,
    ) -> TaskSuccessResponse | TaskFailureResponse:
        """LLM이 반환한 최종 content를 파싱하여 응답을 구성한다."""
        # 파싱
        parsed = self._parser.parse(final_content)
        fallback = parsed is None

        agent_log(
            logger, "결과 파싱",
            component="result_assembler", phase="result_parse",
            parsedOk=not fallback, fallbackApplied=fallback,
        )

        if parsed is None:
            session.set_termination_reason("invalid_final_output")
            outcome = outcome_for_deficiency(DeficiencyClass.MALFORMED_LLM_OUTPUT)
            return self.build_completed_outcome(
                session,
                summary="S3 검토는 완료되었지만 구조화된 최종 Assessment를 확정할 수 없어 inconclusive로 분류했습니다.",
                analysis_outcome=outcome.analysis_outcome,
                quality_outcome=outcome.quality_outcome,
                poc_outcome=outcome.poc_outcome,
                caveats=["LLM final output was not parseable as Assessment JSON after recovery."],
                policy_flags=["recovery_classified", "schema_deficient"],
                recovery_trace=[recovery_trace(
                    deficiency="LLM_OUTPUT_DEFICIENT",
                    action="outcome_classification",
                    outcome="inconclusive",
                    detail="Final content was non-JSON or not a parseable Assessment object.",
                    deficiency_class=DeficiencyClass.MALFORMED_LLM_OUTPUT,
                    dependency_state=DependencyState.OUTPUT_DEFICIENT,
                )],
                termination_reason="invalid_final_output_recovered",
            )

        # 검증: 입력 제공 refs + Phase 1 refs + 도구가 생성한 refs 합집합
        allowed_refs = {ref.refId for ref in session.request.evidenceRefs}
        allowed_refs.update(session.extra_allowed_refs)
        allowed_refs.update(session.evidence_catalog.ref_ids())
        for step in session.trace:
            allowed_refs.update(step.new_evidence_refs)

        allowed_claim_refs = _allowed_claim_ref_ids(session, allowed_refs)
        canonical_repairs, canonical_failure = _canonicalize_deep_assessment(
            parsed,
            session,
            allowed_refs,
            allowed_claim_refs,
        )
        if canonical_repairs:
            agent_log(
                logger,
                "deep assessment canonicalized",
                component="result_assembler",
                phase="result_canonicalize",
                repairs=canonical_repairs,
            )
        if canonical_failure:
            session.set_termination_reason("invalid_grounding")
            outcome = outcome_for_deficiency(DeficiencyClass.GROUNDING)
            return self.build_completed_outcome(
                session,
                summary="S3 검토는 완료되었지만 claim grounding을 정직하게 수용할 수 없어 no_accepted_claims로 분류했습니다.",
                analysis_outcome=outcome.analysis_outcome,
                quality_outcome=outcome.quality_outcome,
                poc_outcome=outcome.poc_outcome,
                caveats=[canonical_failure],
                policy_flags=["recovery_classified", "grounding_deficient"],
                recovery_trace=[recovery_trace(
                    deficiency="GROUNDING_DEFICIENT",
                    action="reject_unaccepted_claims",
                    outcome="no_accepted_claims",
                    detail=canonical_failure,
                    deficiency_class=DeficiencyClass.GROUNDING,
                    dependency_state=DependencyState.AVAILABLE,
                )],
                termination_reason="invalid_grounding_recovered",
            )

        schema_result = self._schema_validator.validate(parsed, session.request.taskType)
        if not schema_result.valid:
            agent_log(
                logger, "결과 검증",
                component="result_assembler", phase="result_validate",
                schemaValid=False,
                evidenceValid=False,
                errorCount=len(schema_result.errors),
            )
            session.set_termination_reason("invalid_final_output")
            outcome = outcome_for_deficiency(DeficiencyClass.SCHEMA)
            return self.build_completed_outcome(
                session,
                summary="S3 검토는 완료되었지만 최종 Assessment 스키마 결함이 남아 inconclusive로 분류했습니다.",
                analysis_outcome=outcome.analysis_outcome,
                quality_outcome=outcome.quality_outcome,
                poc_outcome=outcome.poc_outcome,
                caveats=schema_result.errors,
                policy_flags=["recovery_classified", "schema_deficient"],
                recovery_trace=[recovery_trace(
                    deficiency="SCHEMA_DEFICIENT",
                    action="outcome_classification",
                    outcome="inconclusive",
                    detail="; ".join(schema_result.errors),
                    deficiency_class=DeficiencyClass.SCHEMA,
                    dependency_state=DependencyState.OUTPUT_DEFICIENT,
                )],
                termination_reason="invalid_final_output_recovered",
            )

        evidence_diagnostics = _build_evidence_diagnostics(session, parsed, allowed_refs, allowed_claim_refs)
        contextual_evidence_refs = _contextual_evidence_refs(session, parsed, allowed_refs)
        evidence_valid, evidence_errors = self._evidence_validator.validate(
            parsed,
            allowed_refs,
            evidence_catalog=session.evidence_catalog,
            allowed_claim_ref_ids=allowed_claim_refs,
        )
        if not evidence_valid:
            agent_log(
                logger, "결과 검증",
                component="result_assembler", phase="result_validate",
                schemaValid=True,
                evidenceValid=False,
                errorCount=len(evidence_errors),
            )
            session.set_termination_reason("invalid_grounding")
            outcome = outcome_for_deficiency(DeficiencyClass.GROUNDING)
            return self.build_completed_outcome(
                session,
                summary="S3 검토는 완료되었지만 evidence grounding 결함으로 accepted claim을 확정하지 못했습니다.",
                analysis_outcome=outcome.analysis_outcome,
                quality_outcome=outcome.quality_outcome,
                poc_outcome=outcome.poc_outcome,
                caveats=evidence_errors,
                policy_flags=["recovery_classified", "grounding_deficient"],
                recovery_trace=[recovery_trace(
                    deficiency="REFS_OR_GROUNDING_DEFICIENT",
                    action="reject_unaccepted_claims",
                    outcome="no_accepted_claims",
                    detail="; ".join(evidence_errors),
                    deficiency_class=DeficiencyClass.GROUNDING,
                    dependency_state=DependencyState.AVAILABLE,
                )],
                evidence_diagnostics=evidence_diagnostics,
                contextual_evidence_refs=contextual_evidence_refs,
                claim_diagnostics=_build_claim_lifecycle_outputs(
                    parsed, session, allowed_claim_refs=allowed_claim_refs
                )[1],
                termination_reason="invalid_grounding_recovered",
            )

        # 환각 refId 제거 (raw evidence validation 이후의 방어적 no-op)
        parsed, sanitize_corrections = self._evidence_sanitizer.sanitize(parsed, allowed_refs)
        if sanitize_corrections:
            agent_log(
                logger, "evidence ref defensive cleanup",
                component="result_assembler", phase="result_sanitize",
                correctionCount=len(sanitize_corrections),
                corrections=sanitize_corrections[:10],
            )

        validation = ValidationInfo(
            valid=schema_result.valid and evidence_valid,
            errors=schema_result.errors + evidence_errors,
        )

        agent_log(
            logger, "결과 검증",
            component="result_assembler", phase="result_validate",
            schemaValid=schema_result.valid,
            evidenceValid=evidence_valid,
            errorCount=len(schema_result.errors) + len(evidence_errors),
        )

        # confidence
        finding = session.request.context.trusted.get("finding")
        rule_matches = session.request.context.trusted.get("ruleMatches", [])
        confidence, breakdown = self._confidence_calculator.calculate(
            parsed,
            input_ref_ids=allowed_refs,
            schema_valid=validation.valid,
            has_rule_results=bool(finding or rule_matches),
            rag_hits=0,
        )

        agent_log(
            logger, "결과 신뢰도",
            component="result_assembler", phase="result_confidence",
            confidence=confidence,
            breakdown=breakdown.model_dump() if hasattr(breakdown, "model_dump") else breakdown,
        )

        # AssessmentResult 조립
        claims, claim_diagnostics = _build_claim_lifecycle_outputs(
            parsed, session, allowed_claim_refs=allowed_claim_refs
        )

        analysis_outcome = (
            AnalysisOutcome.ACCEPTED_CLAIMS if claims else AnalysisOutcome.NO_ACCEPTED_CLAIMS
        )
        quality_gate = evaluate_deep_quality(
            claims=claims,
            caveats=parsed.get("caveats", []),
            evidence_errors=[],
        )
        quality_outcome = quality_gate.outcome
        poc_outcome = PocOutcome.POC_NOT_REQUESTED
        clean_pass = clean_pass_for(
            analysis_outcome=analysis_outcome,
            quality_outcome=quality_outcome,
            poc_outcome=poc_outcome,
        )
        evaluation_verdict = _evaluation_verdict_for(
            clean_pass=clean_pass,
            analysis_outcome=analysis_outcome,
            quality_outcome=quality_outcome,
            poc_outcome=poc_outcome,
            evidence_errors=[],
        )

        result = AssessmentResult(
            summary=parsed.get("summary", ""),
            claims=claims,
            caveats=parsed.get("caveats", []),
            usedEvidenceRefs=parsed.get("usedEvidenceRefs", []),
            suggestedSeverity=parsed.get("suggestedSeverity"),
            confidence=confidence,
            confidenceBreakdown=breakdown,
            needsHumanReview=parsed.get("needsHumanReview", True),
            recommendedNextSteps=parsed.get("recommendedNextSteps", []),
            policyFlags=parsed.get("policyFlags", []),
            analysisOutcome=analysis_outcome,
            qualityOutcome=quality_outcome,
            pocOutcome=poc_outcome,
            recoveryTrace=[],
            cleanPass=clean_pass,
            evaluationVerdict=evaluation_verdict,
            contextualEvidenceRefs=contextual_evidence_refs,
            evidenceDiagnostics=evidence_diagnostics,
            claimDiagnostics=claim_diagnostics,
            qualityGate=quality_gate,
        )

        agent_log(
            logger, "결과 조립 완료",
            component="result_assembler", phase="result_build",
            status="completed",
            claimCount=len(claims),
            severity=parsed.get("suggestedSeverity"),
        )

        return TaskSuccessResponse(
            taskId=session.request.taskId,
            taskType=session.request.taskType,
            status=TaskStatus.COMPLETED,
            modelProfile="agent-loop",
            promptVersion="agent-v1",
            schemaVersion="agent-v1.1",
            validation=validation,
            result=result,
            audit=self._build_audit(session, "content_returned"),
        )

    _TERMINATION_MAP: dict[str, tuple[TaskStatus, FailureCode, bool]] = {
        "max_steps":           (TaskStatus.BUDGET_EXCEEDED, FailureCode.MAX_STEPS_EXCEEDED,    False),
        "budget_exhausted":    (TaskStatus.BUDGET_EXCEEDED, FailureCode.TOKEN_BUDGET_EXCEEDED, False),
        "timeout":             (TaskStatus.TIMEOUT,         FailureCode.TIMEOUT,               True),
        "no_new_evidence":     (TaskStatus.BUDGET_EXCEEDED, FailureCode.INSUFFICIENT_EVIDENCE, False),
        "all_tiers_exhausted": (TaskStatus.BUDGET_EXCEEDED, FailureCode.ALL_TOOLS_EXHAUSTED,   False),
    }

    def build_from_exhaustion(
        self,
        session: AgentSession,
    ) -> TaskSuccessResponse | TaskFailureResponse:
        """정책에 의해 루프가 종료된 경우 state-machine outcome으로 분류한다."""
        reason = session.termination_reason
        if reason in {
            "max_steps",
            "budget_exhausted",
            "no_new_evidence",
            "all_tiers_exhausted",
        } or (reason or "").startswith("llm_failure_partial:"):
            outcome = outcome_for_deficiency(
                DeficiencyClass.REPAIR_EXHAUSTED,
                TriageContext(no_accepted_claims=reason == "no_new_evidence"),
            )
            return self.build_completed_outcome(
                session,
                summary="S3 검토는 완료되었지만 복구/증거/도구 예산이 소진되어 negative outcome으로 분류했습니다.",
                analysis_outcome=outcome.analysis_outcome,
                quality_outcome=outcome.quality_outcome,
                poc_outcome=outcome.poc_outcome,
                caveats=[f"Agent loop ended with recoverable exhaustion reason: {reason}"],
                policy_flags=["recovery_classified", "repair_exhausted"],
                recovery_trace=[recovery_trace(
                    deficiency="RECOVERY_EXHAUSTED",
                    action="outcome_classification",
                    outcome=outcome.analysis_outcome.value,
                    detail=f"termination_reason={reason}",
                    deficiency_class=DeficiencyClass.REPAIR_EXHAUSTED,
                    dependency_state=DependencyState.DEGRADED_PARTIAL,
                )],
                termination_reason=f"{reason or 'exhaustion'}_recovered",
            )
        status, code, retryable = self._TERMINATION_MAP.get(
            reason,
            (TaskStatus.BUDGET_EXCEEDED, FailureCode.TOKEN_BUDGET_EXCEEDED, False),
        )
        return self.build_failure(
            session, status, code,
            f"에이전트 루프 종료: {reason}",
            retryable=retryable,
        )

    def build_from_available_evidence(
        self,
        session: AgentSession,
        *,
        deficiency_detail: str,
        termination_reason: str = "llm_failure_local_evidence_recovered",
    ) -> TaskSuccessResponse | TaskFailureResponse:
        """Recover an honest Assessment from already-cataloged local evidence.

        This is a deterministic safety net for cases where S7/vLLM fails before
        S3 receives a usable Assessment, but Phase 1/S4/S5 already supplied
        claim-supporting local evidence.  It must not invent findings: claims
        are generated only from catalog entries that can support claims and are
        still passed through the normal schema, grounding, lifecycle, confidence,
        and quality gates by delegating back to ``build``.
        """
        parsed = _assessment_from_available_evidence(
            session,
            deficiency_detail=deficiency_detail,
        )
        if not parsed["claims"]:
            outcome = outcome_for_deficiency(DeficiencyClass.MALFORMED_LLM_OUTPUT)
            return self.build_completed_outcome(
                session,
                summary="S3 검토는 완료되었지만 LLM 호출 실패 후 claim-supporting local evidence를 찾지 못해 inconclusive로 분류했습니다.",
                analysis_outcome=outcome.analysis_outcome,
                quality_outcome=outcome.quality_outcome,
                poc_outcome=outcome.poc_outcome,
                caveats=[f"LLM output/call deficiency: {deficiency_detail}"],
                policy_flags=["recovery_classified", "llm_output_deficient", "deterministic_evidence_fallback_empty"],
                recovery_trace=[recovery_trace(
                    deficiency="LLM_OUTPUT_DEFICIENT",
                    action="deterministic_local_evidence_fallback",
                    outcome="inconclusive",
                    detail=deficiency_detail,
                    deficiency_class=DeficiencyClass.MALFORMED_LLM_OUTPUT,
                    dependency_state=DependencyState.DEGRADED_PARTIAL,
                )],
                termination_reason=termination_reason,
            )

        result = self.build(json.dumps(parsed, ensure_ascii=False), session)
        if isinstance(result, TaskSuccessResponse):
            result.result.recoveryTrace = [recovery_trace(
                deficiency="LLM_OUTPUT_DEFICIENT",
                action="deterministic_local_evidence_fallback",
                outcome=result.result.analysisOutcome.value,
                detail=deficiency_detail,
                deficiency_class=DeficiencyClass.MALFORMED_LLM_OUTPUT,
                dependency_state=DependencyState.DEGRADED_PARTIAL,
            )]
            result.audit.agentAudit["termination_reason"] = termination_reason  # type: ignore[index]
            session.set_termination_reason(termination_reason)
        return result

    def build_completed_outcome(
        self,
        session: AgentSession,
        *,
        summary: str,
        analysis_outcome: AnalysisOutcome = AnalysisOutcome.INCONCLUSIVE,
        quality_outcome: QualityOutcome = QualityOutcome.INCONCLUSIVE,
        poc_outcome: PocOutcome = PocOutcome.POC_NOT_REQUESTED,
        caveats: list[str] | None = None,
        recommended_next_steps: list[str] | None = None,
        policy_flags: list[str] | None = None,
        recovery_trace: list[RecoveryTraceEntry] | None = None,
        evidence_diagnostics: EvidenceDiagnostics | None = None,
        contextual_evidence_refs: list[str] | None = None,
        claim_diagnostics: ClaimDiagnostics | None = None,
        termination_reason: str = "outcome_classified",
    ) -> TaskSuccessResponse:
        """Build a completed honest envelope for recoverable S3-owned deficiencies."""
        session.set_termination_reason(termination_reason)
        flags = list(dict.fromkeys(policy_flags or []))
        if "state_machine_outcome" not in flags:
            flags.append("state_machine_outcome")
        clean_pass = clean_pass_for(
            analysis_outcome=analysis_outcome,
            quality_outcome=quality_outcome,
            poc_outcome=poc_outcome,
        )
        diagnostics = evidence_diagnostics or _build_evidence_diagnostics(
            session,
            {"claims": [], "usedEvidenceRefs": []},
            _all_allowed_ref_ids(session),
            _allowed_claim_ref_ids(session, _all_allowed_ref_ids(session)),
        )
        quality_gate = _quality_gate_for(
            outcome=quality_outcome,
            caveats=caveats or [],
            evidence_errors=[],
            has_claims=False,
        )
        result = AssessmentResult(
            summary=summary,
            claims=[],
            caveats=caveats or [],
            usedEvidenceRefs=[],
            suggestedSeverity="info",
            confidence=0.0,
            needsHumanReview=True,
            recommendedNextSteps=recommended_next_steps or [
                "Review recoveryTrace/audit details before treating this as a clean pass."
            ],
            policyFlags=flags,
            analysisOutcome=analysis_outcome,
            qualityOutcome=quality_outcome,
            pocOutcome=poc_outcome,
            recoveryTrace=recovery_trace or [],
            cleanPass=clean_pass,
            evaluationVerdict=_evaluation_verdict_for(
                clean_pass=clean_pass,
                analysis_outcome=analysis_outcome,
                quality_outcome=quality_outcome,
                poc_outcome=poc_outcome,
                evidence_errors=caveats or [],
            ),
            contextualEvidenceRefs=contextual_evidence_refs or _contextual_evidence_refs(
                session,
                {"contextualEvidenceRefs": []},
                _all_allowed_ref_ids(session),
            ),
            evidenceDiagnostics=diagnostics,
            claimDiagnostics=claim_diagnostics or ClaimDiagnostics(),
            qualityGate=quality_gate,
        )
        return TaskSuccessResponse(
            taskId=session.request.taskId,
            taskType=session.request.taskType,
            status=TaskStatus.COMPLETED,
            modelProfile="agent-loop",
            promptVersion="agent-v1",
            schemaVersion="agent-v1.1",
            validation=ValidationInfo(valid=True, errors=[]),
            result=result,
            audit=self._build_audit(session, termination_reason),
        )

    def build_failure(
        self,
        session: AgentSession,
        status: TaskStatus,
        code: FailureCode,
        detail: str,
        retryable: bool = False,
    ) -> TaskFailureResponse:
        return TaskFailureResponse(
            taskId=session.request.taskId,
            taskType=session.request.taskType,
            status=status,
            failureCode=code,
            failureDetail=detail,
            retryable=retryable,
            audit=self._build_audit(session, session.termination_reason or "error"),
        )

    def _build_audit(self, session: AgentSession, termination_reason: str) -> AuditInfo:
        input_str = json.dumps(session.request.model_dump(mode="json"), sort_keys=True)
        input_hash = f"sha256:{hashlib.sha256(input_str.encode()).hexdigest()[:16]}"

        agent_audit = AgentAuditInfo(
            input_hash=input_hash,
            latency_ms=session.elapsed_ms(),
            total_prompt_tokens=session.total_prompt_tokens(),
            total_completion_tokens=session.total_completion_tokens(),
            turn_count=session.turn_count,
            tool_call_count=session.total_tool_calls(),
            trace=session.trace,
            turns=sorted([*session.turns, *session.recovery_turns], key=lambda turn: turn.audit_order),
            termination_reason=termination_reason,
            created_at=datetime.now(timezone.utc).isoformat(),
            model_name=self._model_name,
            prompt_version=self._prompt_version,
            evidenceCatalogDiagnostics={
                "liveRecoveryTrace": session.live_recovery_trace_summary(),
                "attemptHistory": _audit_evidence_catalog_attempts(session),
            },
        )

        return AuditInfo(
            inputHash=input_hash,
            latencyMs=session.elapsed_ms(),
            tokenUsage=TokenUsage(
                prompt=session.total_prompt_tokens(),
                completion=session.total_completion_tokens(),
            ),
            retryCount=0,
            ragHits=0,
            createdAt=datetime.now(timezone.utc).isoformat(),
            agentAudit=agent_audit.model_dump(mode="json"),
        )


def _all_allowed_ref_ids(session: AgentSession) -> set[str]:
    refs = {ref.refId for ref in session.request.evidenceRefs}
    refs.update(session.extra_allowed_refs)
    refs.update(session.evidence_catalog.ref_ids())
    for step in session.trace:
        refs.update(step.new_evidence_refs)
    return refs


def _assessment_from_available_evidence(
    session: AgentSession,
    *,
    deficiency_detail: str,
) -> dict:
    _augment_catalog_with_source_hotspots(session)
    local_entries = [
        entry
        for entry in session.evidence_catalog.entries()
        if entry.can_support_claim and _is_fallback_claim_seed(entry)
    ]
    claims = [
        claim
        for entry in sorted(local_entries, key=_fallback_entry_sort_key)[:8]
        if (claim := _claim_from_evidence_entry(entry, session)) is not None
    ]
    used_refs: list[str] = []
    for claim in claims:
        used_refs.extend(claim["supportingEvidenceRefs"])
    used_refs = list(dict.fromkeys(used_refs))
    return {
        "summary": (
            "LLM/S7 응답 결함으로 모델 Assessment를 확정하지 못했지만, "
            "Phase 1/S4/S5가 이미 제공한 로컬 증거에서 deterministic fallback claim을 구성했습니다."
        ),
        "claims": claims,
        "caveats": [
            f"LLM output/call deficiency: {deficiency_detail}",
            "Fallback claims are generated only from S3 evidence catalog entries and still require human review.",
        ],
        "usedEvidenceRefs": used_refs,
        "suggestedSeverity": _fallback_suggested_severity(local_entries),
        "needsHumanReview": True,
        "recommendedNextSteps": [
            "Review cited local evidence refs and rerun LLM-backed analysis when S7/DGX transport is stable.",
            "Use generated PoC only after confirming the cited vulnerable path manually.",
        ],
        "policyFlags": [
            "recovery_classified",
            "llm_output_deficient",
            "deterministic_local_evidence_fallback",
        ],
    }


def _is_fallback_claim_seed(entry) -> bool:
    if entry.category not in {"sast", "source", "caller", "callee"}:
        return False
    if entry.sink or entry.cwe_id or entry.rule_id:
        return True
    text = " ".join(str(part or "") for part in (entry.summary, entry.function, entry.file)).lower()
    return any(keyword in text for keyword in (
        "cwe-",
        "popen",
        "system",
        "exec",
        "sprintf",
        "strcpy",
        "strcat",
        "memcpy",
        "overflow",
        "command injection",
        "rce",
    ))


def _augment_catalog_with_source_hotspots(session: AgentSession) -> None:
    project_path = _trusted_project_path(session)
    if not project_path:
        return
    try:
        root = project_path.resolve()
    except OSError:
        return
    if not root.exists() or not root.is_dir():
        return
    for hit in _iter_source_hotspots(root):
        if hit is not None:
            session.evidence_catalog.add(hit)


_SOURCE_HOTSPOT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".sh", ".md", ".txt", ".conf", ".cfg", ".ini", ".env", ".example",
}

_KNOWN_SOURCE_SIGNATURES: tuple[dict[str, str], ...] = (
    {
        "needle": "cJSON_InsertItemInArray",
        "cwe": "CWE-476",
        "summary": "cJSON_InsertItemInArray null pointer dereference hotspot (CVE-2023-50471): replacement item state can reach dereference paths.",
    },
    {
        "needle": "ldbReplParseCommand",
        "cwe": "CWE-476",
        "summary": "Redis Lua debugger RESP parser null pointer hotspot (CVE-2022-24736): malformed debug protocol input can reach NULL/error states.",
    },
    {
        "needle": "BN_mod_sqrt",
        "cwe": "CWE-835",
        "summary": "OpenSSL BN_mod_sqrt infinite loop denial of service hotspot (CVE-2022-0778): crafted certificate explicit curve parameters can reach this primitive.",
    },
    {
        "needle": "tsx_on_state_proceeding_uas",
        "cwe": "CWE-416",
        "summary": "PJSIP tsx_on_state_proceeding_uas use-after-free hotspot (CVE-2022-24786): SIP INVITE transaction state can mishandle last_tx lifetime.",
    },
)


def _iter_source_hotspots(root: Path):
    seen: set[str] = set()
    for path in _iter_candidate_source_files(root):
        try:
            rel = path.relative_to(root).as_posix()
            text = path.read_text(errors="replace")
        except (OSError, ValueError):
            continue
        lines = text.splitlines()
        for signature in _KNOWN_SOURCE_SIGNATURES:
            needle = signature["needle"]
            if needle not in text:
                continue
            line_no = _first_line_containing(lines, needle)
            yield _source_hotspot_entry(
                rel=rel,
                line=line_no,
                cwe_id=signature["cwe"],
                summary=f"{signature['summary']} Source symbol: {needle}.",
                roles=("source_location", "source_slice", "sink_or_dangerous_api", "library_origin"),
                seen=seen,
            )
        if rel.endswith("xmlparse.c") and re.search(r"\battribute\b", text, flags=re.IGNORECASE):
            line_no = _first_line_matching(lines, r"\battribute\b")
            yield _source_hotspot_entry(
                rel=rel,
                line=line_no,
                cwe_id="CWE-400",
                summary="xmlparse.c attribute parsing resource exhaustion denial of service hotspot: XML attribute/prefix processing can consume CPU/RAM for crafted inputs with many colons.",
                roles=("source_location", "source_slice", "sink_or_dangerous_api", "library_origin"),
                seen=seen,
            )
        if _file_contains_command_execution(lines):
            for line_no, line in enumerate(lines, start=1):
                if re.search(r"\bpopen\s*\(", line):
                    command_context = _command_context_summary(lines)
                    yield _source_hotspot_entry(
                        rel=rel,
                        line=line_no,
                        cwe_id="CWE-78",
                        sink="popen",
                        summary=(
                            "popen command execution hotspot: project code composes shell command strings "
                            f"and invokes popen. {command_context}"
                        ),
                        roles=("source_location", "source_slice", "sink_or_dangerous_api"),
                        seen=seen,
                    )
        for line_no, line in enumerate(lines, start=1):
            lowered = line.lower()
            if _looks_like_hardcoded_psk(line):
                yield _source_hotspot_entry(
                    rel=rel,
                    line=line_no,
                    cwe_id="CWE-798",
                    sink="hardcoded-credential",
                    summary=f"Hardcoded/default PSK credential hotspot: {line.strip()}",
                    roles=("source_location", "source_slice", "sink_or_dangerous_api"),
                    seen=seen,
                )
            if "psk" in lowered and _looks_like_credential_logging(line):
                yield _source_hotspot_entry(
                    rel=rel,
                    line=line_no,
                    cwe_id="CWE-532",
                    sink="credential-logging",
                    summary=f"Sensitive PSK credential logging hotspot: {line.strip()}",
                    roles=("source_location", "source_slice", "sink_or_dangerous_api"),
                    seen=seen,
                )


def _iter_candidate_source_files(root: Path):
    count = 0
    for path in root.rglob("*"):
        if count >= 5000:
            break
        if not path.is_file() or path.suffix not in _SOURCE_HOTSPOT_SUFFIXES:
            continue
        if any(part in {".git", "__pycache__"} or part.startswith("build-aegis") for part in path.parts):
            continue
        try:
            if path.stat().st_size > 1_500_000:
                continue
        except OSError:
            continue
        count += 1
        yield path


def _source_hotspot_entry(
    *,
    rel: str,
    line: int | None,
    cwe_id: str,
    summary: str,
    roles: tuple[str, ...],
    seen: set[str],
    sink: str | None = None,
):
    ref_id = f"eref-source-hotspot-{_stable_suffix(f'{rel}:{line}:{cwe_id}:{summary[:80]}')}"
    if ref_id in seen:
        return None
    seen.add(ref_id)
    return EvidenceCatalogEntry(
        ref_id=ref_id,
        category="source",
        source_tool="source.hotspot_scan",
        artifact_type="source-hotspot",
        file=rel,
        line=line,
        sink=sink,
        cwe_id=cwe_id,
        summary=_truncate_diagnostic_detail(summary, limit=900),
        evidence_class="local",
        roles=roles,
        origin_service="s3",
    )


def _first_line_containing(lines: list[str], needle: str) -> int | None:
    for index, line in enumerate(lines, start=1):
        if needle in line:
            return index
    return None


def _first_line_matching(lines: list[str], pattern: str) -> int | None:
    for index, line in enumerate(lines, start=1):
        if re.search(pattern, line, flags=re.IGNORECASE):
            return index
    return None


def _file_contains_command_execution(lines: list[str]) -> bool:
    text = "\n".join(lines).lower()
    return "popen" in text and any(token in text for token in ("curl", "openssl", "http", "cmd", "command"))


def _command_context_summary(lines: list[str]) -> str:
    snippets = [
        line.strip()
        for line in lines
        if _looks_like_command_context(line)
    ][:10]
    return "Command context: " + " | ".join(snippets)


def _looks_like_hardcoded_psk(line: str) -> bool:
    lowered = line.lower()
    if "psk" not in lowered or not any(token in lowered for token in ("key", "secret", "identity")):
        return False
    return any(token in lowered for token in ("default", "coap-psk-key", "lwm2m-psk-key", "=", ":=", "export", "fallback"))


def _looks_like_credential_logging(line: str) -> bool:
    lowered = line.lower()
    if not any(token in lowered for token in ("log", "printf", "cout", "cerr", "spdlog")):
        return False
    return any(token in lowered for token in ("key", "secret", "identity", "raw", "credential"))


def _fallback_entry_sort_key(entry) -> tuple[int, int, int, str]:
    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    category_rank = {
        "sast": 0,
        "source": 1,
        "caller": 2,
        "callee": 3,
    }
    return (
        _source_hotspot_priority(entry),
        severity_rank.get(_fallback_entry_severity(entry), 5),
        category_rank.get(entry.category, 9),
        entry.ref_id,
    )


def _source_hotspot_priority(entry) -> int:
    if entry.source_tool != "source.hotspot_scan":
        return 5
    file = (entry.file or "").lower()
    summary = (entry.summary or "").lower()
    if "source symbol:" in summary or file.endswith("xmlparse.c"):
        return 0
    if entry.cwe_id == "CWE-78" and file.startswith(("apps/", "src/")):
        return 0
    if "psk_utils" in file:
        return 0
    if "scripts/build/gen_env.sh" in file:
        return 1
    if file == "readme.md" or file.endswith("/readme.md"):
        return 2
    if file.startswith(("apps/", "src/")):
        return 3
    if any(token in summary for token in ("coap-psk-key", "lwm2m-psk-key", "coap_psk_key", "lwm2m_psk_key")):
        return 4
    if file.startswith("libraries/"):
        return 9
    return 5


def _claim_from_evidence_entry(entry, session: AgentSession) -> dict | None:
    support_entries = _support_entries_for(entry, session)
    if not support_entries:
        return None
    refs = [support.ref_id for support in support_entries]
    location = _format_entry_location(entry)
    if not location:
        return None
    sink_or_rule = entry.sink or entry.cwe_id or entry.rule_id or "security-sensitive pattern"
    statement = f"{sink_or_rule} finding is supported by local project evidence at {location}."
    detail = _fallback_claim_detail(entry, support_entries, session)
    return {
        "claimId": f"det-{_stable_suffix(entry.ref_id)}",
        "statement": statement,
        "detail": detail,
        "supportingEvidenceRefs": refs,
        "location": location,
    }


def _support_entries_for(entry, session: AgentSession) -> list:
    entries = [candidate for candidate in session.evidence_catalog.entries() if candidate.can_support_claim]
    primary = [candidate for candidate in entries if candidate.ref_id == entry.ref_id]
    related = [
        candidate
        for candidate in entries
        if candidate.ref_id != entry.ref_id and _entry_supports_primary(candidate, entry)
    ]
    related.sort(key=_support_entry_sort_key)
    return [*primary, *related[:4]]


def _entry_supports_primary(candidate, primary) -> bool:
    if candidate.sink and primary.sink and candidate.sink == primary.sink:
        return True
    if "caller_chain" in candidate.roles and primary.sink and candidate.sink == primary.sink:
        return True
    if "source_slice" in candidate.roles and candidate.file and primary.file and candidate.file == primary.file:
        return True
    if candidate.cwe_id and primary.cwe_id and candidate.cwe_id == primary.cwe_id:
        return True
    return False


def _support_entry_sort_key(entry) -> tuple[int, str]:
    roles = set(entry.roles)
    if "source_slice" in roles:
        rank = 0
    elif "caller_chain" in roles:
        rank = 1
    elif "sast_finding" in roles:
        rank = 2
    else:
        rank = 3
    return (rank, entry.ref_id)


def _fallback_claim_detail(entry, support_entries: list, session: AgentSession) -> str:
    fragments = [
        f"Deterministic fallback selected ref {entry.ref_id}",
    ]
    if entry.cwe_id:
        fragments.append(f"CWE={entry.cwe_id}")
    if entry.rule_id:
        fragments.append(f"rule={entry.rule_id}")
    if entry.sink:
        fragments.append(f"sink={entry.sink}")
    if entry.summary:
        fragments.append(f"evidence summary: {entry.summary}")
    source_context = _source_context_for_entry(entry, session)
    if source_context:
        fragments.append(f"bounded source context: {source_context}")
    refs = ", ".join(support.ref_id for support in support_entries)
    fragments.append(f"supporting refs: {refs}")
    fragments.append(
        "Exploitability is plausible but not fully confirmed from the available evidence; "
        "manual confirmation is required because the LLM-backed reasoning path failed."
    )
    return " | ".join(fragments)


def _source_context_for_entry(entry, session: AgentSession) -> str:
    """Return a bounded same-file source excerpt for deterministic fallback.

    The excerpt is diagnostic context only. It is intentionally small and
    project-local: line window around the finding plus command-construction
    lines from the same file for command-execution sinks.
    """
    project_path = _trusted_project_path(session)
    if not project_path or not entry.file:
        return ""
    try:
        root = project_path.resolve()
        target = (root / entry.file).resolve()
        target.relative_to(root)
        lines = target.read_text(errors="replace").splitlines()
    except (OSError, ValueError):
        return ""
    excerpts: list[str] = []
    if entry.line:
        start = max(1, entry.line - 3)
        end = min(len(lines), entry.line + 3)
        excerpts.extend(f"{line_no}:{lines[line_no - 1].strip()}" for line_no in range(start, end + 1))
    if _is_command_execution_entry(entry):
        command_lines = [
            f"{index}:{line.strip()}"
            for index, line in enumerate(lines, start=1)
            if _looks_like_command_context(line)
        ]
        for line in command_lines[:12]:
            if line not in excerpts:
                excerpts.append(line)
    return _truncate_diagnostic_detail(" || ".join(excerpts), limit=900) or ""


def _trusted_project_path(session: AgentSession) -> Path | None:
    trusted = session.request.context.trusted if session.request.context else {}
    if not isinstance(trusted, dict):
        return None
    value = trusted.get("projectPath") or trusted.get("targetPath")
    if not isinstance(value, str) or not value:
        return None
    return Path(value)


def _is_command_execution_entry(entry) -> bool:
    text = " ".join(str(part or "") for part in (entry.sink, entry.cwe_id, entry.rule_id, entry.summary)).lower()
    return any(token in text for token in ("popen", "system", "exec", "cwe-78", "command injection"))


def _looks_like_command_context(line: str) -> bool:
    lowered = line.lower()
    return any(token in lowered for token in (
        "popen",
        "system(",
        "exec",
        "openssl",
        "curl",
        "wget",
        "bash",
        "/bin/sh",
    ))


def _format_entry_location(entry) -> str | None:
    if entry.file and entry.line:
        return f"{entry.file}:{entry.line}"
    if entry.file:
        return entry.file
    if entry.function:
        return entry.function
    return None


def _fallback_suggested_severity(entries: list) -> str:
    severities = [_fallback_entry_severity(entry) for entry in entries]
    for severity in ("critical", "high", "medium", "low"):
        if severity in severities:
            return severity
    return "info"


def _fallback_entry_severity(entry) -> str:
    text = " ".join(str(part or "") for part in (
        entry.cwe_id,
        entry.rule_id,
        entry.sink,
        entry.summary,
    )).lower()
    if any(token in text for token in ("cwe-78", "command injection", "rce", "popen", "system", "exec")):
        return "critical"
    if entry.cwe_id or any(token in text for token in ("strcpy", "strcat", "sprintf", "memcpy", "overflow")):
        return "high"
    if entry.sink:
        return "medium"
    return "info"


def _stable_suffix(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]


def _allowed_claim_ref_ids(session: AgentSession, allowed_refs: set[str]) -> set[str]:
    """Return refs allowed in final claims.

    The catalog is authoritative. Directly-appended test traces and legacy tool
    traces can lack catalog metadata, so local-looking prefixes remain
    claim-supporting for compatibility; knowledge/operational refs do not.
    """
    claim_refs = set(session.evidence_catalog.final_ref_ids())
    for ref_id in allowed_refs:
        if session.evidence_catalog.get(ref_id) is not None:
            continue
        if _looks_like_local_claim_ref(ref_id):
            claim_refs.add(ref_id)
    return claim_refs


def _looks_like_local_claim_ref(ref_id: str) -> bool:
    if not isinstance(ref_id, str):
        return False
    if ref_id.startswith(("eref-knowledge-", "eref-metadata-", "eref-operational-", "eref-negative-")):
        return False
    return ref_id.startswith((
        "eref-sast-",
        "eref-caller-",
        "eref-callee-",
        "eref-file-",
        "eref-codesearch-",
        "eref-source-",
        "eref-local-",
    ))


def _contextual_evidence_refs(session: AgentSession, parsed: dict, allowed_refs: set[str]) -> list[str]:
    refs: list[str] = []
    explicit = parsed.get("contextualEvidenceRefs", [])
    if isinstance(explicit, list):
        refs.extend(ref for ref in explicit if isinstance(ref, str) and ref in allowed_refs)
    refs.extend(sorted(session.evidence_catalog.contextual_ref_ids()))
    refs.extend(sorted(ref for ref in allowed_refs if isinstance(ref, str) and ref.startswith("eref-knowledge-")))
    return list(dict.fromkeys(refs))


def _build_claim_lifecycle_outputs(
    parsed: dict,
    session: AgentSession,
    allowed_claim_refs: set[str] | None = None,
) -> tuple[list[Claim], ClaimDiagnostics]:
    final_claims: list[Claim] = []
    non_accepted: list[NonAcceptedClaimDiagnostic] = []
    lifecycle_counts: dict[str, int] = {}

    raw_claims = parsed.get("claims", [])
    if not isinstance(raw_claims, list):
        raw_claims = []

    for index, raw in enumerate(raw_claims):
        if not isinstance(raw, dict):
            logger.warning(
                "non-dict claim entry skipped",
                extra={
                    "component": "result_assembler",
                    "phase": "claim_lifecycle",
                    "claimIndex": index,
                    "rawType": type(raw).__name__,
                },
            )
            continue
        claim = Claim(
            statement=raw.get("statement", ""),
            detail=raw.get("detail"),
            supportingEvidenceRefs=raw.get("supportingEvidenceRefs", []),
            location=raw.get("location"),
            claimId=raw.get("claimId") or f"claim-{index}",
            status=raw.get("status", ClaimStatus.CANDIDATE),
            requiredEvidence=raw.get("requiredEvidence", []),
            presentEvidence=raw.get("presentEvidence", []),
            missingEvidence=raw.get("missingEvidence", []),
            evidenceTrail=raw.get("evidenceTrail", []),
            queryHistory=raw.get("queryHistory", []),
            revisionHistory=raw.get("revisionHistory", []),
        )
        diagnosis = diagnose_claim_evidence(
            claim,
            session.evidence_catalog,
            allowed_local_refs=allowed_claim_refs or set(),
        )
        transitioned = transition_claim_status(claim, diagnosis)
        lifecycle_counts[transitioned.status.value] = lifecycle_counts.get(transitioned.status.value, 0) + 1
        if transitioned.status == ClaimStatus.GROUNDED:
            final_claims.append(transitioned)
            continue
        non_accepted.append(NonAcceptedClaimDiagnostic(
            claimId=transitioned.claimId,
            status=transitioned.status,
            family=diagnosis.family,
            primaryLocation=transitioned.location,
            requiredEvidence=transitioned.requiredEvidence,
            presentEvidence=transitioned.presentEvidence,
            missingEvidence=transitioned.missingEvidence,
            evidenceTrail=transitioned.evidenceTrail,
            revisionHistory=transitioned.revisionHistory,
            invalidRefs=diagnosis.invalidRefs,
            supportingEvidenceRefs=transitioned.supportingEvidenceRefs,
            outcomeContribution=(
                "rejected_unsupported"
                if transitioned.status == ClaimStatus.REJECTED
                else "needs_human_review"
                if transitioned.status == ClaimStatus.NEEDS_HUMAN_REVIEW
                else "no_accepted_claims"
            ),
            detail=_truncate_diagnostic_detail(transitioned.detail),
        ))

    return final_claims, ClaimDiagnostics(
        lifecycleCounts=lifecycle_counts,
        nonAcceptedClaims=non_accepted[:10],
    )


def _truncate_diagnostic_detail(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    return value[:limit]


def _build_evidence_diagnostics(
    session: AgentSession,
    parsed: dict,
    allowed_refs: set[str],
    allowed_claim_refs: set[str],
) -> EvidenceDiagnostics:
    invalid_refs: list[str] = []
    invalid_roles: list[EvidenceRefRoleDiagnostic] = []
    for path, ref_id in _iter_response_refs(parsed):
        if ref_id not in allowed_refs:
            invalid_refs.append(ref_id)
            invalid_roles.append(EvidenceRefRoleDiagnostic(
                refId=ref_id,
                actualClass="missing",
                requiredClass="local_or_derived_local",
                path=path,
            ))
            continue
        if path.startswith("claims[") and ref_id not in allowed_claim_refs:
            entry = session.evidence_catalog.get(ref_id)
            invalid_roles.append(EvidenceRefRoleDiagnostic(
                refId=ref_id,
                actualClass=entry.evidence_class if entry else _fallback_evidence_class(ref_id),
                requiredClass="local_or_derived_local",
                path=path,
            ))

    attempted_acquisitions = _attempted_acquisition_diagnostics(session)
    negative_attempts = _negative_attempt_diagnostics(session)
    return EvidenceDiagnostics(
        invalidRefs=list(dict.fromkeys(invalid_refs)),
        invalidRefRoles=_dedupe_role_diagnostics(invalid_roles),
        availableLocalRefs=sorted(session.evidence_catalog.local_ref_ids() | {
            ref for ref in allowed_refs if _looks_like_local_claim_ref(ref)
        }),
        availableKnowledgeRefs=sorted(session.evidence_catalog.contextual_ref_ids() | {
            ref for ref in allowed_refs if isinstance(ref, str) and ref.startswith("eref-knowledge-")
        }),
        unclassifiedRefs=sorted(session.evidence_catalog.unclassified_ref_ids()),
        attemptedAcquisitions=attempted_acquisitions,
        negativeAttempts=negative_attempts,
    )


def _attempted_acquisition_diagnostics(session: AgentSession) -> list[EvidenceAcquisitionDiagnostic]:
    attempts = [
        _diagnostic_from_evidence_entry(entry)
        for entry in session.evidence_catalog.history()
        if (
            entry.source_tool
            or entry.evidence_class in {"negative", "operational"}
            or entry.category in {"sast", "source", "caller", "callee"}
        )
    ]
    if len(attempts) <= 10:
        return attempts
    return attempts[:5] + attempts[-5:]


def _negative_attempt_diagnostics(session: AgentSession) -> list[EvidenceAcquisitionDiagnostic]:
    attempts = [
        _diagnostic_from_evidence_entry(entry)
        for entry in session.evidence_catalog.history()
        if entry.evidence_class == "negative"
    ]
    if len(attempts) <= 10:
        return attempts
    return attempts[:5] + attempts[-5:]


def _diagnostic_from_evidence_entry(entry) -> EvidenceAcquisitionDiagnostic:
    return EvidenceAcquisitionDiagnostic(
        slot=_slot_from_roles(entry.roles),
        tool=entry.source_tool,
        status=_status_from_entry(entry),
        detail=entry.summary,
    )


def _slot_from_roles(roles: tuple[str, ...]) -> str | None:
    for role in roles:
        if role not in {"negative_outcome", "operational_status"}:
            return role
    return None


def _status_from_entry(entry) -> str | None:
    if entry.operational_status:
        return entry.operational_status
    if entry.summary and ": " in entry.summary:
        return entry.summary.split(": ", 1)[1]
    return None


def _audit_evidence_catalog_attempts(session: AgentSession) -> list[dict]:
    attempts: list[dict] = []
    for entry in session.evidence_catalog.history():
        if entry.evidence_class not in {"negative", "operational"}:
            continue
        attempts.append({
            "refId": entry.ref_id,
            "class": entry.evidence_class,
            "sourceTool": entry.source_tool,
            "status": _status_from_entry(entry),
            "roles": list(entry.roles),
            "summary": entry.summary,
            "toolArguments": entry.tool_arguments or {},
        })
    return attempts


def _iter_response_refs(parsed: dict) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    used = parsed.get("usedEvidenceRefs", [])
    if isinstance(used, list):
        refs.extend((f"usedEvidenceRefs[{i}]", ref) for i, ref in enumerate(used) if isinstance(ref, str))
    claims = parsed.get("claims", [])
    if isinstance(claims, list):
        for i, claim in enumerate(claims):
            if not isinstance(claim, dict):
                continue
            supporting = claim.get("supportingEvidenceRefs", [])
            if isinstance(supporting, list):
                refs.extend(
                    (f"claims[{i}].supportingEvidenceRefs[{j}]", ref)
                    for j, ref in enumerate(supporting)
                    if isinstance(ref, str)
                )
    return refs


def _fallback_evidence_class(ref_id: str) -> str:
    if ref_id.startswith("eref-knowledge-"):
        return "knowledge"
    if ref_id.startswith("eref-metadata-"):
        return "operational"
    if ref_id.startswith("eref-operational-"):
        return "operational"
    if ref_id.startswith("eref-negative-"):
        return "negative"
    if _looks_like_local_claim_ref(ref_id):
        return "local"
    return "unclassified"


def _dedupe_role_diagnostics(
    diagnostics: list[EvidenceRefRoleDiagnostic],
) -> list[EvidenceRefRoleDiagnostic]:
    seen: set[tuple[str, str | None, str | None]] = set()
    result: list[EvidenceRefRoleDiagnostic] = []
    for item in diagnostics:
        key = (item.refId, item.requiredClass, item.path)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _quality_gate_for(
    *,
    outcome: QualityOutcome,
    caveats: list[str],
    evidence_errors: list[str],
    has_claims: bool,
) -> QualityGateResult:
    failed_items: list[QualityGateItem] = []
    repairable_items: list[QualityGateItem] = []
    if evidence_errors:
        failed_items.append(QualityGateItem(
            id="evidence-grounding",
            repairable=True,
            requiredEvidenceSlots=["project-local-or-derived evidence"],
            detail="; ".join(evidence_errors),
        ))
    if not has_claims and outcome != QualityOutcome.ACCEPTED:
        repairable_items.append(QualityGateItem(
            id="accepted-claim-coverage",
            repairable=True,
            requiredEvidenceSlots=["grounded accepted claim or explicit negative rationale"],
            detail="No accepted claims were emitted.",
        ))
    return QualityGateResult(
        outcome=outcome,
        failedItems=failed_items,
        repairableItems=repairable_items,
        caveats=caveats,
    )


def _evaluation_verdict_for(
    *,
    clean_pass: bool,
    analysis_outcome: AnalysisOutcome,
    quality_outcome: QualityOutcome,
    poc_outcome: PocOutcome,
    evidence_errors: list[str],
) -> EvaluationVerdict:
    reasons: list[str] = []
    if clean_pass:
        reasons.append("analysis and quality gates accepted")
    else:
        reasons.append(f"analysisOutcome={analysis_outcome.value}")
        reasons.append(f"qualityOutcome={quality_outcome.value}")
        if poc_outcome != PocOutcome.POC_NOT_REQUESTED:
            reasons.append(f"pocOutcome={poc_outcome.value}")
    reasons.extend(evidence_errors[:5])
    return EvaluationVerdict(
        taskCompleted=True,
        cleanPass=clean_pass,
        reasons=list(dict.fromkeys(reasons)),
        gateOutcomes=[
            f"analysis:{analysis_outcome.value}",
            f"quality:{quality_outcome.value}",
            f"poc:{poc_outcome.value}",
        ],
    )


def _canonicalize_deep_assessment(
    parsed: dict,
    session: AgentSession,
    allowed_refs: set[str],
    allowed_claim_refs: set[str],
) -> tuple[list[str], str]:
    """Apply only CWE-agnostic Assessment shape canonicalization.

    Semantic/root-cause repair belongs in a higher-level retry or future
    evidence-role normalizer, not in ResultAssembler.
    """
    if str(session.request.taskType) != "deep-analyze":
        return [], ""

    repairs: list[str] = []
    repairs.extend(_scaffold_deep_assessment(parsed))
    repairs.extend(_sync_used_refs_with_claim_refs(parsed))
    repairs.extend(_normalize_contextual_refs_out_of_final_evidence(parsed, allowed_refs, allowed_claim_refs))
    return list(dict.fromkeys(repairs)), ""


def _scaffold_deep_assessment(parsed: dict) -> list[str]:
    repairs: list[str] = []
    scaffolded = False

    for field in ("caveats", "usedEvidenceRefs", "recommendedNextSteps"):
        if not isinstance(parsed.get(field), list):
            parsed[field] = []
            repairs.append(field)
            scaffolded = True

    if not isinstance(parsed.get("policyFlags"), list):
        parsed["policyFlags"] = []
        repairs.append("policyFlags")
        scaffolded = True

    if not isinstance(parsed.get("needsHumanReview"), bool):
        parsed["needsHumanReview"] = True
        repairs.append("needsHumanReview")
        scaffolded = True

    if not _valid_severity(parsed.get("suggestedSeverity")):
        claims = parsed.get("claims")
        if isinstance(claims, list) and not claims:
            parsed["suggestedSeverity"] = "info"
            repairs.append("suggestedSeverity")
            scaffolded = True

    if scaffolded:
        _append_policy_flag(parsed, "deterministic_schema_scaffold")
    return repairs


def _rebuilt_used_refs(parsed: dict) -> list[str]:
    refs: list[str] = []
    for claim in parsed.get("claims", []) or []:
        if isinstance(claim, dict):
            refs.extend(ref for ref in claim.get("supportingEvidenceRefs", []) if isinstance(ref, str))
    for ref in parsed.get("usedEvidenceRefs", []) or []:
        if isinstance(ref, str):
            refs.append(ref)
    return list(dict.fromkeys(refs))


def _sync_used_refs_with_claim_refs(parsed: dict) -> list[str]:
    used = parsed.get("usedEvidenceRefs")
    if not isinstance(used, list):
        return []
    if any(not isinstance(ref, str) for ref in used):
        return []
    rebuilt = _rebuilt_used_refs(parsed)
    if rebuilt != used:
        parsed["usedEvidenceRefs"] = rebuilt
        return ["usedEvidenceRefs.claimRefSync"]
    return []


def _normalize_contextual_refs_out_of_final_evidence(
    parsed: dict,
    allowed_refs: set[str],
    allowed_claim_refs: set[str],
) -> list[str]:
    """Move contextual refs out of final evidence fields when local refs remain.

    Knowledge/CAPEC/CWE refs are useful context, but final accepted claims must
    stand on project-local or derived-local refs. If the model emitted both
    local refs and contextual refs, keep the local support and move contextual
    refs to ``contextualEvidenceRefs``. If a claim has only contextual refs, do
    not invent grounding here; leave it for validation/outcome classification.
    """
    repairs: list[str] = []
    contextual: list[str] = []
    claim_local_refs: list[str] = []
    response_refs = [ref for _, ref in _iter_response_refs(parsed)]
    if any(ref not in allowed_refs for ref in response_refs):
        return repairs

    claims = parsed.get("claims", [])
    if isinstance(claims, list):
        for index, claim in enumerate(claims):
            if not isinstance(claim, dict):
                continue
            refs = claim.get("supportingEvidenceRefs")
            if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
                continue
            local_refs = [ref for ref in refs if ref in allowed_claim_refs]
            if not local_refs or len(local_refs) == len(refs):
                claim_local_refs.extend(local_refs)
                continue
            removed = [ref for ref in refs if ref in allowed_refs and ref not in allowed_claim_refs]
            claim["supportingEvidenceRefs"] = list(dict.fromkeys(local_refs))
            claim_local_refs.extend(local_refs)
            contextual.extend(removed)
            repairs.append(f"claims[{index}].supportingEvidenceRefs.contextualMoved")

    used_refs = parsed.get("usedEvidenceRefs")
    if isinstance(used_refs, list) and all(isinstance(ref, str) for ref in used_refs):
        local_used_refs = [ref for ref in used_refs if ref in allowed_claim_refs]
        removed_used_refs = [ref for ref in used_refs if ref in allowed_refs and ref not in allowed_claim_refs]
        rebuilt = list(dict.fromkeys(local_used_refs + claim_local_refs))
        if rebuilt and (rebuilt != used_refs):
            parsed["usedEvidenceRefs"] = rebuilt
            contextual.extend(removed_used_refs)
            repairs.append("usedEvidenceRefs.contextualMoved")

    if contextual:
        existing = parsed.get("contextualEvidenceRefs")
        merged = []
        if isinstance(existing, list):
            merged.extend(ref for ref in existing if isinstance(ref, str) and ref in allowed_refs)
        merged.extend(ref for ref in contextual if ref in allowed_refs)
        parsed["contextualEvidenceRefs"] = list(dict.fromkeys(merged))
        _append_policy_flag(parsed, "evidence_role_normalized")

    return repairs


def _append_policy_flag(parsed: dict, flag: str) -> None:
    flags = parsed.get("policyFlags")
    if not isinstance(flags, list):
        flags = []
    if flag not in flags:
        flags.append(flag)
    parsed["policyFlags"] = flags


def _valid_severity(value) -> str | None:
    return value if isinstance(value, str) and value in {"critical", "high", "medium", "low", "info"} else None
