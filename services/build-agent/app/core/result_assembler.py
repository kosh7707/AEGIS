"""ResultAssembler — 에이전트 루프 출력을 TaskResponse 형식으로 변환."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from app.agent_runtime.observability import agent_log
from app.agent_runtime.schemas.agent import AgentAuditInfo
from app.pipeline.confidence import ConfidenceCalculator
from app.pipeline.response_parser import V1ResponseParser
from app.quality import build_quality_gate
from app.schemas.response import (
    ArtifactVerification,
    AssessmentResult,
    AuditInfo,
    BUILD_RESPONSE_SCHEMA_VERSION,
    BuildArtifact,
    BuildDiagnostics,
    BuildOutcome,
    BuildPreparation,
    BuildResult,
    Claim,
    FailureContext,
    SdkProfile,
    TaskFailureResponse,
    TaskSuccessResponse,
    TokenUsage,
    ValidationInfo,
)
from app.types import FailureCode, TaskStatus, TaskType
from app.validators.evidence_validator import EvidenceValidator
from app.validators.schema_validator import SchemaValidator

if TYPE_CHECKING:
    from app.core.agent_session import AgentSession

logger = logging.getLogger(__name__)

_BUILD_SUCCESS_REF = "eref-build-success"
_SDK_MISMATCH_KEYWORDS = (
    "sdk",
    "sysroot",
    "toolchain",
    "cross compiler",
    "compiler not found",
    "arm-none",
    "aarch64",
    "gnueabi",
)
_MISSING_MATERIALS_KEYWORDS = (
    "no such file or directory",
    "cannot find",
    "missing",
    "not found",
    "no rule to make target",
    "undefined reference",
    "fatal error:",
)
_SYNTHESIS_KEYWORDS = (
    "syntax error",
    "unexpected token",
    "build command is required",
    "failed to generate",
    "unable to write",
    "permission denied",
)


@dataclass(slots=True)
class _StrictContract:
    contract_version: str | None
    strict_mode: bool
    build_mode: str | None
    sdk_id: str | None
    expected_artifacts: list[str]
    expected_artifact_paths: list[str]


class ResultAssembler:
    """에이전트 루프의 최종 결과를 API 응답 형식으로 조립한다."""

    def __init__(self, model_name: str = "", prompt_version: str = "build-v3") -> None:
        self._parser = V1ResponseParser()
        self._schema_validator = SchemaValidator()
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
        parsed = self._parser.parse(final_content)
        fallback = parsed is None

        agent_log(
            logger, "결과 파싱",
            component="result_assembler", phase="result_parse",
            parsedOk=not fallback, fallbackApplied=fallback,
        )

        if parsed is None:
            parsed = {
                "summary": final_content[:2000],
                "claims": [],
                "caveats": ["LLM이 구조화된 JSON 대신 자연어로 응답함. 수동 검토 필요."],
                "usedEvidenceRefs": [],
                "needsHumanReview": True,
                "recommendedNextSteps": [],
                "policyFlags": ["unstructured_response"],
            }

        allowed_refs = {ref.refId for ref in session.request.evidenceRefs}
        for step in session.trace:
            allowed_refs.update(step.new_evidence_refs)
        corrections = self._sanitize_evidence_refs(parsed, allowed_refs)
        if corrections:
            agent_log(
                logger, "결과 근거 교정",
                component="result_assembler", phase="result_sanitize",
                correctionCount=len(corrections),
                corrections=corrections[:20],
            )
        schema_result = self._schema_validator.validate(parsed, session.request.taskType)
        evidence_valid, evidence_errors = self._evidence_validator.validate(parsed, allowed_refs)
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

        claims = [
            Claim(
                statement=c.get("statement", ""),
                detail=c.get("detail"),
                supportingEvidenceRefs=c.get("supportingEvidenceRefs", []),
                location=c.get("location"),
            )
            for c in parsed.get("claims", [])
        ]

        build_result = self._parse_build_result(parsed)
        sdk_profile = self._parse_sdk_profile(parsed)
        contract = self._extract_contract(session)
        if build_result is None and session.request.taskType == TaskType.BUILD_RESOLVE:
            parsed["_contractDeficiencyCode"] = FailureCode.BUILD_SCRIPT_SYNTHESIS_FAILED.value
            parsed["_contractDeficiencyDetail"] = "build-resolve 응답에 buildResult가 없어 빌드 결과를 확정할 수 없다."
            build_result = BuildResult(
                success=False,
                declaredMode=contract.build_mode,
                sdkId=contract.sdk_id,
                errorLog=parsed["_contractDeficiencyDetail"],
            )
        if build_result is not None:
            if build_result.declaredMode is None:
                build_result.declaredMode = contract.build_mode
            if build_result.sdkId is None:
                build_result.sdkId = contract.sdk_id
            self._augment_produced_artifacts_from_filesystem(session, build_result, contract)

        contract_failure = self._validate_compile_first_contract(
            session=session,
            parsed=parsed,
            build_result=build_result,
            contract=contract,
        )
        if contract_failure is not None:
            return contract_failure
        build_outcome = self._build_outcome(build_result, contract, parsed)
        build_diagnostics = self._build_diagnostics(build_result, contract, parsed)

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
            buildResult=build_result,
            buildPreparation=self._build_preparation(session, build_result, contract),
            sdkProfile=sdk_profile,
            buildOutcome=build_outcome,
            cleanPass=build_outcome.cleanPass if build_outcome is not None else False,
            buildDiagnostics=build_diagnostics,
        )

        agent_log(
            logger, "결과 조립 완료",
            component="result_assembler", phase="result_build",
            status="completed",
            claimCount=len(claims),
            severity=parsed.get("suggestedSeverity"),
            strictMode=contract.strict_mode,
            contractVersion=contract.contract_version,
        )

        return TaskSuccessResponse(
            taskId=session.request.taskId,
            taskType=session.request.taskType,
            contractVersion=contract.contract_version,
            strictMode=contract.strict_mode,
            status=TaskStatus.COMPLETED,
            modelProfile="agent-loop",
            promptVersion=self._prompt_version,
            schemaVersion=BUILD_RESPONSE_SCHEMA_VERSION,
            validation=validation,
            result=result,
            audit=self._build_audit(session, "content_returned"),
        )

    @staticmethod
    def _sanitize_evidence_refs(parsed: dict, allowed_ref_ids: set[str]) -> list[str]:
        """허용되지 않은 evidence ref를 제거한다."""
        corrections: list[str] = []

        def _sanitize(refs: list, location: str) -> list[str]:
            sanitized: list[str] = []
            seen: set[str] = set()
            for ref_id in refs:
                if not isinstance(ref_id, str):
                    continue
                if ref_id in allowed_ref_ids:
                    if ref_id not in seen:
                        sanitized.append(ref_id)
                        seen.add(ref_id)
                    continue
                corrections.append(f"{location}: '{ref_id}' 제거")
            return sanitized

        used_refs = parsed.get("usedEvidenceRefs", [])
        if isinstance(used_refs, list):
            parsed["usedEvidenceRefs"] = _sanitize(used_refs, "usedEvidenceRefs")

        claims = parsed.get("claims", [])
        if isinstance(claims, list):
            for i, claim in enumerate(claims):
                if not isinstance(claim, dict):
                    continue
                supporting = claim.get("supportingEvidenceRefs", [])
                if isinstance(supporting, list):
                    claim["supportingEvidenceRefs"] = _sanitize(
                        supporting, f"claims[{i}].supportingEvidenceRefs",
                    )

        return corrections

    _TERMINATION_MAP: dict[str, tuple[TaskStatus, FailureCode, bool]] = {
        "max_steps": (TaskStatus.BUDGET_EXCEEDED, FailureCode.MAX_STEPS_EXCEEDED, False),
        "budget_exhausted": (TaskStatus.BUDGET_EXCEEDED, FailureCode.TOKEN_BUDGET_EXCEEDED, False),
        "timeout": (TaskStatus.TIMEOUT, FailureCode.TIMEOUT, True),
        "no_new_evidence": (TaskStatus.BUDGET_EXCEEDED, FailureCode.INSUFFICIENT_EVIDENCE, False),
        "all_tiers_exhausted": (TaskStatus.BUDGET_EXCEEDED, FailureCode.ALL_TOOLS_EXHAUSTED, False),
    }

    def build_from_exhaustion(
        self,
        session: AgentSession,
    ) -> TaskFailureResponse:
        """정책에 의해 루프가 종료된 경우 실패 응답을 생성한다."""
        reason = session.termination_reason
        status, code, retryable = self._TERMINATION_MAP.get(
            reason,
            (TaskStatus.BUDGET_EXCEEDED, FailureCode.TOKEN_BUDGET_EXCEEDED, False),
        )
        return self.build_failure(
            session,
            status,
            code,
            f"에이전트 루프 종료: {reason}",
            retryable=retryable,
        )

    def build_failure(
        self,
        session: AgentSession,
        status: TaskStatus,
        code: FailureCode,
        detail: str,
        retryable: bool = False,
        failure_context: FailureContext | None = None,
    ) -> TaskFailureResponse:
        contract = self._extract_contract(session)
        return TaskFailureResponse(
            taskId=session.request.taskId,
            taskType=session.request.taskType,
            contractVersion=contract.contract_version,
            strictMode=contract.strict_mode,
            status=status,
            failureCode=code,
            failureDetail=detail,
            retryable=retryable,
            failureContext=failure_context,
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
            turns=session.turns,
            termination_reason=termination_reason,
            created_at=datetime.now(timezone.utc).isoformat(),
            model_name=self._model_name,
            prompt_version=self._prompt_version,
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

    def _parse_build_result(self, parsed: dict[str, Any]) -> BuildResult | None:
        build_result_data = parsed.get("buildResult")
        if not isinstance(build_result_data, dict):
            return None

        produced_artifacts = self._parse_build_artifacts(
            build_result_data.get("producedArtifacts")
            or build_result_data.get("artifacts")
            or parsed.get("producedArtifacts")
        )
        return BuildResult(
            success=bool(build_result_data.get("success", False)),
            declaredMode=build_result_data.get("declaredMode"),
            sdkId=build_result_data.get("sdkId"),
            buildCommand=build_result_data.get("buildCommand", "") or "",
            buildScript=build_result_data.get("buildScript", "") or "",
            buildDir=build_result_data.get("buildDir", "build-aegis") or "build-aegis",
            errorLog=build_result_data.get("errorLog"),
            producedArtifacts=produced_artifacts,
        )

    def _parse_sdk_profile(self, parsed: dict[str, Any]) -> SdkProfile | None:
        sdk_profile_data = parsed.get("sdkProfile")
        if not isinstance(sdk_profile_data, dict):
            return None
        return SdkProfile(
            compiler=sdk_profile_data.get("compiler", ""),
            compilerPrefix=sdk_profile_data.get("compilerPrefix", ""),
            gccVersion=sdk_profile_data.get("gccVersion", ""),
            targetArch=sdk_profile_data.get("targetArch", ""),
            languageStandard=sdk_profile_data.get("languageStandard", ""),
            sysroot=sdk_profile_data.get("sysroot", ""),
            environmentSetup=sdk_profile_data.get("environmentSetup", ""),
            includePaths=sdk_profile_data.get("includePaths", []),
            defines=sdk_profile_data.get("defines", {}),
        )

    def _build_preparation(
        self,
        session: AgentSession,
        build_result: BuildResult | None,
        contract: _StrictContract,
    ) -> BuildPreparation | None:
        if session.request.taskType != TaskType.BUILD_RESOLVE or build_result is None:
            return None

        trusted = session.request.context.trusted if isinstance(session.request.context.trusted, dict) else {}
        build_blob = trusted.get("build") if isinstance(trusted.get("build"), dict) else {}
        raw_build_environment = (
            trusted.get("buildEnvironment")
            if trusted.get("buildEnvironment") is not None
            else build_blob.get("environment")
        )
        build_environment = self._normalize_build_environment(raw_build_environment)
        raw_provenance = trusted.get("provenance")
        provenance = dict(raw_provenance) if isinstance(raw_provenance, dict) else {}
        produced_artifacts = [artifact.path or artifact.kind for artifact in build_result.producedArtifacts]
        return BuildPreparation(
            declaredMode=build_result.declaredMode or contract.build_mode,
            sdkId=build_result.sdkId or contract.sdk_id,
            buildCommand=build_result.buildCommand,
            buildScript=build_result.buildScript,
            buildDir=build_result.buildDir,
            buildEnvironment=build_environment,
            provenance=provenance,
            expectedArtifacts=contract.expected_artifacts,
            producedArtifacts=[item for item in produced_artifacts if item],
        )

    def _parse_build_artifacts(self, raw: Any) -> list[BuildArtifact]:
        if not isinstance(raw, list):
            return []

        artifacts: list[BuildArtifact] = []
        for item in raw:
            if isinstance(item, str):
                artifacts.append(BuildArtifact(path=item))
                continue
            if not isinstance(item, dict):
                continue
            artifacts.append(BuildArtifact(
                path=item.get("path") or item.get("artifactPath") or item.get("name") or "",
                kind=item.get("kind") or item.get("type") or "",
                exists=item.get("exists"),
                notes=item.get("notes") or item.get("detail"),
            ))
        return artifacts

    def _validate_compile_first_contract(
        self,
        *,
        session: AgentSession,
        parsed: dict[str, Any],
        build_result: BuildResult | None,
        contract: _StrictContract,
    ) -> TaskFailureResponse | None:
        """Apply strict build contract diagnostics without turning quality into task failure."""
        if session.request.taskType != TaskType.BUILD_RESOLVE:
            return None
        if not contract.strict_mode:
            return None

        if build_result is None:
            parsed["_contractDeficiencyCode"] = FailureCode.BUILD_SCRIPT_SYNTHESIS_FAILED.value
            parsed["_contractDeficiencyDetail"] = "strict compile contract에서는 buildResult가 필수다."
            return None

        if not build_result.buildCommand.strip() or not build_result.buildScript.strip():
            parsed["_contractDeficiencyCode"] = FailureCode.BUILD_SCRIPT_SYNTHESIS_FAILED.value
            parsed["_contractDeficiencyDetail"] = (
                "strict compile contract에서는 재사용 가능한 buildCommand/buildScript가 필수다."
            )
            return None

        if not build_result.success:
            return None

        if not self._has_build_success_evidence(session):
            parsed["_contractDeficiencyCode"] = FailureCode.INVALID_GROUNDING.value
            parsed["_contractDeficiencyDetail"] = (
                "strict compile contract에서는 try_build 성공 evidence가 없는 success 응답을 clean pass로 허용하지 않는다."
            )
            return None

        verification = self._verify_expected_artifacts(build_result, contract)
        if verification is not None:
            build_result.artifactVerification = verification

        return None

    def _classify_build_failure(
        self,
        build_result: BuildResult,
        parsed: dict[str, Any],
    ) -> tuple[FailureCode, str]:
        detail_parts = [
            build_result.errorLog or "",
            parsed.get("summary", "") or "",
            *[item for item in parsed.get("caveats", []) if isinstance(item, str)],
            *[item for item in parsed.get("policyFlags", []) if isinstance(item, str)],
        ]
        detail_blob = "\n".join(part for part in detail_parts if part).strip()
        lowered = detail_blob.lower()

        if not build_result.buildCommand.strip() or not build_result.buildScript.strip():
            return (
                FailureCode.BUILD_SCRIPT_SYNTHESIS_FAILED,
                detail_blob or "빌드 명령/스크립트를 합성하지 못했다.",
            )
        if any(keyword in lowered for keyword in _SDK_MISMATCH_KEYWORDS):
            return (FailureCode.SDK_MISMATCH, detail_blob or "선언된 SDK/툴체인과 실제 환경이 일치하지 않는다.")
        if any(keyword in lowered for keyword in _SYNTHESIS_KEYWORDS):
            return (
                FailureCode.BUILD_SCRIPT_SYNTHESIS_FAILED,
                detail_blob or "빌드 스크립트/명령 생성 또는 실행 준비에 실패했다.",
            )
        if any(keyword in lowered for keyword in _MISSING_MATERIALS_KEYWORDS):
            return (FailureCode.MISSING_BUILD_MATERIALS, detail_blob or "빌드에 필요한 파일/의존성이 누락되었다.")
        return (FailureCode.COMPILE_FAILED, detail_blob or "완전한 재료는 있었지만 compile/link 단계에서 실패했다.")

    def _build_outcome(
        self,
        build_result: BuildResult | None,
        contract: _StrictContract,
        parsed: dict[str, Any],
    ) -> BuildOutcome | None:
        contract_code, contract_detail = _contract_deficiency(parsed)
        if contract_code is not None:
            return BuildOutcome(
                outcome=build_quality_gate.build_outcome_value_for(contract_code),
                cleanPass=False,
                reasons=[contract_detail],
            )
        if build_result is None:
            return None
        if build_result.success:
            verification = build_result.artifactVerification
            if verification is not None and not verification.matched:
                return BuildOutcome(
                    outcome="artifact_mismatch",
                    cleanPass=False,
                    reasons=["expected artifacts did not match produced artifacts"],
                )
            return BuildOutcome(
                outcome="built",
                cleanPass=True,
                reasons=["buildResult.success=true", "no strict artifact mismatch"],
            )

        code, detail = self._classify_build_failure(build_result, parsed)
        return BuildOutcome(
            outcome=build_quality_gate.build_outcome_value_for(code),
            cleanPass=False,
            reasons=[detail],
        )

    def _build_diagnostics(
        self,
        build_result: BuildResult | None,
        contract: _StrictContract,
        parsed: dict[str, Any],
    ) -> BuildDiagnostics | None:
        if build_result is None:
            return None
        code, _ = _contract_deficiency(parsed)
        if code is None and not build_result.success:
            code, _ = self._classify_build_failure(build_result, parsed)
        produced = [artifact.path or artifact.kind for artifact in build_result.producedArtifacts]
        verification = build_result.artifactVerification
        if code is None and verification is not None and not verification.matched:
            code = FailureCode.EXPECTED_ARTIFACTS_MISMATCH
        return BuildDiagnostics(
            failureCode=code.value if code is not None else None,
            failureCategory=build_quality_gate.build_outcome_value_for(code) if code is not None else None,
            expectedArtifacts=contract.expected_artifacts,
            producedArtifacts=[item for item in produced if item],
            missingArtifacts=verification.missing if verification is not None else [],
            caveats=[item for item in parsed.get("caveats", []) if isinstance(item, str)],
        )

    def _extract_contract(self, session: AgentSession) -> _StrictContract:
        request = session.request
        metadata = request.metadata if isinstance(request.metadata, dict) else {}
        trusted = request.context.trusted if isinstance(request.context.trusted, dict) else {}
        contract_blob = metadata.get("buildContract") if isinstance(metadata.get("buildContract"), dict) else {}
        if not contract_blob and isinstance(trusted.get("buildContract"), dict):
            contract_blob = trusted["buildContract"]
        build_blob = trusted.get("build") if isinstance(trusted.get("build"), dict) else {}

        contract_version = self._pick_first_non_empty(
            getattr(request, "contractVersion", None),
            metadata.get("contractVersion"),
            contract_blob.get("contractVersion"),
            trusted.get("contractVersion"),
        )
        build_mode = self._pick_first_non_empty(
            getattr(request, "buildMode", None),
            metadata.get("buildMode"),
            contract_blob.get("buildMode"),
            contract_blob.get("mode"),
            build_blob.get("mode"),
            trusted.get("buildMode"),
        )
        sdk_id = self._pick_first_non_empty(
            getattr(request, "sdkId", None),
            metadata.get("sdkId"),
            contract_blob.get("sdkId"),
            build_blob.get("sdkId"),
            trusted.get("sdkId"),
        )
        strict_flag = self._pick_first_defined(
            getattr(request, "strictMode", None),
            metadata.get("strictMode"),
            contract_blob.get("strictMode"),
            trusted.get("strictMode"),
        )
        expected_raw = self._pick_first_defined(
            getattr(request, "expectedArtifacts", None),
            metadata.get("expectedArtifacts"),
            contract_blob.get("expectedArtifacts"),
            trusted.get("expectedArtifacts"),
        )
        expected_artifacts = self._normalize_artifact_list(expected_raw)
        expected_artifact_paths = self._extract_expected_artifact_paths(expected_raw)
        strict_mode = bool(strict_flag) or bool(contract_version)
        return _StrictContract(
            contract_version=contract_version,
            strict_mode=strict_mode,
            build_mode=build_mode,
            sdk_id=sdk_id,
            expected_artifacts=expected_artifacts,
            expected_artifact_paths=expected_artifact_paths,
        )

    @staticmethod
    def _pick_first_non_empty(*values: Any) -> str | None:
        for value in values:
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _pick_first_defined(*values: Any) -> Any:
        for value in values:
            if value is not None:
                return value
        return None

    @staticmethod
    def _normalize_build_environment(raw: Any) -> dict[str, str]:
        if not isinstance(raw, dict):
            return {}
        normalized: dict[str, str] = {}
        for key, value in raw.items():
            if not isinstance(key, str) or not key.strip() or not isinstance(value, str):
                continue
            normalized[key.strip()] = value
        return normalized

    def _normalize_artifact_list(self, raw: Any) -> list[str]:
        if not isinstance(raw, list):
            return []
        normalized: list[str] = []
        for item in raw:
            identity = self._artifact_identity(item)
            if identity and identity not in normalized:
                normalized.append(identity)
        return normalized

    def _extract_expected_artifact_paths(self, raw: Any) -> list[str]:
        if not isinstance(raw, list):
            return []
        paths: list[str] = []
        for item in raw:
            if isinstance(item, str):
                value = item.strip()
            elif isinstance(item, dict):
                value = (
                    item.get("path")
                    or item.get("name")
                    or item.get("artifactPath")
                    or item.get("file")
                    or ""
                )
                value = value.strip() if isinstance(value, str) else ""
            else:
                value = ""
            if value and value not in paths:
                paths.append(value)
        return paths

    def _augment_produced_artifacts_from_filesystem(
        self,
        session: AgentSession,
        build_result: BuildResult,
        contract: _StrictContract,
    ) -> None:
        trusted = session.request.context.trusted if isinstance(session.request.context.trusted, dict) else {}
        project_path = trusted.get("projectPath")
        build_target_path = trusted.get("buildTargetPath") or trusted.get("targetPath") or ""
        if not isinstance(project_path, str) or not project_path.strip():
            return

        build_root = os.path.join(project_path, build_target_path) if build_target_path else project_path
        build_root = os.path.normpath(build_root)
        build_dir = build_result.buildDir.strip() if build_result.buildDir else ""
        build_script_dir = ""
        if build_result.buildScript:
            script_path = PurePosixPath(build_result.buildScript.strip())
            if script_path.parent and str(script_path.parent) != ".":
                build_script_dir = str(script_path.parent)
        build_command_dir = ""
        if build_result.buildCommand:
            for token in build_result.buildCommand.split():
                if not token.endswith(".sh"):
                    continue
                script_token = PurePosixPath(token.strip().strip('"').strip("'"))
                if script_token.parent and str(script_token.parent) != ".":
                    build_command_dir = str(script_token.parent)
                    break

        existing_identities = {
            identity
            for artifact in build_result.producedArtifacts
            if (identity := self._artifact_identity({"path": artifact.path, "kind": artifact.kind}))
        }

        recursive_roots: list[str] = []

        def add_recursive_root(path: str) -> None:
            normalized = os.path.normpath(path)
            if normalized in recursive_roots or not os.path.isdir(normalized):
                return
            recursive_roots.append(normalized)

        current_rel_dirs: list[str] = []
        for rel_dir in (build_dir, build_script_dir, build_command_dir):
            rel_dir = rel_dir.strip().strip("/")
            if rel_dir and rel_dir not in current_rel_dirs:
                current_rel_dirs.append(rel_dir)
                add_recursive_root(os.path.join(build_root, rel_dir))

        # Some LLM-produced build scripts keep the reusable script under the
        # caller-provided buildDir (for example build-aegis-<hash>/aegis-build.sh)
        # but run CMake/Make with the conventional project-root build directory.
        # The successful try_build evidence proves a fresh build ran in this
        # request, so it is safe to search conventional output directories while
        # still refusing stale project-root binaries.
        for fallback_dir in ("build", "out", "bin", "dist"):
            add_recursive_root(os.path.join(build_root, fallback_dir))

        def is_under_current_dir(rel_path: str, rel_dir: str) -> bool:
            rel_posix = rel_path.replace("\\", "/").strip("/")
            rel_dir_posix = rel_dir.replace("\\", "/").strip("/")
            return rel_posix == rel_dir_posix or rel_posix.startswith(f"{rel_dir_posix}/")

        for raw_path in contract.expected_artifact_paths:
            normalized_raw = raw_path.strip().replace("\\", "/").strip("/")
            if not normalized_raw or normalized_raw.startswith("../") or "/../" in normalized_raw:
                continue
            candidates: list[str] = []
            if len(PurePosixPath(normalized_raw).parts) > 1:
                candidates.append(os.path.join(build_root, normalized_raw))
            if any(is_under_current_dir(normalized_raw, rel_dir) for rel_dir in current_rel_dirs):
                candidates.append(os.path.join(build_root, normalized_raw))
            for rel_dir in current_rel_dirs:
                if not is_under_current_dir(normalized_raw, rel_dir):
                    candidates.append(os.path.join(build_root, rel_dir, normalized_raw))

            for candidate in candidates:
                normalized_candidate = os.path.normpath(candidate)
                if not os.path.exists(normalized_candidate):
                    continue
                rel_path = os.path.relpath(normalized_candidate, build_root)
                identity = self._artifact_identity({"path": rel_path})
                if not identity or identity in existing_identities:
                    continue
                kind = "directory" if os.path.isdir(normalized_candidate) else "file"
                build_result.producedArtifacts.append(
                    BuildArtifact(path=rel_path, kind=kind, exists=True, notes="filesystem-inferred"),
                )
                existing_identities.add(identity)
                break
            else:
                discovered = self._find_nested_expected_artifact(
                    build_root=build_root,
                    recursive_roots=recursive_roots,
                    raw_path=raw_path,
                    existing_identities=existing_identities,
                )
                if discovered is None:
                    continue
                rel_path, kind, identity = discovered
                build_result.producedArtifacts.append(
                    BuildArtifact(path=rel_path, kind=kind, exists=True, notes="filesystem-inferred-recursive"),
                )
                existing_identities.add(identity)

    def _find_nested_expected_artifact(
        self,
        *,
        build_root: str,
        recursive_roots: list[str],
        raw_path: str,
        existing_identities: set[str],
    ) -> tuple[str, str, str] | None:
        normalized_raw = raw_path.strip().replace("\\", "/")
        if not normalized_raw:
            return None

        expected_tail = PurePosixPath(normalized_raw)
        expected_name = expected_tail.name
        if not expected_name:
            return None

        preferred_subdirs = ("build", "out", "bin", "dist")
        direct_candidates: list[str] = []
        for root in recursive_roots:
            direct_candidates.append(os.path.join(root, expected_name))
            for subdir in preferred_subdirs:
                direct_candidates.append(os.path.join(root, subdir, expected_name))

        for candidate in direct_candidates:
            if not os.path.exists(candidate):
                continue
            discovered = self._materialize_discovered_artifact(
                build_root=build_root,
                candidate=candidate,
                expected_tail=expected_tail,
                existing_identities=existing_identities,
            )
            if discovered is not None:
                return discovered

        for root in recursive_roots:
            try:
                root_path = Path(root)
                for current_root, dirnames, filenames in os.walk(root):
                    current_path = Path(current_root)
                    depth = len(current_path.relative_to(root_path).parts)
                    if depth >= 4:
                        dirnames[:] = []
                        continue
                    dirnames[:] = [
                        dirname for dirname in dirnames
                        if dirname not in {"CMakeFiles", ".git", "__pycache__"}
                    ]
                    for name in filenames:
                        if name != expected_name:
                            continue
                        candidate = os.path.join(current_root, name)
                        discovered = self._materialize_discovered_artifact(
                            build_root=build_root,
                            candidate=candidate,
                            expected_tail=expected_tail,
                            existing_identities=existing_identities,
                        )
                        if discovered is not None:
                            return discovered
            except OSError:
                continue
        return None

    def _materialize_discovered_artifact(
        self,
        *,
        build_root: str,
        candidate: str,
        expected_tail: PurePosixPath,
        existing_identities: set[str],
    ) -> tuple[str, str, str] | None:
        normalized_candidate = os.path.normpath(candidate)
        if not os.path.exists(normalized_candidate):
            return None
        rel_path = os.path.relpath(normalized_candidate, build_root)
        rel_posix = PurePosixPath(rel_path.replace(os.sep, "/"))
        if len(expected_tail.parts) > 1 and not str(rel_posix).endswith(str(expected_tail)):
            return None
        identity = self._artifact_identity({"path": rel_path})
        if not identity or identity in existing_identities:
            return None
        kind = "directory" if os.path.isdir(normalized_candidate) else "file"
        return rel_path, kind, identity

    def _verify_expected_artifacts(
        self,
        build_result: BuildResult,
        contract: _StrictContract,
    ) -> ArtifactVerification | None:
        if not contract.expected_artifacts:
            return None
        produced = [
            identity
            for artifact in build_result.producedArtifacts
            if (identity := self._artifact_identity({"path": artifact.path, "kind": artifact.kind}))
        ]
        produced_unique = list(dict.fromkeys(produced))
        missing = [expected for expected in contract.expected_artifacts if expected not in produced_unique]
        return ArtifactVerification(
            strict=True,
            expected=contract.expected_artifacts,
            produced=produced_unique,
            matched=not missing,
            missing=missing,
        )

    def _build_failure_context(
        self,
        build_result: BuildResult | None,
        contract: _StrictContract,
        missing_artifacts: list[str] | None = None,
    ) -> FailureContext:
        produced_artifacts = [artifact.path or artifact.kind for artifact in build_result.producedArtifacts] if build_result else []
        return FailureContext(
            buildCommand=build_result.buildCommand if build_result else None,
            buildScript=build_result.buildScript if build_result else None,
            buildDir=build_result.buildDir if build_result else None,
            expectedArtifacts=contract.expected_artifacts,
            producedArtifacts=[item for item in produced_artifacts if item],
            missingArtifacts=missing_artifacts or [],
            strictMode=contract.strict_mode,
            contractVersion=contract.contract_version,
        )

    @staticmethod
    def _has_build_success_evidence(session: AgentSession) -> bool:
        return any(_BUILD_SUCCESS_REF in step.new_evidence_refs for step in session.trace)

    def _artifact_identity(self, item: Any) -> str | None:
        if isinstance(item, str):
            return self._normalize_artifact_string(item)
        if not isinstance(item, dict):
            return None
        for key in ("path", "artifactPath", "name", "output", "file"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return self._normalize_artifact_string(value)
        kind = item.get("kind") or item.get("type")
        if isinstance(kind, str) and kind.strip():
            return kind.strip().lower()
        return None

    @staticmethod
    def _normalize_artifact_string(value: str) -> str:
        text = value.strip().lower()
        if not text:
            return ""
        path = PurePosixPath(text)
        if path.name and path.name != ".":
            return path.name
        return text


def _contract_deficiency(parsed: dict[str, Any]) -> tuple[FailureCode | None, str]:
    raw_code = parsed.get("_contractDeficiencyCode")
    if not isinstance(raw_code, str) or not raw_code:
        return None, ""
    try:
        code = FailureCode(raw_code)
    except ValueError:
        return None, ""
    detail = parsed.get("_contractDeficiencyDetail")
    if not isinstance(detail, str) or not detail.strip():
        detail = code.value
    return code, detail
