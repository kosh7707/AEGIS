"""Generate-POC task handler extracted from tasks router."""

from __future__ import annotations

import logging
import asyncio
import json
import copy
import re
import time

from app.config import settings
from app.agent_runtime.context import get_request_id
from app.agent_runtime.errors import BudgetExhaustedError
from app.agent_runtime.llm.generation_policy import STRICT_JSON_REPAIR, THINKING_CODING, controls_from_constraints
from app.agent_runtime.security.input_boundary import render_untrusted_source_for_llm
from app.core.evidence_catalog import EvidenceCatalog, EvidenceCatalogEntry
from app.runtime.request_summary import request_summary_tracker
from app.schemas.request import TaskRequest
from app.schemas.response import (
    AssessmentResult,
    AuditInfo,
    Claim,
    ClaimDiagnostics,
    EvaluationVerdict,
    NonAcceptedClaimDiagnostic,
    QualityGateResult,
    RecoveryTraceEntry,
    TaskFailureResponse,
    TaskSuccessResponse,
    TokenUsage,
    ValidationInfo,
)
from app.quality.poc_quality_gate import evaluate_poc_quality
from app.state_machine.claim import diagnose_claim_evidence, transition_claim_status
from app.state_machine.dependency_state import state_from_exception
from app.state_machine.outcomes import clean_pass_for
from app.state_machine.types import DependencyState
from app.types import AnalysisOutcome, ClaimStatus, FailureCode, PocOutcome, QualityOutcome, TaskStatus

logger = logging.getLogger(__name__)
_GENERATE_POC_LLM_STALL_SECONDS = 45.0


def _monotonic() -> float:
    return time.monotonic()


def _elapsed_ms(start: float) -> int:
    return int((_monotonic() - start) * 1000)


def _poc_quality_repair_max_attempts() -> int:
    """Configured cap for bounded PoC quality repair attempts."""
    return max(0, settings.poc_quality_repair_max_attempts)


def _generate_poc_completion_cap(request: TaskRequest) -> int:
    requested = request.constraints.maxTokens or settings.agent_llm_max_tokens
    return max(0, min(requested, settings.agent_max_completion_tokens))


def _generate_poc_remaining_repair_tokens(request: TaskRequest, used_completion_tokens: int) -> int:
    return max(0, _generate_poc_completion_cap(request) - max(0, used_completion_tokens))


def _generate_poc_repair_max_tokens(
    request: TaskRequest,
    used_completion_tokens: int,
    *,
    useful_minimum: int = 512,
) -> int:
    remaining = _generate_poc_remaining_repair_tokens(request, used_completion_tokens)
    if remaining < useful_minimum:
        raise BudgetExhaustedError(
            "generate-poc repair skipped: remaining completion-token budget below useful minimum"
        )
    return min(remaining, request.constraints.maxTokens or settings.agent_llm_max_tokens, settings.agent_llm_max_tokens)


def _build_generate_poc_evidence_catalog(
    *,
    request: TaskRequest,
    files: list,
    claim_supporting: list[str],
) -> EvidenceCatalog:
    """Build a PoC-local evidence catalog without fabricating slot-bearing refs."""
    catalog = EvidenceCatalog()
    catalog.ingest_request(request)

    for ref in request.evidenceRefs:
        entry = catalog.get(ref.refId)
        if entry is None:
            continue
        content = _generate_poc_file_content_for_ref(ref, files)
        sink = _generate_poc_infer_sink(content or "")
        roles = set(entry.roles)
        if entry.file:
            roles.add("source_location")
        if content:
            roles.add("source_slice")
        if sink:
            roles.add("sink_or_dangerous_api")
        if roles == set(entry.roles) and sink == entry.sink:
            continue
        catalog.add(EvidenceCatalogEntry(
            ref_id=entry.ref_id,
            category=entry.category,
            source_tool=entry.source_tool,
            tool_arguments=entry.tool_arguments,
            artifact_type=entry.artifact_type,
            file=entry.file,
            line=entry.line,
            function=entry.function,
            sink=sink or entry.sink,
            rule_id=entry.rule_id,
            cwe_id=entry.cwe_id,
            summary=entry.summary,
            callees=entry.callees,
            evidence_class=entry.evidence_class,
            roles=tuple(sorted(roles)),
            source_local_refs=entry.source_local_refs,
            origin_service=entry.origin_service,
            operational_status=entry.operational_status,
            project_id=entry.project_id,
            revision=entry.revision,
            build_snapshot=entry.build_snapshot,
        ))

    for ref_id in claim_supporting:
        if catalog.get(ref_id) is not None:
            continue
        catalog.add(EvidenceCatalogEntry(
            ref_id=ref_id,
            category="request",
            artifact_type="trusted-upstream-claim-ref",
            summary="trusted upstream bare claim ref",
            evidence_class="local",
            roles=(),
            origin_service="s3",
        ))
    return catalog


def _generate_poc_file_content_for_ref(ref, files: list) -> str | None:
    locator = ref.locator if isinstance(ref.locator, dict) else {}
    ref_file = locator.get("file") or locator.get("path")
    if not isinstance(ref_file, str) or not ref_file:
        return None
    ref_name = ref_file.rsplit("/", 1)[-1]
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        path = file_entry.get("path")
        if not isinstance(path, str):
            continue
        if path == ref_file or path.endswith("/" + ref_file) or path.rsplit("/", 1)[-1] == ref_name:
            content = file_entry.get("content")
            return content if isinstance(content, str) and content else None
    return None


def _generate_poc_infer_sink(text: str) -> str | None:
    patterns = {
        "exec": r"\bexec(?:ve|v|le|lp|l|p)?\b",
        "getenv": r"\bgetenv\b",
        "gets": r"\bgets\b",
        "memcpy": r"\bmemcpy\b",
        "popen": r"\bpopen\b",
        "readlink": r"\breadlink\b",
        "sprintf": r"\bsprintf\b",
        "strcpy": r"\bstrcpy\b",
        "system": r"\bsystem\b",
    }
    lowered = text.lower()
    for name, pattern in patterns.items():
        if re.search(pattern, lowered):
            return name
    return None


def _build_generate_poc_lifecycle_outputs(
    parsed: dict,
    catalog: EvidenceCatalog,
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
                "generate-poc non-dict claim entry skipped",
                extra={
                    "component": "generate_poc",
                    "phase": "poc_claim_lifecycle",
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
            claimId=raw.get("claimId") or f"poc-claim-{index}",
            status=raw.get("status", ClaimStatus.CANDIDATE),
            requiredEvidence=raw.get("requiredEvidence", []),
            presentEvidence=raw.get("presentEvidence", []),
            missingEvidence=raw.get("missingEvidence", []),
            evidenceTrail=raw.get("evidenceTrail", []),
            queryHistory=raw.get("queryHistory", []),
            revisionHistory=raw.get("revisionHistory", []),
        )
        diagnosis = diagnose_claim_evidence(claim, catalog)
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
            detail=_truncate_poc_diagnostic_detail(transitioned.detail),
        ))

    return final_claims, ClaimDiagnostics(
        lifecycleCounts=lifecycle_counts,
        nonAcceptedClaims=non_accepted[:10],
    )


def _truncate_poc_diagnostic_detail(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    return value[:limit]


async def handle_generate_poc(request: TaskRequest, model_registry) -> TaskSuccessResponse | TaskFailureResponse:
    """generate-poc 요청: 미니 Phase 1(KB 조회) + 단일 LLM 호출로 PoC 생성."""
    import hashlib
    import re
    from datetime import datetime, timezone

    import httpx

    from app.agent_runtime.context import get_request_id
    from app.agent_runtime.schemas.agent import BudgetState
    from app.agent_runtime.errors import StrictJsonContractError
    from app.agent_runtime.observability import agent_log
    from app.budget.manager import BudgetManager
    from app.pipeline.confidence import ConfidenceCalculator
    from app.pipeline.response_parser import V1ResponseParser
    from app.validators.evidence_validator import EvidenceValidator
    from app.validators.schema_validator import SchemaValidator

    start = _monotonic()
    trusted = request.context.trusted
    claim = trusted.get("claim", {})
    files = trusted.get("files", [])
    project_id = trusted.get("projectId")
    build_preparation = trusted.get("buildPreparation") or {}
    # Evidence refs carried by the input claim (typically produced by deep-analyze).
    # Used both in the user-message evidence list and later to widen allowed_refs
    # so the sanitizer does not strip refs that came from a trusted upstream result.
    _claim_sr = claim.get("supportingEvidenceRefs")
    claim_supporting: list[str] = (
        [r for r in _claim_sr if isinstance(r, str) and r] if isinstance(_claim_sr, list) else []
    )
    request_id = get_request_id() or request.taskId
    request_summary_tracker.mark_phase_advancing(request_id, source="generate-poc-start")

    agent_log(
        logger, "generate-poc 시작",
        component="generate_poc", phase="poc_start",
        claimLocation=claim.get("location"),
        fileCount=len(files),
    )

    if not _valid_input_claim(claim) or not isinstance(files, list) or not files:
        elapsed = _elapsed_ms(start)
        missing = []
        if not _valid_input_claim(claim):
            missing.append("context.trusted.claim(statement/detail/location)")
        if not isinstance(files, list) or not files:
            missing.append("context.trusted.files")
        return TaskFailureResponse(
            taskId=request.taskId,
            taskType=request.taskType,
            status=TaskStatus.VALIDATION_FAILED,
            failureCode=FailureCode.INVALID_SCHEMA,
            failureDetail="generate-poc invalid input: missing/invalid " + ", ".join(missing),
            retryable=False,
            audit=AuditInfo(
                inputHash="",
                latencyMs=elapsed,
                tokenUsage=TokenUsage(prompt=0, completion=0),
                retryCount=0,
                ragHits=0,
                createdAt=datetime.now(timezone.utc).isoformat(),
            ),
        )

    # ─── 미니 Phase 1: KB 컨텍스트 수집 ───
    kb_context_lines = []

    request_summary_tracker.mark_transport_only(request_id, source="kb-lookup")
    async with httpx.AsyncClient(base_url=settings.kb_endpoint, timeout=10.0) as kb:
        headers: dict[str, str] = {"X-Timeout-Ms": "10000"}
        if request_id:
            headers["X-Request-Id"] = request_id

        # 1. 호출자 체인 조회 (claim.location에서 함수명 추출)
        target_func = extract_function_from_claim(claim)
        if target_func and project_id:
            try:
                resp = await kb.get(
                    f"/v1/code-graph/{project_id}/callers/{target_func}",
                    params={"depth": 3},
                    headers=headers,
                )
                resp.raise_for_status()
                callers_data = resp.json()
                callers = callers_data.get("callers", [])
                if callers:
                    kb_context_lines.append(f"## 호출자 체인 ({target_func})")
                    for c in callers[:10]:
                        origin = ""
                        if c.get("origin"):
                            lib = c.get("original_lib") or c.get("originalLib") or "?"
                            origin = f" [{c['origin']}: {lib}]"
                        kb_context_lines.append(
                            f"- {c.get('name', '?')} ({c.get('file', '?')}:{c.get('line', '?')}){origin}"
                        )
                    kb_context_lines.append("")
            except Exception as e:
                agent_log(logger, f"PoC KB callers 조회 실패: {e}",
                          component="generate_poc", phase="kb_error", level=logging.WARNING)

        # 2. 위협 지식 검색 (CWE 기반)
        cwe_match = re.search(r"CWE-\d+", f"{claim.get('statement', '')} {claim.get('detail', '')}")
        if cwe_match:
            cwe_id = cwe_match.group(0)
            try:
                resp = await kb.post(
                    "/v1/search",
                    json={"query": cwe_id, "source_filter": ["CWE", "CAPEC"]},
                    headers=headers,
                )
                if resp.status_code != 200:
                    detail = resp.text[:200] if resp.text else str(resp.status_code)
                    agent_log(logger, f"PoC KB search 실패: {resp.status_code} — {detail}",
                              component="generate_poc", phase="kb_error", level=logging.WARNING)
                else:
                    hits = resp.json().get("hits", [])
                    if hits:
                        kb_context_lines.append(f"## 위협 지식 ({cwe_id})")
                        for h in hits:
                            kb_context_lines.append(
                                f"- [{h.get('source', '?')}/{h.get('id', '?')}] {h.get('title', '?')}"
                            )
                        kb_context_lines.append("")
            except Exception as e:
                agent_log(logger, f"PoC KB search 예외: {e}",
                          component="generate_poc", phase="kb_error", level=logging.WARNING)

    kb_context = "\n".join(kb_context_lines) if kb_context_lines else "(KB 컨텍스트 없음)"
    request_summary_tracker.mark_phase_advancing(request_id, source="kb-phase-complete")

    agent_log(
        logger, "generate-poc 미니 Phase 1 완료",
        component="generate_poc", phase="poc_phase1_end",
        kbContextLines=len(kb_context_lines),
    )

    # ─── LLM 프롬프트 조립 ───
    system_prompt = (
        "당신은 자동차 임베디드 보안 연구원입니다.\n"
        "정적 분석으로 발견된 취약점에 대한 PoC(Proof of Concept)를 작성합니다.\n\n"
        "## 당신의 임무\n"
        "1. 제공된 소스코드와 호출자 체인을 분석하여 취약점의 실제 트리거 조건을 파악하라\n"
        "2. 취약점 존재를 증명하는 최소한의 PoC 코드를 작성하라\n"
        "3. 실행 방법과 예상 결과를 명확하게 기술하라\n\n"
        "## PoC 작성 원칙\n"
        "- 취약점 존재를 **증명**하되, **파괴적 동작은 포함하지 마라** (id, whoami, echo 등 무해한 커맨드 사용)\n"
        "- PoC는 Python, curl, 또는 셸 스크립트로 작성하라 (재현 용이성 우선)\n"
        "- 실행 환경의 전제 조건 (타겟 서비스 기동, 포트, 인증 등)을 명시하라\n"
        "- 방어 우회가 필요한 경우 (ASLR, 스택 카나리 등) 그 한계를 caveat에 명시하라\n\n"
        "## Target metadata honesty\n"
        "빌드 산출물 이름, 컴파일 명령, 실행 방식은 **context에 주어진 것만 사용하라. 없으면 추측하지 말고 명시하라**:\n"
        "- 입력에 `Build metadata` 섹션이 있으면 거기 적힌 `buildCommand`/`buildScript`/`declaredMode`/`buildDir` 값을 그대로 사용\n"
        "- 없으면 PoC의 실행 방법 섹션에 `<unknown: please compile from source; check CMakeLists.txt/Makefile for target name>` 같이 명시적으로 표기\n"
        "- 바이너리 이름을 확신할 수 없으면 `./<binary-from-CMakeLists-add_executable>` 같이 플레이스홀더로 남겨 분석가가 채우도록\n\n"
        "## 출력 형식\n"
        "**순수 JSON만 출력하라. ```json 코드 펜스, 인사말, 설명문을 절대 붙이지 마라. 첫 문자는 반드시 `{`이어야 한다.**\n"
        "반드시 아래 스키마를 정확히 따라라:\n"
        "```json\n"
        "{\n"
        '  "summary": "PoC 요약 (1문장)",\n'
        '  "claims": [{\n'
        '    "statement": "PoC가 증명하는 취약점 (1문장)",\n'
        '    "detail": "## PoC 코드\\n```python\\n...코드...\\n```\\n\\n## 실행 방법\\n1. ...\\n\\n## 예상 결과\\n...",\n'
        '    "supportingEvidenceRefs": ["eref-file-00"],\n'
        '    "location": "src/파일.cpp:줄번호"\n'
        "  }],\n"
        '  "caveats": ["PoC의 한계, 전제 조건"],\n'
        '  "usedEvidenceRefs": ["eref-file-00"],\n'
        '  "suggestedSeverity": "critical",\n'
        '  "needsHumanReview": true,\n'
        '  "recommendedNextSteps": ["취약점 수정 방법"],\n'
        '  "policyFlags": []\n'
        "}\n"
        "```\n"
        "- summary, claims, caveats, usedEvidenceRefs는 **최상위 필드로 필수**이다.\n"
        "- claims 안에 caveats를 넣지 마라. caveats는 최상위 필드이다.\n"
        "- caveats가 없으면 필드를 생략하지 말고 반드시 `\"caveats\": []`로 출력하라.\n"
        "- usedEvidenceRefs가 없으면 필드를 생략하지 말고 반드시 `\"usedEvidenceRefs\": []`로 출력하라.\n"
    )

    # 소스코드 포맷팅 — source files are untrusted data, so render them through
    # the LLM-facing boundary before interpolation. Raw request context remains
    # unchanged for audit/evidence handling.
    source_sections = []
    for f in files[:5]:
        source_sections.append(
            render_untrusted_source_for_llm(
                str(f.get('path', '?')),
                str(f.get('content', '')),
                language="cpp",
            )
        )
    source_text = "\n\n".join(source_sections) if source_sections else "(소스코드 없음)"

    # Build metadata from caller (buildPreparation alias). Prevents LLM from inventing
    # binary names / compile commands when caller actually provided them.
    build_meta_lines: list[str] = []
    for key in ("declaredMode", "buildCommand", "buildScript", "buildDir"):
        value = build_preparation.get(key)
        if value:
            build_meta_lines.append(f"- **{key}**: `{value}`")
    expected_artifacts = build_preparation.get("expectedArtifacts")
    if isinstance(expected_artifacts, list) and expected_artifacts:
        names: list[str] = []
        for item in expected_artifacts:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict) and item.get("name"):
                names.append(str(item["name"]))
        if names:
            build_meta_lines.append(f"- **expectedArtifacts**: {', '.join(names)}")
    produced_artifacts = build_preparation.get("producedArtifacts")
    if isinstance(produced_artifacts, list) and produced_artifacts:
        parts: list[str] = []
        for item in produced_artifacts:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("path") or item.get("name") or item))
        if parts:
            build_meta_lines.append(f"- **producedArtifacts**: {', '.join(parts)}")
    if build_meta_lines:
        build_meta_section = "## Build metadata (caller-provided, use as-is)\n" + "\n".join(build_meta_lines) + "\n\n"
    else:
        build_meta_section = (
            "## Build metadata\n"
            "(no buildPreparation provided; do not invent binary names — state `<unknown>` or placeholder)\n\n"
        )

    user_message = (
        f"## 분석된 취약점\n"
        f"- **statement**: {claim.get('statement', '?')}\n"
        f"- **detail**: {claim.get('detail', '?')}\n"
        f"- **location**: {claim.get('location', '?')}\n\n"
        f"{build_meta_section}"
        f"{kb_context}\n\n"
        f"## 소스코드\n{source_text}\n\n"
        f"## 사용 가능한 Evidence Refs\n"
    )
    for ref in request.evidenceRefs:
        user_message += f"- `{ref.refId}` ({ref.artifactType}: {ref.locator.get('file', '?')})\n"
    # Also list refs carried by the input claim so the LLM can cite them in output.
    _top_level_ids = {ref.refId for ref in request.evidenceRefs}
    for r in claim_supporting:
        if r not in _top_level_ids:
            user_message += f"- `{r}` (carried over from input claim)\n"

    # ─── LLM 호출 (LlmCaller — adaptive timeout + X-Timeout-Seconds 적용) ───
    from app.agent_runtime.llm.caller import LlmCaller

    if settings.llm_mode == "real":
        profile = model_registry.get_default()
        llm = LlmCaller(
            endpoint=profile.endpoint if profile else settings.llm_endpoint,
            model=profile.modelName if profile else settings.llm_model,
            api_key=profile.apiKey if profile else settings.llm_api_key,
            default_max_tokens=request.constraints.maxTokens or 8192,
            service_id="s3-agent",
            async_poll_interval_seconds=settings.llm_async_poll_interval_seconds,
        )
    else:
        from app.agent_runtime.llm.static_caller import StaticLlmCaller

        llm = StaticLlmCaller(
            content='{"summary":"Mock PoC","claims":[{"statement":"mock","detail":"mock poc code","supportingEvidenceRefs":["eref-file-00"],"location":"clients/http_client.cpp:62"}],"caveats":[],"usedEvidenceRefs":["eref-file-00"],"suggestedSeverity":"info","needsHumanReview":true,"recommendedNextSteps":[],"policyFlags":[]}',
            prompt_tokens=100,
            completion_tokens=50,
        )

    schema_repair_used = False
    strict_json_retry_used = False
    # P7/§4.9: initial PoC drafting is a precise coding task, so it uses the
    # Qwen3.6 thinking-coding preset (T=0.6) rather than the broad-analysis
    # preset. Request constraints may override the tuple explicitly.
    coding_generation = controls_from_constraints(THINKING_CODING, request.constraints)
    # P7/§4.9: strict JSON retry, schema repair, and quality repair are narrow
    # correction tasks over an existing artifact, so they use the greedy repair
    # preset to avoid drifting away while the repair budget is bounded.
    strict_generation = controls_from_constraints(STRICT_JSON_REPAIR, request.constraints)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    try:
        request_summary_tracker.mark_transport_only(request_id, source="llm-inference")
        llm_response = await asyncio.wait_for(
            llm.call(
                messages,
                max_tokens=request.constraints.maxTokens or 8192,
                generation=coding_generation,
                prefer_async_ownership=True,
            ),
            timeout=_GENERATE_POC_LLM_STALL_SECONDS,
        )
        raw = llm_response.content or ""
        prompt_tokens = llm_response.prompt_tokens
        completion_tokens = llm_response.completion_tokens
        request_summary_tracker.mark_phase_advancing(request_id, source="llm-response")
    except StrictJsonContractError as e:
        strict_json_retry_used = True
        try:
            retry_messages = [
                *messages,
                {
                    "role": "user",
                    "content": (
                        "[시스템] S7 strict JSON contract violation이 발생했습니다. "
                        "동일한 요청을 순수 JSON Assessment 객체로 한 번만 재시도합니다. "
                        "설명문/코드펜스 없이 첫 문자는 반드시 `{`이어야 하며, 모든 required key를 포함하십시오."
                    ),
                },
            ]
            request_summary_tracker.mark_transport_only(request_id, source="llm-strict-json-retry")
            llm_response = await asyncio.wait_for(
                llm.call(
                    retry_messages,
                    max_tokens=request.constraints.maxTokens or 8192,
                    generation=strict_generation,
                    prefer_async_ownership=True,
                ),
                timeout=_GENERATE_POC_LLM_STALL_SECONDS,
            )
            raw = llm_response.content or ""
            prompt_tokens = llm_response.prompt_tokens
            completion_tokens = llm_response.completion_tokens
            request_summary_tracker.mark_phase_advancing(request_id, source="llm-strict-json-retry-response")
        except StrictJsonContractError as e2:
            if hasattr(llm, 'aclose'):
                await llm.aclose()
            return _build_poc_completed_outcome(
                request,
                start=start,
                prompt_tokens=0,
                completion_tokens=0,
                retry_count=1,
                rag_hits=0,
                deficiency="LLM_OUTPUT_DEFICIENT",
                action="strict_json_retry_exhausted",
                outcome=PocOutcome.POC_INCONCLUSIVE,
                detail=_strict_json_failure_detail(e2),
            )
        except Exception as e2:
            if hasattr(llm, 'aclose'):
                await llm.aclose()
            return _build_poc_llm_exception_response(
                request,
                start=start,
                prompt_tokens=0,
                completion_tokens=0,
                retry_count=1,
                rag_hits=len(kb_context_lines),
                action="strict_json_retry_failed",
                error=e2,
            )
    except Exception as e:
        if hasattr(llm, 'aclose'):
            await llm.aclose()
        return _build_poc_llm_exception_response(
            request,
            start=start,
            prompt_tokens=0,
            completion_tokens=0,
            retry_count=0,
            rag_hits=len(kb_context_lines),
            action="llm_call_failed",
            error=e,
        )

    # ─── 파싱 + 검증 ───
    parser = V1ResponseParser()
    parsed = parser.parse(raw)
    if parsed is None:
        try:
            schema_repair_max_tokens = _generate_poc_repair_max_tokens(request, completion_tokens)
            raw, repair_prompt_tokens, repair_completion_tokens = await _repair_generate_poc_schema(
                llm=llm,
                messages=messages,
                invalid_content=raw,
                schema_errors=["non-JSON output"],
                request=request,
                max_tokens=schema_repair_max_tokens,
                generation=strict_generation,
            )
        except Exception as e:
            if hasattr(llm, 'aclose'):
                await llm.aclose()
            return _build_poc_completed_outcome(
                request,
                start=start,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                retry_count=1 + int(strict_json_retry_used),
                rag_hits=len(kb_context_lines),
                deficiency="SCHEMA_DEFICIENT",
                action="schema_repair_call_failed",
                outcome=PocOutcome.POC_INCONCLUSIVE,
                detail=_schema_repair_failure_detail(e),
            )
        schema_repair_used = True
        prompt_tokens += repair_prompt_tokens
        completion_tokens += repair_completion_tokens
        parsed = parser.parse(raw)
        if parsed is None:
            if hasattr(llm, 'aclose'):
                await llm.aclose()
            return _build_poc_completed_outcome(
                request,
                start=start,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                retry_count=int(schema_repair_used) + int(strict_json_retry_used),
                rag_hits=len(kb_context_lines),
                deficiency="SCHEMA_DEFICIENT",
                action="outcome_classification",
                outcome=PocOutcome.POC_INCONCLUSIVE,
                detail="generate-poc strict schema repair did not return parseable JSON",
            )

    schema_probe = SchemaValidator().validate(parsed, request.taskType)
    if not schema_probe.valid:
        try:
            schema_repair_max_tokens = _generate_poc_repair_max_tokens(request, completion_tokens)
            raw, repair_prompt_tokens, repair_completion_tokens = await _repair_generate_poc_schema(
                llm=llm,
                messages=messages,
                invalid_content=raw,
                schema_errors=schema_probe.errors,
                request=request,
                max_tokens=schema_repair_max_tokens,
                generation=strict_generation,
            )
        except Exception as e:
            if hasattr(llm, 'aclose'):
                await llm.aclose()
            return _build_poc_completed_outcome(
                request,
                start=start,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                retry_count=1 + int(schema_repair_used) + int(strict_json_retry_used),
                rag_hits=len(kb_context_lines),
                deficiency="SCHEMA_DEFICIENT",
                action="schema_repair_call_failed",
                outcome=PocOutcome.POC_INCONCLUSIVE,
                detail=_schema_repair_failure_detail(e),
            )
        schema_repair_used = True
        prompt_tokens += repair_prompt_tokens
        completion_tokens += repair_completion_tokens
        parsed = parser.parse(raw)
        if parsed is None:
            if hasattr(llm, 'aclose'):
                await llm.aclose()
            return _build_poc_completed_outcome(
                request,
                start=start,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                retry_count=int(schema_repair_used) + int(strict_json_retry_used),
                rag_hits=len(kb_context_lines),
                deficiency="SCHEMA_DEFICIENT",
                action="outcome_classification",
                outcome=PocOutcome.POC_INCONCLUSIVE,
                detail="generate-poc schema repair returned non-JSON output",
            )
        agent_log(
            logger,
            "generate-poc strict schema repair applied",
            component="generate_poc",
            phase="poc_schema_repair",
            errors=schema_probe.errors,
        )

    if schema_repair_used:
        repaired_schema = SchemaValidator().validate(parsed, request.taskType)
        if not repaired_schema.valid:
            if hasattr(llm, 'aclose'):
                await llm.aclose()
            return _build_poc_completed_outcome(
                request,
                start=start,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                retry_count=int(schema_repair_used) + int(strict_json_retry_used),
                rag_hits=len(kb_context_lines),
                deficiency="SCHEMA_DEFICIENT",
                action="outcome_classification",
                outcome=PocOutcome.POC_REJECTED,
                detail="generate-poc schema repair failed: " + "; ".join(repaired_schema.errors),
            )

    if strict_json_retry_used:
        policy_flags = parsed.get("policyFlags")
        if isinstance(policy_flags, list) and "strict_json_retry" not in policy_flags:
            policy_flags.append("strict_json_retry")
            parsed["policyFlags"] = policy_flags

    evidence_catalog = _build_generate_poc_evidence_catalog(
        request=request,
        files=files,
        claim_supporting=claim_supporting,
    )

    # allowed_refs: request-level EvidenceRef IDs ∪ input claim's supportingEvidenceRefs.
    # Input claim's refs come from a trusted upstream (deep-analyze) result, so they are
    # treated as allowed by default — without this, the sanitizer strips them and grounding
    # collapses to the 0.3 ceiling even when the claim already carries valid refs.
    allowed_refs = {ref.refId for ref in request.evidenceRefs} | set(claim_supporting)
    evidence_validator = EvidenceValidator()
    raw_evidence_valid, raw_evidence_errors = evidence_validator.validate(parsed, allowed_refs)
    if not raw_evidence_valid:
        agent_log(
            logger,
            "generate-poc raw evidence refs invalid; deferring to lifecycle diagnostics",
            component="generate_poc",
            phase="poc_raw_ref_invalid",
            errors=raw_evidence_errors[:10],
            level=logging.WARNING,
        )
    lifecycle_source = copy.deepcopy(parsed)

    # raw grounding validation 이후의 방어적 ref cleanup
    from app.validators.evidence_sanitizer import EvidenceRefSanitizer
    sanitizer = EvidenceRefSanitizer()
    parsed, sanitize_corrections = sanitizer.sanitize(parsed, allowed_refs)
    if sanitize_corrections:
        from app.agent_runtime.observability import agent_log as _agent_log
        _agent_log(logger, "generate-poc evidence ref defensive cleanup",
                   component="generate_poc", phase="poc_sanitize",
                   corrections=sanitize_corrections[:10])

    schema_validator = SchemaValidator()
    schema_result = schema_validator.validate(parsed, request.taskType)
    evidence_valid, evidence_errors = evidence_validator.validate(parsed, allowed_refs)

    confidence_calc = ConfidenceCalculator()
    confidence, breakdown = confidence_calc.calculate(
        parsed, input_ref_ids=allowed_refs,
        schema_valid=schema_result.valid and evidence_valid,
        has_rule_results=True, rag_hits=len(kb_context_lines),
    )

    claims, claim_diagnostics = _build_generate_poc_lifecycle_outputs(lifecycle_source, evidence_catalog)

    input_str = json.dumps(request.model_dump(mode="json"), sort_keys=True)
    input_hash = f"sha256:{hashlib.sha256(input_str.encode()).hexdigest()[:16]}"

    raw_claim_count = len([c for c in parsed.get("claims", []) or [] if isinstance(c, dict)])
    if raw_claim_count > 0 and not claims:
        if hasattr(llm, 'aclose'):
            await llm.aclose()
        return _build_poc_completed_outcome(
            request,
            start=start,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            retry_count=int(schema_repair_used) + int(strict_json_retry_used),
            rag_hits=len(kb_context_lines),
            deficiency="POC_GROUNDING_DEFICIENT",
            action="poc_lifecycle_no_accepted_claims",
            outcome=PocOutcome.POC_REJECTED,
            detail="generate-poc lifecycle produced zero accepted claims; see claimDiagnostics.nonAcceptedClaims",
            analysis_outcome=AnalysisOutcome.NO_ACCEPTED_CLAIMS,
            claim_diagnostics=claim_diagnostics,
        )

    if not schema_result.valid or not evidence_valid or raw_claim_count == 0:
        errors = schema_result.errors + evidence_errors
        if raw_claim_count == 0:
            errors.append("generate-poc는 최소 1개 이상의 구조화된 claim을 반환해야 함")
        if hasattr(llm, 'aclose'):
            await llm.aclose()
        return _build_poc_completed_outcome(
            request,
            start=start,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            retry_count=int(schema_repair_used) + int(strict_json_retry_used),
            rag_hits=len(kb_context_lines),
            deficiency="POC_DEFICIENT",
            action="poc_outcome_classification",
            outcome=PocOutcome.POC_REJECTED if raw_claim_count == 0 else PocOutcome.POC_INCONCLUSIVE,
            detail="; ".join(errors),
            claim_diagnostics=claim_diagnostics,
        )

    quality_repair_attempts = 0
    quality_repair_max_attempts = _poc_quality_repair_max_attempts()
    quality_repair_budget_exhausted = False
    quality_repair_failed = False
    repair_budget = BudgetManager(BudgetState(
        max_completion_tokens=settings.agent_max_completion_tokens,
        max_prompt_tokens=settings.agent_max_prompt_tokens,
    ))
    repair_budget.record_tokens(prompt_tokens, completion_tokens)
    quality_gate = evaluate_poc_quality(claims=claims, caveats=parsed.get("caveats", []))
    while (
        quality_gate.outcome == QualityOutcome.REJECTED
        and any(item.repairable for item in quality_gate.failedItems)
        and quality_repair_attempts < quality_repair_max_attempts
    ):
        remaining_repair_tokens = _generate_poc_remaining_repair_tokens(request, completion_tokens)
        repair_completion_estimate = min(remaining_repair_tokens, settings.agent_llm_max_tokens)
        if repair_budget.would_exceed_after_repair(completion_tokens_estimate=repair_completion_estimate):
            quality_repair_budget_exhausted = True
            break
        try:
            quality_repair_max_tokens = _generate_poc_repair_max_tokens(request, completion_tokens)
        except BudgetExhaustedError:
            quality_repair_budget_exhausted = True
            break
        quality_repair_attempts += 1
        try:
            raw, repair_prompt_tokens, repair_completion_tokens = await _repair_generate_poc_quality(
                llm=llm,
                messages=messages,
                parsed=parsed,
                quality_gate=quality_gate,
                request=request,
                max_tokens=quality_repair_max_tokens,
                generation=strict_generation,
            )
        except Exception as e:
            quality_repair_failed = True
            logger.warning("PoC quality repair attempt %d failed: %s",
                quality_repair_attempts,
                e,
                extra={
                    "component": "generate_poc",
                    "phase": "quality_repair_failure",
                    "attempt": quality_repair_attempts,
                    "error": str(e),
                },
            )
            break
        prompt_tokens += repair_prompt_tokens
        completion_tokens += repair_completion_tokens
        repair_budget.record_tokens(repair_prompt_tokens, repair_completion_tokens)
        repaired = parser.parse(raw)
        if repaired is None:
            break
        repaired_schema = schema_validator.validate(repaired, request.taskType)
        if not repaired_schema.valid:
            break
        repaired_evidence_valid, repaired_evidence_errors = evidence_validator.validate(repaired, allowed_refs)
        if not repaired_evidence_valid:
            break
        parsed = repaired
        schema_result = repaired_schema
        evidence_valid = repaired_evidence_valid
        evidence_errors = repaired_evidence_errors
        confidence, breakdown = confidence_calc.calculate(
            parsed, input_ref_ids=allowed_refs,
            schema_valid=schema_result.valid and evidence_valid,
            has_rule_results=True, rag_hits=len(kb_context_lines),
        )
        claims, claim_diagnostics = _build_generate_poc_lifecycle_outputs(parsed, evidence_catalog)
        if not claims:
            break
        quality_gate = evaluate_poc_quality(claims=claims, caveats=parsed.get("caveats", []))

    quality_outcome = quality_gate.outcome
    if quality_gate.outcome == QualityOutcome.REJECTED:
        if hasattr(llm, 'aclose'):
            await llm.aclose()
        # Only repairable quality gaps can become "repair exhausted".
        # Hard safety failures must remain poc_rejected even when the
        # configured repair cap is zero.
        repairable_quality_failure = any(item.repairable for item in quality_gate.failedItems)
        exhausted = repairable_quality_failure and (
            quality_repair_budget_exhausted
            or quality_repair_failed
            or quality_repair_attempts >= quality_repair_max_attempts
        )
        return _build_poc_completed_outcome(
            request,
            start=start,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            retry_count=int(schema_repair_used) + int(strict_json_retry_used) + quality_repair_attempts,
            rag_hits=len(kb_context_lines),
            deficiency="POC_QUALITY_DEFICIENT",
            action="poc_quality_repair_exhausted" if exhausted else "poc_quality_rejected",
            outcome=PocOutcome.POC_INCONCLUSIVE if exhausted else PocOutcome.POC_REJECTED,
            detail=_quality_failure_detail(quality_gate),
            quality_outcome=QualityOutcome.REPAIR_EXHAUSTED if exhausted else QualityOutcome.REJECTED,
            quality_gate=quality_gate,
            claim_diagnostics=claim_diagnostics,
        )

    if hasattr(llm, 'aclose'):
        await llm.aclose()
    elapsed = _elapsed_ms(start)
    agent_log(
        logger, "generate-poc 완료",
        component="generate_poc", phase="poc_end",
        claimCount=len(claims), latencyMs=elapsed,
        promptTokens=prompt_tokens, completionTokens=completion_tokens,
        qualityRepairAttempts=quality_repair_attempts,
    )
    clean_pass = clean_pass_for(
        analysis_outcome=AnalysisOutcome.ACCEPTED_CLAIMS,
        quality_outcome=quality_outcome,
        poc_outcome=PocOutcome.POC_ACCEPTED,
    )
    evaluation_verdict = _poc_evaluation_verdict_for(
        clean_pass=clean_pass,
        analysis_outcome=AnalysisOutcome.ACCEPTED_CLAIMS,
        quality_outcome=quality_outcome,
        poc_outcome=PocOutcome.POC_ACCEPTED,
    )

    return TaskSuccessResponse(
        taskId=request.taskId,
        taskType=request.taskType,
        status=TaskStatus.COMPLETED,
        modelProfile="poc-v1",
        promptVersion="generate-poc-v1",
        schemaVersion="agent-v1.1",
        validation=ValidationInfo(
            valid=schema_result.valid and evidence_valid,
            errors=schema_result.errors + evidence_errors,
        ),
        result=AssessmentResult(
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
            analysisOutcome=AnalysisOutcome.ACCEPTED_CLAIMS,
            qualityOutcome=quality_outcome,
            pocOutcome=PocOutcome.POC_ACCEPTED,
            recoveryTrace=[],
            cleanPass=clean_pass,
            evaluationVerdict=evaluation_verdict,
            qualityGate=quality_gate,
            claimDiagnostics=claim_diagnostics,
        ),
        audit=AuditInfo(
            inputHash=input_hash,
            latencyMs=elapsed,
            tokenUsage=TokenUsage(prompt=prompt_tokens, completion=completion_tokens),
            retryCount=int(schema_repair_used) + int(strict_json_retry_used) + quality_repair_attempts,
            ragHits=len(kb_context_lines),
            createdAt=datetime.now(timezone.utc).isoformat(),
        ),
    )

def extract_function_from_claim(claim: dict) -> str | None:
    """claim의 statement/detail에서 위험 함수명을 추출한다."""
    import re
    text = f"{claim.get('statement', '')} {claim.get('detail', '')}"
    # 위험 함수 목록에서 매칭
    dangerous = {"popen", "system", "exec", "getenv", "readlink", "strcpy", "sprintf", "gets"}
    for func in dangerous:
        if func in text.lower():
            return func
    # 일반 함수명 패턴 (xxx() 형태)
    match = re.search(r"\b([a-zA-Z_]\w+)\(\)", text)
    return match.group(1) if match else None


def _valid_input_claim(claim: object) -> bool:
    if not isinstance(claim, dict):
        return False
    return all(
        isinstance(claim.get(field), str) and claim[field].strip()
        for field in ("statement", "detail", "location")
    )


def _build_poc_completed_outcome(
    request: TaskRequest,
    *,
    start: float,
    prompt_tokens: int,
    completion_tokens: int,
    retry_count: int,
    rag_hits: int,
    deficiency: str,
    action: str,
    outcome: PocOutcome,
    detail: str,
    analysis_outcome: AnalysisOutcome = AnalysisOutcome.INCONCLUSIVE,
    quality_outcome: QualityOutcome = QualityOutcome.REJECTED,
    quality_gate: QualityGateResult | None = None,
    claim_diagnostics: ClaimDiagnostics | None = None,
) -> TaskSuccessResponse:
    """Return completed PoC outcome for valid-input/live-runtime deficiencies."""
    import hashlib
    import time
    from datetime import datetime, timezone

    input_str = json.dumps(request.model_dump(mode="json"), sort_keys=True)
    input_hash = f"sha256:{hashlib.sha256(input_str.encode()).hexdigest()[:16]}"
    elapsed = int((time.monotonic() - start) * 1000)
    trace = RecoveryTraceEntry(
        deficiency=deficiency,
        action=action,
        outcome=outcome.value,
        detail=detail,
    )
    policy_flags = ["state_machine_outcome", "poc_recovery_classified"]
    if quality_outcome == QualityOutcome.REPAIR_EXHAUSTED:
        policy_flags.append("repair_exhausted")
    return TaskSuccessResponse(
        taskId=request.taskId,
        taskType=request.taskType,
        status=TaskStatus.COMPLETED,
        modelProfile="poc-v1",
        promptVersion="generate-poc-v1",
        schemaVersion="agent-v1.1",
        validation=ValidationInfo(valid=True, errors=[]),
        result=AssessmentResult(
            summary="S3 PoC 검토는 완료되었지만 PoC를 정직하게 accepted 상태로 확정하지 못했습니다.",
            claims=[],
            caveats=[detail] if detail else [],
            usedEvidenceRefs=[],
            suggestedSeverity="info",
            confidence=0.0,
            needsHumanReview=True,
            recommendedNextSteps=[
                "Review recoveryTrace/audit details before treating this as a clean PoC pass."
            ],
            policyFlags=policy_flags,
            analysisOutcome=analysis_outcome,
            qualityOutcome=quality_outcome,
            pocOutcome=outcome,
            recoveryTrace=[trace],
            cleanPass=False,
            evaluationVerdict=EvaluationVerdict(
                taskCompleted=True,
                cleanPass=False,
                reasons=[f"pocOutcome={outcome.value}", detail] if detail else [f"pocOutcome={outcome.value}"],
                gateOutcomes=[
                    f"analysis:{analysis_outcome.value}",
                    f"quality:{quality_outcome.value}",
                    f"poc:{outcome.value}",
                ],
            ),
            claimDiagnostics=claim_diagnostics or ClaimDiagnostics(),
            qualityGate=quality_gate or QualityGateResult(
                outcome=quality_outcome,
                caveats=[detail] if detail else [],
            ),
        ),
        audit=AuditInfo(
            inputHash=input_hash,
            latencyMs=elapsed,
            tokenUsage=TokenUsage(prompt=prompt_tokens, completion=completion_tokens),
            retryCount=retry_count,
            ragHits=rag_hits,
            createdAt=datetime.now(timezone.utc).isoformat(),
        ),
    )


def _build_poc_llm_exception_response(
    request: TaskRequest,
    *,
    start: float,
    prompt_tokens: int,
    completion_tokens: int,
    retry_count: int,
    rag_hits: int,
    action: str,
    error: Exception,
) -> TaskSuccessResponse | TaskFailureResponse:
    """Classify generate-poc LLM exceptions without conflating output quality with availability.

    Only invalid-input/true dependency/hard-deadline boundaries remain public
    task failures. Unknown model-output/client deficiencies become completed
    inconclusive envelopes so callers can still consume a stable result shape.
    """
    import time
    from datetime import datetime, timezone

    dependency_state = state_from_exception(error)
    detail = f"{action}: {error}"
    retryable = bool(getattr(error, "retryable", True))
    error_code = getattr(error, "code", "")
    elapsed = int((time.monotonic() - start) * 1000)

    if error_code == "INPUT_TOO_LARGE":
        return TaskFailureResponse(
            taskId=request.taskId,
            taskType=request.taskType,
            status=TaskStatus.VALIDATION_FAILED,
            failureCode=FailureCode.INPUT_TOO_LARGE,
            failureDetail=detail,
            retryable=False,
            audit=AuditInfo(
                inputHash="",
                latencyMs=elapsed,
                tokenUsage=TokenUsage(prompt=prompt_tokens, completion=completion_tokens),
                retryCount=retry_count,
                ragHits=rag_hits,
                createdAt=datetime.now(timezone.utc).isoformat(),
            ),
        )

    if dependency_state == DependencyState.DEADLINE_EXCEEDED:
        return _build_poc_completed_outcome(
            request,
            start=start,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            retry_count=retry_count,
            rag_hits=rag_hits,
            deficiency="LLM_TIMEOUT_RECOVERED",
            action=action,
            outcome=PocOutcome.POC_INCONCLUSIVE,
            detail=(
                detail
                + "; S3 returned a completed inconclusive PoC envelope "
                "because the valid-input/live-runtime path can still assemble a schema-valid response."
            ),
        )

    if dependency_state == DependencyState.UNAVAILABLE:
        return TaskFailureResponse(
            taskId=request.taskId,
            taskType=request.taskType,
            status=TaskStatus.MODEL_ERROR,
            failureCode=FailureCode.MODEL_UNAVAILABLE,
            failureDetail=detail,
            retryable=retryable,
            audit=AuditInfo(
                inputHash="",
                latencyMs=elapsed,
                tokenUsage=TokenUsage(prompt=prompt_tokens, completion=completion_tokens),
                retryCount=retry_count,
                ragHits=rag_hits,
                createdAt=datetime.now(timezone.utc).isoformat(),
            ),
        )

    return _build_poc_completed_outcome(
        request,
        start=start,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        retry_count=retry_count,
        rag_hits=rag_hits,
        deficiency="LLM_OUTPUT_DEFICIENT",
        action=action,
        outcome=PocOutcome.POC_INCONCLUSIVE,
        detail=detail,
    )



def _poc_evaluation_verdict_for(
    *,
    clean_pass: bool,
    analysis_outcome: AnalysisOutcome,
    quality_outcome: QualityOutcome,
    poc_outcome: PocOutcome,
) -> EvaluationVerdict:
    reasons = (
        ["analysis, quality, and PoC gates accepted"]
        if clean_pass
        else [
            f"analysisOutcome={analysis_outcome.value}",
            f"qualityOutcome={quality_outcome.value}",
            f"pocOutcome={poc_outcome.value}",
        ]
    )
    return EvaluationVerdict(
        taskCompleted=True,
        cleanPass=clean_pass,
        reasons=reasons,
        gateOutcomes=[
            f"analysis:{analysis_outcome.value}",
            f"quality:{quality_outcome.value}",
            f"poc:{poc_outcome.value}",
        ],
    )


async def _repair_generate_poc_quality(
    *,
    llm,
    messages: list[dict],
    parsed: dict,
    quality_gate: QualityGateResult,
    request: TaskRequest,
    max_tokens: int,
    generation,
) -> tuple[str, int, int]:
    """Ask the producer to repair a quality-rejected PoC once, with critic feedback."""
    failures = [
        {
            "id": item.id,
            "requiredEvidenceSlots": item.requiredEvidenceSlots,
            "detail": item.detail,
        }
        for item in quality_gate.failedItems
    ]
    repair_prompt = (
        "[시스템] 이전 generate-poc JSON은 schema/ref 검증은 통과했지만 PoC QualityGate에서 거절되었습니다. "
        "아래 실패 항목만 고치고, 같은 Assessment JSON 스키마로 다시 출력하십시오. "
        "파괴적 동작을 제거하고, command-injection PoC라면 randomized non-destructive canary를 포함하십시오. "
        "코드펜스 밖 설명문 없이 순수 JSON만 출력하십시오.\n\n"
        f"repairHint:\n{quality_gate.repairHint or '(none)'}\n\n"
        f"QualityGate failures:\n{json.dumps(failures, ensure_ascii=False, indent=2)}\n\n"
        f"Previous JSON:\n{json.dumps(parsed, ensure_ascii=False)}"
    )
    # P7: quality repair is a local edit over a rejected candidate, not a fresh
    # creative draft; callers pass STRICT_JSON_REPAIR unless explicitly overridden.
    response = await llm.call(
        [*messages, {"role": "user", "content": repair_prompt}],
        max_tokens=max_tokens,
        generation=generation,
        prefer_async_ownership=True,
    )
    return response.content or "", response.prompt_tokens, response.completion_tokens


def _quality_failure_detail(quality_gate: QualityGateResult) -> str:
    if not quality_gate.failedItems:
        return "PoC quality gate rejected the output."
    return "; ".join(
        f"{item.id}: {item.detail or 'quality gate failed'}"
        for item in quality_gate.failedItems
    )


async def _repair_generate_poc_schema(
    *,
    llm,
    messages: list[dict],
    invalid_content: str,
    schema_errors: list[str],
    request: TaskRequest,
    max_tokens: int,
    generation,
) -> tuple[str, int, int]:
    """Repair malformed generate-poc JSON with a deterministic scaffold.

    The LLM is allowed to refine wording, but the required Assessment object
    shape is scaffolded before the retry and preserved after the retry. This
    prevents a repair turn from repeating an invalid ``summary + claims``-only
    shape.
    """
    from app.pipeline.response_parser import V1ResponseParser

    parser = V1ResponseParser()
    partial = parser.parse(invalid_content) or {}
    scaffold = _build_generate_poc_repair_scaffold(
        partial=partial,
        request=request,
    )
    scaffold_json = json.dumps(scaffold, ensure_ascii=False, indent=2)
    repair_messages = [
        *messages,
        {"role": "assistant", "content": invalid_content[:8000]},
        {
            "role": "user",
            "content": (
                "[시스템] 직전 응답은 generate-poc Assessment 스키마를 위반했습니다. "
                "아래 S3가 제공하는 scaffold의 object shape와 모든 key를 유지한 채 하나의 유효한 JSON 객체로 재작성하십시오. "
                "설명문/코드펜스 없이 첫 문자는 반드시 `{`이어야 합니다.\n\n"
                f"Schema errors: {'; '.join(schema_errors)}\n\n"
                "필수 top-level fields: summary, claims, caveats, usedEvidenceRefs, "
                "suggestedSeverity, needsHumanReview, recommendedNextSteps, policyFlags.\n"
                "각 claims[] 원소는 statement, detail, supportingEvidenceRefs, location을 가진 객체여야 합니다.\n"
                "절대 key를 삭제하지 마십시오. supportingEvidenceRefs와 usedEvidenceRefs에는 scaffold에 있는 refId만 사용하십시오.\n\n"
                "S3 deterministic scaffold:\n"
                f"```json\n{scaffold_json}\n```"
            ),
        },
    ]
    request_summary_tracker.mark_transport_only(
        get_request_id() or request.taskId,
        source="generate-poc-schema-repair",
    )
    # P7: schema/scaffold repair is mechanical narrowing; keep it on the strict
    # repair tuple unless a caller deliberately supplies a different preset.
    response = await llm.call(
        repair_messages,
        max_tokens=max_tokens,
        generation=generation,
        prefer_async_ownership=True,
    )
    request_summary_tracker.mark_phase_advancing(
        get_request_id() or request.taskId,
        source="generate-poc-schema-repair-response",
    )
    refinement = parser.parse(response.content or "")
    repaired = _merge_generate_poc_repair_refinement(
        scaffold=scaffold,
        refinement=refinement,
        request=request,
    )
    return (
        json.dumps(repaired, ensure_ascii=False),
        response.prompt_tokens,
        response.completion_tokens,
    )


def _build_generate_poc_repair_scaffold(
    *,
    partial: dict,
    request: TaskRequest,
) -> dict:
    trusted = request.context.trusted if isinstance(request.context.trusted, dict) else {}
    input_claim = trusted.get("claim", {}) if isinstance(trusted.get("claim"), dict) else {}
    allowed_refs = _allowed_generate_poc_ref_ids(request)
    partial_claims = partial.get("claims")
    claim_sources = [c for c in partial_claims if isinstance(c, dict)] if isinstance(partial_claims, list) else []
    if not claim_sources:
        claim_sources = [input_claim]

    claims: list[dict] = []
    for source in claim_sources:
        refs = _valid_generate_poc_refs(source.get("supportingEvidenceRefs"), allowed_refs)
        if not refs:
            refs = _valid_generate_poc_refs(input_claim.get("supportingEvidenceRefs"), allowed_refs)
        if not refs:
            refs = _matching_request_refs_for_claim(request, input_claim)

        claims.append({
            "statement": _first_nonempty_string(
                source.get("statement"),
                input_claim.get("statement"),
                "Generate a PoC for the supplied security claim.",
            ),
            "detail": _first_nonempty_string(
                source.get("detail"),
                input_claim.get("detail"),
                source.get("statement"),
                input_claim.get("statement"),
                "PoC details require analyst review.",
            ),
            "supportingEvidenceRefs": refs,
            "location": _first_nonempty_string(
                source.get("location"),
                input_claim.get("location"),
                _location_from_request_evidence(request),
            ),
        })

    used_refs = _valid_generate_poc_refs(partial.get("usedEvidenceRefs"), allowed_refs)
    if not used_refs:
        used_refs = list(dict.fromkeys(ref for claim in claims for ref in claim["supportingEvidenceRefs"]))

    caveats = _string_list(partial.get("caveats"))
    recommended_next_steps = _string_list(partial.get("recommendedNextSteps"))
    policy_flags = _string_list(partial.get("policyFlags"))
    if "structured_finalizer" not in policy_flags:
        policy_flags.append("structured_finalizer")

    return {
        "summary": _first_nonempty_string(
            partial.get("summary"),
            input_claim.get("statement"),
            "PoC generated from the supplied security claim.",
        ),
        "claims": claims,
        "caveats": caveats,
        "usedEvidenceRefs": used_refs,
        "suggestedSeverity": _infer_generate_poc_severity(partial, input_claim),
        "needsHumanReview": partial.get("needsHumanReview") if isinstance(partial.get("needsHumanReview"), bool) else True,
        "recommendedNextSteps": recommended_next_steps,
        "policyFlags": policy_flags,
    }


def _merge_generate_poc_repair_refinement(
    *,
    scaffold: dict,
    refinement: dict | None,
    request: TaskRequest,
) -> dict:
    if not isinstance(refinement, dict):
        return scaffold

    allowed_refs = _allowed_generate_poc_ref_ids(request)
    repaired = {
        **scaffold,
        "claims": [dict(c) for c in scaffold.get("claims", []) if isinstance(c, dict)],
    }

    for field in ("summary",):
        if isinstance(refinement.get(field), str) and refinement[field].strip():
            repaired[field] = refinement[field]
    for field in ("caveats", "recommendedNextSteps", "policyFlags"):
        values = _string_list(refinement.get(field))
        if values or field in refinement:
            repaired[field] = values
    severity = _infer_generate_poc_severity(refinement, {})
    if severity:
        repaired["suggestedSeverity"] = severity
    if isinstance(refinement.get("needsHumanReview"), bool):
        repaired["needsHumanReview"] = refinement["needsHumanReview"]

    refined_claims = refinement.get("claims")
    if isinstance(refined_claims, list):
        for index, refined_claim in enumerate(c for c in refined_claims if isinstance(c, dict)):
            if index >= len(repaired["claims"]):
                repaired["claims"].append(dict(scaffold["claims"][-1]))
            target = repaired["claims"][index]
            for field in ("statement", "detail", "location"):
                if isinstance(refined_claim.get(field), str) and refined_claim[field].strip():
                    target[field] = refined_claim[field]
            refs = _valid_generate_poc_refs(refined_claim.get("supportingEvidenceRefs"), allowed_refs)
            if refs:
                target["supportingEvidenceRefs"] = refs

    used_refs = _valid_generate_poc_refs(refinement.get("usedEvidenceRefs"), allowed_refs)
    if used_refs:
        repaired["usedEvidenceRefs"] = used_refs
    if not repaired.get("usedEvidenceRefs"):
        repaired["usedEvidenceRefs"] = list(dict.fromkeys(
            ref
            for claim in repaired.get("claims", [])
            if isinstance(claim, dict)
            for ref in claim.get("supportingEvidenceRefs", [])
            if isinstance(ref, str)
        ))

    if "structured_finalizer" not in repaired.get("policyFlags", []):
        repaired["policyFlags"] = list(repaired.get("policyFlags", [])) + ["structured_finalizer"]
    return repaired


def _allowed_generate_poc_ref_ids(request: TaskRequest) -> list[str]:
    trusted = request.context.trusted if isinstance(request.context.trusted, dict) else {}
    input_claim = trusted.get("claim", {}) if isinstance(trusted.get("claim"), dict) else {}
    refs: list[str] = []
    raw_claim_refs = input_claim.get("supportingEvidenceRefs")
    if isinstance(raw_claim_refs, list):
        refs.extend(ref for ref in raw_claim_refs if isinstance(ref, str) and ref)
    refs.extend(ref.refId for ref in request.evidenceRefs if isinstance(ref.refId, str) and ref.refId)
    return list(dict.fromkeys(refs))


def _matching_request_refs_for_claim(request: TaskRequest, input_claim: dict) -> list[str]:
    location = input_claim.get("location") if isinstance(input_claim, dict) else None
    location_file = location.split(":", 1)[0] if isinstance(location, str) and location else ""
    if not location_file:
        return []
    matched: list[str] = []
    for ref in request.evidenceRefs:
        locator = ref.locator if isinstance(ref.locator, dict) else {}
        ref_file = locator.get("file") or locator.get("path")
        artifact_type = str(ref.artifactType or "").lower()
        if artifact_type and not any(marker in artifact_type for marker in ("source", "sast", "code")):
            continue
        if location_file and isinstance(ref_file, str) and ref_file and ref_file != location_file:
            continue
        if ref.refId:
            matched.append(ref.refId)
    return list(dict.fromkeys(matched))


def _valid_generate_poc_refs(raw_refs, allowed_refs: list[str]) -> list[str]:
    allowed = set(allowed_refs)
    if not isinstance(raw_refs, list):
        return []
    return list(dict.fromkeys(ref for ref in raw_refs if isinstance(ref, str) and ref in allowed))


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _first_nonempty_string(*values) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _location_from_request_evidence(request: TaskRequest) -> str:
    for ref in request.evidenceRefs:
        locator = ref.locator if isinstance(ref.locator, dict) else {}
        file_name = locator.get("file") or locator.get("path")
        line = locator.get("startLine") or locator.get("fromLine") or locator.get("line")
        if file_name:
            return f"{file_name}:{line}" if line else str(file_name)
    return ""


def _infer_generate_poc_severity(partial: dict, input_claim: dict) -> str:
    allowed = {"critical", "high", "medium", "low", "info"}
    for source in (partial, input_claim):
        for key in ("suggestedSeverity", "severity"):
            value = source.get(key) if isinstance(source, dict) else None
            if isinstance(value, str) and value in allowed:
                return value
    return "medium"


def _strict_json_failure_detail(error) -> str:
    parts = [
        f"blockedReason={getattr(error, 'blocked_reason', 'strict_json_contract_violation')}",
    ]
    if getattr(error, "async_request_id", None):
        parts.append(f"asyncRequestId={error.async_request_id}")
    if getattr(error, "gateway_request_id", None):
        parts.append(f"gatewayRequestId={error.gateway_request_id}")
    if getattr(error, "error_detail", None):
        parts.append(f"errorDetail={error.error_detail}")
    return "strict_json_contract_violation; " + "; ".join(parts)


def _schema_repair_failure_detail(error) -> str:
    if (
        getattr(error, "blocked_reason", None) == "strict_json_contract_violation"
        or error.__class__.__name__ == "StrictJsonContractError"
    ):
        return "generate-poc schema repair call failed: " + _strict_json_failure_detail(error)
    return f"generate-poc schema repair call failed: {error}"
