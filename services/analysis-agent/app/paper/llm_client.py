from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urljoin

import httpx

from app.agent_runtime.context import get_request_id
from app.agent_runtime.llm.generation_policy import (
    TRACEAUDIT_QWEN36_ACQUISITION_V1,
    TRACEAUDIT_QWEN36_FINALIZER_V1,
)
from app.config import settings

from .artifacts import read_json
from .errors import PaperOperationalError
from .models import PaperCaseCreateRequest
from .observability import log_http_end, log_http_error, log_http_start, log_llm_exchange_metadata
from .timeout_policy import wait_while_alive_http_timeout
from .triage import fallback_unknown_for_finding


def _resolve_s7_url(base_url: str, candidate: str | None, fallback_path: str) -> str:
    """Resolve S7 relative ownership URLs against the configured Gateway base."""

    base = base_url.rstrip("/") + "/"
    target = candidate or fallback_path
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return urljoin(base, target.lstrip("/"))


def _drop_none(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}


def _compact_async_status(status_data: dict[str, Any]) -> dict[str, Any]:
    """Keep S7 async status evidence that is useful for paper-run audit.

    The full S7 status can be large and may grow additively. S3 preserves the
    stable ownership/progress/error fields plus backendActivity so paper
    transcripts can prove which async request was observed and whether S7 saw
    backend stream progress.
    """

    keys = [
        "requestId",
        "traceRequestId",
        "state",
        "localAckState",
        "phase",
        "blockedReason",
        "error",
        "errorDetail",
        "retryable",
        "resultReady",
        "acceptedAt",
        "startedAt",
        "endedAt",
        "expiresAt",
        "backendActivity",
    ]
    return _drop_none({key: status_data.get(key) for key in keys})


class LlmTriageClient:
    def __init__(self, endpoint: str | None = None, timeout_seconds: float = 120.0):
        self.endpoint = endpoint or settings.llm_endpoint
        # Deprecated compatibility attribute; live paper triage must not fail
        # solely because model inference crossed a caller-side read deadline
        # while S7/DGX are still alive.
        self.timeout_seconds = timeout_seconds
        self.transport_timeout = wait_while_alive_http_timeout()
        self.async_poll_interval_seconds = 1.0

    async def acquire_for_finding(
        self,
        case: PaperCaseCreateRequest,
        *,
        finding: dict[str, Any],
        evidence_rows: list[dict[str, Any]],
        acquisition_messages: list[dict[str, Any]] | None = None,
        round_index: int = 1,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run the paper evidence-acquisition LLM turn with tools enabled.

        ``tool_choice=auto`` is intentional: Qwen/vLLM is known to fail with
        required+thinking. The caller must execute allowed tool calls and apply
        deterministic missing-tool fallback where the paper contract requires
        S5 context.
        """

        prompt = self._build_acquisition_prompt(case, finding=finding, evidence_rows=evidence_rows)
        request = {
            "caseId": case.caseId,
            "findingId": finding["findingId"],
            "roundIndex": round_index,
            "modelProfile": TRACEAUDIT_QWEN36_ACQUISITION_V1.profile_id,
            "generationProfile": TRACEAUDIT_QWEN36_ACQUISITION_V1.to_metadata(model=settings.llm_model),
            "prompt": prompt,
        }
        if case.producerArtifacts.llmTriageByFindingId.get(finding["findingId"]) or settings.llm_mode == "mock":
            log_llm_exchange_metadata(
                phase="paper_acquisition",
                mode="deterministic_required_tools",
                model=settings.llm_model,
                max_tokens=TRACEAUDIT_QWEN36_ACQUISITION_V1.max_tokens,
                latency_ms=0,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding["findingId"],
                tool_call_count=0,
            )
            return {"toolCalls": [], "content": None, "mode": "deterministic_required_tools"}, {"mode": "skipped", **request}
        body = self._build_s7_acquisition_body(prompt, acquisition_messages=acquisition_messages)
        headers = {
            "X-AEGIS-Paper-Controls": "true",
        }
        payload, latency_ms, async_metadata = await self._post_chat(
            body,
            headers,
            case=case,
            finding_id=finding["findingId"],
            phase="paper_acquisition",
        )
        try:
            turn = _extract_tool_call_turn(payload)
        except PaperOperationalError:
            choice = _first_choice(payload)
            log_llm_exchange_metadata(
                phase="paper_acquisition",
                mode="live",
                model=body.get("model"),
                max_tokens=body.get("max_tokens"),
                latency_ms=latency_ms,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding["findingId"],
                finish_reason=choice.get("finish_reason") if isinstance(choice, dict) else None,
                usage=payload.get("usage"),
                status="error",
                error_code="LLM_RESPONSE_CONTRACT_ERROR",
            )
            raise
        log_llm_exchange_metadata(
            phase="paper_acquisition",
            mode="live",
            model=body.get("model"),
            max_tokens=body.get("max_tokens"),
            latency_ms=latency_ms,
            case_id=case.caseId,
            build_target_id=case.buildTargetId,
            paper_run_id=case.paperRunId,
            finding_id=finding["findingId"],
            finish_reason=turn.get("finishReason"),
            tool_call_count=len(turn.get("toolCalls") or []),
            usage=turn.get("usage"),
        )
        return turn, {"mode": "live", **request, "body": body, "headers": headers, "rawResponse": payload, "s7Async": async_metadata}

    async def finalize_finding(
        self,
        case: PaperCaseCreateRequest,
        *,
        finding: dict[str, Any],
        evidence_rows: list[dict[str, Any]],
        acquisition_notes: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        path = case.producerArtifacts.llmTriageByFindingId.get(finding["findingId"])
        prompt = self._build_finalizer_prompt(
            case,
            finding=finding,
            evidence_rows=evidence_rows,
            acquisition_notes=acquisition_notes or {},
        )
        request = {
            "caseId": case.caseId,
            "findingId": finding["findingId"],
            "modelProfile": TRACEAUDIT_QWEN36_FINALIZER_V1.profile_id,
            "generationProfile": TRACEAUDIT_QWEN36_FINALIZER_V1.to_metadata(model=settings.llm_model),
            "prompt": prompt,
        }
        if path:
            log_llm_exchange_metadata(
                phase="paper_finalizer",
                mode="file_backed",
                model=settings.llm_model,
                max_tokens=TRACEAUDIT_QWEN36_FINALIZER_V1.max_tokens,
                latency_ms=0,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding["findingId"],
                tool_call_count=0,
            )
            return read_json(path), {"mode": "file_backed", **request}
        if settings.llm_mode == "mock":
            log_llm_exchange_metadata(
                phase="paper_finalizer",
                mode="mock",
                model=settings.llm_model,
                max_tokens=TRACEAUDIT_QWEN36_FINALIZER_V1.max_tokens,
                latency_ms=0,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding["findingId"],
                tool_call_count=0,
            )
            return fallback_unknown_for_finding(finding), {"mode": "mock", **request}
        body = self._build_s7_finalizer_body(prompt)
        headers = {
            "X-AEGIS-Paper-Controls": "true",
            "X-AEGIS-Strict-JSON": "true",
        }
        payload, latency_ms, async_metadata = await self._post_chat(
            body,
            headers,
            case=case,
            finding_id=finding["findingId"],
            phase="paper_finalizer",
        )
        choice = _first_choice(payload)
        try:
            parsed = _extract_openai_json_content(payload)
        except PaperOperationalError:
            log_llm_exchange_metadata(
                phase="paper_finalizer",
                mode="live",
                model=body.get("model"),
                max_tokens=body.get("max_tokens"),
                latency_ms=latency_ms,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding["findingId"],
                finish_reason=choice.get("finish_reason") if isinstance(choice, dict) else None,
                usage=payload.get("usage"),
                status="error",
                error_code="LLM_RESPONSE_CONTRACT_ERROR",
            )
            raise
        log_llm_exchange_metadata(
            phase="paper_finalizer",
            mode="live",
            model=body.get("model"),
            max_tokens=body.get("max_tokens"),
            latency_ms=latency_ms,
            case_id=case.caseId,
            build_target_id=case.buildTargetId,
            paper_run_id=case.paperRunId,
            finding_id=finding["findingId"],
            finish_reason=choice.get("finish_reason") if isinstance(choice, dict) else None,
            tool_call_count=0,
            usage=payload.get("usage"),
        )
        return parsed, {"mode": "live", **request, "body": body, "headers": headers, "rawResponse": payload, "s7Async": async_metadata}

    async def triage_finding(self, case: PaperCaseCreateRequest, *, finding: dict[str, Any], evidence_rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Compatibility wrapper for older tests/callers.

        New paper execution must call ``acquire_for_finding`` then
        ``finalize_finding`` so S5/code tools can be consumed before verdict
        finalization.
        """

        return await self.finalize_finding(case, finding=finding, evidence_rows=evidence_rows, acquisition_notes={})

    async def _post_chat(
        self,
        body: dict[str, Any],
        headers: dict[str, str],
        *,
        case: PaperCaseCreateRequest,
        finding_id: str,
        phase: str,
    ) -> tuple[dict[str, Any], int, dict[str, Any]]:
        path = "/v1/async-chat-requests"
        request_id = get_request_id()
        if request_id:
            headers["X-Request-Id"] = request_id
        operation_started_at = asyncio.get_running_loop().time()
        started_at = log_http_start(
            target="s7-gateway",
            method="POST",
            path=path,
            case_id=case.caseId,
            build_target_id=case.buildTargetId,
            paper_run_id=case.paperRunId,
            finding_id=finding_id,
            child_request_id=request_id,
        )
        try:
            async with httpx.AsyncClient(timeout=self.transport_timeout) as client:
                response = await client.post(f"{self.endpoint.rstrip('/')}{path}", json=body, headers=headers)
        except httpx.HTTPError as exc:
            latency_ms = log_http_error(
                started_at=started_at,
                target="s7-gateway",
                method="POST",
                path=path,
                error_code=type(exc).__name__,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding_id,
                child_request_id=request_id,
            )
            log_llm_exchange_metadata(
                phase=phase,
                mode="live",
                model=body.get("model"),
                max_tokens=body.get("max_tokens"),
                latency_ms=latency_ms,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding_id,
                status="error",
                error_code=type(exc).__name__,
            )
            raise PaperOperationalError(f"S7 LLM transport failure: {exc}") from exc
        latency_ms = log_http_end(
            started_at=started_at,
            target="s7-gateway",
            method="POST",
            path=path,
            status=response.status_code,
            case_id=case.caseId,
            build_target_id=case.buildTargetId,
            paper_run_id=case.paperRunId,
            finding_id=finding_id,
            child_request_id=request_id,
        )
        if response.status_code >= 400:
            log_llm_exchange_metadata(
                phase=phase,
                mode="live",
                model=body.get("model"),
                max_tokens=body.get("max_tokens"),
                latency_ms=latency_ms,
                case_id=case.caseId,
                build_target_id=case.buildTargetId,
                paper_run_id=case.paperRunId,
                finding_id=finding_id,
                status="error",
                error_code=f"HTTP_{response.status_code}",
            )
            raise PaperOperationalError(f"S7 LLM HTTP {response.status_code}", detail={"body": response.text[:1000]})
        submit_data = response.json()
        async_request_id = submit_data.get("requestId")
        if not async_request_id:
            raise PaperOperationalError("S7 async submit response missing requestId", detail={"body": submit_data})
        status_url = _resolve_s7_url(
            self.endpoint,
            submit_data.get("statusUrl"),
            f"/v1/async-chat-requests/{async_request_id}",
        )
        result_url = _resolve_s7_url(
            self.endpoint,
            submit_data.get("resultUrl"),
            f"/v1/async-chat-requests/{async_request_id}/result",
        )
        poll_headers = {"X-Request-Id": request_id} if request_id else {}
        async_metadata: dict[str, Any] = {
            "requestId": async_request_id,
            "traceRequestId": submit_data.get("traceRequestId"),
            "statusUrl": status_url,
            "resultUrl": result_url,
            "acceptedAt": submit_data.get("acceptedAt"),
            "expiresAt": submit_data.get("expiresAt"),
        }
        async with httpx.AsyncClient(timeout=self.transport_timeout) as client:
            while True:
                status_response = await client.get(status_url, headers=poll_headers)
                if status_response.status_code >= 400:
                    raise PaperOperationalError(
                        f"S7 async status HTTP {status_response.status_code}",
                        detail={"body": status_response.text[:1000], "asyncRequestId": async_request_id},
                    )
                status_data = status_response.json()
                state = status_data.get("state")
                blocked_reason = status_data.get("blockedReason")
                local_ack_state = status_data.get("localAckState")
                result_ready = bool(status_data.get("resultReady"))
                async_metadata["lastStatus"] = _compact_async_status(status_data)
                if blocked_reason or local_ack_state == "ack-break":
                    raise PaperOperationalError(
                        "S7 async request reached terminal blocked state",
                        detail={"status": status_data, "asyncRequestId": async_request_id},
                    )
                if state in {"queued", "running"} and not result_ready:
                    await asyncio.sleep(self.async_poll_interval_seconds)
                    continue
                if state == "completed" or result_ready:
                    result_response = await client.get(result_url, headers=poll_headers)
                    if result_response.status_code == 409:
                        await asyncio.sleep(self.async_poll_interval_seconds)
                        continue
                    if result_response.status_code >= 400:
                        raise PaperOperationalError(
                            f"S7 async result HTTP {result_response.status_code}",
                            detail={"body": result_response.text[:1000], "asyncRequestId": async_request_id},
                        )
                    result_data = result_response.json()
                    payload = result_data.get("response") if isinstance(result_data, dict) else None
                    if not isinstance(payload, dict):
                        raise PaperOperationalError(
                            "S7 async result missing response payload",
                            detail={"body": result_data, "asyncRequestId": async_request_id},
                        )
                    total_latency_ms = int((asyncio.get_running_loop().time() - operation_started_at) * 1000)
                    async_metadata["completedAt"] = result_data.get("completedAt")
                    async_metadata["resultState"] = result_data.get("state")
                    async_metadata["resultExpiresAt"] = result_data.get("expiresAt")
                    return payload, total_latency_ms, _drop_none(async_metadata)
                raise PaperOperationalError(
                    "S7 async request did not complete successfully",
                    detail={"status": status_data, "asyncRequestId": async_request_id},
                )

    def _build_s7_acquisition_body(self, prompt: str, *, acquisition_messages: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        messages = acquisition_messages or [
            {
                "role": "system",
                "content": (
                    "You are AEGIS TraceAudit's evidence-acquisition analyst. "
                    "Do not emit a final verdict in this turn. Use available tools "
                    "to collect the context needed for a later strict finalizer. "
                    "If a required context tool looks relevant, call it with the current findingId. "
                    "For retrieve_finding_context, inspect source coverage, displayRefs, diagnostics, "
                    "and textPreview fields; do not fabricate source context when coverage is "
                    "non_overlapping, not_available, or unknown. For retrieve_generic_threat_context, "
                    "coverage is not applicable; inspect surfaceStatus, diagnostics, sourceType, "
                    "queryIntent, and textPreview fields. If local source context is suspicious or "
                    "insufficient, use explore_source_kg for bounded source slices, function bodies, "
                    "or call-graph neighborhood. If the finding depends on literal source tokens, "
                    "operators, arguments, or call-site relationships and the current textPreview is only "
                    "metadata such as 'references symbol', use explore_source_kg even when coverage is "
                    "covered. Do not treat exploration no_hit/not_available as safe evidence."
                ),
            },
            {"role": "user", "content": prompt},
        ]
        return {
            "model": settings.llm_model,
            "messages": messages,
            "tools": paper_tool_schemas(),
            "tool_choice": "auto",
            **TRACEAUDIT_QWEN36_ACQUISITION_V1.to_gateway_fields(),
        }

    def _build_s7_finalizer_body(self, prompt: str) -> dict[str, Any]:
        return {
            "model": settings.llm_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are AEGIS TraceAudit's evidence-guided SAST triage analyst. "
                        "Reason carefully over the complete bounded evidence packet before deciding. "
                        "Never use s3-diagnostic refs as citedEvidenceRefs or claimEvidenceLinks; "
                        "diagnostics belong only in diagnosticRefsUsed or boundaryNotes. If only "
                        "diagnostics, no-hit, or retrieval absence support a claim, choose UNKNOWN "
                        "with unknownReason=UNKNOWN_INSUFFICIENT_CONTEXT. "
                        "Return only the requested JSON object."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "tool_choice": "none",
            # Do not shrink this for smoke-test convenience. DGX Spark Qwen is
            # slow (~single-digit tokens/sec), but paper triage prioritizes
            # accurate claims, sufficient reasoning room, and complete
            # claim-evidence linkage over latency.
            **TRACEAUDIT_QWEN36_FINALIZER_V1.to_gateway_fields(),
        }

    def _build_acquisition_prompt(self, case: PaperCaseCreateRequest, *, finding: dict[str, Any], evidence_rows: list[dict[str, Any]]) -> str:
        packet = {
            "caseId": case.caseId,
            "buildTargetId": case.buildTargetId,
            "findingId": finding["findingId"],
            "finding": finding,
            "currentEvidenceRows": evidence_rows,
            "requiredContextTools": ["retrieve_finding_context", "retrieve_generic_threat_context"],
        }
        return "\n".join(
            [
                "Task: acquire bounded evidence for this SAST finding before final triage.",
                "",
                "Rules:",
                "- Do not decide TP/FP/UNKNOWN in this turn.",
                "- Use tool_choice auto tool calls; never assume S5 no_hit/empty means safe.",
                "- Prefer retrieve_finding_context and retrieve_generic_threat_context for the current finding.",
                "- For retrieve_finding_context, inspect coverage/displayRefs/textPreview before deciding whether more evidence is needed.",
                "- For retrieve_generic_threat_context, coverage is not applicable; inspect surfaceStatus, diagnostics, sourceType, queryIntent, and textPreview.",
                "- If source context is non-overlapping, partial, unknown, or otherwise insufficient, prefer explore_source_kg before stopping when a bounded source slice/function/caller/callee/neighborhood query could reduce uncertainty.",
                "- If the finding turns on literal code tokens/operators/arguments, exact call sites, or whether a variable is modified, call explore_source_kg with source_slice or function_body unless current evidence includes concrete code text for that claim; covered metadata without raw code is not enough.",
                "- Use list_evidence_rows to inspect current normalized rows, and do not fabricate missing source context.",
                "- You may call list_evidence_rows to inspect current normalized rows.",
                "",
                "Acquisition packet JSON:",
                json.dumps(packet, ensure_ascii=False, sort_keys=True),
            ]
        )

    def _build_finalizer_prompt(
        self,
        case: PaperCaseCreateRequest,
        *,
        finding: dict[str, Any],
        evidence_rows: list[dict[str, Any]],
        acquisition_notes: dict[str, Any],
    ) -> str:
        evidence_refs = [str(row.get("evidenceRef")) for row in evidence_rows if row.get("evidenceRef")]
        claim_support_refs = [
            str(row.get("evidenceRef"))
            for row in evidence_rows
            if row.get("evidenceRef") and not row.get("diagnostic") and row.get("surfaceStatus") == "produced"
        ]
        diagnostic_refs = [
            str(row.get("evidenceRef"))
            for row in evidence_rows
            if row.get("evidenceRef") and row.get("diagnostic")
        ]
        packet = {
            "caseId": case.caseId,
            "buildTargetId": case.buildTargetId,
            "findingId": finding["findingId"],
            "finding": finding,
            "knownEvidenceRefs": evidence_refs,
            "claimSupportEvidenceRefs": claim_support_refs,
            "allowedCitedEvidenceRefs": claim_support_refs,
            "diagnosticEvidenceRefs": diagnostic_refs,
            "evidenceRows": evidence_rows,
            "acquisitionNotes": acquisition_notes,
        }
        return "\n".join(
            [
                "Task: classify this SAST finding as TP, FP, or UNKNOWN for an auditable TraceAudit packet.",
                "",
                "Decision policy:",
                "- Prioritize correctness over speed or brevity.",
                "- TP/FP require explicit citedEvidenceRefs from knownEvidenceRefs.",
                "- citedEvidenceRefs and claimEvidenceLinks may use only claimSupportEvidenceRefs/allowedCitedEvidenceRefs.",
                "- diagnosticEvidenceRefs are audit context only; use them only in diagnosticRefsUsed or boundaryNotes.",
                "- If bounded evidence is insufficient, choose UNKNOWN with unknownReason=UNKNOWN_INSUFFICIENT_CONTEXT.",
                "- Do not promote producer diagnostics, empty/no_hit, operational absence, or retrieval failure into security evidence.",
                "- Never put s3-diagnostic:* refs in citedEvidenceRefs or claimEvidenceLinks; put them only in diagnosticRefsUsed or boundaryNotes.",
                "- If only diagnostic/no_hit/retrieval-absence refs support a claim, choose UNKNOWN_INSUFFICIENT_CONTEXT and leave citedEvidenceRefs limited to grounding refs, or empty if no grounding refs support the claim.",
                "- Use S4/S5 evidence only within each producer's claim boundary.",
                "- It is acceptable to cite multiple evidence rows when the claim depends on SAST, code context, and threat context together.",
                "",
                "Required JSON schema:",
                "{",
                '  "findingId": string,',
                '  "verdict": "TP" | "FP" | "UNKNOWN",',
                '  "rationale": string,',
                '  "citedEvidenceRefs": string[],',
                '  "claimEvidenceLinks": [{"claim": string, "stance": string, "evidenceRefs": string[]}],',
                '  "unsupportedClaims": string[],',
                '  "unknownReason": string | null,',
                '  "diagnosticRefsUsed": string[],',
                '  "boundaryNotes": string[]',
                "}",
                "",
                "Evidence packet JSON:",
                json.dumps(packet, ensure_ascii=False, sort_keys=True),
            ]
        )


def paper_tool_schemas() -> list[dict[str, Any]]:
    finding_id_property = {
        "type": "string",
        "description": "Current S4 findingId. Must match the finding under triage.",
    }
    return [
        {
            "type": "function",
            "function": {
                "name": "retrieve_finding_context",
                "description": "Retrieve target-local Code KB / Source KG context for the current SAST finding.",
                "parameters": {
                    "type": "object",
                    "properties": {"findingId": finding_id_property},
                    "required": ["findingId"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "retrieve_generic_threat_context",
                "description": "Retrieve generic CWE/CAPEC/security concept context without CVE/advisory/fix leakage.",
                "parameters": {
                    "type": "object",
                    "properties": {"findingId": finding_id_property},
                    "required": ["findingId"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "explore_source_kg",
                "description": "Explore bounded Source KG source slices, functions, symbols, callers, callees, neighborhoods, or data-flow availability for the current finding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findingId": finding_id_property,
                        "mode": {
                            "type": "string",
                            "enum": ["source_slice", "function_body", "callers", "callees", "symbol_lookup", "neighborhood", "data_flow"],
                            "description": "Bounded Source KG exploration mode.",
                        },
                        "path": {"type": "string", "description": "Optional source path selector. Defaults to the finding location path."},
                        "lineStart": {"type": "integer", "description": "Optional 1-based start line selector. Defaults to the finding start line."},
                        "lineEnd": {"type": "integer", "description": "Optional 1-based end line selector. Defaults to the finding end line/start line."},
                        "symbolName": {"type": "string", "description": "Optional function or symbol name selector."},
                        "functionRef": {"type": "string", "description": "Optional S4/S5 function reference selector."},
                        "graphNodeId": {"type": "string", "description": "Optional Source KG graph node selector."},
                        "depth": {"type": "integer", "minimum": 1, "maximum": 3, "description": "Bounded graph neighborhood depth."},
                        "topK": {"type": "integer", "minimum": 1, "maximum": 10, "description": "Maximum Source KG rows to request."},
                    },
                    "required": ["findingId", "mode"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_evidence_rows",
                "description": "List current normalized evidence rows already known to S3 for this finding.",
                "parameters": {
                    "type": "object",
                    "properties": {"findingId": finding_id_property},
                    "required": ["findingId"],
                    "additionalProperties": False,
                },
            },
        },
    ]


def _extract_openai_json_content(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise PaperOperationalError("S7 LLM response missing choices[0].message.content") from exc
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        raise PaperOperationalError("S7 LLM response content is not a JSON string/object")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PaperOperationalError(f"S7 LLM response content is not JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise PaperOperationalError("S7 LLM response JSON content is not an object")
    return parsed


def _first_choice(payload: dict[str, Any]) -> dict[str, Any] | None:
    try:
        choice = payload["choices"][0]
    except (KeyError, IndexError, TypeError):
        return None
    return choice if isinstance(choice, dict) else None


def _extract_tool_call_turn(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        choice = payload["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise PaperOperationalError("S7 acquisition response missing choices[0].message") from exc
    calls = []
    raw_tool_calls = message.get("tool_calls") or []
    for call in message.get("tool_calls") or []:
        try:
            function = call["function"]
            raw_args = function.get("arguments", "{}")
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            calls.append(
                {
                    "id": call.get("id") or f"tool-call-{len(calls) + 1}",
                    "name": function["name"],
                    "arguments": args if isinstance(args, dict) else {},
                }
            )
        except (KeyError, json.JSONDecodeError):
            calls.append(
                {
                    "id": call.get("id") if isinstance(call, dict) else f"tool-call-{len(calls) + 1}",
                    "name": "<parse_error>",
                    "arguments": {},
                    "error": "tool_call_parse_error",
                }
            )
    assistant_message: dict[str, Any] = {"role": "assistant", "content": message.get("content")}
    if raw_tool_calls:
        assistant_message["tool_calls"] = raw_tool_calls
    return {
        "toolCalls": calls,
        "content": message.get("content"),
        "reasoning": message.get("reasoning"),
        "finishReason": choice.get("finish_reason"),
        "usage": payload.get("usage", {}),
        "assistantMessage": assistant_message,
    }
