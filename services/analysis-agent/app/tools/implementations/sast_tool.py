"""SastScanTool — sast.scan tool 구현체. S4 SAST Runner에 NDJSON 스트리밍으로 위임."""

from __future__ import annotations

import asyncio
import json
import logging

import httpx

from app.agent_runtime.context import get_request_id
from app.clients.s4_ownership import (
    S4OwnershipError,
    S4OwnershipUnsupported,
    is_s4_abort_status,
    is_s4_alive_status,
    post_and_wait_s4_ownership,
)
from app.agent_runtime.observability import agent_log
from app.agent_runtime.schemas.agent import ToolResult
from app.core.s4_static_evidence import extract_static_evidence_contract, summarize_static_evidence_contract
from app.agent_runtime.schemas.upstream import SastFinding
from app.runtime.request_summary import request_summary_tracker

logger = logging.getLogger(__name__)

_INACTIVITY_TIMEOUT_S = 60.0  # 60초간 이벤트 없으면 S4 hang 판정
_STALL_CONSECUTIVE = 3  # filesCompleted가 연속 N회 동일 → stall


class SastScanTool:
    wait_while_alive = True

    """sast.scan tool — S4 SAST Runner /v1/scan NDJSON 스트리밍 호출."""

    def __init__(self, base_url: str = "http://localhost:9000", timeout_s: float = 450.0, *, prefer_durable_ownership: bool = True) -> None:
        self._base_url = base_url
        self._timeout_s = timeout_s
        self._prefer_durable_ownership = prefer_durable_ownership
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=_INACTIVITY_TIMEOUT_S + 10.0, write=10.0, pool=10.0),
        )

    async def execute(self, arguments: dict) -> ToolResult:
        headers: dict[str, str] = {
            "Accept": "application/x-ndjson",
            "X-Timeout-Ms": str(int(self._timeout_s * 1000)),
        }
        request_id = get_request_id()
        if request_id:
            headers["X-Request-Id"] = request_id

        try:
            if request_id:
                request_summary_tracker.mark_transport_only(request_id, source="s4-scan-wait")
            if self._prefer_durable_ownership:
                try:
                    ownership = await post_and_wait_s4_ownership(
                        self._client,
                        base_url=self._base_url,
                        endpoint_path="/v1/scan",
                        payload=arguments,
                        root_request_id=request_id,
                        operation="sast_scan",
                    )
                    return self._build_result(ownership.payload)
                except (S4OwnershipUnsupported, TypeError):
                    # Compatibility fallback for older S4 or legacy unit tests that only mock NDJSON.
                    pass
                except S4OwnershipError as exc:
                    return ToolResult(
                        tool_call_id="", name="", success=False,
                        content=json.dumps({
                            "error": str(exc),
                            "statusCode": exc.status_code,
                            "detail": exc.payload,
                        }, ensure_ascii=False),
                        error=str(exc),
                    )
            return await self._stream_scan(arguments, headers)
        except Exception as e:
            logger.warning("SAST Runner 호출 실패: %s", e)
            return ToolResult(
                tool_call_id="", name="", success=False,
                content=json.dumps({"error": f"SAST Runner unavailable: {e}"}),
                error=str(e),
            )

    async def _stream_scan(self, arguments: dict, headers: dict) -> ToolResult:
        """NDJSON 스트리밍으로 S4 스캔 결과를 수신한다."""
        async with self._client.stream(
            "POST",
            f"{self._base_url}/v1/scan",
            json=arguments,
            headers=headers,
        ) as response:
            content_type = response.headers.get("content-type", "")

            # S4가 NDJSON을 지원하지 않으면 동기 fallback
            if "ndjson" not in content_type:
                body = await response.aread()
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    data = {
                        "success": False,
                        "error": body.decode(errors="replace")[:500],
                    }

                if response.status_code >= 400:
                    message = (
                        data.get("errorDetail", {}).get("message")
                        or data.get("error")
                        or f"SAST scan failed with HTTP {response.status_code}"
                    )
                    return ToolResult(
                        tool_call_id="",
                        name="",
                        success=False,
                        content=json.dumps(data, ensure_ascii=False),
                        error=message,
                    )
                return self._build_result(data)

            # NDJSON 스트리밍 소비
            result_data = None
            error_event = None
            stall_detected = False
            raw_events: list[str] = []

            # stall 감지 상태
            prev_files_completed: int | None = None
            stall_count = 0
            is_running = False  # queued → running 전환 추적

            async for line in self._iter_lines_with_timeout(response, headers=headers):
                line = line.strip()
                if not line:
                    continue
                raw_events.append(line)

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_type = event.get("type", "")

                if event_type == "progress":
                    request_id = get_request_id()
                    if request_id:
                        request_summary_tracker.mark_phase_advancing(
                            request_id,
                            source="s4-progress",
                        )
                    agent_log(
                        logger, "SAST 도구 진행",
                        component="sast_tool", phase="sast_progress",
                        tool=event.get("tool"),
                        status=event.get("status"),
                        findingsCount=event.get("findingsCount"),
                        elapsedMs=event.get("elapsedMs"),
                    )
                elif event_type == "heartbeat":
                    hb_status = event.get("status", "running")

                    if hb_status == "queued":
                        # 세마포어 대기 중 — stall 감지 비활성화
                        is_running = False
                        agent_log(
                            logger, "SAST 큐 대기 중",
                            component="sast_tool", phase="sast_queued",
                        )
                    elif hb_status == "running":
                        request_id = get_request_id()
                        if request_id:
                            request_summary_tracker.mark_phase_advancing(
                                request_id,
                                source="s4-heartbeat",
                            )
                        is_running = True
                        progress = event.get("progress", {})
                        files_completed = progress.get("filesCompleted", 0)

                        if prev_files_completed is not None and files_completed == prev_files_completed:
                            stall_count += 1
                        else:
                            stall_count = 0

                        prev_files_completed = files_completed

                        if stall_count >= _STALL_CONSECUTIVE:
                            active_tools = progress.get("activeTools", [])
                            current_file = progress.get("currentFile", "unknown")
                            agent_log(
                                logger, "SAST stall 감지",
                                component="sast_tool", phase="sast_stall",
                                level=logging.WARNING,
                                activeTools=active_tools,
                                currentFile=current_file,
                                filesCompleted=files_completed,
                                stallCount=stall_count,
                            )
                            stall_detected = True
                            # stall 감지해도 연결 유지 — S4가 per-tool timeout으로 자체 해결
                            # S3는 로깅만 수행

                        agent_log(
                            logger, "SAST 하트비트",
                            component="sast_tool", phase="sast_heartbeat",
                            activeTools=progress.get("activeTools"),
                            completedTools=progress.get("completedTools"),
                            findingsCount=progress.get("findingsCount"),
                            filesCompleted=files_completed,
                            filesTotal=progress.get("filesTotal"),
                        )
                elif event_type == "result":
                    result_data = event.get("data", {})
                elif event_type == "error":
                    error_event = event

            if error_event:
                return ToolResult(
                    tool_call_id="", name="", success=False,
                    content=json.dumps(error_event, ensure_ascii=False),
                    error=error_event.get("message", "SAST scan error"),
                )

            if result_data:
                return self._build_result(result_data, stall_detected=stall_detected)

            if response.status_code >= 400:
                fallback_content = "\n".join(raw_events) if raw_events else json.dumps(
                    {
                        "success": False,
                        "error": f"SAST scan failed with HTTP {response.status_code}",
                    },
                    ensure_ascii=False,
                )
                return ToolResult(
                    tool_call_id="",
                    name="",
                    success=False,
                    content=fallback_content,
                    error=f"SAST scan failed with HTTP {response.status_code}",
                )

            return ToolResult(
                tool_call_id="", name="", success=False,
                content='{"error": "SAST stream ended without result"}',
                error="no_result",
            )

    async def _iter_lines_with_timeout(self, response: httpx.Response, *, headers: dict):
        """Yield NDJSON lines; on inactivity, verify S4 health before aborting.

        NDJSON is now a compatibility fallback. Inactivity is only a suspicion:
        if `/v1/health?requestId=...` still reports the same request alive and
        non-blocked, keep waiting. Only explicit ack-break/blocked/terminal health
        converts the suspicion into abort.
        """
        aiter = response.aiter_lines()
        request_id = headers.get("X-Request-Id")
        while True:
            try:
                line = await asyncio.wait_for(
                    aiter.__anext__(),
                    timeout=_INACTIVITY_TIMEOUT_S,
                )
                yield line
            except asyncio.TimeoutError:
                logger.warning("SAST 스트리밍 inactivity suspicion (%.0fs)", _INACTIVITY_TIMEOUT_S)
                if await self._health_allows_stream_wait(request_id):
                    continue
                break
            except StopAsyncIteration:
                break

    async def _health_allows_stream_wait(self, request_id: str | None) -> bool:
        if not request_id:
            return False
        try:
            resp = await self._client.get(
                f"{self._base_url}/v1/health",
                params={"requestId": request_id},
                timeout=httpx.Timeout(connect=10.0, read=10.0, write=10.0, pool=10.0),
            )
            if resp.status_code >= 400:
                return False
            data = resp.json()
            summary = data.get("requestSummary") if isinstance(data, dict) else None
            if not isinstance(summary, dict):
                return False
            if is_s4_abort_status(summary):
                logger.warning("SAST stream health poll returned abort state: %s", summary)
                return False
            return is_s4_alive_status(summary, expected_request_id=request_id)
        except Exception as exc:
            logger.warning("SAST stream health verification failed: %s", exc)
            return False

    @staticmethod
    def _build_result(data: dict, *, stall_detected: bool = False) -> ToolResult:
        """동기/스트리밍 공통 — ScanResponse를 ToolResult로 변환."""
        if data.get("success") is False:
            detail = data.get("failureDetail") or data.get("errorDetail")
            message = None
            code = None
            if isinstance(detail, dict):
                message = detail.get("message")
                code = detail.get("code") or detail.get("category")
            message = message or data.get("error") or data.get("message") or "SAST scan failed"
            error = f"{code}: {message}" if code else str(message)
            return ToolResult(
                tool_call_id="", name="", success=False,
                content=json.dumps(data, ensure_ascii=False),
                error=error,
            )

        findings = [SastFinding.model_validate(f) for f in data.get("findings", [])[:10]]
        new_refs = [f"eref-sast-{f.ruleId}" for f in findings if f.ruleId]

        # failed/partial 도구 감지 → 결과에 caveats 메타데이터 추가
        execution = data.get("execution", {})
        tool_results = execution.get("toolResults", {})
        incomplete_tools: list[str] = []
        for tool_name, tr in tool_results.items():
            status = tr.get("status", "ok")
            if status in ("failed", "partial"):
                reason = tr.get("skipReason", "") or tr.get("timedOutFiles", "")
                incomplete_tools.append(f"{tool_name}({status}: {reason})" if reason else f"{tool_name}({status})")

        static_contract = extract_static_evidence_contract(data)
        static_evidence_diagnostics = summarize_static_evidence_contract(static_contract)
        if incomplete_tools or stall_detected or static_evidence_diagnostics.get("ready") is False:
            data["_sast_caveats"] = {
                "incompleteTools": incomplete_tools,
                "stallDetected": stall_detected,
                "staticEvidenceDiagnostics": static_evidence_diagnostics,
            }

        return ToolResult(
            tool_call_id="", name="", success=True,
            content=json.dumps(data, ensure_ascii=False),
            new_evidence_refs=new_refs,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
