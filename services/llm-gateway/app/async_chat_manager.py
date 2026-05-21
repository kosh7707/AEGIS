from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Awaitable, Callable
from uuid import uuid4

from app.request_tracker import RequestTracker

logger = logging.getLogger(__name__)

_RETENTION_MS = 15 * 60 * 1000


def _now_ms() -> int:
    return int(time.time() * 1000)


def _iso_from_ms(value: int | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, tz=UTC).isoformat()


@dataclass
class AsyncChatRequestRecord:
    request_id: str
    trace_request_id: str
    status_url: str
    result_url: str
    cancel_url: str
    state: str = "queued"
    local_ack_state: str | None = "phase-advancing"
    phase: str | None = "queued"
    degraded: bool = False
    degrade_reasons: list[str] = field(default_factory=list)
    last_ack_at: int | None = None
    last_ack_source: str | None = None
    blocked_reason: str | None = None
    error: str | None = None
    error_detail: str | None = None
    retryable: bool = False
    result_ready: bool = False
    accepted_at_ms: int = field(default_factory=_now_ms)
    started_at_ms: int | None = None
    ended_at_ms: int | None = None
    expires_at_ms: int = field(default_factory=lambda: _now_ms() + _RETENTION_MS)
    response_payload: dict | None = None
    task: asyncio.Task | None = None
    backend_started_at_ms: int | None = None
    backend_last_activity_at_ms: int | None = None
    backend_activity_source: str | None = None
    backend_stream_chunk_count: int = 0
    backend_response_bytes: int = 0
    backend_completion_chars: int = 0

    def to_submit_response(self) -> dict:
        return {
            "requestId": self.request_id,
            "traceRequestId": self.trace_request_id,
            "status": "accepted",
            "statusUrl": self.status_url,
            "resultUrl": self.result_url,
            "cancelUrl": self.cancel_url,
            "acceptedAt": _iso_from_ms(self.accepted_at_ms),
            "expiresAt": _iso_from_ms(self.expires_at_ms),
        }

    def backend_activity_response(self) -> dict | None:
        if self.backend_started_at_ms is None:
            return None
        now_ms = _now_ms()
        last_activity_ms = self.backend_last_activity_at_ms or self.backend_started_at_ms
        return {
            "backendStartedAt": _iso_from_ms(self.backend_started_at_ms),
            "lastBackendActivityAt": _iso_from_ms(last_activity_ms),
            "backendElapsedMs": max(now_ms - self.backend_started_at_ms, 0),
            "backendIdleMs": max(now_ms - last_activity_ms, 0),
            "streamChunkCount": self.backend_stream_chunk_count,
            "responseBytes": self.backend_response_bytes,
            "approxCompletionChars": self.backend_completion_chars,
            "activitySource": self.backend_activity_source,
        }

    def to_status_response(self) -> dict:
        payload = {
            "requestId": self.request_id,
            "traceRequestId": self.trace_request_id,
            "state": self.state,
            "localAckState": self.local_ack_state,
            "phase": self.phase,
            "degraded": self.degraded,
            "degradeReasons": list(self.degrade_reasons),
            "lastAckAt": self.last_ack_at,
            "lastAckSource": self.last_ack_source,
            "blockedReason": self.blocked_reason,
            "error": self.error,
            "errorDetail": self.error_detail,
            "retryable": self.retryable,
            "resultReady": self.result_ready,
            "acceptedAt": _iso_from_ms(self.accepted_at_ms),
            "startedAt": _iso_from_ms(self.started_at_ms),
            "endedAt": _iso_from_ms(self.ended_at_ms),
            "expiresAt": _iso_from_ms(self.expires_at_ms),
            "statusUrl": self.status_url,
            "resultUrl": self.result_url,
            "cancelUrl": self.cancel_url,
        }
        backend_activity = self.backend_activity_response()
        if backend_activity is not None:
            payload["backendActivity"] = backend_activity
        return payload

    def to_result_response(self) -> dict:
        return {
            "requestId": self.request_id,
            "traceRequestId": self.trace_request_id,
            "state": self.state,
            "completedAt": _iso_from_ms(self.ended_at_ms),
            "expiresAt": _iso_from_ms(self.expires_at_ms),
            "response": self.response_payload,
        }


RunnerFn = Callable[[AsyncChatRequestRecord], Awaitable[None]]


class AsyncChatRequestManager:
    """Async ownership surface manager for reconnect-safe chat requests."""

    def __init__(self, request_tracker: RequestTracker | None = None) -> None:
        self._lock = asyncio.Lock()
        self._requests: dict[str, AsyncChatRequestRecord] = {}
        self._request_tracker = request_tracker

    async def submit(
        self,
        *,
        trace_request_id: str,
        runner: RunnerFn,
    ) -> AsyncChatRequestRecord:
        request_id = f"acr_{uuid4().hex[:16]}"
        status_url = f"/v1/async-chat-requests/{request_id}"
        result_url = f"{status_url}/result"
        cancel_url = status_url
        record = AsyncChatRequestRecord(
            request_id=request_id,
            trace_request_id=trace_request_id,
            status_url=status_url,
            result_url=result_url,
            cancel_url=cancel_url,
            last_ack_at=_now_ms(),
            last_ack_source="submit-accepted",
        )

        async with self._lock:
            self._requests[request_id] = record

        if self._request_tracker:
            self._request_tracker.register(request_id, endpoint="async-chat")

        task = asyncio.create_task(self._run(record.request_id, runner))
        async with self._lock:
            current = self._requests.get(request_id)
            if current is not None:
                current.task = task
        return record

    async def _run(self, request_id: str, runner: RunnerFn) -> None:
        record = await self.get_record(request_id)
        if record is None:
            return

        try:
            await runner(record)
        except asyncio.CancelledError:
            await self._mark_cancelled(
                request_id,
                blocked_reason="cancelled_by_client",
                ack_source="cancel",
            )
            raise
        except Exception:
            logger.exception("[async-chat] background request crashed requestId=%s", request_id)
            await self._mark_failed(
                request_id,
                blocked_reason="internal_error",
                ack_source="internal-error",
            )
        finally:
            async with self._lock:
                current = self._requests.get(request_id)
                if current is not None:
                    current.task = None

    async def mark_phase(
        self,
        request_id: str,
        *,
        phase: str,
        state: str = "running",
        ack_source: str,
        degraded: bool | None = None,
        degrade_reasons: list[str] | None = None,
    ) -> None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None:
                return
            now_ms = _now_ms()
            record.phase = phase
            record.state = state
            record.local_ack_state = "phase-advancing"
            record.last_ack_at = now_ms
            record.last_ack_source = ack_source
            record.blocked_reason = None
            if record.started_at_ms is None and state == "running":
                record.started_at_ms = now_ms
            if degraded is not None:
                record.degraded = degraded
            if degrade_reasons is not None:
                record.degrade_reasons = list(degrade_reasons)
            if not record.degraded:
                record.degrade_reasons = []

        if self._request_tracker:
            self._request_tracker.mark_phase(
                request_id,
                phase=phase,
                state=state,
                ack_source=ack_source,
                degraded=degraded,
                degrade_reasons=degrade_reasons,
            )

    async def mark_transport_only(
        self,
        request_id: str,
        *,
        phase: str,
        source: str = "transport-alive",
    ) -> None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None:
                return
            record.phase = phase
            record.state = "running"
            record.local_ack_state = "transport-only"
            if record.started_at_ms is None:
                record.started_at_ms = _now_ms()
            if record.last_ack_source is None:
                record.last_ack_source = source

        if self._request_tracker:
            self._request_tracker.mark_transport_only(
                request_id,
                phase=phase,
                source=source,
            )

    async def mark_backend_activity(
        self,
        request_id: str,
        *,
        source: str,
        response_bytes_increment: int = 0,
        completion_chars_increment: int = 0,
        stream_chunk_increment: int = 0,
    ) -> None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None:
                return
            now_ms = _now_ms()
            if record.started_at_ms is None:
                record.started_at_ms = now_ms
            if record.backend_started_at_ms is None:
                record.backend_started_at_ms = now_ms
            record.backend_last_activity_at_ms = now_ms
            record.backend_activity_source = source
            record.backend_response_bytes += max(response_bytes_increment, 0)
            record.backend_completion_chars += max(completion_chars_increment, 0)
            record.backend_stream_chunk_count += max(stream_chunk_increment, 0)

        if self._request_tracker:
            self._request_tracker.mark_backend_activity(
                request_id,
                source=source,
                response_bytes_increment=response_bytes_increment,
                completion_chars_increment=completion_chars_increment,
                stream_chunk_increment=stream_chunk_increment,
            )

    async def complete(self, request_id: str, *, response_payload: dict) -> None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None:
                return
            now_ms = _now_ms()
            record.state = "completed"
            record.local_ack_state = None
            record.phase = None
            record.blocked_reason = None
            record.result_ready = True
            record.response_payload = response_payload
            record.ended_at_ms = now_ms
            record.expires_at_ms = max(record.expires_at_ms, now_ms + _RETENTION_MS)

        if self._request_tracker:
            self._request_tracker.clear(request_id)

    async def fail(
        self,
        request_id: str,
        *,
        blocked_reason: str,
        ack_source: str = "ack-break",
        error: str | None = None,
        error_detail: str | None = None,
        retryable: bool = False,
    ) -> None:
        await self._mark_failed(
            request_id,
            blocked_reason=blocked_reason,
            ack_source=ack_source,
            error=error,
            error_detail=error_detail,
            retryable=retryable,
        )

    async def _mark_failed(
        self,
        request_id: str,
        *,
        blocked_reason: str,
        ack_source: str,
        error: str | None = None,
        error_detail: str | None = None,
        retryable: bool = False,
    ) -> None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None or record.state in {"completed", "failed", "cancelled", "expired"}:
                return
            now_ms = _now_ms()
            record.state = "failed"
            record.local_ack_state = "ack-break"
            record.phase = None
            record.blocked_reason = blocked_reason
            record.error = error or "Async request did not complete successfully"
            record.error_detail = error_detail or blocked_reason
            record.retryable = retryable
            record.result_ready = False
            record.ended_at_ms = now_ms
            record.expires_at_ms = max(record.expires_at_ms, now_ms + _RETENTION_MS)
            record.last_ack_at = now_ms
            record.last_ack_source = ack_source

        if self._request_tracker:
            self._request_tracker.mark_ack_break(
                request_id,
                blocked_reason=blocked_reason,
                ack_source=ack_source,
            )
            self._request_tracker.clear(request_id)

    async def cancel(self, request_id: str) -> AsyncChatRequestRecord | None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None:
                return None
            task = record.task

        await self._mark_cancelled(
            request_id,
            blocked_reason="cancelled_by_client",
            ack_source="cancel",
        )

        if task is not None and not task.done():
            task.cancel()

        return await self.get_record(request_id)

    async def _mark_cancelled(
        self,
        request_id: str,
        *,
        blocked_reason: str,
        ack_source: str,
    ) -> None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None or record.state in {"completed", "failed", "cancelled", "expired"}:
                return
            now_ms = _now_ms()
            record.state = "cancelled"
            record.local_ack_state = "ack-break"
            record.phase = None
            record.blocked_reason = blocked_reason
            record.result_ready = False
            record.ended_at_ms = now_ms
            record.expires_at_ms = max(record.expires_at_ms, now_ms + _RETENTION_MS)
            record.last_ack_at = now_ms
            record.last_ack_source = ack_source

        if self._request_tracker:
            self._request_tracker.mark_ack_break(
                request_id,
                blocked_reason=blocked_reason,
                ack_source=ack_source,
            )
            self._request_tracker.clear(request_id)

    async def get_record(self, request_id: str) -> AsyncChatRequestRecord | None:
        async with self._lock:
            record = self._requests.get(request_id)
            if record is None:
                return None
            self._refresh_active_lease_locked(record)
            self._expire_locked(record)
            return record

    async def status(self, request_id: str) -> dict | None:
        record = await self.get_record(request_id)
        if record is None:
            return None
        return record.to_status_response()

    async def result(self, request_id: str) -> AsyncChatRequestRecord | None:
        return await self.get_record(request_id)

    async def close(self) -> None:
        async with self._lock:
            tasks = [
                record.task
                for record in self._requests.values()
                if record.task is not None and not record.task.done()
            ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _expire_locked(self, record: AsyncChatRequestRecord) -> None:
        if record.state not in {"completed", "failed", "cancelled"}:
            return
        if _now_ms() <= record.expires_at_ms:
            return
        record.state = "expired"
        record.local_ack_state = None
        record.phase = None
        record.blocked_reason = None
        record.result_ready = False
        record.response_payload = None

    def _refresh_active_lease_locked(self, record: AsyncChatRequestRecord) -> None:
        """Keep active async ownership leases fresh while work is alive.

        `expires_at_ms` is the retention/ownership lease timestamp exposed to
        callers. For queued/running requests it must not become an elapsed-age
        abort signal; terminal records still use the fixed retention window and
        may later become explicitly `expired`.
        """
        if record.state not in {"queued", "running"}:
            return
        now_ms = _now_ms()
        record.expires_at_ms = max(record.expires_at_ms, now_ms + _RETENTION_MS)
