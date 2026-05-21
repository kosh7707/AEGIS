from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock


def _now_ms() -> int:
    return int(time.time() * 1000)


def _iso_from_ms(value: int | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, tz=UTC).isoformat()


@dataclass
class TrackedRequest:
    request_id: str
    endpoint: str
    task_type: str | None = None
    state: str = "queued"
    local_ack_state: str | None = "phase-advancing"
    degraded: bool = False
    degrade_reasons: list[str] = field(default_factory=list)
    last_ack_at: int | None = None
    last_ack_source: str | None = None
    blocked_reason: str | None = None
    phase: str | None = None
    started_at: int = field(default_factory=_now_ms)
    backend_started_at: int | None = None
    backend_last_activity_at: int | None = None
    backend_activity_source: str | None = None
    backend_stream_chunk_count: int = 0
    backend_response_bytes: int = 0
    backend_completion_chars: int = 0

    def backend_activity_summary(self, now_ms: int) -> dict | None:
        if self.backend_started_at is None:
            return None
        last_activity = self.backend_last_activity_at or self.backend_started_at
        return {
            "backendStartedAt": _iso_from_ms(self.backend_started_at),
            "lastBackendActivityAt": _iso_from_ms(last_activity),
            "backendElapsedMs": max(now_ms - self.backend_started_at, 0),
            "backendIdleMs": max(now_ms - last_activity, 0),
            "streamChunkCount": self.backend_stream_chunk_count,
            "responseBytes": self.backend_response_bytes,
            "approxCompletionChars": self.backend_completion_chars,
            "activitySource": self.backend_activity_source,
        }

    def to_summary(self, now_ms: int) -> dict:
        payload = {
            "requestId": self.request_id,
            "endpoint": self.endpoint,
            "taskType": self.task_type,
            "state": self.state,
            "localAckState": self.local_ack_state,
            "degraded": self.degraded,
            "degradeReasons": list(self.degrade_reasons),
            "lastAckAt": self.last_ack_at,
            "lastAckSource": self.last_ack_source,
            "blockedReason": self.blocked_reason,
            "phase": self.phase,
            "elapsedMs": max(now_ms - self.started_at, 0),
        }
        backend_activity = self.backend_activity_summary(now_ms)
        if backend_activity is not None:
            payload["backendActivity"] = backend_activity
        return payload


class RequestTracker:
    """현재 active request의 compact control-signal summary를 관리한다."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._requests: dict[str, TrackedRequest] = {}

    def register(self, request_id: str, *, endpoint: str, task_type: str | None = None) -> None:
        now_ms = _now_ms()
        with self._lock:
            self._requests[request_id] = TrackedRequest(
                request_id=request_id,
                endpoint=endpoint,
                task_type=task_type,
                state="queued",
                local_ack_state="phase-advancing",
                last_ack_at=now_ms,
                last_ack_source="request-accepted",
            )

    def mark_phase(
        self,
        request_id: str,
        *,
        phase: str,
        state: str = "running",
        ack_source: str,
        degraded: bool | None = None,
        degrade_reasons: list[str] | None = None,
    ) -> None:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return
            req.phase = phase
            req.state = state
            req.local_ack_state = "phase-advancing"
            req.last_ack_at = _now_ms()
            req.last_ack_source = ack_source
            if degraded is not None:
                req.degraded = degraded
            if degrade_reasons is not None:
                req.degrade_reasons = list(degrade_reasons)
            if not req.degraded:
                req.degrade_reasons = []
            req.blocked_reason = None

    def mark_transport_only(self, request_id: str, *, phase: str, source: str = "transport-alive") -> None:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return
            req.phase = phase
            req.state = "running"
            req.local_ack_state = "transport-only"
            if req.last_ack_source is None:
                req.last_ack_source = source

    def mark_backend_activity(
        self,
        request_id: str,
        *,
        source: str,
        response_bytes_increment: int = 0,
        completion_chars_increment: int = 0,
        stream_chunk_increment: int = 0,
    ) -> None:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return
            now_ms = _now_ms()
            req.state = "running"
            if req.backend_started_at is None:
                req.backend_started_at = now_ms
            req.backend_last_activity_at = now_ms
            req.backend_activity_source = source
            req.backend_response_bytes += max(response_bytes_increment, 0)
            req.backend_completion_chars += max(completion_chars_increment, 0)
            req.backend_stream_chunk_count += max(stream_chunk_increment, 0)

    def mark_ack_break(
        self,
        request_id: str,
        *,
        blocked_reason: str,
        ack_source: str = "ack-break",
    ) -> None:
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return
            req.state = "failed"
            req.local_ack_state = "ack-break"
            req.blocked_reason = blocked_reason
            req.last_ack_at = _now_ms()
            req.last_ack_source = ack_source

    def clear(self, request_id: str) -> None:
        with self._lock:
            self._requests.pop(request_id, None)

    def snapshot(self, *, request_id: str | None = None) -> dict:
        now_ms = _now_ms()
        with self._lock:
            active_requests = [
                req for req in self._requests.values()
                if req.state in {"queued", "running"}
            ]
            active_requests.sort(key=lambda req: req.started_at)

            if request_id:
                target = self._requests.get(request_id)
                if target is None or target.state not in {"queued", "running"}:
                    target = None
            else:
                target = active_requests[0] if active_requests else None

            return {
                "activeRequestCount": len(active_requests),
                "requestSummary": (
                    target.to_summary(now_ms)
                    if target is not None
                    else {
                        "requestId": None,
                        "endpoint": None,
                        "taskType": None,
                        "state": "idle",
                        "localAckState": None,
                        "degraded": False,
                        "degradeReasons": [],
                        "lastAckAt": None,
                        "lastAckSource": None,
                        "blockedReason": None,
                        "phase": None,
                        "elapsedMs": 0,
                    }
                ),
            }
