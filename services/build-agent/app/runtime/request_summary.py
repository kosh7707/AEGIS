from __future__ import annotations

import threading
import time
from copy import deepcopy
from typing import Any


_RETENTION_SECONDS = 300


def _now_ms() -> int:
    return int(time.time() * 1000)


def _idle_summary() -> dict[str, Any]:
    return {
        "requestId": None,
        "endpoint": "tasks",
        "state": "idle",
        "localAckState": None,
        "degraded": False,
        "degradeReasons": [],
        "lastAckAt": None,
        "lastAckSource": None,
        "blockedReason": None,
    }


class RequestSummaryTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    def reset(self) -> None:
        with self._lock:
            self._entries = {}

    def _prune_locked(self) -> None:
        cutoff = _now_ms() - (_RETENTION_SECONDS * 1000)
        expired = [
            request_id
            for request_id, entry in self._entries.items()
            if entry.get("state") in {"completed", "failed"} and (entry.get("lastAckAt") or 0) < cutoff
        ]
        for request_id in expired:
            self._entries.pop(request_id, None)

    def register(self, request_id: str, *, endpoint: str = "tasks") -> None:
        with self._lock:
            self._prune_locked()
            summary = _idle_summary()
            now = _now_ms()
            summary.update(
                {
                    "requestId": request_id,
                    "endpoint": endpoint,
                    "state": "queued",
                    "localAckState": "phase-advancing",
                    "lastAckAt": now,
                    "lastAckSource": "request-accepted",
                },
            )
            self._entries[request_id] = summary

    def mark_phase_advancing(
        self,
        request_id: str,
        *,
        source: str,
        degraded: bool | None = None,
        degrade_reasons: list[str] | None = None,
    ) -> None:
        updates: dict[str, Any] = {
            "state": "running",
            "localAckState": "phase-advancing",
            "lastAckSource": source,
        }
        if degraded is not None:
            updates["degraded"] = degraded
        if degrade_reasons is not None:
            updates["degradeReasons"] = list(degrade_reasons)
        self._update(request_id, **updates)

    def mark_transport_only(self, request_id: str, *, source: str) -> None:
        self._update(
            request_id,
            state="running",
            localAckState="transport-only",
            lastAckSource=source,
        )

    def mark_completed(self, request_id: str) -> None:
        self._update(
            request_id,
            state="completed",
            localAckState=None,
            blockedReason=None,
            lastAckSource="terminal-result",
        )

    def mark_failed(self, request_id: str, reason: str) -> None:
        self._update(
            request_id,
            state="failed",
            localAckState="ack-break",
            blockedReason=reason,
            lastAckSource="ack-break",
        )

    def _update(self, request_id: str, **updates: Any) -> None:
        with self._lock:
            entry = self._entries.get(request_id)
            if not entry:
                return
            entry.update(updates)
            entry["lastAckAt"] = _now_ms()

    def active_request_count(self) -> int:
        with self._lock:
            self._prune_locked()
            return sum(1 for entry in self._entries.values() if entry.get("state") in {"queued", "running"})

    def get_summary(self, request_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            self._prune_locked()
            if request_id:
                entry = self._entries.get(request_id)
                if not entry or entry.get("state") == "completed":
                    return _idle_summary()
                return deepcopy(entry)

            active_entries = [
                entry
                for entry in self._entries.values()
                if entry.get("state") in {"queued", "running"}
            ]
            if active_entries:
                active_entries.sort(
                    key=lambda entry: (
                        0 if entry.get("state") == "running" else 1,
                        -(entry.get("lastAckAt") or 0),
                    ),
                )
                return deepcopy(active_entries[0])

            return _idle_summary()


request_summary_tracker = RequestSummaryTracker()
