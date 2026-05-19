from __future__ import annotations

import asyncio
import time
from copy import deepcopy
from typing import Any, Awaitable, Callable

from pydantic import BaseModel

from app.errors import INTERNAL_ERROR_MESSAGE, PolicyViolationError, SastRunnerError
from app.runtime.request_summary import request_summary_tracker

_RETENTION_SECONDS = 300


def _now_ms() -> int:
    return int(time.time() * 1000)


def _urls(request_id: str) -> tuple[str, str]:
    return f"/v1/requests/{request_id}", f"/v1/requests/{request_id}/result"


def _payload(value: Any) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        return value.model_dump(by_alias=True, exclude_none=True)
    if isinstance(value, dict):
        return deepcopy(value)
    return {"value": value}


def _is_success(payload: dict[str, Any]) -> bool:
    return payload.get("success") is True


def _blocked_reason(payload: dict[str, Any], fallback: str = "request failed") -> str:
    failure = payload.get("failureDetail") or payload.get("errorDetail") or {}
    if isinstance(failure, dict):
        for key in ("summary", "message", "code", "category"):
            if failure.get(key):
                return str(failure[key])
    if payload.get("error"):
        return str(payload["error"])
    if payload.get("message"):
        return str(payload["message"])
    nested_build = payload.get("build")
    if isinstance(nested_build, dict) and nested_build.get("success") is False:
        return _blocked_reason(nested_build, fallback)
    return fallback


def _cancel_payload(request_id: str, reason: str = "request cancelled") -> dict[str, Any]:
    return {
        "success": False,
        "error": reason,
        "errorDetail": {
            "code": "REQUEST_CANCELLED",
            "message": reason,
            "requestId": request_id,
            "retryable": False,
        },
    }


def _request_error_payload(*, code: str, message: str, request_id: str) -> dict[str, Any]:
    return {
        "success": False,
        "error": code,
        "requestId": request_id,
        "errorDetail": {
            "code": code,
            "message": message,
            "requestId": request_id,
            "retryable": False,
        },
    }


class RequestOwnershipStore:
    def __init__(self, retention_seconds: int = _RETENTION_SECONDS) -> None:
        self.retention_seconds = retention_seconds
        self._lock = asyncio.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    async def reset(self) -> None:
        async with self._lock:
            self._entries = {}

    async def submit(
        self,
        request_id: str,
        *,
        endpoint: str,
        runner: Callable[[], Awaitable[Any]],
    ) -> tuple[dict[str, Any], int]:
        async with self._lock:
            self._prune_locked()
            existing = self._entries.get(request_id)
            if existing and not self._is_expired_locked(existing):
                if existing.get("endpoint") != endpoint:
                    payload = _request_error_payload(
                        code="REQUEST_ID_CONFLICT",
                        message="request id already belongs to another endpoint",
                        request_id=request_id,
                    )
                    payload.update(
                        {
                            "existingEndpoint": existing.get("endpoint"),
                            "requestedEndpoint": endpoint,
                            "statusUrl": existing.get("statusUrl"),
                            "resultUrl": existing.get("resultUrl"),
                        }
                    )
                    return payload, 409
                status_code = 202 if existing["state"] in {"queued", "running"} else 200
                return self._status_locked(existing, reused=True), status_code

            submitted_at = _now_ms()
            status_url, result_url = _urls(request_id)
            entry = {
                "requestId": request_id,
                "endpoint": endpoint,
                "state": "queued",
                "resultReady": False,
                "statusUrl": status_url,
                "resultUrl": result_url,
                "submittedAt": submitted_at,
                "startedAt": None,
                "completedAt": None,
                "expiresAt": None,
                "result": None,
                "error": None,
                "task": None,
            }
            self._entries[request_id] = entry
            request_summary_tracker.register(request_id, endpoint=endpoint)
            entry["task"] = asyncio.create_task(self._run_owned(request_id, runner))
            return self._status_locked(entry), 202

    async def _run_owned(self, request_id: str, runner: Callable[[], Awaitable[Any]]) -> None:
        async with self._lock:
            entry = self._entries.get(request_id)
            if entry:
                entry["state"] = "running"
                entry["startedAt"] = _now_ms()
        try:
            result = await runner()
            payload = _payload(result)
            if _is_success(payload):
                await self._complete(request_id, "completed", payload)
                request_summary_tracker.mark_completed(request_id)
            else:
                reason = _blocked_reason(payload)
                request_summary_tracker.mark_failed(request_id, reason)
                await self._complete(request_id, "failed", payload, error=reason)
        except asyncio.CancelledError:
            reason = "request cancelled"
            payload = _cancel_payload(request_id, reason)
            request_summary_tracker.mark_cancelled(request_id, reason)
            await self._complete(request_id, "cancelled", payload, error=reason)
        except PolicyViolationError as exc:
            payload = _payload(exc.scan_response)
            reason = exc.message
            request_summary_tracker.mark_failed(request_id, reason)
            await self._complete(request_id, "failed", payload, error=reason)
        except SastRunnerError as exc:
            payload = {
                "success": False,
                "error": exc.message,
                "errorDetail": {
                    "code": exc.code,
                    "message": exc.message,
                    "requestId": request_id,
                    "retryable": exc.retryable,
                },
            }
            request_summary_tracker.mark_failed(request_id, exc.message)
            await self._complete(request_id, "failed", payload, error=exc.message)
        except Exception as exc:  # pragma: no cover - defensive wrapper
            payload = {
                "success": False,
                "error": INTERNAL_ERROR_MESSAGE,
                "errorDetail": {
                    "code": "INTERNAL_ERROR",
                    "message": INTERNAL_ERROR_MESSAGE,
                    "requestId": request_id,
                    "retryable": False,
                },
            }
            request_summary_tracker.mark_failed(request_id, INTERNAL_ERROR_MESSAGE)
            await self._complete(
                request_id,
                "failed",
                payload,
                error=INTERNAL_ERROR_MESSAGE,
            )

    async def _complete(
        self,
        request_id: str,
        state: str,
        payload: dict[str, Any],
        *,
        error: str | None = None,
    ) -> None:
        async with self._lock:
            entry = self._entries.get(request_id)
            if not entry:
                return
            if entry.get("state") == "cancelled" and state != "cancelled":
                return
            completed_at = _now_ms()
            entry.update(
                {
                    "state": state,
                    "resultReady": True,
                    "completedAt": completed_at,
                    "expiresAt": completed_at + self.retention_seconds * 1000,
                    "result": payload,
                    "error": error,
                },
            )

    async def get_status(self, request_id: str) -> tuple[dict[str, Any], int]:
        async with self._lock:
            self._prune_locked()
            entry = self._entries.get(request_id)
            if not entry:
                return _request_error_payload(
                    code="REQUEST_NOT_FOUND",
                    message="request not found",
                    request_id=request_id,
                ), 404
            if self._is_expired_locked(entry):
                return _request_error_payload(
                    code="REQUEST_EXPIRED",
                    message="request expired",
                    request_id=request_id,
                ), 410
            return self._status_locked(entry), 200

    async def get_result(self, request_id: str) -> tuple[dict[str, Any], int]:
        async with self._lock:
            self._prune_locked()
            entry = self._entries.get(request_id)
            if not entry:
                return _request_error_payload(
                    code="REQUEST_NOT_FOUND",
                    message="request not found",
                    request_id=request_id,
                ), 404
            if self._is_expired_locked(entry):
                return _request_error_payload(
                    code="REQUEST_EXPIRED",
                    message="request expired",
                    request_id=request_id,
                ), 410
            if entry["state"] in {"queued", "running"}:
                return self._status_locked(entry), 202
            return self._result_locked(entry), 200

    async def cancel(self, request_id: str) -> tuple[dict[str, Any], int]:
        async with self._lock:
            self._prune_locked()
            entry = self._entries.get(request_id)
            if not entry:
                return _request_error_payload(
                    code="REQUEST_NOT_FOUND",
                    message="request not found",
                    request_id=request_id,
                ), 404
            if self._is_expired_locked(entry):
                return _request_error_payload(
                    code="REQUEST_EXPIRED",
                    message="request expired",
                    request_id=request_id,
                ), 410

            if entry["state"] in {"queued", "running"}:
                task = entry.get("task")
                if task and not task.done():
                    task.cancel()

                reason = "request cancelled"
                completed_at = _now_ms()
                entry.update(
                    {
                        "state": "cancelled",
                        "resultReady": True,
                        "completedAt": completed_at,
                        "expiresAt": completed_at + self.retention_seconds * 1000,
                        "result": _cancel_payload(request_id, reason),
                        "error": reason,
                    },
                )
                request_summary_tracker.mark_cancelled(request_id, reason)
                return self._result_locked(entry), 202

            return self._result_locked(entry), 200

    def _status_locked(self, entry: dict[str, Any], *, reused: bool = False) -> dict[str, Any]:
        status = {
            key: deepcopy(entry.get(key))
            for key in (
                "requestId",
                "endpoint",
                "state",
                "resultReady",
                "statusUrl",
                "resultUrl",
                "submittedAt",
                "startedAt",
                "completedAt",
                "expiresAt",
            )
        }
        status["requestSummary"] = request_summary_tracker.get_summary(entry["requestId"])
        if reused:
            status["reused"] = True
        return status

    def _result_locked(self, entry: dict[str, Any]) -> dict[str, Any]:
        envelope = self._status_locked(entry)
        envelope["result"] = deepcopy(entry.get("result"))
        if entry.get("error"):
            envelope["error"] = entry["error"]
        return envelope

    def _is_expired_locked(self, entry: dict[str, Any]) -> bool:
        expires_at = entry.get("expiresAt")
        return bool(expires_at and expires_at <= _now_ms())

    def _prune_locked(self) -> None:
        expired_ids = [rid for rid, entry in self._entries.items() if self._is_expired_locked(entry)]
        for rid in expired_ids:
            entry = self._entries[rid]
            entry["state"] = "expired"
            entry["result"] = None
            entry["resultReady"] = False


request_ownership_store = RequestOwnershipStore()
