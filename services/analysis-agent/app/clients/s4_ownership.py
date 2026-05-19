"""S4 durable ownership helpers for health-control v2 wait-while-alive callers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

_CONTINUE_ACK_STATES = {"phase-advancing", "transport-only", None}
_TERMINAL_STATES = {"failed", "cancelled", "expired"}
_UNSUPPORTED_STATUS = {404, 405, 501}
_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]+")


class S4OwnershipUnsupported(RuntimeError):
    """Raised when the producer does not expose durable ownership for a path."""


class S4OwnershipError(RuntimeError):
    """Raised for explicit terminal/blocked ownership failures."""

    def __init__(self, message: str, *, status_code: int | None = None, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


@dataclass(frozen=True)
class S4OwnershipResult:
    request_id: str
    payload: dict[str, Any]
    raw: dict[str, Any]


def _safe_id(value: str) -> str:
    cleaned = _SAFE_ID_RE.sub("-", value.strip())
    return cleaned[:80] or "s3"


def make_s4_operation_request_id(
    root_request_id: str | None,
    *,
    endpoint: str,
    operation: str,
    payload: dict[str, Any],
) -> str:
    """Derive an endpoint/attempt-specific S4 ownership key.

    Same endpoint + same logical operation + identical payload reuses the key for
    uncertain transport retry. A changed build command/environment/provenance or
    a different endpoint produces a different key, preventing stale S4 reuse.
    """
    root = _safe_id(root_request_id or "s3-request")
    endpoint_key = _safe_id(endpoint.strip("/").replace("/", "-"))
    operation_key = _safe_id(operation)
    material = json.dumps(
        {"endpoint": endpoint, "operation": operation, "payload": payload},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{root}:s4:{endpoint_key}:{operation_key}:{digest}"


def resolve_s4_url(base_url: str, value: str | None, fallback_path: str) -> str:
    base = base_url.rstrip("/")
    if isinstance(value, str) and value:
        if value.startswith("http://") or value.startswith("https://"):
            return value
        if value.startswith("/"):
            return f"{base}{value}"
    return f"{base}{fallback_path}"


def unwrap_s4_result_payload(data: dict[str, Any]) -> dict[str, Any]:
    nested = data.get("result")
    if isinstance(nested, dict):
        return nested
    nested = data.get("data")
    if isinstance(nested, dict):
        return nested
    return data



def _response_payload(resp) -> Any:
    try:
        return resp.json()
    except Exception:
        return getattr(resp, "text", "")[:500]


def _is_continue_state(status_data: dict[str, Any]) -> bool:
    state = status_data.get("state")
    ack = status_data.get("localAckState")
    blocked = status_data.get("blockedReason")
    return state in {"queued", "running"} and ack in _CONTINUE_ACK_STATES and not blocked


def is_s4_alive_status(status_data: dict[str, Any], *, expected_request_id: str | None = None) -> bool:
    if expected_request_id and status_data.get("requestId") not in {expected_request_id, None}:
        return False
    return _is_continue_state(status_data)


def is_s4_abort_status(status_data: dict[str, Any]) -> bool:
    return (
        bool(status_data.get("blockedReason"))
        or status_data.get("localAckState") == "ack-break"
        or status_data.get("state") in _TERMINAL_STATES
    )


async def post_and_wait_s4_ownership(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    endpoint_path: str,
    payload: dict[str, Any],
    root_request_id: str | None,
    operation: str,
    poll_interval_seconds: float = 1.0,
    submit_timeout_seconds: float = 30.0,
    poll_timeout_seconds: float = 30.0,
) -> S4OwnershipResult:
    endpoint_path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
    request_id = make_s4_operation_request_id(
        root_request_id,
        endpoint=endpoint_path,
        operation=operation,
        payload=payload,
    )
    headers = {
        "Prefer": "respond-async",
        "X-Request-Id": request_id,
    }
    submit_url = resolve_s4_url(base_url, endpoint_path, endpoint_path)
    submit_resp = await client.post(
        submit_url,
        json=payload,
        headers=headers,
        timeout=httpx.Timeout(connect=10.0, read=submit_timeout_seconds, write=10.0, pool=10.0),
    )

    if submit_resp.status_code in _UNSUPPORTED_STATUS:
        raise S4OwnershipUnsupported(f"S4 durable ownership unsupported for {endpoint_path}")
    if submit_resp.status_code == 409:
        raise S4OwnershipError("S4 request id conflict", status_code=409, payload=_response_payload(submit_resp))
    if submit_resp.status_code >= 400:
        try:
            error_payload: Any = submit_resp.json()
        except Exception:
            error_payload = submit_resp.text[:500]
        raise S4OwnershipError(
            f"S4 submit failed with HTTP {submit_resp.status_code}",
            status_code=submit_resp.status_code,
            payload=error_payload,
        )

    submit_data = submit_resp.json()
    if submit_resp.status_code == 200 and not submit_data.get("statusUrl") and not submit_data.get("requestId"):
        return S4OwnershipResult(request_id=request_id, payload=submit_data, raw=submit_data)

    owner_request_id = submit_data.get("requestId") or request_id
    status_url = resolve_s4_url(base_url, submit_data.get("statusUrl"), f"/v1/requests/{owner_request_id}")
    result_url = resolve_s4_url(base_url, submit_data.get("resultUrl"), f"/v1/requests/{owner_request_id}/result")
    poll_headers = {"X-Request-Id": request_id}

    while True:
        status_resp = await client.get(
            status_url,
            headers=poll_headers,
            timeout=httpx.Timeout(connect=10.0, read=poll_timeout_seconds, write=10.0, pool=10.0),
        )
        if status_resp.status_code == 409:
            raise S4OwnershipError("S4 request id conflict", status_code=409, payload=_response_payload(status_resp))
        if status_resp.status_code in {404, 410}:
            raise S4OwnershipError(
                f"S4 ownership unavailable with HTTP {status_resp.status_code}",
                status_code=status_resp.status_code,
                payload=_response_payload(status_resp),
            )
        if status_resp.status_code >= 400:
            raise S4OwnershipError(
                f"S4 status failed with HTTP {status_resp.status_code}",
                status_code=status_resp.status_code,
                payload=_response_payload(status_resp),
            )
        status_data = status_resp.json()
        state = status_data.get("state")
        blocked = status_data.get("blockedReason")
        ack = status_data.get("localAckState")
        result_ready = bool(status_data.get("resultReady"))

        if _is_continue_state(status_data) and not result_ready:
            await asyncio.sleep(poll_interval_seconds)
            continue

        if blocked or ack == "ack-break":
            reason = blocked or f"S4 ownership terminal state={state}"
            raise S4OwnershipError(reason, payload=status_data)

        should_fetch_result = state == "completed" or result_ready or state == "failed"
        if should_fetch_result:
            result_resp = await client.get(
                result_url,
                headers=poll_headers,
                timeout=httpx.Timeout(connect=10.0, read=poll_timeout_seconds, write=10.0, pool=10.0),
            )
            if result_resp.status_code == 202:
                await asyncio.sleep(poll_interval_seconds)
                continue
            if result_resp.status_code == 409:
                raise S4OwnershipError("S4 request id conflict", status_code=409, payload=_response_payload(result_resp))
            if result_resp.status_code in {404, 410}:
                raise S4OwnershipError(
                    f"S4 result unavailable with HTTP {result_resp.status_code}",
                    status_code=result_resp.status_code,
                    payload=_response_payload(result_resp),
                )
            if result_resp.status_code >= 400:
                raise S4OwnershipError(
                    f"S4 result failed with HTTP {result_resp.status_code}",
                    status_code=result_resp.status_code,
                    payload=_response_payload(result_resp),
                )
            result_data = result_resp.json()
            return S4OwnershipResult(
                request_id=owner_request_id,
                payload=unwrap_s4_result_payload(result_data),
                raw=result_data,
            )

        if state in _TERMINAL_STATES:
            raise S4OwnershipError(f"S4 ownership terminal state={state}", payload=status_data)

        raise S4OwnershipError(f"Unknown S4 ownership state: {state}", payload=status_data)
