from __future__ import annotations

import httpx


WAIT_WHILE_ALIVE_TIMEOUT_POLICY = "wait-while-alive"
"""Paper-path producer calls must not fail only because wall-clock time elapsed.

The paper path can be substantially longer than the ordinary interactive S3
tools. Correctness policy is: if the producer service is alive/progressing, S3
keeps waiting; terminal producer failure is distinct from caller-side read
deadline expiry. Until every paper producer offers first-class async ownership
or heartbeat/status endpoints, S3 uses a compatibility transport timeout with
no read deadline.
"""


def wait_while_alive_http_timeout(
    *,
    connect: float = 10.0,
    write: float = 10.0,
    pool: float = 10.0,
) -> httpx.Timeout:
    """Return an HTTPX timeout that preserves bounded connection setup only.

    ``read=None`` is intentional: a long-running synchronous producer response
    is allowed to take arbitrarily long while the underlying connection remains
    alive. Connect/write/pool deadlines remain bounded because those are
    transport-acquisition failures, not long-running producer work.
    """

    return httpx.Timeout(connect=connect, read=None, write=write, pool=pool)


def wait_while_alive_headers(request_id: str | None = None) -> dict[str, str]:
    """Headers that advertise the paper path's liveness policy to producers."""

    headers = {"X-AEGIS-Timeout-Policy": WAIT_WHILE_ALIVE_TIMEOUT_POLICY}
    if request_id:
        headers["X-Request-Id"] = request_id
    return headers
