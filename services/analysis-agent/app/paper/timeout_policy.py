from __future__ import annotations

import httpx


"""Transport timeout helpers for long-running TraceAudit paper calls.

The paper path can be substantially longer than ordinary interactive S3 tools.
Correctness policy is: terminal producer status is evidence of producer outcome;
caller-side read-deadline expiry is not. Producer correlation is carried by
``X-Request-Id`` at each service boundary, not by legacy timeout-policy headers.
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
