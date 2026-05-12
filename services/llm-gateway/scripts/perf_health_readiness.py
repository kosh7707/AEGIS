#!/usr/bin/env python3
"""Evaluator for S7 /v1/health backend-readiness cache performance.

This is intentionally deterministic: it uses FastAPI TestClient and a mocked
backend health probe with a configurable delay, then compares uncached vs cached
real-mode /v1/health calls in the same process.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings
from app.main import app


@dataclass
class RunResult:
    mean_ms: float
    p95_ms: float
    backend_probe_calls: int
    bodies: list[dict[str, Any]]


def _clear_cache() -> None:
    for attr in ("llm_backend_health_cache", "llm_backend_health_cache_lock"):
        if hasattr(app.state, attr):
            delattr(app.state, attr)


def _percentile_95(samples: list[float]) -> float:
    if len(samples) < 2:
        return samples[0]
    return statistics.quantiles(samples, n=20)[18]


def _make_probe(delay_seconds: float, *, fail_after_first: bool = False):
    calls = {"count": 0}

    async def fake_get(url: str, timeout: float | None = None):
        del timeout
        calls["count"] += 1
        await asyncio.sleep(delay_seconds)
        if fail_after_first and calls["count"] > 1:
            raise httpx.ConnectError("simulated backend unreachable after cache expiry")
        return httpx.Response(200, request=httpx.Request("GET", url))

    return calls, fake_get


def _run_health_batch(client: TestClient, *, requests: int, delay_seconds: float) -> RunResult:
    calls, fake_get = _make_probe(delay_seconds)
    original_get = app.state.proxy_client.get
    app.state.proxy_client.get = fake_get
    durations: list[float] = []
    bodies: list[dict[str, Any]] = []
    try:
        for _ in range(requests):
            started = time.perf_counter()
            resp = client.get("/v1/health")
            durations.append((time.perf_counter() - started) * 1000)
            resp.raise_for_status()
            bodies.append(resp.json())
    finally:
        app.state.proxy_client.get = original_get
    return RunResult(
        mean_ms=statistics.mean(durations),
        p95_ms=_percentile_95(durations),
        backend_probe_calls=calls["count"],
        bodies=bodies,
    )


def _assert_cache_expiry_reports_unreachable(client: TestClient, *, delay_seconds: float) -> None:
    _clear_cache()
    object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.05)
    calls, fake_get = _make_probe(delay_seconds, fail_after_first=True)
    original_get = app.state.proxy_client.get
    app.state.proxy_client.get = fake_get
    try:
        first = client.get("/v1/health")
        first.raise_for_status()
        time.sleep(0.07)
        second = client.get("/v1/health")
        second.raise_for_status()
    finally:
        app.state.proxy_client.get = original_get
        _clear_cache()

    first_body = first.json()
    second_body = second.json()
    if calls["count"] < 2:
        raise AssertionError(f"cache did not refresh after TTL expiry; calls={calls['count']}")
    if first_body["llmBackend"]["status"] != "ok":
        raise AssertionError(f"first readiness probe was not ok: {first_body['llmBackend']}")
    if second_body["llmBackend"]["status"] != "unreachable":
        raise AssertionError(f"expired cache hid unreachable backend: {second_body['llmBackend']}")
    if second_body["ready"] is not False or second_body["llmReady"] is not False:
        raise AssertionError("unreachable backend after TTL must report ready=false and llmReady=false")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-delay-ms", type=float, default=200.0)
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--min-improvement-ratio", type=float, default=0.50)
    args = parser.parse_args()

    original_mode = settings.llm_mode
    original_rag = settings.rag_enabled
    original_ttl = settings.llm_health_cache_ttl_seconds
    delay_seconds = args.backend_delay_ms / 1000.0

    # Start TestClient in mock mode to avoid a real LLM warmup request.  The
    # evaluator switches to real mode after lifespan startup because it only
    # exercises the health route and replaces proxy_client.get with a mock.
    object.__setattr__(settings, "llm_mode", "mock")
    object.__setattr__(settings, "rag_enabled", False)

    try:
        with TestClient(app) as client:
            object.__setattr__(settings, "llm_mode", "real")
            _clear_cache()
            object.__setattr__(settings, "llm_health_cache_ttl_seconds", 0.0)
            uncached = _run_health_batch(client, requests=args.requests, delay_seconds=delay_seconds)

            _clear_cache()
            object.__setattr__(settings, "llm_health_cache_ttl_seconds", 30.0)
            cached = _run_health_batch(client, requests=args.requests, delay_seconds=delay_seconds)

            _assert_cache_expiry_reports_unreachable(client, delay_seconds=0.0)
    finally:
        object.__setattr__(settings, "llm_mode", original_mode)
        object.__setattr__(settings, "rag_enabled", original_rag)
        object.__setattr__(settings, "llm_health_cache_ttl_seconds", original_ttl)
        _clear_cache()

    improvement = 1.0 - (cached.mean_ms / uncached.mean_ms)
    print(
        "health-readiness-cache evaluator: "
        f"uncached_mean_ms={uncached.mean_ms:.2f} "
        f"cached_mean_ms={cached.mean_ms:.2f} "
        f"improvement={improvement:.3f} "
        f"uncached_p95_ms={uncached.p95_ms:.2f} "
        f"cached_p95_ms={cached.p95_ms:.2f} "
        f"uncached_probe_calls={uncached.backend_probe_calls} "
        f"cached_probe_calls={cached.backend_probe_calls}"
    )

    if improvement < args.min_improvement_ratio:
        raise SystemExit(
            f"FAIL: improvement {improvement:.3f} < required {args.min_improvement_ratio:.3f}"
        )
    if cached.backend_probe_calls >= uncached.backend_probe_calls:
        raise SystemExit(
            "FAIL: cached run did not reduce backend probe calls: "
            f"cached={cached.backend_probe_calls} uncached={uncached.backend_probe_calls}"
        )
    if cached.backend_probe_calls != 1:
        raise SystemExit(f"FAIL: cached run should probe backend once, got {cached.backend_probe_calls}")
    if cached.bodies[0]["llmBackend"].get("cached") is not False:
        raise SystemExit("FAIL: first cached-window response must be fresh")
    if not all(body["llmBackend"].get("cached") is True for body in cached.bodies[1:]):
        raise SystemExit("FAIL: subsequent cached-window responses must report cached=true")
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
