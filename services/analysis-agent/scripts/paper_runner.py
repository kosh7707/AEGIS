#!/usr/bin/env python3
"""Sequential TraceAudit paper-case runner.

This is intentionally a thin client-side sequencer. S3 remains responsible for a
single case only: create/register, synchronous start, status, and artifacts.
The runner records every case result and exits non-zero if any case fails.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx


class PaperHttpClient(Protocol):
    def post(self, url: str, *, json: dict[str, Any] | None = None) -> Any: ...
    def get(self, url: str) -> Any: ...


@dataclass
class RunnerResult:
    ok: bool
    summary: dict[str, Any]


def wait_while_alive_http_timeout(*, connect: float = 10.0, write: float = 10.0, pool: float = 10.0) -> httpx.Timeout:
    """Bound transport setup, but never impose a paper-case read deadline."""

    return httpx.Timeout(connect=connect, read=None, write=write, pool=pool)


def load_manifest(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        cases = data
    elif isinstance(data, dict) and isinstance(data.get("cases"), list):
        cases = data["cases"]
    else:
        raise ValueError("paper runner manifest must be a JSON array or an object with cases[]")
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"cases[{index}] must be an object")
        if not case.get("caseId"):
            raise ValueError(f"cases[{index}] missing caseId")
    return cases


def run_cases(
    cases: list[dict[str, Any]],
    *,
    client: PaperHttpClient,
    base_url: str,
    fail_fast: bool = False,
) -> RunnerResult:
    base = base_url.rstrip("/")
    results: list[dict[str, Any]] = []
    ok = True
    for index, case in enumerate(cases):
        case_id = str(case["caseId"])
        record: dict[str, Any] = {"index": index, "caseId": case_id, "ok": False}
        try:
            create_resp = client.post(f"{base}/v1/paper/analysis-cases", json=case)
            record["createStatusCode"] = create_resp.status_code
            record["createBody"] = _json_or_text(create_resp)
            if create_resp.status_code not in {200, 201}:
                raise RuntimeError(f"create failed with HTTP {create_resp.status_code}")

            start_resp = client.post(f"{base}/v1/paper/analysis-cases/{case_id}/start")
            record["startStatusCode"] = start_resp.status_code
            record["startBody"] = _json_or_text(start_resp)
            if start_resp.status_code != 200:
                raise RuntimeError(f"start failed with HTTP {start_resp.status_code}")
            start_body = record["startBody"] if isinstance(record["startBody"], dict) else {}
            if start_body.get("status") != "PAPER_EXPORT_READY":
                raise RuntimeError(f"start did not reach PAPER_EXPORT_READY: {start_body.get('status')}")

            artifacts_resp = client.get(f"{base}/v1/paper/analysis-cases/{case_id}/artifacts")
            record["artifactsStatusCode"] = artifacts_resp.status_code
            record["artifactsBody"] = _json_or_text(artifacts_resp)
            if artifacts_resp.status_code != 200:
                raise RuntimeError(f"artifacts failed with HTTP {artifacts_resp.status_code}")
            record["ok"] = True
        except Exception as exc:  # deliberately record and continue unless fail-fast
            ok = False
            record["error"] = str(exc)
            if fail_fast:
                results.append(record)
                break
        results.append(record)
    summary = {
        "ok": ok,
        "caseCount": len(cases),
        "completedCount": sum(1 for item in results if item.get("ok")),
        "failedCount": sum(1 for item in results if not item.get("ok")),
        "cases": results,
    }
    return RunnerResult(ok=ok, summary=summary)


def write_summary(path: str | Path, summary: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def _json_or_text(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return getattr(response, "text", "")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sequentially run S3 /v1/paper analysis cases.")
    parser.add_argument("--manifest", required=True, help="JSON array or object with cases[]")
    parser.add_argument("--base-url", default="http://localhost:8001", help="S3 analysis-agent base URL")
    parser.add_argument("--summary-out", required=True, help="Path for runner summary JSON")
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Deprecated compatibility flag. Paper runs no longer use an absolute read timeout.",
    )
    parser.add_argument("--fail-fast", action="store_true", help="Stop after the first failed case")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    cases = load_manifest(args.manifest)
    with httpx.Client(timeout=wait_while_alive_http_timeout()) as client:
        result = run_cases(cases, client=client, base_url=args.base_url, fail_fast=args.fail_fast)
    write_summary(args.summary_out, result.summary)
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
