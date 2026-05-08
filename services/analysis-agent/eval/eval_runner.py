"""eval_runner.py — 골든셋 → LLM 직접 호출 → 결과 수집 + 채점.

Phase 1 결과를 골든셋에서 가져와 build_phase2_prompt()로 프롬프트를 조립하고,
S7 Gateway에 도구 스키마 없이 직접 호출한다.
Analysis Agent 서비스 불필요 — S7 Gateway(8000)만 있으면 동작.

Usage:
    python -m eval.eval_runner --gateway-url http://localhost:8000 --run-id baseline-v1
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

# 프로젝트 루트를 sys.path에 추가 (eval/ 에서 app/ 임포트를 위해)
_PROJECT_ROOT = Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.core.phase_one import Phase1Result, build_phase2_prompt
from app.agent_runtime.llm.generation_policy import THINKING_GENERAL, TimeoutDefaults
from eval.scorer import score_response

_GOLDEN_DIR = Path(__file__).parent / "golden" / "cases"
_RESULTS_DIR = Path(__file__).parent / "results"
_ASYNC_UNSUPPORTED_RETRY_SECONDS = 60.0


def _load_golden_cases(golden_dir: Path, case_filter: str = "") -> list[dict]:
    """골든 케이스 JSON 파일을 로드한다."""
    cases = []
    for p in sorted(golden_dir.glob("*.json")):
        if case_filter and case_filter not in p.stem:
            continue
        cases.append(json.loads(p.read_text()))
    return cases


def _golden_to_phase1(golden: dict) -> Phase1Result:
    """골든 케이스 입력 → Phase1Result 객체."""
    inp = golden["input"]
    result = Phase1Result()
    result.sast_findings = inp.get("sast_findings", [])
    result.code_functions = inp.get("code_functions", [])
    result.threat_context = inp.get("threat_context", [])
    result.sca_libraries = inp.get("sca_libraries", [])
    result.cve_lookup = inp.get("cve_lookup", [])
    result.dangerous_callers = inp.get("dangerous_callers", [])
    result.project_memory = inp.get("project_memory", [])
    return result


def _build_evidence_refs(golden: dict) -> list[dict]:
    """골든 케이스에서 evidence ref 목록을 구성한다."""
    refs = []
    # 골든 입력의 명시적 refs
    for ref in golden.get("input", {}).get("evidence_refs", []):
        refs.append(ref)
    # SAST finding 기반 자동 생성 refs
    for i, f in enumerate(golden.get("input", {}).get("sast_findings", [])):
        rule = f.get("ruleId", f"finding-{i}")
        refs.append({
            "refId": f"eref-sast-{rule}",
            "artifactType": "sast-finding",
            "locator": f.get("location", {}),
        })
    return refs


def _build_prompt(golden: dict) -> tuple[str, str]:
    """골든 케이스 → Phase 2 시스템 프롬프트 + 유저 메시지."""
    phase1 = _golden_to_phase1(golden)
    trusted = {
        "objective": golden["input"].get("objective", "보안 취약점 심층 분석"),
        "projectId": f"eval-{golden['id']}",
        "files": [{"path": "src/source.c", "content": golden["input"].get("source_code", "")}],
    }
    evidence_refs = _build_evidence_refs(golden)

    system_prompt, user_message = build_phase2_prompt(
        phase1, trusted,
        evidence_refs=evidence_refs,
    )
    return system_prompt, user_message


async def _call_llm(
    client: httpx.AsyncClient,
    gateway_url: str,
    system_prompt: str,
    user_message: str,
    model: str,
    max_tokens: int = 4096,
) -> dict:
    """S7 Gateway에 도구 없이 직접 LLM 호출.

    새 async ownership surface가 있으면 우선 사용하고,
    없으면 기존 동기 `/v1/chat`로 fallback 한다.
    """
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    }
    body.update(THINKING_GENERAL.to_gateway_fields())

    headers = {
        "Content-Type": "application/json",
        "X-Timeout-Seconds": str(int(TimeoutDefaults.TASK_CLIENT_READ_SECONDS)),
        "X-AEGIS-Strict-JSON": "true",
    }

    async_data = await _call_llm_via_async_ownership(client, gateway_url, body, headers=headers)
    if async_data is not None:
        return async_data

    resp = await client.post(
        f"{gateway_url}/v1/chat",
        json=body,
        headers=headers,
        timeout=httpx.Timeout(connect=10.0, read=TimeoutDefaults.TASK_CLIENT_READ_SECONDS + 60.0, write=10.0, pool=30.0),
    )
    resp.raise_for_status()
    return resp.json()


async def _call_llm_via_async_ownership(
    client: httpx.AsyncClient,
    gateway_url: str,
    body: dict,
    *,
    headers: dict[str, str] | None = None,
) -> dict | None:
    retry_at = client.__dict__.get("_aegis_async_retry_at", 0.0)
    if time.monotonic() < retry_at:
        return None

    submit_resp = await client.post(
        f"{gateway_url}/v1/async-chat-requests",
        json=body,
        headers=headers or {"Content-Type": "application/json"},
        timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=30.0),
    )

    if submit_resp.status_code in (404, 405, 501):
        setattr(client, "_aegis_async_retry_at", time.monotonic() + _ASYNC_UNSUPPORTED_RETRY_SECONDS)
        return None

    submit_resp.raise_for_status()
    submit_data = submit_resp.json()

    request_id = submit_data.get("requestId")
    if not request_id:
        raise ValueError("async submit missing requestId")

    status_url = _resolve_async_url(
        gateway_url,
        submit_data.get("statusUrl"),
        f"/v1/async-chat-requests/{request_id}",
    )
    result_url = _resolve_async_url(
        gateway_url,
        submit_data.get("resultUrl"),
        f"/v1/async-chat-requests/{request_id}/result",
    )

    while True:
        status_resp = await client.get(
            status_url,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=30.0),
        )
        status_resp.raise_for_status()
        status_data = status_resp.json()

        state = status_data.get("state")
        result_ready = bool(status_data.get("resultReady"))
        local_ack_state = status_data.get("localAckState")
        blocked_reason = status_data.get("blockedReason")

        if blocked_reason or local_ack_state == "ack-break":
            raise ValueError(blocked_reason or f"async chat request failed: {state}")

        if state in {"queued", "running"} and not result_ready:
            await asyncio.sleep(1.0)
            continue

        if state == "completed" or result_ready:
            result_resp = await client.get(
                result_url,
                timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=30.0),
            )
            if result_resp.status_code == 409:
                await asyncio.sleep(1.0)
                continue
            result_resp.raise_for_status()
            result_data = result_resp.json()
            wrapped = result_data.get("response")
            if not isinstance(wrapped, dict):
                raise ValueError("async result missing wrapped response")
            return wrapped

        if state in {"failed", "cancelled", "expired"}:
            raise ValueError(f"async chat request terminal non-success: {state}")

        raise ValueError(f"unknown async chat state: {state}")


def _resolve_async_url(gateway_url: str, value: str | None, fallback_path: str) -> str:
    if isinstance(value, str) and value:
        if value.startswith("http://") or value.startswith("https://"):
            return value
        if value.startswith("/"):
            return f"{gateway_url}{value}"
    return f"{gateway_url}{fallback_path}"


def _parse_llm_response(llm_data: dict) -> dict:
    """LLM 응답을 TaskSuccessResponse 유사 형태로 변환."""
    import re

    choice = llm_data.get("choices", [{}])[0]
    message = choice.get("message", {})
    content = message.get("content", "")
    usage = llm_data.get("usage", {})

    # <think> 태그 제거 (Qwen3)
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    # JSON 추출
    result = {}
    try:
        # 순수 JSON
        result = json.loads(content)
    except json.JSONDecodeError:
        # 코드 펜스 안의 JSON
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
        if match:
            try:
                result = json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        if not result:
            # { 부터 } 까지
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                try:
                    result = json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

    if not result:
        result = {
            "summary": content[:500],
            "claims": [],
            "caveats": ["LLM이 구조화된 JSON 대신 자연어로 응답함"],
            "usedEvidenceRefs": [],
        }

    return {
        "status": "completed",
        "result": result,
        "validation": {"valid": bool(result.get("claims")), "errors": []},
        "audit": {
            "tokenUsage": {
                "prompt": usage.get("prompt_tokens", 0),
                "completion": usage.get("completion_tokens", 0),
            },
            "agentAudit": {
                "turn_count": 1,
                "tool_call_count": 0,
                "termination_reason": "direct_eval",
                "total_prompt_tokens": usage.get("prompt_tokens", 0),
                "total_completion_tokens": usage.get("completion_tokens", 0),
            },
        },
    }


async def _run_single_case(
    client: httpx.AsyncClient,
    gateway_url: str,
    model: str,
    golden: dict,
) -> dict:
    """단일 골든 케이스를 실행하고 채점한다."""
    start = time.monotonic()

    try:
        system_prompt, user_message = _build_prompt(golden)
        llm_data = await _call_llm(client, gateway_url, system_prompt, user_message, model)
        response_data = _parse_llm_response(llm_data)
        elapsed_ms = int((time.monotonic() - start) * 1000)
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "golden_id": golden["id"],
            "eval_result": {
                "golden_id": golden["id"],
                "status": "error",
                "metrics": {},
                "composite_score": 0.0,
                "details": {"error": str(e)},
            },
            "raw_response": None,
            "latency_ms": elapsed_ms,
        }

    # 채점
    eval_result = score_response(golden, response_data)

    return {
        "golden_id": golden["id"],
        "eval_result": {
            "golden_id": eval_result.golden_id,
            "timestamp": eval_result.timestamp,
            "status": eval_result.status,
            "metrics": eval_result.metrics,
            "composite_score": eval_result.composite_score,
            "details": eval_result.details,
        },
        "raw_response": response_data,
        "latency_ms": elapsed_ms,
    }


async def run_evaluation(
    golden_dir: str = "",
    output_dir: str = "",
    gateway_url: str = "http://localhost:8000",
    model: str = "",
    run_id: str = "",
    case_filter: str = "",
) -> str:
    """전체 골든셋 평가를 실행한다. 결과 파일 경로를 반환."""
    gdir = Path(golden_dir) if golden_dir else _GOLDEN_DIR
    odir = Path(output_dir) if output_dir else _RESULTS_DIR
    odir.mkdir(parents=True, exist_ok=True)

    if not run_id:
        run_id = f"eval-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    # 모델 자동 감지
    if not model:
        try:
            async with httpx.AsyncClient() as c:
                health = (await c.get(f"{gateway_url}/v1/health", timeout=5)).json()
                model = health.get("model", health.get("config", {}).get("model", "unknown"))
        except Exception:
            model = "unknown"

    cases = _load_golden_cases(gdir, case_filter)
    if not cases:
        print(f"[EVAL] No golden cases found in {gdir}")
        return ""

    print(f"[EVAL] {len(cases)} cases loaded, gateway: {gateway_url}, model: {model}")

    results = []
    async with httpx.AsyncClient() as client:
        for case in cases:
            print(f"  Running: {case['id']}...", end=" ", flush=True)
            result = await _run_single_case(client, gateway_url, model, case)
            score = result["eval_result"]["composite_score"]
            status = result["eval_result"]["status"]
            print(f"{status} (score: {score:.2f}, {result['latency_ms']}ms)")
            results.append(result)

    # 요약 통계
    completed = [r for r in results if r["eval_result"]["status"] == "completed"]
    summary = {
        "mean_composite": _safe_mean([r["eval_result"]["composite_score"] for r in completed]),
        "mean_recall": _safe_mean([r["eval_result"]["metrics"].get("recall", 0) for r in completed]),
        "mean_precision": _safe_mean([r["eval_result"]["metrics"].get("precision", 0) for r in completed]),
        "pass_count": sum(1 for r in completed if r["eval_result"]["composite_score"] >= 0.6),
        "fail_count": sum(1 for r in completed if r["eval_result"]["composite_score"] < 0.6),
        "error_count": sum(1 for r in results if r["eval_result"]["status"] == "error"),
        "total_latency_ms": sum(r["latency_ms"] for r in results),
    }

    output = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config": {
            "gateway_url": gateway_url,
            "model": model,
            "case_count": len(cases),
            "case_filter": case_filter,
            "mode": "direct_llm",
        },
        "results": results,
        "summary": summary,
    }

    output_path = odir / f"{run_id}.json"
    output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2))

    # 터미널 요약
    print(f"\n[EVAL] === Summary ({run_id}) ===")
    print(f"  Composite: {summary['mean_composite']:.2f}")
    print(f"  Recall:    {summary['mean_recall']:.2f}")
    print(f"  Precision: {summary['mean_precision']:.2f}")
    print(f"  Pass/Fail/Error: {summary['pass_count']}/{summary['fail_count']}/{summary['error_count']}")
    print(f"  Total time: {summary['total_latency_ms']}ms")
    print(f"  Results: {output_path}")

    return str(output_path)


def _safe_mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def main():
    parser = argparse.ArgumentParser(description="AEGIS Analysis Agent Evaluation Runner")
    parser.add_argument("--gateway-url", default="http://localhost:8000",
                        help="S7 LLM Gateway URL (default: http://localhost:8000)")
    parser.add_argument("--model", default="", help="LLM model name (auto-detected from gateway)")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--case", default="", help="Filter cases by name substring")
    parser.add_argument("--golden-dir", default="")
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    asyncio.run(run_evaluation(
        golden_dir=args.golden_dir,
        output_dir=args.output_dir,
        gateway_url=args.gateway_url,
        model=args.model,
        run_id=args.run_id,
        case_filter=args.case,
    ))


if __name__ == "__main__":
    main()
