from __future__ import annotations

import json
from typing import Any

import httpx

from app.config import settings

from .artifacts import read_json
from .errors import PaperOperationalError
from .models import PaperCaseCreateRequest
from .triage import fallback_unknown_for_finding


class LlmTriageClient:
    def __init__(self, endpoint: str | None = None, timeout_seconds: float = 120.0):
        self.endpoint = endpoint or settings.llm_endpoint
        self.timeout_seconds = timeout_seconds

    async def triage_finding(self, case: PaperCaseCreateRequest, *, finding: dict[str, Any], evidence_rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        path = case.producerArtifacts.llmTriageByFindingId.get(finding["findingId"])
        prompt = self._build_prompt(case, finding=finding, evidence_rows=evidence_rows)
        request = {
            "caseId": case.caseId,
            "findingId": finding["findingId"],
            "modelProfile": "traceaudit-paper-default",
            "prompt": prompt,
        }
        if path:
            return read_json(path), {"mode": "file_backed", **request}
        if settings.llm_mode == "mock":
            return fallback_unknown_for_finding(finding), {"mode": "mock", **request}
        body = self._build_s7_chat_body(prompt)
        headers = {
            "X-AEGIS-Strict-JSON": "true",
            "X-Timeout-Seconds": str(int(self.timeout_seconds)),
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.endpoint.rstrip('/')}/v1/chat", json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise PaperOperationalError(f"S7 LLM transport failure: {exc}") from exc
        if response.status_code >= 400:
            raise PaperOperationalError(f"S7 LLM HTTP {response.status_code}", detail={"body": response.text[:1000]})
        payload = response.json()
        return _extract_openai_json_content(payload), {"mode": "live", **request, "body": body, "headers": headers, "rawResponse": payload}

    def _build_s7_chat_body(self, prompt: str) -> dict[str, Any]:
        return {
            "model": settings.llm_model,
            "messages": [
                {"role": "system", "content": "Return strict JSON for TraceAudit triage."},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 2048,
            "temperature": 0.0,
            "top_p": 1.0,
            "top_k": -1,
            "min_p": 0.0,
            "presence_penalty": 0.0,
            "repetition_penalty": 1.0,
            "chat_template_kwargs": {"enable_thinking": False},
            "response_format": {"type": "json_object"},
        }

    def _build_prompt(self, case: PaperCaseCreateRequest, *, finding: dict[str, Any], evidence_rows: list[dict[str, Any]]) -> str:
        lines = [
            "Classify this SAST finding as TP, FP, or UNKNOWN.",
            "TP/FP require cited evidence refs. Do not use producer diagnostics as security evidence.",
            f"caseId={case.caseId} findingId={finding['findingId']}",
            f"finding={finding}",
            "evidenceRows:",
        ]
        for row in evidence_rows:
            lines.append(f"- {row.get('evidenceRef')}: {row.get('text')}")
        return "\n".join(lines)


def _extract_openai_json_content(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise PaperOperationalError("S7 LLM response missing choices[0].message.content") from exc
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        raise PaperOperationalError("S7 LLM response content is not a JSON string/object")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PaperOperationalError(f"S7 LLM response content is not JSON: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise PaperOperationalError("S7 LLM response JSON content is not an object")
    return parsed
