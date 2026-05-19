from __future__ import annotations

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
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    f"{self.endpoint.rstrip('/')}/v1/chat",
                    json={
                        "messages": [
                            {"role": "system", "content": "Return strict JSON for TraceAudit triage."},
                            {"role": "user", "content": prompt},
                        ],
                        "response_format": {"type": "json_object"},
                    },
                )
        except httpx.HTTPError as exc:
            raise PaperOperationalError(f"S7 LLM transport failure: {exc}") from exc
        if response.status_code >= 400:
            raise PaperOperationalError(f"S7 LLM HTTP {response.status_code}", detail={"body": response.text[:1000]})
        payload = response.json()
        content = payload.get("content") or payload.get("message") or payload
        if isinstance(content, dict):
            return content, {"mode": "live", **request, "rawResponse": payload}
        import json

        return json.loads(content), {"mode": "live", **request, "rawResponse": payload}

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
