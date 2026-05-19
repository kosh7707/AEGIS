"""MetadataTool — build.metadata tool 구현체. S4 SAST Runner /v1/metadata에 HTTP 위임."""

from __future__ import annotations

import json
import logging

import httpx

from app.agent_runtime.context import get_request_id
from app.agent_runtime.schemas.agent import ToolResult

logger = logging.getLogger(__name__)


def _s4_build_profile(build_profile: dict | None) -> dict:
    if not isinstance(build_profile, dict):
        return {}
    normalized = {
        key: value
        for key, value in build_profile.items()
        if not (key == "sdkId" and value == "custom")
    }
    mode = normalized.get("sdkResolutionMode")
    if mode == "none":
        normalized.pop("sdkId", None)
        normalized.pop("sdkDescriptor", None)
        return normalized
    if mode == "non-registered":
        normalized.pop("sdkId", None)
        descriptor = normalized.get("sdkDescriptor")
        if isinstance(descriptor, dict):
            normalized["sdkDescriptor"] = {
                key: value
                for key, value in descriptor.items()
                if value not in (None, "", [], {})
            }
        return normalized
    return normalized


class MetadataTool:
    """build.metadata tool — S4 /v1/metadata로 타겟 빌드 환경 매크로/아키텍처 조회."""

    def __init__(
        self,
        sast_endpoint: str = "http://localhost:9000",
        project_path: str = "",
        build_profile: dict | None = None,
    ) -> None:
        self._sast_endpoint = sast_endpoint
        self._project_path = project_path
        self._build_profile = _s4_build_profile(build_profile)
        self._client = httpx.AsyncClient(timeout=30.0)

    async def execute(self, arguments: dict) -> ToolResult:
        if not self._project_path:
            return ToolResult(
                tool_call_id="", name="", success=False,
                content='{"error": "projectPath not available"}',
                error="no project_path",
            )

        try:
            headers: dict[str, str] = {}
            request_id = get_request_id()
            if request_id:
                headers["X-Request-Id"] = request_id

            body: dict = {"projectPath": self._project_path}
            if self._build_profile:
                body["buildProfile"] = self._build_profile

            resp = await self._client.post(
                f"{self._sast_endpoint}/v1/metadata",
                json=body,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

            target_info = data.get("targetInfo", {})
            arch = target_info.get("arch", "unknown")

            return ToolResult(
                tool_call_id="", name="", success=True,
                content=json.dumps(data, ensure_ascii=False),
                new_evidence_refs=[f"eref-metadata-{arch}"],
            )
        except Exception as e:
            logger.warning("S4 /v1/metadata 호출 실패: %s", e)
            return ToolResult(
                tool_call_id="", name="", success=False,
                content=json.dumps({"error": f"SAST Runner metadata unavailable: {e}"}),
                error=str(e),
            )

    async def aclose(self) -> None:
        await self._client.aclose()
