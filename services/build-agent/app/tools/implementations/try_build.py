"""TryBuildTool — S4 POST /v1/build 호출 + 금지 명령어 검사 + 결과 검증.

v3: explicit buildCommand/buildEnvironment/provenance 전송, bear 자동 제거,
S4 v0.11 buildEvidence/failureDetail 응답과 legacy exitCode 응답을 모두 수용.
"""
from __future__ import annotations

import json
import logging
import re
import shlex
from pathlib import Path

import httpx
from app.agent_runtime.path_util import resolve_scoped_path
from app.clients.s4_ownership import S4OwnershipError, S4OwnershipUnsupported, post_and_wait_s4_ownership
from app.runtime.request_summary import request_summary_tracker
from app.agent_runtime.schemas.agent import ToolResult

logger = logging.getLogger(__name__)

# 워드 바운더리 기반 금지 명령어 (arm-linux-... 등의 오탐 방지)
_FORBIDDEN_PATTERNS = [
    re.compile(r"\brm\b"),
    re.compile(r"\bdd\b"),
    re.compile(r"\bcurl\b"),
    re.compile(r"\bwget\b"),
    re.compile(r"\bgit\b"),
    re.compile(r"\bdocker\b"),
    re.compile(r"\bchmod\b"),
    re.compile(r"\bchown\b"),
    re.compile(r"\bpatch\b"),
    re.compile(r"\bsed\s+-i\b"),
]

# S4가 자동으로 bear를 감싸므로, LLM이 넣은 bear를 제거
_BEAR_PREFIX_RE = re.compile(r"\bbear\s+--\s*")


def _validate_build_result(data: dict) -> tuple[bool, str | None]:
    """S4 빌드 응답의 성공 판정. v0.11 buildEvidence와 legacy exitCode 모두 수용."""
    build_evidence = data.get("buildEvidence", {}) if isinstance(data.get("buildEvidence"), dict) else {}
    exit_code = build_evidence.get("exitCode", data.get("exitCode", -1))

    if exit_code == 0:
        return True, None

    # 부분 빌드: 실패했지만 일부 compile_commands 사용 가능
    user_entries = build_evidence.get("userEntries", data.get("userEntries", 0))
    failure_detail = data.get("failureDetail", {}) if isinstance(data.get("failureDetail"), dict) else {}
    failure_summary = failure_detail.get("summary", "")
    failure_hint = failure_detail.get("hint", "")
    s4_warning = data.get("warning", "")
    if user_entries > 0:
        return False, (
            f"빌드 exit code={exit_code} (실패). "
            f"단, 부분 compile_commands 사용 가능 ({user_entries}개 유저 엔트리). "
            f"{failure_summary or s4_warning}".strip()
        )

    extra = " ".join(part for part in (failure_summary, failure_hint, s4_warning) if part).strip()
    if extra:
        return False, f"빌드 exit code={exit_code} (실패). {extra}"
    return False, f"빌드 exit code={exit_code} (실패)."


class TryBuildTool:
    wait_while_alive = True

    def __init__(
        self,
        sast_endpoint: str,
        project_path: str,
        request_id: str = "",
        *,
        default_build_environment: dict[str, str] | None = None,
        provenance: dict[str, str] | None = None,
        build_dir: str | None = None,
    ) -> None:
        self._sast_endpoint = sast_endpoint
        self._project_path = project_path
        self._request_id = request_id
        self._default_build_environment = dict(default_build_environment or {})
        self._provenance = dict(provenance or {})
        self._build_dir = build_dir

    def _validate_generated_script_command(self, build_cmd: str) -> str | None:
        """Return an error if build_cmd does not execute the generated script only.

        When Build Agent has a request-scoped build directory, the safety
        contract is runtime-enforced here: uploaded/caller-provided scripts are
        reference material only and must not be executed directly by try_build.
        """
        if not self._build_dir:
            return None

        try:
            parts = shlex.split(build_cmd)
        except ValueError as exc:
            return f"invalid build command quoting: {exc}"

        if len(parts) != 2 or parts[0] not in {"bash", "/bin/bash"}:
            return (
                "build_command must execute only the generated request-scoped "
                f"script: bash {self._build_dir}/aegis-build.sh"
            )

        script_arg = parts[1]
        expected_rel = f"{self._build_dir}/aegis-build.sh"
        expected_abs = resolve_scoped_path(self._project_path, expected_rel)
        if expected_abs is None:
            return "generated build script path is outside project scope"

        if Path(script_arg).is_absolute():
            try:
                candidate = str(Path(script_arg).resolve())
            except OSError:
                return "build_command script path could not be resolved"
        else:
            candidate = resolve_scoped_path(self._project_path, script_arg)
            if candidate is None:
                return "build_command script path must stay inside project scope"

        if candidate != expected_abs:
            return (
                "build_command must not execute uploaded/reference scripts directly; "
                f"use bash {self._build_dir}/aegis-build.sh"
            )

        return None

    async def execute(self, arguments: dict) -> ToolResult:
        build_cmd = arguments.get("build_command", "")
        build_environment = arguments.get("build_environment") or {}

        if not build_cmd:
            return ToolResult(tool_call_id="", name="", success=False,
                              content='{"error": "build_command is required"}', error="missing command")

        # 금지 명령어 검사 (정규식 워드 바운더리)
        cmd_lower = build_cmd.lower()
        for pattern in _FORBIDDEN_PATTERNS:
            match = pattern.search(cmd_lower)
            if match:
                forbidden = match.group()
                return ToolResult(tool_call_id="", name="", success=False,
                                  content=f'{{"error": "forbidden command: {forbidden}"}}',
                                  error=f"forbidden: {forbidden}")

        # LLM이 넣은 bear 제거 (S4가 자동으로 감싸므로 이중 방지)
        build_cmd = _BEAR_PREFIX_RE.sub("", build_cmd).strip()

        generated_script_error = self._validate_generated_script_command(build_cmd)
        if generated_script_error:
            return ToolResult(
                tool_call_id="", name="", success=False,
                content=json.dumps({"error": generated_script_error}, ensure_ascii=False),
                error=generated_script_error,
            )

        try:
            merged_environment = dict(self._default_build_environment)
            if build_environment:
                merged_environment.update(build_environment)
            payload: dict = {
                "projectPath": self._project_path,
                "buildCommand": build_cmd,
                "wrapWithBear": True,
            }
            if merged_environment:
                payload["buildEnvironment"] = merged_environment
            if self._provenance:
                payload["provenance"] = self._provenance

            if self._request_id:
                request_summary_tracker.mark_transport_only(self._request_id, source="s4-build-ownership-wait")
            async with httpx.AsyncClient(timeout=None) as client:
                try:
                    ownership = await post_and_wait_s4_ownership(
                        client,
                        base_url=self._sast_endpoint,
                        endpoint_path="/v1/build",
                        payload=payload,
                        root_request_id=self._request_id,
                        operation="try_build",
                    )
                    data = ownership.payload
                except S4OwnershipUnsupported:
                    data = await self._execute_sync_compat(client, payload)

                actual_success, warning = _validate_build_result(data)
                if warning:
                    data["_s3_warning"] = warning
                    logger.warning("[try_build] S4 응답 검증: %s", warning)

                # 빌드 실패 시 에러 분류 + 복구 제안 추가
                if not actual_success:
                    from app.pipeline.build_error_classifier import classify_build_error
                    build_evidence = data.get("buildEvidence", {}) if isinstance(data.get("buildEvidence"), dict) else {}
                    failure_detail = data.get("failureDetail", {}) if isinstance(data.get("failureDetail"), dict) else {}
                    error_output = (
                        build_evidence.get("buildOutput", "")
                        + data.get("stderr", "")
                        + data.get("stdout", "")
                        + data.get("output", "")
                        + failure_detail.get("summary", "")
                    )
                    classifications = classify_build_error(error_output)
                    if classifications:
                        data["_error_classification"] = [
                            {"category": c.category, "message": c.message, "suggestion": c.suggestion}
                            for c in classifications
                        ]

                new_refs = ["eref-build-success"] if actual_success else []
                return ToolResult(
                    tool_call_id="", name="", success=actual_success,
                    content=json.dumps(data, ensure_ascii=False),
                    new_evidence_refs=new_refs,
                )
        except S4OwnershipError as e:
            return ToolResult(tool_call_id="", name="", success=False,
                              content=json.dumps({"error": str(e), "detail": e.payload}, ensure_ascii=False), error=str(e))
        except Exception as e:
            return ToolResult(tool_call_id="", name="", success=False,
                              content=f'{{"error": "build API call failed: {e}"}}', error=str(e))

    async def _execute_sync_compat(self, client: httpx.AsyncClient, payload: dict) -> dict:
        headers = {"X-Request-Id": self._request_id} if self._request_id else {}
        resp = await client.post(
            f"{self._sast_endpoint}/v1/build",
            json=payload,
            headers=headers,
            timeout=httpx.Timeout(connect=10.0, read=180.0, write=10.0, pool=10.0),
        )
        resp.raise_for_status()
        return resp.json()
