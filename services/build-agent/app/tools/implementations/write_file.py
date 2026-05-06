"""WriteFileTool — build-aegis/ 폴더 안에만 파일 생성. FilePolicy 연동."""
from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from app.agent_runtime.schemas.agent import ToolResult
from app.tools.implementations.path_utils import normalize_generated_build_path

if TYPE_CHECKING:
    from app.policy.file_policy import FilePolicy


class WriteFileTool:
    def __init__(self, project_path: str, build_dir: str = "build-aegis",
                 file_policy: "FilePolicy | None" = None) -> None:
        self._target_dir = os.path.normpath(os.path.join(project_path, build_dir))
        self._build_dir = build_dir
        self._file_policy = file_policy

    async def execute(self, arguments: dict) -> ToolResult:
        rel_path = normalize_generated_build_path(arguments.get("path", ""), self._build_dir)
        content = arguments.get("content", "")
        if not rel_path:
            return ToolResult(tool_call_id="", name="", success=False,
                              content='{"error": "path is required"}', error="missing path")
        full_path = os.path.normpath(os.path.join(self._target_dir, rel_path))
        if not full_path.startswith(self._target_dir + os.sep):
            return ToolResult(tool_call_id="", name="", success=False,
                              content=json.dumps({"error": f"write only allowed in {self._build_dir}/"}),
                              error="write blocked")
        try:
            # 스크립트 내용 안전성 검사
            from app.policy.file_policy import FilePolicy
            content_warnings = FilePolicy.scan_content(content)
            if content_warnings:
                return ToolResult(
                    tool_call_id="",
                    name="",
                    success=False,
                    content=json.dumps(
                        {
                            "error": "forbidden content in generated file",
                            "blockedPatterns": content_warnings,
                        },
                        ensure_ascii=False,
                    ),
                    error="forbidden content",
                )

            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            if self._file_policy:
                self._file_policy.record_created(rel_path)
            size = len(content.encode("utf-8"))
            result_data: dict = {"written": f"{self._build_dir}/{rel_path}", "bytes": size}
            return ToolResult(tool_call_id="", name="", success=True,
                              content=json.dumps(result_data, ensure_ascii=False))
        except Exception as e:
            return ToolResult(tool_call_id="", name="", success=False,
                              content=json.dumps({"error": str(e)}), error=str(e))
