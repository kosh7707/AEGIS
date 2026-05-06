"""EditFileTool — 에이전트가 생성한 파일만 수정 가능 (전체 덮어쓰기)."""
from __future__ import annotations

import os

from app.agent_runtime.schemas.agent import ToolResult
from app.policy.file_policy import FilePolicy
from app.tools.implementations.path_utils import normalize_generated_build_path


class EditFileTool:
    def __init__(self, project_path: str, file_policy: FilePolicy, build_dir: str = "build-aegis") -> None:
        self._target_dir = os.path.join(project_path, build_dir)
        self._build_dir = build_dir
        self._file_policy = file_policy

    async def execute(self, arguments: dict) -> ToolResult:
        rel_path = normalize_generated_build_path(arguments.get("path", ""), self._build_dir)
        content = arguments.get("content", "")

        if not rel_path:
            return ToolResult(
                tool_call_id="", name="", success=False,
                content='{"error": "path is required"}', error="missing path",
            )

        if not self._file_policy.can_edit(rel_path):
            return ToolResult(
                tool_call_id="", name="", success=False,
                content='{"error": "edit blocked: file not created by agent in this session"}',
                error="policy: edit blocked",
            )

        full_path = os.path.normpath(os.path.join(self._target_dir, rel_path))
        if not os.path.isfile(full_path):
            return ToolResult(
                tool_call_id="", name="", success=False,
                content=f'{{"error": "file does not exist: {self._build_dir}/{rel_path}"}}',
                error="file not found",
            )

        # 스크립트 내용 안전성 검사
        content_warnings = FilePolicy.scan_content(content)
        if content_warnings:
            import json
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

        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

        size = len(content.encode("utf-8"))
        result_data = {"edited": f"{self._build_dir}/{rel_path}", "bytes": size}
        import json
        return ToolResult(
            tool_call_id="", name="", success=True,
            content=json.dumps(result_data, ensure_ascii=False),
        )
