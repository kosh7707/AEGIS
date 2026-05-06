"""DeleteFileTool — 에이전트가 생성한 파일만 삭제 가능."""
from __future__ import annotations

import os

from app.agent_runtime.schemas.agent import ToolResult
from app.policy.file_policy import FilePolicy
from app.tools.implementations.path_utils import normalize_generated_build_path


class DeleteFileTool:
    def __init__(self, project_path: str, file_policy: FilePolicy, build_dir: str = "build-aegis") -> None:
        self._target_dir = os.path.join(project_path, build_dir)
        self._build_dir = build_dir
        self._file_policy = file_policy

    async def execute(self, arguments: dict) -> ToolResult:
        rel_path = normalize_generated_build_path(arguments.get("path", ""), self._build_dir)

        if not rel_path:
            return ToolResult(
                tool_call_id="", name="", success=False,
                content='{"error": "path is required"}', error="missing path",
            )

        if not self._file_policy.can_delete(rel_path):
            return ToolResult(
                tool_call_id="", name="", success=False,
                content='{"error": "delete blocked: file not created by agent in this session"}',
                error="policy: delete blocked",
            )

        full_path = os.path.normpath(os.path.join(self._target_dir, rel_path))
        if not os.path.isfile(full_path):
            return ToolResult(
                tool_call_id="", name="", success=False,
                content=f'{{"error": "file does not exist: {self._build_dir}/{rel_path}"}}',
                error="file not found",
            )

        os.remove(full_path)
        self._file_policy.record_deleted(rel_path)

        return ToolResult(
            tool_call_id="", name="", success=True,
            content=f'{{"deleted": "{self._build_dir}/{rel_path}"}}',
        )
