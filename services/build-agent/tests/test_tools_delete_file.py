"""DeleteFileTool — 에이전트 생성 파일 삭제 테스트."""
from __future__ import annotations

import pytest

from app.policy.file_policy import FilePolicy
from app.tools.implementations.delete_file import DeleteFileTool


@pytest.fixture
def setup(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    build = project / "build-aegis"
    build.mkdir()
    policy = FilePolicy(str(project))
    tool = DeleteFileTool(str(project), policy)
    return tool, policy, build


@pytest.mark.asyncio
async def test_delete_agent_created_file(setup):
    tool, policy, build = setup
    f = build / "temp.sh"
    f.write_text("temp")
    policy.record_created("temp.sh")

    result = await tool.execute({"path": "temp.sh"})
    assert result.success is True
    assert not f.exists()
    assert policy.can_delete("temp.sh") is False


@pytest.mark.asyncio
async def test_delete_blocked_non_agent_file(setup):
    tool, policy, build = setup
    (build / "existing.sh").write_text("data")

    result = await tool.execute({"path": "existing.sh"})
    assert result.success is False
    assert "delete blocked" in (result.error or "")
    assert (build / "existing.sh").exists()


@pytest.mark.asyncio
async def test_delete_nonexistent_file(setup):
    tool, policy, build = setup
    policy.record_created("gone.sh")

    result = await tool.execute({"path": "gone.sh"})
    assert result.success is False
    assert "does not exist" in result.content


@pytest.mark.asyncio
async def test_delete_missing_path(setup):
    tool, policy, build = setup
    result = await tool.execute({})
    assert result.success is False


@pytest.mark.asyncio
async def test_delete_traversal_blocked(setup):
    tool, policy, build = setup
    result = await tool.execute({"path": "../../important.txt"})
    assert result.success is False


@pytest.mark.asyncio
async def test_delete_then_cannot_edit(setup):
    tool, policy, build = setup
    f = build / "script.sh"
    f.write_text("data")
    policy.record_created("script.sh")

    await tool.execute({"path": "script.sh"})
    assert policy.can_edit("script.sh") is False


@pytest.mark.asyncio
async def test_delete_accepts_project_relative_generated_script_path_without_nesting(setup):
    tool, policy, build = setup
    build_dir = build.name
    f = build / "aegis-build.sh"
    f.write_text("#!/bin/bash\necho stale")
    policy.record_created("aegis-build.sh")

    result = await tool.execute({"path": f"{build_dir}/aegis-build.sh"})

    assert result.success is True
    assert not f.exists()
    assert not (build / build_dir).exists()
    assert policy.can_edit("aegis-build.sh") is False
