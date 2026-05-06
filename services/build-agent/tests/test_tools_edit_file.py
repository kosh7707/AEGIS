"""EditFileTool — 에이전트 생성 파일 수정 테스트."""
from __future__ import annotations

import pytest

from app.policy.file_policy import FilePolicy
from app.tools.implementations.edit_file import EditFileTool


@pytest.fixture
def setup(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    build = project / "build-aegis"
    build.mkdir()
    policy = FilePolicy(str(project))
    tool = EditFileTool(str(project), policy)
    return tool, policy, build


@pytest.mark.asyncio
async def test_edit_agent_created_file(setup):
    tool, policy, build = setup
    (build / "aegis-build.sh").write_text("#!/bin/bash\necho old")
    policy.record_created("aegis-build.sh")

    result = await tool.execute({"path": "aegis-build.sh", "content": "#!/bin/bash\necho new"})
    assert result.success is True
    assert (build / "aegis-build.sh").read_text() == "#!/bin/bash\necho new"


@pytest.mark.asyncio
async def test_edit_blocked_non_agent_file(setup):
    tool, policy, build = setup
    (build / "other.sh").write_text("#!/bin/bash")

    result = await tool.execute({"path": "other.sh", "content": "modified"})
    assert result.success is False
    assert "edit blocked" in (result.error or "")


@pytest.mark.asyncio
async def test_edit_nonexistent_file(setup):
    tool, policy, build = setup
    policy.record_created("missing.sh")

    result = await tool.execute({"path": "missing.sh", "content": "data"})
    assert result.success is False
    assert "does not exist" in result.content


@pytest.mark.asyncio
async def test_edit_missing_path(setup):
    tool, policy, build = setup
    result = await tool.execute({"content": "data"})
    assert result.success is False


@pytest.mark.asyncio
async def test_edit_traversal_blocked(setup):
    tool, policy, build = setup
    result = await tool.execute({"path": "../../etc/passwd", "content": "pwned"})
    assert result.success is False


@pytest.mark.asyncio
async def test_edit_preserves_unicode(setup):
    tool, policy, build = setup
    (build / "script.sh").write_text("old")
    policy.record_created("script.sh")

    content = "#!/bin/bash\n# 크로스 컴파일 설정\necho '한글'"
    result = await tool.execute({"path": "script.sh", "content": content})
    assert result.success is True
    assert (build / "script.sh").read_text() == content


@pytest.mark.asyncio
async def test_edit_nested_path(setup):
    tool, policy, build = setup
    sub = build / "cmake"
    sub.mkdir()
    (sub / "toolchain.cmake").write_text("old")
    policy.record_created("cmake/toolchain.cmake")

    result = await tool.execute({"path": "cmake/toolchain.cmake", "content": "new"})
    assert result.success is True
    assert (sub / "toolchain.cmake").read_text() == "new"


@pytest.mark.asyncio
async def test_edit_accepts_project_relative_generated_script_path_without_nesting(setup):
    tool, policy, build = setup
    build_dir = build.name
    (build / "aegis-build.sh").write_text("#!/bin/bash\necho old")
    policy.record_created("aegis-build.sh")

    result = await tool.execute(
        {"path": f"{build_dir}/aegis-build.sh", "content": "#!/bin/bash\necho new"}
    )

    assert result.success is True
    assert (build / "aegis-build.sh").read_text() == "#!/bin/bash\necho new"
    assert not (build / build_dir).exists()


@pytest.mark.asyncio
async def test_edit_returns_byte_count(setup):
    tool, policy, build = setup
    (build / "a.sh").write_text("x")
    policy.record_created("a.sh")

    result = await tool.execute({"path": "a.sh", "content": "hello"})
    assert result.success is True
    assert '"bytes": 5' in result.content


@pytest.mark.asyncio
async def test_edit_blocks_forbidden_content(setup):
    tool, policy, build = setup
    (build / "script.sh").write_text("#!/bin/bash\necho ok")
    policy.record_created("script.sh")

    result = await tool.execute({"path": "script.sh", "content": "sudo make install"})

    assert result.success is False
    assert "forbidden content" in (result.error or "")
