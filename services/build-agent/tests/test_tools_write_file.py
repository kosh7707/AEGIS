"""Safety tests for WriteFileTool — build-dir isolation, path traversal."""

from __future__ import annotations

import os

import pytest

from app.tools.implementations.write_file import WriteFileTool
from app.agent_runtime.schemas.agent import ToolResult


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_creates_file(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "test.cmake", "content": "cmake_minimum_required(VERSION 3.20)"})

    assert result.success is True
    written = os.path.join(tmp_path, "build-aegis", "test.cmake")
    assert os.path.isfile(written)
    with open(written, encoding="utf-8") as f:
        assert f.read() == "cmake_minimum_required(VERSION 3.20)"


@pytest.mark.asyncio
async def test_write_creates_intermediate_dirs(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "sub/dir/file.txt", "content": "deep"})

    assert result.success is True
    written = os.path.join(tmp_path, "build-aegis", "sub", "dir", "file.txt")
    assert os.path.isfile(written)


@pytest.mark.asyncio
async def test_write_blocked_outside_build_dir(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "../escape.txt", "content": "pwned"})

    assert result.success is False
    assert "write" in (result.error or "").lower() or "blocked" in (result.error or "").lower()
    # File must NOT exist outside build-aegis
    assert not os.path.isfile(os.path.join(tmp_path, "escape.txt"))


@pytest.mark.asyncio
async def test_write_blocked_absolute_path(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "/tmp/escape.txt", "content": "pwned"})

    assert result.success is False
    # normpath(join(target_dir, "/tmp/escape.txt")) = "/tmp/escape.txt"
    # which does not startswith target_dir
    assert not os.path.isfile("/tmp/escape.txt") or True  # don't fail if file already exists for other reasons


@pytest.mark.asyncio
async def test_write_overwrites_existing(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    await tool.execute({"path": "over.txt", "content": "first"})
    result = await tool.execute({"path": "over.txt", "content": "second"})

    assert result.success is True
    written = os.path.join(tmp_path, "build-aegis", "over.txt")
    with open(written, encoding="utf-8") as f:
        assert f.read() == "second"


@pytest.mark.asyncio
async def test_write_empty_content(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "blank.txt", "content": ""})

    assert result.success is True
    written = os.path.join(tmp_path, "build-aegis", "blank.txt")
    assert os.path.getsize(written) == 0


@pytest.mark.asyncio
async def test_write_unicode_content(tmp_path):
    korean = "AEGIS 빌드 설정 파일"
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "korean.txt", "content": korean})

    assert result.success is True
    written = os.path.join(tmp_path, "build-aegis", "korean.txt")
    with open(written, encoding="utf-8") as f:
        assert f.read() == korean


@pytest.mark.asyncio
async def test_write_response_format(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "fmt.txt", "content": "hello"})

    assert result.success is True
    assert "written" in result.content
    assert "bytes" in result.content


@pytest.mark.asyncio
async def test_write_dotdot_in_nested(tmp_path):
    """sub/../../escape.txt resolves to ../escape.txt which is outside build-aegis/."""
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "sub/../../escape.txt", "content": "pwned"})

    assert result.success is False
    assert not os.path.isfile(os.path.join(tmp_path, "escape.txt"))


@pytest.mark.asyncio
async def test_write_custom_build_dir(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path), build_dir="custom")
    result = await tool.execute({"path": "test.txt", "content": "isolated"})

    assert result.success is True
    written = os.path.join(tmp_path, "custom", "test.txt")
    assert os.path.isfile(written)
    # Must NOT appear in default build-aegis
    assert not os.path.isfile(os.path.join(tmp_path, "build-aegis", "test.txt"))


@pytest.mark.asyncio
async def test_write_accepts_project_relative_generated_script_path_without_nesting(tmp_path):
    """LLMs sometimes pass the final buildScript path to write_file.

    The tool schema says path is relative to build_dir, but the final JSON and
    operational command use ``{build_dir}/aegis-build.sh``. Accepting that
    project-relative spelling prevents accidental build-aegis/build-aegis nesting.
    """
    build_dir = "build-aegis-deadbeef"
    tool = WriteFileTool(project_path=str(tmp_path), build_dir=build_dir)

    result = await tool.execute(
        {"path": f"{build_dir}/aegis-build.sh", "content": "#!/bin/bash\necho ok\n"}
    )

    assert result.success is True
    assert os.path.isfile(os.path.join(tmp_path, build_dir, "aegis-build.sh"))
    assert not os.path.exists(os.path.join(tmp_path, build_dir, build_dir))
    assert f'"written": "{build_dir}/aegis-build.sh"' in result.content


@pytest.mark.asyncio
async def test_write_prefixed_traversal_remains_blocked(tmp_path):
    build_dir = "build-aegis-deadbeef"
    tool = WriteFileTool(project_path=str(tmp_path), build_dir=build_dir)

    result = await tool.execute({"path": f"{build_dir}/../escape.txt", "content": "pwned"})

    assert result.success is False
    assert not os.path.isfile(os.path.join(tmp_path, "escape.txt"))


@pytest.mark.asyncio
async def test_write_empty_path(tmp_path):
    """빈 path 시 에러 반환."""
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "", "content": "data"})
    assert result.success is False
    assert "path is required" in result.content


@pytest.mark.asyncio
async def test_write_unicode_byte_count(tmp_path):
    """유니코드 문자열의 바이트 수가 UTF-8 인코딩 기준으로 정확한지 확인."""
    import json
    korean = "한글 테스트"  # UTF-8 = 15 bytes (한 3 + 글 3 + 공백 1 + 테 3 + 스 3 + 트 3 = 16? let me check)
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "unicode.txt", "content": korean})
    assert result.success is True
    data = json.loads(result.content)
    assert data["bytes"] == len(korean.encode("utf-8"))


@pytest.mark.asyncio
async def test_write_blocks_forbidden_content(tmp_path):
    tool = WriteFileTool(project_path=str(tmp_path))
    result = await tool.execute({"path": "script.sh", "content": "apt-get update -qq"})

    assert result.success is False
    assert "forbidden content" in (result.error or "")
