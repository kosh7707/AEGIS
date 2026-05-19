"""MetadataTool 단위 테스트."""

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.tools.implementations.metadata_tool import MetadataTool


@pytest.fixture
def tool():
    return MetadataTool(
        sast_endpoint="http://localhost:9000",
        project_path="/tmp/test-project",
        build_profile={"sdkId": "ti-am335x"},
    )


@pytest.mark.asyncio
async def test_success(tool):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "compiler": "arm-none-linux-gnueabihf-gcc 9.2.1",
        "macros": {
            "__ARM_ARCH": "7",
            "__SIZEOF_POINTER__": "4",
            "__SIZEOF_LONG__": "4",
            "__BYTE_ORDER__": "__ORDER_LITTLE_ENDIAN__",
        },
        "targetInfo": {
            "arch": "arm",
            "pointerSize": 4,
            "longSize": 4,
            "endianness": "little",
        },
    }
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=mock_resp)

    result = await tool.execute({})
    assert result.success is True
    assert "__SIZEOF_POINTER__" in result.content
    assert "eref-metadata-arm" in result.new_evidence_refs


@pytest.mark.asyncio
async def test_no_project_path():
    tool = MetadataTool(project_path="")
    result = await tool.execute({})
    assert result.success is False
    assert "projectPath" in result.content


@pytest.mark.asyncio
async def test_http_error(tool):
    tool._client = MagicMock()
    tool._client.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

    result = await tool.execute({})
    assert result.success is False
    assert "error" in result.content.lower()


@pytest.mark.asyncio
async def test_sends_build_profile(tool):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"macros": {}, "targetInfo": {"arch": "x86_64"}}
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=mock_resp)

    await tool.execute({})
    call_args = tool._client.post.call_args
    body = call_args.kwargs.get("json") or call_args[1].get("json")
    assert body["projectPath"] == "/tmp/test-project"
    assert body["buildProfile"]["sdkId"] == "ti-am335x"


@pytest.mark.asyncio
async def test_omits_custom_sdkid_for_s4_metadata():
    tool = MetadataTool(
        sast_endpoint="http://localhost:9000",
        project_path="/tmp/test-project",
        build_profile={"sdkId": "custom", "compiler": "g++"},
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"macros": {}, "targetInfo": {"arch": "x86_64"}}
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=mock_resp)

    await tool.execute({})
    call_args = tool._client.post.call_args
    body = call_args.kwargs.get("json") or call_args[1].get("json")
    assert body["buildProfile"] == {"compiler": "g++"}


@pytest.mark.asyncio
async def test_metadata_profile_honors_none_sdk_resolution_mode():
    tool = MetadataTool(
        sast_endpoint="http://localhost:9000",
        project_path="/tmp/test-project",
        build_profile={
            "sdkResolutionMode": "none",
            "sdkId": "must-not-be-sent",
            "sdkDescriptor": {"sdkRootPath": "/secret/sdk"},
            "compiler": "g++",
        },
    )
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"macros": {}, "targetInfo": {"arch": "x86_64"}}
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=mock_resp)

    await tool.execute({})

    body = tool._client.post.call_args.kwargs["json"]
    assert body["buildProfile"] == {"sdkResolutionMode": "none", "compiler": "g++"}


@pytest.mark.asyncio
async def test_metadata_profile_preserves_non_registered_descriptor_without_empty_values():
    tool = MetadataTool(
        sast_endpoint="http://localhost:9000",
        project_path="/tmp/test-project",
        build_profile={
            "sdkResolutionMode": "non-registered",
            "sdkId": "must-not-be-sent",
            "sdkDescriptor": {"sdkRootPath": "/uploads/sdk", "sysroot": "", "compilerPath": None},
            "compiler": "g++",
        },
    )
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"macros": {}, "targetInfo": {"arch": "x86_64"}}
    tool._client = MagicMock()
    tool._client.post = AsyncMock(return_value=mock_resp)

    await tool.execute({})

    body = tool._client.post.call_args.kwargs["json"]
    assert body["buildProfile"] == {
        "sdkResolutionMode": "non-registered",
        "sdkDescriptor": {"sdkRootPath": "/uploads/sdk"},
        "compiler": "g++",
    }
