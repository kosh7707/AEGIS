"""CppcheckRunner 파서 단위 테스트."""

import logging
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.scanner.cppcheck_runner import CppcheckRunner
from app.scanner.path_utils import normalize_path
from app.schemas.request import BuildProfile


@pytest.fixture
def runner():
    return CppcheckRunner()


def _make_proc_mock(returncode: int, stdout: bytes = b"", stderr: bytes = b""):
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = AsyncMock()
    return proc


SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer dereference: p"
           verbose="Null pointer dereference" cwe="476">
      <location file="/tmp/scan/src/main.c" line="17" column="5"/>
    </error>
    <error id="bufferAccessOutOfBounds" severity="error"
           msg="Buffer is accessed out of bounds" cwe="788">
      <location file="/tmp/scan/src/main.c" line="8" column="5"/>
      <location file="/tmp/scan/src/main.c" line="7" column="5"/>
    </error>
    <error id="unusedVariable" severity="style" msg="Unused variable: x">
      <location file="/tmp/scan/src/util.c" line="3" column="9"/>
    </error>
  </errors>
</results>
"""

EMPTY_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <errors/>
</results>
"""


class TestParseXml:
    def test_basic_parsing(self, runner):
        findings = runner._parse_xml(SAMPLE_XML, Path("/tmp/scan"))
        assert len(findings) == 3

    def test_tool_id(self, runner):
        findings = runner._parse_xml(SAMPLE_XML, Path("/tmp/scan"))
        assert all(f.tool_id == "cppcheck" for f in findings)

    def test_rule_id_format(self, runner):
        findings = runner._parse_xml(SAMPLE_XML, Path("/tmp/scan"))
        assert findings[0].rule_id == "cppcheck:nullPointer"

    def test_cwe_extraction(self, runner):
        findings = runner._parse_xml(SAMPLE_XML, Path("/tmp/scan"))
        assert "CWE-476" in findings[0].metadata["cwe"]
        assert "CWE-788" in findings[1].metadata["cwe"]

    def test_no_cwe(self, runner):
        findings = runner._parse_xml(SAMPLE_XML, Path("/tmp/scan"))
        assert "cwe" not in findings[2].metadata or findings[2].metadata.get("cwe") is None

    def test_path_normalization(self, runner):
        findings = runner._parse_xml(SAMPLE_XML, Path("/tmp/scan"))
        assert findings[0].location.file == "src/main.c"

    def test_data_flow_multiple_locations(self, runner):
        findings = runner._parse_xml(SAMPLE_XML, Path("/tmp/scan"))
        # bufferAccessOutOfBounds has 2 locations → data flow
        buf_finding = findings[1]
        assert buf_finding.data_flow is not None
        assert len(buf_finding.data_flow) >= 1

    def test_empty_results(self, runner):
        findings = runner._parse_xml(EMPTY_XML, Path("/tmp/scan"))
        assert findings == []


class TestNormalizePath:
    def test_strips_base_dir(self):
        result = normalize_path("/tmp/scan/src/main.c", Path("/tmp/scan"))
        assert result == "src/main.c"

    def test_already_relative(self):
        result = normalize_path("src/main.c", Path("/tmp/scan"))
        assert result == "src/main.c"

    def test_different_base(self):
        result = normalize_path("/other/path/file.c", Path("/tmp/scan"))
        assert result == "/other/path/file.c"


class TestRun:
    @pytest.mark.asyncio
    async def test_command_start_log_does_not_echo_raw_command(self, runner, tmp_path, caplog):
        """Cppcheck 실행 시작 로그는 joined command, scan_dir, include path를 남기지 않는다."""
        scan_dir = tmp_path / "SECRET_CPPCHECK_SCAN_DIR_SHOULD_NOT_LEAK"
        scan_dir.mkdir()
        profile = BuildProfile(
            includePaths=["SECRET_CPPCHECK_INCLUDE_SHOULD_NOT_LEAK"],
            languageStandard="c11",
        )
        proc = _make_proc_mock(0, stderr=EMPTY_XML.encode())
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.run(scan_dir, profile)

        assert result == []
        assert "Running Cppcheck" in caplog.text
        assert "SECRET_CPPCHECK_SCAN_DIR_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_CPPCHECK_INCLUDE_SHOULD_NOT_LEAK" not in caplog.text
        assert "--xml" not in caplog.text
        assert "--enable=all" not in caplog.text
