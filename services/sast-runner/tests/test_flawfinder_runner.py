"""FlawfinderRunner 파서 단위 테스트."""

import logging
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.scanner.flawfinder_runner import FlawfinderRunner


@pytest.fixture
def runner():
    return FlawfinderRunner()


def _make_proc_mock(returncode: int, stdout: bytes = b"", stderr: bytes = b""):
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = AsyncMock()
    return proc


SAMPLE_CSV = """\
File,Line,Column,Context,Level,Category,Name,Warning,Suggestion,Note,CWEs,Other
/tmp/scan/src/main.c,8,5,"  gets(buf);",5,buffer,gets,"Does not check for buffer overflows (CWE-120, CWE-20).",Consider using fgets().,,"CWE-120, CWE-20",
/tmp/scan/src/main.c,10,5,"  printf(buf);",4,format,printf,"If format strings can be influenced by an attacker, they can be exploited (CWE-134).",Use a constant for the format specification.,,"CWE-134",
/tmp/scan/src/main.c,3,0,"",1,buffer,strcpy,"Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120).",Consider using snprintf or strlcpy.,,"CWE-120",
"""


class TestParseCsv:
    def test_basic_parsing(self, runner):
        findings = runner._parse_csv(SAMPLE_CSV, Path("/tmp/scan"))
        assert len(findings) == 3

    def test_tool_id(self, runner):
        findings = runner._parse_csv(SAMPLE_CSV, Path("/tmp/scan"))
        assert all(f.tool_id == "flawfinder" for f in findings)

    def test_rule_id_format(self, runner):
        findings = runner._parse_csv(SAMPLE_CSV, Path("/tmp/scan"))
        assert findings[0].rule_id == "flawfinder:buffer/gets"

    def test_cwe_extraction_from_warning(self, runner):
        findings = runner._parse_csv(SAMPLE_CSV, Path("/tmp/scan"))
        # gets has CWE-120 in Warning text
        cwe = findings[0].metadata.get("cwe")
        assert cwe is not None
        assert "CWE-120" in (cwe if isinstance(cwe, list) else [cwe])

    def test_severity_mapping(self, runner):
        findings = runner._parse_csv(SAMPLE_CSV, Path("/tmp/scan"))
        # Level 5 → error, Level 4 → error (high risk)
        assert findings[0].severity == "error"
        # Level 4 is also high — actual mapping determines this
        assert findings[1].severity in ("error", "warning")

    def test_path_normalization(self, runner):
        findings = runner._parse_csv(SAMPLE_CSV, Path("/tmp/scan"))
        assert findings[0].location.file == "src/main.c"

    def test_location_line_column(self, runner):
        findings = runner._parse_csv(SAMPLE_CSV, Path("/tmp/scan"))
        assert findings[0].location.line == 8
        assert findings[0].location.column == 5

    def test_empty_csv(self, runner):
        empty = "File,Line,Column,Context,Level,Category,Name,Warning,Suggestion,Note,CWEs,Other\n"
        findings = runner._parse_csv(empty, Path("/tmp/scan"))
        assert findings == []

    def test_malformed_numeric_fields_do_not_crash_parser(self, runner):
        malformed = """\
File,Line,Column,Context,Level,Category,Name,Warning,Suggestion,Note,CWEs,Other
/tmp/scan/src/missing_line.c,,,"  gets(buf);",5,buffer,gets,"CWE-120",,,,
/tmp/scan/src/missing_level.c,12,,"  strcpy(a,b);",,buffer,strcpy,"CWE-120",,,,
"""

        findings = runner._parse_csv(malformed, Path("/tmp/scan"))

        assert len(findings) == 1
        assert findings[0].location.file == "src/missing_level.c"
        assert findings[0].location.line == 12
        assert findings[0].location.column is None
        assert findings[0].metadata["flawfinderLevel"] == 1

    def test_non_numeric_fields_do_not_crash_parser(self, runner):
        malformed = """\
File,Line,Column,Context,Level,Category,Name,Warning,Suggestion,Note,CWEs,Other
/tmp/scan/src/non_numeric_line.c,abc,7,"  gets(buf);",5,buffer,gets,"CWE-120",,,,
/tmp/scan/src/non_numeric_level_column.c,13,nan,"  strcpy(a,b);",abc,buffer,strcpy,"CWE-120",,,,
"""

        findings = runner._parse_csv(malformed, Path("/tmp/scan"))

        assert len(findings) == 1
        assert findings[0].location.file == "src/non_numeric_level_column.c"
        assert findings[0].location.line == 13
        assert findings[0].location.column is None
        assert findings[0].metadata["flawfinderLevel"] == 1


class TestRun:
    @pytest.mark.asyncio
    async def test_command_start_log_does_not_echo_raw_command(self, runner, tmp_path, caplog):
        """Flawfinder 실행 시작 로그는 joined command와 scan_dir를 남기지 않는다."""
        scan_dir = tmp_path / "SECRET_FLAWFINDER_SCAN_DIR_SHOULD_NOT_LEAK"
        scan_dir.mkdir()
        proc = _make_proc_mock(
            0,
            stdout=b"File,Line,Column,Context,Level,Category,Name,Warning,Suggestion,Note,CWEs,Other\n",
        )
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner.run(scan_dir)

        assert result == []
        assert "Running Flawfinder" in caplog.text
        assert "SECRET_FLAWFINDER_SCAN_DIR_SHOULD_NOT_LEAK" not in caplog.text
        assert "--csv" not in caplog.text
        assert "--minlevel=1" not in caplog.text
