"""ScanbuildRunner 파서 단위 테스트."""

import asyncio
import logging
import plistlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner.path_utils import normalize_path
from app.scanner.scanbuild_runner import ScanbuildRunner


@pytest.fixture
def runner():
    return ScanbuildRunner()


class TestConvertDiagnostic:
    """_convert_diagnostic() 메서드 단위 테스트."""

    def test_basic_diagnostic(self, runner):
        files_list = ["src/main.c", "src/util.c"]
        diag = {
            "description": "Null pointer dereference",
            "category": "Logic error",
            "check_name": "core.NullDereference",
            "location": {"file": 0, "line": 17, "col": 5},
            "path": [],
        }
        finding = runner._convert_diagnostic(diag, files_list, Path("/tmp/scan"))
        assert finding is not None
        assert finding.tool_id == "scan-build"
        assert finding.rule_id == "scan-build:core.NullDereference"
        assert finding.location.file == "src/main.c"
        assert finding.location.line == 17

    def test_cwe_mapping(self, runner):
        files_list = ["src/main.c"]
        diag = {
            "description": "Use of memory after it is freed",
            "category": "Memory error",
            "check_name": "unix.Malloc",
            "location": {"file": 0, "line": 14, "col": 5},
            "path": [],
        }
        finding = runner._convert_diagnostic(diag, files_list, Path("/tmp/scan"))
        assert finding is not None
        cwe = finding.metadata.get("cwe")
        assert cwe is not None

    def test_data_flow_extraction(self, runner):
        files_list = ["src/main.c"]
        diag = {
            "description": "Dereference of null pointer",
            "category": "Logic error",
            "check_name": "core.NullDereference",
            "location": {"file": 0, "line": 17, "col": 5},
            "path": [
                {"kind": "event", "location": {"file": 0, "line": 15, "col": 3},
                 "message": "Variable 'q' initialized to NULL"},
                {"kind": "control", "location": {"file": 0, "line": 16, "col": 3}},
                {"kind": "event", "location": {"file": 0, "line": 17, "col": 5},
                 "message": "Dereference of null pointer"},
            ],
        }
        finding = runner._convert_diagnostic(diag, files_list, Path("/tmp/scan"))
        assert finding is not None
        assert finding.data_flow is not None
        # Only "event" kind entries become data flow steps
        assert len(finding.data_flow) == 2

    def test_invalid_file_index(self, runner):
        files_list = ["src/main.c"]
        diag = {
            "description": "Some error",
            "category": "Logic error",
            "check_name": "core.Something",
            "location": {"file": 99, "line": 1, "col": 1},
            "path": [],
        }
        finding = runner._convert_diagnostic(diag, files_list, Path("/tmp/scan"))
        assert finding is None

    def test_negative_file_index(self, runner):
        """음수 file_idx는 files_list[-1]이 아닌 None 반환."""
        files_list = ["src/main.c"]
        diag = {
            "description": "Some error",
            "category": "Logic error",
            "check_name": "core.Something",
            "location": {"file": -1, "line": 10, "col": 1},
            "path": [],
        }
        finding = runner._convert_diagnostic(diag, files_list, Path("/tmp/scan"))
        assert finding is None

    def test_missing_line(self, runner):
        files_list = ["src/main.c"]
        diag = {
            "description": "Some error",
            "category": "Logic error",
            "check_name": "core.Something",
            "location": {"file": 0},
            "path": [],
        }
        finding = runner._convert_diagnostic(diag, files_list, Path("/tmp/scan"))
        assert finding is None


class TestNormalizePath:
    def test_strips_base_dir(self):
        assert normalize_path("/tmp/scan/src/main.c", Path("/tmp/scan")) == "src/main.c"

    def test_already_relative(self):
        assert normalize_path("src/main.c", Path("/tmp/scan")) == "src/main.c"


class TestParsePlistResults:
    def test_malformed_plist_log_does_not_echo_filename_or_parser_error(self, runner, tmp_path, caplog):
        output_dir = tmp_path / "scan-build-output"
        output_dir.mkdir()
        secret_name = "SECRET_SCAN_BUILD_PLIST_NAME_SHOULD_NOT_LEAK.plist"
        secret_content = "SECRET_SCAN_BUILD_PLIST_CONTENT_SHOULD_NOT_LEAK"
        (output_dir / secret_name).write_text(secret_content, encoding="utf-8")
        valid_plist = output_dir / "valid.plist"
        with valid_plist.open("wb") as handle:
            plistlib.dump(
                {
                    "files": ["/tmp/scan/src/main.c"],
                    "diagnostics": [
                        {
                            "description": "Null pointer dereference",
                            "category": "Logic error",
                            "check_name": "core.NullDereference",
                            "location": {"file": 0, "line": 17, "col": 5},
                            "path": [],
                        }
                    ],
                },
                handle,
            )
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        findings = runner._parse_plist_results(output_dir, Path("/tmp/scan"))

        assert len(findings) == 1
        assert findings[0].location.file == "src/main.c"
        assert "Failed to parse scan-build plist" in caplog.text
        assert "SECRET_SCAN_BUILD_PLIST_NAME_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_SCAN_BUILD_PLIST_CONTENT_SHOULD_NOT_LEAK" not in caplog.text
        assert "Invalid file" not in caplog.text


class TestFileProgressCallback:
    @pytest.mark.asyncio
    async def test_per_file_failure_log_does_not_echo_exception_text(self, runner, caplog):
        """파일별 실패 로그는 raw source file이나 exception text를 남기지 않는다."""
        secret_source = "src/SECRET_SCANBUILD_SOURCE_FILE_SHOULD_NOT_LEAK.c"

        async def _mock_single(bin_name, scan_dir, f, profile, timeout):
            del bin_name, scan_dir, f, profile, timeout
            raise RuntimeError("SECRET_SCAN_BUILD_ERROR_SHOULD_NOT_LEAK")

        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        with (
            patch.object(runner, "_run_single", side_effect=_mock_single),
            patch.object(runner, "check_available", return_value=(True, "scan-build-18")),
        ):
            findings = await runner.run(
                scan_dir=Path("/tmp/scan"),
                source_files=[secret_source],
                profile=None,
                timeout=60,
            )

        assert findings == []
        assert runner._last_failed == 1
        assert "scan-build failed" in caplog.text
        assert "SECRET_SCANBUILD_SOURCE_FILE_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_SCAN_BUILD_ERROR_SHOULD_NOT_LEAK" not in caplog.text

    @pytest.mark.asyncio
    async def test_per_file_timeout_log_does_not_echo_source_file(self, runner, caplog):
        """파일별 timeout 로그는 raw source file을 남기지 않는다."""
        source_file = "src/SECRET_SCANBUILD_TIMEOUT_SOURCE_SHOULD_NOT_LEAK.c"
        proc = AsyncMock()
        proc.kill = MagicMock()
        proc.communicate = AsyncMock(side_effect=[asyncio.TimeoutError(), (b"", b"")])
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await runner._run_single(
                "scan-build",
                Path("/tmp/scan"),
                source_file,
                profile=None,
                timeout=10,
            )

        assert result is None
        assert "scan-build timed out" in caplog.text
        assert "SECRET_SCANBUILD_TIMEOUT_SOURCE_SHOULD_NOT_LEAK" not in caplog.text

    @pytest.mark.asyncio
    async def test_on_file_progress_called(self, runner):
        """파일 완료 시 on_file_progress 콜백이 호출되고 done/total이 정확한지 확인."""
        progress_calls = []

        async def on_file_progress(file: str, done: int, total: int):
            progress_calls.append((file, done, total))

        async def _mock_single(bin_name, scan_dir, f, profile, timeout):
            return []

        with (
            patch.object(runner, "_run_single", side_effect=_mock_single),
            patch.object(runner, "check_available", return_value=(True, "scan-build-18")),
        ):
            await runner.run(
                scan_dir=Path("/tmp/scan"),
                source_files=["src/a.c", "src/b.c"],
                profile=None,
                timeout=60,
                on_file_progress=on_file_progress,
            )

        assert len(progress_calls) == 2
        files = [f for f, _, _ in progress_calls]
        assert set(files) == {"src/a.c", "src/b.c"}
        last = max(progress_calls, key=lambda x: x[1])
        assert last[1] == last[2] == 2
