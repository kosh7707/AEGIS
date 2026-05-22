"""ast_dumper 단위 테스트 — 병렬화 + skip_paths + _filter_skip_paths."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner.ast_dumper import AstDumper, _filter_skip_paths


# ──────────────────── _filter_skip_paths ────────────────────


class TestFilterSkipPaths:
    """vendored/third-party 경로 필터링 유틸."""

    def test_empty_skip_paths(self):
        files = ["src/main.c", "lib/foo.c"]
        assert _filter_skip_paths(files, []) == files

    def test_skip_single_dir(self):
        files = ["src/main.c", "libraries/curl/lib.c", "libraries/curl/util.c", "src/app.c"]
        result = _filter_skip_paths(files, ["libraries/curl"])
        assert result == ["src/main.c", "src/app.c"]

    def test_skip_multiple_dirs(self):
        files = [
            "src/main.c",
            "vendor/lib1/a.c",
            "third_party/lib2/b.c",
            "src/util.c",
        ]
        result = _filter_skip_paths(files, ["vendor/lib1", "third_party/lib2"])
        assert result == ["src/main.c", "src/util.c"]

    def test_trailing_slash_handled(self):
        files = ["libs/foo/bar.c", "src/main.c"]
        assert _filter_skip_paths(files, ["libs/foo/"]) == ["src/main.c"]

    def test_no_false_positive_on_prefix(self):
        """libraries/curl은 스킵하지만 libraries/curly는 스킵 안 함."""
        files = ["libraries/curl/lib.c", "libraries/curly/lib.c"]
        result = _filter_skip_paths(files, ["libraries/curl"])
        assert result == ["libraries/curly/lib.c"]

    def test_all_skipped(self):
        files = ["vendor/a.c", "vendor/b.c"]
        assert _filter_skip_paths(files, ["vendor"]) == []

    def test_none_skipped(self):
        files = ["src/a.c", "src/b.c"]
        assert _filter_skip_paths(files, ["vendor"]) == files


# ──────────────────── dump_functions 병렬화 ────────────────────


class TestDumpFunctionsParallel:
    """dump_functions가 asyncio.gather로 병렬 실행되는지 검증."""

    @pytest.fixture
    def dumper(self):
        return AstDumper()

    @pytest.fixture
    def scan_dir(self, tmp_path):
        """3개 소스 파일이 있는 임시 프로젝트."""
        for name in ("a.c", "b.c", "c.c"):
            (tmp_path / name).write_text(f"void {name[0]}() {{}}")
        return tmp_path

    @pytest.mark.asyncio
    async def test_parallel_execution(self, dumper, scan_dir):
        """_extract_functions가 파일별로 병렬 호출되는지 확인."""
        call_order = []

        async def mock_extract(file_path, sd, profile, timeout):
            call_order.append(file_path.name)
            await asyncio.sleep(0.01)  # 비동기 양보 지점
            return [{"name": f"func_{file_path.stem}", "file": file_path.name, "line": 1, "calls": []}]

        with patch.object(dumper, "_extract_functions", side_effect=mock_extract):
            result = await dumper.dump_functions(
                scan_dir, ["a.c", "b.c", "c.c"], None,
            )

        assert len(result["functions"]) == 3
        names = {f["name"] for f in result["functions"]}
        assert names == {"func_a", "func_b", "func_c"}

    @pytest.mark.asyncio
    async def test_skip_paths_reduces_calls(self, dumper, scan_dir):
        """skip_paths로 지정된 파일은 _extract_functions가 호출되지 않는다."""
        # vendor 디렉토리 생성
        vendor_dir = scan_dir / "vendor"
        vendor_dir.mkdir()
        (vendor_dir / "lib.c").write_text("void lib() {}")

        extract_calls = []

        async def mock_extract(file_path, sd, profile, timeout):
            extract_calls.append(file_path.name)
            return [{"name": f"func_{file_path.stem}", "file": str(file_path.relative_to(sd)), "line": 1, "calls": []}]

        with patch.object(dumper, "_extract_functions", side_effect=mock_extract):
            result = await dumper.dump_functions(
                scan_dir, ["a.c", "b.c", "vendor/lib.c"], None,
                skip_paths=["vendor"],
            )

        assert len(result["functions"]) == 2
        assert "lib.c" not in extract_calls

    @pytest.mark.asyncio
    async def test_nonexistent_files_skipped(self, dumper, scan_dir):
        """존재하지 않는 파일은 빈 결과를 반환."""
        async def mock_extract(file_path, sd, profile, timeout):
            return [{"name": "func", "file": file_path.name, "line": 1, "calls": []}]

        with patch.object(dumper, "_extract_functions", side_effect=mock_extract):
            result = await dumper.dump_functions(
                scan_dir, ["a.c", "nonexistent.c"], None,
            )

        # a.c만 처리됨, nonexistent.c는 스킵
        assert len(result["functions"]) == 1

    @pytest.mark.asyncio
    async def test_origin_tagging_still_works(self, dumper, scan_dir):
        """병렬화 후에도 origin 태깅이 정상 동작."""
        lib_dir = scan_dir / "libraries" / "mylib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "core.c").write_text("void core() {}")

        async def mock_extract(file_path, sd, profile, timeout):
            return [{"name": f"func_{file_path.stem}", "file": str(file_path.relative_to(sd)), "line": 1, "calls": []}]

        libraries = [
            {"name": "mylib", "version": "1.0", "path": "libraries/mylib", "diff": {"matchRatio": 95}},
        ]

        with patch.object(dumper, "_extract_functions", side_effect=mock_extract):
            result = await dumper.dump_functions(
                scan_dir, ["a.c", "libraries/mylib/core.c"], None,
                libraries=libraries,
            )

        funcs_by_name = {f["name"]: f for f in result["functions"]}
        assert "origin" not in funcs_by_name["func_a"]
        assert funcs_by_name["func_core"]["origin"] == "modified-third-party"
        assert funcs_by_name["func_core"]["originalLib"] == "mylib"

    def test_function_rows_preserve_body_end_line_and_calls(self, dumper):
        """Function extraction must expose full body extents for downstream anchoring."""
        ast = {
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "trim",
                    "loc": {"file": "/tmp/scan/main.cpp", "line": 51},
                    "range": {"begin": {"line": 51}, "end": {"line": 67}},
                    "inner": [
                        {"kind": "ParmVarDecl", "name": "s"},
                        {
                            "kind": "CompoundStmt",
                            "inner": [
                                {
                                    "kind": "CallExpr",
                                    "inner": [
                                        {"kind": "DeclRefExpr", "referencedDecl": {"name": "substr"}},
                                    ],
                                },
                            ],
                        },
                    ],
                },
            ],
        }
        rows: list[dict] = []

        dumper._extract_user_functions(
            ast,
            rel_path="main.cpp",
            source_path="/tmp/scan/main.cpp",
            source_lines=100,
            out=rows,
        )

        assert rows == [
            {
                "name": "trim",
                "file": "main.cpp",
                "line": 51,
                "endLine": 67,
                "calls": ["substr"],
            },
        ]


# ──────────────────── _dump_single failure logging ────────────────────


class TestDumpSingleFailureLogging:
    """_dump_single 실패 로그는 caller/file/exception detail을 노출하지 않는다."""

    @pytest.fixture
    def dumper(self):
        return AstDumper()

    @pytest.mark.asyncio
    async def test_failure_log_uses_category_without_filename_or_exception_text(
        self, dumper, tmp_path, caplog
    ):
        source = tmp_path / "SECRET_AST_FILENAME_SHOULD_NOT_LEAK.c"
        source.write_text("int main(void) { return 0; }")

        async def mock_exec(*args, **kwargs):
            raise FileNotFoundError("SECRET_AST_ERROR_SHOULD_NOT_LEAK")

        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await dumper._dump_single(source, tmp_path, None, timeout=1)

        assert result is None
        assert "AST dump failed" in caplog.text
        assert "AST dump failed for" not in caplog.text
        assert "SECRET_AST_FILENAME_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_AST_ERROR_SHOULD_NOT_LEAK" not in caplog.text


# ──────────────────── dump_ast 병렬화 ────────────────────


class TestDumpAstParallel:
    """dump_ast가 asyncio.gather로 병렬 실행되는지 검증."""

    @pytest.fixture
    def dumper(self):
        return AstDumper()

    @pytest.fixture
    def scan_dir(self, tmp_path):
        for name in ("x.c", "y.h"):
            (tmp_path / name).write_text(f"// {name}")
        return tmp_path

    @pytest.mark.asyncio
    async def test_parallel_ast_dump(self, dumper, scan_dir):
        async def mock_dump(file_path, sd, profile, timeout):
            return {"kind": "TranslationUnitDecl", "file": file_path.name}

        with patch.object(dumper, "_dump_single", side_effect=mock_dump):
            result = await dumper.dump_ast(scan_dir, ["x.c", "y.h"], None)

        assert "x.c" in result["files"]
        assert "y.h" in result["files"]

    @pytest.mark.asyncio
    async def test_skip_paths_in_dump_ast(self, dumper, scan_dir):
        vendor_dir = scan_dir / "vendor"
        vendor_dir.mkdir()
        (vendor_dir / "v.c").write_text("// vendor")

        async def mock_dump(file_path, sd, profile, timeout):
            return {"kind": "TranslationUnitDecl"}

        with patch.object(dumper, "_dump_single", side_effect=mock_dump):
            result = await dumper.dump_ast(
                scan_dir, ["x.c", "vendor/v.c"], None,
                skip_paths=["vendor"],
            )

        assert "x.c" in result["files"]
        assert "vendor/v.c" not in result["files"]
