"""include_resolver 단위 테스트 — gcc -E -M 의존성 파싱."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.scanner.include_resolver import IncludeResolver


@pytest.fixture
def resolver():
    return IncludeResolver()


class TestParseDeps:
    def test_single_line(self, resolver):
        raw = "main.o: src/main.c include/header.h /usr/include/stdio.h"
        result = resolver._parse_deps(raw, Path("src/main.c"))
        assert "include/header.h" in result
        assert "<external>/stdio.h" in result

    def test_absolute_external_dependency_redacts_host_root(self, resolver, tmp_path):
        raw = "main.o: src/main.c /tmp/SECRET_SDK_ROOT/usr/include/stdio.h"
        result = resolver._parse_deps(
            raw,
            Path("src/main.c"),
            scan_dir=tmp_path / "project",
        )

        assert result == ["<external>/stdio.h"]
        assert "SECRET_SDK_ROOT" not in str(result)
        assert not any(Path(dep).is_absolute() for dep in result)

    def test_odd_absolute_dependency_uses_unknown_external_sentinel(self, resolver):
        raw = "main.o: src/main.c /"

        result = resolver._parse_deps(raw, Path("src/main.c"))

        assert result == ["<external>/<unknown>"]

    def test_windows_absolute_dependency_redacts_host_root(self, resolver):
        raw = r"main.o: src/main.c C:\SECRET_SDK_ROOT\include\winsock.h"

        result = resolver._parse_deps(raw, Path("src/main.c"))

        assert result == ["<external>/winsock.h"]
        assert "SECRET_SDK_ROOT" not in str(result)

    def test_absolute_project_dependency_becomes_scan_relative(self, resolver, tmp_path):
        scan_dir = tmp_path / "SECRET_PROJECT_ROOT"
        source = scan_dir / "src" / "main.c"
        local_header = scan_dir / "include" / "local.h"
        raw = f"main.o: {source} {local_header}"

        result = resolver._parse_deps(raw, source, scan_dir=scan_dir)

        assert result == ["include/local.h"]
        assert "SECRET_PROJECT_ROOT" not in str(result)

    def test_relative_dependency_remains_unchanged_with_scan_dir(self, resolver, tmp_path):
        raw = "main.o: src/main.c include/header.h"
        result = resolver._parse_deps(
            raw,
            Path("src/main.c"),
            scan_dir=tmp_path / "project",
        )
        assert result == ["include/header.h"]

    def test_multiline_backslash(self, resolver):
        raw = "main.o: src/main.c \\\n include/a.h \\\n include/b.h"
        result = resolver._parse_deps(raw, Path("src/main.c"))
        assert "include/a.h" in result
        assert "include/b.h" in result

    def test_source_file_excluded(self, resolver):
        raw = "main.o: src/main.c include/header.h"
        result = resolver._parse_deps(raw, Path("src/main.c"))
        assert not any(d.endswith("main.c") for d in result)

    def test_no_colon(self, resolver):
        raw = "no deps here"
        result = resolver._parse_deps(raw, Path("src/main.c"))
        assert result == []

    def test_empty_deps(self, resolver):
        raw = "main.o:"
        result = resolver._parse_deps(raw, Path("src/main.c"))
        assert result == []


class TestResolveGcc:
    def test_no_profile_returns_gcc(self, resolver):
        assert resolver._resolve_gcc(None) == "gcc"
