"""LibraryIdentifier 단위 테스트."""

import logging
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.scanner.library_identifier import LibraryIdentifier


@pytest.fixture
def identifier():
    return LibraryIdentifier()


class TestParseCmake:
    def test_project_with_version(self, identifier, tmp_path):
        cmake = tmp_path / "CMakeLists.txt"
        cmake.write_text('cmake_minimum_required(VERSION 3.10)\nproject(civetweb VERSION 1.16)\n')
        result = identifier._parse_cmake(cmake)
        assert result is not None
        assert result["name"] == "civetweb"
        assert result["version"] == "1.16"

    def test_project_without_version(self, identifier, tmp_path):
        cmake = tmp_path / "CMakeLists.txt"
        cmake.write_text('project(mylib)\nadd_library(mylib src/lib.c)\n')
        result = identifier._parse_cmake(cmake)
        # version 없으면 None 가능
        assert result is None or result.get("version") is None

    def test_set_version_variables(self, identifier, tmp_path):
        cmake = tmp_path / "CMakeLists.txt"
        cmake.write_text(
            'project(rapidjson)\n'
            'set(LIB_MAJOR_VERSION "1")\n'
            'set(LIB_MINOR_VERSION "1")\n'
            'set(LIB_PATCH_VERSION "0")\n'
        )
        result = identifier._parse_cmake(cmake)
        assert result is not None
        assert result["version"] == "1.1.0"


class TestParseConfigureAc:
    def test_ac_init(self, identifier, tmp_path):
        ac = tmp_path / "configure.ac"
        ac.write_text('AC_INIT([tinydtls], [0.8.6])\nAC_CONFIG_SRCDIR([dtls.c])\n')
        result = identifier._parse_configure_ac(ac)
        assert result is not None
        assert result["name"] == "tinydtls"
        assert result["version"] == "0.8.6"

    def test_no_ac_init(self, identifier, tmp_path):
        ac = tmp_path / "configure.ac"
        ac.write_text('dnl just a comment\n')
        result = identifier._parse_configure_ac(ac)
        assert result is None


class TestParseVersionHeader:
    def test_define_version(self, identifier, tmp_path):
        header = tmp_path / "version.h"
        header.write_text('#define CIVETWEB_VERSION "1.16"\n')
        result = identifier._parse_version_header(header, "civetweb")
        assert result is not None
        assert result["version"] == "1.16"

    def test_no_version_define(self, identifier, tmp_path):
        header = tmp_path / "config.h"
        header.write_text('#define BUFFER_SIZE 1024\n')
        result = identifier._parse_version_header(header, "mylib")
        assert result is None


class TestFindLibraryDirs:
    def test_finds_libraries_dir(self, identifier, tmp_path):
        lib_dir = tmp_path / "libraries" / "civetweb"
        lib_dir.mkdir(parents=True)
        (lib_dir / "civetweb.c").write_text("// source\n")
        dirs = identifier._find_library_dirs(tmp_path)
        assert len(dirs) >= 1

    def test_skips_build_dir(self, identifier, tmp_path):
        build_dir = tmp_path / "build" / "somelib"
        build_dir.mkdir(parents=True)
        (build_dir / "lib.c").write_text("// source\n")
        dirs = identifier._find_library_dirs(tmp_path)
        assert all("build" not in str(d) for d in dirs)

    def test_skips_node_modules(self, identifier, tmp_path):
        nm = tmp_path / "node_modules" / "somelib"
        nm.mkdir(parents=True)
        dirs = identifier._find_library_dirs(tmp_path)
        assert all("node_modules" not in str(d) for d in dirs)

    def test_permission_denied_log_uses_category_without_child_path(
        self, identifier, tmp_path, monkeypatch, caplog
    ):
        """권한 거부 로그는 child path/name/error detail을 노출하지 않는다."""

        class SecretPermissionChild:
            name = "SECRET_PERMISSION_DIR_SHOULD_NOT_LEAK"

            def is_dir(self):
                raise PermissionError("SECRET_PERMISSION_ERROR_SHOULD_NOT_LEAK")

            def __str__(self):
                return "/tmp/SECRET_PERMISSION_DIR_SHOULD_NOT_LEAK"

        def fake_iterdir(path):
            if path == tmp_path:
                return iter([SecretPermissionChild()])
            return iter([])

        monkeypatch.setattr(Path, "iterdir", fake_iterdir)
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        dirs = identifier._find_library_dirs(tmp_path)

        assert dirs == []
        assert "Permission denied scanning directory" in caplog.text
        assert "SECRET_PERMISSION_DIR_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_PERMISSION_ERROR_SHOULD_NOT_LEAK" not in caplog.text


class TestIdentify:
    def test_identify_summary_log_uses_count_without_project_path(
        self, identifier, tmp_path, caplog
    ):
        """식별 summary 로그는 project root path를 노출하지 않는다."""
        project = tmp_path / "SECRET_PROJECT_ROOT_SHOULD_NOT_LEAK"
        lib_dir = project / "libraries" / "mylib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "CMakeLists.txt").write_text("project(mylib VERSION 2.0.0)\n")

        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        libs = identifier.identify(project)

        assert len([lib for lib in libs if lib["name"] == "mylib"]) == 1
        assert "Identified 1 libraries" in caplog.text
        assert "SECRET_PROJECT_ROOT_SHOULD_NOT_LEAK" not in caplog.text

    def test_cmake_library(self, identifier, tmp_path):
        lib_dir = tmp_path / "libraries" / "mylib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "CMakeLists.txt").write_text('project(mylib VERSION 2.0.0)\n')
        (lib_dir / "mylib.c").write_text("// source\n")

        libs = identifier.identify(tmp_path)
        assert len(libs) >= 1
        mylib = [l for l in libs if l["name"] == "mylib"]
        assert len(mylib) == 1
        assert mylib[0]["version"] == "2.0.0"


class TestGitInfo:
    def test_git_remote_query_fragment_do_not_pollute_name(self, identifier, tmp_path):
        """git remote에서 name을 추출할 때 credential/query/fragment를 제외한다."""
        lib_dir = tmp_path / "private-lib"
        lib_dir.mkdir()
        secret_url = (
            "https://user:SECRET_TOKEN_SHOULD_NOT_LEAK@example.internal/org/"
            "private-lib.git?token=SECRET_QUERY_SHOULD_NOT_LEAK#SECRET_FRAGMENT_SHOULD_NOT_LEAK"
        )

        outputs = [
            "abc123",  # commit
            "main",  # branch
            secret_url,  # remote
            "",  # exact tag
            "",  # nearest tag
        ]

        def fake_run(*args, **kwargs):
            return Mock(stdout=outputs.pop(0))

        with patch("subprocess.run", side_effect=fake_run):
            result = identifier._parse_git_info(lib_dir)

        assert result is not None
        assert result["name"] == "private-lib"
        assert result["remoteUrl"] == secret_url  # internal clone material remains raw
        rendered_name = json.dumps({"name": result["name"]})
        assert "SECRET_TOKEN_SHOULD_NOT_LEAK" not in rendered_name
        assert "SECRET_QUERY_SHOULD_NOT_LEAK" not in rendered_name
        assert "SECRET_FRAGMENT_SHOULD_NOT_LEAK" not in rendered_name
