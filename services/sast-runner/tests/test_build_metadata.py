"""BuildMetadataExtractor 단위 테스트 — _parse_macros, _derive_target_info, _lang_flag."""

from __future__ import annotations

import json
import logging
from unittest.mock import AsyncMock, patch

import pytest

from app.scanner.build_metadata import BuildMetadataExtractor
from app.schemas.request import BuildProfile


@pytest.fixture
def extractor():
    return BuildMetadataExtractor()


# ---------------------------------------------------------------------------
# _parse_macros
# ---------------------------------------------------------------------------

SAMPLE_GCC_OUTPUT = """\
#define __STDC__ 1
#define __STDC_VERSION__ 201710L
#define __GNUC__ 13
#define __GNUC_MINOR__ 3
#define __GNUC_PATCHLEVEL__ 0
#define __SIZEOF_POINTER__ 8
#define __SIZEOF_LONG__ 8
#define __SIZEOF_INT__ 4
#define __SIZEOF_LONG_LONG__ 8
#define __SIZEOF_LONG_DOUBLE__ 16
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#define __ORDER_LITTLE_ENDIAN__ 1234
#define __ORDER_BIG_ENDIAN__ 4321
#define __x86_64__ 1
#define __LP64__ 1
#define __linux__ 1
#define __unix__ 1
#define __USER_LABEL_PREFIX__
#define __REGISTER_PREFIX__
#define __HAVE_SPECULATION_SAFE_VALUE 1
#define __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16 1
"""


class TestParseMacros:
    def test_parses_interesting_macros(self, extractor):
        """관심 매크로만 파싱하여 반환."""
        result = extractor._parse_macros(SAMPLE_GCC_OUTPUT)

        assert result["__GNUC__"] == "13"
        assert result["__GNUC_MINOR__"] == "3"
        assert result["__SIZEOF_POINTER__"] == "8"
        assert result["__x86_64__"] == "1"
        assert result["__linux__"] == "1"
        assert result["__STDC_VERSION__"] == "201710L"
        assert result["__BYTE_ORDER__"] == "__ORDER_LITTLE_ENDIAN__"

    def test_ignores_non_interesting_macros(self, extractor):
        """_INTERESTING_MACROS에 없는 매크로는 무시."""
        result = extractor._parse_macros(SAMPLE_GCC_OUTPUT)

        assert "__STDC__" not in result
        assert "__USER_LABEL_PREFIX__" not in result
        assert "__REGISTER_PREFIX__" not in result
        assert "__HAVE_SPECULATION_SAFE_VALUE" not in result
        assert "__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16" not in result

    def test_empty_input(self, extractor):
        """빈 입력 → 빈 딕셔너리."""
        result = extractor._parse_macros("")
        assert result == {}

    def test_malformed_lines_skipped(self, extractor):
        """형식이 잘못된 줄은 무시."""
        raw = "#define __GNUC__ 13\nno-define line\n#define\n"
        result = extractor._parse_macros(raw)
        assert result == {"__GNUC__": "13"}


# ---------------------------------------------------------------------------
# _derive_target_info
# ---------------------------------------------------------------------------

class TestDeriveTargetInfo:
    def test_arm_macros(self, extractor):
        """__arm__ → arch=arm."""
        macros = {
            "__arm__": "1",
            "__ARM_ARCH": "7",
            "__SIZEOF_POINTER__": "4",
            "__BYTE_ORDER__": "__ORDER_LITTLE_ENDIAN__",
        }
        info = extractor._derive_target_info(macros)

        assert info["arch"] == "arm"
        assert info["pointerSize"] == 4
        assert info["endianness"] == "little"

    def test_aarch64_macros(self, extractor):
        """__aarch64__ → arch=aarch64 (arm보다 우선)."""
        macros = {
            "__aarch64__": "1",
            "__SIZEOF_POINTER__": "8",
            "__SIZEOF_LONG__": "8",
            "__BYTE_ORDER__": "__ORDER_LITTLE_ENDIAN__",
        }
        info = extractor._derive_target_info(macros)

        assert info["arch"] == "aarch64"
        assert info["pointerSize"] == 8
        assert info["longSize"] == 8

    def test_x86_64_macros(self, extractor):
        """__x86_64__ → arch=x86_64."""
        macros = {
            "__x86_64__": "1",
            "__SIZEOF_POINTER__": "8",
            "__BYTE_ORDER__": "__ORDER_LITTLE_ENDIAN__",
        }
        info = extractor._derive_target_info(macros)

        assert info["arch"] == "x86_64"

    def test_i386_macros(self, extractor):
        """__i386__ → arch=i386."""
        macros = {"__i386__": "1"}
        info = extractor._derive_target_info(macros)
        assert info["arch"] == "i386"

    def test_big_endian(self, extractor):
        """__BYTE_ORDER__ == BIG → endianness=big."""
        macros = {
            "__arm__": "1",
            "__BYTE_ORDER__": "__ORDER_BIG_ENDIAN__",
        }
        info = extractor._derive_target_info(macros)
        assert info["endianness"] == "big"

    def test_cpp_standard(self, extractor):
        """__cplusplus → cppStandard."""
        macros = {"__cplusplus": "201703L"}
        info = extractor._derive_target_info(macros)
        assert info["cppStandard"] == "201703L"

    def test_c_standard(self, extractor):
        """__STDC_VERSION__ → cStandard."""
        macros = {"__STDC_VERSION__": "201710L"}
        info = extractor._derive_target_info(macros)
        assert info["cStandard"] == "201710L"

    def test_empty_macros(self, extractor):
        """매크로 없으면 빈 딕셔너리."""
        info = extractor._derive_target_info({})
        assert info == {}

    def test_no_byte_order(self, extractor):
        """__BYTE_ORDER__ 없으면 endianness 키 없음."""
        macros = {"__arm__": "1"}
        info = extractor._derive_target_info(macros)
        assert "endianness" not in info


# ---------------------------------------------------------------------------
# _lang_flag
# ---------------------------------------------------------------------------

class TestLangFlag:
    def test_cpp17_returns_cpp(self, extractor):
        """c++17 표준 → 'c++'."""
        profile = BuildProfile(language_standard="c++17")
        assert extractor._lang_flag(profile) == "c++"

    def test_gnuplusplus14_returns_cpp(self, extractor):
        """gnu++14 표준 → 'c++'."""
        profile = BuildProfile(language_standard="gnu++14")
        assert extractor._lang_flag(profile) == "c++"

    def test_c99_returns_c(self, extractor):
        """c99 표준 → 'c'."""
        profile = BuildProfile(language_standard="c99")
        assert extractor._lang_flag(profile) == "c"

    def test_c11_returns_c(self, extractor):
        """c11 표준 → 'c'."""
        profile = BuildProfile(language_standard="c11")
        assert extractor._lang_flag(profile) == "c"

    def test_none_profile_returns_c(self, extractor):
        """profile=None → 'c'."""
        assert extractor._lang_flag(None) == "c"

    def test_no_language_standard_returns_c(self, extractor):
        """language_standard 없는 profile → 'c'."""
        profile = BuildProfile()
        assert extractor._lang_flag(profile) == "c"

    def test_uppercase_cpp(self, extractor):
        """대소문자 혼합 C++17 → 'c++' (lower 처리)."""
        profile = BuildProfile(language_standard="C++17")
        assert extractor._lang_flag(profile) == "c++"


# ---------------------------------------------------------------------------
# extract (integration-style, subprocess mocked)
# ---------------------------------------------------------------------------

class TestExtract:
    async def test_extract_returns_metadata(self, extractor):
        """extract()가 subprocess를 호출하고 결과를 조합."""
        gcc_output = (
            b"#define __GNUC__ 13\n"
            b"#define __GNUC_MINOR__ 3\n"
            b"#define __x86_64__ 1\n"
            b"#define __SIZEOF_POINTER__ 8\n"
            b"#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__\n"
        )

        proc = AsyncMock()
        proc.communicate = AsyncMock(return_value=(gcc_output, b""))

        version_proc = AsyncMock()
        version_proc.communicate = AsyncMock(
            return_value=(b"gcc (Ubuntu 13.3.0-6ubuntu2) 13.3.0\n", b"")
        )

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return proc
            return version_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await extractor.extract(None)

        assert "gcc" in result["compiler"]
        assert "13.3.0" in result["compiler"]
        assert result["macros"]["__GNUC__"] == "13"
        assert result["targetInfo"]["arch"] == "x86_64"
        assert result["targetInfo"]["endianness"] == "little"

    async def test_extract_success_compiler_identity_redacts_absolute_path(
        self, extractor
    ):
        """성공 metadata compiler 필드는 실행 경로가 아니라 compiler identity만 노출한다."""
        secret_compiler = (
            "/tmp/SECRET_SDK_ROOT_SHOULD_NOT_LEAK/sysroots/arm/usr/bin/"
            "arm-none-eabi-gcc"
        )
        proc = AsyncMock()
        proc.communicate = AsyncMock(
            return_value=(
                b"#define __GNUC__ 9\n#define __arm__ 1\n#define __SIZEOF_POINTER__ 4\n",
                b"",
            )
        )

        async def mock_exec(*args, **kwargs):
            assert args[0] == secret_compiler
            return proc

        with (
            patch.object(extractor, "_resolve_gcc", return_value=secret_compiler),
            patch.object(extractor, "_get_version", new_callable=AsyncMock, return_value="9.2.1"),
            patch("asyncio.create_subprocess_exec", side_effect=mock_exec),
        ):
            result = await extractor.extract(None)

        assert result["compiler"] == "arm-none-eabi-gcc 9.2.1"
        rendered = json.dumps(result, sort_keys=True)
        assert "SECRET_SDK_ROOT_SHOULD_NOT_LEAK" not in rendered
        assert secret_compiler not in rendered

    async def test_extract_failure_log_uses_category_without_exception_text(
        self, extractor, caplog
    ):
        """macro 수집 실패 로그는 raw exception text를 노출하지 않는다."""

        async def mock_exec(*args, **kwargs):
            raise FileNotFoundError("SECRET_BUILD_METADATA_ERROR_SHOULD_NOT_LEAK")

        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await extractor.extract(None)

        assert result["compiler"] == "gcc"
        assert result["macros"] == {}
        assert result["targetInfo"] == {}
        assert "gcc macro extraction failed" in caplog.text
        assert "SECRET_BUILD_METADATA_ERROR_SHOULD_NOT_LEAK" not in caplog.text
        assert "gcc -E -dM failed:" not in caplog.text

    async def test_extract_failure_compiler_identity_redacts_windows_like_path(
        self, extractor
    ):
        """실패 metadata compiler 필드도 Windows-like 경로를 identity로 정규화한다."""
        secret_compiler = (
            r"C:\SECRET_SDK_ROOT_SHOULD_NOT_LEAK\sysroots\arm\usr\bin"
            r"\arm-none-eabi-gcc.exe"
        )

        async def mock_exec(*args, **kwargs):
            assert args[0] == secret_compiler
            raise FileNotFoundError("SECRET_BUILD_METADATA_ERROR_SHOULD_NOT_LEAK")

        with (
            patch.object(extractor, "_resolve_gcc", return_value=secret_compiler),
            patch("asyncio.create_subprocess_exec", side_effect=mock_exec),
        ):
            result = await extractor.extract(None)

        assert result["compiler"] == "arm-none-eabi-gcc.exe"
        rendered = json.dumps(result, sort_keys=True)
        assert "SECRET_SDK_ROOT_SHOULD_NOT_LEAK" not in rendered
        assert secret_compiler not in rendered

    async def test_extract_handles_timeout(self, extractor):
        """타임아웃 시 빈 macros/targetInfo 반환."""
        import asyncio

        async def mock_exec(*args, **kwargs):
            raise FileNotFoundError("gcc not found")

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await extractor.extract(None)

        assert result["compiler"] == "gcc"
        assert result["macros"] == {}
        assert result["targetInfo"] == {}
