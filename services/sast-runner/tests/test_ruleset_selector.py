"""BuildProfile 기반 룰셋 선택 단위 테스트."""

from __future__ import annotations

import pytest

from app.scanner.ruleset_selector import (
    detect_language_family,
    resolve_header_language,
    resolve_rulesets,
    semgrep_include_extensions,
)
from app.schemas.request import BuildProfile


def _make_profile(**overrides) -> BuildProfile:
    """테스트용 BuildProfile 팩토리."""
    defaults = {
        "sdkId": "test-sdk",
        "compiler": "arm-none-eabi-gcc",
        "targetArch": "arm-cortex-m7",
        "languageStandard": "c99",
        "headerLanguage": "c",
    }
    defaults.update(overrides)
    return BuildProfile(**defaults)


class TestDetectLanguageFamily:

    def test_c_standards(self) -> None:
        for std in ["c89", "c90", "c99", "c11", "c17", "c23"]:
            p = _make_profile(languageStandard=std)
            assert detect_language_family(p) == "c", f"Failed for {std}"

    def test_gnu_c_standards(self) -> None:
        for std in ["gnu89", "gnu99", "gnu11", "gnu17", "gnu23"]:
            p = _make_profile(languageStandard=std)
            assert detect_language_family(p) == "c", f"Failed for {std}"

    def test_cpp_standards(self) -> None:
        for std in ["c++11", "c++14", "c++17", "c++20", "c++23"]:
            p = _make_profile(languageStandard=std)
            assert detect_language_family(p) == "cpp", f"Failed for {std}"

    def test_gnupp_standards(self) -> None:
        for std in ["gnu++11", "gnu++14", "gnu++17", "gnu++20"]:
            p = _make_profile(languageStandard=std)
            assert detect_language_family(p) == "cpp", f"Failed for {std}"

    def test_cpp_alias(self) -> None:
        """cpp17 형태도 인식."""
        p = _make_profile(languageStandard="cpp17")
        assert detect_language_family(p) == "cpp"

    def test_unknown_fallback(self) -> None:
        p = _make_profile(languageStandard="rust2024")
        assert detect_language_family(p) == "mixed"

    def test_case_insensitive(self) -> None:
        p = _make_profile(languageStandard="C++17")
        assert detect_language_family(p) == "cpp"


class TestResolveRulesets:

    def test_explicit_rulesets_override_everything(self) -> None:
        profile = _make_profile(languageStandard="c++17")
        result = resolve_rulesets(["p/custom"], profile, ["p/default"])
        assert result == ["p/custom"]

    def test_profile_based_c(self) -> None:
        profile = _make_profile(languageStandard="c99")
        result = resolve_rulesets(None, profile, ["p/default"])
        assert "p/c" in result
        assert "p/security-audit" in result

    def test_profile_based_cpp(self) -> None:
        profile = _make_profile(languageStandard="c++17")
        result = resolve_rulesets(None, profile, ["p/default"])
        assert "p/c" in result  # retained as a baseline C ruleset; C++ coverage is reported separately
        assert "p/security-audit" in result

    def test_no_profile_uses_defaults(self) -> None:
        result = resolve_rulesets(None, None, ["p/default-1", "p/default-2"])
        assert result == ["p/default-1", "p/default-2"]

    def test_empty_explicit_rulesets(self) -> None:
        """빈 리스트로 명시하면 빈 리스트 그대로."""
        result = resolve_rulesets([], _make_profile(), ["p/default"])
        assert result == []


class TestResolveHeaderLanguage:

    def test_no_profile_defaults_to_c(self) -> None:
        assert resolve_header_language(None) == "c"

    def test_explicit_c(self) -> None:
        p = _make_profile(headerLanguage="c")
        assert resolve_header_language(p) == "c"

    def test_explicit_cpp(self) -> None:
        p = _make_profile(headerLanguage="cpp")
        assert resolve_header_language(p) == "cpp"

    def test_auto_infers_from_c_standard(self) -> None:
        p = _make_profile(headerLanguage="auto", languageStandard="c11")
        assert resolve_header_language(p) == "c"

    def test_auto_infers_from_cpp_standard(self) -> None:
        p = _make_profile(headerLanguage="auto", languageStandard="c++17")
        assert resolve_header_language(p) == "cpp"


class TestSemgrepIncludeExtensions:

    def test_none_profile(self) -> None:
        """profile 없으면 None (전체 스캔)."""
        assert semgrep_include_extensions(None) is None

    def test_c_project(self) -> None:
        """C 프로젝트 → None (전체 스캔)."""
        p = _make_profile(languageStandard="c99")
        assert semgrep_include_extensions(p) is None

    def test_cpp_project(self) -> None:
        """C++ 프로젝트 → C/C++ 확장자를 모두 허용한다."""
        p = _make_profile(languageStandard="c++17")
        result = semgrep_include_extensions(p)
        assert result is not None
        assert ".c" in result
        assert ".h" in result
        assert ".cpp" in result
        assert ".cc" in result
        assert ".cxx" in result
        assert ".hpp" in result

    def test_mixed_project(self) -> None:
        """mixed 프로젝트 → C/C++ 확장자를 모두 허용한다."""
        p = _make_profile(languageStandard="rust2024")  # mixed fallback
        result = semgrep_include_extensions(p)
        assert result is not None
        assert ".c" in result
        assert ".cpp" in result
