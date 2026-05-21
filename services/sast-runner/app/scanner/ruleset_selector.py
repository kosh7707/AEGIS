"""BuildProfile 기반 Semgrep 룰셋 자동 선택."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.scanner.semgrep_coverage import C_CPP_INCLUDE_EXTENSIONS

if TYPE_CHECKING:
    from app.schemas.request import BuildProfile

logger = logging.getLogger("aegis-sast-runner")

# 언어 표준 → 언어 계열 매핑
_CPP_STANDARDS = frozenset({
    "c++98", "c++03", "c++11", "c++14", "c++17", "c++20", "c++23", "c++26",
    "gnu++98", "gnu++03", "gnu++11", "gnu++14", "gnu++17", "gnu++20", "gnu++23", "gnu++26",
    "cpp98", "cpp03", "cpp11", "cpp14", "cpp17", "cpp20", "cpp23", "cpp26",
})

_C_STANDARDS = frozenset({
    "c89", "c90", "c99", "c11", "c17", "c18", "c23",
    "gnu89", "gnu90", "gnu99", "gnu11", "gnu17", "gnu18", "gnu23",
})

# Semgrep 룰셋 매핑
C_RULESETS = ["p/c"]
CPP_RULESETS = ["p/c"]  # baseline C registry pack; effective C++ coverage is reported separately.
SECURITY_RULESETS = ["p/security-audit"]


def detect_language_family(profile: BuildProfile) -> str:
    """BuildProfile에서 주 언어 계열을 판별한다.

    Returns:
        "c", "cpp", 또는 "mixed"
    """
    if not profile.language_standard:
        return "mixed"
    std = profile.language_standard.lower().strip()

    if std in _CPP_STANDARDS:
        return "cpp"
    if std in _C_STANDARDS:
        return "c"

    # 접두사 기반 폴백
    if std.startswith("c++") or std.startswith("gnu++") or std.startswith("cpp"):
        return "cpp"
    if std.startswith("c") or std.startswith("gnu"):
        return "c"

    return "mixed"


def resolve_rulesets(
    explicit_rulesets: list[str] | None,
    profile: BuildProfile | None,
    defaults: list[str],
) -> list[str]:
    """최종 사용할 Semgrep 룰셋을 결정한다.

    우선순위:
    1. 요청에서 명시적으로 지정된 rulesets → 그대로 사용
    2. BuildProfile이 있으면 → 언어 계열에 맞는 룰셋 자동 선택
    3. 둘 다 없으면 → settings.default_rulesets
    """
    if explicit_rulesets is not None:
        return explicit_rulesets

    if profile is not None:
        lang = detect_language_family(profile)
        rulesets = _rulesets_for_language(lang)
        logger.info(
            "Auto-selected rulesets from BuildProfile",
            extra={
                "languageStandard": profile.language_standard,
                "detectedLanguage": lang,
                "rulesets": rulesets,
            },
        )
        return rulesets

    return defaults


def resolve_header_language(profile: BuildProfile | None) -> str:
    """`.h` 파일의 처리 언어를 결정한다.

    Returns:
        "c" 또는 "cpp". "auto"이면 languageStandard에서 추론.
    """
    if profile is None:
        return "c"  # 기본값: C

    if profile.header_language != "auto":
        return profile.header_language

    # auto → languageStandard에서 추론
    lang = detect_language_family(profile)
    return "cpp" if lang == "cpp" else "c"


def semgrep_include_extensions(profile: BuildProfile | None) -> list[str] | None:
    """Semgrep이 스캔할 파일 확장자 필터를 결정한다.

    Returns:
        None: 전체 스캔 (C 프로젝트 또는 profile 없음)
        C/C++ extension allowlist: C++ 또는 mixed 프로젝트에서 .cpp를 배제하지 않음.
    """
    if profile is None:
        return None
    lang = detect_language_family(profile)
    if lang == "c":
        return None  # C 프로젝트 → 전체 스캔
    # cpp 또는 mixed → C/C++ 파일을 모두 포함한다. 실제 유효 커버리지는 별도 품질 메타데이터로 노출한다.
    return list(C_CPP_INCLUDE_EXTENSIONS)


def _rulesets_for_language(lang: str) -> list[str]:
    """언어 계열에 맞는 룰셋 조합."""
    if lang == "cpp":
        return CPP_RULESETS + SECURITY_RULESETS
    elif lang == "c":
        return C_RULESETS + SECURITY_RULESETS
    else:
        # mixed: 양쪽 다
        return C_RULESETS + SECURITY_RULESETS
