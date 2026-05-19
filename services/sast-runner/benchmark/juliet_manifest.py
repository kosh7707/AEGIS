"""Juliet Test Suite 파일 파싱 — 파일명에서 CWE/variant 메타데이터 추출."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# 파일명 패턴: CWE{num}_{name}__{variant}_{flow}_{sink}_{id}.c
_FILENAME_RE = re.compile(
    r"^CWE(\d+)_.*?_(\d+)\.c$"
)


@dataclass
class JulietTestCase:
    """Juliet 테스트 케이스 하나."""
    file_path: Path
    cwe_num: int
    variant_id: str        # "01", "02", ...
    relative_path: str     # 디렉토리 내 상대 경로


@dataclass
class JulietCWESuite:
    """하나의 CWE에 속하는 테스트 케이스 모음."""
    cwe_num: int
    cwe_name: str          # "OS_Command_Injection"
    directory: Path
    test_cases: list[JulietTestCase] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.test_cases)


def discover_cwe_suites(
    juliet_root: Path,
    target_cwes: list[int] | None = None,
    variant_filter: str | None = None,
) -> list[JulietCWESuite]:
    """Juliet testcases/ 디렉토리에서 CWE별 테스트 파일을 수집.

    Args:
        juliet_root: Juliet C/ 디렉토리 경로 (testcases/, testcasesupport/ 포함)
        target_cwes: 대상 CWE 번호 목록. None이면 전부.
        variant_filter: "01"이면 _01.c 파일만. None이면 전부.
    """
    testcases_dir = juliet_root / "testcases"
    if not testcases_dir.is_dir():
        raise FileNotFoundError("Juliet testcases directory not found")

    suites: list[JulietCWESuite] = []

    for cwe_dir in sorted(testcases_dir.iterdir()):
        if not cwe_dir.is_dir():
            continue
        if not cwe_dir.name.startswith("CWE"):
            continue

        # CWE 번호 추출
        m = re.match(r"CWE(\d+)_(.*)", cwe_dir.name)
        if not m:
            continue

        cwe_num = int(m.group(1))
        cwe_name = m.group(2)

        if target_cwes and cwe_num not in target_cwes:
            continue

        suite = JulietCWESuite(
            cwe_num=cwe_num,
            cwe_name=cwe_name,
            directory=cwe_dir,
        )

        # C 소스 파일 수집 (하위 디렉토리 포함: s01/, s02/, ...)
        for c_file in sorted(cwe_dir.rglob("*.c")):
            fm = _FILENAME_RE.match(c_file.name)
            if not fm:
                continue

            file_cwe = int(fm.group(1))
            variant = fm.group(2)

            # variant 필터
            if variant_filter and variant != variant_filter:
                continue

            # Windows 전용 파일 스킵
            if "_w32_" in c_file.name or "_wchar_t_" in c_file.name:
                continue

            suite.test_cases.append(JulietTestCase(
                file_path=c_file,
                cwe_num=file_cwe,
                variant_id=variant,
                relative_path=str(c_file.relative_to(cwe_dir)),
            ))

        if suite.test_cases:
            suites.append(suite)

    return suites


def get_testcasesupport_path(juliet_root: Path) -> Path | None:
    """testcasesupport/ 경로 반환."""
    support = juliet_root / "testcasesupport"
    return support if support.is_dir() else None
