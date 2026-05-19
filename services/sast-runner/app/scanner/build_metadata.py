"""빌드 메타데이터 추출 — gcc -E -dM 기반."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from app.scanner.sdk_resolver import get_sdk_compiler
from app.schemas.request import BuildProfile

logger = logging.getLogger("aegis-sast-runner")

# 관심 있는 매크로 목록
_INTERESTING_MACROS = {
    "__ARM_ARCH", "__ARM_ARCH_ISA_ARM", "__ARM_ARCH_ISA_THUMB",
    "__ARM_ARCH_PROFILE", "__arm__", "__aarch64__",
    "__x86_64__", "__i386__",
    "__SIZEOF_POINTER__", "__SIZEOF_LONG__", "__SIZEOF_INT__",
    "__SIZEOF_LONG_LONG__", "__SIZEOF_LONG_DOUBLE__",
    "__BYTE_ORDER__", "__ORDER_LITTLE_ENDIAN__", "__ORDER_BIG_ENDIAN__",
    "__LP64__", "__ILP32__",
    "__STDC_VERSION__", "__cplusplus",
    "__GNUC__", "__GNUC_MINOR__", "__GNUC_PATCHLEVEL__",
    "__clang__", "__clang_major__",
    "__linux__", "__unix__", "_WIN32", "_WIN64",
}


class BuildMetadataExtractor:
    """gcc -E -dM으로 타겟 빌드 환경 매크로를 추출한다."""

    async def extract(
        self,
        profile: BuildProfile | None,
        timeout: int = 15,
    ) -> dict[str, Any]:
        """BuildProfile의 컴파일러로 타겟 매크로 환경을 추출.

        Returns:
            { "compiler": "...", "macros": {...}, "targetInfo": {...} }
        """
        gcc_bin = self._resolve_gcc(profile)
        lang_flag = self._lang_flag(profile)

        # gcc -E -dM -x {c|c++} /dev/null
        cmd = [gcc_bin, "-E", "-dM", "-x", lang_flag, "/dev/null"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except (asyncio.TimeoutError, FileNotFoundError):
            logger.warning("gcc macro extraction failed")
            return {"compiler": self._compiler_identity(gcc_bin), "macros": {}, "targetInfo": {}}

        raw = stdout.decode()
        macros = self._parse_macros(raw)

        # 컴파일러 버전
        compiler_version = await self._get_version(gcc_bin)

        return {
            "compiler": self._compiler_identity(gcc_bin, compiler_version),
            "macros": macros,
            "targetInfo": self._derive_target_info(macros),
        }

    def _compiler_identity(self, gcc_bin: str, version: str | None = None) -> str:
        """Public compiler evidence uses executable identity, never host-local paths."""
        raw = str(gcc_bin or "").strip()
        name = raw.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] if raw else "gcc"
        if not name:
            name = "gcc"
        return f"{name} {version}" if version else name

    def _parse_macros(self, raw: str) -> dict[str, str]:
        """#define 출력을 파싱. 관심 매크로만 반환."""
        result: dict[str, str] = {}

        for line in raw.splitlines():
            match = re.match(r"^#define\s+(\w+)\s+(.*)", line)
            if match:
                name, value = match.group(1), match.group(2).strip()
                if name in _INTERESTING_MACROS:
                    result[name] = value

        return result

    def _derive_target_info(self, macros: dict[str, str]) -> dict[str, Any]:
        """매크로에서 타겟 정보를 추론."""
        info: dict[str, Any] = {}

        # 아키텍처
        if "__aarch64__" in macros:
            info["arch"] = "aarch64"
        elif "__arm__" in macros:
            info["arch"] = "arm"
        elif "__x86_64__" in macros:
            info["arch"] = "x86_64"
        elif "__i386__" in macros:
            info["arch"] = "i386"

        # 포인터/long 크기
        ptr = macros.get("__SIZEOF_POINTER__")
        if ptr:
            info["pointerSize"] = int(ptr)
        lng = macros.get("__SIZEOF_LONG__")
        if lng:
            info["longSize"] = int(lng)

        # 엔디안
        order = macros.get("__BYTE_ORDER__")
        if order:
            if "LITTLE" in order:
                info["endianness"] = "little"
            elif "BIG" in order:
                info["endianness"] = "big"

        # 언어 표준
        cpp = macros.get("__cplusplus")
        if cpp:
            info["cppStandard"] = cpp
        stdc = macros.get("__STDC_VERSION__")
        if stdc:
            info["cStandard"] = stdc

        return info

    async def _get_version(self, gcc_bin: str) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                gcc_bin, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            match = re.search(r"(\d+\.\d+\.\d+)", stdout.decode())
            return match.group(1) if match else None
        except Exception:
            return None

    def _resolve_gcc(self, profile: BuildProfile | None) -> str:
        if profile:
            sdk_gcc = get_sdk_compiler(profile)
            if sdk_gcc:
                return sdk_gcc
        return "gcc"

    def _lang_flag(self, profile: BuildProfile | None) -> str:
        if profile and profile.language_standard:
            std = profile.language_standard.lower()
            if std.startswith("c++") or std.startswith("gnu++"):
                return "c++"
        return "c"
