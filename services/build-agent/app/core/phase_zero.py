"""Phase 0 — 결정론적 사전 분석. LLM 없이 빌드 시스템/프로젝트 구조를 탐지한다."""
from __future__ import annotations

import glob
import logging
import os
import shlex
import time
from dataclasses import dataclass, field

from app.agent_runtime.observability import agent_log

logger = logging.getLogger(__name__)

_EXCLUDE_DIRS = frozenset({
    "build", "build-wsl", "build-aegis", "CMakeFiles", ".git", "__pycache__",
    "node_modules", ".cache", ".venv", "venv",
    "test", "tests", "doc", "docs", "example", "examples", "unittest",
    "third_party", "vendor", "external", "deps",
})

_BUILD_FILE_PATTERNS = ["**/CMakeLists.txt", "**/Makefile", "**/*.sh", "**/*.cmake"]
_MAX_BUILD_FILES = 20
_MAX_TREE_DEPTH = 2
_MAX_TREE_ENTRIES = 80


@dataclass
class Phase0Result:
    """Phase 0 결정론적 사전 분석 결과."""
    build_system: str  # "cmake", "make", "autotools", "shell", "unknown"
    build_files: list[str] = field(default_factory=list)
    project_tree: str = ""
    has_existing_build_script: bool = False
    existing_script_path: str = ""
    detected_languages: list[str] = field(default_factory=list)
    duration_ms: int = 0


class Phase0Executor:
    """LLM 루프 전에 프로젝트를 결정론적으로 분석한다."""

    def __init__(
        self,
        project_path: str,
        target_path: str = "",
    ) -> None:
        self._project_path = project_path
        self._target_path = target_path
        self._search_root = (
            os.path.join(project_path, target_path)
            if target_path and os.path.isdir(os.path.join(project_path, target_path))
            else project_path
        )
        self._result: Phase0Result | None = None

    async def execute(self, request_id: str | None = None) -> Phase0Result:
        t0 = time.monotonic()

        build_system = self._detect_build_system()
        build_files = self._discover_build_files()
        project_tree = self._generate_tree()
        languages = self._detect_languages()
        has_script, script_path = self._find_existing_build_script()

        result = Phase0Result(
            build_system=build_system,
            build_files=build_files,
            project_tree=project_tree,
            has_existing_build_script=has_script,
            existing_script_path=script_path,
            detected_languages=languages,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

        self._result = result

        agent_log(
            logger, "Phase 0 완료",
            component="phase_zero", phase="phase0_done",
            buildSystem=build_system,
            buildFileCount=len(build_files),
            languages=languages,
            hasExistingScript=has_script,
            durationMs=result.duration_ms,
        )
        return result

    def _detect_build_system(self) -> str:
        """파일 존재 여부로 빌드 시스템 유형을 결정론적으로 탐지한다."""
        try:
            root_files = os.listdir(self._search_root)
        except OSError:
            return "unknown"

        if "CMakeLists.txt" in root_files:
            return "cmake"
        if "Makefile" in root_files or "GNUmakefile" in root_files or "makefile" in root_files:
            return "make"
        if "configure" in root_files or "configure.ac" in root_files or "configure.in" in root_files:
            return "autotools"

        # 셸 스크립트 빌드 (scripts/ 또는 루트)
        for f in root_files:
            if f.endswith(".sh") and "build" in f.lower():
                return "shell"
        scripts_dir = os.path.join(self._search_root, "scripts")
        if os.path.isdir(scripts_dir):
            for f in os.listdir(scripts_dir):
                if f.endswith(".sh") and "build" in f.lower():
                    return "shell"

        # 하위 1레벨 탐색
        for d in root_files:
            subdir = os.path.join(self._search_root, d)
            if os.path.isdir(subdir) and d not in _EXCLUDE_DIRS:
                try:
                    sub_files = os.listdir(subdir)
                except OSError:
                    continue
                if "CMakeLists.txt" in sub_files:
                    return "cmake"
                if "Makefile" in sub_files:
                    return "make"

        return "unknown"

    def _discover_build_files(self) -> list[str]:
        """빌드 관련 파일을 탐색한다. 기존 tasks.py 로직 추출."""
        found: list[str] = []
        for pat in _BUILD_FILE_PATTERNS:
            matches = glob.glob(os.path.join(self._search_root, pat), recursive=True)
            for m in matches:
                rel = os.path.relpath(m, self._project_path)
                parts = rel.split(os.sep)
                if len(parts) > 4:
                    continue
                if any(p in _EXCLUDE_DIRS for p in parts):
                    continue
                if rel not in found:
                    found.append(rel)
        return sorted(found)[:_MAX_BUILD_FILES]

    def _generate_tree(self) -> str:
        """컴팩트한 프로젝트 트리 (depth 2)."""
        lines: list[str] = []
        for root, dirs, files in os.walk(self._search_root):
            depth = root[len(self._search_root):].count(os.sep)
            if depth >= _MAX_TREE_DEPTH:
                dirs.clear()
                continue
            dirs[:] = sorted(d for d in dirs if d not in _EXCLUDE_DIRS and not d.startswith("."))
            indent = "  " * depth
            for d in dirs:
                lines.append(f"{indent}{d}/")
            for f in sorted(files):
                if not f.startswith("."):
                    lines.append(f"{indent}{f}")
            if len(lines) >= _MAX_TREE_ENTRIES:
                lines.append(f"... ({_MAX_TREE_ENTRIES}개 항목에서 잘림)")
                break
        return "\n".join(lines) if lines else "(empty)"

    def _detect_languages(self) -> list[str]:
        """파일 확장자로 프로그래밍 언어를 탐지한다."""
        ext_map = {".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".h": "c", ".hpp": "cpp"}
        found = set()
        for root, dirs, files in os.walk(self._search_root):
            depth = root[len(self._search_root):].count(os.sep)
            if depth >= 3:
                dirs.clear()
                continue
            dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in ext_map:
                    found.add(ext_map[ext])
        return sorted(found)

    def _find_existing_build_script(self) -> tuple[bool, str]:
        """기존 빌드 스크립트를 탐지한다."""
        candidates = [
            "scripts/cross_build.sh", "scripts/build.sh", "build.sh",
            "scripts/build_all.sh", "scripts/build/build_all.sh",
            "scripts/build/cross_build.sh",
            "scripts/compile.sh", "compile.sh", "Makefile",
        ]
        for c in candidates:
            full = os.path.join(self._search_root, c)
            if os.path.isfile(full):
                return True, c
        return False, ""

    def generate_initial_script(
        self,
        setup_script: str | None = None,
        sdk_environment: dict[str, str] | None = None,
        script_hint_path: str | None = None,
    ) -> str | None:
        """감지된 빌드 시스템에 맞는 초기 빌드 스크립트를 결정론적으로 생성한다.

        unknown인 경우 None (LLM이 자유 생성). shell + script hint가
        있으면 request-scoped wrapper를 생성한다.
        """
        build_system = self._result.build_system if self._result else "unknown"
        if build_system == "unknown":
            return None

        sdk_setup = ""
        if sdk_environment:
            for key in sorted(sdk_environment):
                if not key.replace("_", "").isalnum() or key[0].isdigit():
                    continue
                value = sdk_environment[key]
                sdk_setup += f"export {key}={shlex.quote(value)}\n"
        if setup_script:
            sdk_setup += f"source {shlex.quote(setup_script)}\n"

        if build_system == "shell":
            if not script_hint_path:
                return None
            script_hint = shlex.quote(script_hint_path)
            return (
                "#!/bin/bash\n"
                "set -eo pipefail\n"
                f"{sdk_setup}"
                'PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
                'cd "$PROJECT_ROOT"\n'
                f"bash {script_hint}\n"
            )

        templates = {
            "cmake": (
                "#!/bin/bash\n"
                "set -eo pipefail\n"
                f'{sdk_setup}'
                'PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
                'cd "$PROJECT_ROOT"\n'
                'mkdir -p build && cd build\n'
                'cmake .. -DCMAKE_BUILD_TYPE=Release\n'
                'make -j"$(nproc)"\n'
            ),
            "make": (
                "#!/bin/bash\n"
                "set -eo pipefail\n"
                f'{sdk_setup}'
                'PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
                'cd "$PROJECT_ROOT"\n'
                'make -j"$(nproc)"\n'
            ),
            "autotools": (
                "#!/bin/bash\n"
                "set -eo pipefail\n"
                f'{sdk_setup}'
                'PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
                'cd "$PROJECT_ROOT"\n'
                './configure\n'
                'make -j"$(nproc)"\n'
            ),
        }
        return templates.get(build_system)
