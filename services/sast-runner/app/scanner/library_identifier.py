"""라이브러리 식별 — 프로젝트 내 vendored 라이브러리의 이름/버전을 추출."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from app.scanner.repository_url import repository_name_from_url

logger = logging.getLogger("aegis-sast-runner")

# 버전 추출 패턴들
_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # CMakeLists.txt: project(name VERSION x.y.z)
    ("CMakeLists.txt", "cmake_project", re.compile(
        r'project\s*\(\s*(\w+)\s+VERSION\s+([\d.]+)', re.IGNORECASE
    )),
    # CMakeLists.txt: set(XXX_VERSION "x.y.z")
    ("CMakeLists.txt", "cmake_set", re.compile(
        r'set\s*\(\s*(\w*VERSION\w*)\s+"([\d.]+)"', re.IGNORECASE
    )),
    # CMakeLists.txt: set(LIB_MAJOR/MINOR/PATCH)
    ("CMakeLists.txt", "cmake_split", None),  # 특수 처리
    # configure.ac: AC_INIT([name], [version])
    ("configure.ac", "ac_init", re.compile(
        r'AC_INIT\s*\(\s*\[([^\]]+)\]\s*,\s*\[([^\]]+)\]'
    )),
    # package.json
    ("package.json", "npm", re.compile(
        r'"name"\s*:\s*"([^"]+)".*?"version"\s*:\s*"([^"]+)"', re.DOTALL
    )),
    # version.h / version header
    ("*.h", "version_define", re.compile(
        r'#define\s+(\w*VERSION\w*)\s+"([\d.]+)"'
    )),
]

# 알려진 라이브러리 → git URL 매핑
_KNOWN_REPOS: dict[str, str] = {
    "civetweb": "https://github.com/civetweb/civetweb.git",
    "rapidjson": "https://github.com/Tencent/rapidjson.git",
    "tinydtls": "https://github.com/eclipse/tinydtls.git",
    "wakaama": "https://github.com/eclipse/wakaama.git",
    "libcoap": "https://github.com/obgm/libcoap.git",
    "mosquitto": "https://github.com/eclipse/mosquitto.git",
    "freertos": "https://github.com/FreeRTOS/FreeRTOS-Kernel.git",
    "zephyr": "https://github.com/zephyrproject-rtos/zephyr.git",
    "openssl": "https://github.com/openssl/openssl.git",
    "mbedtls": "https://github.com/Mbed-TLS/mbedtls.git",
}


class LibraryIdentifier:
    """프로젝트 내 vendored 라이브러리를 식별한다."""

    def identify(self, project_path: Path) -> list[dict[str, Any]]:
        """프로젝트 디렉토리에서 vendored 라이브러리를 찾고 이름/버전을 추출.

        Returns:
            [{ "name": "civetweb", "version": "1.16.0", "path": "libraries/civetweb",
               "source": "CMakeLists.txt", "repoUrl": "https://..." }, ...]
        """
        libraries: list[dict[str, Any]] = []

        # libraries/, lib/, third_party/, vendor/, deps/ 등 디렉토리 탐색
        lib_dirs = self._find_library_dirs(project_path)

        for lib_dir in lib_dirs:
            info = self._identify_single(lib_dir, project_path)
            if info:
                libraries.append(info)

        logger.info("Identified %d libraries", len(libraries))
        return libraries

    def _find_library_dirs(self, project_path: Path) -> list[Path]:
        """라이브러리가 있을 법한 디렉토리를 재귀적으로 찾는다.

        - libraries/, lib/, third_party/ 등의 하위 디렉토리를 탐색
        - 서브 라이브러리도 탐지 (wakaama/transport/tinydtls 등)
        """
        candidates: list[Path] = []
        seen: set[str] = set()  # 같은 라이브러리 중복 방지
        lib_dir_names = {"libraries", "lib", "libs", "third_party", "vendor",
                         "deps", "external", "contrib", "ext", "transport"}
        skip_dirs = {"node_modules", ".git", "build", "dist", "__pycache__",
                     "test", "tests", "doc", "docs", "example", "examples"}

        def scan(directory: Path, depth: int = 0) -> None:
            if depth > 4:
                return
            try:
                for child in directory.iterdir():
                    if not child.is_dir() or child.name.startswith("."):
                        continue
                    if child.name.lower() in skip_dirs:
                        continue
                    if child.name.lower() in lib_dir_names:
                        for sub in child.iterdir():
                            if sub.is_dir() and not sub.name.startswith("."):
                                # 중복 방지 (이름 기준)
                                if sub.name.lower() not in seen:
                                    candidates.append(sub)
                                    seen.add(sub.name.lower())
                                # 서브 라이브러리 탐색 (wakaama/transport/tinydtls 등)
                                scan(sub, depth + 1)
                    else:
                        scan(child, depth + 1)
            except PermissionError:
                logger.warning("Permission denied scanning directory")

        scan(project_path)
        return candidates

    def _identify_single(
        self, lib_dir: Path, project_root: Path,
    ) -> dict[str, Any] | None:
        """단일 라이브러리 디렉토리에서 이름/버전을 추출."""
        rel_path = str(lib_dir.relative_to(project_root))

        # 1. .git 디렉토리 — 최우선 (정확한 커밋 해시 + 리모트 URL)
        git_dir = lib_dir / ".git"
        git_info: dict[str, Any] | None = None
        if git_dir.exists():
            git_info = self._parse_git_info(lib_dir)

        # 2. CMakeLists.txt — 버전 정보 보강
        cmake = lib_dir / "CMakeLists.txt"
        if cmake.exists():
            info = self._parse_cmake(cmake)
            if info:
                if git_info:
                    # git 정보에 CMake 버전을 병합
                    git_info["version"] = git_info.get("version") or info["version"]
                    git_info["path"] = rel_path
                    git_info["repoUrl"] = git_info.get("repoUrl") or git_info.get("remoteUrl") or _KNOWN_REPOS.get(git_info["name"].lower())
                    return git_info
                info["path"] = rel_path
                info["repoUrl"] = _KNOWN_REPOS.get(info["name"].lower())
                return info

        # 3. configure.ac (직접 또는 하위 디렉토리)
        configure = lib_dir / "configure.ac"
        if not configure.exists():
            # 하위에서 탐색 (third_party/tinydtls/configure.ac 등)
            for candidate in lib_dir.rglob("configure.ac"):
                configure = candidate
                break
        if configure.exists():
            info = self._parse_configure_ac(configure)
            if info:
                if git_info:
                    git_info["version"] = git_info.get("version") or info["version"]
                    git_info["path"] = rel_path
                    git_info["repoUrl"] = git_info.get("repoUrl") or git_info.get("remoteUrl") or _KNOWN_REPOS.get(git_info["name"].lower())
                    return git_info
                info["path"] = rel_path
                info["repoUrl"] = _KNOWN_REPOS.get(info["name"].lower())
                return info

        # 4. package.json
        pkg = lib_dir / "package.json"
        if pkg.exists():
            info = self._parse_package_json(pkg)
            if info:
                if git_info:
                    git_info["version"] = git_info.get("version") or info["version"]
                    git_info["path"] = rel_path
                    git_info["repoUrl"] = git_info.get("repoUrl") or git_info.get("remoteUrl") or _KNOWN_REPOS.get(git_info["name"].lower())
                    return git_info
                info["path"] = rel_path
                info["repoUrl"] = _KNOWN_REPOS.get(info["name"].lower())
                return info

        # 5. git 정보만 있는 경우 (CMake/autoconf 없음)
        if git_info:
            git_info["path"] = rel_path
            git_info["repoUrl"] = git_info.get("repoUrl") or git_info.get("remoteUrl") or _KNOWN_REPOS.get(git_info["name"].lower())
            return git_info

        # 5. version.h 등 버전 헤더 파일
        for vfile in ("version.h", "config.h", f"{lib_dir.name}_version.h"):
            vh = lib_dir / vfile
            if not vh.exists():
                # include/ 하위도 탐색
                vh = lib_dir / "include" / vfile
            if vh.exists():
                info = self._parse_version_header(vh, lib_dir.name)
                if info:
                    info["path"] = rel_path
                    info["repoUrl"] = _KNOWN_REPOS.get(info["name"].lower())
                    return info

        # 5. README에서 버전 추출
        for readme in ("README.md", "README", "README.txt", "README.rst"):
            rp = lib_dir / readme
            if rp.exists():
                info = self._parse_readme(rp, lib_dir.name)
                if info:
                    info["path"] = rel_path
                    info["repoUrl"] = _KNOWN_REPOS.get(info["name"].lower())
                    return info

        # 6. 디렉토리 이름으로 추측
        name = lib_dir.name.lower()
        repo_url = _KNOWN_REPOS.get(name)
        if repo_url:
            return {
                "name": name,
                "version": None,
                "path": rel_path,
                "source": "directory_name",
                "repoUrl": repo_url,
            }

        return None

    def _parse_git_info(self, lib_dir: Path) -> dict[str, Any] | None:
        """.git 디렉토리에서 커밋 해시, 브랜치, 리모트 URL을 추출."""
        import subprocess
        try:
            commit = subprocess.run(
                ["git", "-C", str(lib_dir), "log", "-1", "--format=%H"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()

            branch = subprocess.run(
                ["git", "-C", str(lib_dir), "branch", "--show-current"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()

            remote_url = subprocess.run(
                ["git", "-C", str(lib_dir), "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()

            tag = subprocess.run(
                ["git", "-C", str(lib_dir), "describe", "--tags", "--exact-match"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()

            # 정확한 태그가 없으면 가장 가까운 태그에서 버전 추론
            nearest_tag = ""
            if not tag:
                nearest = subprocess.run(
                    ["git", "-C", str(lib_dir), "describe", "--tags", "--abbrev=0"],
                    capture_output=True, text=True, timeout=5,
                ).stdout.strip()
                if nearest:
                    nearest_tag = nearest
                    # v2.0.22 → 2.0.22
                    tag = nearest.lstrip("vV")

            if not commit:
                return None

            # 라이브러리 이름은 디렉토리명 또는 리모트 URL에서 추출
            name = lib_dir.name
            if remote_url:
                # https://github.com/eclipse/mosquitto.git → mosquitto
                name = repository_name_from_url(remote_url, fallback=lib_dir.name)

            return {
                "name": name,
                "version": tag if tag else None,
                "nearestTag": nearest_tag or None,
                "commit": commit,
                "branch": branch or None,
                "remoteUrl": remote_url or None,
                "source": "git",
            }
        except Exception:
            return None

    def _parse_version_header(self, path: Path, fallback_name: str) -> dict[str, Any] | None:
        """version.h 등에서 #define VERSION 추출."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:5000]
        except Exception:
            return None

        match = re.search(r'#define\s+\w*VERSION\w*\s+"([\d.]+)"', content)
        if match:
            return {
                "name": fallback_name,
                "version": match.group(1),
                "source": f"{path.name}:#define",
            }
        return None

    def _parse_readme(self, path: Path, fallback_name: str) -> dict[str, Any] | None:
        """README에서 프로젝트 이름/버전 추출."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:3000]
        except Exception:
            return None

        # "# ProjectName v1.2.3" 또는 "ProjectName 1.2.3"
        match = re.search(r'#\s*(\w+)\s+v?([\d]+\.[\d]+(?:\.[\d]+)?)', content)
        if match:
            return {
                "name": match.group(1),
                "version": match.group(2),
                "source": f"{path.name}:heading",
            }
        return None

    def _parse_cmake(self, cmake_path: Path) -> dict[str, Any] | None:
        """CMakeLists.txt에서 프로젝트 이름/버전 추출."""
        try:
            content = cmake_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        # project(name VERSION x.y.z)
        match = re.search(
            r'project\s*\(\s*(\w+)\s+VERSION\s+([\d.]+)', content, re.IGNORECASE,
        )
        if match:
            return {
                "name": match.group(1),
                "version": match.group(2),
                "source": "CMakeLists.txt:project()",
            }

        # set(LIB_MAJOR_VERSION "x") 패턴
        major = re.search(r'set\s*\(\s*LIB_MAJOR_VERSION\s+"(\d+)"', content)
        minor = re.search(r'set\s*\(\s*LIB_MINOR_VERSION\s+"(\d+)"', content)
        patch = re.search(r'set\s*\(\s*LIB_PATCH_VERSION\s+"(\d+)"', content)
        if major and minor and patch:
            # 프로젝트 이름은 디렉토리명에서
            name = cmake_path.parent.name
            return {
                "name": name,
                "version": f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}",
                "source": "CMakeLists.txt:set(LIB_*_VERSION)",
            }

        return None

    def _parse_configure_ac(self, path: Path) -> dict[str, Any] | None:
        """configure.ac에서 AC_INIT 추출."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        match = re.search(r'AC_INIT\s*\(\s*\[([^\]]+)\]\s*,\s*\[([^\]]+)\]', content)
        if match:
            return {
                "name": match.group(1),
                "version": match.group(2),
                "source": "configure.ac:AC_INIT()",
            }
        return None

    def _parse_package_json(self, path: Path) -> dict[str, Any] | None:
        """package.json에서 name/version 추출."""
        import json
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {
                "name": data.get("name", path.parent.name),
                "version": data.get("version"),
                "source": "package.json",
            }
        except Exception:
            return None
