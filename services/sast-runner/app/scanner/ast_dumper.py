"""코드 구조 dump 생성 — clang AST JSON + cppcheck XML dump."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from app.errors import ScanTimeoutError
from app.schemas.request import BuildProfile

logger = logging.getLogger("aegis-sast-runner")

# 동시 clang 프로세스 수 제한 — CPU 코어 수에 맞춰 조절 가능
_MAX_CONCURRENT_CLANG = 16


class AstDumper:
    """clang AST JSON dump를 생성한다."""

    async def dump_ast(
        self,
        scan_dir: Path,
        source_files: list[str],
        profile: BuildProfile | None,
        timeout: int = 60,
        skip_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """소스 파일들의 AST를 JSON으로 덤프.

        Returns:
            { "files": { "src/main.c": { ...ast... }, ... } }
        """
        c_cpp_files = [
            f for f in source_files
            if f.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"))
        ]

        if skip_paths:
            c_cpp_files = _filter_skip_paths(c_cpp_files, skip_paths)

        sem = asyncio.Semaphore(_MAX_CONCURRENT_CLANG)

        async def _process(src: str) -> tuple[str, dict | None]:
            full_path = scan_dir / src
            if not full_path.exists():
                return src, None
            async with sem:
                ast = await self._dump_single(full_path, scan_dir, profile, timeout)
            return src, ast

        pairs = await asyncio.gather(*[_process(src) for src in c_cpp_files])
        result = {src: ast for src, ast in pairs if ast is not None}
        return {"files": result}

    async def dump_functions(
        self,
        scan_dir: Path,
        source_files: list[str],
        profile: BuildProfile | None,
        timeout: int = 60,
        libraries: list[dict[str, Any]] | None = None,
        skip_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """소스 파일들에서 함수 목록 + 호출 관계를 추출.

        clang AST의 전체 덤프 대신 함수 선언/호출만 추출하여 경량화.
        libraries가 제공되면 함수에 origin 태깅 (서드파티 출처 식별).
        skip_paths가 제공되면 해당 경로 하위 파일은 clang 실행 없이 스킵.

        Returns:
            {
              "functions": [
                { "name": "postJson", "file": "src/http_client.cpp", "line": 8,
                  "calls": ["getenv", "popen", "fgets", "pclose"] },
                { "name": "curl_exec", "file": "third-party/libcurl/curl_exec.c", "line": 42,
                  "calls": ["curl_multi_perform"],
                  "origin": "modified-third-party",
                  "originalLib": "libcurl", "originalVersion": "7.68.0" }
              ]
            }
        """
        c_cpp_files = [
            f for f in source_files
            if f.endswith((".c", ".cpp", ".cc", ".cxx"))
        ]

        before_count = len(c_cpp_files)
        if skip_paths:
            c_cpp_files = _filter_skip_paths(c_cpp_files, skip_paths)
        skipped_count = before_count - len(c_cpp_files)
        if skipped_count > 0:
            logger.info(
                "Functions extraction: skipped %d vendored/third-party files",
                skipped_count,
                extra={"skippedFiles": skipped_count, "remainingFiles": len(c_cpp_files)},
            )

        sem = asyncio.Semaphore(_MAX_CONCURRENT_CLANG)

        async def _process(src: str) -> list[dict[str, Any]]:
            full_path = scan_dir / src
            if not full_path.exists():
                return []
            async with sem:
                return await self._extract_functions(full_path, scan_dir, profile, timeout)

        results = await asyncio.gather(*[_process(src) for src in c_cpp_files])
        functions: list[dict[str, Any]] = []
        for funcs in results:
            functions.extend(funcs)

        # origin 태깅: 라이브러리 경로와 함수 파일 경로를 교차 대조
        if libraries:
            self._tag_origin(functions, libraries)

        return {"functions": functions}

    def _tag_origin(
        self,
        functions: list[dict[str, Any]],
        libraries: list[dict[str, Any]],
    ) -> None:
        """함수에 서드파티 출처 메타데이터를 태깅.

        라이브러리 path와 함수 file 경로를 대조하여:
        - diff.matchRatio == 100% → origin: "third-party"
        - diff.matchRatio < 100% → origin: "modified-third-party"
        """
        for func in functions:
            file_path = func["file"]
            for lib in libraries:
                lib_path = lib.get("path", "")
                if not lib_path:
                    continue
                # 함수 파일이 라이브러리 경로 하위인지 확인
                if file_path.startswith(lib_path):
                    # 수정 여부 판별
                    diff = lib.get("diff")
                    match_ratio = diff.get("matchRatio", 100) if diff else 100
                    if match_ratio >= 100:
                        func["origin"] = "third-party"
                    else:
                        func["origin"] = "modified-third-party"
                    func["originalLib"] = lib["name"]
                    if lib.get("version"):
                        func["originalVersion"] = lib["version"]
                    break

    async def _dump_single(
        self,
        file_path: Path,
        scan_dir: Path,
        profile: BuildProfile | None,
        timeout: int,
    ) -> dict | None:
        """단일 파일의 clang AST JSON dump."""
        cmd = self._build_clang_cmd(file_path, profile, scan_dir)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )

            raw = stdout.decode()
            if not raw.strip():
                return None

            return json.loads(raw)

        except (asyncio.TimeoutError, json.JSONDecodeError, FileNotFoundError):
            logger.warning("AST dump failed")
            return None

    async def _extract_functions(
        self,
        file_path: Path,
        scan_dir: Path,
        profile: BuildProfile | None,
        timeout: int,
    ) -> list[dict[str, Any]]:
        """clang AST에서 사용자 코드 함수 + 호출 관계를 추출.

        clang AST의 loc.file은 변경될 때만 나타남.
        최상위 inner 노드만 순회하여 사용자 파일의 FunctionDecl을 수집.
        """
        ast = await self._dump_single(file_path, scan_dir, profile, timeout)
        if ast is None:
            return []

        functions: list[dict[str, Any]] = []
        rel_path = str(file_path.relative_to(scan_dir))

        source_path = str(file_path)
        # 파일 줄 수를 미리 계산 — 헤더 함수 필터링용
        try:
            source_lines = file_path.read_text(encoding="utf-8").count("\n") + 1
        except Exception:
            source_lines = 10000

        self._extract_user_functions(ast, rel_path, source_path, source_lines, functions)
        return functions

    def _extract_user_functions(
        self,
        ast: dict,
        rel_path: str,
        source_path: str,
        source_lines: int,
        out: list[dict[str, Any]],
    ) -> None:
        """AST 최상위에서 사용자 파일의 FunctionDecl만 수집.

        필터링 전략:
        1. loc.file이 있고 소스 파일과 다르면 → 헤더 함수, 스킵
        2. loc.file이 없으면 → line 번호로 판정 (소스 파일 줄 수 초과하면 헤더)
        3. isImplicit이면 스킵
        4. 함수 본문(CompoundStmt)이 없으면 → 선언만 있는 헤더 함수, 스킵
        """
        self._visit_nodes(ast.get("inner", []), rel_path, source_path, source_lines, out)

    def _visit_nodes(
        self,
        nodes: list,
        rel_path: str,
        source_path: str,
        source_lines: int,
        out: list[dict[str, Any]],
    ) -> None:
        """AST 노드 리스트를 순회하며 FunctionDecl을 수집. NamespaceDecl은 재귀."""
        for node in nodes:
            if not isinstance(node, dict):
                continue

            kind = node.get("kind", "")

            # NamespaceDecl → 재귀 (namespace gw { ... } 안의 함수를 잡기 위해)
            if kind == "NamespaceDecl":
                ns_name = node.get("name", "")
                # std, __gnu_cxx 등 표준 라이브러리 네임스페이스는 스킵
                if ns_name.startswith("__") or ns_name == "std":
                    continue
                self._visit_nodes(node.get("inner", []), rel_path, source_path, source_lines, out)
                continue

            if kind != "FunctionDecl":
                continue

            name = node.get("name", "")
            if not name or name.startswith("__") or name.startswith("operator"):
                continue
            if node.get("isImplicit"):
                continue

            loc = node.get("loc", {})
            loc_file = loc.get("file", loc.get("expansionLoc", {}).get("file", ""))
            line = loc.get("line", loc.get("expansionLoc", {}).get("line", 0))

            # 필터 1: loc.file이 있고 소스 파일과 다르면 스킵
            if loc_file and loc_file != source_path:
                continue

            # 필터 2: line이 소스 파일 줄 수를 초과하면 헤더 함수
            if line > source_lines:
                continue

            # 필터 3: line이 소스 파일 범위 안이지만 본문이 없으면 → extern 선언
            # clang AST에서 함수 정의는 inner에 CompoundStmt 또는 ParmVarDecl + CompoundStmt
            inner = node.get("inner", [])
            has_body = any(
                isinstance(c, dict) and c.get("kind") == "CompoundStmt"
                for c in inner
            )
            if not has_body:
                continue

            # 필터 4: line이 소스 파일 범위 안이라도 실제 소스가 아닌 인라인 확장일 수 있음
            # → range의 begin/end가 소스 파일 범위 내인지 확인
            range_info = node.get("range", {})
            begin_line = range_info.get("begin", {}).get("line", line)
            end_line = range_info.get("end", {}).get("line", line)
            if begin_line > source_lines or end_line > source_lines:
                continue

            if line <= 0:
                continue

            # 호출 관계 수집
            calls: list[str] = []
            self._collect_calls(node, calls)

            out.append({
                "name": name,
                "file": rel_path,
                "line": line,
                "calls": sorted(set(calls)),
            })

    def _collect_calls(self, node: dict, calls: list[str]) -> None:
        """노드 내부의 CallExpr에서 호출되는 함수 이름을 수집."""
        if node.get("kind") == "CallExpr":
            name = self._extract_callee_name(node)
            if name:
                calls.append(name)

        for child in node.get("inner", []):
            if isinstance(child, dict):
                self._collect_calls(child, calls)

    def _extract_callee_name(self, call_expr: dict) -> str | None:
        """CallExpr에서 callee 함수 이름을 추출.

        clang AST 구조:
          CallExpr
            ├── ImplicitCastExpr
            │   └── DeclRefExpr { referencedDecl: { name: "popen" } }
            ├── MemberExpr { name: "c_str", referencedMemberDecl: ... }
            └── (arguments)
        """
        for child in call_expr.get("inner", []):
            if not isinstance(child, dict):
                continue

            # 직접 DeclRefExpr (함수 포인터 등)
            if child.get("kind") == "DeclRefExpr":
                name = child.get("referencedDecl", {}).get("name")
                if name:
                    return name

            # ImplicitCastExpr → DeclRefExpr (일반 함수 호출)
            if child.get("kind") == "ImplicitCastExpr":
                for gc in child.get("inner", []):
                    if isinstance(gc, dict) and gc.get("kind") == "DeclRefExpr":
                        name = gc.get("referencedDecl", {}).get("name")
                        if name:
                            return name

            # MemberExpr (멤버 함수 호출)
            if child.get("kind") == "MemberExpr":
                name = child.get("name")
                if name:
                    return name

        return None

    def _build_clang_cmd(
        self,
        file_path: Path,
        profile: BuildProfile | None,
        scan_dir: Path,
    ) -> list[str]:
        # clang 또는 clang-18 등 버전 접미사 대응
        clang_bin = self._find_clang()
        cmd = [
            clang_bin,
            "-Xclang", "-ast-dump=json",
            "-fsyntax-only",
            "-ferror-limit=0",   # 에러 무제한 허용 — 파싱 가능한 부분만 AST 생성
            "-w",                # 경고 숨김
        ]

        if profile:
            if profile.language_standard:
                cmd.append(f"-std={profile.language_standard.lower()}")
            if profile.include_paths:
                for inc in profile.include_paths:
                    inc_path = Path(inc)
                    if not inc_path.is_absolute():
                        inc_path = scan_dir / inc
                    cmd.extend(["-I", str(inc_path)])
            if profile.defines:
                for key, val in profile.defines.items():
                    cmd.append(f"-D{key}={val}" if val else f"-D{key}")

        cmd.append(str(file_path))
        return cmd

    def _find_clang(self) -> str:
        """clang 바이너리를 찾는다. clang → clang-18 → clang-17 순."""
        import shutil as _sh
        for name in ("clang", "clang-18", "clang-17", "clang-16"):
            if _sh.which(name):
                return name
        return "clang"  # 없으면 에러가 나겠지만, 기본값


def _filter_skip_paths(files: list[str], skip_paths: list[str]) -> list[str]:
    """skip_paths 하위의 파일을 제거한다.

    skip_paths의 각 항목은 상대 경로 prefix (예: "libraries/civetweb/").
    trailing slash 유무 모두 처리.
    """
    normalized = []
    for sp in skip_paths:
        p = sp.rstrip("/") + "/"
        normalized.append(p)

    return [
        f for f in files
        if not any(f.startswith(prefix) for prefix in normalized)
    ]
