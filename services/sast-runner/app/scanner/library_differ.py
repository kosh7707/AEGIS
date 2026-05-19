"""라이브러리 upstream diff — vendored 라이브러리와 원본을 비교."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import shutil
import tempfile
import time as _time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.scanner.library_hasher import compare_hashes, hash_source_files
from app.scanner.repository_url import sanitize_repository_url_for_evidence

logger = logging.getLogger("aegis-sast-runner")


@dataclass
class DiffResult:
    """라이브러리 diff 결과 — 성공/에러 모두 동일한 shape."""

    matched_version: str | None = None
    repo_url: str = ""
    match_ratio: float | None = None
    identical_files: int = 0
    modified_files: int = 0
    added_files: int = 0
    deleted_files: int = 0
    modifications: list[dict[str, Any]] = field(default_factory=list)
    added_files_list: list[str] = field(default_factory=list)
    searched_tags: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """API 응답 shape으로 직렬화."""
        d: dict[str, Any] = {
            "matchedVersion": self.matched_version,
            "repoUrl": sanitize_repository_url_for_evidence(self.repo_url),
            "matchRatio": self.match_ratio,
            "identicalFiles": self.identical_files,
            "modifiedFiles": self.modified_files,
            "addedFiles": self.added_files,
            "deletedFiles": self.deleted_files,
            "modifications": self.modifications,
            "error": self.error,
        }
        if self.added_files_list:
            d["addedFilesList"] = self.added_files_list
        if self.searched_tags is not None:
            d["searchedTags"] = self.searched_tags
        return d


class CloneCache:
    """TTL 기반 git clone 캐시."""

    def __init__(
        self, base_dir: str | None = None, ttl_seconds: int = 3600,
    ) -> None:
        self._base = Path(base_dir or "/tmp/aegis-lib-cache")
        self._ttl = ttl_seconds
        self._lock = asyncio.Lock()

    def _key(self, repo_url: str) -> str:
        return hashlib.sha256(repo_url.encode()).hexdigest()[:16]

    def _cache_path(self, repo_url: str) -> Path:
        return self._base / self._key(repo_url)

    async def get_or_clone(self, repo_url: str, timeout: int) -> Path | None:
        """캐시 HIT → fetch, MISS → full clone. 실패 시 None."""
        async with self._lock:
            cache_dir = self._cache_path(repo_url)

            if cache_dir.is_dir() and (cache_dir / ".git").is_dir():
                age = _time.time() - cache_dir.stat().st_mtime
                if age < self._ttl:
                    fetch_ok = await self._git_fetch(cache_dir, timeout)
                    if fetch_ok:
                        logger.debug("Clone cache HIT (age=%.0fs)", age)
                        return cache_dir
                # stale or fetch failed
                shutil.rmtree(cache_dir, ignore_errors=True)

            cache_dir.mkdir(parents=True, exist_ok=True)
            ok = await self._git_clone(repo_url, cache_dir, timeout)
            if ok:
                logger.debug("Clone cache MISS — cloned fresh")
                return cache_dir

            shutil.rmtree(cache_dir, ignore_errors=True)
            return None

    async def checkout(self, cache_dir: Path, ref: str) -> bool:
        """캐시된 clone에서 특정 ref로 checkout."""
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(cache_dir), "checkout", ref,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def _git_fetch(self, repo_dir: Path, timeout: int) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(repo_dir), "fetch", "--all", "--tags",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode == 0
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False

    async def _git_clone(self, url: str, dest: Path, timeout: int) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", url, str(dest),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode == 0
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False


class LibraryDiffer:
    """vendored 라이브러리를 upstream과 비교하여 수정분을 추출한다."""

    def __init__(self, cache: CloneCache | None = None) -> None:
        self._cache = cache

    async def diff(
        self,
        lib_path: Path,
        repo_url: str,
        version: str | None,
        commit: str | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """라이브러리 디렉토리와 upstream을 비교.

        Returns:
            {
                "matchedVersion": "v1.16.0",
                "totalFiles": 150,
                "modifiedFiles": 3,
                "addedFiles": 1,
                "deletedFiles": 0,
                "diffStats": { "insertions": 45, "deletions": 12 },
                "modifications": [
                    { "file": "src/civetweb.c", "insertions": 30, "deletions": 8 }
                ]
            }
        """
        clone_dir = Path(tempfile.mkdtemp(prefix="lib-diff-"))
        try:
            # 1. upstream clone — 커밋 해시가 있으면 정확한 커밋으로
            if commit:
                tag = await self._clone_at_commit(
                    repo_url, commit, clone_dir, timeout,
                )
            else:
                tag = await self._clone_and_checkout(
                    repo_url, version, clone_dir, timeout,
                )
            if tag is None:
                return DiffResult(error="Failed to clone upstream", repo_url=repo_url).to_dict()

            # 2. 해시 기반 비교 (패키징 차이에 면역)
            local_hashes = hash_source_files(lib_path)
            upstream_hashes = hash_source_files(clone_dir)
            hash_result = compare_hashes(local_hashes, upstream_hashes)

            # 3. 수정된 파일만 줄 단위 diff (상세 정보)
            modifications: list[dict[str, Any]] = []
            for mod_file in hash_result["modified"][:50]:
                local_file = lib_path / mod_file
                upstream_file = clone_dir / mod_file
                if local_file.exists() and upstream_file.exists():
                    ins, dels = await self._count_diff_lines(upstream_file, local_file)
                    modifications.append({
                        "file": mod_file,
                        "insertions": ins,
                        "deletions": dels,
                    })

            return DiffResult(
                matched_version=tag,
                repo_url=repo_url,
                match_ratio=hash_result["matchRatio"],
                identical_files=hash_result["identicalCount"],
                modified_files=hash_result["modifiedCount"],
                added_files=hash_result["addedCount"],
                deleted_files=hash_result["deletedCount"],
                modifications=modifications,
                added_files_list=hash_result["added"][:20],
            ).to_dict()

        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)

    async def find_closest_version(
        self,
        lib_path: Path,
        repo_url: str,
        timeout: int = 120,
    ) -> dict[str, Any]:
        """version을 모를 때, 모든 태그에 대해 diff를 비교하여 최소 diff 버전을 찾는다.

        비용이 크므로, version이 None일 때만 사용.
        """
        clone_dir = Path(tempfile.mkdtemp(prefix="lib-find-"))
        try:
            # 1. clone (전체)
            ok = await self._git_clone(repo_url, clone_dir, timeout)
            if not ok:
                return DiffResult(error="Failed to clone", repo_url=repo_url).to_dict()

            # 2. 태그 목록
            tags = await self._get_tags(clone_dir)
            if not tags:
                return DiffResult(error="No tags found", repo_url=repo_url).to_dict()

            # 3. 각 태그에 대해 diff 크기 비교 (최대 20개)
            candidates = tags[-20:]  # 최근 20개 태그
            best_tag = None
            best_diff_size = float("inf")

            for tag in candidates:
                await self._git_checkout(clone_dir, tag)
                diff_size = await self._quick_diff_size(lib_path, clone_dir)
                if diff_size < best_diff_size:
                    best_diff_size = diff_size
                    best_tag = tag
                    if diff_size == 0:
                        break  # 완벽 매치 — 나머지 태그 검사 불필요

            if best_tag:
                await self._git_checkout(clone_dir, best_tag)
                result = await self._compute_diff(lib_path, clone_dir, timeout)
                result["matchedVersion"] = best_tag
                result["repoUrl"] = sanitize_repository_url_for_evidence(repo_url)
                result["searchedTags"] = len(candidates)
                return result

            return DiffResult(error="No matching version found", repo_url=repo_url).to_dict()

        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)

    async def _clone_at_commit(
        self, repo_url: str, commit: str, dest: Path, timeout: int,
    ) -> str | None:
        """전체 clone 후 특정 커밋으로 checkout."""
        ok = await self._git_clone(repo_url, dest, timeout, shallow=False)
        if not ok:
            return None
        checkout_ok = await self._git_checkout(dest, commit)
        return commit if checkout_ok else None

    async def _clone_and_checkout(
        self, repo_url: str, version: str | None, dest: Path, timeout: int,
    ) -> str | None:
        """shallow clone + 버전 태그 checkout."""
        # version이 있으면 해당 태그로 clone
        if version:
            # 태그 이름 후보: v1.16.0, 1.16.0, release-1.16.0 등
            # 태그 후보: v1.16.0, v1.16, 1.16.0, release-1.16.0 등
            parts = version.split(".")
            short_version = ".".join(parts[:2]) if len(parts) >= 3 else version
            tag_candidates = [
                f"v{version}", version,
                f"v{short_version}", short_version,
                f"release-{version}", f"V{version}",
            ]
            # 중복 제거
            tag_candidates = list(dict.fromkeys(tag_candidates))

            for tag in tag_candidates:
                ok = await self._git_clone_tag(repo_url, tag, dest, timeout)
                if ok:
                    return tag
                # 실패하면 dest 비우고 재시도
                for child in dest.iterdir():
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink(missing_ok=True)

        # version 없거나 태그 못 찾으면 기본 브랜치
        ok = await self._git_clone(repo_url, dest, timeout, shallow=True)
        return "HEAD" if ok else None

    async def _git_clone_tag(
        self, url: str, tag: str, dest: Path, timeout: int,
    ) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth=1", "--branch", tag, url, str(dest),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode == 0
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False

    async def _git_clone(
        self, url: str, dest: Path, timeout: int, shallow: bool = False,
    ) -> bool:
        cmd = ["git", "clone"]
        if shallow:
            cmd.extend(["--depth=1"])
        cmd.extend([url, str(dest)])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode == 0
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False

    async def _get_tags(self, repo_dir: Path) -> list[str]:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(repo_dir), "tag", "--sort=version:refname",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return [t.strip() for t in stdout.decode().splitlines() if t.strip()]

    async def _git_checkout(self, repo_dir: Path, tag: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(repo_dir), "checkout", tag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def _quick_diff_size(self, local: Path, upstream: Path) -> int:
        """빠른 diff 크기 비교 (줄 수)."""
        proc = await asyncio.create_subprocess_exec(
            "diff", "-rq", "--exclude=.git", "--exclude=.svn",
            str(local), str(upstream),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return len(stdout.decode().splitlines())

    async def _compute_diff(
        self, local: Path, upstream: Path, timeout: int = 60,
    ) -> dict[str, Any]:
        """상세 diff 계산."""
        proc = await asyncio.create_subprocess_exec(
            "diff", "-ru", "--brief",
            "--exclude=.git", "--exclude=.svn", "--exclude=__pycache__",
            str(upstream), str(local),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"error": "diff timed out"}

        brief = stdout.decode()
        modified_files: list[str] = []
        added_files: list[str] = []
        local_root = local.resolve()

        # 소스 코드 확장자만 관심
        source_exts = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
        # 테스트/예제/문서 경로 제외
        skip_paths = {"test/", "tests/", "example/", "examples/", "doc/", "docs/",
                      "benchmark/", "fuzztest/", "unittest/", "perftest/"}

        def _safe_relative_source_path(candidate: Path) -> str | None:
            try:
                rel = candidate.resolve().relative_to(local_root)
            except (OSError, ValueError):
                return None
            rel_path = rel.as_posix()
            if Path(rel_path).suffix.lower() not in source_exts:
                return None
            if any(skip in rel_path.lower() for skip in skip_paths):
                return None
            return rel_path

        def _parse_only_in_added_file(line: str) -> str | None:
            if not line.startswith("Only in ") or ": " not in line:
                return None
            directory, name = line[len("Only in "):].split(": ", 1)
            return _safe_relative_source_path(Path(directory) / name)

        for line in brief.splitlines():
            if line.startswith("Files") and "differ" in line:
                parts = line.split(" and ")
                if len(parts) >= 2:
                    file_path = parts[1].split(" differ")[0].strip()
                    rel = _safe_relative_source_path(Path(file_path))
                    if rel is not None:
                        modified_files.append(rel)
            elif line.startswith("Only in "):
                rel = _parse_only_in_added_file(line)
                if rel is not None:
                    added_files.append(rel)

        # 수정된 파일별 상세 diff (줄 수)
        modifications: list[dict[str, Any]] = []
        total_insertions = 0
        total_deletions = 0

        for mod_file in modified_files[:50]:  # 최대 50개
            local_file = local / mod_file
            upstream_file = upstream / mod_file
            if local_file.exists() and upstream_file.exists():
                ins, dels = await self._count_diff_lines(upstream_file, local_file)
                total_insertions += ins
                total_deletions += dels
                if ins > 0 or dels > 0:
                    modifications.append({
                        "file": mod_file,
                        "insertions": ins,
                        "deletions": dels,
                    })

        return {
            "totalFiles": len(list(local.rglob("*")) if local.is_dir() else []),
            "modifiedFiles": len(modified_files),
            "addedFiles": len(added_files),
            "addedFilesList": added_files,
            "diffStats": {
                "insertions": total_insertions,
                "deletions": total_deletions,
            },
            "modifications": modifications,
        }

    async def _count_diff_lines(
        self, file_a: Path, file_b: Path,
    ) -> tuple[int, int]:
        """두 파일 간 삽입/삭제 줄 수."""
        proc = await asyncio.create_subprocess_exec(
            "diff", "-u", str(file_a), str(file_b),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        insertions = 0
        deletions = 0
        for line in stdout.decode().splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                insertions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        return insertions, deletions
