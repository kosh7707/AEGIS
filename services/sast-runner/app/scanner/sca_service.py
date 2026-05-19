"""SCA 서비스 — 라이브러리 식별 + upstream diff 오케스트레이션."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from app.config import settings
from app.scanner.library_differ import CloneCache, LibraryDiffer
from app.scanner.library_identifier import LibraryIdentifier
from app.scanner.repository_url import (
    sanitize_repository_url_fields_for_evidence,
    sanitize_repository_url_for_evidence,
)

logger = logging.getLogger("aegis-sast-runner")

# 모듈 수준 싱글톤 (router에서 공유)
_identifier = LibraryIdentifier()
_cache = CloneCache(
    base_dir=settings.lib_cache_dir,
    ttl_seconds=settings.lib_cache_ttl,
)
_differ = LibraryDiffer(cache=_cache)


async def analyze_libraries(
    project_dir: Path,
    *,
    include_diff: bool = True,
) -> list[dict[str, Any]]:
    """라이브러리 식별 + upstream diff를 수행.

    /v1/scan, /v1/functions, /v1/libraries, /v1/build-and-analyze에서 공통 사용.

    Args:
        project_dir: 프로젝트 루트 경로
        include_diff: upstream diff 수행 여부 (기본 True)

    Returns:
        라이브러리 목록 (각각 diff 결과 포함)
    """
    libs_raw = await asyncio.to_thread(_identifier.identify, project_dir)
    results: list[dict[str, Any]] = []

    for lib in libs_raw:
        entry: dict[str, Any] = dict(lib)
        lib_path = project_dir / lib["path"]
        repo_url = lib.get("repoUrl")
        version = lib.get("version")
        commit = lib.get("commit")

        if include_diff and repo_url:
            try:
                if commit:
                    entry["diff"] = await _differ.diff(
                        lib_path, repo_url, version, commit=commit,
                    )
                elif version:
                    entry["diff"] = await _differ.diff(
                        lib_path, repo_url, version,
                    )
                else:
                    entry["diff"] = await _differ.find_closest_version(
                        lib_path, repo_url,
                    )
            except Exception:
                logger.warning("lib_differ.diff failed")
                entry["diff"] = None
        elif not repo_url:
            entry["diff"] = None
            if include_diff:
                entry["note"] = "Unknown library — no upstream repo to compare"

        if isinstance(entry.get("diff"), dict):
            entry["diff"] = sanitize_repository_url_fields_for_evidence(entry["diff"])
        _sanitize_public_repository_urls(entry)
        results.append(entry)

    return results


async def identify_libraries(project_dir: Path) -> list[dict[str, Any]]:
    """라이브러리 식별만 수행 (diff 없음). origin 태깅용. 이벤트루프 블로킹 방지."""
    return await asyncio.to_thread(_identifier.identify, project_dir)


def _sanitize_public_repository_urls(entry: dict[str, Any]) -> None:
    for key in ("repoUrl", "remoteUrl"):
        if key in entry:
            entry[key] = sanitize_repository_url_for_evidence(entry.get(key))
