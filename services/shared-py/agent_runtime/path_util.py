"""path_util — 경로 스코프 검증 공통 유틸."""
from __future__ import annotations

from pathlib import Path


def resolve_scoped_path(root: str, rel: str) -> str | None:
    """root 내부로 한정된 절대 경로를 반환한다. 스코프 밖이면 None.

    Path.resolve()로 symlink + .. 를 모두 해소한 뒤
    is_relative_to()로 root 내부인지 검증한다.
    prefix confusion(/tmp/proj vs /tmp/project_evil)을 방지한다.
    """
    try:
        root_resolved = Path(root).resolve()
        target = (root_resolved / rel).resolve()
        if target == root_resolved or target.is_relative_to(root_resolved):
            return str(target)
        return None
    except (ValueError, OSError):
        return None
