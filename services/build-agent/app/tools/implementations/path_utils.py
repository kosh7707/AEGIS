"""Path helpers for generated build-dir tools."""
from __future__ import annotations

import os


def normalize_generated_build_path(path: str, build_dir: str) -> str:
    """Return the path relative to ``build_dir`` accepted by file tools.

    Tool schemas define write/edit/delete ``path`` as build-dir-relative
    (for example ``aegis-build.sh``), while the final build result and
    try_build command use project-relative spelling
    (``{build_dir}/aegis-build.sh``). LLMs sometimes pass that final
    buildScript spelling back into file tools. Accept exactly that leading
    build-dir component without creating ``build_dir/build_dir`` nests.

    Absolute paths and traversal remain untrusted: this helper only rewrites
    an exact leading build-dir component, then lets each tool's existing
    boundary checks decide whether the normalized path is allowed.
    """
    if not path:
        return path

    raw_path = os.fspath(path)
    if os.path.isabs(raw_path):
        return os.path.normpath(raw_path)

    candidate = raw_path
    dot_prefix = "." + os.sep
    while candidate.startswith(dot_prefix):
        candidate = candidate[len(dot_prefix):]

    build_prefix = os.path.normpath(build_dir)
    if candidate == build_prefix:
        return "."
    if candidate.startswith(build_prefix + os.sep):
        return os.path.normpath(candidate[len(build_prefix):].lstrip(os.sep))

    return os.path.normpath(raw_path)
