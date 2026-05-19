"""Repository URL helpers for separating internal clone inputs from public evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def sanitize_repository_url_for_evidence(url: str | None) -> str | None:
    """Return a public-safe repository URL without credentials/query/fragment.

    Internal clone/fetch code may still use raw URLs. Public evidence should keep
    only stable repository identity: scheme, host/port, and path.
    """
    if url is None:
        return None
    raw = str(url).strip()
    if not raw:
        return None
    if "://" not in raw:
        return raw

    parts = urlsplit(raw)
    netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def repository_name_from_url(url: str | None, fallback: str) -> str:
    """Derive a repository name without allowing URL credentials to pollute it."""
    safe_url = sanitize_repository_url_for_evidence(url)
    candidate = ""
    if safe_url:
        if "://" in safe_url:
            candidate = urlsplit(safe_url).path.rstrip("/").rsplit("/", 1)[-1]
        elif ":" in safe_url:
            candidate = safe_url.rsplit(":", 1)[-1].rstrip("/").rsplit("/", 1)[-1]
        else:
            candidate = safe_url.rstrip("/").rsplit("/", 1)[-1]

    if candidate.endswith(".git"):
        candidate = candidate[:-4]
    return candidate or fallback


def sanitize_repository_url_fields_for_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a shallow copy with public repository URL fields sanitized."""
    sanitized = dict(value)
    for key in ("repoUrl", "remoteUrl"):
        if key in sanitized:
            sanitized[key] = sanitize_repository_url_for_evidence(sanitized.get(key))
    return sanitized
