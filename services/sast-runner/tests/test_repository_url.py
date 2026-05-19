"""Repository URL evidence sanitization helpers."""

from app.scanner.repository_url import (
    repository_name_from_url,
    sanitize_repository_url_for_evidence,
)


def test_sanitize_repository_url_drops_userinfo_query_and_fragment() -> None:
    raw = "https://user:SECRET@example.internal:8443/org/repo.git?token=SECRET#SECRET"

    assert sanitize_repository_url_for_evidence(raw) == "https://example.internal:8443/org/repo.git"


def test_sanitize_repository_url_drops_ssh_userinfo() -> None:
    raw = "ssh://git:SECRET@host.example/org/repo.git"

    assert sanitize_repository_url_for_evidence(raw) == "ssh://host.example/org/repo.git"


def test_sanitize_repository_url_leaves_scp_like_url_unchanged() -> None:
    raw = "git@github.com:org/repo.git"

    assert sanitize_repository_url_for_evidence(raw) == raw


def test_repository_name_from_url_ignores_userinfo_query_and_fragment() -> None:
    raw = "https://user:SECRET@example.internal/org/private-lib.git?token=SECRET#SECRET"

    assert repository_name_from_url(raw, fallback="fallback") == "private-lib"
