"""sca_service 단위 테스트 — analyze_libraries, identify_libraries."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner import sca_service


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_identifier():
    """_identifier.identify를 모킹."""
    with patch.object(sca_service, "_identifier") as m:
        m.identify = MagicMock()
        yield m


@pytest.fixture
def mock_differ():
    """_differ.diff / find_closest_version을 모킹."""
    with patch.object(sca_service, "_differ") as m:
        m.diff = AsyncMock()
        m.find_closest_version = AsyncMock()
        yield m


# ---------------------------------------------------------------------------
# analyze_libraries
# ---------------------------------------------------------------------------

class TestAnalyzeLibraries:
    async def test_with_diff_enabled(self, mock_identifier, mock_differ, tmp_path: Path):
        """include_diff=True + repoUrl + version → diff 호출."""
        mock_identifier.identify.return_value = [
            {
                "name": "civetweb",
                "path": "libraries/civetweb",
                "version": "1.16",
                "repoUrl": "https://github.com/civetweb/civetweb",
            }
        ]
        mock_differ.diff.return_value = {"matchedVersion": "v1.16", "modifiedFiles": 2}

        result = await sca_service.analyze_libraries(tmp_path, include_diff=True)

        assert len(result) == 1
        assert result[0]["diff"] == {"matchedVersion": "v1.16", "modifiedFiles": 2}
        mock_differ.diff.assert_awaited_once()

    async def test_with_commit(self, mock_identifier, mock_differ, tmp_path: Path):
        """commit이 있으면 diff에 commit 인자 전달."""
        mock_identifier.identify.return_value = [
            {
                "name": "lib",
                "path": "lib",
                "version": "1.0",
                "commit": "abc123",
                "repoUrl": "https://example.com/lib",
            }
        ]
        mock_differ.diff.return_value = {"matchedVersion": "abc123"}

        result = await sca_service.analyze_libraries(tmp_path)

        mock_differ.diff.assert_awaited_once()
        call_kwargs = mock_differ.diff.call_args
        assert call_kwargs.kwargs.get("commit") == "abc123"

    async def test_without_version_calls_find_closest(
        self, mock_identifier, mock_differ, tmp_path: Path
    ):
        """version/commit 모두 없으면 find_closest_version 호출."""
        mock_identifier.identify.return_value = [
            {
                "name": "lib",
                "path": "lib",
                "repoUrl": "https://example.com/lib",
            }
        ]
        mock_differ.find_closest_version.return_value = {"matchedVersion": "v2.0"}

        result = await sca_service.analyze_libraries(tmp_path)

        mock_differ.find_closest_version.assert_awaited_once()
        assert result[0]["diff"] == {"matchedVersion": "v2.0"}

    async def test_include_diff_false(self, mock_identifier, mock_differ, tmp_path: Path):
        """include_diff=False → diff 호출 없음."""
        mock_identifier.identify.return_value = [
            {
                "name": "civetweb",
                "path": "libraries/civetweb",
                "version": "1.16",
                "repoUrl": "https://github.com/civetweb/civetweb",
            }
        ]

        result = await sca_service.analyze_libraries(tmp_path, include_diff=False)

        assert len(result) == 1
        mock_differ.diff.assert_not_awaited()
        mock_differ.find_closest_version.assert_not_awaited()

    async def test_diff_failure_returns_none(
        self, mock_identifier, mock_differ, tmp_path: Path, caplog
    ):
        """diff 실패 시 entry['diff'] = None, 나머지 라이브러리 계속 처리."""
        mock_identifier.identify.return_value = [
            {
                "name": "SECRET_LIB_NAME_SHOULD_NOT_LEAK",
                "path": "lib1",
                "version": "1.0",
                "repoUrl": "https://example.com/lib1",
            },
            {
                "name": "lib2",
                "path": "lib2",
                "version": "2.0",
                "repoUrl": "https://example.com/lib2",
            },
        ]
        mock_differ.diff.side_effect = [
            RuntimeError("SECRET_DIFF_ERROR_SHOULD_NOT_LEAK"),
            {"matchedVersion": "v2.0"},
        ]
        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        result = await sca_service.analyze_libraries(tmp_path)

        assert len(result) == 2
        assert result[0]["diff"] is None
        assert result[1]["diff"] == {"matchedVersion": "v2.0"}
        assert "lib_differ.diff failed" in caplog.text
        assert "lib_differ.diff failed for" not in caplog.text
        assert "SECRET_LIB_NAME_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_DIFF_ERROR_SHOULD_NOT_LEAK" not in caplog.text

    async def test_no_repo_url(self, mock_identifier, mock_differ, tmp_path: Path):
        """repoUrl 없으면 diff=None + note 추가."""
        mock_identifier.identify.return_value = [
            {
                "name": "unknown_lib",
                "path": "vendor/unknown",
            }
        ]

        result = await sca_service.analyze_libraries(tmp_path, include_diff=True)

        assert len(result) == 1
        assert result[0]["diff"] is None
        assert "note" in result[0]
        assert "Unknown library" in result[0]["note"]
        mock_differ.diff.assert_not_awaited()

    async def test_no_repo_url_diff_disabled(
        self, mock_identifier, mock_differ, tmp_path: Path
    ):
        """repoUrl 없고 include_diff=False → note 없음."""
        mock_identifier.identify.return_value = [
            {"name": "lib", "path": "lib"}
        ]

        result = await sca_service.analyze_libraries(tmp_path, include_diff=False)

        assert len(result) == 1
        # include_diff=False이므로 elif not repo_url 블록에 진입하지만
        # include_diff가 False이므로 note가 추가되지 않음
        assert "note" not in result[0]

    async def test_public_repository_urls_are_sanitized_but_diff_uses_raw_url(
        self, mock_identifier, mock_differ, tmp_path: Path
    ):
        """공개 SCA entry는 URL credential을 제거하지만 diff 입력은 raw URL을 유지한다."""
        secret_repo = (
            "https://user:SECRET_TOKEN_SHOULD_NOT_LEAK@example.internal:8443/org/"
            "lib.git?token=SECRET_QUERY_SHOULD_NOT_LEAK#SECRET_FRAGMENT_SHOULD_NOT_LEAK"
        )
        secret_remote = (
            "ssh://git:SECRET_SSH_PASSWORD_SHOULD_NOT_LEAK@git.example.internal/org/"
            "lib.git?token=SECRET_REMOTE_QUERY_SHOULD_NOT_LEAK"
        )
        mock_identifier.identify.return_value = [
            {
                "name": "lib",
                "path": "lib",
                "version": "1.0",
                "repoUrl": secret_repo,
                "remoteUrl": secret_remote,
            }
        ]
        mock_differ.diff.return_value = {"matchedVersion": "v1.0"}

        result = await sca_service.analyze_libraries(tmp_path, include_diff=True)

        mock_differ.diff.assert_awaited_once()
        assert mock_differ.diff.call_args.args[1] == secret_repo
        assert result[0]["repoUrl"] == "https://example.internal:8443/org/lib.git"
        assert result[0]["remoteUrl"] == "ssh://git.example.internal/org/lib.git"
        rendered = json.dumps(result, sort_keys=True)
        assert "SECRET_TOKEN_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_QUERY_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_FRAGMENT_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_SSH_PASSWORD_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_REMOTE_QUERY_SHOULD_NOT_LEAK" not in rendered

    async def test_public_diff_repository_url_is_sanitized_but_diff_uses_raw_url(
        self, mock_identifier, mock_differ, tmp_path: Path
    ):
        """Public nested diff.repoUrl must not echo differ/test-double credentials."""
        raw_repo = "https://user:SECRET_INPUT_SHOULD_NOT_LEAK@example.internal/org/lib.git"
        raw_diff_repo = (
            "https://user:SECRET_DIFF_TOKEN_SHOULD_NOT_LEAK@example.internal/org/"
            "lib.git?token=SECRET_DIFF_QUERY_SHOULD_NOT_LEAK#SECRET_DIFF_FRAGMENT_SHOULD_NOT_LEAK"
        )
        mock_identifier.identify.return_value = [
            {
                "name": "lib",
                "path": "lib",
                "version": "1.0",
                "repoUrl": raw_repo,
            }
        ]
        mock_differ.diff.return_value = {
            "matchedVersion": "v1.0",
            "repoUrl": raw_diff_repo,
        }

        result = await sca_service.analyze_libraries(tmp_path, include_diff=True)

        mock_differ.diff.assert_awaited_once()
        assert mock_differ.diff.call_args.args[1] == raw_repo
        assert result[0]["repoUrl"] == "https://example.internal/org/lib.git"
        assert result[0]["diff"]["repoUrl"] == "https://example.internal/org/lib.git"
        rendered = json.dumps(result, sort_keys=True)
        assert "SECRET_INPUT_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_DIFF_TOKEN_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_DIFF_QUERY_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_DIFF_FRAGMENT_SHOULD_NOT_LEAK" not in rendered


# ---------------------------------------------------------------------------
# identify_libraries
# ---------------------------------------------------------------------------

class TestIdentifyLibraries:
    async def test_returns_raw_results(self, mock_identifier, tmp_path: Path):
        """identify_libraries는 _identifier.identify 결과를 그대로 반환."""
        expected = [
            {"name": "civetweb", "path": "libraries/civetweb", "version": "1.16"},
            {"name": "tinydtls", "path": "libraries/tinydtls", "version": "0.8.6"},
        ]
        mock_identifier.identify.return_value = expected

        result = await sca_service.identify_libraries(tmp_path)

        assert result == expected
        mock_identifier.identify.assert_called_once_with(tmp_path)

    async def test_empty_project(self, mock_identifier, tmp_path: Path):
        """라이브러리가 없는 프로젝트 → 빈 리스트."""
        mock_identifier.identify.return_value = []

        result = await sca_service.identify_libraries(tmp_path)

        assert result == []
