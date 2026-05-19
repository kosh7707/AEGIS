"""library_differ 단위 테스트 — upstream diff, clone, 해시 비교."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner.library_differ import CloneCache, DiffResult, LibraryDiffer


@pytest.fixture
def differ():
    return LibraryDiffer()


def _assert_log_records_do_not_contain(caplog, *secrets: str) -> None:
    """Assert neither rendered log text nor structured LogRecord fields contain secrets."""
    for secret in secrets:
        assert secret not in caplog.text
        for record in caplog.records:
            assert secret not in record.getMessage()
            assert secret not in repr(record.__dict__)


# ──────────────────── _count_diff_lines ────────────────────


class TestCountDiffLines:
    @pytest.mark.asyncio
    async def test_basic_diff(self, differ, tmp_path):
        a = tmp_path / "a.c"
        b = tmp_path / "b.c"
        a.write_text("line1\nline2\nline3\n")
        b.write_text("line1\nmodified\nline3\nnew_line\n")
        ins, dels = await differ._count_diff_lines(a, b)
        assert ins == 2  # modified + new_line
        assert dels == 1  # line2

    @pytest.mark.asyncio
    async def test_identical_files(self, differ, tmp_path):
        a = tmp_path / "a.c"
        b = tmp_path / "b.c"
        a.write_text("same\n")
        b.write_text("same\n")
        ins, dels = await differ._count_diff_lines(a, b)
        assert ins == 0
        assert dels == 0


# ──────────────────── _clone_and_checkout ────────────────────


class TestCloneCacheLogging:
    @pytest.mark.asyncio
    async def test_cache_miss_log_redacts_repo_url(self, tmp_path, caplog):
        """Clone cache MISS logs must not expose private repo URLs."""
        cache = CloneCache(base_dir=str(tmp_path))
        secret_repo = "https://token:SECRET_TOKEN_SHOULD_NOT_LEAK@example.internal/private/repo.git"
        caplog.set_level(logging.DEBUG, logger="aegis-sast-runner")

        with patch.object(cache, "_git_clone", new_callable=AsyncMock, return_value=True):
            result = await cache.get_or_clone(secret_repo, timeout=30)

        assert result == cache._cache_path(secret_repo)
        assert "Clone cache MISS" in caplog.text
        assert "cloned fresh" in caplog.text
        _assert_log_records_do_not_contain(
            caplog,
            secret_repo,
            "SECRET_TOKEN_SHOULD_NOT_LEAK",
            "example.internal",
            "private/repo.git",
        )

    @pytest.mark.asyncio
    async def test_cache_hit_log_redacts_repo_url(self, tmp_path, caplog):
        """Clone cache HIT logs must keep age only, not private repo URLs."""
        cache = CloneCache(base_dir=str(tmp_path))
        secret_repo = "ssh://git@SECRET_HOST_SHOULD_NOT_LEAK/private/repo.git"
        cache_dir = cache._cache_path(secret_repo)
        (cache_dir / ".git").mkdir(parents=True)
        caplog.set_level(logging.DEBUG, logger="aegis-sast-runner")

        with patch.object(cache, "_git_fetch", new_callable=AsyncMock, return_value=True):
            result = await cache.get_or_clone(secret_repo, timeout=30)

        assert result == cache_dir
        assert "Clone cache HIT" in caplog.text
        _assert_log_records_do_not_contain(
            caplog,
            secret_repo,
            "SECRET_HOST_SHOULD_NOT_LEAK",
            "private/repo.git",
        )


class TestCloneAndCheckout:
    @pytest.mark.asyncio
    async def test_tag_found_first_try(self, differ, tmp_path):
        with patch.object(differ, "_git_clone_tag", new_callable=AsyncMock, return_value=True):
            tag = await differ._clone_and_checkout("https://repo", "1.2.0", tmp_path, 30)
        assert tag == "v1.2.0"  # 첫 번째 후보

    @pytest.mark.asyncio
    async def test_tag_not_found_fallback_head(self, differ, tmp_path):
        with patch.object(differ, "_git_clone_tag", new_callable=AsyncMock, return_value=False), \
             patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True):
            tag = await differ._clone_and_checkout("https://repo", "9.9.9", tmp_path, 30)
        assert tag == "HEAD"

    @pytest.mark.asyncio
    async def test_all_clone_fail(self, differ, tmp_path):
        with patch.object(differ, "_git_clone_tag", new_callable=AsyncMock, return_value=False), \
             patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=False):
            tag = await differ._clone_and_checkout("https://repo", "1.0", tmp_path, 30)
        assert tag is None

    @pytest.mark.asyncio
    async def test_no_version_clone_head(self, differ, tmp_path):
        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True):
            tag = await differ._clone_and_checkout("https://repo", None, tmp_path, 30)
        assert tag == "HEAD"


# ──────────────────── _clone_at_commit ────────────────────


class TestCloneAtCommit:
    @pytest.mark.asyncio
    async def test_success(self, differ, tmp_path):
        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True), \
             patch.object(differ, "_git_checkout", new_callable=AsyncMock, return_value=True):
            result = await differ._clone_at_commit("https://repo", "abc123", tmp_path, 30)
        assert result == "abc123"

    @pytest.mark.asyncio
    async def test_clone_fail(self, differ, tmp_path):
        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=False):
            result = await differ._clone_at_commit("https://repo", "abc", tmp_path, 30)
        assert result is None

    @pytest.mark.asyncio
    async def test_checkout_fail(self, differ, tmp_path):
        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True), \
             patch.object(differ, "_git_checkout", new_callable=AsyncMock, return_value=False):
            result = await differ._clone_at_commit("https://repo", "bad", tmp_path, 30)
        assert result is None


# ──────────────────── diff (integration-style, mocked) ────────────────────


class TestDiff:
    @pytest.mark.asyncio
    async def test_diff_with_commit(self, differ, tmp_path):
        # local 라이브러리 디렉토리
        lib_dir = tmp_path / "local_lib"
        lib_dir.mkdir()
        (lib_dir / "main.c").write_text("int main() { return 0; }\n")

        with patch.object(differ, "_clone_at_commit", new_callable=AsyncMock, return_value="abc123"), \
             patch("app.scanner.library_differ.hash_source_files") as mock_hash, \
             patch("app.scanner.library_differ.compare_hashes") as mock_compare:
            mock_hash.return_value = {"main.c": "aaa"}
            mock_compare.return_value = {
                "identical": ["main.c"], "modified": [], "added": [], "deleted": [],
                "identicalCount": 1, "modifiedCount": 0, "addedCount": 0, "deletedCount": 0,
                "matchRatio": 1.0,
            }
            result = await differ.diff(lib_dir, "https://repo", "1.0", commit="abc123")

        assert result["matchedVersion"] == "abc123"
        assert result["matchRatio"] == 1.0
        assert result["modifiedFiles"] == 0

    @pytest.mark.asyncio
    async def test_diff_clone_fail(self, differ, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        with patch.object(differ, "_clone_and_checkout", new_callable=AsyncMock, return_value=None):
            result = await differ.diff(lib_dir, "https://repo", "1.0")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_diff_with_modifications(self, differ, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        (lib_dir / "mod.c").write_text("modified content\n")

        with patch.object(differ, "_clone_and_checkout", new_callable=AsyncMock, return_value="v1.0"), \
             patch("app.scanner.library_differ.hash_source_files") as mock_hash, \
             patch("app.scanner.library_differ.compare_hashes") as mock_compare, \
             patch.object(differ, "_count_diff_lines", new_callable=AsyncMock, return_value=(5, 2)):
            mock_hash.return_value = {"mod.c": "aaa"}
            mock_compare.return_value = {
                "identical": [], "modified": ["mod.c"], "added": [], "deleted": [],
                "identicalCount": 0, "modifiedCount": 1, "addedCount": 0, "deletedCount": 0,
                "matchRatio": 0.0,
            }
            # _count_diff_lines needs both files to exist
            clone_dir_patch = tmp_path / "clone"
            clone_dir_patch.mkdir(exist_ok=True)
            (clone_dir_patch / "mod.c").write_text("original\n")

            result = await differ.diff(lib_dir, "https://repo", "1.0")

        assert result["matchedVersion"] == "v1.0"
        assert result["modifiedFiles"] == 1


# ──────────────────── find_closest_version ────────────────────


class TestFindClosestVersion:
    @pytest.mark.asyncio
    async def test_no_tags(self, differ, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True), \
             patch.object(differ, "_get_tags", new_callable=AsyncMock, return_value=[]):
            result = await differ.find_closest_version(lib_dir, "https://repo")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_clone_fail(self, differ, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=False):
            result = await differ.find_closest_version(lib_dir, "https://repo")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_best_tag_found(self, differ, tmp_path):
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True), \
             patch.object(differ, "_get_tags", new_callable=AsyncMock, return_value=["v1.0", "v2.0"]), \
             patch.object(differ, "_git_checkout", new_callable=AsyncMock, return_value=True), \
             patch.object(differ, "_quick_diff_size", new_callable=AsyncMock, side_effect=[10, 3]), \
             patch.object(differ, "_compute_diff", new_callable=AsyncMock, return_value={"modifiedFiles": 1}):
            result = await differ.find_closest_version(lib_dir, "https://repo")

        assert result["matchedVersion"] == "v2.0"  # smaller diff
        assert result["searchedTags"] == 2

    @pytest.mark.asyncio
    async def test_best_tag_result_sanitizes_public_repo_url(self, differ, tmp_path):
        """find_closest_version() direct repoUrl assignment strips URL credentials."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()
        secret_repo = (
            "https://user:SECRET_TOKEN_SHOULD_NOT_LEAK@example.internal/org/"
            "lib.git?token=SECRET_QUERY_SHOULD_NOT_LEAK#SECRET_FRAGMENT_SHOULD_NOT_LEAK"
        )

        with (
            patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True),
            patch.object(differ, "_get_tags", new_callable=AsyncMock, return_value=["v1.0"]),
            patch.object(differ, "_git_checkout", new_callable=AsyncMock, return_value=True),
            patch.object(differ, "_quick_diff_size", new_callable=AsyncMock, return_value=0),
            patch.object(differ, "_compute_diff", new_callable=AsyncMock, return_value={"modifiedFiles": 0}),
        ):
            result = await differ.find_closest_version(lib_dir, secret_repo)

        assert result["repoUrl"] == "https://example.internal/org/lib.git"
        rendered = json.dumps(result, sort_keys=True)
        assert "SECRET_TOKEN_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_QUERY_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_FRAGMENT_SHOULD_NOT_LEAK" not in rendered

    @pytest.mark.asyncio
    async def test_perfect_match_short_circuits(self, differ, tmp_path):
        """diff_size == 0 (완벽 매치) 시 나머지 태그를 검사하지 않는다."""
        lib_dir = tmp_path / "lib"
        lib_dir.mkdir()

        diff_mock = AsyncMock(side_effect=[0, 999])

        with patch.object(differ, "_git_clone", new_callable=AsyncMock, return_value=True), \
             patch.object(differ, "_get_tags", new_callable=AsyncMock, return_value=["v1.0", "v2.0"]), \
             patch.object(differ, "_git_checkout", new_callable=AsyncMock, return_value=True), \
             patch.object(differ, "_quick_diff_size", diff_mock), \
             patch.object(differ, "_compute_diff", new_callable=AsyncMock, return_value={"modifiedFiles": 0}):
            result = await differ.find_closest_version(lib_dir, "https://repo")

        assert result["matchedVersion"] == "v1.0"
        assert diff_mock.call_count == 1  # 두 번째 태그 미호출 (조기 종료)


# ──────────────────── _compute_diff sanitization ────────────────────


class _Proc:
    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, b""

    def kill(self) -> None:
        self.returncode = -9


class TestComputeDiff:
    @pytest.mark.asyncio
    async def test_compute_diff_added_files_are_relative_and_do_not_echo_only_in_lines(
        self,
        differ,
        tmp_path,
    ):
        local = tmp_path / "SECRET_LOCAL_ROOT_SHOULD_NOT_LEAK"
        upstream = tmp_path / "upstream"
        (local / "src").mkdir(parents=True)
        upstream.mkdir()
        (local / "root_added.c").write_text("int root_added;\n")
        (local / "src" / "nested_added.c").write_text("int nested_added;\n")

        stdout = (
            f"Only in {local}: root_added.c\n"
            f"Only in {local / 'src'}: nested_added.c\n"
        ).encode()
        proc = _Proc(stdout)

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await differ._compute_diff(local, upstream)

        assert result["addedFiles"] == 2
        assert result["addedFilesList"] == ["root_added.c", "src/nested_added.c"]
        assert "SECRET_LOCAL_ROOT_SHOULD_NOT_LEAK" not in str(result)
        assert "Only in" not in str(result)

    @pytest.mark.asyncio
    async def test_compute_diff_ignores_modified_rows_outside_local_root(
        self,
        differ,
        tmp_path,
    ):
        local = tmp_path / "local"
        upstream = tmp_path / "upstream"
        outside = tmp_path / "SECRET_OUTSIDE_ROOT_SHOULD_NOT_LEAK"
        (local / "src").mkdir(parents=True)
        (upstream / "src").mkdir(parents=True)
        outside.mkdir()
        (local / "src" / "valid.c").write_text("int valid = 1;\n")
        (upstream / "src" / "valid.c").write_text("int valid = 0;\n")
        (outside / "evil.c").write_text("int evil;\n")

        stdout = (
            f"Files {upstream / 'src' / 'valid.c'} and {local / 'src' / 'valid.c'} differ\n"
            f"Files {upstream / 'src' / 'evil.c'} and {outside / 'evil.c'} differ\n"
        ).encode()
        proc = _Proc(stdout)

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)), \
             patch.object(differ, "_count_diff_lines", AsyncMock(return_value=(2, 1))):
            result = await differ._compute_diff(local, upstream)

        assert result["modifiedFiles"] == 1
        assert result["modifications"] == [
            {"file": "src/valid.c", "insertions": 2, "deletions": 1},
        ]
        assert "SECRET_OUTSIDE_ROOT_SHOULD_NOT_LEAK" not in str(result)
        assert "evil.c" not in str(result)


# ──────────────────── DiffResult ────────────────────


class TestDiffResult:
    def test_success_to_dict(self):
        r = DiffResult(
            matched_version="v1.0", repo_url="https://repo",
            match_ratio=0.95, identical_files=10, modified_files=2,
            added_files=1, deleted_files=0,
            modifications=[{"file": "a.c", "insertions": 5, "deletions": 2}],
        )
        d = r.to_dict()
        assert d["matchedVersion"] == "v1.0"
        assert d["matchRatio"] == 0.95
        assert d["error"] is None
        assert d["modifiedFiles"] == 2

    def test_error_to_dict(self):
        """에러 응답도 동일한 shape (nullable 필드는 None)."""
        r = DiffResult(error="Failed to clone", repo_url="https://repo")
        d = r.to_dict()
        assert d["error"] == "Failed to clone"
        assert d["matchedVersion"] is None
        assert d["matchRatio"] is None
        assert d["modifiedFiles"] == 0
        assert d["repoUrl"] == "https://repo"

    def test_diff_clone_fail_has_unified_shape(self):
        """diff() 실패 시에도 matchedVersion, matchRatio 등 모든 키 존재."""
        r = DiffResult(error="Failed to clone upstream", repo_url="https://repo")
        d = r.to_dict()
        expected_keys = {"matchedVersion", "repoUrl", "matchRatio", "identicalFiles",
                         "modifiedFiles", "addedFiles", "deletedFiles", "modifications", "error"}
        assert expected_keys.issubset(set(d.keys()))

    def test_repo_url_evidence_strips_credentials_query_and_fragment(self):
        """DiffResult public repoUrl keeps repo identity but drops credentials."""
        r = DiffResult(
            error="Failed to clone",
            repo_url=(
                "https://user:SECRET_PASS_SHOULD_NOT_LEAK@example.internal:8443/org/"
                "repo.git?token=SECRET_QUERY_SHOULD_NOT_LEAK#SECRET_FRAGMENT_SHOULD_NOT_LEAK"
            ),
        )

        d = r.to_dict()

        assert d["repoUrl"] == "https://example.internal:8443/org/repo.git"
        rendered = json.dumps(d, sort_keys=True)
        assert "SECRET_PASS_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_QUERY_SHOULD_NOT_LEAK" not in rendered
        assert "SECRET_FRAGMENT_SHOULD_NOT_LEAK" not in rendered


# ──────────────────── CloneCache ────────────────────


class TestCloneCache:
    @pytest.mark.asyncio
    async def test_miss_clones_fresh(self, tmp_path):
        """캐시 미스 → full clone."""
        cache = CloneCache(base_dir=str(tmp_path / "cache"), ttl_seconds=3600)
        with patch.object(cache, "_git_clone", new_callable=AsyncMock, return_value=True):
            result = await cache.get_or_clone("https://example.com/repo.git", timeout=30)
        assert result is not None
        assert result.is_dir()

    @pytest.mark.asyncio
    async def test_clone_failure_returns_none(self, tmp_path):
        """clone 실패 → None."""
        cache = CloneCache(base_dir=str(tmp_path / "cache"), ttl_seconds=3600)
        with patch.object(cache, "_git_clone", new_callable=AsyncMock, return_value=False):
            result = await cache.get_or_clone("https://fail.com/repo.git", timeout=30)
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_key_deterministic(self, tmp_path):
        """동일 URL → 동일 캐시 키."""
        cache = CloneCache(base_dir=str(tmp_path / "cache"))
        key1 = cache._key("https://github.com/foo/bar.git")
        key2 = cache._key("https://github.com/foo/bar.git")
        assert key1 == key2
        # 다른 URL → 다른 키
        key3 = cache._key("https://github.com/baz/qux.git")
        assert key1 != key3
