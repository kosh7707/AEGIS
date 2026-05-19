from __future__ import annotations

import pytest

from app.errors import NoFilesError
from app.routers.scan import _validate_path


@pytest.mark.parametrize(
    ("file_path", "expected_message", "secret_fragment"),
    [
        (
            r"..\SECRET_BACKSLASH_TRAVERSAL_SHOULD_NOT_LEAK.c",
            "Path traversal not allowed",
            "SECRET_BACKSLASH_TRAVERSAL_SHOULD_NOT_LEAK",
        ),
        (
            r"src\..\SECRET_NESTED_BACKSLASH_TRAVERSAL_SHOULD_NOT_LEAK.c",
            "Path traversal not allowed",
            "SECRET_NESTED_BACKSLASH_TRAVERSAL_SHOULD_NOT_LEAK",
        ),
        (
            r"C:\SECRET_WINDOWS_DRIVE_SHOULD_NOT_LEAK.c",
            "Absolute path not allowed",
            "SECRET_WINDOWS_DRIVE_SHOULD_NOT_LEAK",
        ),
        (
            r"\\server\share\SECRET_UNC_SHOULD_NOT_LEAK.c",
            "Absolute path not allowed",
            "SECRET_UNC_SHOULD_NOT_LEAK",
        ),
        (
            "C:SECRET_DRIVE_RELATIVE_SHOULD_NOT_LEAK.c",
            "Absolute path not allowed",
            "SECRET_DRIVE_RELATIVE_SHOULD_NOT_LEAK",
        ),
        (
            "z:SECRET_LOWER_DRIVE_RELATIVE_SHOULD_NOT_LEAK.c",
            "Absolute path not allowed",
            "SECRET_LOWER_DRIVE_RELATIVE_SHOULD_NOT_LEAK",
        ),
    ],
)
def test_validate_path_rejects_windows_and_backslash_escape_shapes_without_raw_echo(
    file_path: str,
    expected_message: str,
    secret_fragment: str,
) -> None:
    with pytest.raises(NoFilesError) as exc_info:
        _validate_path(file_path)

    assert str(exc_info.value) == expected_message
    assert secret_fragment not in str(exc_info.value)


@pytest.mark.parametrize("file_path", ["src/main.c", r"src\main.c", "src:main.c"])
def test_validate_path_allows_safe_relative_paths(file_path: str) -> None:
    _validate_path(file_path)
