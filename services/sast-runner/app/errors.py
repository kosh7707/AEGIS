from __future__ import annotations

from typing import Any


class SastRunnerError(Exception):
    code: str = "INTERNAL_ERROR"
    status_code: int = 500
    retryable: bool = False

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class NoFilesError(SastRunnerError):
    code = "NO_FILES_PROVIDED"
    status_code = 400
    retryable = False


class SdkNotFoundError(SastRunnerError):
    code = "SDK_NOT_FOUND"
    status_code = 400
    retryable = False


class InvalidSdkProfileError(SastRunnerError):
    code = "SDK_PROFILE_INVALID"
    status_code = 400
    retryable = False


class SemgrepNotAvailableError(SastRunnerError):
    code = "SEMGREP_NOT_AVAILABLE"
    status_code = 503
    retryable = True


class ScanTimeoutError(SastRunnerError):
    code = "SCAN_TIMEOUT"
    status_code = 504
    retryable = True


class SarifParseError(SastRunnerError):
    code = "SARIF_PARSE_ERROR"
    status_code = 502
    retryable = False


class PolicyViolationError(SastRunnerError):
    code = "DISALLOWED_TOOL_OMISSION"
    status_code = 503
    retryable = False

    def __init__(
        self,
        message: str,
        *,
        scan_response: Any,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.scan_response = scan_response
        if code is not None:
            self.code = code
