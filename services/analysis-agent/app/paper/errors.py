from __future__ import annotations


class PaperError(Exception):
    status_code = 500
    code = "PAPER_ERROR"

    def __init__(self, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class PaperContractError(PaperError):
    status_code = 422
    code = "PAPER_CONTRACT_ERROR"


class PaperOperationalError(PaperError):
    status_code = 502
    code = "PAPER_OPERATIONAL_ERROR"


class PaperNotFoundError(PaperError):
    status_code = 404
    code = "PAPER_CASE_NOT_FOUND"


class PaperConflictError(PaperError):
    status_code = 409
    code = "PAPER_CASE_CONFLICT"
