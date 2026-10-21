"""Observability 규격 에러 응답 헬퍼.

docs/contracts/shared-models.md 에 정의된 공통 에러 포맷:
  {success: false, error: string, errorDetail: {code, message, requestId, retryable}}
"""

from __future__ import annotations

from starlette.responses import JSONResponse

from app.context import get_request_id


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    retryable: bool = False,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": message,
            "errorDetail": {
                "code": code,
                "message": message,
                "requestId": get_request_id(),
                "retryable": retryable,
            },
        },
    )
