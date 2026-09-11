from __future__ import annotations


class S3Error(Exception):
    """S3 LLM Gateway 기본 예외."""

    def __init__(self, message: str, *, code: str, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class LlmTimeoutError(S3Error):
    """S7 LLM Gateway request timed out."""

    def __init__(self, message: str = "LLM 요청 시간 초과"):
        super().__init__(message, code="LLM_TIMEOUT", retryable=True)


class LlmUnavailableError(S3Error):
    """S7 LLM Gateway is unavailable."""

    def __init__(self, message: str = "LLM 서버 연결 불가"):
        super().__init__(message, code="LLM_UNAVAILABLE", retryable=True)


class LlmInputTooLargeError(S3Error):
    """프롬프트가 모델 입력 한도를 초과."""

    def __init__(self, chars: int, limit: int):
        msg = f"프롬프트가 입력 한도를 초과합니다 ({chars:,}자 > {limit:,}자 상한)"
        super().__init__(msg, code="INPUT_TOO_LARGE", retryable=False)
        self.chars = chars
        self.limit = limit


class LlmHttpError(S3Error):
    """S7 LLM Gateway returned a non-success HTTP status."""

    def __init__(
        self,
        status_code: int,
        message: str | None = None,
        *,
        retry_after: float | None = None,
    ):
        msg = message or f"LLM 서버 HTTP {status_code} 오류"
        retryable = status_code in (429, 503)
        code = "LLM_OVERLOADED" if retryable else "LLM_HTTP_ERROR"
        super().__init__(msg, code=code, retryable=retryable)
        self.upstream_status = status_code
        self.retry_after = retry_after  # S7이 보내는 Retry-After 값 (초)


class StrictJsonContractError(S3Error):
    """S7 strict JSON contract failure with retry/audit metadata."""

    def __init__(
        self,
        message: str = "strict_json_contract_violation",
        *,
        blocked_reason: str = "strict_json_contract_violation",
        error_detail: str | None = None,
        async_request_id: str | None = None,
        gateway_request_id: str | None = None,
        http_status: int = 409,
        raw_excerpt: str | None = None,
    ) -> None:
        super().__init__(message, code="STRICT_JSON_CONTRACT_VIOLATION", retryable=True)
        self.blocked_reason = blocked_reason
        self.error_detail = error_detail
        self.async_request_id = async_request_id
        self.gateway_request_id = gateway_request_id
        self.http_status = http_status
        self.raw_excerpt = raw_excerpt


class LlmContractViolationError(S3Error):
    """Retryable S7 response-contract failure with diagnostic excerpts.

    Used when the transport returned a nominal response, but the parsed OpenAI
    message has no actionable assistant content/tool call because the gateway
    detected or exposed a response-contract violation (for example
    finish_reason=tool_calls with an empty tool_calls array, or all output being
    absorbed into the reasoning field).
    """

    def __init__(
        self,
        message: str = "llm_response_contract_violation",
        *,
        violation_reason: str = "response_contract_violation",
        finish_reason: str | None = None,
        reasoning_excerpt: str | None = None,
        content_excerpt: str | None = None,
        raw_excerpt: str | None = None,
        async_request_id: str | None = None,
        gateway_request_id: str | None = None,
    ) -> None:
        super().__init__(message, code="LLM_RESPONSE_CONTRACT_VIOLATION", retryable=True)
        self.violation_reason = violation_reason
        self.finish_reason = finish_reason
        self.reasoning_excerpt = reasoning_excerpt
        self.content_excerpt = content_excerpt
        self.raw_excerpt = raw_excerpt
        self.async_request_id = async_request_id
        self.gateway_request_id = gateway_request_id


class BudgetExhaustedError(S3Error):
    """A recovery/finalizer LLM call would exceed the request token budget."""

    def __init__(self, message: str = "S3 repair/finalizer token budget exhausted"):
        super().__init__(message, code="BUDGET_EXHAUSTED", retryable=False)


class LlmPoolExhaustedError(S3Error):
    """HTTP 연결 풀 소진 — 동시 요청 과다."""

    def __init__(self, message: str = "HTTP 연결 풀 소진 (동시 요청 과다)"):
        super().__init__(message, code="POOL_EXHAUSTED", retryable=True)
