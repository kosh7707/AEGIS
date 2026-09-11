"""RetryPolicy — LLM 호출 실패 시 재시도 판단."""

from __future__ import annotations

from app.agent_runtime.errors import (
    LlmContractViolationError,
    LlmHttpError,
    LlmPoolExhaustedError,
    LlmTimeoutError,
    LlmUnavailableError,
    StrictJsonContractError,
)


class RetryPolicy:
    """transient 에러(timeout, 429, 503, pool exhausted)만 재시도.

    CB OPEN(503)은 S7 복구 주기(30초)에 맞춰 최대 2회 재시도.
    429는 Retry-After 헤더가 있으면 해당 값, 없으면 지수 백오프.
    """

    def __init__(self, max_retries: int = 2) -> None:
        self._max_retries = max_retries

    def should_retry(self, error: Exception, attempt: int) -> bool:
        if attempt >= self._max_retries:
            return False
        if isinstance(error, (
            LlmTimeoutError,
            LlmUnavailableError,
            LlmPoolExhaustedError,
            LlmContractViolationError,
            StrictJsonContractError,
        )):
            return True
        if isinstance(error, LlmHttpError) and error.retryable:
            return True
        return False

    def get_delay_seconds(self, error: Exception, attempt: int) -> float:
        """재시도 전 대기 시간 (초).

        CB OPEN 503 → 30초 (S7 복구 주기에 맞춤).
        429 + Retry-After → 서버가 지정한 대기 시간 (최대 60초 cap).
        Pool 소진 → 5초 (짧은 대기 후 재시도).
        기타 → 지수 백오프 2s, 4s, 8s max.
        """
        # CB OPEN: 고정 30초
        if isinstance(error, LlmHttpError) and error.upstream_status == 503:
            return 30.0

        # 429: Retry-After 헤더 우선, 없으면 백오프
        if isinstance(error, LlmHttpError) and error.upstream_status == 429:
            if error.retry_after is not None:
                return min(error.retry_after, 60.0)
            return min(2.0 * (2 ** attempt), 15.0)

        # Pool 소진: 짧은 대기
        if isinstance(error, LlmPoolExhaustedError):
            return 5.0

        # Gateway/parser contract violations are usually transient model/parser
        # races; retry quickly rather than waiting for CB recovery.
        if isinstance(error, (LlmContractViolationError, StrictJsonContractError)):
            return 2.0

        # 기타 (timeout, unavailable): 지수 백오프
        return min(2.0 * (2 ** attempt), 8.0)
