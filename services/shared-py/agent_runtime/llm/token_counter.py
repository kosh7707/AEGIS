"""Shared token accounting for S3 agent sessions."""

from __future__ import annotations

from typing import Protocol


class TokenUsageResponse(Protocol):
    prompt_tokens: int
    completion_tokens: int


class TokenBudgetSession(Protocol):
    budget: object


class TokenCounter:
    """Record LLM completion token usage on a session budget."""

    def record(self, response: TokenUsageResponse, session: TokenBudgetSession) -> None:
        session.budget.total_prompt_tokens += response.prompt_tokens
        session.budget.total_completion_tokens += response.completion_tokens
