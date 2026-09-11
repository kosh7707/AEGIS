"""Shared BudgetManager for S3 agents."""

from __future__ import annotations

import logging

from app.agent_runtime.observability import agent_log
from app.agent_runtime.schemas.agent import BudgetState, ToolCostTier

logger = logging.getLogger(__name__)


class BudgetManager:
    """BudgetState 기반 예산 관리."""

    def __init__(self, budget: BudgetState) -> None:
        self._budget = budget

    @property
    def state(self) -> BudgetState:
        return self._budget

    def snapshot(self) -> dict:
        """현재 예산 상태를 딕셔너리로 반환."""
        b = self._budget
        return {
            "steps": b.total_steps,
            "tokens": b.total_completion_tokens,
            "prompt_tokens": b.total_prompt_tokens,
            "cheap": b.cheap_calls,
            "medium": b.medium_calls,
            "expensive": b.expensive_calls,
        }

    def tier_usage(self, tier: ToolCostTier) -> tuple[int, int]:
        """Returns (current_count, max_count) for the given tier."""
        if tier == ToolCostTier.CHEAP:
            return self._budget.cheap_calls, self._budget.max_cheap_calls
        if tier == ToolCostTier.MEDIUM:
            return self._budget.medium_calls, self._budget.max_medium_calls
        if tier == ToolCostTier.EXPENSIVE:
            return self._budget.expensive_calls, self._budget.max_expensive_calls
        return 0, 0

    def can_make_call(self, tier: ToolCostTier) -> bool:
        """해당 tier의 호출 예산이 남아있는지 확인."""
        current, maximum = self.tier_usage(tier)
        return current < maximum

    def record_tool_call(self, tier: ToolCostTier, *, turn: int | None = None) -> None:
        """tier별 호출 카운트 증가 + 전체 step 증가."""
        if tier == ToolCostTier.CHEAP:
            self._budget.cheap_calls += 1
        elif tier == ToolCostTier.MEDIUM:
            self._budget.medium_calls += 1
        elif tier == ToolCostTier.EXPENSIVE:
            self._budget.expensive_calls += 1
        self._budget.total_steps += 1

        agent_log(
            logger,
            "예산 갱신",
            component="budget",
            phase="budget_update",
            turn=turn,
            event="tool_call",
            budget=self.snapshot(),
            level=logging.DEBUG,
        )

    def record_tokens(self, prompt: int, completion: int, *, turn: int | None = None) -> None:
        self._budget.total_completion_tokens += completion
        self._budget.total_prompt_tokens += prompt

        if self._budget.total_prompt_tokens > self._budget.max_prompt_tokens * 0.8:
            agent_log(
                logger,
                "prompt 토큰 예산 80% 초과",
                component="budget",
                phase="budget_warning",
                turn=turn,
                prompt_tokens=self._budget.total_prompt_tokens,
                max_prompt_tokens=self._budget.max_prompt_tokens,
                level=logging.WARNING,
            )

        agent_log(
            logger,
            "예산 갱신",
            component="budget",
            phase="budget_update",
            turn=turn,
            event="tokens",
            budget=self.snapshot(),
            level=logging.DEBUG,
        )

    def is_duplicate_call(self, args_hash: str) -> bool:
        return args_hash in self._budget.duplicate_call_hashes

    def register_call_hash(self, args_hash: str) -> None:
        self._budget.duplicate_call_hashes.add(args_hash)

    def clear_duplicate_hashes(self) -> None:
        """mutating tool 실행 후 호출 — 상태가 바뀌었으므로 재시도를 허용한다."""
        self._budget.duplicate_call_hashes.clear()

    def record_no_evidence_turn(self, *, turn: int | None = None) -> None:
        self._budget.consecutive_no_evidence_turns += 1

        agent_log(
            logger,
            "예산 갱신",
            component="budget",
            phase="budget_update",
            turn=turn,
            event="no_evidence",
            budget=self.snapshot(),
            level=logging.DEBUG,
        )

    def reset_no_evidence_counter(self, *, turn: int | None = None) -> None:
        self._budget.consecutive_no_evidence_turns = 0

        agent_log(
            logger,
            "예산 갱신",
            component="budget",
            phase="budget_update",
            turn=turn,
            event="reset",
            budget=self.snapshot(),
            level=logging.DEBUG,
        )

    def is_exhausted(self) -> bool:
        """토큰 또는 step 예산이 소진되었는지."""
        return (
            self._budget.total_steps >= self._budget.max_steps
            or self._budget.total_completion_tokens >= self._budget.max_completion_tokens
        )

    def no_callable_tools_remaining(self) -> bool:
        """모든 tier 예산이 소진되어 호출 가능한 tool이 없는지."""
        return (
            not self.can_make_call(ToolCostTier.CHEAP)
            and not self.can_make_call(ToolCostTier.MEDIUM)
            and not self.can_make_call(ToolCostTier.EXPENSIVE)
        )

    def would_exceed_after_repair(
        self,
        *,
        completion_tokens_estimate: int = 0,
        completion_tokens: int | None = None,
        tool_steps: int = 0,
    ) -> bool:
        """Return whether a bounded repair attempt would exceed loop budgets."""
        projected_completion = completion_tokens_estimate if completion_tokens is None else completion_tokens
        return (
            self._budget.total_steps + tool_steps > self._budget.max_steps
            or self._budget.total_completion_tokens + projected_completion > self._budget.max_completion_tokens
        )
