"""Shared TerminationPolicy for S3 agents."""

from __future__ import annotations

import logging
from typing import Protocol

from app.agent_runtime.observability import agent_log
from app.agent_runtime.schemas.agent import BudgetState

logger = logging.getLogger(__name__)


class TerminationSession(Protocol):
    """Minimal session shape required by TerminationPolicy."""

    budget: BudgetState
    turn_count: int

    def elapsed_ms(self) -> int: ...
    def set_termination_reason(self, reason: str) -> None: ...


def _budget_snapshot(session: TerminationSession) -> dict:
    b = session.budget
    return {
        "steps": b.total_steps,
        "tokens": b.total_completion_tokens,
        "cheap": b.cheap_calls,
        "medium": b.medium_calls,
        "expensive": b.expensive_calls,
    }


def _all_tiers_exhausted(budget: BudgetState) -> bool:
    return (
        budget.cheap_calls >= budget.max_cheap_calls
        and budget.medium_calls >= budget.max_medium_calls
        and budget.expensive_calls >= budget.max_expensive_calls
    )


class TerminationPolicy:
    """5가지 종료 조건을 검사하여 루프 중단 여부를 결정한다."""

    def __init__(self, timeout_ms: int = 300_000) -> None:
        self._timeout_ms = timeout_ms

    def should_stop(self, session: TerminationSession) -> bool:
        """종료 조건 충족 시 True 반환 + session에 사유 기록."""
        reason = self._check(session)
        snapshot = _budget_snapshot(session)

        if reason:
            agent_log(
                logger,
                "종료 결정",
                component="termination",
                phase="policy_triggered",
                turn=session.turn_count,
                reason=reason,
                budgetSnapshot=snapshot,
            )
            session.set_termination_reason(reason)
            return True

        agent_log(
            logger,
            "종료 조건 미충족",
            component="termination",
            phase="policy_check",
            turn=session.turn_count,
            shouldStop=False,
            budgetSnapshot=snapshot,
            level=logging.DEBUG,
        )
        return False

    def _check(self, session: TerminationSession) -> str:
        budget = session.budget

        if session.turn_count >= budget.max_steps:
            return "max_steps"
        if budget.total_completion_tokens >= budget.max_completion_tokens:
            return "budget_exhausted"
        # 2026-04-14 health-control policy:
        # elapsed wall-clock time is informational only and must not by itself
        # trigger abort while the ack/progress chain is still alive.
        if budget.consecutive_no_evidence_turns >= budget.max_consecutive_no_evidence:
            return "no_new_evidence"
        if _all_tiers_exhausted(budget):
            return "all_tiers_exhausted"
        return ""
