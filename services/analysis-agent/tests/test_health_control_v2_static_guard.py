"""Static guard for health-control v2 age-only poll abort removal."""

from __future__ import annotations

from pathlib import Path

FORBIDDEN_RUNTIME_PATTERNS = (
    "async_poll_deadline",
    "poll_deadline",
    "poll deadline exceeded",
    "poll_deadline_exceeded",
    "LLM_ASYNC_POLL_TIMEOUT",
    "llmAsyncPollDeadlineMs",
)
ALLOWED_GENERIC_PATTERNS = ("deadline_exceeded",)
RUNTIME_ROOTS = (
    Path("services/analysis-agent/app"),
    Path("services/analysis-agent/eval"),
    Path("services/build-agent/app"),
)


def test_no_age_only_async_poll_abort_runtime_patterns_remain() -> None:
    offenders: list[str] = []
    for root in RUNTIME_ROOTS:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for pattern in FORBIDDEN_RUNTIME_PATTERNS:
                if pattern in text:
                    offenders.append(f"{path}:{pattern}")
            for pattern in ALLOWED_GENERIC_PATTERNS:
                # Generic state-machine deadline enums are still allowed, but only under state_machine.
                if pattern in text and "state_machine" not in path.parts:
                    offenders.append(f"{path}:{pattern}")
    assert offenders == []
