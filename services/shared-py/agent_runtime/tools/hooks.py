"""ToolHook — Pre/Post 도구 실행 훅 프레임워크.

claw-code conversation.rs 패턴 참조:
- PreToolUse: 도구 실행 전 검증/거부/감사
- PostToolUse: 도구 실행 후 검증/감사/피드백
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.agent_runtime.observability import agent_log

logger = logging.getLogger(__name__)


@dataclass
class HookResult:
    """훅 실행 결과."""
    allow: bool = True
    messages: list[str] = field(default_factory=list)

    def is_denied(self) -> bool:
        return not self.allow

    @staticmethod
    def allowed(message: str | None = None) -> HookResult:
        msgs = [message] if message else []
        return HookResult(allow=True, messages=msgs)

    @staticmethod
    def denied(reason: str) -> HookResult:
        return HookResult(allow=False, messages=[reason])


@runtime_checkable
class ToolHook(Protocol):
    """도구 실행 훅 프로토콜. 구현체는 이 인터페이스를 따른다."""

    def pre_tool_use(self, name: str, args: dict) -> HookResult:
        """도구 실행 전 호출. deny 반환 시 도구 실행이 건너뛰어진다."""
        ...

    def post_tool_use(
        self, name: str, args: dict, output: str, is_error: bool,
    ) -> HookResult:
        """도구 실행 후 호출. deny 반환 시 결과가 에러로 변환된다."""
        ...


class HookRunner:
    """등록된 훅을 순차 실행한다."""

    def __init__(self) -> None:
        self._hooks: list[ToolHook] = []

    def register(self, hook: ToolHook) -> None:
        """훅을 등록한다."""
        self._hooks.append(hook)

    def run_pre_hooks(self, name: str, args: dict) -> HookResult:
        """모든 pre_tool_use 훅을 실행한다. 하나라도 deny면 즉시 중단."""
        all_messages: list[str] = []
        for hook in self._hooks:
            result = hook.pre_tool_use(name, args)
            all_messages.extend(result.messages)
            if result.is_denied():
                return HookResult(allow=False, messages=all_messages)
        return HookResult(allow=True, messages=all_messages)

    def run_post_hooks(
        self, name: str, args: dict, output: str, is_error: bool,
    ) -> HookResult:
        """모든 post_tool_use 훅을 실행한다."""
        all_messages: list[str] = []
        denied = False
        for hook in self._hooks:
            result = hook.post_tool_use(name, args, output, is_error)
            all_messages.extend(result.messages)
            if result.is_denied():
                denied = True
        return HookResult(allow=not denied, messages=all_messages)

    @property
    def hook_count(self) -> int:
        return len(self._hooks)


class AuditLogHook:
    """기본 감사 로깅 훅. 모든 도구 호출을 agent_log로 기록한다."""

    def __init__(self, component: str = "tool_hook") -> None:
        self._component = component

    def pre_tool_use(self, name: str, args: dict) -> HookResult:
        agent_log(
            logger, "PreToolUse",
            component=self._component, phase="pre_tool_use",
            toolName=name, argsKeys=list(args.keys()),
        )
        return HookResult.allowed()

    def post_tool_use(
        self, name: str, args: dict, output: str, is_error: bool,
    ) -> HookResult:
        agent_log(
            logger, "PostToolUse",
            component=self._component, phase="post_tool_use",
            toolName=name, isError=is_error,
            outputLen=len(output),
        )
        return HookResult.allowed()


def truncate_tool_result(content: str, max_chars: int = 8000) -> str:
    """도구 결과가 max_chars를 초과하면 잘라내고 truncation 안내를 추가한다."""
    if len(content) <= max_chars:
        return content
    truncated = content[:max_chars]
    return f"{truncated}\n... [truncated: 원본 {len(content)}자 중 {max_chars}자 표시]"


def merge_hook_feedback(messages: list[str], output: str, denied: bool) -> str:
    """훅 메시지를 도구 출력에 병합한다 (claw-code merge_hook_feedback 패턴)."""
    if not messages:
        return output
    label = "Hook feedback (denied)" if denied else "Hook feedback"
    parts = []
    if output.strip():
        parts.append(output)
    parts.append(f"{label}:\n" + "\n".join(messages))
    return "\n\n".join(parts)
