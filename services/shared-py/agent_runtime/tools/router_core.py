"""Shared ToolRouter core for S3 agents."""

from __future__ import annotations

import json
import logging
from typing import Protocol

from app.agent_runtime.observability import agent_log
from app.agent_runtime.schemas.agent import ToolCallRequest, ToolResult, ToolTraceStep
from app.agent_runtime.tools.base import ToolImplementation
from app.agent_runtime.tools.executor import ToolExecutor
from app.agent_runtime.tools.hooks import HookRunner, merge_hook_feedback, truncate_tool_result
from app.agent_runtime.tools.registry import ToolRegistry, ToolSchema
from app.agent_runtime.tools.schema_validator import validate_tool_arguments

logger = logging.getLogger(__name__)


class BudgetManagerLike(Protocol):
    def is_duplicate_call(self, args_hash: str) -> bool: ...
    def can_make_call(self, tier) -> bool: ...
    def tier_usage(self, tier) -> tuple[int, int]: ...
    def record_tool_call(self, tier, *, turn: int | None = None) -> None: ...
    def register_call_hash(self, args_hash: str) -> None: ...
    def clear_duplicate_hashes(self) -> None: ...
    def reset_no_evidence_counter(self, *, turn: int | None = None) -> None: ...
    def record_no_evidence_turn(self, *, turn: int | None = None) -> None: ...


class ToolFailurePolicyLike(Protocol):
    def handle(self, call: ToolCallRequest, error: str, session) -> ToolResult: ...


class AgentSessionLike(Protocol):
    turn_count: int
    trace: list[ToolTraceStep]


class SharedToolRouter:
    """tool_call을 구현체로 라우팅하고 실행한다."""

    def __init__(
        self,
        registry: ToolRegistry,
        executor: ToolExecutor,
        budget_manager: BudgetManagerLike,
        tool_failure_policy: ToolFailurePolicyLike,
        hook_runner: HookRunner | None = None,
    ) -> None:
        self._registry = registry
        self._executor = executor
        self._budget_manager = budget_manager
        self._failure_policy = tool_failure_policy
        self._implementations: dict[str, ToolImplementation] = {}
        self._hook_runner = hook_runner or HookRunner()

    def register_implementation(self, name: str, impl: ToolImplementation) -> None:
        self._implementations[name] = impl

    async def execute(
        self,
        tool_calls: list[ToolCallRequest],
        session: AgentSessionLike,
    ) -> list[ToolResult]:
        results: list[ToolResult] = []
        for call in tool_calls:
            result = await self._execute_single(call, session)
            results.append(result)
        return results

    async def _execute_single(
        self,
        call: ToolCallRequest,
        session: AgentSessionLike,
    ) -> ToolResult:
        turn = session.turn_count + 1

        schema = self._registry.get(call.name)
        if not schema:
            agent_log(
                logger, "미등록 tool",
                component="tool_router", phase="tool_blocked_unknown",
                turn=turn, toolName=call.name, level=logging.WARNING,
            )
            return ToolResult(
                tool_call_id=call.id,
                name=call.name,
                success=False,
                content=f'{{"error": "Unknown tool: {call.name}"}}',
                error=f"Unknown tool: {call.name}",
            )

        impl = self._implementations.get(call.name)
        if not impl:
            return self._failure_policy.handle(call, f"No implementation for {call.name}", session)

        violations = validate_tool_arguments(call.arguments, schema.parameters)
        if violations:
            agent_log(
                logger, "tool schema validation failed",
                component="tool_router", phase="tool_blocked_schema",
                turn=turn, tool=call.name, violations=violations, level=logging.WARNING,
            )
            return ToolResult(
                tool_call_id=call.id,
                name=call.name,
                success=False,
                content=json.dumps({
                    "tool": call.name,
                    "violations": violations,
                    "retryHint": "Retry with arguments that satisfy the registered tool schema.",
                }, ensure_ascii=False),
                error="schema_violation",
            )

        if self._budget_manager.is_duplicate_call(call.args_hash):
            agent_log(
                logger, "중복 tool 호출 차단",
                component="tool_router", phase="tool_blocked_duplicate",
                turn=turn, tool=call.name, argsHash=call.args_hash,
            )
            return ToolResult(
                tool_call_id=call.id,
                name=call.name,
                success=False,
                content=self._duplicate_call_message(call),
                error="duplicate_call",
            )

        tier = schema.cost_tier
        if not self._budget_manager.can_make_call(tier):
            current, max_count = self._budget_manager.tier_usage(tier)
            agent_log(
                logger, "tier 예산 소진",
                component="tool_router", phase="tool_blocked_budget",
                turn=turn, tool=call.name, tier=tier.value,
                currentCount=current, maxCount=max_count,
                level=logging.WARNING,
            )
            return ToolResult(
                tool_call_id=call.id,
                name=call.name,
                success=False,
                content=f'{{"error": "Budget exhausted for {tier.value} tier tools."}}',
                error=f"{tier.value}_budget_exhausted",
            )

        pre_result = self._hook_runner.run_pre_hooks(call.name, call.arguments)
        if pre_result.is_denied():
            deny_msg = merge_hook_feedback(pre_result.messages, "", True)
            agent_log(
                logger, "PreToolUse 훅 거부",
                component="tool_router", phase="tool_hook_denied",
                turn=turn, tool=call.name,
            )
            return ToolResult(
                tool_call_id=call.id,
                name=call.name,
                success=False,
                content=deny_msg or f'{{"error": "PreToolUse hook denied tool {call.name}"}}',
                error="hook_denied",
            )

        agent_log(
            logger, "Tool 디스패치",
            component="tool_router", phase="tool_dispatch",
            turn=turn, tool=call.name, tier=tier.value,
            argsHash=call.args_hash,
        )

        result = await self._executor.execute(impl, call, turn=turn)
        result.content = truncate_tool_result(result.content)

        post_result = self._hook_runner.run_post_hooks(
            call.name, call.arguments, result.content, not result.success,
        )
        if post_result.messages:
            result.content = merge_hook_feedback(
                post_result.messages, result.content, post_result.is_denied(),
            )
        if post_result.is_denied():
            result.success = False
            result.error = result.error or "hook_denied_post"

        self._budget_manager.record_tool_call(tier, turn=turn)
        self._budget_manager.register_call_hash(call.args_hash)
        if self._should_clear_duplicate_hashes(schema=schema, result=result):
            self._budget_manager.clear_duplicate_hashes()

        if result.success and result.new_evidence_refs:
            self._budget_manager.reset_no_evidence_counter(turn=turn)
        elif result.success:
            self._budget_manager.record_no_evidence_turn(turn=turn)

        session.trace.append(ToolTraceStep(
            step_id=f"step_{len(session.trace) + 1:02d}",
            turn_number=turn,
            tool=call.name,
            args_hash=call.args_hash,
            cost_tier=tier,
            duration_ms=result.duration_ms,
            success=result.success,
            new_evidence_refs=result.new_evidence_refs,
            error=result.error,
        ))

        agent_log(
            logger, "Tool 완료",
            component="tool_router", phase="tool_complete",
            turn=turn, tool=call.name, success=result.success,
            durationMs=result.duration_ms,
            newEvidenceCount=len(result.new_evidence_refs),
        )

        return result

    def _duplicate_call_message(self, call: ToolCallRequest) -> str:
        return '{"error": "Duplicate tool call blocked. Same arguments were already used."}'

    def _should_clear_duplicate_hashes(
        self,
        *,
        schema: ToolSchema,
        result: ToolResult,
    ) -> bool:
        return False
