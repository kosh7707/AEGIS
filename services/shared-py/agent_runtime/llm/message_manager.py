"""MessageManager — 멀티 턴 대화의 messages 배열 관리."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING

from app.agent_runtime.schemas.agent import ToolCallRequest, ToolResult
from app.agent_runtime.security.input_boundary import render_tool_result_for_llm

if TYPE_CHECKING:
    from app.agent_runtime.llm.turn_summarizer import TurnSummarizer


class MessageManager:
    """messages 배열을 누적 관리한다. tool result 주입을 포함."""

    def __init__(self, system_prompt: str, initial_user_message: str) -> None:
        self._messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_user_message},
        ]

    def get_messages(self) -> list[dict]:
        """현재 messages 배열의 deep copy를 반환한다."""
        return copy.deepcopy(self._messages)

    def add_user_message(self, content: str) -> None:
        """user 메시지를 추가한다 (에이전트 루프의 지시 주입 등)."""
        self._messages.append({"role": "user", "content": content})

    def add_assistant_content(self, content: str) -> None:
        """assistant의 텍스트 응답을 추가한다."""
        self._messages.append({"role": "assistant", "content": content})

    def add_assistant_tool_calls(self, tool_calls: list[ToolCallRequest]) -> None:
        """assistant의 tool_calls 응답을 추가한다 (content=null)."""
        self._messages.append({
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                    },
                }
                for tc in tool_calls
            ],
        })

    def add_tool_results(self, results: list[ToolResult]) -> None:
        """tool 실행 결과를 role='tool' 메시지로 추가한다."""
        for result in results:
            self._messages.append({
                "role": "tool",
                "tool_call_id": result.tool_call_id,
                "content": render_tool_result_for_llm(result),
            })

    def message_count(self) -> int:
        return len(self._messages)

    def get_token_estimate(self) -> int:
        """대략적 토큰 추정 (4자 = 1토큰). content + tool_calls JSON 포함."""
        total_chars = 0
        for m in self._messages:
            total_chars += len(str(m.get("content", "") or ""))
            # tool_calls가 있으면 그 JSON 크기도 포함
            tool_calls = m.get("tool_calls")
            if tool_calls:
                total_chars += len(str(tool_calls))
        return total_chars // 4

    async def compact(
        self,
        summarizer: TurnSummarizer,
        keep_last_n: int = 4,
        state_summary: dict | None = None,
    ) -> int:
        """메시지를 압축한다. 제거된 메시지 수를 반환한다."""
        before = len(self._messages)
        self._messages = await summarizer.summarize(
            self._messages, keep_last_n, state_summary=state_summary,
        )
        return before - len(self._messages)
