"""Small deterministic LLM caller for explicit mock/dev mode."""

from __future__ import annotations

from app.agent_runtime.schemas.agent import LlmResponse


class StaticLlmCaller:
    """Return one predefined LlmResponse from the async caller interface."""

    def __init__(
        self,
        *,
        content: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> None:
        self._response = LlmResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    async def call(self, *args, **kwargs) -> LlmResponse:
        return self._response

    async def aclose(self) -> None:
        return None
