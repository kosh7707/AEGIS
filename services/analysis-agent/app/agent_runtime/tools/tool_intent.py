"""ToolIntent runtime-dispatch helpers.

The LLM emits a small JSON intent; S3 validates it and constructs the
ToolCallRequest itself so evidence-acquisition does not depend on vLLM's
Qwen tool-call parser path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from app.agent_runtime.schemas.agent import ToolCallRequest


class ToolIntentError(ValueError):
    """The LLM returned a malformed or unsupported ToolIntent."""


@dataclass(frozen=True)
class ToolIntent:
    action: str
    tool_name: str
    arguments: dict
    rationale: str = ""


def available_tool_names(tools_schema: list[dict] | None) -> set[str]:
    """Extract function names from OpenAI-style tool schemas."""
    names: set[str] = set()
    for tool in tools_schema or []:
        function = tool.get("function") if isinstance(tool, dict) else None
        name = function.get("name") if isinstance(function, dict) else None
        if isinstance(name, str) and name:
            names.add(name)
    return names


def parse_tool_intent(content: str | None, *, available_tool_names: Iterable[str]) -> ToolIntent:
    """Parse and minimally validate a ToolIntent JSON object."""
    if not content or not content.strip():
        raise ToolIntentError("ToolIntent content must be a valid JSON object")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ToolIntentError("ToolIntent content must be valid JSON") from exc

    if not isinstance(payload, dict):
        raise ToolIntentError("ToolIntent content must be a JSON object")
    action = payload.get("action")
    if action != "call_tool":
        raise ToolIntentError(f"unsupported action: {action!r}")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise ToolIntentError("ToolIntent tool_name must be a non-empty string")
    allowed = set(available_tool_names)
    if tool_name not in allowed:
        raise ToolIntentError(f"unknown tool: {tool_name}")
    arguments = payload.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ToolIntentError("ToolIntent arguments must be a JSON object")
    rationale = payload.get("rationale") or ""
    if not isinstance(rationale, str):
        rationale = str(rationale)
    return ToolIntent(
        action=action,
        tool_name=tool_name,
        arguments=arguments,
        rationale=rationale,
    )


def tool_intent_to_request(intent: ToolIntent, *, turn: int) -> ToolCallRequest:
    """Convert a validated ToolIntent into a runtime-owned synthetic tool call."""
    return ToolCallRequest(
        id=f"runtime-toolintent-{turn:02d}",
        name=intent.tool_name,
        arguments=intent.arguments,
    )


_TOOL_INTENT_CONTEXT_LIMIT = 1200
_TOOL_INTENT_TOTAL_LIMIT = 2600


def build_tool_intent_messages(messages: list[dict], tools_schema: list[dict]) -> list[dict]:
    """Build a compact ToolIntent-only prompt.

    This path intentionally does not append to the full Phase 2 transcript.
    Live Qwen/vLLM tool-planning calls are latency-sensitive, and the full
    evidence handoff can be tens of KB.  ToolIntent only needs the immediate
    acquisition objective plus compact tool signatures; the authoritative
    evidence remains in S3 state and is used again for final result assembly.
    """
    rendered_tools = _render_compact_tool_catalog(tools_schema)
    context = _compact_context_excerpt(messages)
    instruction = (
        "[S3 ToolIntent runtime-dispatch]\n"
        "You are in an evidence-acquisition turn. Do not write a final report. "
        "Choose exactly one currently useful tool and return only one JSON object "
        "with this shape:\n"
        "{\"action\":\"call_tool\",\"tool_name\":\"<registered tool>\","
        "\"arguments\":{},\"rationale\":\"short reason\"}\n\n"
        "Rules:\n"
        "- action must be \"call_tool\".\n"
        "- tool_name must exactly match one registered tool below.\n"
        "- arguments must satisfy that tool's schema.\n"
        "- rationale is diagnostic only and is not evidence.\n"
        "- Return no markdown, no prose, and no OpenAI tool_calls.\n\n"
        f"Current task/context excerpt:\n{context}\n\n"
        f"Registered tools:\n{rendered_tools}"
    )
    if len(instruction) > _TOOL_INTENT_TOTAL_LIMIT:
        instruction = instruction[: _TOOL_INTENT_TOTAL_LIMIT - 80] + "\n...[ToolIntent prompt truncated]"
    return [{"role": "user", "content": instruction}]


def _compact_context_excerpt(messages: list[dict]) -> str:
    chunks: list[str] = []
    for message in reversed(messages):
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            continue
        chunks.append(content.strip())
        if sum(len(chunk) for chunk in chunks) >= _TOOL_INTENT_CONTEXT_LIMIT:
            break
    joined = "\n\n".join(reversed(chunks))
    if not joined:
        return "(no prior context)"
    return _head_tail(joined, _TOOL_INTENT_CONTEXT_LIMIT)


def _render_compact_tool_catalog(tools_schema: list[dict]) -> str:
    rendered: list[str] = []
    for tool in tools_schema or []:
        function = tool.get("function") if isinstance(tool, dict) else None
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name:
            continue
        params = function.get("parameters") if isinstance(function.get("parameters"), dict) else {}
        properties = params.get("properties") if isinstance(params, dict) else {}
        required = params.get("required") if isinstance(params, dict) else []
        arg_bits: list[str] = []
        if isinstance(properties, dict):
            for arg_name, arg_schema in properties.items():
                if not isinstance(arg_name, str):
                    continue
                arg_type = "any"
                if isinstance(arg_schema, dict) and isinstance(arg_schema.get("type"), str):
                    arg_type = arg_schema["type"]
                marker = "*" if isinstance(required, list) and arg_name in required else ""
                arg_bits.append(f"{arg_name}{marker}:{arg_type}")
        rendered.append(f"- {name}({', '.join(arg_bits)})")
    return "\n".join(rendered) if rendered else "(no registered tools)"


def _head_tail(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    head = max(0, limit // 2 - 20)
    tail = max(0, limit - head - 40)
    return f"{value[:head]}\n...[truncated]...\n{value[-tail:]}"
