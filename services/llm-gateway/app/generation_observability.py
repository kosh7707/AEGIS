"""Shared generation-control observability helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


_CONTROL_KEYS = (
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "presence_penalty",
    "repetition_penalty",
    "seed",
    "logprobs",
    "top_logprobs",
    "tool_choice",
    "response_format",
    "structured_outputs",
)


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(value: Any) -> str:
    """Return a deterministic sha256 hash for audit snapshots."""

    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def effective_enable_thinking(
    body: dict[str, Any],
) -> bool | None:
    """Return the caller-supplied Qwen thinking flag for a forwarded request body."""

    chat_template_kwargs = body.get("chat_template_kwargs")
    if not isinstance(chat_template_kwargs, dict):
        return None
    value = chat_template_kwargs.get("enable_thinking")
    return value if isinstance(value, bool) else None


def effective_preserve_thinking(body: dict[str, Any]) -> bool | None:
    """Return the caller-supplied Qwen preserve_thinking flag."""

    chat_template_kwargs = body.get("chat_template_kwargs")
    if not isinstance(chat_template_kwargs, dict):
        return None
    value = chat_template_kwargs.get("preserve_thinking")
    return value if isinstance(value, bool) else None


def generation_log_fields(
    body: dict[str, Any],
    *,
    task_type: str | None = None,
) -> dict[str, Any]:
    """Build the low-cardinality generation tuple used by logs and metrics."""

    return {
        "maxTokens": body.get("max_tokens"),
        "temperature": body.get("temperature"),
        "topP": body.get("top_p"),
        "topK": body.get("top_k"),
        "minP": body.get("min_p"),
        "presencePenalty": body.get("presence_penalty"),
        "repetitionPenalty": body.get("repetition_penalty"),
        "enableThinking": effective_enable_thinking(body),
        "taskType": task_type,
    }


def normalize_tool_choice(value: Any) -> str:
    """Bucket OpenAI-compatible tool_choice into bounded Prometheus labels."""

    if value is None:
        return "none"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"auto", "required", "none"}:
            return normalized
        return "named" if normalized else "none"
    if isinstance(value, dict):
        return "named"
    return "none"


def schema_snapshot(body: dict[str, Any]) -> Any | None:
    """Return only schema-related request controls for hashing."""

    if isinstance(body.get("response_format"), dict):
        return {"response_format": body["response_format"]}
    if isinstance(body.get("structured_outputs"), dict):
        return {"structured_outputs": body["structured_outputs"]}
    return None


def redacted_body_summary(body: dict[str, Any]) -> dict[str, Any]:
    """Return a prompt/schema/seed-redacted request summary for paper audit logs."""

    summary: dict[str, Any] = {
        "model": body.get("model"),
        "messageCount": len(body.get("messages", [])) if isinstance(body.get("messages"), list) else None,
        "toolCount": len(body.get("tools", [])) if isinstance(body.get("tools"), list) else 0,
        "hasResponseFormat": "response_format" in body,
        "hasStructuredOutputs": "structured_outputs" in body,
        "controlKeys": sorted(key for key in _CONTROL_KEYS if key in body),
    }
    if "seed" in body:
        summary["seedHash"] = stable_hash({"seed": body.get("seed")})
    schema = schema_snapshot(body)
    if schema is not None:
        summary["schemaSnapshotHash"] = stable_hash(schema)
    return summary


def response_summary(response_data: Any) -> dict[str, Any]:
    """Return a content-redacted response summary for paper audit logs."""

    if not isinstance(response_data, dict):
        return {"type": type(response_data).__name__}
    choices = response_data.get("choices") if isinstance(response_data.get("choices"), list) else []
    first = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    return {
        "choiceCount": len(choices),
        "finishReason": first.get("finish_reason"),
        "usage": response_data.get("usage"),
        "hasMessageContent": isinstance(message.get("content"), str) and bool(message.get("content")),
        "hasReasoning": bool(message.get("reasoning")),
        "hasLogprobs": first.get("logprobs") is not None,
    }


def _control_summary(body: dict[str, Any]) -> dict[str, Any]:
    chat_template_kwargs = body.get("chat_template_kwargs")
    summary = {
        "maxTokens": body.get("max_tokens"),
        "temperature": body.get("temperature"),
        "topP": body.get("top_p"),
        "topK": body.get("top_k"),
        "minP": body.get("min_p"),
        "presencePenalty": body.get("presence_penalty"),
        "repetitionPenalty": body.get("repetition_penalty"),
        "logprobs": body.get("logprobs"),
        "topLogprobs": body.get("top_logprobs"),
        "toolChoice": body.get("tool_choice"),
        "toolCount": len(body.get("tools", [])) if isinstance(body.get("tools"), list) else 0,
        "hasSchema": schema_snapshot(body) is not None,
    }
    if isinstance(chat_template_kwargs, dict):
        summary["enableThinking"] = chat_template_kwargs.get("enable_thinking")
        summary["preserveThinking"] = chat_template_kwargs.get("preserve_thinking")
    if "seed" in body:
        summary["seedHash"] = stable_hash({"seed": body.get("seed")})
    return summary


def _control_diff(accepted_body: dict[str, Any], forwarded_body: dict[str, Any]) -> dict[str, Any]:
    keys = set(_CONTROL_KEYS) | {"chat_template_kwargs", "tools", "model"}
    added = sorted(key for key in keys if key not in accepted_body and key in forwarded_body)
    dropped = sorted(key for key in keys if key in accepted_body and key not in forwarded_body)
    overwritten = sorted(
        key
        for key in keys
        if key in accepted_body and key in forwarded_body and accepted_body.get(key) != forwarded_body.get(key)
    )
    return {"added": added, "dropped": dropped, "overwritten": overwritten}


def control_observability(
    *,
    accepted_body: dict[str, Any],
    forwarded_body: dict[str, Any],
    response_data: Any,
    request_id: str,
    async_request_id: str | None,
    trace_request_id: str | None,
    paper_controls: bool,
    paper_phase: str | None,
    strict_json: bool,
    profile_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build prompt-redacted paper-control audit evidence for exchange logs."""

    schema = schema_snapshot(forwarded_body)
    resp_summary = response_summary(response_data)
    accepted = _control_summary(accepted_body)
    forwarded = _control_summary(forwarded_body)
    observed = {
        "finishReason": resp_summary.get("finishReason"),
        "logprobsReturned": resp_summary.get("hasLogprobs"),
        "schemaValidationApplied": bool(schema) and paper_phase == "finalizer",
        "effectiveThinking": effective_enable_thinking(forwarded_body),
        "preserveThinkingForwarded": effective_preserve_thinking(forwarded_body),
    }
    body_summary = redacted_body_summary(forwarded_body)
    output = {
        "paperControls": paper_controls,
        "paperPhase": paper_phase,
        "requestId": request_id,
        "asyncRequestId": async_request_id,
        "traceRequestId": trace_request_id or request_id,
        "acceptedControls": accepted,
        "forwardedControls": forwarded,
        "controlDiff": _control_diff(accepted_body, forwarded_body),
        "observedControls": observed,
        "knownIneffectiveOrUnverified": [
            "seed_reproducibility_online_serving",
            "min_p_effective_sampling",
            "preserve_thinking_external_effect",
            "mtp_nondeterminism",
        ],
        "requestControlSnapshotHash": stable_hash({"accepted": accepted, "forwarded": forwarded}),
        "redactedBodyHash": stable_hash(body_summary),
        "responseSummaryHash": stable_hash(resp_summary),
        "schemaSnapshotHash": stable_hash(schema) if schema is not None else None,
        "profileSnapshotHash": stable_hash(profile_snapshot or {}),
    }
    return output
