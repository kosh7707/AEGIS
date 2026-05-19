"""Canonical serving query planner for S5 Judge re-query controls."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from app.config import redact_url_for_log, redact_urls_in_text_for_log
from app.graphrag.retrieval_policy import clamp_top_k

if TYPE_CHECKING:
    from app.judge.models import JudgeQueryRequest

SCHEMA_VERSION = "s5-canonical-query-v1"
SUPPORTED_PREFER = {"sourceCodeKg", "localReachability", "targetContext", "threatKb", "freshEvidence"}
SUPPORTED_ANSWER_MODES = {"evidence_grounded", "alternatives_without_excluded", "strict_target_context", "exploratory_context"}
KNOWN_CONTROL_KEYS = {"exclude", "prefer", "forceContext", "answerMode", "topK"}
MAX_CONTROL_VALUE_ECHO_CHARS = 512
MAX_CONTROL_LIST_ITEMS = 128
CONTROL_LIST_TOO_LONG_REASON = "control_list_too_long"
MAX_FORCE_CONTEXT_ROOT_KEYS = 128
MAX_FORCE_CONTEXT_TOTAL_ITEMS = 512
MAX_FORCE_CONTEXT_ECHO_BYTES = 16_384
MAX_FORCE_CONTEXT_DEPTH = 8
MAX_UNSUPPORTED_CONTROL_ECHO_ITEMS = 128
MAX_CONTROL_ECHO_TOTAL_ITEMS = 512
MAX_CONTROL_ECHO_BYTES = 16_384
CONTROL_OBJECT_TOO_LARGE_REASON = "control_object_too_large"
STOPWORDS = {
    "a", "an", "and", "are", "as", "for", "in", "is", "it", "of", "or", "the", "this", "to", "with",
    "does", "do", "give", "if", "me", "please", "tell", "current", "target", "build",
}


def _clean_string(value: Any, *, lower: bool = False) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if not cleaned:
        return None
    return cleaned.lower() if lower else cleaned


def normalize_control_identifier(value: Any) -> str | None:
    """Normalize CVE/advisory control identifiers for keying and suppression.

    Control IDs are treated as protocol identifiers, not natural-language text.
    Whitespace and case must not allow excluded evidence to reappear.
    """

    cleaned = _clean_string(value)
    return cleaned.upper() if cleaned else None


def _clean_list(values: Any, *, upper: bool = False) -> list[str]:
    cleaned: list[str] = []
    for value in values or []:
        item = _clean_string(value)
        if item:
            cleaned.append(item.upper() if upper else item)
    return cleaned


def _has_oversized_string(value: Any) -> bool:
    if isinstance(value, str):
        return len(value) > MAX_CONTROL_VALUE_ECHO_CHARS
    if isinstance(value, list):
        return any(_has_oversized_string(item) for item in value)
    if isinstance(value, dict):
        return any(len(str(key)) > MAX_CONTROL_VALUE_ECHO_CHARS or _has_oversized_string(item) for key, item in value.items())
    return False


def _walk_force_context_budget(value: Any, *, depth: int = 0) -> tuple[int, int]:
    if isinstance(value, dict):
        item_count = len(value)
        max_depth = depth
        for item in value.values():
            child_count, child_depth = _walk_force_context_budget(item, depth=depth + 1)
            item_count += child_count
            max_depth = max(max_depth, child_depth)
        return item_count, max_depth
    if isinstance(value, list):
        item_count = len(value)
        max_depth = depth
        for item in value:
            child_count, child_depth = _walk_force_context_budget(item, depth=depth + 1)
            item_count += child_count
            max_depth = max(max_depth, child_depth)
        return item_count, max_depth
    return 0, depth


def force_context_budget(value: Any) -> dict[str, int]:
    """Return bounded echo/cardinality metrics for forceContext controls.

    Oversized strings are measured after the standard redaction transform so
    already-safe large-string rejections remain soft, while many small values
    cannot inflate response or serving-ledger packets.
    """

    if not isinstance(value, dict):
        return {"rootKeys": 0, "totalItems": 0, "maxDepth": 0, "echoBytes": 0}
    sanitized = sanitize_large_echo_value(value)
    encoded = json.dumps(
        sanitized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    total_items, max_depth = _walk_force_context_budget(value)
    return {
        "rootKeys": len(value),
        "totalItems": total_items,
        "maxDepth": max_depth,
        "echoBytes": len(encoded),
    }


def force_context_budget_too_large(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    budget = force_context_budget(value)
    return (
        budget["rootKeys"] > MAX_FORCE_CONTEXT_ROOT_KEYS
        or budget["totalItems"] > MAX_FORCE_CONTEXT_TOTAL_ITEMS
        or budget["maxDepth"] > MAX_FORCE_CONTEXT_DEPTH
        or budget["echoBytes"] > MAX_FORCE_CONTEXT_ECHO_BYTES
    )


def summarize_force_context_budget(value: Any) -> dict[str, Any]:
    return {
        "redacted": True,
        "type": "object",
        "reason": CONTROL_OBJECT_TOO_LARGE_REASON,
        "budget": force_context_budget(value),
    }


def _echo_container_too_large(value: Any) -> bool:
    if not isinstance(value, (dict, list)):
        return False
    total_items, max_depth = _walk_force_context_budget(value)
    return (
        len(value) > MAX_UNSUPPORTED_CONTROL_ECHO_ITEMS
        or total_items > MAX_CONTROL_ECHO_TOTAL_ITEMS
        or max_depth > MAX_FORCE_CONTEXT_DEPTH
        or _echo_container_bytes(value) > MAX_CONTROL_ECHO_BYTES
    )


def _echo_container_bytes(value: Any) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    )


def summarize_large_echo_container(value: Any) -> dict[str, Any]:
    return {
        "redacted": True,
        "type": "list" if isinstance(value, list) else "object",
        "length": len(value) if isinstance(value, (dict, list)) else 0,
        "reason": CONTROL_OBJECT_TOO_LARGE_REASON,
    }


def _clean_control_values(values: Any, *, upper: bool = False) -> tuple[list[Any], list[str], list[Any]]:
    requested: list[Any] = []
    accepted: list[str] = []
    oversized: list[Any] = []
    for value in values or []:
        item = _clean_string(value)
        if not item:
            continue
        if len(item) > MAX_CONTROL_VALUE_ECHO_CHARS:
            redacted = sanitize_large_echo_value(item)
            requested.append(redacted)
            oversized.append(redacted)
            continue
        normalized = item.upper() if upper else item
        safe_normalized = sanitize_large_echo_value(normalized)
        requested.append(safe_normalized)
        accepted.append(safe_normalized)
    return requested, accepted, oversized


def _clean_top_k(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            parsed = int(stripped)
            return parsed if parsed >= 1 else None
    return None


def sanitize_large_echo_value(value: Any) -> Any:
    """Bound echoed user values so invalid controls cannot bloat answers/ledger rows."""

    if isinstance(value, str):
        redacted = redact_urls_in_text_for_log(value)
        if len(redacted) > MAX_CONTROL_VALUE_ECHO_CHARS:
            return {"redacted": True, "type": "str", "length": len(value)}
        return redacted
    if _echo_container_too_large(value):
        return summarize_large_echo_container(value)
    if isinstance(value, list):
        return [sanitize_large_echo_value(item) for item in value]
    if isinstance(value, dict):
        return {sanitize_large_echo_key(key): sanitize_large_echo_value(item) for key, item in value.items()}
    return value


def sanitize_large_echo_key(key: Any) -> str:
    item = redact_urls_in_text_for_log(str(key))
    if len(item) > MAX_CONTROL_VALUE_ECHO_CHARS:
        return f"<redacted-key:{len(item)}>"
    return item


def sanitize_control_label(key: Any) -> Any:
    item = redact_urls_in_text_for_log(str(key))
    if len(item) > MAX_CONTROL_VALUE_ECHO_CHARS:
        return {"redacted": True, "type": "control", "length": len(item)}
    return item


def _canonical(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(prefix: str, payload: Any) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(payload).encode('utf-8')).hexdigest()[:16]}"


def _request_dict(request: "JudgeQueryRequest | dict[str, Any]") -> dict[str, Any]:
    if hasattr(request, "model_dump"):
        return request.model_dump(by_alias=True, warnings=False)
    return dict(request or {})


def _terms(question: str | None) -> list[str]:
    tokens = re.findall(r"[a-z0-9_.:+-]+", (question or "").lower())
    return sorted({token for token in tokens if token and token not in STOPWORDS})


def _controls(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    controls = raw.get("controls") or {}
    if not isinstance(controls, dict):
        controls = {}
    answer_mode = _clean_string(controls.get("answerMode"))
    answer_mode_oversized = bool(answer_mode and len(answer_mode) > MAX_CONTROL_VALUE_ECHO_CHARS)
    top_k_requested = controls.get("topK") not in (None, "")
    top_k = _clean_top_k(controls.get("topK"))
    requested_exclude, accepted_exclude, oversized_exclude = _clean_control_values(controls.get("exclude", []), upper=True)
    requested_prefer, cleaned_prefer, oversized_prefer = _clean_control_values(controls.get("prefer", []))
    force_context_requested = controls.get("forceContext") or {}
    force_context_oversized = _has_oversized_string(force_context_requested)
    force_context_too_large = force_context_budget_too_large(force_context_requested)
    force_context_requested_echo = (
        summarize_force_context_budget(force_context_requested)
        if force_context_too_large
        else sanitize_large_echo_value(force_context_requested)
    )
    requested = {
        "exclude": sorted(requested_exclude, key=lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True)),
        "prefer": requested_prefer,
        "forceContext": force_context_requested_echo,
        "answerMode": sanitize_large_echo_value(answer_mode) if answer_mode_oversized else answer_mode,
    }
    accepted = {
        "exclude": sorted(set(accepted_exclude)),
        "prefer": [item for item in cleaned_prefer if item in SUPPORTED_PREFER],
        "forceContext": sanitize_large_echo_value(force_context_requested)
        if isinstance(force_context_requested, dict) and not force_context_oversized and not force_context_too_large
        else {},
        "answerMode": answer_mode if answer_mode in SUPPORTED_ANSWER_MODES and not answer_mode_oversized else None,
    }
    if top_k_requested:
        requested["topK"] = top_k if top_k is not None else sanitize_large_echo_value(controls.get("topK"))
        if top_k is not None:
            accepted["topK"] = clamp_top_k(top_k)
    rejected = []
    ignored = []
    for key in sorted(set(controls) - KNOWN_CONTROL_KEYS, key=str):
        rejected.append({"control": sanitize_control_label(key), "value": sanitize_large_echo_value(controls.get(key)), "reason": "unsupported_control"})
    for item in oversized_exclude:
        rejected.append({"control": "exclude", "value": item, "reason": "control_value_too_long"})
    for item in cleaned_prefer:
        if item not in SUPPORTED_PREFER:
            rejected.append({"control": "prefer", "value": sanitize_large_echo_value(item), "reason": "unsupported_preference"})
    for item in oversized_prefer:
        rejected.append({"control": "prefer", "value": item, "reason": "control_value_too_long"})
    if force_context_requested and not isinstance(force_context_requested, dict):
        rejected.append({"control": "forceContext", "value": sanitize_large_echo_value(force_context_requested), "reason": "forceContext_must_be_object"})
    elif force_context_too_large:
        rejected.append({"control": "forceContext", "value": force_context_requested_echo, "reason": CONTROL_OBJECT_TOO_LARGE_REASON})
    elif force_context_oversized:
        rejected.append({"control": "forceContext", "value": sanitize_large_echo_value(force_context_requested), "reason": "control_value_too_long"})
    if answer_mode and answer_mode_oversized:
        rejected.append({"control": "answerMode", "value": sanitize_large_echo_value(answer_mode), "reason": "control_value_too_long"})
    elif answer_mode and answer_mode not in SUPPORTED_ANSWER_MODES:
        rejected.append({"control": "answerMode", "value": sanitize_large_echo_value(answer_mode), "reason": "unsupported_answer_mode"})
    if top_k_requested and top_k is None:
        rejected.append({"control": "topK", "value": sanitize_large_echo_value(controls.get("topK")), "reason": "topK_must_be_integer"})
    if requested["answerMode"] is None:
        ignored.append({"control": "answerMode", "reason": "not_requested"})
    return {
        "requested": requested,
        "accepted": accepted,
        "rejected": rejected,
        "ignored": ignored,
    }, accepted


def build_canonical_query(request: "JudgeQueryRequest | dict[str, Any]") -> dict[str, Any]:
    raw = _request_dict(request)
    component = raw.get("component") or {}
    source_context = raw.get("sourceContext") or {}
    control_summary, accepted_controls = _controls(raw)
    normalized = {
        "component": {
            "name": _clean_string(component.get("name"), lower=True),
            "version": _clean_string(component.get("version")),
            "purl": _clean_string(component.get("purl")),
            "packageIdentityId": _clean_string(component.get("packageIdentityId")),
            "cpe": _clean_string(component.get("cpe")),
            "repoUrl": _clean_string(component.get("repoUrl")),
            "sourceComponentId": _clean_string(component.get("sourceComponentId")),
        },
        "sourceContext": {
            "repositorySnapshotId": _clean_string(source_context.get("repositorySnapshotId")),
            "buildContextId": _clean_string(source_context.get("buildContextId")),
            "analysisArtifactSetId": _clean_string(source_context.get("analysisArtifactSetId")),
            "graphNodeIds": sorted(_clean_list(source_context.get("graphNodeIds") or [])),
            "evidenceSnippetIds": sorted(_clean_list(source_context.get("evidenceSnippetIds") or [])),
            "richIrArtifactIds": sorted(_clean_list(source_context.get("richIrArtifactIds") or [])),
        },
        "controls": accepted_controls,
        "questionTerms": _terms(redact_urls_in_text_for_log(raw.get("question"))),
        "answerMode": accepted_controls.get("answerMode") or "evidence_grounded",
    }
    canonical_query_id = _digest("canonical-query", normalized)
    decision_fragment = {
        "component": normalized["component"],
        "sourceContext": normalized["sourceContext"],
        "controls": accepted_controls,
        "answerMode": normalized["answerMode"],
    }
    return {
        "schemaVersion": SCHEMA_VERSION,
        "canonicalQueryId": canonical_query_id,
        "decisionFragmentKey": _digest("decision-fragment", decision_fragment),
        "normalized": normalized,
        "controlSummary": control_summary,
    }
