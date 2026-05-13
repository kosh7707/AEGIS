"""Canonical serving query planner for S5 Judge re-query controls."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.judge.models import JudgeQueryRequest

SCHEMA_VERSION = "s5-canonical-query-v1"
SUPPORTED_PREFER = {"sourceCodeKg", "localReachability", "targetContext", "threatKb", "freshEvidence"}
SUPPORTED_ANSWER_MODES = {"evidence_grounded", "alternatives_without_excluded", "strict_target_context", "exploratory_context"}
KNOWN_CONTROL_KEYS = {"exclude", "prefer", "forceContext", "answerMode"}
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


def _canonical(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(prefix: str, payload: Any) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(payload).encode('utf-8')).hexdigest()[:16]}"


def _request_dict(request: "JudgeQueryRequest | dict[str, Any]") -> dict[str, Any]:
    if hasattr(request, "model_dump"):
        return request.model_dump(by_alias=True)
    return dict(request or {})


def _terms(question: str | None) -> list[str]:
    tokens = re.findall(r"[a-z0-9_.:+-]+", (question or "").lower())
    return sorted({token for token in tokens if token and token not in STOPWORDS})


def _controls(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    controls = raw.get("controls") or {}
    if not isinstance(controls, dict):
        controls = {}
    answer_mode = _clean_string(controls.get("answerMode"))
    requested = {
        "exclude": sorted({item for item in (normalize_control_identifier(value) for value in controls.get("exclude", [])) if item}),
        "prefer": _clean_list(controls.get("prefer", [])),
        "forceContext": controls.get("forceContext") or {},
        "answerMode": answer_mode,
    }
    accepted = {
        "exclude": requested["exclude"],
        "prefer": [item for item in requested["prefer"] if item in SUPPORTED_PREFER],
        "forceContext": requested["forceContext"] if isinstance(requested["forceContext"], dict) else {},
        "answerMode": requested["answerMode"] if requested["answerMode"] in SUPPORTED_ANSWER_MODES else None,
    }
    rejected = []
    ignored = []
    for key in sorted(set(controls) - KNOWN_CONTROL_KEYS):
        rejected.append({"control": key, "value": controls.get(key), "reason": "unsupported_control"})
    for item in requested["prefer"]:
        if item not in SUPPORTED_PREFER:
            rejected.append({"control": "prefer", "value": item, "reason": "unsupported_preference"})
    if requested["forceContext"] and not isinstance(requested["forceContext"], dict):
        rejected.append({"control": "forceContext", "value": requested["forceContext"], "reason": "forceContext_must_be_object"})
    if requested["answerMode"] and requested["answerMode"] not in SUPPORTED_ANSWER_MODES:
        rejected.append({"control": "answerMode", "value": requested["answerMode"], "reason": "unsupported_answer_mode"})
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
        "questionTerms": _terms(raw.get("question")),
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
