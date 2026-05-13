"""Small deterministic in-process decision-fragment cache for S5 serving."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

_CACHE: dict[str, dict[str, Any]] = {}


def reset_decision_cache() -> None:
    _CACHE.clear()


def get_decision_fragment(key: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if key in _CACHE:
        return deepcopy(_CACHE[key]), {"schemaVersion": "s5-decision-cache-trace-v1", "decisionFragmentKey": key, "hit": True, "miss": False, "stored": False, "reason": "decision_fragment_cache_hit"}
    return None, {"schemaVersion": "s5-decision-cache-trace-v1", "decisionFragmentKey": key, "hit": False, "miss": True, "stored": False, "reason": "decision_fragment_cache_miss"}


def store_decision_fragment(key: str, fragment: dict[str, Any], trace: dict[str, Any] | None = None) -> dict[str, Any]:
    _CACHE[key] = deepcopy(fragment)
    if trace is None:
        trace = {"schemaVersion": "s5-decision-cache-trace-v1", "decisionFragmentKey": key, "hit": False, "miss": True, "stored": True, "reason": "decision_fragment_stored"}
    else:
        trace = {**trace, "stored": True, "reason": "decision_fragment_stored_after_miss"}
    return trace
