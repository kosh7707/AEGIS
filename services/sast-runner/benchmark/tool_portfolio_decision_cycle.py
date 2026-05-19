from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

FORBIDDEN_IMPORT_PATTERNS = (
    re.compile(r"^\s*import\s+(requests|httpx|socket|urllib|openai)\b", re.MULTILINE),
    re.compile(r"^\s*from\s+(requests|httpx|socket|urllib|openai)\b", re.MULTILINE),
)
FORBIDDEN_CALL_PATTERNS = (
    re.compile(r"/v1/cve"),
    re.compile(r"knowledge-base"),
    re.compile(r"GraphRAG", re.IGNORECASE),
    re.compile(r"llm", re.IGNORECASE),
)


def stable_json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def checksum_json(value: Any) -> str:
    return "sha256:" + sha256(stable_json_dumps(value).encode("utf-8")).hexdigest()


def build_decision_cycle_lock(
    *,
    decision_cycle_id: str,
    phase: str,
    corpus_manifest: Mapping[str, Any],
    matching_policy: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    split_assignments: Mapping[str, Any],
    rulesets: Mapping[str, Any],
    tool_versions: Mapping[str, Any],
    tool_paths: Mapping[str, Any],
    timeout_config: Mapping[str, Any],
    environment_summary: Mapping[str, Any],
    lockfile: Mapping[str, Any],
) -> dict[str, Any]:
    if phase not in {"validation", "test", "canary"}:
        raise ValueError("phase must be validation, test, or canary")
    return {
        "decisionCycleId": decision_cycle_id,
        "phase": phase,
        "frozen": True,
        "corpusManifestChecksum": checksum_json(corpus_manifest),
        "matchingPolicyChecksum": checksum_json(matching_policy),
        "thresholdsChecksum": checksum_json(thresholds),
        "splitAssignmentChecksum": checksum_json(split_assignments),
        "rulesetChecksums": {key: checksum_json(value) for key, value in sorted(rulesets.items())},
        "toolVersions": dict(sorted(tool_versions.items())),
        "toolPaths": dict(sorted(tool_paths.items())),
        "timeoutConfig": dict(timeout_config),
        "environmentSummary": dict(environment_summary),
        "lockfileChecksum": checksum_json(lockfile),
    }


def assert_test_phase_not_drifted(
    lock: Mapping[str, Any],
    *,
    corpus_manifest: Mapping[str, Any],
    matching_policy: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    split_assignments: Mapping[str, Any],
) -> None:
    checks = {
        "corpusManifestChecksum": checksum_json(corpus_manifest),
        "matchingPolicyChecksum": checksum_json(matching_policy),
        "thresholdsChecksum": checksum_json(thresholds),
        "splitAssignmentChecksum": checksum_json(split_assignments),
    }
    for key, current in checks.items():
        if lock.get(key) != current:
            raise ValueError(f"{key} drift detected after decision-cycle freeze")


def assert_no_forbidden_runtime_coupling(paths: Iterable[Path]) -> dict[str, Any]:
    checked = 0
    violations: list[dict[str, str]] = []
    for path in paths:
        checked += 1
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_IMPORT_PATTERNS:
            if pattern.search(text):
                violations.append({"file": str(path), "pattern": pattern.pattern})
        # Call-pattern scan ignores explicit documentation strings in this guard module.
        if path.name != "tool_portfolio_decision_cycle.py":
            for pattern in FORBIDDEN_CALL_PATTERNS:
                if pattern.search(text):
                    violations.append({"file": str(path), "pattern": pattern.pattern})
    if violations:
        raise ValueError("forbidden runtime coupling detected")
    return {"status": "pass", "checkedFiles": checked, "violations": []}
