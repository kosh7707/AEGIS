from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping

from app.scanner.orchestrator import ALL_TOOLS
from benchmark.tool_portfolio_acquisition_manifest import build_acquisition_index

CORPUS_SCHEMA_VERSION = "s4-tool-portfolio-experiment-corpus-v1"
TRACKED_CWES = [
    "CWE-78",
    "CWE-121",
    "CWE-122",
    "CWE-134",
    "CWE-190",
    "CWE-252",
    "CWE-369",
    "CWE-401",
    "CWE-416",
    "CWE-457",
    "CWE-476",
    "CWE-680",
]
SLICE_KINDS = {
    "s4-canary",
    "juliet-controlled-positive",
    "juliet-controlled-negative",
    "sard-focused",
    "real-cve-pair",
    "build-context-required",
    "parser-regression",
    "s4-harness-fixture-positive",
    "s4-harness-fixture-negative",
}
EXTERNAL_SLICE_KINDS = {
    "juliet-controlled-positive",
    "juliet-controlled-negative",
    "sard-focused",
    "real-cve-pair",
    "s4-harness-fixture-positive",
    "s4-harness-fixture-negative",
}
SPLITS = {"validation", "test", "canary"}
FORBIDDEN_VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}
FUTURE_CONFIG_PREFIXES = ("upgrade-ab:", "ruleset-ab:", "add-one-in:", "remove-candidate:")


def required_current_six_configs() -> list[str]:
    return (
        ["full-current-six"]
        + [f"single-tool:{tool}" for tool in ALL_TOOLS]
        + [f"leave-one-out:{tool}" for tool in ALL_TOOLS]
        + ["parser-only-current-six", "contract-canary-current-six"]
    )


def validate_tool_set_config(config: str, *, allow_future: bool = False) -> dict[str, Any]:
    if config == "full-current-six":
        return {"status": "pass", "toolSetConfig": config, "tools": list(ALL_TOOLS), "kind": "full"}
    if config == "parser-only-current-six":
        return {"status": "pass", "toolSetConfig": config, "tools": [], "kind": "parser-only"}
    if config == "contract-canary-current-six":
        return {"status": "pass", "toolSetConfig": config, "tools": list(ALL_TOOLS), "kind": "contract-canary"}
    if config.startswith("single-tool:"):
        tool = config.split(":", 1)[1]
        if tool not in ALL_TOOLS:
            raise ValueError(f"unknown current S4 tool: {tool}")
        return {"status": "pass", "toolSetConfig": config, "tools": [tool], "kind": "single-tool"}
    if config.startswith("leave-one-out:"):
        tool = config.split(":", 1)[1]
        if tool not in ALL_TOOLS:
            raise ValueError(f"unknown current S4 tool: {tool}")
        return {"status": "pass", "toolSetConfig": config, "tools": [item for item in ALL_TOOLS if item != tool], "kind": "leave-one-out"}
    if config.startswith(FUTURE_CONFIG_PREFIXES):
        if not allow_future:
            raise ValueError(f"future WR-gated tool-set config is disabled for Milestone 1: {config}")
        return {"status": "pass", "toolSetConfig": config, "tools": [], "kind": "future-wr-gated"}
    raise ValueError(f"unknown tool-set config: {config}")


def validate_corpus_manifest(
    manifest: Mapping[str, Any],
    *,
    acquisition_index: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("corpus manifest must be an object")
    data = dict(manifest)
    _reject_forbidden_keys(data)
    if data.get("schemaVersion") != CORPUS_SCHEMA_VERSION:
        raise ValueError(f"schemaVersion must be {CORPUS_SCHEMA_VERSION!r}")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a non-empty list")
    if acquisition_index is None:
        acquisition_index = {}
    else:
        acquisition_index = dict(acquisition_index)

    seen_case_ids: set[str] = set()
    split_counts: Counter[str] = Counter()
    slice_counts: Counter[str] = Counter()
    lineage_splits: dict[str, set[str]] = defaultdict(set)
    target_rows: list[dict[str, Any]] = []

    for idx, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise ValueError(f"cases[{idx}] must be an object")
        case_id = _require_non_empty_string(case, "caseId", context=f"cases[{idx}]")
        if case_id in seen_case_ids:
            raise ValueError(f"duplicate caseId: {case_id}")
        seen_case_ids.add(case_id)
        split = _require_member(case, "split", SPLITS, context=case_id)
        slice_kind = _require_member(case, "sliceKind", SLICE_KINDS, context=case_id)
        split_counts[split] += 1
        slice_counts[slice_kind] += 1
        lineage_id = case.get("lineageId") or case.get("sourceRef") or case_id
        if not isinstance(lineage_id, str) or not lineage_id:
            raise ValueError(f"{case_id}.lineageId must be a non-empty string when provided")
        lineage_splits[lineage_id].add(split)
        _validate_case_checksum(case, case_id)
        if slice_kind in EXTERNAL_SLICE_KINDS:
            _validate_acquisition_linkage(case, acquisition_index, case_id)
        expected = case.get("expected")
        if not isinstance(expected, Mapping):
            raise ValueError(f"{case_id}.expected must be an object")
        _validate_expected(expected, case_id)
        target_rows.append(_target_row(case, expected))

    for lineage_id, splits in lineage_splits.items():
        if "validation" in splits and "test" in splits:
            raise ValueError(f"lineage leakage across validation/test: {lineage_id}")

    tracked = list(data.get("trackedCwes") or TRACKED_CWES)
    if tracked != TRACKED_CWES:
        raise ValueError("trackedCwes must match the fixed S4 experiment tracked CWE set")

    return {
        "schemaVersion": CORPUS_SCHEMA_VERSION,
        "status": "pass",
        "profile": data.get("profile"),
        "trackedCwes": TRACKED_CWES,
        "caseCount": len(cases),
        "splitCounts": dict(sorted(split_counts.items())),
        "sliceCounts": dict(sorted(slice_counts.items())),
        "targets": target_rows,
    }


def corpus_targets(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [_target_row(case, case.get("expected", {})) for case in manifest.get("cases", []) if isinstance(case, Mapping)]


def _target_row(case: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "caseId": case.get("caseId"),
        "targetId": expected.get("targetId") or case.get("targetId") or case.get("caseId"),
        "lineageId": case.get("lineageId") or case.get("sourceRef") or case.get("caseId"),
        "sliceKind": case.get("sliceKind"),
        "split": case.get("split"),
        "sourceArtifact": case.get("sourceArtifact"),
        "sourcePath": case.get("sourcePath"),
        "expected": dict(expected),
    }


def _validate_case_checksum(case: Mapping[str, Any], case_id: str) -> None:
    checksum = case.get("checksum")
    if not isinstance(checksum, str) or not checksum.startswith("sha256:"):
        raise ValueError(f"{case_id}.checksum must be sha256-prefixed")


def _validate_acquisition_linkage(
    case: Mapping[str, Any],
    acquisition_index: Mapping[str, Mapping[str, Any]],
    case_id: str,
) -> None:
    acquisition_id = _require_non_empty_string(case, "acquisitionId", context=case_id)
    acquisition_checksum = _require_non_empty_string(case, "acquisitionManifestChecksum", context=case_id)
    _require_non_empty_string(case, "sourceRef", context=case_id)
    if acquisition_id not in acquisition_index:
        raise ValueError(f"{case_id}: acquisitionId not found in acquisition index: {acquisition_id}")
    expected_checksum = acquisition_index[acquisition_id].get("manifestChecksum")
    if acquisition_checksum != expected_checksum:
        raise ValueError(f"{case_id}: acquisition checksum mismatch for {acquisition_id}")


def _validate_expected(expected: Mapping[str, Any], case_id: str) -> None:
    target_id = _require_non_empty_string(expected, "targetId", context=f"{case_id}.expected")
    del target_id
    polarity = _require_member(expected, "polarity", {"positive", "negative"}, context=f"{case_id}.expected")
    _require_non_empty_string(expected, "granularity", context=f"{case_id}.expected")
    if polarity == "positive":
        _require_non_empty_string(expected, "cweId", context=f"{case_id}.expected")
        if not expected.get("locations") and not expected.get("functionRegion"):
            raise ValueError(f"{case_id}.expected positive target needs locations or functionRegion")
    else:
        if not expected.get("functionRegion") and not expected.get("locations"):
            raise ValueError(f"{case_id}.expected negative target needs region metadata")
        policy = expected.get("allowedWarningPolicy")
        if not isinstance(policy, Mapping):
            raise ValueError(f"{case_id}.expected.allowedWarningPolicy must be an object for negative targets")
        mode = policy.get("mode")
        if mode not in {"no-findings-in-region", "allow-listed-rules-only"}:
            raise ValueError(f"{case_id}.expected.allowedWarningPolicy.mode is invalid")
        allowed_rule_ids = policy.get("allowedRuleIds", [])
        if not isinstance(allowed_rule_ids, list) or not all(isinstance(item, str) for item in allowed_rule_ids):
            raise ValueError(f"{case_id}.expected.allowedWarningPolicy.allowedRuleIds must be a string list")


def _reject_forbidden_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key in FORBIDDEN_VERDICT_KEYS:
                raise ValueError(f"forbidden verdict key at {path}.{key}: {key}")
            _reject_forbidden_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _reject_forbidden_keys(item, f"{path}[{idx}]")


def _require_non_empty_string(data: Mapping[str, Any], field: str, *, context: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}.{field} must be a non-empty string")
    return value


def _require_member(data: Mapping[str, Any], field: str, allowed: set[str], *, context: str) -> str:
    value = _require_non_empty_string(data, field, context=context)
    if value not in allowed:
        raise ValueError(f"{context}.{field} must be one of {sorted(allowed)}")
    return value
