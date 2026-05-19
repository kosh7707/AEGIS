from __future__ import annotations

import re
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
CASE_CHECKSUM_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
MANIFEST_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")


def required_current_six_configs() -> list[str]:
    return (
        ["full-current-six"]
        + [f"single-tool:{tool}" for tool in ALL_TOOLS]
        + [f"leave-one-out:{tool}" for tool in ALL_TOOLS]
        + ["parser-only-current-six", "contract-canary-current-six"]
    )


def validate_tool_set_config(config: str, *, allow_future: bool = False) -> dict[str, Any]:
    if not isinstance(config, str):
        raise ValueError("tool-set config must be a string")
    if config == "full-current-six":
        return {"status": "pass", "toolSetConfig": config, "tools": list(ALL_TOOLS), "kind": "full"}
    if config == "parser-only-current-six":
        return {"status": "pass", "toolSetConfig": config, "tools": [], "kind": "parser-only"}
    if config == "contract-canary-current-six":
        return {"status": "pass", "toolSetConfig": config, "tools": list(ALL_TOOLS), "kind": "contract-canary"}
    if config.startswith("single-tool:"):
        tool = config.split(":", 1)[1]
        if tool not in ALL_TOOLS:
            raise ValueError("unknown current S4 tool")
        return {"status": "pass", "toolSetConfig": config, "tools": [tool], "kind": "single-tool"}
    if config.startswith("leave-one-out:"):
        tool = config.split(":", 1)[1]
        if tool not in ALL_TOOLS:
            raise ValueError("unknown current S4 tool")
        return {"status": "pass", "toolSetConfig": config, "tools": [item for item in ALL_TOOLS if item != tool], "kind": "leave-one-out"}
    if config.startswith(FUTURE_CONFIG_PREFIXES):
        if not allow_future:
            raise ValueError("future WR-gated tool-set config is disabled for Milestone 1")
        return {"status": "pass", "toolSetConfig": config, "tools": [], "kind": "future-wr-gated"}
    raise ValueError("unknown tool-set config")


def validate_corpus_manifest(
    manifest: Mapping[str, Any],
    *,
    acquisition_index: Mapping[str, Mapping[str, Any]] | None = None,
    allow_unsafe_source_path: bool = False,
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
    source_artifact_splits: dict[str, set[str]] = defaultdict(set)
    target_rows: list[dict[str, Any]] = []

    for idx, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise ValueError(f"cases[{idx}] must be an object")
        case_id = _require_safe_identifier(case, "caseId", context=f"cases[{idx}]")
        if case_id in seen_case_ids:
            raise ValueError("duplicate caseId")
        seen_case_ids.add(case_id)
        split = _require_member(case, "split", SPLITS, context=case_id)
        slice_kind = _require_member(case, "sliceKind", SLICE_KINDS, context=case_id)
        split_counts[split] += 1
        slice_counts[slice_kind] += 1
        lineage_id = (
            _require_safe_identifier(case, "lineageId", context=case_id)
            if "lineageId" in case and case.get("lineageId") is not None
            else case_id
        )
        lineage_splits[lineage_id].add(split)
        source_artifact_key = _source_artifact_key(case)
        if source_artifact_key:
            source_artifact_splits[source_artifact_key].add(split)
        _validate_source_path(case, case_id, allow_unsafe=allow_unsafe_source_path)
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
            raise ValueError("lineage leakage across validation/test")
    for source_key, splits in source_artifact_splits.items():
        if "validation" in splits and "test" in splits:
            raise ValueError("source artifact leakage across validation/test")

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
        "lineageId": case.get("lineageId") or case.get("caseId"),
        "sliceKind": case.get("sliceKind"),
        "split": case.get("split"),
        "sourceArtifact": case.get("sourceArtifact"),
        "sourcePath": case.get("sourcePath"),
        "expected": dict(expected),
    }


def _validate_case_checksum(case: Mapping[str, Any], case_id: str) -> None:
    checksum = case.get("checksum")
    if not isinstance(checksum, str) or CASE_CHECKSUM_RE.match(checksum) is None:
        raise ValueError(f"{case_id}.checksum must be sha256:<64 lowercase hex>")


def _validate_source_path(case: Mapping[str, Any], case_id: str, *, allow_unsafe: bool = False) -> None:
    source_path = case.get("sourcePath")
    field = f"{case_id}.sourcePath"
    if not isinstance(source_path, str) or not source_path:
        raise ValueError(f"{field} must be a non-empty safe relative path")
    if source_path != source_path.strip():
        raise ValueError(f"{field} has surrounding whitespace")
    normalized = source_path.replace("\\", "/")
    if allow_unsafe:
        return
    if _is_absolute_source_path(normalized):
        raise ValueError(f"{field} must not be an absolute path")
    if any(part == ".." for part in normalized.split("/")):
        raise ValueError(f"{field} must not contain path traversal")


def _is_absolute_source_path(normalized_source_path: str) -> bool:
    if normalized_source_path.startswith("/"):
        return True
    if normalized_source_path.startswith("//"):
        return True
    if len(normalized_source_path) >= 3 and normalized_source_path[1] == ":" and normalized_source_path[2] == "/":
        return normalized_source_path[0].isalpha()
    return False


def _source_artifact_key(case: Mapping[str, Any]) -> str | None:
    acquisition_id = case.get("acquisitionId")
    source_ref = case.get("sourceRef")
    checksum = case.get("checksum")
    if not all(isinstance(item, str) and item.strip() for item in [acquisition_id, source_ref, checksum]):
        return None
    return f"{acquisition_id}:{source_ref}:{checksum}"


def _validate_acquisition_linkage(
    case: Mapping[str, Any],
    acquisition_index: Mapping[str, Mapping[str, Any]],
    case_id: str,
) -> None:
    acquisition_id = _require_safe_identifier(case, "acquisitionId", context=case_id)
    acquisition_checksum = _require_non_empty_string(case, "acquisitionManifestChecksum", context=case_id)
    _require_non_empty_string(case, "sourceRef", context=case_id)
    if acquisition_id not in acquisition_index:
        raise ValueError(f"{case_id}.acquisitionId not found in acquisition index")
    expected_checksum = acquisition_index[acquisition_id].get("manifestChecksum")
    if acquisition_checksum != expected_checksum:
        raise ValueError(f"{case_id}.acquisitionManifestChecksum mismatch")


def _validate_expected(expected: Mapping[str, Any], case_id: str) -> None:
    target_id = _require_safe_identifier(expected, "targetId", context=f"{case_id}.expected")
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
            forbidden_key = _canonical_forbidden_verdict_key(key)
            if forbidden_key is not None:
                raise ValueError(f"forbidden verdict key at {path}.{forbidden_key}: {forbidden_key}")
            _reject_forbidden_keys(nested, f"{path}.<field>")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _reject_forbidden_keys(item, f"{path}[{idx}]")


def _canonical_forbidden_verdict_key(key: Any) -> str | None:
    for forbidden_key in sorted(FORBIDDEN_VERDICT_KEYS):
        if key == forbidden_key:
            return forbidden_key
    return None


def _require_non_empty_string(data: Mapping[str, Any], field: str, *, context: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}.{field} must be a non-empty string")
    return value


def _require_safe_identifier(data: Mapping[str, Any], field: str, *, context: str) -> str:
    value = _require_non_empty_string(data, field, context=context)
    if (
        value != value.strip()
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        or MANIFEST_ID_RE.match(value) is None
    ):
        raise ValueError(f"{context}.{field} must be a safe identifier")
    return value


def _require_member(data: Mapping[str, Any], field: str, allowed: set[str], *, context: str) -> str:
    value = _require_non_empty_string(data, field, context=context)
    if value not in allowed:
        raise ValueError(f"{context}.{field} must be one of {sorted(allowed)}")
    return value
