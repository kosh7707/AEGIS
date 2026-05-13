from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping, Sequence

from app.schemas.response import SastFinding
from benchmark.cwe_matcher import CWE_HIERARCHY

MATCHING_POLICY_SCHEMA_VERSION = "s4-oracle-matching-policy-v1"


class MatchClass(StrEnum):
    EXACT_TARGET_MATCH = "exact-target-match"
    STRONG_RELATED_MATCH = "strong-related-match"
    WEAK_RELATED_MATCH = "weak-related-match"
    WRONG_CWE_TARGET_LOCATION = "wrong-cwe-target-location"
    OFF_TARGET_FINDING = "off-target-finding"
    NEGATIVE_CASE_FINDING = "negative-case-finding"
    MISSED_TARGET = "missed-target"


@dataclass(frozen=True)
class FindingEvidence:
    tool_id: str
    rule_id: str
    file: str
    line: int
    cwes: set[str] = field(default_factory=set)
    dataflow_lines: list[int] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MatchResult:
    target_id: str
    finding_key: str | None
    tool_id: str | None
    match_class: MatchClass
    counts_as_target_tp: bool = False
    counts_as_fp: bool = False
    reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "targetId": self.target_id,
            "findingKey": self.finding_key,
            "toolId": self.tool_id,
            "matchClass": self.match_class.value,
            "countsAsTargetTp": self.counts_as_target_tp,
            "countsAsFp": self.counts_as_fp,
            "reasonCodes": list(self.reason_codes),
        }


def finding_to_evidence(finding: SastFinding | Mapping[str, Any]) -> FindingEvidence:
    if isinstance(finding, SastFinding):
        tool_id = finding.tool_id
        rule_id = finding.rule_id
        file = finding.location.file
        line = finding.location.line
        metadata = dict(finding.metadata or {})
        dataflow = finding.data_flow or []
        dataflow_lines = [step.line for step in dataflow if isinstance(step.line, int)]
    else:
        tool_id = str(finding.get("toolId") or finding.get("tool_id") or "unknown")
        rule_id = str(finding.get("ruleId") or finding.get("rule_id") or "unknown")
        location = finding.get("location") or {}
        file = str(location.get("file") or finding.get("file") or "")
        line = int(location.get("line") or finding.get("line") or 0)
        metadata = dict(finding.get("metadata") or {})
        dataflow = finding.get("dataFlow") or finding.get("data_flow") or []
        dataflow_lines = [int(step["line"]) for step in dataflow if isinstance(step, Mapping) and isinstance(step.get("line"), int)]
    return FindingEvidence(
        tool_id=tool_id,
        rule_id=rule_id,
        file=_normalize_path(file),
        line=line,
        cwes=_extract_cwes_from_metadata(metadata),
        dataflow_lines=dataflow_lines,
        metadata=metadata,
    )


def match_finding_to_target(
    target: Mapping[str, Any],
    finding: SastFinding | Mapping[str, Any] | FindingEvidence,
    *,
    matching_policy: Mapping[str, Any] | None = None,
) -> MatchResult:
    evidence = finding if isinstance(finding, FindingEvidence) else finding_to_evidence(finding)
    expected = _expected(target)
    target_id = str(expected.get("targetId") or target.get("targetId") or target.get("caseId") or "unknown-target")
    finding_key = _finding_key(evidence)
    polarity = expected.get("polarity", "positive")

    if polarity == "negative":
        if _intersects_target_region(expected, evidence, matching_policy):
            if _negative_finding_is_allowed(expected, evidence):
                return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.OFF_TARGET_FINDING, reason_codes=("NEGATIVE_REGION_ALLOWED_RULE",))
            return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.NEGATIVE_CASE_FINDING, counts_as_fp=True, reason_codes=("NEGATIVE_REGION_VIOLATION",))
        return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.OFF_TARGET_FINDING, reason_codes=("OUTSIDE_NEGATIVE_REGION",))

    cwe_match = _target_cwe_matches(expected, evidence)
    location_match = _line_window_match(expected, evidence, matching_policy)
    region_match = _intersects_target_region(expected, evidence, matching_policy)
    function_fallback_enabled = _function_fallback_enabled(expected, matching_policy)
    dataflow_match = _dataflow_intersects_expected_location(expected, evidence)

    if cwe_match and location_match:
        return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.EXACT_TARGET_MATCH, counts_as_target_tp=True)
    if cwe_match and (dataflow_match or (region_match and function_fallback_enabled)):
        return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.STRONG_RELATED_MATCH, counts_as_target_tp=True)
    if location_match and evidence.cwes and not cwe_match:
        return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.WRONG_CWE_TARGET_LOCATION, counts_as_fp=True, reason_codes=("WRONG_CWE",))
    if region_match or location_match:
        return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.WEAK_RELATED_MATCH, counts_as_fp=True, reason_codes=("REGION_MATCH_WITHOUT_REQUIRED_CWE_OR_SINK",))
    return MatchResult(target_id, finding_key, evidence.tool_id, MatchClass.OFF_TARGET_FINDING, counts_as_fp=True, reason_codes=("OFF_TARGET",))


def score_targets(
    targets: Sequence[Mapping[str, Any]],
    findings: Sequence[SastFinding | Mapping[str, Any] | FindingEvidence],
    *,
    tool_set_config: str,
    matching_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_items = [finding if isinstance(finding, FindingEvidence) else finding_to_evidence(finding) for finding in findings]
    positive_targets = [target for target in targets if _expected(target).get("polarity", "positive") == "positive"]
    negative_targets = [target for target in targets if _expected(target).get("polarity") == "negative"]
    rows: list[dict[str, Any]] = []
    used_tp_finding_keys: set[str] = set()
    target_tp = 0
    target_fn = 0
    weak_related_count = 0
    wrong_cwe_count = 0

    for target in positive_targets:
        matches = [match_finding_to_target(target, evidence, matching_policy=matching_policy) for evidence in evidence_items]
        best = _best_positive_match(matches)
        if best and best.counts_as_target_tp:
            target_tp += 1
            used_tp_finding_keys.add(best.finding_key or "")
        else:
            target_fn += 1
            rows.append(_missed_row(target, tool_set_config, matching_policy))
        for match in matches:
            if match.match_class == MatchClass.WEAK_RELATED_MATCH:
                weak_related_count += 1
            elif match.match_class == MatchClass.WRONG_CWE_TARGET_LOCATION:
                wrong_cwe_count += 1
        if best:
            rows.append(_row(target, best, tool_set_config, matching_policy))

    negative_target_violation = 0
    negative_target_clean = 0
    negative_violation_finding_keys: set[str] = set()
    allowed_negative_finding_keys: set[str] = set()
    for target in negative_targets:
        matches = [match_finding_to_target(target, evidence, matching_policy=matching_policy) for evidence in evidence_items]
        violations = [match for match in matches if match.match_class == MatchClass.NEGATIVE_CASE_FINDING]
        allowed_negative_finding_keys.update(
            match.finding_key or ""
            for match in matches
            if "NEGATIVE_REGION_ALLOWED_RULE" in match.reason_codes
        )
        if violations:
            negative_target_violation += 1
            for violation in violations:
                negative_violation_finding_keys.add(violation.finding_key or "")
                rows.append(_row(target, violation, tool_set_config, matching_policy))
        else:
            negative_target_clean += 1

    matched_tp_findings = len(used_tp_finding_keys)
    fp_keys = {
        _finding_key(evidence)
        for evidence in evidence_items
        if _finding_key(evidence) not in used_tp_finding_keys
        and _finding_key(evidence) not in allowed_negative_finding_keys
    } | negative_violation_finding_keys
    fp_findings = len(fp_keys)
    analyzed_files = len({target.get("sourcePath") for target in targets if target.get("sourcePath")}) or 1
    target_recall = _round_ratio(target_tp, target_tp + target_fn)
    finding_precision = _round_ratio(matched_tp_findings, matched_tp_findings + fp_findings)
    negative_fpr = _round_ratio(negative_target_violation, negative_target_violation + negative_target_clean)
    positive_detection_rate = target_recall or 0.0
    negative_violation_rate = negative_fpr or 0.0

    return {
        "toolSetConfig": tool_set_config,
        "targetTP": target_tp,
        "targetFN": target_fn,
        "matchedTpFindings": matched_tp_findings,
        "fpFindings": fp_findings,
        "negativeTargetViolationCount": negative_target_violation,
        "negativeTargetCleanCount": negative_target_clean,
        "targetRecall": target_recall,
        "findingPrecision": finding_precision,
        "negativeTargetFpr": negative_fpr,
        "discrimination": round(positive_detection_rate - negative_violation_rate, 4),
        "noisePerFile": round(fp_findings / analyzed_files, 4),
        "weakRelatedCount": weak_related_count,
        "wrongCweCount": wrong_cwe_count,
        "rows": rows,
        "rowMetadata": {
            "toolSetConfig": tool_set_config,
            "matchingPolicy": (matching_policy or {}).get("schemaVersion", MATCHING_POLICY_SCHEMA_VERSION),
        },
    }


def _best_positive_match(matches: Sequence[MatchResult]) -> MatchResult | None:
    rank = {
        MatchClass.EXACT_TARGET_MATCH: 0,
        MatchClass.STRONG_RELATED_MATCH: 1,
        MatchClass.WRONG_CWE_TARGET_LOCATION: 2,
        MatchClass.WEAK_RELATED_MATCH: 3,
        MatchClass.OFF_TARGET_FINDING: 4,
    }
    if not matches:
        return None
    return sorted(matches, key=lambda item: rank.get(item.match_class, 99))[0]


def _row(target: Mapping[str, Any], match: MatchResult, tool_set_config: str, matching_policy: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        "caseId": target.get("caseId"),
        "targetId": match.target_id,
        "sourceArtifact": target.get("sourceArtifact"),
        "sourcePath": target.get("sourcePath"),
        "sliceKind": target.get("sliceKind"),
        "split": target.get("split"),
        "toolSetConfig": tool_set_config,
        "matchingPolicy": (matching_policy or {}).get("schemaVersion", MATCHING_POLICY_SCHEMA_VERSION),
        **match.to_dict(),
    }


def _missed_row(target: Mapping[str, Any], tool_set_config: str, matching_policy: Mapping[str, Any] | None) -> dict[str, Any]:
    expected = _expected(target)
    match = MatchResult(str(expected.get("targetId") or target.get("targetId") or target.get("caseId")), None, None, MatchClass.MISSED_TARGET, reason_codes=("NO_MATCHING_FINDING",))
    return _row(target, match, tool_set_config, matching_policy)


def _expected(target: Mapping[str, Any]) -> Mapping[str, Any]:
    expected = target.get("expected")
    return expected if isinstance(expected, Mapping) else target


def _target_cwe_matches(expected: Mapping[str, Any], evidence: FindingEvidence) -> bool:
    target_cwe = _normalize_cwe(expected.get("cweId"))
    if not target_cwe or not evidence.cwes:
        return False
    if target_cwe in evidence.cwes:
        return True
    for parent, children in CWE_HIERARCHY.items():
        if parent in evidence.cwes and target_cwe in children:
            return True
        if target_cwe == parent and evidence.cwes.intersection(children):
            return True
    return False


def _line_window_match(expected: Mapping[str, Any], evidence: FindingEvidence, matching_policy: Mapping[str, Any] | None) -> bool:
    for location in expected.get("locations") or []:
        if not isinstance(location, Mapping):
            continue
        if _normalize_path(str(location.get("file") or "")) != evidence.file:
            continue
        line = location.get("line")
        if not isinstance(line, int):
            continue
        line_delta = _line_delta(expected, matching_policy)
        if abs(evidence.line - line) <= line_delta:
            return True
    return False


def _intersects_target_region(expected: Mapping[str, Any], evidence: FindingEvidence, matching_policy: Mapping[str, Any] | None) -> bool:
    region = expected.get("functionRegion") or expected.get("region")
    if isinstance(region, Mapping):
        start = region.get("startLine") or region.get("start")
        end = region.get("endLine") or region.get("end")
        if isinstance(start, int) and isinstance(end, int) and start <= evidence.line <= end:
            files = { _normalize_path(str(loc.get("file") or "")) for loc in expected.get("locations") or [] if isinstance(loc, Mapping) }
            return not files or evidence.file in files
    return _line_window_match(expected, evidence, matching_policy)


def _dataflow_intersects_expected_location(expected: Mapping[str, Any], evidence: FindingEvidence) -> bool:
    if not evidence.dataflow_lines:
        return False
    for location in expected.get("locations") or []:
        if not isinstance(location, Mapping):
            continue
        line = location.get("line")
        if isinstance(line, int) and line in evidence.dataflow_lines:
            return True
    return False


def _line_delta(expected: Mapping[str, Any], matching_policy: Mapping[str, Any] | None) -> int:
    window = expected.get("allowedMatchWindows") or {}
    if isinstance(window, Mapping) and isinstance(window.get("lineDelta"), int):
        return int(window["lineDelta"])
    if matching_policy and isinstance(matching_policy.get("lineWindowDefault"), int):
        return int(matching_policy["lineWindowDefault"])
    return 5


def _function_fallback_enabled(expected: Mapping[str, Any], matching_policy: Mapping[str, Any] | None) -> bool:
    window = expected.get("allowedMatchWindows") or {}
    if isinstance(window, Mapping) and isinstance(window.get("functionFallback"), bool):
        return bool(window["functionFallback"])
    if matching_policy and isinstance(matching_policy.get("functionFallbackDefault"), bool):
        return bool(matching_policy["functionFallbackDefault"])
    return False


def _negative_finding_is_allowed(expected: Mapping[str, Any], evidence: FindingEvidence) -> bool:
    policy = expected.get("allowedWarningPolicy")
    if not isinstance(policy, Mapping):
        return False
    mode = policy.get("mode")
    if mode == "no-findings-in-region":
        return False
    if mode == "allow-listed-rules-only":
        allowed_rule_ids = policy.get("allowedRuleIds")
        return isinstance(allowed_rule_ids, list) and evidence.rule_id in {item for item in allowed_rule_ids if isinstance(item, str)}
    return False


def _extract_cwes_from_metadata(metadata: Mapping[str, Any]) -> set[str]:
    cwes: set[str] = set()
    cwe_id = _normalize_cwe(metadata.get("cweId"))
    if cwe_id:
        cwes.add(cwe_id)
    cwe_list = metadata.get("cwe")
    if isinstance(cwe_list, list):
        for item in cwe_list:
            normalized = _normalize_cwe(item)
            if normalized:
                cwes.add(normalized)
    evidence_resolution = metadata.get("evidenceResolution")
    if isinstance(evidence_resolution, Mapping):
        cwe_info = evidence_resolution.get("cwe")
        if isinstance(cwe_info, Mapping):
            normalized = _normalize_cwe(cwe_info.get("id"))
            if normalized:
                cwes.add(normalized)
    return cwes


def _normalize_cwe(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.upper().strip()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return normalized


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _finding_key(evidence: FindingEvidence) -> str:
    return f"{evidence.tool_id}:{evidence.rule_id}:{evidence.file}:{evidence.line}"


def _round_ratio(num: int, denom: int) -> float | None:
    if denom <= 0:
        return None
    return round(num / denom, 4)
