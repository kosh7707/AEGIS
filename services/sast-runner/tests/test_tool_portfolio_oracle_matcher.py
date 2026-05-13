from __future__ import annotations

from app.schemas.response import SastFinding
from benchmark.cwe_matcher import extract_cwes
from benchmark.tool_portfolio_oracle_matcher import (
    MatchClass,
    finding_to_evidence,
    match_finding_to_target,
    score_targets,
)


def _finding(
    *,
    tool: str = "semgrep",
    file: str = "src/juliet.c",
    line: int = 42,
    cwe: str | None = "CWE-121",
    dataflow_lines: list[int] | None = None,
) -> SastFinding:
    metadata: dict = {}
    if cwe is not None:
        metadata["cweId"] = cwe
        metadata["cwe"] = [cwe]
    metadata["evidenceResolution"] = {
        "cwe": {"status": "known" if cwe else "unknown", "id": cwe, "source": "metadata.cweId" if cwe else None}
    }
    return SastFinding(
        toolId=tool,
        ruleId=f"{tool}:rule",
        severity="warning",
        message="synthetic finding",
        location={"file": file, "line": line, "column": 1},
        dataFlow=[{"file": file, "line": item, "content": "step"} for item in dataflow_lines] if dataflow_lines else None,
        metadata=metadata,
    )


def _target(*, polarity: str = "positive", cwe: str = "CWE-121", start: int = 35, end: int = 50) -> dict:
    return {
        "caseId": "juliet-same-file",
        "targetId": "bad-target" if polarity == "positive" else "good-target",
        "sliceKind": "juliet-controlled-positive" if polarity == "positive" else "juliet-controlled-negative",
        "split": "validation",
        "sourceArtifact": "s4-harness-fixture",
        "expected": {
            "targetId": "bad-target" if polarity == "positive" else "good-target",
            "granularity": "sink-line" if polarity == "positive" else "negative-region",
            "cweId": cwe,
            "polarity": polarity,
            "locations": [{"file": "src/juliet.c", "line": 42 if polarity == "positive" else start, "role": "sink"}],
            "functionRegion": {"function": "bad" if polarity == "positive" else "good", "startLine": start, "endLine": end},
            "allowedMatchWindows": {"lineDelta": 5, "functionFallback": False},
        },
    }


def test_existing_cwe_extractor_uses_metadata_cwe_id_before_advanced_matching() -> None:
    finding = _finding(cwe="CWE-121")
    finding.metadata = {"cweId": "CWE-121"}

    assert extract_cwes(finding) == {"CWE-121"}


def test_finding_evidence_preserves_file_line_tool_cwe_dataflow_and_evidence_resolution() -> None:
    finding = _finding(tool="scan-build", line=70, cwe="CWE-476", dataflow_lines=[41, 70])

    evidence = finding_to_evidence(finding)

    assert evidence.tool_id == "scan-build"
    assert evidence.file == "src/juliet.c"
    assert evidence.line == 70
    assert evidence.cwes == {"CWE-476"}
    assert evidence.dataflow_lines == [41, 70]
    assert evidence.metadata["evidenceResolution"]["cwe"]["id"] == "CWE-476"


def test_exact_match_uses_cwe_and_sink_line_window() -> None:
    result = match_finding_to_target(_target(), _finding(line=44, cwe="CWE-121"))

    assert result.match_class == MatchClass.EXACT_TARGET_MATCH
    assert result.counts_as_target_tp is True
    assert result.counts_as_fp is False


def test_strong_related_match_can_use_dataflow_sink_when_location_is_outside_window() -> None:
    result = match_finding_to_target(_target(), _finding(line=80, cwe="CWE-121", dataflow_lines=[10, 42]))

    assert result.match_class == MatchClass.STRONG_RELATED_MATCH
    assert result.counts_as_target_tp is True


def test_wrong_cwe_and_weak_related_are_not_true_positives() -> None:
    wrong = match_finding_to_target(_target(), _finding(line=42, cwe="CWE-190"))
    weak = match_finding_to_target(_target(), _finding(line=40, cwe=None))

    assert wrong.match_class == MatchClass.WRONG_CWE_TARGET_LOCATION
    assert wrong.counts_as_fp is True
    assert weak.match_class == MatchClass.WEAK_RELATED_MATCH
    assert weak.counts_as_target_tp is False


def test_function_region_only_same_cwe_is_not_tp_when_function_fallback_disabled() -> None:
    target = _target()
    finding = _finding(line=50, cwe="CWE-121")

    result = match_finding_to_target(
        target,
        finding,
        matching_policy={"schemaVersion": "s4-oracle-matching-policy-v1", "lineWindowDefault": 3, "functionFallbackDefault": False},
    )

    assert result.match_class == MatchClass.WEAK_RELATED_MATCH
    assert result.counts_as_target_tp is False
    assert result.counts_as_fp is True


def test_same_file_juliet_good_region_is_region_scoped_not_file_scoped() -> None:
    negative = _target(polarity="negative", start=70, end=95)

    bad_region_finding = match_finding_to_target(negative, _finding(line=42, cwe="CWE-121"))
    good_region_finding = match_finding_to_target(negative, _finding(line=75, cwe="CWE-121"))

    assert bad_region_finding.match_class == MatchClass.OFF_TARGET_FINDING
    assert good_region_finding.match_class == MatchClass.NEGATIVE_CASE_FINDING
    assert good_region_finding.counts_as_fp is True


def test_negative_allowed_warning_policy_allows_listed_rules_and_blocks_others() -> None:
    negative = _target(polarity="negative", start=70, end=95)
    negative["expected"]["allowedWarningPolicy"] = {
        "mode": "allow-listed-rules-only",
        "allowedRuleIds": ["semgrep:allowed-noise"],
    }
    allowed = _finding(tool="semgrep", line=80, cwe="CWE-121")
    allowed = allowed.model_copy(update={"rule_id": "semgrep:allowed-noise"})
    disallowed = _finding(tool="semgrep", line=80, cwe="CWE-121")
    disallowed = disallowed.model_copy(update={"rule_id": "semgrep:disallowed"})

    allowed_result = match_finding_to_target(negative, allowed)
    disallowed_result = match_finding_to_target(negative, disallowed)

    assert allowed_result.match_class == MatchClass.OFF_TARGET_FINDING
    assert allowed_result.counts_as_fp is False
    assert "NEGATIVE_REGION_ALLOWED_RULE" in allowed_result.reason_codes
    assert disallowed_result.match_class == MatchClass.NEGATIVE_CASE_FINDING
    assert disallowed_result.counts_as_fp is True


def test_score_targets_does_not_count_allowed_negative_region_warning_as_fp() -> None:
    negative = _target(polarity="negative", start=70, end=95)
    negative["expected"]["allowedWarningPolicy"] = {
        "mode": "allow-listed-rules-only",
        "allowedRuleIds": ["semgrep:allowed-noise"],
    }
    allowed = _finding(tool="semgrep", line=80, cwe="CWE-121")
    allowed = allowed.model_copy(update={"rule_id": "semgrep:allowed-noise"})

    summary = score_targets([negative], [allowed], tool_set_config="full-current-six")

    assert summary["negativeTargetViolationCount"] == 0
    assert summary["negativeTargetCleanCount"] == 1
    assert summary["fpFindings"] == 0
    assert summary["negativeTargetFpr"] == 0.0


def test_score_targets_separates_target_recall_finding_precision_and_negative_fpr() -> None:
    positive = _target()
    negative = _target(polarity="negative", start=70, end=95)
    findings = [
        _finding(tool="semgrep", line=42, cwe="CWE-121"),
        _finding(tool="flawfinder", line=80, cwe="CWE-121"),
        _finding(tool="cppcheck", file="src/other.c", line=1, cwe="CWE-121"),
    ]

    summary = score_targets([positive, negative], findings, tool_set_config="full-current-six")

    assert summary["targetTP"] == 1
    assert summary["targetFN"] == 0
    assert summary["matchedTpFindings"] == 1
    assert summary["fpFindings"] == 2
    assert summary["negativeTargetViolationCount"] == 1
    assert summary["negativeTargetCleanCount"] == 0
    assert summary["targetRecall"] == 1.0
    assert summary["findingPrecision"] == round(1 / 3, 4)
    assert summary["negativeTargetFpr"] == 1.0
    assert summary["rowMetadata"]["toolSetConfig"] == "full-current-six"
