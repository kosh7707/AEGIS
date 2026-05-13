from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from benchmark.static_evidence_consumer_canary import summarize_static_evidence_contract

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "static_evidence_contract" / "consumer_canaries"
FORBIDDEN_OUTPUT_KEYS = {
    "vulnerable",
    "safe",
    "affected",
    "clean",
    "riskScore",
    "securityVerdict",
    "verdict",
    "risk",
    "severityScore",
    "shouldCallS5",
    "nextService",
    "routeTo",
    "repairAction",
    "agentDecision",
}
REQUIRED_NOT_PROVIDED_SURFACES = {
    "externalVulnerabilityKnowledge",
    "semanticGraphRetrieval",
    "runtimeBehavior",
    "exploitabilityJudgment",
    "finalSecurityVerdict",
}


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _collect_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for nested in value.values():
            keys.update(_collect_keys(nested))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for item in value:
            keys.update(_collect_keys(item))
        return keys
    return set()


def _assert_no_forbidden_output_keys(summary: dict[str, Any]) -> None:
    keys = _collect_keys(summary)
    forbidden = keys.intersection(FORBIDDEN_OUTPUT_KEYS)
    assert not forbidden, f"consumer canary output has forbidden decision/orchestration keys: {sorted(forbidden)}"


def test_clean_ready_top_level_contract_is_local_static_ready() -> None:
    summary = summarize_static_evidence_contract(_load_fixture("clean_ready_top_level.json"))

    assert summary["contractPresent"] is True
    assert summary["contractLocation"] == "top-level"
    assert summary["systemStability"] == "pass"
    assert summary["evidenceReadiness"] == "ready"
    assert summary["claimSupportReadiness"] == "pass"
    assert summary["qualityEvaluation"] == "not_evaluated"
    assert summary["localStaticEvidenceReady"] is True
    assert summary["toolAnomalyReasonCodes"] == []
    assert set(summary["notProvidedSurfaces"]) == REQUIRED_NOT_PROVIDED_SURFACES
    assert "absence-of-vulnerability-from-empty-findings" in summary["mustNotSupportAlone"]
    assert {"absence-of-vulnerability", "cwe-absence"}.issubset(summary["unsupportedClaims"])
    assert summary["claimSupportStatuses"]["absence-of-vulnerability"] == "unsupported"
    assert summary["claimSupportStatuses"]["reported-finding-positive-evidence"] == "not_applicable"
    _assert_no_forbidden_output_keys(summary)


def test_failed_tool_contract_is_degraded_partial_not_locally_ready() -> None:
    summary = summarize_static_evidence_contract(_load_fixture("failed_tool_degraded_top_level.json"))

    assert summary["systemStability"] == "degraded"
    assert summary["evidenceReadiness"] == "partial"
    assert summary["claimSupportReadiness"] == "partial"
    assert "LOCAL_ARTIFACT_DEGRADED" in summary["claimSupportReasonCodes"]
    assert summary["localStaticEvidenceReady"] is False
    assert summary["toolAnomalyReasonCodes"] == ["TOOL_FAILED:scan-build"]
    assert summary["toolMatrixStatuses"]["scan-build"] == "failed"
    assert summary["toolConsumerPolicies"]["scan-build"] == "local_tool_failed_do_not_use_as_negative_evidence"
    _assert_no_forbidden_output_keys(summary)


def test_missing_tool_metadata_contract_is_degraded_partial_not_locally_ready() -> None:
    summary = summarize_static_evidence_contract(_load_fixture("missing_tool_metadata_top_level.json"))

    assert summary["systemStability"] == "degraded"
    assert summary["evidenceReadiness"] == "partial"
    assert summary["claimSupportReadiness"] == "partial"
    assert summary["localStaticEvidenceReady"] is False
    assert summary["toolAnomalyReasonCodes"] == [
        "TOOL_NOT_RECORDED:cppcheck",
        "TOOL_NOT_RECORDED:flawfinder",
        "TOOL_NOT_RECORDED:clang-tidy",
        "TOOL_NOT_RECORDED:scan-build",
        "TOOL_NOT_RECORDED:gcc-fanalyzer",
    ]
    assert summary["toolMatrixStatuses"]["cppcheck"] == "not_recorded"
    _assert_no_forbidden_output_keys(summary)


def test_policy_failure_contract_is_failed_not_ready() -> None:
    summary = summarize_static_evidence_contract(_load_fixture("policy_failure_top_level.json"))

    assert summary["systemStability"] == "fail"
    assert summary["evidenceReadiness"] == "not_ready"
    assert summary["claimSupportReadiness"] == "fail"
    assert summary["localStaticEvidenceReady"] is False
    assert "POLICY_VIOLATION" in summary["systemReasonCodes"]
    assert "POLICY_VIOLATION" in summary["claimSupportReasonCodes"]
    assert summary["toolAnomalyReasonCodes"] == ["TOOL_BLOCKING_SKIP:semgrep"]
    _assert_no_forbidden_output_keys(summary)


def test_allowed_skip_nested_contract_remains_pass_ready() -> None:
    summary = summarize_static_evidence_contract(_load_fixture("allowed_skip_nested_build_and_analyze.json"))

    assert summary["contractPresent"] is True
    assert summary["contractLocation"] == "scan.staticEvidenceContract"
    assert summary["systemStability"] == "pass"
    assert summary["evidenceReadiness"] == "ready"
    assert summary["claimSupportReadiness"] == "pass"
    assert summary["localStaticEvidenceReady"] is True
    assert summary["toolAnomalyReasonCodes"] == []
    assert summary["toolConsumerPolicies"]["clang-tidy"] == "not_requested_or_not_applicable"
    _assert_no_forbidden_output_keys(summary)


def test_consumer_canary_ignores_raw_execution_tool_results() -> None:
    payload = _load_fixture("clean_ready_top_level.json")
    baseline = summarize_static_evidence_contract(payload)
    poisoned = copy.deepcopy(payload)
    poisoned["execution"] = {
        "toolResults": {
            "semgrep": {"status": "failed"},
            "cppcheck": {"status": "failed"},
            "flawfinder": {"status": "failed"},
            "clang-tidy": {"status": "failed"},
            "scan-build": {"status": "failed"},
            "gcc-fanalyzer": {"status": "failed"},
        }
    }

    assert summarize_static_evidence_contract(poisoned) == baseline


def test_absent_contract_does_not_infer_readiness_from_success_flag() -> None:
    payload = {"success": True, "status": "completed", "findings": [], "execution": {"toolResults": {}}}

    summary = summarize_static_evidence_contract(payload)

    assert summary["contractPresent"] is False
    assert summary["contractLocation"] == "missing"
    assert summary["systemStability"] == "unknown"
    assert summary["evidenceReadiness"] == "not_ready"
    assert summary["claimSupportReadiness"] == "unknown"
    assert summary["qualityEvaluation"] == "unknown"
    assert summary["localStaticEvidenceReady"] is False
    assert summary["toolAnomalyReasonCodes"] == []
    _assert_no_forbidden_output_keys(summary)


def test_malformed_contract_does_not_infer_readiness_from_success_flag() -> None:
    payload = {"success": True, "staticEvidenceContract": "malformed"}

    summary = summarize_static_evidence_contract(payload)

    assert summary["contractPresent"] is False
    assert summary["contractLocation"] == "malformed"
    assert summary["systemStability"] == "unknown"
    assert summary["evidenceReadiness"] == "not_ready"
    assert summary["claimSupportReadiness"] == "unknown"
    assert summary["localStaticEvidenceReady"] is False
    _assert_no_forbidden_output_keys(summary)


def test_consumer_canary_helper_is_json_only_and_side_effect_free() -> None:
    helper = Path(__file__).parents[1] / "benchmark" / "static_evidence_consumer_canary.py"
    text = helper.read_text(encoding="utf-8")

    forbidden_tokens = [
        "from app.",
        "import app.",
        "toolResults",
        "batch-lookup",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "socket",
        "grpc",
        "openai",
        "anthropic",
        "shouldCallS5",
        "nextService",
        "routeTo",
        "repairAction",
        "agentDecision",
    ]
    for token in forbidden_tokens:
        assert token not in text, f"consumer canary helper must not reference {token!r}"
