from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import benchmark.static_evidence_consumer_canary as consumer_module
from benchmark.static_evidence_consumer_canary import (
    SUMMARY_SCHEMA_VERSION,
    summarize_static_evidence_contract,
)

REPO_ROOT = Path(__file__).parents[1]
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "static_evidence_contract" / "consumer_canaries"
CONSUMER_SUMMARY_RELATIVE_PATH = Path(
    "benchmark/results/static_evidence/s4-clean-ready-consumer-summary-v1.json",
)
CONSUMER_SUMMARY_PATH = REPO_ROOT / CONSUMER_SUMMARY_RELATIVE_PATH
EXPECTED_SUMMARY_KEYS = {
    "summarySchemaVersion",
    "contractPresent",
    "contractLocation",
    "systemStability",
    "evidenceReadiness",
    "claimSupportReadiness",
    "qualityEvaluation",
    "localStaticEvidenceReady",
    "systemReasonCodes",
    "evidenceReasonCodes",
    "claimSupportReasonCodes",
    "toolAnomalyReasonCodes",
    "notProvidedSurfaces",
    "partialSurfaces",
    "blockingSurfaces",
    "mustNotSupportAlone",
    "unsupportedClaims",
    "claimSupportStatuses",
    "toolMatrixStatuses",
    "toolConsumerPolicies",
}
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
FORBIDDEN_OUTPUT_VALUE_TOKENS = {
    "shouldCallS5",
    "nextService",
    "routeTo",
    "repairAction",
    "agentDecision",
    "riskScore",
    "securityVerdict",
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


def _assert_summary_contract(summary: dict[str, Any]) -> None:
    assert set(summary) == EXPECTED_SUMMARY_KEYS
    assert summary["summarySchemaVersion"] == SUMMARY_SCHEMA_VERSION


def _assert_no_forbidden_output_keys(summary: dict[str, Any]) -> None:
    _assert_summary_contract(summary)
    keys = _collect_keys(summary)
    forbidden = keys.intersection(FORBIDDEN_OUTPUT_KEYS)
    assert not forbidden, f"consumer canary output has forbidden decision/orchestration keys: {sorted(forbidden)}"


def _assert_no_forbidden_output_tokens(summary: dict[str, Any], *extra_tokens: str) -> None:
    serialized = json.dumps(summary, sort_keys=True)
    forbidden_tokens = sorted(
        token for token in FORBIDDEN_OUTPUT_VALUE_TOKENS.union(extra_tokens) if token in serialized
    )
    assert not forbidden_tokens, f"consumer canary output has forbidden decision/orchestration values: {forbidden_tokens}"


def _assert_cli_error_payload(
    stderr: str,
    *,
    error: str,
    reason_code: str,
    stage: str,
) -> dict[str, Any]:
    payload = json.loads(stderr)
    assert payload == {
        "error": error,
        "reasonCode": reason_code,
        "reasonCodes": [reason_code],
        "stage": stage,
        "summaryEmitted": False,
    }
    return payload


def _consumer_summary_artifact_offenders(
    *,
    results_root: Path,
    repo_root: Path,
    expected_summary: dict[str, Any],
) -> list[str]:
    offenders: list[str] = []
    for path in sorted(results_root.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("summarySchemaVersion") != SUMMARY_SCHEMA_VERSION:
            continue
        relative_path = path.relative_to(repo_root)
        if relative_path == CONSUMER_SUMMARY_RELATIVE_PATH and document == expected_summary:
            continue
        offenders.append(str(relative_path))
    return offenders


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
    _assert_no_forbidden_output_tokens(summary)


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
    _assert_no_forbidden_output_tokens(summary)


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
    _assert_no_forbidden_output_tokens(summary)


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
    _assert_no_forbidden_output_tokens(summary)


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
    _assert_no_forbidden_output_tokens(summary)


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


def test_consumer_canary_summary_schema_version_and_exact_keys_are_locked() -> None:
    summaries = [
        summarize_static_evidence_contract(_load_fixture("clean_ready_top_level.json")),
        summarize_static_evidence_contract({"success": True}),
        summarize_static_evidence_contract({"staticEvidenceContract": "malformed"}),
    ]

    for summary in summaries:
        _assert_summary_contract(summary)


def test_consumer_canary_cli_emits_summary_for_clean_ready_response(capsys) -> None:
    response_path = FIXTURES_DIR / "clean_ready_top_level.json"
    expected = summarize_static_evidence_contract(_load_fixture("clean_ready_top_level.json"))

    exit_code = consumer_module.main(["--response", str(response_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    summary = json.loads(captured.out)
    assert summary == expected
    assert summary["localStaticEvidenceReady"] is True
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_cli_require_local_static_ready_exits_two_for_non_ready_response(capsys) -> None:
    response_path = FIXTURES_DIR / "failed_tool_degraded_top_level.json"

    default_exit_code = consumer_module.main(["--response", str(response_path)])
    default_captured = capsys.readouterr()
    default_summary = json.loads(default_captured.out)

    assert default_exit_code == 0
    assert default_captured.err == ""
    assert default_summary["contractPresent"] is True
    assert default_summary["localStaticEvidenceReady"] is False
    _assert_no_forbidden_output_keys(default_summary)
    _assert_no_forbidden_output_tokens(default_summary)

    required_exit_code = consumer_module.main([
        "--response",
        str(response_path),
        "--require-local-static-ready",
    ])
    required_captured = capsys.readouterr()
    required_summary = json.loads(required_captured.out)

    assert required_exit_code == 2
    assert required_captured.err == ""
    assert required_summary == default_summary


def test_consumer_canary_cli_absent_and_malformed_contracts_exit_two_after_summary(
    tmp_path: Path,
    capsys,
) -> None:
    cases = [
        ("absent.json", {"success": True}),
        ("malformed.json", {"staticEvidenceContract": "malformed"}),
    ]

    for filename, payload in cases:
        response_path = tmp_path / filename
        response_path.write_text(json.dumps(payload), encoding="utf-8")

        exit_code = consumer_module.main(["--response", str(response_path)])
        captured = capsys.readouterr()
        summary = json.loads(captured.out)

        assert exit_code == 2, filename
        assert captured.err == "", filename
        assert summary["contractPresent"] is False, filename
        assert summary["localStaticEvidenceReady"] is False, filename
        _assert_no_forbidden_output_keys(summary)
        _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_cli_input_failures_emit_structured_stderr_without_echo(
    tmp_path: Path,
    capsys,
) -> None:
    response_path = tmp_path / "SECRET_STATIC_RESPONSE_PATH_SHOULD_NOT_LEAK.json"
    response_path.write_text("{not-json: SECRET_STATIC_RESPONSE_CONTENT_SHOULD_NOT_LEAK}", encoding="utf-8")

    exit_code = consumer_module.main(["--response", str(response_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    _assert_cli_error_payload(
        captured.err,
        error="input validation failed",
        reason_code="STATIC_EVIDENCE_CONSUMER_CLI_INPUT_INVALID",
        stage="input",
    )
    assert "Traceback" not in captured.err
    assert "usage:" not in captured.err
    assert "SECRET_STATIC_RESPONSE_PATH_SHOULD_NOT_LEAK" not in captured.err
    assert "SECRET_STATIC_RESPONSE_CONTENT_SHOULD_NOT_LEAK" not in captured.err
    assert str(response_path) not in captured.err


def test_consumer_canary_cli_argument_error_exits_one(capsys) -> None:
    exit_code = consumer_module.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    _assert_cli_error_payload(
        captured.err,
        error="input validation failed",
        reason_code="STATIC_EVIDENCE_CONSUMER_CLI_INPUT_INVALID",
        stage="input",
    )
    assert "usage:" not in captured.err


def test_consumer_canary_cli_stdout_write_failure_exits_one_without_echo(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    response_path = tmp_path / "SECRET_STATIC_RESPONSE_STDOUT_PATH_SHOULD_NOT_LEAK.json"
    response_path.write_text(
        (FIXTURES_DIR / "clean_ready_top_level.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    secret_error = "SECRET_STATIC_RESPONSE_STDOUT_ERROR_SHOULD_NOT_LEAK"

    class FailingStdout:
        def write(self, text: str) -> int:
            del text
            raise OSError(secret_error)

        def flush(self) -> None:
            return None

    monkeypatch.setattr(sys, "stdout", FailingStdout())

    exit_code = consumer_module.main(["--response", str(response_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    _assert_cli_error_payload(
        captured.err,
        error="summary output failed",
        reason_code="STATIC_EVIDENCE_CONSUMER_CLI_OUTPUT_FAILED",
        stage="output",
    )
    assert "Traceback" not in captured.err
    assert "OSError" not in captured.err
    assert secret_error not in captured.err
    assert "SECRET_STATIC_RESPONSE_STDOUT_PATH_SHOULD_NOT_LEAK" not in captured.err
    assert str(response_path) not in captured.err


def test_consumer_canary_cli_broken_stderr_is_best_effort(
    monkeypatch,
    capsys,
) -> None:
    secret_error = "SECRET_STATIC_RESPONSE_STDERR_ERROR_SHOULD_NOT_LEAK"

    class FailingStderr:
        def write(self, text: str) -> int:
            del text
            raise OSError(secret_error)

        def flush(self) -> None:
            return None

    monkeypatch.setattr(sys, "stderr", FailingStderr())

    exit_code = consumer_module.main([])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert secret_error not in captured.err


def test_committed_static_evidence_consumer_summary_matches_clean_ready_summary() -> None:
    expected_summary = summarize_static_evidence_contract(_load_fixture("clean_ready_top_level.json"))
    committed = json.loads(CONSUMER_SUMMARY_PATH.read_text(encoding="utf-8"))

    assert committed == expected_summary
    assert committed["summarySchemaVersion"] == SUMMARY_SCHEMA_VERSION
    assert committed["contractPresent"] is True
    assert committed["localStaticEvidenceReady"] is True
    _assert_no_forbidden_output_keys(committed)
    _assert_no_forbidden_output_tokens(committed)


def test_consumer_canary_cli_output_matches_committed_static_evidence_summary(capsys) -> None:
    committed = json.loads(CONSUMER_SUMMARY_PATH.read_text(encoding="utf-8"))

    exit_code = consumer_module.main(["--response", str(FIXTURES_DIR / "clean_ready_top_level.json")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert json.loads(captured.out) == committed
    _assert_no_forbidden_output_keys(committed)
    _assert_no_forbidden_output_tokens(committed)


def test_static_evidence_consumer_summary_artifact_offender_detection_blocks_extra_and_drifted_summaries(
    tmp_path: Path,
) -> None:
    results_root = tmp_path / "benchmark" / "results" / "static_evidence"
    results_root.mkdir(parents=True)
    canonical_path = tmp_path / CONSUMER_SUMMARY_RELATIVE_PATH
    expected_summary = summarize_static_evidence_contract(_load_fixture("clean_ready_top_level.json"))
    canonical_path.write_text(json.dumps(expected_summary, sort_keys=True), encoding="utf-8")

    assert _consumer_summary_artifact_offenders(
        results_root=results_root,
        repo_root=tmp_path,
        expected_summary=expected_summary,
    ) == []

    extra_path = results_root / "stale-consumer-summary.json"
    extra_path.write_text(json.dumps({
        "summarySchemaVersion": SUMMARY_SCHEMA_VERSION,
        "contractPresent": False,
    }), encoding="utf-8")
    assert _consumer_summary_artifact_offenders(
        results_root=results_root,
        repo_root=tmp_path,
        expected_summary=expected_summary,
    ) == ["benchmark/results/static_evidence/stale-consumer-summary.json"]

    extra_path.unlink()
    drifted_summary = copy.deepcopy(expected_summary)
    drifted_summary["localStaticEvidenceReady"] = False
    canonical_path.write_text(json.dumps(drifted_summary, sort_keys=True), encoding="utf-8")
    assert _consumer_summary_artifact_offenders(
        results_root=results_root,
        repo_root=tmp_path,
        expected_summary=expected_summary,
    ) == [str(CONSUMER_SUMMARY_RELATIVE_PATH)]


def test_only_canonical_static_evidence_consumer_summary_artifact_is_committed() -> None:
    expected_summary = summarize_static_evidence_contract(_load_fixture("clean_ready_top_level.json"))

    assert _consumer_summary_artifact_offenders(
        results_root=CONSUMER_SUMMARY_PATH.parent,
        repo_root=REPO_ROOT,
        expected_summary=expected_summary,
    ) == []


def test_consumer_canary_requires_projection_completeness_for_local_static_ready() -> None:
    cases = [
        (
            "empty_projected_evidence",
            lambda contract: (
                contract.__setitem__("coverage", {}),
                contract.__setitem__("claimBoundaries", {}),
                contract.__setitem__("claimBoundaryMatrix", []),
                contract.__setitem__("toolEvidenceMatrix", []),
            ),
        ),
        (
            "missing_required_coverage_surface",
            lambda contract: contract["coverage"].pop("staticToolExecution"),
        ),
        (
            "empty_claim_boundaries",
            lambda contract: contract.__setitem__("claimBoundaries", {}),
        ),
        (
            "incomplete_tool_matrix",
            lambda contract: contract.__setitem__(
                "toolEvidenceMatrix",
                [
                    row
                    for row in contract["toolEvidenceMatrix"]
                    if row.get("toolId") != "gcc-fanalyzer"
                ],
            ),
        ),
        (
            "missing_required_claim_support_status",
            lambda contract: contract.__setitem__(
                "claimBoundaryMatrix",
                [
                    row
                    for row in contract["claimBoundaryMatrix"]
                    if row.get("claimId") != "absence-of-vulnerability"
                ],
            ),
        ),
    ]

    for label, mutate in cases:
        payload = _load_fixture("clean_ready_top_level.json")
        poisoned = copy.deepcopy(payload)
        mutate(poisoned["staticEvidenceContract"])

        summary = summarize_static_evidence_contract(poisoned)

        assert summary["contractPresent"] is True, label
        assert summary["systemStability"] == "pass", label
        assert summary["evidenceReadiness"] == "ready", label
        assert summary["claimSupportReadiness"] == "pass", label
        assert summary["localStaticEvidenceReady"] is False, label
        assert summary["toolAnomalyReasonCodes"] == [], label
        for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
            assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"], label
        _assert_no_forbidden_output_keys(summary)
        _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_does_not_add_completeness_unsafe_for_non_ready_reports() -> None:
    payload = _load_fixture("failed_tool_degraded_top_level.json")
    degraded = copy.deepcopy(payload)
    degraded["staticEvidenceContract"]["coverage"].pop("staticToolExecution", None)
    degraded["staticEvidenceContract"]["claimBoundaries"] = {}
    degraded["staticEvidenceContract"]["claimBoundaryMatrix"] = []
    degraded["staticEvidenceContract"]["toolEvidenceMatrix"] = []

    summary = summarize_static_evidence_contract(degraded)

    assert summary["localStaticEvidenceReady"] is False
    assert summary["systemStability"] == "degraded"
    assert summary["evidenceReadiness"] == "partial"
    assert summary["claimSupportReadiness"] == "partial"
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary[reason_field]
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_sanitizes_unsafe_projection_values() -> None:
    payload = _load_fixture("clean_ready_top_level.json")
    poisoned = copy.deepcopy(payload)
    contract = poisoned["staticEvidenceContract"]
    contract["gates"]["systemStability"]["status"] = "shouldCallS5"
    contract["gates"]["systemStability"]["reasonCodes"] = [
        "routeTo",
        object(),
        123,
        "",
        "POLICY_VIOLATION",
    ]
    contract["gates"]["evidenceReadiness"]["partialSurfaces"] = [
        "findingDataflow",
        "nextService",
        object(),
    ]
    contract["gates"]["claimSupportReadiness"]["reasonCodes"] = ["agentDecision"]
    contract["coverage"]["shouldCallS5"] = {"status": "not_provided"}
    contract["claimBoundaryMatrix"].append({
        "claimId": "routeTo",
        "supportStatus": "verdict",
        "consumerPolicy": "agentDecision",
    })
    contract["toolEvidenceMatrix"].append({
        "toolId": "shouldCallS5",
        "status": "verdict",
        "consumerPolicy": "agentDecision",
    })

    summary = summarize_static_evidence_contract(poisoned)

    assert summary["systemStability"] == "unknown"
    assert summary["localStaticEvidenceReady"] is False
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" in summary[reason_field]
    assert "POLICY_VIOLATION" in summary["systemReasonCodes"]
    assert "findingDataflow" in summary["partialSurfaces"]
    assert "routeTo" not in summary["claimSupportStatuses"]
    assert "shouldCallS5" not in summary["toolMatrixStatuses"]
    assert "shouldCallS5" not in summary["notProvidedSurfaces"]
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary["toolAnomalyReasonCodes"]
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_does_not_stringify_unsafe_surface_keys() -> None:
    class SecretSurface:
        def __str__(self) -> str:
            return "SECRET_SURFACE_KEY_SHOULD_NOT_LEAK"

    payload = _load_fixture("clean_ready_top_level.json")
    poisoned = copy.deepcopy(payload)
    poisoned["staticEvidenceContract"]["coverage"][SecretSurface()] = {"status": "not_provided"}

    summary = summarize_static_evidence_contract(poisoned)

    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" in summary["systemReasonCodes"]
    assert "SECRET_SURFACE_KEY_SHOULD_NOT_LEAK" not in json.dumps(summary, sort_keys=True)
    assert summary["localStaticEvidenceReady"] is False


def test_consumer_canary_marks_malformed_tool_anomaly_reason_as_unsafe_without_echo() -> None:
    payload = _load_fixture("clean_ready_top_level.json")
    poisoned = copy.deepcopy(payload)
    poisoned["staticEvidenceContract"]["coverage"]["staticToolExecution"]["anomalyReasonCodes"] = [
        "TOOL_FAILED:semgrep",
        "shouldCallS5",
        object(),
    ]

    summary = summarize_static_evidence_contract(poisoned)

    assert summary["toolAnomalyReasonCodes"] == ["TOOL_FAILED:semgrep"]
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary["toolAnomalyReasonCodes"]
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" in summary[reason_field]
    assert summary["localStaticEvidenceReady"] is False
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_preserves_generated_partial_tool_state_without_unsafe_projection() -> None:
    payload = _load_fixture("clean_ready_top_level.json")
    partial = copy.deepcopy(payload)
    contract = partial["staticEvidenceContract"]
    contract["gates"]["systemStability"]["status"] = "degraded"
    contract["gates"]["systemStability"]["reasonCodes"] = ["TOOL_EXECUTION_PARTIAL", "TOOL_PARTIAL:semgrep"]
    contract["gates"]["evidenceReadiness"]["status"] = "partial"
    contract["gates"]["evidenceReadiness"]["reasonCodes"] = ["LOCAL_EVIDENCE_PARTIAL"]
    contract["gates"]["claimSupportReadiness"]["status"] = "partial"
    contract["gates"]["claimSupportReadiness"]["reasonCodes"] = ["LOCAL_ARTIFACT_DEGRADED"]
    contract["coverage"]["staticToolExecution"]["status"] = "partial"
    contract["coverage"]["staticToolExecution"]["anomalyReasonCodes"] = ["TOOL_PARTIAL:semgrep"]
    contract["toolEvidenceMatrix"][0]["toolId"] = "semgrep"
    contract["toolEvidenceMatrix"][0]["status"] = "partial"
    contract["toolEvidenceMatrix"][0]["consumerPolicy"] = "local_tool_partial_use_with_degradation_metadata"

    summary = summarize_static_evidence_contract(partial)

    assert summary["systemStability"] == "degraded"
    assert summary["evidenceReadiness"] == "partial"
    assert summary["claimSupportReadiness"] == "partial"
    assert summary["localStaticEvidenceReady"] is False
    assert summary["toolAnomalyReasonCodes"] == ["TOOL_PARTIAL:semgrep"]
    assert summary["toolMatrixStatuses"]["semgrep"] == "partial"
    assert summary["toolConsumerPolicies"]["semgrep"] == "local_tool_partial_use_with_degradation_metadata"
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary[reason_field]
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_preserves_generated_failure_and_unknown_reason_codes() -> None:
    payload = _load_fixture("clean_ready_top_level.json")
    failed = copy.deepcopy(payload)
    contract = failed["staticEvidenceContract"]
    contract["gates"]["systemStability"]["status"] = "fail"
    contract["gates"]["systemStability"]["reasonCodes"] = [
        "RESPONSE_FAILED",
        "ARTIFACT_FAILED",
        "REQUIRED_EVIDENCE_MISSING",
        "EXECUTION_DEGRADED",
        "TOOL_DEGRADED:semgrep",
        "TOOL_STATUS_UNKNOWN:cppcheck",
    ]
    contract["gates"]["evidenceReadiness"]["status"] = "not_ready"
    contract["gates"]["evidenceReadiness"]["reasonCodes"] = ["REQUIRED_EVIDENCE_MISSING"]
    contract["gates"]["claimSupportReadiness"]["status"] = "fail"
    contract["gates"]["claimSupportReadiness"]["reasonCodes"] = ["CLAIM_SUPPORT_CLASSIFICATION_UNKNOWN"]
    contract["coverage"]["staticToolExecution"]["status"] = "partial"
    contract["coverage"]["staticToolExecution"]["anomalyReasonCodes"] = [
        "TOOL_DEGRADED:semgrep",
        "TOOL_STATUS_UNKNOWN:cppcheck",
    ]
    contract["toolEvidenceMatrix"][1]["toolId"] = "cppcheck"
    contract["toolEvidenceMatrix"][1]["status"] = "unknown"

    summary = summarize_static_evidence_contract(failed)

    assert summary["systemStability"] == "fail"
    assert summary["evidenceReadiness"] == "not_ready"
    assert summary["claimSupportReadiness"] == "fail"
    assert summary["localStaticEvidenceReady"] is False
    assert "RESPONSE_FAILED" in summary["systemReasonCodes"]
    assert "ARTIFACT_FAILED" in summary["systemReasonCodes"]
    assert "REQUIRED_EVIDENCE_MISSING" in summary["evidenceReasonCodes"]
    assert "CLAIM_SUPPORT_CLASSIFICATION_UNKNOWN" in summary["claimSupportReasonCodes"]
    assert summary["toolAnomalyReasonCodes"] == [
        "TOOL_DEGRADED:semgrep",
        "TOOL_STATUS_UNKNOWN:cppcheck",
    ]
    assert summary["toolMatrixStatuses"]["cppcheck"] == "unknown"
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary[reason_field]
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_caller_provided_unsafe_projection_reason_as_spoofed() -> None:
    payload = _load_fixture("clean_ready_top_level.json")
    spoofed = copy.deepcopy(payload)
    contract = spoofed["staticEvidenceContract"]
    contract["gates"]["systemStability"]["reasonCodes"] = ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
    contract["gates"]["evidenceReadiness"]["reasonCodes"] = ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
    contract["gates"]["claimSupportReadiness"]["reasonCodes"] = ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
    contract["coverage"]["staticToolExecution"]["anomalyReasonCodes"] = [
        "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"
    ]

    summary = summarize_static_evidence_contract(spoofed)

    assert summary["systemStability"] == "pass"
    assert summary["evidenceReadiness"] == "ready"
    assert summary["claimSupportReadiness"] == "pass"
    assert summary["localStaticEvidenceReady"] is False
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary["toolAnomalyReasonCodes"]
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_caller_provided_absent_malformed_reasons_as_spoofed() -> None:
    payload = _load_fixture("clean_ready_top_level.json")
    spoofed = copy.deepcopy(payload)
    contract = spoofed["staticEvidenceContract"]
    summary_only_reasons = [
        "STATIC_EVIDENCE_CONTRACT_ABSENT",
        "STATIC_EVIDENCE_CONTRACT_MALFORMED",
    ]
    contract["gates"]["systemStability"]["reasonCodes"] = summary_only_reasons
    contract["gates"]["evidenceReadiness"]["reasonCodes"] = summary_only_reasons
    contract["gates"]["claimSupportReadiness"]["reasonCodes"] = summary_only_reasons
    contract["coverage"]["staticToolExecution"]["anomalyReasonCodes"] = summary_only_reasons

    summary = summarize_static_evidence_contract(spoofed)

    assert summary["systemStability"] == "pass"
    assert summary["evidenceReadiness"] == "ready"
    assert summary["claimSupportReadiness"] == "pass"
    assert summary["localStaticEvidenceReady"] is False
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
        assert "STATIC_EVIDENCE_CONTRACT_ABSENT" not in summary[reason_field]
        assert "STATIC_EVIDENCE_CONTRACT_MALFORMED" not in summary[reason_field]
    assert summary["toolAnomalyReasonCodes"] == []
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_malformed_coverage_container_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_STATIC_COVERAGE_CONTAINER_SHOULD_NOT_LEAK"

    payload = _load_fixture("clean_ready_top_level.json")
    poisoned = copy.deepcopy(payload)
    poisoned["staticEvidenceContract"]["coverage"] = [SecretContainer()]

    summary = summarize_static_evidence_contract(poisoned)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["contractPresent"] is True
    assert summary["localStaticEvidenceReady"] is False
    assert summary["notProvidedSurfaces"] == []
    assert summary["toolAnomalyReasonCodes"] == []
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary["toolAnomalyReasonCodes"]
    assert "SECRET_STATIC_COVERAGE_CONTAINER_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_malformed_claim_boundaries_container_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_STATIC_BOUNDARIES_CONTAINER_SHOULD_NOT_LEAK"

    payload = _load_fixture("clean_ready_top_level.json")
    poisoned = copy.deepcopy(payload)
    poisoned["staticEvidenceContract"]["claimBoundaries"] = [SecretContainer()]

    summary = summarize_static_evidence_contract(poisoned)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["contractPresent"] is True
    assert summary["localStaticEvidenceReady"] is False
    assert summary["mustNotSupportAlone"] == []
    assert summary["toolAnomalyReasonCodes"] == []
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
    assert "SECRET_STATIC_BOUNDARIES_CONTAINER_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_malformed_gate_containers_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_STATIC_GATE_CONTAINER_SHOULD_NOT_LEAK"

    cases = [
        ("systemStability", "systemStability", "unknown"),
        ("evidenceReadiness", "evidenceReadiness", "not_ready"),
        ("claimSupportReadiness", "claimSupportReadiness", "unknown"),
        ("qualityEvaluation", "qualityEvaluation", "unknown"),
    ]

    for gate_key, summary_field, expected_status in cases:
        payload = _load_fixture("clean_ready_top_level.json")
        poisoned = copy.deepcopy(payload)
        poisoned["staticEvidenceContract"]["gates"][gate_key] = [SecretContainer()]

        summary = summarize_static_evidence_contract(poisoned)
        serialized = json.dumps(summary, sort_keys=True)

        assert summary["contractPresent"] is True, gate_key
        assert summary[summary_field] == expected_status, gate_key
        assert summary["localStaticEvidenceReady"] is False, gate_key
        assert summary["toolAnomalyReasonCodes"] == [], gate_key
        for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
            assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"], gate_key
        assert "SECRET_STATIC_GATE_CONTAINER_SHOULD_NOT_LEAK" not in serialized, gate_key
        _assert_no_forbidden_output_keys(summary)
        _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_malformed_static_tool_execution_container_as_unsafe() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_STATIC_TOOL_EXECUTION_CONTAINER_SHOULD_NOT_LEAK"

    payload = _load_fixture("clean_ready_top_level.json")
    poisoned = copy.deepcopy(payload)
    poisoned["staticEvidenceContract"]["coverage"]["staticToolExecution"] = [SecretContainer()]

    summary = summarize_static_evidence_contract(poisoned)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["contractPresent"] is True
    assert summary["localStaticEvidenceReady"] is False
    assert summary["toolAnomalyReasonCodes"] == []
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"]
    assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary["toolAnomalyReasonCodes"]
    assert "SECRET_STATIC_TOOL_EXECUTION_CONTAINER_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_duplicate_tool_matrix_identities_as_unsafe() -> None:
    class SecretValue:
        def __str__(self) -> str:
            return "SECRET_STATIC_TOOL_MATRIX_DUPLICATE_SHOULD_NOT_LEAK"

    cases = [
        (
            "conflicting_duplicate",
            {
                "toolId": "semgrep",
                "status": "failed",
                "consumerPolicy": "local_tool_failed_do_not_use_as_negative_evidence",
                "secret": SecretValue(),
            },
        ),
        (
            "same_value_duplicate",
            {
                "toolId": "semgrep",
                "status": "ok",
                "consumerPolicy": "local_tool_execution_state_only_not_vulnerability_verdict",
                "secret": SecretValue(),
            },
        ),
    ]

    for label, duplicate_row in cases:
        payload = _load_fixture("clean_ready_top_level.json")
        poisoned = copy.deepcopy(payload)
        poisoned["staticEvidenceContract"]["toolEvidenceMatrix"].append(duplicate_row)

        summary = summarize_static_evidence_contract(poisoned)
        serialized = json.dumps(summary, sort_keys=True)

        assert summary["contractPresent"] is True, label
        assert summary["localStaticEvidenceReady"] is False, label
        assert summary["toolMatrixStatuses"]["semgrep"] == "ok", label
        assert summary["toolConsumerPolicies"]["semgrep"] == (
            "local_tool_execution_state_only_not_vulnerability_verdict"
        ), label
        assert summary["toolMatrixStatuses"]["cppcheck"] == "ok", label
        assert summary["toolConsumerPolicies"]["cppcheck"] == (
            "local_tool_execution_state_only_not_vulnerability_verdict"
        ), label
        assert summary["toolAnomalyReasonCodes"] == [], label
        for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
            assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"], label
        assert "STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION" not in summary["toolAnomalyReasonCodes"], label
        assert "SECRET_STATIC_TOOL_MATRIX_DUPLICATE_SHOULD_NOT_LEAK" not in serialized, label
        _assert_no_forbidden_output_keys(summary)
        _assert_no_forbidden_output_tokens(summary)


def test_consumer_canary_treats_duplicate_claim_matrix_identities_as_unsafe() -> None:
    class SecretValue:
        def __str__(self) -> str:
            return "SECRET_STATIC_CLAIM_MATRIX_DUPLICATE_SHOULD_NOT_LEAK"

    cases = [
        (
            "supported_then_unsupported",
            "local-static-artifact",
            "supported",
            "unsupported",
            False,
        ),
        (
            "unsupported_then_supported",
            "absence-of-vulnerability",
            "unsupported",
            "supported",
            True,
        ),
        (
            "same_value_duplicate",
            "absence-of-vulnerability",
            "unsupported",
            "unsupported",
            True,
        ),
    ]

    for label, claim_id, expected_first_status, duplicate_status, expected_unsupported in cases:
        payload = _load_fixture("clean_ready_top_level.json")
        poisoned = copy.deepcopy(payload)
        poisoned["staticEvidenceContract"]["claimBoundaryMatrix"].append({
            "claimId": claim_id,
            "supportStatus": duplicate_status,
            "consumerPolicy": "do_not_use_as_negative_evidence",
            "secret": SecretValue(),
        })

        summary = summarize_static_evidence_contract(poisoned)
        serialized = json.dumps(summary, sort_keys=True)

        assert summary["contractPresent"] is True, label
        assert summary["localStaticEvidenceReady"] is False, label
        assert summary["claimSupportStatuses"][claim_id] == expected_first_status, label
        assert ("local-static-artifact" in summary["unsupportedClaims"]) is False, label
        assert ("absence-of-vulnerability" in summary["unsupportedClaims"]) is True, label
        assert (claim_id in summary["unsupportedClaims"]) is expected_unsupported, label
        assert summary["claimSupportStatuses"]["reported-finding-positive-evidence"] == "not_applicable", label
        assert summary["toolAnomalyReasonCodes"] == [], label
        for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
            assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_UNSAFE_PROJECTION"], label
        assert "SECRET_STATIC_CLAIM_MATRIX_DUPLICATE_SHOULD_NOT_LEAK" not in serialized, label
        _assert_no_forbidden_output_keys(summary)
        _assert_no_forbidden_output_tokens(summary)


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


def test_malformed_nested_scan_container_is_not_classified_as_absent() -> None:
    class SecretContainer:
        def __str__(self) -> str:
            return "SECRET_STATIC_SCAN_CONTAINER_SHOULD_NOT_LEAK"

    payload = {"success": True, "scan": [SecretContainer()]}

    summary = summarize_static_evidence_contract(payload)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["contractPresent"] is False
    assert summary["contractLocation"] == "malformed"
    assert summary["localStaticEvidenceReady"] is False
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_MALFORMED"]
    assert summary["toolAnomalyReasonCodes"] == []
    assert "SECRET_STATIC_SCAN_CONTAINER_SHOULD_NOT_LEAK" not in serialized
    _assert_no_forbidden_output_keys(summary)
    _assert_no_forbidden_output_tokens(summary)


def test_none_nested_scan_container_remains_absent_compatible() -> None:
    summary = summarize_static_evidence_contract({"success": True, "scan": None})

    assert summary["contractPresent"] is False
    assert summary["contractLocation"] == "missing"
    assert summary["localStaticEvidenceReady"] is False
    for reason_field in ("systemReasonCodes", "evidenceReasonCodes", "claimSupportReasonCodes"):
        assert summary[reason_field] == ["STATIC_EVIDENCE_CONTRACT_ABSENT"]
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
