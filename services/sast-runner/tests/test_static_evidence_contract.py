"""Executable RED oracles for S4 Static Evidence Contract v1.

The tests are intentionally added before the producer implementation.  RED
should mean the additive ``staticEvidenceContract`` artifact is absent, not
that S4 contacted external services or emitted a verdict.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.scanner.evidence import enrich_finding_evidence
from app.scanner.orchestrator import ALL_TOOLS
from app.scanner.static_evidence_contract import (
    TOOL_EVIDENCE_ORDER,
    _evidence_readiness as _evaluate_evidence_readiness,
    build_static_evidence_contract,
)
from app.schemas.request import SnapshotProvenance
from app.schemas.response import (
    BuildEvidence,
    BuildReadiness,
    BuildResponse,
    ExecutionReport,
    FindingsFilterInfo,
    SastDataFlowStep,
    SastFinding,
    SastFindingLocation,
    ScanStats,
    SdkResolutionInfo,
    ToolExecutionResult,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CONTRACT_FIXTURE = FIXTURES_DIR / "static_evidence_contract" / "minimum_contract_oracle.json"
EVIDENCE_FIXTURES = FIXTURES_DIR / "evidence_oracles"
FORBIDDEN_NEUTRAL_HINT_TOKENS = (
    "post ",
    "/v1/",
    "batch-lookup",
    "batch lookup",
    "call s5",
    "s5 ",
    "s5.",
    "s5/",
    "http://",
    "https://",
    "openai",
    "anthropic",
    "llm",
    "risk score",
    "security verdict",
)


def _load_oracle() -> dict[str, Any]:
    return json.loads(CONTRACT_FIXTURE.read_text())


def _assert_no_verdict_keys(value: Any, forbidden: set[str], path: str = "$") -> None:
    if isinstance(value, dict):
        overlap = forbidden.intersection(value)
        assert not overlap, f"verdict-like key(s) at {path}: {sorted(overlap)}"
        for key, nested in value.items():
            _assert_no_verdict_keys(nested, forbidden, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_verdict_keys(nested, forbidden, f"{path}[{index}]")


def _assert_neutral_readiness_items(items: list[dict[str, Any]] | None) -> None:
    if not items:
        return
    for item in items:
        text = json.dumps(item, sort_keys=True).lower()
        for token in FORBIDDEN_NEUTRAL_HINT_TOKENS:
            assert token not in text, f"non-neutral follow-up token {token!r} in {item!r}"


def _assert_static_evidence_contract_minimum(contract: dict[str, Any]) -> None:
    oracle = _load_oracle()
    forbidden = set(oracle["forbiddenVerdictKeys"])

    missing_top = sorted(set(oracle["requiredTopLevelKeys"]) - set(contract))
    assert not missing_top, f"missing required staticEvidenceContract keys: {missing_top}"
    assert "missingEvidence" not in oracle["requiredTopLevelKeys"]

    assert contract["schemaVersion"] == oracle["schemaVersion"]
    assert contract["analysisProfile"] == oracle["analysisProfile"]
    assert contract["artifactKind"] == oracle["artifactKind"]
    assert contract["producer"]["service"] == "s4-sast-runner"
    assert contract["producer"]["deterministic"] is True

    gates = contract["gates"]
    assert sorted(gates) == sorted(oracle["requiredGateKeys"])
    quality = gates["qualityEvaluation"]
    assert quality["status"] == oracle["qualityEvaluationDefault"]["status"]
    assert oracle["qualityEvaluationDefault"]["reasonCode"] in quality["reasonCodes"]
    assert quality["consumerPolicy"] == oracle["qualityEvaluationDefault"]["consumerPolicy"]
    claim_support = gates["claimSupportReadiness"]
    assert claim_support["status"] in oracle["allowedClaimSupportReadinessStatuses"]
    assert claim_support["consumerPolicy"] == oracle["claimSupportReadinessDefaultPolicy"]

    coverage = contract["coverage"]
    missing_coverage = sorted(set(oracle["requiredCoverageSurfaces"]) - set(coverage))
    assert not missing_coverage, f"missing coverage surface(s): {missing_coverage}"

    allowed_statuses = set(oracle["allowedCoverageStatuses"])
    for surface, entry in coverage.items():
        assert entry["status"] in allowed_statuses, f"invalid status for {surface}: {entry}"
        if entry["status"] != "provided":
            assert entry.get("reasonCodes"), f"non-provided coverage needs reasonCodes: {surface}"
            assert entry.get("consumerPolicy"), f"non-provided coverage needs consumerPolicy: {surface}"

    for surface, reason_code in oracle["requiredNotProvidedSurfaces"].items():
        entry = coverage[surface]
        assert entry["status"] == "not_provided"
        assert reason_code in entry["reasonCodes"]
        assert entry["consumerPolicy"] == oracle["nonProvidedConsumerPolicy"]

    structural = coverage["structuralCodeGraph"]
    if structural["status"] == "provided":
        expected = oracle["structuralCodeGraphProvided"]
        assert structural["graphKind"] == expected["graphKind"]
        assert structural["semanticRetrieval"] == expected["semanticRetrieval"]
        assert structural["graphRag"] == expected["graphRag"]
        assert structural["consumerPolicy"] == expected["consumerPolicy"]

    boundaries = contract["claimBoundaries"]
    assert boundaries["negativeEvidencePolicy"] == oracle["negativeEvidencePolicy"]
    assert "absence-of-vulnerability-from-empty-findings" in boundaries["mustNotSupportAlone"]
    assert "final-security-verdict" in boundaries["mustNotSupportAlone"]

    claim_matrix = contract["claimBoundaryMatrix"]
    assert isinstance(claim_matrix, list)
    claim_by_id = {entry["claimId"]: entry for entry in claim_matrix}
    assert len(claim_by_id) == len(claim_matrix)
    missing_claims = sorted(set(oracle["requiredClaimBoundaryClaims"]) - set(claim_by_id))
    assert not missing_claims, f"missing claim-boundary entries: {missing_claims}"
    allowed_claim_statuses = set(oracle["allowedClaimSupportStatuses"])
    for claim_id, entry in claim_by_id.items():
        assert entry["claimType"], f"claimType is required for {claim_id}"
        assert entry["supportStatus"] in allowed_claim_statuses
        assert entry["consumerPolicy"], f"consumerPolicy is required for {claim_id}"
        assert isinstance(entry["reasonCodes"], list)
        assert isinstance(entry["evidenceRefs"], list)
    assert claim_by_id["absence-of-vulnerability"]["supportStatus"] == "unsupported"
    assert claim_by_id["absence-of-vulnerability"]["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert claim_by_id["cwe-absence"]["supportStatus"] == "unsupported"
    assert claim_by_id["cwe-absence"]["consumerPolicy"] == "do_not_use_as_negative_evidence"

    matrix = contract["toolEvidenceMatrix"]
    assert [entry["toolId"] for entry in matrix] == oracle["requiredToolEvidenceOrder"]
    allowed_tool_policies = set(oracle["allowedToolExecutionConsumerPolicies"])
    for entry in matrix:
        assert entry["consumerPolicy"] in allowed_tool_policies
        assert entry["deterministic"] is True
        assert entry["requiresNetwork"] is False
        assert entry["requiresExternalKnowledge"] is False
        assert entry["emitsFinalVerdict"] is False
        assert entry["verdictPolicy"] == "local-tool-state-is-not-a-vulnerability-verdict"
        assert entry["role"]
        assert entry["uniqueContribution"]
        assert entry["limitations"]

    _assert_neutral_readiness_items(contract.get("followUpHints"))
    _assert_neutral_readiness_items(contract.get("missingEvidence"))
    _assert_no_verdict_keys(contract, forbidden)


def _execution_report(*, degraded: bool = False) -> ExecutionReport:
    return ExecutionReport(
        toolsRun=["semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"],
        toolResults={
            "semgrep": ToolExecutionResult(status="ok", findingsCount=1, elapsedMs=10, version="1.45.0"),
            "cppcheck": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=5, version="2.13.0"),
            "flawfinder": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=3, version="2.0.19"),
            "clang-tidy": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=8, version="18.1.3"),
            "scan-build": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=8, version="18.1.3"),
            "gcc-fanalyzer": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=8, version="13.3.0"),
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=degraded,
        degradeReasons=["oracle-degraded"] if degraded else [],
    )


def _policy_failure_execution_report() -> ExecutionReport:
    execution = _execution_report()
    return execution.model_copy(
        update={
            "tools_run": ["cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"],
            "tool_results": {
                **execution.tool_results,
                "semgrep": ToolExecutionResult(
                    status="skipped",
                    findingsCount=0,
                    elapsedMs=0,
                    skipReason="environment-drift",
                    version="1.45.0",
                ),
            },
        },
    )


def _execution_report_with_tool_result(
    tool_id: str,
    result: ToolExecutionResult | None,
    *,
    tools_run: list[str] | None = None,
    degraded: bool = False,
    degrade_reasons: list[str] | None = None,
) -> ExecutionReport:
    execution = _execution_report(degraded=degraded)
    tool_results = dict(execution.tool_results)
    if result is None:
        tool_results.pop(tool_id, None)
    else:
        tool_results[tool_id] = result
    return execution.model_copy(
        update={
            "tools_run": tools_run or list(execution.tools_run),
            "tool_results": tool_results,
            "degraded": degraded,
            "degrade_reasons": degrade_reasons or ([] if not degraded else ["oracle-degraded"]),
        },
    )


def _oracle_finding() -> SastFinding:
    return SastFinding(
        toolId="semgrep",
        ruleId="c.security.strcpy",
        severity="high",
        message="oracle finding",
        location=SastFindingLocation(file="src/vulnerable.c", line=4, column=5),
        metadata={"cweId": "CWE-120", "cwe": ["CWE-120"]},
    )


def _oracle_dataflow_finding() -> SastFinding:
    return SastFinding(
        toolId="semgrep",
        ruleId="c.security.strcpy",
        severity="high",
        message="oracle finding",
        location=SastFindingLocation(file="src/vulnerable.c", line=4, column=5),
        dataFlow=[SastDataFlowStep(file="src/vulnerable.c", line=4, content="strcpy(dst, src);")],
        metadata={"cweId": "CWE-120", "cwe": ["CWE-120"]},
    )


def _build_response(project: Path, provenance: SnapshotProvenance) -> BuildResponse:
    return BuildResponse(
        success=True,
        provenance=provenance,
        buildEvidence=BuildEvidence(
            requestedBuildCommand="make",
            effectiveBuildCommand="make",
            buildDir=str(project),
            compileCommandsPath=str(project / "compile_commands.json"),
            entries=1,
            userEntries=1,
            exitCode=0,
            buildOutput="ok",
            wrapWithBear=True,
            timeoutSeconds=600,
            environmentKeys=[],
            elapsedMs=1,
        ),
        readiness=BuildReadiness(
            status="ready",
            compileCommandsReady=True,
            quickEligible=True,
            summary="ready",
        ),
    )


def test_contract_oracle_fixture_matches_s3_minimum_key_set() -> None:
    oracle = _load_oracle()

    assert oracle["schemaVersion"] == "s4-static-evidence-contract-v1"
    assert "followUpHints" in oracle["requiredTopLevelKeys"]
    assert "toolEvidenceMatrix" in oracle["requiredTopLevelKeys"]
    assert "missingEvidence" not in oracle["requiredTopLevelKeys"]
    assert "missingEvidence" in oracle["optionalTopLevelKeys"]
    assert oracle["requiredToolEvidenceOrder"] == ALL_TOOLS
    assert tuple(oracle["requiredToolEvidenceOrder"]) == TOOL_EVIDENCE_ORDER
    assert set(oracle["requiredNotProvidedSurfaces"]) == {
        "externalVulnerabilityKnowledge",
        "semanticGraphRetrieval",
        "runtimeBehavior",
        "exploitabilityJudgment",
        "finalSecurityVerdict",
    }


def test_tool_evidence_matrix_covers_current_tools_and_consumer_policy_taxonomy() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    execution = ExecutionReport(
        toolsRun=["semgrep", "cppcheck", "flawfinder"],
        toolResults={
            "semgrep": ToolExecutionResult(status="ok", findingsCount=1, elapsedMs=10, version="1.45.0"),
            "cppcheck": ToolExecutionResult(
                status="partial",
                findingsCount=2,
                elapsedMs=30,
                degraded=True,
                degradeReasons=["timed-out-files"],
                version="2.13.0",
            ),
            "flawfinder": ToolExecutionResult(status="failed", findingsCount=0, elapsedMs=4, skipReason="parse-error"),
            "clang-tidy": ToolExecutionResult(
                status="skipped",
                findingsCount=0,
                elapsedMs=0,
                skipReason="operator-requested-subset",
            ),
            "scan-build": ToolExecutionResult(
                status="skipped",
                findingsCount=0,
                elapsedMs=0,
                skipReason="runtime-tool-missing",
            ),
            "gcc-fanalyzer": ToolExecutionResult(
                status="skipped",
                findingsCount=0,
                elapsedMs=0,
                skipReason="profile-not-applicable",
            ),
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=True,
        degradeReasons=["timed-out-files"],
    )

    matrix = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=execution,
    )["toolEvidenceMatrix"]
    by_tool = {entry["toolId"]: entry for entry in matrix}

    assert list(by_tool) == ALL_TOOLS
    assert by_tool["semgrep"]["status"] == "ok"
    assert by_tool["semgrep"]["consumerPolicy"] == "local_tool_execution_state_only_not_vulnerability_verdict"
    assert by_tool["semgrep"]["findingsCount"] == 1
    assert by_tool["cppcheck"]["consumerPolicy"] == "local_tool_partial_use_with_degradation_metadata"
    assert by_tool["cppcheck"]["degraded"] is True
    assert by_tool["cppcheck"]["degradeReasons"] == ["timed-out-files"]
    assert by_tool["flawfinder"]["consumerPolicy"] == "local_tool_failed_do_not_use_as_negative_evidence"
    assert by_tool["clang-tidy"]["consumerPolicy"] == "not_requested_or_not_applicable"
    assert by_tool["scan-build"]["consumerPolicy"] == "blocks_successful_artifact"
    assert by_tool["gcc-fanalyzer"]["consumerPolicy"] == "not_requested_or_not_applicable"
    for entry in matrix:
        assert entry["deterministic"] is True
        assert entry["requiresNetwork"] is False
        assert entry["requiresExternalKnowledge"] is False
        assert entry["emitsFinalVerdict"] is False
        assert entry["verdictPolicy"] == "local-tool-state-is-not-a-vulnerability-verdict"


def test_tool_evidence_matrix_fails_closed_when_execution_metadata_is_absent() -> None:
    contract = build_static_evidence_contract(
        success=True,
        findings=[],
        execution=None,
    )

    matrix = contract["toolEvidenceMatrix"]
    assert [entry["toolId"] for entry in matrix] == ALL_TOOLS
    assert {entry["status"] for entry in matrix} == {"not_recorded"}
    assert {entry["consumerPolicy"] for entry in matrix} == {"metadata_absent_do_not_infer"}
    assert all(entry["evidenceRefs"] == [] for entry in matrix)


def test_policy_failure_reason_forces_fail_and_not_ready_even_if_success_flag_true() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(),
        policy_failure_reason_codes=["POLICY_VIOLATION", "DISALLOWED_TOOL_OMISSION"],
    )

    stability = contract["gates"]["systemStability"]
    readiness = contract["gates"]["evidenceReadiness"]
    assert stability["status"] == "fail"
    assert "POLICY_VIOLATION" in stability["reasonCodes"]
    assert readiness["status"] == "not_ready"
    assert "POLICY_VIOLATION" in readiness["reasonCodes"]


def test_system_stability_pass_when_successful_execution_is_clean() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(),
    )

    stability = contract["gates"]["systemStability"]
    assert stability == {
        "status": "pass",
        "reasonCodes": [],
        "consumerPolicy": "local_artifact_stable",
    }


def test_system_stability_degraded_when_execution_reports_degradation() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(degraded=True),
    )

    stability = contract["gates"]["systemStability"]
    assert stability["status"] == "degraded"
    assert stability["reasonCodes"] == ["oracle-degraded"]
    assert stability["consumerPolicy"] == "use_with_degradation_metadata"
    assert contract["gates"]["evidenceReadiness"]["status"] == "ready"


def test_tool_failed_degrades_stability_and_partializes_required_execution_surface() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    execution = _execution_report_with_tool_result(
        "scan-build",
        ToolExecutionResult(status="failed", findingsCount=0, elapsedMs=11, skipReason="parse-error"),
    )

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=execution,
    )

    stability = contract["gates"]["systemStability"]
    assert stability["status"] == "degraded"
    assert stability["reasonCodes"] == ["TOOL_FAILED:scan-build"]
    static_execution = contract["coverage"]["staticToolExecution"]
    assert static_execution["status"] == "partial"
    assert "TOOL_EXECUTION_PARTIAL" in static_execution["reasonCodes"]
    assert static_execution["anomalyReasonCodes"] == ["TOOL_FAILED:scan-build"]
    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "partial"
    assert "staticToolExecution" in readiness["partialSurfaces"]
    matrix = {entry["toolId"]: entry for entry in contract["toolEvidenceMatrix"]}
    assert matrix["scan-build"]["consumerPolicy"] == "local_tool_failed_do_not_use_as_negative_evidence"


def test_tool_partial_and_degraded_metadata_have_deterministic_anomaly_order() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    clean_execution = _execution_report()
    tool_results = dict(clean_execution.tool_results)
    tool_results["cppcheck"] = ToolExecutionResult(
        status="partial",
        findingsCount=1,
        elapsedMs=33,
        degraded=True,
        degradeReasons=["timed-out-files"],
    )
    tool_results["gcc-fanalyzer"] = ToolExecutionResult(
        status="ok",
        findingsCount=0,
        elapsedMs=22,
        degraded=True,
        degradeReasons=["recovered-nonfatal-warning"],
    )
    execution = clean_execution.model_copy(
        update={
            "tool_results": tool_results,
        },
    )

    contract = build_static_evidence_contract(success=True, findings=[finding], execution=execution)

    assert contract["gates"]["systemStability"]["status"] == "degraded"
    assert contract["gates"]["systemStability"]["reasonCodes"] == [
        "TOOL_PARTIAL:cppcheck",
        "TOOL_DEGRADED:gcc-fanalyzer",
    ]
    static_execution = contract["coverage"]["staticToolExecution"]
    assert static_execution["status"] == "partial"
    assert static_execution["anomalyReasonCodes"] == [
        "TOOL_PARTIAL:cppcheck",
        "TOOL_DEGRADED:gcc-fanalyzer",
    ]
    assert contract["gates"]["evidenceReadiness"]["status"] == "partial"


def test_tool_partial_status_subsumes_its_degraded_flag_in_anomaly_codes() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    execution = _execution_report_with_tool_result(
        "gcc-fanalyzer",
        ToolExecutionResult(
            status="partial",
            findingsCount=1,
            elapsedMs=33,
            degraded=True,
            degradeReasons=["timed-out-files"],
        ),
    )

    contract = build_static_evidence_contract(success=True, findings=[finding], execution=execution)

    assert contract["gates"]["systemStability"]["status"] == "degraded"
    assert contract["gates"]["systemStability"]["reasonCodes"] == ["TOOL_PARTIAL:gcc-fanalyzer"]
    assert contract["coverage"]["staticToolExecution"]["status"] == "partial"
    assert contract["coverage"]["staticToolExecution"]["anomalyReasonCodes"] == ["TOOL_PARTIAL:gcc-fanalyzer"]
    assert contract["gates"]["evidenceReadiness"]["status"] == "partial"


def test_allowed_tool_skip_does_not_degrade_artifact_when_other_required_surfaces_are_ready() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    execution = _execution_report_with_tool_result(
        "clang-tidy",
        ToolExecutionResult(
            status="skipped",
            findingsCount=0,
            elapsedMs=0,
            skipReason="profile-not-applicable",
        ),
    )

    contract = build_static_evidence_contract(success=True, findings=[finding], execution=execution)

    assert contract["gates"]["systemStability"]["status"] == "pass"
    assert contract["coverage"]["staticToolExecution"]["status"] == "provided"
    assert contract["gates"]["evidenceReadiness"]["status"] == "ready"


def test_blocking_skip_without_policy_reason_degrades_but_policy_reason_still_fails() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    execution = _execution_report_with_tool_result(
        "semgrep",
        ToolExecutionResult(
            status="skipped",
            findingsCount=0,
            elapsedMs=0,
            skipReason="environment-drift",
        ),
    )

    degraded_contract = build_static_evidence_contract(success=True, findings=[finding], execution=execution)

    assert degraded_contract["gates"]["systemStability"]["status"] == "degraded"
    assert degraded_contract["gates"]["systemStability"]["reasonCodes"] == ["TOOL_BLOCKING_SKIP:semgrep"]
    assert degraded_contract["coverage"]["staticToolExecution"]["status"] == "partial"
    assert degraded_contract["gates"]["evidenceReadiness"]["status"] == "partial"

    failed_contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=execution,
        policy_failure_reason_codes=["POLICY_VIOLATION", "DISALLOWED_TOOL_ENVIRONMENT_DRIFT"],
    )

    assert failed_contract["gates"]["systemStability"]["status"] == "fail"
    assert failed_contract["gates"]["evidenceReadiness"]["status"] == "not_ready"


def test_missing_current_tool_result_partializes_execution_surface() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    execution = _execution_report_with_tool_result("flawfinder", None)

    contract = build_static_evidence_contract(success=True, findings=[finding], execution=execution)

    assert contract["gates"]["systemStability"]["status"] == "degraded"
    assert contract["gates"]["systemStability"]["reasonCodes"] == ["TOOL_NOT_RECORDED:flawfinder"]
    assert contract["coverage"]["staticToolExecution"]["status"] == "partial"
    assert contract["gates"]["evidenceReadiness"]["status"] == "partial"


def test_matrix_not_recorded_tools_are_summarized_by_gates() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    execution = ExecutionReport(
        toolsRun=["semgrep"],
        toolResults={
            "semgrep": ToolExecutionResult(status="ok", findingsCount=1, elapsedMs=10, version="1.45.0"),
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=False,
        degradeReasons=[],
    )

    contract = build_static_evidence_contract(success=True, findings=[finding], execution=execution)

    expected_missing = [
        "TOOL_NOT_RECORDED:cppcheck",
        "TOOL_NOT_RECORDED:flawfinder",
        "TOOL_NOT_RECORDED:clang-tidy",
        "TOOL_NOT_RECORDED:scan-build",
        "TOOL_NOT_RECORDED:gcc-fanalyzer",
    ]
    assert contract["gates"]["systemStability"]["status"] == "degraded"
    assert contract["gates"]["systemStability"]["reasonCodes"] == expected_missing
    static_execution = contract["coverage"]["staticToolExecution"]
    assert static_execution["status"] == "partial"
    assert static_execution["anomalyReasonCodes"] == expected_missing
    assert contract["gates"]["evidenceReadiness"]["status"] == "partial"
    matrix = {entry["toolId"]: entry for entry in contract["toolEvidenceMatrix"]}
    assert matrix["semgrep"]["status"] == "ok"
    assert matrix["cppcheck"]["status"] == "not_recorded"
    assert matrix["gcc-fanalyzer"]["consumerPolicy"] == "metadata_absent_do_not_infer"


def test_all_attempted_tools_failed_degrades_instead_of_passing() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    failed_results = {
        tool: ToolExecutionResult(status="failed", findingsCount=0, elapsedMs=1, skipReason="runner-error")
        for tool in ALL_TOOLS
    }
    execution = ExecutionReport(
        toolsRun=list(ALL_TOOLS),
        toolResults=failed_results,
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=False,
        degradeReasons=[],
    )

    contract = build_static_evidence_contract(success=True, findings=[finding], execution=execution)

    assert contract["gates"]["systemStability"]["status"] == "degraded"
    assert contract["gates"]["systemStability"]["reasonCodes"] == [
        f"TOOL_FAILED:{tool}" for tool in ALL_TOOLS
    ]
    assert contract["coverage"]["staticToolExecution"]["status"] == "partial"
    assert contract["gates"]["evidenceReadiness"]["status"] == "partial"


def test_empty_findings_list_is_provided_local_surface_not_missing() -> None:
    contract = build_static_evidence_contract(
        success=True,
        findings=[],
        execution=_execution_report(),
    )

    assert contract["coverage"]["sastFindings"]["status"] == "provided"
    assert contract["coverage"]["sastFindings"]["observedCount"] == 0
    assert contract["coverage"]["findingLocations"]["status"] == "provided"
    assert contract["coverage"]["findingCweMapping"]["status"] == "provided"
    assert contract["coverage"]["originClassification"]["status"] == "provided"
    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "ready"
    assert "blockingSurfaces" not in readiness
    assert (
        "absence-of-vulnerability-from-empty-findings"
        in contract["claimBoundaries"]["mustNotSupportAlone"]
    )


def test_evidence_readiness_not_ready_when_required_findings_surface_missing() -> None:
    contract = build_static_evidence_contract(
        success=True,
        findings=None,
        execution=_execution_report(),
    )

    assert contract["coverage"]["sastFindings"]["status"] == "not_computed"
    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "not_ready"
    assert "REQUIRED_EVIDENCE_MISSING" in readiness["reasonCodes"]
    assert "sastFindings" in readiness["blockingSurfaces"]


def test_optional_mixed_sca_diff_evidence_is_partial() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(),
        sca={
            "libraries": [
                {"name": "lib-a", "versionEvidence": {"status": "observed"}, "diffAvailable": True},
                {"name": "lib-b", "versionEvidence": {"status": "observed"}, "diffAvailable": False},
            ],
        },
    )

    assert contract["coverage"]["scaDiffEvidence"]["status"] == "partial"
    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "partial"
    assert "scaDiffEvidence" in readiness["partialSurfaces"]



def test_evidence_readiness_ready_when_required_surfaces_provided_and_optional_not_computed_ignored() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(),
        code_graph=None,
        sca=None,
        metadata=None,
    )

    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "ready"
    assert readiness["reasonCodes"] == []
    assert readiness["consumerPolicy"] == "local_static_evidence_ready"
    assert contract["coverage"]["structuralCodeGraph"]["status"] == "not_computed"
    assert contract["coverage"]["scaIdentity"]["status"] == "not_computed"


def test_evidence_readiness_partial_for_optional_partial_surface() -> None:
    finding = enrich_finding_evidence(_oracle_finding())

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(),
    )

    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "partial"
    assert "LOCAL_EVIDENCE_PARTIAL" in readiness["reasonCodes"]
    assert "findingDataflow" in readiness["partialSurfaces"]
    assert "includeGraph" not in readiness["partialSurfaces"]


@pytest.mark.parametrize("optional_status", ["failed", "unavailable", "unknown"])
def test_evidence_readiness_partial_for_degraded_optional_statuses(optional_status: str) -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())
    coverage = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(),
    )["coverage"]
    coverage["targetMetadata"] = {
        "status": optional_status,
        "reasonCodes": [f"TARGET_METADATA_{optional_status.upper()}"],
        "consumerPolicy": "do_not_use_as_negative_evidence",
    }

    readiness = _evaluate_evidence_readiness(coverage, success=True)

    assert readiness["status"] == "partial"
    assert "LOCAL_EVIDENCE_PARTIAL" in readiness["reasonCodes"]
    assert "targetMetadata" in readiness["partialSurfaces"]


def test_evidence_readiness_not_ready_for_failed_artifact() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())

    contract = build_static_evidence_contract(
        success=False,
        findings=[finding],
        execution=_execution_report(),
        policy_failure_reason_codes=["POLICY_VIOLATION", "DISALLOWED_TOOL_OMISSION"],
    )

    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "not_ready"
    assert "ARTIFACT_FAILED" in readiness["reasonCodes"]
    assert "POLICY_VIOLATION" in readiness["reasonCodes"]
    assert readiness["consumerPolicy"] == "do_not_use_as_negative_evidence"


def test_evidence_readiness_not_ready_when_required_execution_surface_missing() -> None:
    finding = enrich_finding_evidence(_oracle_dataflow_finding())

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=None,
    )

    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "not_ready"
    assert "REQUIRED_EVIDENCE_MISSING" in readiness["reasonCodes"]
    assert "staticToolExecution" in readiness["blockingSurfaces"]


def test_evidence_readiness_partial_when_required_cwe_mapping_is_partial() -> None:
    finding = enrich_finding_evidence(
        SastFinding(
            toolId="cppcheck",
            ruleId="unknown-rule",
            severity="medium",
            message="unknown CWE oracle",
            location=SastFindingLocation(file="src/incomplete.c", line=2),
        ),
    )

    contract = build_static_evidence_contract(
        success=True,
        findings=[finding],
        execution=_execution_report(),
    )

    readiness = contract["gates"]["evidenceReadiness"]
    assert readiness["status"] == "partial"
    assert "findingCweMapping" in readiness["partialSurfaces"]
    assert "findingDataflow" in readiness["partialSurfaces"]



@pytest.mark.asyncio
async def test_scan_file_mode_returns_static_evidence_contract_red_oracle(
    client: AsyncClient,
) -> None:
    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], _execution_report()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "contract-file-mode",
                "projectId": "proj-contract",
                "files": [{"path": "src/vulnerable.c", "content": "int main(void) { return 0; }"}],
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["findings"][0]["metadata"]["evidenceResolution"]["schemaVersion"] == "s4-evidence-v1"
    assert data["findings"][0]["metadata"]["evidenceResolution"]["kind"] == "sast-finding"
    contract = data["staticEvidenceContract"]
    _assert_static_evidence_contract_minimum(contract)
    assert contract["coverage"]["structuralCodeGraph"]["status"] == "not_computed"
    assert contract["coverage"]["sastFindings"]["observedCount"] == len(data["findings"])


@pytest.mark.asyncio
async def test_scan_project_path_marks_code_graph_structural_only(
    client: AsyncClient,
) -> None:
    project = EVIDENCE_FIXTURES / "sca_known_library"

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], _execution_report()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
        patch(
            "app.routers.scan.ast_dumper.dump_functions",
            AsyncMock(return_value={"functions": [{"name": "main", "file": "src/main.c", "line": 1, "calls": []}]}),
        ),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "contract-project-mode",
                "projectId": "proj-contract",
                "projectPath": str(project),
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    contract = data["staticEvidenceContract"]
    assert data["sca"]["libraries"], "existing enriched SCA surface must remain present"
    first_library = data["sca"]["libraries"][0]
    assert {"name", "version", "path", "repoUrl"}.issubset(first_library)
    assert "versionEvidence" in first_library
    assert "cveLookupEligible" in first_library
    _assert_static_evidence_contract_minimum(contract)

    structural = contract["coverage"]["structuralCodeGraph"]
    assert structural["status"] == "provided"
    assert structural["graphKind"] == "structural-callgraph"
    assert structural["semanticRetrieval"] == "not_provided"
    assert structural["graphRag"] == "not_provided"
    assert contract["coverage"]["semanticGraphRetrieval"]["status"] == "not_provided"
    assert contract["coverage"]["externalVulnerabilityKnowledge"]["status"] == "not_provided"


@pytest.mark.asyncio
async def test_build_and_analyze_exposes_nested_and_top_level_contract(
    client: AsyncClient,
) -> None:
    project = EVIDENCE_FIXTURES / "sca_known_library"
    provenance = SnapshotProvenance(
        buildSnapshotId="bsnap-contract",
        buildUnitId="bunit-contract",
        snapshotSchemaVersion="build-snapshot-v1",
    )

    with (
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=_build_response(project, provenance).model_dump(by_alias=True, exclude_none=True))),
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], _execution_report()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
        patch(
            "app.routers.scan.ast_dumper.dump_functions",
            AsyncMock(return_value={"functions": [{"name": "main", "file": "src/main.c", "line": 1, "calls": []}]}),
        ),
        patch("app.routers.scan.metadata_extractor.extract", AsyncMock(return_value={"compiler": "gcc"})),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": str(project),
                "buildCommand": "make",
                "projectId": "proj-contract",
                "provenance": provenance.model_dump(by_alias=True, exclude_none=True),
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    nested = data["scan"]["staticEvidenceContract"]
    top_level = data["staticEvidenceContract"]
    _assert_static_evidence_contract_minimum(nested)
    _assert_static_evidence_contract_minimum(top_level)
    assert top_level["schemaVersion"] == nested["schemaVersion"]
    assert top_level["coverage"]["structuralCodeGraph"]["status"] == "provided"
    assert [entry["toolId"] for entry in top_level["toolEvidenceMatrix"]] == ALL_TOOLS
    assert [entry["toolId"] for entry in nested["toolEvidenceMatrix"]] == ALL_TOOLS


@pytest.mark.asyncio
async def test_scan_success_with_failed_tool_exposes_degraded_partial_contract(
    client: AsyncClient,
) -> None:
    execution = _execution_report_with_tool_result(
        "scan-build",
        ToolExecutionResult(status="failed", findingsCount=0, elapsedMs=11, skipReason="runner-error"),
    )

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], execution))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "contract-tool-failed-success",
                "projectId": "proj-contract",
                "files": [{"path": "src/vulnerable.c", "content": "int main(void) { return 0; }"}],
            },
        )

    assert resp.status_code == 200
    contract = resp.json()["staticEvidenceContract"]
    assert contract["gates"]["systemStability"]["status"] == "degraded"
    assert contract["coverage"]["staticToolExecution"]["status"] == "partial"
    assert contract["gates"]["evidenceReadiness"]["status"] == "partial"
    assert contract["gates"]["claimSupportReadiness"]["status"] == "partial"


@pytest.mark.asyncio
async def test_build_and_analyze_success_with_failed_tool_exposes_degraded_partial_contract(
    client: AsyncClient,
) -> None:
    project = EVIDENCE_FIXTURES / "sca_known_library"
    provenance = SnapshotProvenance(
        buildSnapshotId="bsnap-contract-failed-tool",
        buildUnitId="bunit-contract-failed-tool",
        snapshotSchemaVersion="build-snapshot-v1",
    )
    execution = _execution_report_with_tool_result(
        "gcc-fanalyzer",
        ToolExecutionResult(status="failed", findingsCount=0, elapsedMs=11, skipReason="runner-error"),
    )

    with (
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=_build_response(project, provenance).model_dump(by_alias=True, exclude_none=True))),
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], execution))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
        patch("app.routers.scan.metadata_extractor.extract", AsyncMock(return_value={"compiler": "gcc"})),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": str(project),
                "buildCommand": "make",
                "projectId": "proj-contract",
                "provenance": provenance.model_dump(by_alias=True, exclude_none=True),
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "degraded"
    assert data["staticEvidenceContract"]["coverage"]["staticToolExecution"]["status"] == "partial"
    assert data["scan"]["staticEvidenceContract"]["gates"]["evidenceReadiness"]["status"] == "partial"
    assert data["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "partial"


@pytest.mark.asyncio
async def test_policy_violation_marks_system_stability_failed(
    client: AsyncClient,
) -> None:
    policy_violation = {
        "code": "DISALLOWED_TOOL_OMISSION",
        "message": "required SAST tool omitted",
        "omittedTools": ["semgrep"],
        "policyReasons": ["runtime-tool-missing"],
    }

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], _execution_report()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=policy_violation)),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "contract-policy-failure",
                "projectId": "proj-contract",
                "files": [{"path": "src/vulnerable.c", "content": "int main(void) { return 0; }"}],
            },
        )

    assert resp.status_code == 503
    data = resp.json()
    assert data["success"] is False
    stability = data["staticEvidenceContract"]["gates"]["systemStability"]
    assert stability["status"] == "fail"
    assert "POLICY_VIOLATION" in stability["reasonCodes"]
    assert "DISALLOWED_TOOL_OMISSION" in stability["reasonCodes"]
    assert stability["consumerPolicy"] == "do_not_treat_as_successful_artifact"
    assert data["staticEvidenceContract"]["gates"]["evidenceReadiness"]["status"] == "not_ready"
    assert data["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "fail"
    assert [entry["toolId"] for entry in data["staticEvidenceContract"]["toolEvidenceMatrix"]] == ALL_TOOLS


@pytest.mark.asyncio
async def test_async_scan_policy_violation_has_failed_contract(
    client: AsyncClient,
) -> None:
    policy_violation = {
        "code": "DISALLOWED_TOOL_OMISSION",
        "message": "required SAST tool omitted",
        "omittedTools": ["semgrep"],
        "policyReasons": ["runtime-tool-missing"],
    }

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], _policy_failure_execution_report()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=policy_violation)),
    ):
        submit = await client.post(
            "/v1/scan",
            headers={"X-Request-Id": "contract-policy-scan-async", "Prefer": "respond-async"},
            json={
                "scanId": "contract-policy-scan-async",
                "projectId": "proj-contract",
                "files": [{"path": "src/vulnerable.c", "content": "int main(void) { return 0; }"}],
            },
        )
        assert submit.status_code == 202
        result = await _wait_for_owned_result(client, "contract-policy-scan-async")

    data = result["result"]
    assert data["success"] is False
    stability = data["staticEvidenceContract"]["gates"]["systemStability"]
    assert stability["status"] == "fail"
    assert "POLICY_VIOLATION" in stability["reasonCodes"]
    assert "DISALLOWED_TOOL_OMISSION" in stability["reasonCodes"]
    assert data["staticEvidenceContract"]["gates"]["evidenceReadiness"]["status"] == "not_ready"
    assert data["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "fail"
    matrix = {entry["toolId"]: entry for entry in data["staticEvidenceContract"]["toolEvidenceMatrix"]}
    assert matrix["semgrep"]["skipReason"] == "environment-drift"
    assert matrix["semgrep"]["consumerPolicy"] == "blocks_successful_artifact"


async def _wait_for_owned_result(client: AsyncClient, request_id: str) -> dict[str, Any]:
    for _ in range(20):
        resp = await client.get(f"/v1/requests/{request_id}/result")
        if resp.status_code == 200:
            return resp.json()
        await asyncio.sleep(0.02)
    raise AssertionError(f"owned result was not ready for {request_id}")


@pytest.mark.asyncio
async def test_build_and_analyze_policy_violation_has_top_level_failed_contract(
    client: AsyncClient,
) -> None:
    project = EVIDENCE_FIXTURES / "sca_known_library"
    provenance = SnapshotProvenance(
        buildSnapshotId="bsnap-policy",
        buildUnitId="bunit-policy",
        snapshotSchemaVersion="build-snapshot-v1",
    )
    policy_violation = {
        "code": "DISALLOWED_TOOL_OMISSION",
        "message": "required SAST tool omitted",
        "omittedTools": ["semgrep"],
        "policyReasons": ["runtime-tool-missing"],
    }

    with (
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=_build_response(project, provenance).model_dump(by_alias=True, exclude_none=True))),
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], _execution_report()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=policy_violation)),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": str(project),
                "buildCommand": "make",
                "projectId": "proj-contract",
                "provenance": provenance.model_dump(by_alias=True, exclude_none=True),
            },
        )

    assert resp.status_code == 503
    data = resp.json()
    assert data["success"] is False
    assert data["scan"]["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"
    stability = data["staticEvidenceContract"]["gates"]["systemStability"]
    assert stability["status"] == "fail"
    assert "POLICY_VIOLATION" in stability["reasonCodes"]
    assert "DISALLOWED_TOOL_OMISSION" in stability["reasonCodes"]
    assert data["staticEvidenceContract"]["gates"]["evidenceReadiness"]["status"] == "not_ready"
    assert data["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "fail"


@pytest.mark.asyncio
async def test_async_build_and_analyze_policy_violation_has_top_level_failed_contract(
    client: AsyncClient,
) -> None:
    project = EVIDENCE_FIXTURES / "sca_known_library"
    provenance = SnapshotProvenance(
        buildSnapshotId="bsnap-policy-async",
        buildUnitId="bunit-policy-async",
        snapshotSchemaVersion="build-snapshot-v1",
    )
    policy_violation = {
        "code": "DISALLOWED_TOOL_OMISSION",
        "message": "required SAST tool omitted",
        "omittedTools": ["semgrep"],
        "policyReasons": ["runtime-tool-missing"],
    }

    with (
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=_build_response(project, provenance).model_dump(by_alias=True, exclude_none=True))),
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_oracle_finding()], _execution_report()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=policy_violation)),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
    ):
        submit = await client.post(
            "/v1/build-and-analyze",
            headers={"X-Request-Id": "contract-policy-async", "Prefer": "respond-async"},
            json={
                "projectPath": str(project),
                "buildCommand": "make",
                "projectId": "proj-contract",
                "provenance": provenance.model_dump(by_alias=True, exclude_none=True),
            },
        )
        assert submit.status_code == 202
        result = await _wait_for_owned_result(client, "contract-policy-async")

    data = result["result"]
    assert data["success"] is False
    assert data["scan"]["staticEvidenceContract"]["gates"]["systemStability"]["status"] == "fail"
    stability = data["staticEvidenceContract"]["gates"]["systemStability"]
    assert stability["status"] == "fail"
    assert "POLICY_VIOLATION" in stability["reasonCodes"]
    assert "DISALLOWED_TOOL_OMISSION" in stability["reasonCodes"]
    assert data["staticEvidenceContract"]["gates"]["evidenceReadiness"]["status"] == "not_ready"
    assert data["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "fail"


def test_static_evidence_contract_helper_is_s4_only_and_side_effect_free() -> None:
    helper = Path(__file__).parents[1] / "app" / "scanner" / "static_evidence_contract.py"
    assert helper.is_file(), "expected deterministic S4 helper module before contract can ship"

    text = helper.read_text(encoding="utf-8").lower()
    forbidden_tokens = [
        "batch-lookup",
        "/v1/cve",
        "cve",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "socket",
        "http.client",
        "grpc",
        "openai",
        "anthropic",
        "llm",
        "s5",
        "graphragclient",
        "graphrag client",
        "graphrag query",
        "graph_rag_client",
        "graph_rag.query",
        "graph rag query",
    ]
    for token in forbidden_tokens:
        assert token not in text, f"static contract helper must not reference {token!r}"
