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
from app.scanner.static_evidence_contract import build_static_evidence_contract
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    SastDataFlowStep,
    SastFinding,
    SastFindingLocation,
    SdkResolutionInfo,
    ToolExecutionResult,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MANIFEST_PATH = FIXTURES_DIR / "claim_support_gate_v1" / "manifest.json"
FORBIDDEN_VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}
CONCRETE_TOOL_TOKENS = tuple(ALL_TOOLS)


def _manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text())


def _case_id(case: dict[str, Any]) -> str:
    return str(case["id"])


def _known_finding(*, dataflow: bool = True) -> SastFinding:
    return enrich_finding_evidence(
        SastFinding(
            toolId="semgrep",
            ruleId="quality.known-cwe",
            severity="high",
            message="known local static evidence",
            location=SastFindingLocation(file="src/main.c", line=7, column=3),
            dataFlow=[SastDataFlowStep(file="src/main.c", line=7, content="strcpy(dst, src);")] if dataflow else None,
            metadata={"cweId": "CWE-120", "cwe": ["CWE-120"]},
        ),
    )


def _unknown_cwe_finding() -> SastFinding:
    return enrich_finding_evidence(
        SastFinding(
            toolId="cppcheck",
            ruleId="quality.unknown-cwe",
            severity="medium",
            message="unknown CWE local static evidence",
            location=SastFindingLocation(file="src/unknown.c", line=3),
        ),
    )


def _execution(kind: str = "clean") -> ExecutionReport:
    tool_results = {
        tool: ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=1, version="test")
        for tool in ALL_TOOLS
    }
    tool_results["semgrep"] = ToolExecutionResult(status="ok", findingsCount=1, elapsedMs=1, version="test")
    degraded = False
    degrade_reasons: list[str] = []
    if kind == "degraded-tool-failure":
        tool_results["scan-build"] = ToolExecutionResult(
            status="failed",
            findingsCount=0,
            elapsedMs=1,
            skipReason="runner-error",
            version="test",
        )
    return ExecutionReport(
        toolsRun=list(ALL_TOOLS),
        toolResults=tool_results,
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=degraded,
        degradeReasons=degrade_reasons,
    )


def _findings(kind: str) -> list[SastFinding] | None:
    if kind == "missing":
        return None
    if kind == "empty":
        return []
    if kind == "unknown-cwe":
        return [_unknown_cwe_finding()]
    if kind == "known-cwe-with-dataflow":
        return [_known_finding(dataflow=True)]
    raise AssertionError(f"unknown finding fixture kind: {kind}")


def _contract_for_case(case: dict[str, Any]) -> dict[str, Any]:
    case_input = case["input"]
    return build_static_evidence_contract(
        success=bool(case_input.get("success", True)),
        findings=_findings(str(case_input["findings"])),
        execution=_execution(str(case_input.get("execution", "clean"))),
        metadata=case_input.get("metadata"),
        policy_failure_reason_codes=case_input.get("policyFailureReasonCodes"),
    )


def _build_result(project_path: str) -> dict[str, Any]:
    return {
        "success": True,
        "buildEvidence": {
            "requestedBuildCommand": "make",
            "effectiveBuildCommand": "make",
            "buildDir": project_path,
            "compileCommandsPath": f"{project_path}/compile_commands.json",
            "entries": 1,
            "userEntries": 1,
            "exitCode": 0,
            "buildOutput": "ok",
            "wrapWithBear": True,
            "timeoutSeconds": 600,
            "environmentKeys": [],
            "elapsedMs": 1,
        },
        "readiness": {
            "status": "ready",
            "compileCommandsReady": True,
            "quickEligible": True,
            "summary": "ready",
        },
    }


async def _wait_for_owned_result(client: AsyncClient, request_id: str) -> dict[str, Any]:
    for _ in range(20):
        resp = await client.get(f"/v1/requests/{request_id}/result")
        if resp.status_code == 200:
            return resp.json()
        await asyncio.sleep(0.02)
    raise AssertionError(f"owned result was not ready for {request_id}")


def _claim_by_id(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    matrix = contract["claimBoundaryMatrix"]
    assert isinstance(matrix, list)
    by_id = {entry["claimId"]: entry for entry in matrix}
    assert len(by_id) == len(matrix), "claimBoundaryMatrix claimIds must be unique"
    return by_id


def _assert_no_verdict_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        overlap = FORBIDDEN_VERDICT_KEYS.intersection(value)
        assert not overlap, f"verdict-like key(s) at {path}: {sorted(overlap)}"
        for key, nested in value.items():
            _assert_no_verdict_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_verdict_keys(nested, f"{path}[{index}]")


def test_claim_support_fixture_manifest_is_executable_and_tool_agnostic() -> None:
    manifest = _manifest()

    assert manifest["schemaVersion"] == "s4-claim-support-readiness-fixtures-v1"
    assert manifest["gateName"] == "tool-agnostic-claim-support-readiness-gate"
    assert len(manifest["cases"]) >= 7
    text = json.dumps(manifest, sort_keys=True).lower()
    for forbidden in ("openai", "anthropic", "llm", "s5", "graphrag", "http://", "https://"):
        assert forbidden not in text
    assert "new sast tools" in text


@pytest.mark.parametrize("case", _manifest()["cases"], ids=_case_id)
def test_claim_support_readiness_gate_matches_fixture_cases(case: dict[str, Any]) -> None:
    contract = _contract_for_case(case)
    expected = case["expected"]

    assert "claimSupportReadiness" in contract["gates"]
    assert contract["gates"]["qualityEvaluation"]["status"] == "not_evaluated"

    claim_support = contract["gates"]["claimSupportReadiness"]
    assert claim_support["status"] == expected["claimSupportReadinessStatus"]
    for reason_code in expected.get("claimSupportReadinessReasonCodes", []):
        assert reason_code in claim_support["reasonCodes"]
    for surface in expected.get("partialSurfaces", []):
        assert surface in claim_support.get("partialSurfaces", [])
    for surface in expected.get("blockingSurfaces", []):
        assert surface in claim_support.get("blockingSurfaces", [])

    claims = _claim_by_id(contract)
    for claim_id in expected.get("supportedClaims", []):
        assert claims[claim_id]["supportStatus"] == "supported"
    for claim_id in expected.get("partialClaims", []):
        assert claims[claim_id]["supportStatus"] == "partially_supported"
    for claim_id in expected.get("unsupportedClaims", []):
        assert claims[claim_id]["supportStatus"] == "unsupported"
    for claim_id in expected.get("notApplicableClaims", []):
        assert claims[claim_id]["supportStatus"] == "not_applicable"

    assert claims["absence-of-vulnerability"]["consumerPolicy"] == "do_not_use_as_negative_evidence"
    assert claims["cwe-absence"]["consumerPolicy"] == "do_not_use_as_negative_evidence"
    _assert_no_verdict_keys({"claimSupportReadiness": claim_support, "claimBoundaryMatrix": contract["claimBoundaryMatrix"]})


def test_claim_support_readiness_gate_does_not_leak_concrete_tool_ids() -> None:
    contract = build_static_evidence_contract(
        success=True,
        findings=[_known_finding()],
        execution=_execution("degraded-tool-failure"),
    )

    gate_and_boundaries = {
        "claimSupportReadiness": contract["gates"]["claimSupportReadiness"],
        "claimBoundaryMatrix": contract["claimBoundaryMatrix"],
    }
    text = json.dumps(gate_and_boundaries, sort_keys=True).lower()
    for tool_id in CONCRETE_TOOL_TOKENS:
        assert tool_id not in text
    assert "TOOL_FAILED" not in json.dumps(gate_and_boundaries, sort_keys=True)
    assert contract["coverage"]["staticToolExecution"]["anomalyReasonCodes"] == ["TOOL_FAILED:scan-build"]


def test_claim_support_gate_implementation_has_no_tool_identity_or_external_coupling() -> None:
    helper = Path(__file__).parents[1] / "app" / "scanner" / "claim_support_gate.py"
    assert helper.is_file(), "claim support readiness gate must live in its own tool-agnostic helper"

    text = helper.read_text(encoding="utf-8").lower()
    for token in CONCRETE_TOOL_TOKENS:
        assert token not in text, f"claim support readiness gate must not branch on concrete tool id {token!r}"
    forbidden_tokens = [
        "tool_evidence_order",
        "toolevidencematrix",
        "batch-lookup",
        "/v1/cve",
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
        "graphrag",
        "risk score",
        "security verdict",
    ]
    for token in forbidden_tokens:
        assert token not in text, f"claim support readiness gate must not reference {token!r}"


@pytest.mark.asyncio
async def test_scan_endpoint_propagates_claim_support_readiness_gate(client: AsyncClient) -> None:
    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_known_finding()], _execution()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "claim-support-contract",
                "projectId": "proj-claim-support",
                "files": [{"path": "src/main.c", "content": "int main(void) { return 0; }"}],
            },
        )

    assert resp.status_code == 200
    contract = resp.json()["staticEvidenceContract"]
    assert contract["gates"]["claimSupportReadiness"]["status"] == "pass"
    assert {entry["claimId"] for entry in contract["claimBoundaryMatrix"]} >= {
        "local-static-artifact",
        "reported-finding-positive-evidence",
        "absence-of-vulnerability",
        "cwe-absence",
        "build-configuration-dependent-negative-claim",
    }


@pytest.mark.asyncio
async def test_async_scan_result_propagates_claim_support_readiness_gate(client: AsyncClient) -> None:
    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_known_finding()], _execution()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
    ):
        submit = await client.post(
            "/v1/scan",
            headers={"X-Request-Id": "claim-support-scan-async", "Prefer": "respond-async"},
            json={
                "scanId": "claim-support-scan-async",
                "projectId": "proj-claim-support",
                "files": [{"path": "src/main.c", "content": "int main(void) { return 0; }"}],
            },
        )
        assert submit.status_code == 202
        result = await _wait_for_owned_result(client, "claim-support-scan-async")

    contract = result["result"]["staticEvidenceContract"]
    assert contract["gates"]["claimSupportReadiness"]["status"] == "pass"
    assert contract["claimBoundaryMatrix"][0]["claimId"] == "local-static-artifact"


@pytest.mark.asyncio
async def test_build_and_analyze_propagates_claim_support_readiness_to_nested_and_top_level_contracts(
    client: AsyncClient,
) -> None:
    project = FIXTURES_DIR / "evidence_oracles" / "sca_known_library"

    with (
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=_build_result(str(project)))),
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([_known_finding()], _execution()))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
        patch("app.routers.scan.metadata_extractor.extract", AsyncMock(return_value={"compiler": "gcc"})),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": str(project),
                "buildCommand": "make",
                "projectId": "proj-claim-support",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "pass"
    assert data["scan"]["staticEvidenceContract"]["gates"]["claimSupportReadiness"]["status"] == "pass"
    assert {
        entry["claimId"] for entry in data["staticEvidenceContract"]["claimBoundaryMatrix"]
    } >= {"absence-of-vulnerability", "semantic-graph-completeness"}
