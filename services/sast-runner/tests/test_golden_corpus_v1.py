from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from benchmark.golden_corpus_validator import REQUIRED_LAYERS, load_manifest, validate_manifest
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
MANIFEST_PATH = FIXTURES_DIR / "golden_corpus_v1" / "manifest.json"
VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}


def _manifest() -> dict[str, Any]:
    return load_manifest(MANIFEST_PATH)


def _case_id(case: dict[str, Any]) -> str:
    return str(case.get("id") or case.get("toolId") or "case")


def _layer_cases(layer: str) -> list[dict[str, Any]]:
    return list(_manifest()["layers"][layer])


def _assert_no_verdict_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        forbidden = VERDICT_KEYS.intersection(value)
        assert not forbidden, f"verdict-like key(s) at {path}: {sorted(forbidden)}"
        for key, nested in value.items():
            _assert_no_verdict_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_verdict_keys(nested, f"{path}[{index}]")


def _golden_finding(cwe_id: str = "CWE-120", *, data_flow: bool = True) -> SastFinding:
    return enrich_finding_evidence(
        SastFinding(
            toolId="semgrep",
            ruleId=f"golden.{cwe_id.lower()}",
            severity="high",
            message=f"{cwe_id} local static evidence canary",
            location=SastFindingLocation(file="src/main.c", line=4, column=5),
            dataFlow=[SastDataFlowStep(file="src/main.c", line=4, content="canary();")] if data_flow else None,
            metadata={"cweId": cwe_id, "cwe": [cwe_id]},
        ),
    )


def _golden_execution(kind: str = "clean") -> ExecutionReport:
    tool_results = {
        "semgrep": ToolExecutionResult(status="ok", findingsCount=1, elapsedMs=10, version="1.45.0"),
        "cppcheck": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=5, version="2.13.0"),
        "flawfinder": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=3, version="2.0.19"),
        "clang-tidy": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=8, version="18.1.3"),
        "scan-build": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=8, version="18.1.3"),
        "gcc-fanalyzer": ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=8, version="13.3.0"),
    }
    degraded = False
    degrade_reasons: list[str] = []
    if kind == "degraded":
        degraded = True
        degrade_reasons = ["timed-out-files"]
        tool_results["scan-build"] = ToolExecutionResult(
            status="partial",
            findingsCount=1,
            elapsedMs=120,
            timedOutFiles=1,
            degraded=True,
            degradeReasons=degrade_reasons,
            version="18.1.3",
        )
    if kind == "policy-failure":
        tool_results["semgrep"] = ToolExecutionResult(
            status="skipped",
            findingsCount=0,
            elapsedMs=0,
            skipReason="environment-drift",
            version="1.45.0",
        )
    return ExecutionReport(
        toolsRun=[tool for tool, result in tool_results.items() if result.status != "skipped"],
        toolResults=tool_results,
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
        degraded=degraded,
        degradeReasons=degrade_reasons,
    )


def _build_bundle_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    contract_input = dict(bundle.get("contractInput") or {})
    finding = _golden_finding(
        str(contract_input.get("cweId") or "CWE-120"),
        data_flow=bool(contract_input.get("dataFlow", True)),
    )
    contract = build_static_evidence_contract(
        success=bool(contract_input.get("success", True)),
        findings=[finding],
        execution=_golden_execution(str(contract_input.get("execution") or "clean")),
        code_graph=contract_input.get("codeGraph"),
        sca=contract_input.get("sca"),
        metadata=contract_input.get("metadata"),
        policy_failure_reason_codes=contract_input.get("policyFailureReasonCodes"),
    )
    return {
        "findings": [finding.model_dump(by_alias=True, exclude_none=True)],
        "staticEvidenceContract": contract,
    }


def _get_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, list):
            by_key = {
                item.get("toolId") or item.get("claimId"): item
                for item in current
                if isinstance(item, dict)
            }
            current = by_key[part]
            continue
        current = current[part]
    return current


def test_golden_corpus_manifest_has_four_executable_layers() -> None:
    manifest = _manifest()
    report = validate_manifest(manifest, repo_root=Path(__file__).parents[1])

    assert report["status"] == "pass", report["errors"]
    assert tuple(manifest["layers"].keys()) == REQUIRED_LAYERS
    assert all(layer["caseCount"] >= 1 for layer in report["layers"])
    assert all(layer["executableCount"] >= 1 for layer in report["layers"])
    assert len(manifest["expansionCriteria"]) >= 4


def test_tool_capability_manifest_covers_existing_six_tools() -> None:
    tool_cases = _manifest()["layers"]["toolCapabilityOracles"]
    by_tool = {case["toolId"]: case for case in tool_cases}

    assert list(by_tool) == ALL_TOOLS
    for tool_id in ALL_TOOLS:
        case = by_tool[tool_id]
        assert case["executable"].endswith("test_tool_capability_manifest_covers_existing_six_tools")
        assert case["primaryEvidence"], f"{tool_id} must document observed evidence surfaces"
        assert case["knownLimits"], f"{tool_id} must document non-negative-evidence limits"
        assert "final verdict" not in json.dumps(case).lower()


@pytest.mark.parametrize("bundle_case", _layer_cases("evidenceBundleCorpus"), ids=_case_id)
def test_evidence_bundle_cases_preserve_required_surfaces(bundle_case: dict[str, Any]) -> None:
    bundle_path = Path(__file__).parents[1] / bundle_case["fixture"]
    bundle = json.loads(bundle_path.read_text())
    payload = _build_bundle_payload(bundle)

    assert payload["findings"][0]["metadata"]["evidenceResolution"]["schemaVersion"] == "s4-evidence-v1"
    for required_path in bundle["requiredResponseSurfaces"]:
        if required_path == "findings[].metadata.evidenceResolution":
            assert payload["findings"][0]["metadata"]["evidenceResolution"]
            continue
        assert _get_path(payload, required_path) is not None
    for path, expected in (bundle.get("expectedContractPaths") or {}).items():
        assert _get_path(payload, path) == expected
    _assert_no_verdict_keys(payload)


@pytest.mark.parametrize("canary", _layer_cases("vulnerabilityFamilyCanaries"), ids=_case_id)
def test_vulnerability_family_canaries_produce_local_evidence_without_verdict(canary: dict[str, Any]) -> None:
    source = (Path(__file__).parents[1] / canary["fixture"]).read_text()
    assert canary["cweId"] in source

    finding = _golden_finding(canary["cweId"])
    contract = build_static_evidence_contract(success=True, findings=[finding], execution=_golden_execution())

    assert finding.metadata["evidenceResolution"]["cwe"]["id"] == canary["cweId"]
    assert contract["coverage"]["externalVulnerabilityKnowledge"]["status"] == "not_provided"
    assert contract["coverage"]["finalSecurityVerdict"]["status"] == "not_provided"
    assert "absence-of-vulnerability-from-empty-findings" in contract["claimBoundaries"]["mustNotSupportAlone"]
    _assert_no_verdict_keys({"finding": finding.model_dump(by_alias=True), "contract": contract})


def test_golden_corpus_validator_report_is_deterministic() -> None:
    manifest = _manifest()
    repo_root = Path(__file__).parents[1]

    first = validate_manifest(manifest, repo_root=repo_root)
    second = validate_manifest(manifest, repo_root=repo_root)

    assert first == second
    assert first["status"] == "pass"
