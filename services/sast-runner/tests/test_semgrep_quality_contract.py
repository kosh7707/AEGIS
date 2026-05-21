from __future__ import annotations

from types import SimpleNamespace

from app.scanner.paper_static_evidence import _project_tool_runs
from app.scanner.static_evidence_contract import build_static_evidence_contract
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    SdkResolutionInfo,
    ToolExecutionResult,
)


def _execution_with_semgrep_quality_degraded() -> ExecutionReport:
    tool_results = {
        tool: ToolExecutionResult(status="ok", findingsCount=0, elapsedMs=10)
        for tool in ("semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer")
    }
    tool_results["semgrep"] = ToolExecutionResult(
        status="ok",
        findingsCount=0,
        elapsedMs=10,
        coverageDegraded=True,
        coverageReasons=["SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"],
        coverage={
            "coverageKind": "semgrep-effective-coverage-v1",
            "coverageStatus": "degraded",
            "coverageReasons": ["SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"],
            "targetLanguageCounts": {"c": 0, "cpp": 1, "header": 0, "other": 0},
            "localRuleLanguageCounts": {"c": 39, "cpp": 0, "generic": 0, "unknown": 0},
        },
    )
    return ExecutionReport(
        toolsRun=list(tool_results),
        toolResults=tool_results,
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=False,
        degradeReasons=[],
    )


def test_semgrep_quality_degradation_does_not_degrade_system_stability() -> None:
    contract = build_static_evidence_contract(
        success=True,
        findings=[],
        execution=_execution_with_semgrep_quality_degraded(),
    )

    assert contract["gates"]["systemStability"]["status"] == "pass"
    assert contract["gates"]["qualityEvaluation"]["status"] == "not_evaluated"
    assert contract["gates"]["coverageQuality"]["status"] == "degraded"
    assert (
        "TOOL_COVERAGE_DEGRADED:semgrep:SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"
        in contract["gates"]["coverageQuality"]["reasonCodes"]
    )
    semgrep_row = next(row for row in contract["toolEvidenceMatrix"] if row["toolId"] == "semgrep")
    assert semgrep_row["status"] == "ok"
    assert semgrep_row["degraded"] is False
    assert semgrep_row["coverageDegraded"] is True
    assert semgrep_row["consumerPolicy"] == "local_tool_effective_coverage_partial_not_negative_evidence"
    assert semgrep_row["coverage"]["coverageStatus"] == "degraded"


def test_tool_execution_result_serializes_coverage_fields_by_alias() -> None:
    semgrep_result = _execution_with_semgrep_quality_degraded().tool_results["semgrep"]

    payload = semgrep_result.model_dump(by_alias=True, exclude_none=True)

    assert payload["coverageDegraded"] is True
    assert payload["coverageReasons"] == ["SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"]
    assert payload["coverage"]["coverageKind"] == "semgrep-effective-coverage-v1"


def test_paper_tool_run_success_with_semgrep_quality_degradation_has_diagnostic() -> None:
    diagnostics: list[dict] = []
    request = SimpleNamespace(
        case_id="case-test",
        build_target_id="target-test",
        provenance=SimpleNamespace(
            source_root_ref="source-root:test",
            compile_context_ref="compile-context:test",
        ),
    )
    rows, diagnostic_refs = _project_tool_runs(
        request=request,
        request_id="req-test",
        producer_run_id="producer-run-test",
        bundle_ref="bundle:test",
        execution=_execution_with_semgrep_quality_degraded(),
        diagnostics=diagnostics,
    )

    semgrep = next(row for row in rows if row["toolId"] == "semgrep")
    assert semgrep["status"] == "success"
    assert semgrep["degraded"] is False
    assert semgrep["coverageDegraded"] is True
    assert semgrep["coverageReasons"] == ["SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"]
    assert semgrep["coverage"]["coverageStatus"] == "degraded"
    assert semgrep["diagnosticRefs"]
    assert semgrep["diagnosticRefs"] == diagnostic_refs
    assert diagnostics[0]["category"] == "tool-coverage"
    assert diagnostics[0]["reasonCode"] == "SEMGREP_CPP_EFFECTIVE_COVERAGE_UNPROVEN"
