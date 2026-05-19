from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.request import SnapshotProvenance
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    SdkResolutionInfo,
    ToolExecutionResult,
)


def _execution_report(
    *,
    status_by_tool: dict[str, str] | None = None,
    diagnostic_tools: set[str] | None = None,
) -> ExecutionReport:
    from app.scanner.paper_static_evidence import CURRENT_SIX_TOOLS

    statuses = status_by_tool or {}
    diagnostic_tools = diagnostic_tools or set()
    return ExecutionReport(
        toolsRun=[
            tool
            for tool in CURRENT_SIX_TOOLS
            if statuses.get(tool, "ok") not in {"skipped", "not_available"}
        ],
        toolResults={
            tool: ToolExecutionResult(
                status=(
                    "failed"
                    if statuses.get(tool) in {"failed", "timeout", "not_available"}
                    else "skipped"
                    if statuses.get(tool) == "skipped"
                    else "ok"
                ),
                findingsCount=0,
                elapsedMs=0,
                skipReason=(
                    "runtime-tool-missing"
                    if statuses.get(tool) == "not_available"
                    else "tool-execution-failed"
                    if tool in diagnostic_tools
                    else None
                ),
                version="test-version",
                degraded=tool in diagnostic_tools,
                degradeReasons=(["tool-execution-failed"] if tool in diagnostic_tools else None),
            )
            for tool in CURRENT_SIX_TOOLS
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=bool(diagnostic_tools),
        degradeReasons=(["tool-execution-failed"] if diagnostic_tools else []),
    )


def _make_source_root(tmp_path: Path, *, compile_commands: object | None = None) -> Path:
    root = tmp_path / "target"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (root / "src" / "unused.c").write_text("int unused(void) { return 0; }\n", encoding="utf-8")
    payload = compile_commands
    if payload is None:
        payload = [
            {
                "directory": str(root),
                "command": "cc -c src/main.c",
                "file": "src/main.c",
            },
        ]
    (root / "compile_commands.json").write_text(json.dumps(payload), encoding="utf-8")
    return root


def _paper_request(root: Path) -> dict:
    return {
        "caseId": "case-001",
        "buildTargetId": "target-001",
        "sourceRoot": str(root),
        "compileContext": {
            "type": "compile_commands_json",
            "path": "compile_commands.json",
            "ref": "compile-context:case-001:target-001",
        },
        "provenance": {
            "paperRunId": "paper-run-001",
            "buildSnapshotId": "build-snapshot-001",
            "buildUnitId": "build-unit-001",
            "datasetRootRef": "dataset-root:paper",
            "sourceRootRef": "source-root:case-001:target-001",
            "compileContextRef": "compile-context:case-001:target-001",
        },
        "scope": {"includePaths": [], "excludePaths": [], "thirdPartyPaths": []},
    }


def _minimal_bundle() -> dict:
    from app.scanner.paper_static_evidence import (
        CURRENT_SIX_TOOLS,
        REQUIRED_CLAIM_IDS,
        REQUIRED_SURFACES,
    )

    base_trace = {
        "caseId": "case-001",
        "buildTargetId": "target-001",
        "bundleRef": "s4-bundle:case-001:target-001:request-001",
        "s4RequestId": "request-001",
        "s4ProducerRunId": "run-001",
        "sourceRootRef": "source-root:case-001:target-001",
        "compileContextRef": "compile-context:case-001:target-001",
    }
    tool_runs = [
        {
            "toolRunId": f"toolrun:{idx:04d}:{tool}",
            "toolId": tool,
            "status": "success",
            "findingsCount": 0,
            "version": "test-version",
            "elapsedMs": 0,
            "degraded": False,
            "degradeReasons": [],
            "consumerPolicy": "local_tool_execution_state_only_not_vulnerability_verdict",
            "diagnosticRefs": [],
            "trace": {
                **base_trace,
                "surface": "toolRuns",
                "surfaceId": "surface:toolRuns",
                "toolRunId": f"toolrun:{idx:04d}:{tool}",
                "rawObjectRef": f"toolRuns[{idx}]",
            },
        }
        for idx, tool in enumerate(CURRENT_SIX_TOOLS)
    ]
    source_file = {
        "sourceFileId": "src:0000",
        "path": "src/main.c",
        "language": "c",
        "compileContextRef": "compile-context:case-001:target-001",
        "diagnosticRefs": [],
        "trace": {
            **base_trace,
            "surface": "sourceFiles",
            "surfaceId": "surface:sourceFiles",
            "sourceFileId": "src:0000",
            "rawObjectRef": "sourceFiles[0]",
        },
    }
    claim_matrix = [
        {
            "claimId": claim_id,
            "supportStatus": "unsupported"
            if claim_id
            not in {"local-static-artifact", "reported-finding-positive-evidence"}
            else "supported",
            "reasonCodes": [],
            "consumerPolicy": "claim_boundary_contract",
            "evidenceRefs": [],
            "summary": "claim boundary row",
        }
        for claim_id in REQUIRED_CLAIM_IDS
    ]
    claim_boundaries = {
        "negativeEvidencePolicy": "empty-or-missing-s4-evidence-is-not-negative-security-evidence",
        "mustNotSupportAlone": [
            "final-security-verdict",
            "vulnerability-absence",
            "cwe-absence",
            "exploitability-judgment",
            "external-affectedness",
            "semantic-graphrag-completeness",
            "s5-sufficiency",
        ],
    }
    static_contract = {
        "schemaVersion": "s4-static-evidence-contract-v1",
        "analysisProfile": "c-cpp-core",
        "artifactKind": "s4-static-evidence-artifact",
        "producer": {"service": "s4-sast-runner", "deterministic": True},
        "provenance": {},
        "gates": {
            "qualityEvaluation": {
                "status": "not_evaluated",
                "reasonCodes": ["NO_VALIDATION_PROFILE_RAN"],
                "consumerPolicy": "do_not_treat_as_quality_score",
            },
            "claimSupportReadiness": {"status": "not_evaluated"},
        },
        "coverage": {},
        "claimBoundaries": claim_boundaries,
        "claimBoundaryMatrix": claim_matrix,
        "toolEvidenceMatrix": [],
        "followUpHints": [],
    }
    surfaces = {
        surface: {
            "status": "empty",
            "count": 0,
            "consumerPolicy": "empty_is_not_negative_evidence",
            "reasonCodes": [],
            "diagnosticRefs": [],
        }
        for surface in REQUIRED_SURFACES
    }
    surfaces.update(
        {
            "sourceFiles": {
                "status": "produced",
                "count": 1,
                "consumerPolicy": "local_static_structure_only",
                "reasonCodes": [],
                "diagnosticRefs": [],
            },
            "toolRuns": {
                "status": "produced",
                "count": len(CURRENT_SIX_TOOLS),
                "consumerPolicy": "local_tool_execution_state_only",
                "reasonCodes": [],
                "diagnosticRefs": [],
            },
            "targetMetadata": {
                "status": "produced",
                "count": 1,
                "consumerPolicy": "producer_metadata_only",
                "reasonCodes": [],
                "diagnosticRefs": [],
            },
            "staticEvidenceContract": {
                "status": "produced",
                "count": 1,
                "consumerPolicy": "claim_boundary_contract",
                "reasonCodes": [],
                "diagnosticRefs": [],
            },
            "claimBoundaryMatrix": {
                "status": "produced",
                "count": len(claim_matrix),
                "consumerPolicy": "claim_boundary_contract",
                "reasonCodes": [],
                "diagnosticRefs": [],
            },
            "claimBoundaries": {
                "status": "produced",
                "count": 1,
                "consumerPolicy": "claim_boundary_contract",
                "reasonCodes": [],
                "diagnosticRefs": [],
            },
        },
    )
    return {
        "schemaVersion": "s4-paper-static-evidence-bundle-v1",
        "bundleProfile": "s4-paper-static-evidence-full-v1",
        "surfacePolicy": "always_attempt_full_bundle",
        "success": True,
        "bundleStatus": "produced",
        "evidenceCompleteness": {
            "status": "bounded_partial",
            "consumerPolicy": "not_complete_security_evidence",
        },
        "caseId": "case-001",
        "buildTargetId": "target-001",
        "s4RequestId": "request-001",
        "s4ProducerRunId": "run-001",
        "bundleRef": "s4-bundle:case-001:target-001:request-001",
        "producer": {"service": "s4-sast-runner", "serviceVersion": "0.11.2", "deterministic": True},
        "provenance": {
            "paperRunId": "paper-run-001",
            "buildSnapshotId": "build-snapshot-001",
            "buildUnitId": "build-unit-001",
            "datasetRootRef": "dataset-root:paper",
            "sourceRootRef": "source-root:case-001:target-001",
            "compileContextRef": "compile-context:case-001:target-001",
        },
        "surfaceStatus": surfaces,
        "diagnostics": [],
        "findings": [],
        "evidence": [],
        "sourceFiles": [source_file],
        "functions": [],
        "includeEdges": [],
        "libraries": [],
        "toolRuns": tool_runs,
        "targetMetadata": {
            "trace": {**base_trace, "surface": "targetMetadata", "rawObjectRef": "targetMetadata"},
            "language": "c/cpp",
            "sourceRootRef": "source-root:case-001:target-001",
            "compileContext": {
                "type": "compile_commands_json",
                "path": "compile_commands.json",
                "ref": "compile-context:case-001:target-001",
            },
            "scopeSummary": {"includePathCount": 0, "excludePathCount": 0, "thirdPartyPathCount": 0},
            "observedBuildProfile": {"compileDatabaseEntries": 1, "analyzableSourceFiles": 1},
        },
        "staticEvidenceContract": static_contract,
        "claimBoundaryMatrix": claim_matrix,
        "claimBoundaries": claim_boundaries,
    }


def _assert_validation_passes(report: dict) -> None:
    assert report["overallStatus"] == "pass", report
    assert report["contractValidation"]["status"] == "pass", report
    assert report["producerSanityValidation"]["status"] == "pass", report


def _reason_codes(report: dict) -> set[str]:
    return {
        issue["reasonCode"]
        for section in ("contractValidation", "producerSanityValidation")
        for bucket in ("errors", "warnings")
        for issue in report[section][bucket]
    }


def test_paper_bundle_validator_accepts_minimal_contract_valid_bundle() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    _assert_validation_passes(validate_paper_static_evidence_bundle(_minimal_bundle()))


@pytest.mark.parametrize(
    ("mutator", "reason_code"),
    [
        (lambda bundle: bundle["surfaceStatus"].pop("findings"), "SURFACE_STATUS_INCOMPLETE"),
        (lambda bundle: bundle["sourceFiles"][0].pop("diagnosticRefs"), "DIAGNOSTIC_REFS_MISSING"),
        (lambda bundle: bundle["sourceFiles"][0]["diagnosticRefs"].append("missing-diagnostic"), "DIAGNOSTIC_REF_UNRESOLVED"),
        (lambda bundle: bundle["sourceFiles"][0].pop("trace"), "ROW_TRACE_MISSING"),
        (lambda bundle: bundle["toolRuns"].__setitem__(1, {**bundle["toolRuns"][0]}), "DUPLICATE_ROW_ID"),
        (lambda bundle: bundle.__setitem__("checksum", "sha256:abc"), "FORBIDDEN_SEMANTIC_FIELD"),
        (lambda bundle: bundle.__setitem__("verdict", "TP"), "FORBIDDEN_SEMANTIC_FIELD"),
        (lambda bundle: bundle["producer"].__setitem__("note", "UNKNOWN"), "FORBIDDEN_SEMANTIC_VALUE"),
    ],
)
def test_paper_contract_validator_fails_closed_on_schema_and_semantic_violations(
    mutator,
    reason_code: str,
) -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    mutator(bundle)

    report = validate_paper_static_evidence_bundle(bundle)

    assert report["contractValidation"]["status"] == "fail"
    assert reason_code in _reason_codes(report)


def test_paper_contract_validator_fails_claim_boundary_mirror_mismatch() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    bundle["claimBoundaries"] = {
        **bundle["claimBoundaries"],
        "mustNotSupportAlone": [
            *bundle["claimBoundaries"]["mustNotSupportAlone"],
            "extra-local-only-claim",
        ],
    }

    report = validate_paper_static_evidence_bundle(bundle)

    assert "CLAIM_BOUNDARY_MIRROR_MISMATCH" in _reason_codes(report)


def test_claim_boundary_keeps_empty_findings_from_supporting_absence_or_final_verdicts() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    for row in bundle["claimBoundaryMatrix"]:
        if row["claimId"] == "final-security-verdict":
            row["supportStatus"] = "supported"

    report = validate_paper_static_evidence_bundle(bundle)

    assert "CLAIM_BOUNDARY_NEGATIVE_CLAIM_UNSAFE" in _reason_codes(report)


def test_empty_findings_is_valid_only_as_successful_zero_row_surface() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    _assert_validation_passes(validate_paper_static_evidence_bundle(bundle))

    bundle["surfaceStatus"]["findings"]["count"] = 1
    report = validate_paper_static_evidence_bundle(bundle)

    assert "EMPTY_SURFACE_COUNT_MISMATCH" in _reason_codes(report)


def test_producer_sanity_requires_all_current_six_tool_runs() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    bundle["toolRuns"] = bundle["toolRuns"][:-1]
    bundle["surfaceStatus"]["toolRuns"]["count"] = len(bundle["toolRuns"])

    report = validate_paper_static_evidence_bundle(bundle)

    assert report["contractValidation"]["status"] == "pass"
    assert report["producerSanityValidation"]["status"] == "fail"
    assert "CURRENT_SIX_TOOL_RUN_MISSING" in _reason_codes(report)


def test_non_success_tool_run_requires_diagnostic_reason() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    bundle["toolRuns"][0]["status"] = "failed"

    report = validate_paper_static_evidence_bundle(bundle)

    assert "TOOL_RUN_DIAGNOSTIC_REQUIRED" in _reason_codes(report)


def test_non_success_tool_run_with_diagnostic_can_still_be_produced() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    diagnostic = {
        "diagnosticId": "diag:tool:semgrep",
        "severity": "warning",
        "category": "tool-execution",
        "reasonCode": "REQUIRED_TOOL_UNAVAILABLE",
        "surface": "toolRuns",
        "message": "A current-six tool was unavailable.",
        "consumerPolicy": "producer_diagnostic_not_security_evidence",
        "trace": {**bundle["toolRuns"][0]["trace"], "rawObjectRef": "diagnostics[0]"},
    }
    bundle["diagnostics"].append(diagnostic)
    bundle["toolRuns"][0]["status"] = "not_available"
    bundle["toolRuns"][0]["diagnosticRefs"] = [diagnostic["diagnosticId"]]

    _assert_validation_passes(validate_paper_static_evidence_bundle(bundle))


def test_load_compile_context_uses_compile_db_not_project_walk(tmp_path: Path) -> None:
    from app.scanner.paper_static_evidence import load_paper_compile_context
    from app.schemas.request import PaperStaticEvidenceRequest

    root = _make_source_root(tmp_path)
    request_model = PaperStaticEvidenceRequest.model_validate(_paper_request(root))

    context = load_paper_compile_context(request_model)

    assert context.analyzable_source_files == ["src/main.c"]
    assert context.compile_database_entries == 1


def test_load_compile_context_resolves_relative_file_against_compile_db_directory(tmp_path: Path) -> None:
    from app.scanner.paper_static_evidence import load_paper_compile_context
    from app.schemas.request import PaperStaticEvidenceRequest

    root = _make_source_root(
        tmp_path,
        compile_commands=[
            {
                "directory": str(tmp_path / "target" / "src"),
                "command": "cc -c main.c",
                "file": "main.c",
            },
        ],
    )
    request_model = PaperStaticEvidenceRequest.model_validate(_paper_request(root))

    context = load_paper_compile_context(request_model)

    assert context.analyzable_source_files == ["src/main.c"]


def test_load_compile_context_rejects_source_root_escape(tmp_path: Path) -> None:
    from app.scanner.paper_static_evidence import PaperStaticEvidenceContractError, load_paper_compile_context
    from app.schemas.request import PaperStaticEvidenceRequest

    root = _make_source_root(
        tmp_path,
        compile_commands=[
            {
                "directory": str(tmp_path / "target"),
                "command": "cc -c ../outside.c",
                "file": "../outside.c",
            },
        ],
    )
    request_model = PaperStaticEvidenceRequest.model_validate(_paper_request(root))

    with pytest.raises(PaperStaticEvidenceContractError) as exc:
        load_paper_compile_context(request_model)

    assert exc.value.reason_code == "COMPILE_CONTEXT_SOURCE_UNRESOLVED"


@pytest.mark.parametrize(
    ("compile_commands", "reason_code"),
    [
        ("not-json", "COMPILE_CONTEXT_PARSE_FAILED"),
        ({"not": "a-list"}, "COMPILE_CONTEXT_PARSE_FAILED"),
        ([{"directory": ".", "command": "cc -c README.md", "file": "README.md"}], "COMPILE_CONTEXT_NO_ANALYZABLE_ENTRIES"),
    ],
)
def test_load_compile_context_fails_closed_for_invalid_compile_db(
    tmp_path: Path,
    compile_commands: object,
    reason_code: str,
) -> None:
    from app.scanner.paper_static_evidence import PaperStaticEvidenceContractError, load_paper_compile_context
    from app.schemas.request import PaperStaticEvidenceRequest

    root = _make_source_root(tmp_path)
    if isinstance(compile_commands, str):
        (root / "compile_commands.json").write_text(compile_commands, encoding="utf-8")
    else:
        (root / "compile_commands.json").write_text(json.dumps(compile_commands), encoding="utf-8")
    request_model = PaperStaticEvidenceRequest.model_validate(_paper_request(root))

    with pytest.raises(PaperStaticEvidenceContractError) as exc:
        load_paper_compile_context(request_model)

    assert exc.value.reason_code == reason_code


def test_file_backed_writer_emits_raw_and_validation_artifacts(tmp_path: Path) -> None:
    from app.scanner.paper_static_evidence import write_paper_static_evidence_artifacts

    bundle = _minimal_bundle()

    report = write_paper_static_evidence_artifacts(tmp_path, bundle)

    assert (tmp_path / "s4-static-evidence.raw.json").is_file()
    assert (tmp_path / "s4-static-evidence.validation.json").is_file()
    written_bundle = json.loads((tmp_path / "s4-static-evidence.raw.json").read_text())
    written_report = json.loads((tmp_path / "s4-static-evidence.validation.json").read_text())
    assert written_bundle == bundle
    assert written_report == report
    _assert_validation_passes(report)


def test_current_six_liveness_gate_is_separate_system_stability_gate() -> None:
    from app.scanner.paper_static_evidence import CURRENT_SIX_TOOLS, validate_current_six_liveness

    report = validate_current_six_liveness(
        {
            tool: {"available": tool != "semgrep", "version": "test-version", "probeReason": "runtime-tool-missing"}
            for tool in CURRENT_SIX_TOOLS
        },
    )

    assert report["status"] == "fail"
    assert report["gate"] == "current-six-liveness"
    assert report["failures"][0]["toolId"] == "semgrep"
    assert report["failures"][0]["reasonCode"] == "runtime-tool-missing"


@pytest.mark.asyncio
async def test_live_paper_static_evidence_endpoint_returns_valid_bundle(client, tmp_path: Path) -> None:
    root = _make_source_root(tmp_path)
    execution = _execution_report()

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
        patch("app.routers.scan.include_resolver.resolve", AsyncMock(return_value={"src/main.c": ["include/header.h"]})),
        patch("app.routers.scan.identify_libraries", AsyncMock(return_value=[])),
    ):
        response = await client.post("/v1/paper/static-evidence", json=_paper_request(root))

    assert response.status_code == 200
    bundle = response.json()
    assert bundle["schemaVersion"] == "s4-paper-static-evidence-bundle-v1"
    assert bundle["bundleStatus"] == "produced"
    assert bundle["surfaceStatus"]["findings"]["status"] == "empty"
    assert [row["toolId"] for row in bundle["toolRuns"]] == [
        "semgrep",
        "cppcheck",
        "flawfinder",
        "clang-tidy",
        "scan-build",
        "gcc-fanalyzer",
    ]
    assert bundle["includeEdges"][0]["fromSourceFileId"] == "src:0000"
    assert bundle["includeEdges"][0]["includeText"] == "include/header.h"

    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    _assert_validation_passes(validate_paper_static_evidence_bundle(bundle))


@pytest.mark.asyncio
async def test_live_endpoint_projects_required_tool_unavailable_as_produced_diagnostic_bundle(
    client,
    tmp_path: Path,
) -> None:
    from app.errors import RequiredToolUnavailableError

    root = _make_source_root(tmp_path)
    execution = _execution_report(
        status_by_tool={"semgrep": "not_available"},
        diagnostic_tools={"semgrep"},
    )

    with (
        patch(
            "app.routers.scan.orchestrator.run",
            AsyncMock(
                side_effect=RequiredToolUnavailableError(
                    "Required SAST tool preflight failed.",
                    execution=execution,
                    tool_failures=[{"toolId": "semgrep", "reasonCode": "runtime-tool-missing"}],
                ),
            ),
        ),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
        patch("app.routers.scan.include_resolver.resolve", AsyncMock(return_value=[])),
        patch("app.routers.scan.identify_libraries", AsyncMock(return_value=[])),
    ):
        response = await client.post("/v1/paper/static-evidence", json=_paper_request(root))

    assert response.status_code == 200
    bundle = response.json()
    assert bundle["success"] is True
    assert bundle["bundleStatus"] == "produced"
    semgrep = next(row for row in bundle["toolRuns"] if row["toolId"] == "semgrep")
    assert semgrep["status"] == "not_available"
    assert semgrep["diagnosticRefs"]
    assert bundle["surfaceStatus"]["findings"]["status"] == "partial"
    assert bundle["surfaceStatus"]["evidence"]["status"] == "partial"
    assert bundle["surfaceStatus"]["evidence"]["diagnosticRefs"]

    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    _assert_validation_passes(validate_paper_static_evidence_bundle(bundle))


@pytest.mark.asyncio
async def test_live_endpoint_generic_orchestrator_failure_does_not_claim_static_contract_stability(
    client,
    tmp_path: Path,
) -> None:
    root = _make_source_root(tmp_path)

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(side_effect=RuntimeError("boom"))),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
        patch("app.routers.scan.include_resolver.resolve", AsyncMock(return_value=[])),
        patch("app.routers.scan.identify_libraries", AsyncMock(return_value=[])),
    ):
        response = await client.post("/v1/paper/static-evidence", json=_paper_request(root))

    assert response.status_code == 200
    bundle = response.json()
    system_stability = bundle["staticEvidenceContract"]["gates"]["systemStability"]
    assert system_stability["status"] == "fail"
    assert "PRODUCER_INTERNAL_ERROR" in system_stability["reasonCodes"]

    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    _assert_validation_passes(validate_paper_static_evidence_bundle(bundle))


@pytest.mark.asyncio
async def test_live_endpoint_rejects_forbidden_request_field_with_paper_reason_code(client, tmp_path: Path) -> None:
    root = _make_source_root(tmp_path)
    payload = _paper_request(root)
    payload["checksum"] = "sha256:abc"

    response = await client.post("/v1/paper/static-evidence", json=payload)

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errorDetail"]["code"] == "PAPER_STATIC_EVIDENCE_REQUEST_FORBIDDEN_FIELD"


@pytest.mark.asyncio
async def test_live_endpoint_rejects_compile_context_ref_mismatch(client, tmp_path: Path) -> None:
    root = _make_source_root(tmp_path)
    payload = _paper_request(root)
    payload["compileContext"]["ref"] = "compile-context:different"

    response = await client.post("/v1/paper/static-evidence", json=payload)

    assert response.status_code == 400
    assert response.json()["errorDetail"]["code"] == "COMPILE_CONTEXT_REF_MISMATCH"


@pytest.mark.asyncio
async def test_live_endpoint_rejects_unsupported_compile_context_type_with_specific_reason(
    client,
    tmp_path: Path,
) -> None:
    root = _make_source_root(tmp_path)
    payload = _paper_request(root)
    payload["compileContext"]["type"] = "bear_json"

    response = await client.post("/v1/paper/static-evidence", json=payload)

    assert response.status_code == 400
    assert response.json()["errorDetail"]["code"] == "UNSUPPORTED_COMPILE_CONTEXT_TYPE"


def test_b2_b4_rendering_order_uses_same_evidence_rows() -> None:
    from app.scanner.paper_static_evidence import paper_reviewer_visible_rows

    bundle = _minimal_bundle()
    bundle["evidence"] = [
        {
            "evidenceId": "ev:0000",
            "evidenceType": "sast-finding-message",
            "producer": "s4",
            "findingId": None,
            "sourceFileId": "src:0000",
            "text": "same reviewer-visible text",
            "consumerPolicy": "local_static_structure_only",
            "diagnosticRefs": [],
            "trace": {**bundle["sourceFiles"][0]["trace"], "surface": "evidence", "rawObjectRef": "evidence[0]"},
        },
    ]
    bundle["surfaceStatus"]["evidence"]["status"] = "produced"
    bundle["surfaceStatus"]["evidence"]["count"] = 1

    b2_rows = paper_reviewer_visible_rows(bundle, packet_condition="B2")
    b4_rows = paper_reviewer_visible_rows(bundle, packet_condition="B4")

    assert b2_rows == b4_rows == ["same reviewer-visible text"]


@pytest.mark.integration
def test_real_admitted_target_smoke_request_is_manifest_driven_if_available() -> None:
    """Operational smoke placeholder for `/home/kosh/aegis-for-paper` without implementation overfitting.

    The implementation must remain request/manifest driven. This smoke is skipped unless
    a real paper request manifest exists at the documented optional location.
    """

    manifest = Path("/home/kosh/aegis-for-paper/s4-paper-static-evidence-request.json")
    if not manifest.is_file():
        pytest.skip("real admitted target manifest not available")

    from app.schemas.request import PaperStaticEvidenceRequest

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    request_model = PaperStaticEvidenceRequest.model_validate(payload)
    assert request_model.case_id
    assert request_model.compile_context.ref == request_model.provenance.compile_context_ref
