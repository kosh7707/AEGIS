from __future__ import annotations

import asyncio
import ast
import copy
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


async def _wait_for_owned_result(client, request_id: str) -> dict:
    for _ in range(30):
        response = await client.get(f"/v1/requests/{request_id}/result")
        if response.status_code == 200:
            return response.json()
        await asyncio.sleep(0.02)
    raise AssertionError(f"owned paper static-evidence result was not ready: {request_id}")


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
            "trace": {
                **base_trace,
                "surface": "targetMetadata",
                "surfaceId": "surface:targetMetadata",
                "rawObjectRef": "targetMetadata",
            },
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


def _minimal_failed_bundle() -> dict:
    bundle = _minimal_bundle()
    diagnostic = {
        "diagnosticId": "diag:0000:producer_internal_error",
        "severity": "error",
        "category": "producer-invariant",
        "reasonCode": "PRODUCER_INTERNAL_ERROR",
        "surface": "staticEvidenceContract",
        "message": "S4 static-evidence producer failed after request admission.",
        "consumerPolicy": "producer_diagnostic_not_security_evidence",
        "trace": {
            **bundle["sourceFiles"][0]["trace"],
            "surface": "diagnostics",
            "surfaceId": "surface:diagnostics",
            "rawObjectRef": "diagnostics[0]",
        },
    }
    bundle["success"] = False
    bundle["bundleStatus"] = "failed"
    bundle["diagnostics"] = [diagnostic]
    for surface in ("findings", "evidence", "functions", "includeEdges", "libraries", "toolRuns"):
        bundle[surface] = []
        bundle["surfaceStatus"][surface] = {
            "status": "failed",
            "count": 0,
            "consumerPolicy": "producer_diagnostic_not_security_evidence",
            "reasonCodes": ["PRODUCER_INTERNAL_ERROR"],
            "diagnosticRefs": [diagnostic["diagnosticId"]],
        }
    bundle["targetMetadata"] = {}
    bundle["surfaceStatus"]["targetMetadata"] = {
        "status": "failed",
        "count": 0,
        "consumerPolicy": "producer_diagnostic_not_security_evidence",
        "reasonCodes": ["PRODUCER_INTERNAL_ERROR"],
        "diagnosticRefs": [diagnostic["diagnosticId"]],
    }
    bundle["staticEvidenceContract"] = {}
    bundle["surfaceStatus"]["staticEvidenceContract"] = {
        "status": "failed",
        "count": 0,
        "consumerPolicy": "producer_diagnostic_not_security_evidence",
        "reasonCodes": ["PRODUCER_INTERNAL_ERROR"],
        "diagnosticRefs": [diagnostic["diagnosticId"]],
    }
    return bundle


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


def test_paper_bundle_validator_accepts_diagnostic_backed_failed_bundle_without_current_six_rows() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_failed_bundle()

    _assert_validation_passes(validate_paper_static_evidence_bundle(bundle))


def test_paper_bundle_validator_rejects_failed_bundle_without_diagnostics() -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_failed_bundle()
    bundle["diagnostics"] = []
    for entry in bundle["surfaceStatus"].values():
        entry["diagnosticRefs"] = []

    report = validate_paper_static_evidence_bundle(bundle)

    assert "FAILED_BUNDLE_DIAGNOSTICS_REQUIRED" in _reason_codes(report)


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


@pytest.mark.parametrize(
    ("mutator", "reason_code"),
    [
        (lambda bundle: bundle["sourceFiles"][0].__setitem__("trace", {}), "ROW_TRACE_MISSING"),
        (lambda bundle: bundle["diagnostics"][0].__setitem__("trace", {}), "ROW_TRACE_MISSING"),
        (lambda bundle: bundle["diagnostics"][0].__setitem__("category", "raw-exception"), "DIAGNOSTIC_CATEGORY_INVALID"),
        (lambda bundle: bundle["diagnostics"][0].__setitem__("reasonCode", "RAW_TRACEBACK"), "DIAGNOSTIC_REASON_INVALID"),
        (lambda bundle: bundle["diagnostics"][0].__setitem__("message", "Traceback File /home/secret/project/main.c"), "DIAGNOSTIC_MESSAGE_UNSAFE"),
    ],
)
def test_paper_contract_validator_requires_strict_trace_and_sanitized_diagnostics(
    mutator,
    reason_code: str,
) -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_failed_bundle()
    mutator(bundle)

    report = validate_paper_static_evidence_bundle(bundle)

    assert reason_code in _reason_codes(report)


@pytest.mark.parametrize(
    ("mutator", "reason_code"),
    [
        (lambda bundle: bundle["surfaceStatus"]["sourceFiles"].__setitem__("count", 99), "SURFACE_COUNT_MISMATCH"),
        (lambda bundle: bundle["surfaceStatus"]["targetMetadata"].__setitem__("count", 0), "SURFACE_COUNT_MISMATCH"),
        (lambda bundle: bundle["surfaceStatus"]["staticEvidenceContract"].__setitem__("count", 0), "SURFACE_COUNT_MISMATCH"),
    ],
)
def test_paper_contract_validator_reconciles_surface_status_counts(mutator, reason_code: str) -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    mutator(bundle)

    report = validate_paper_static_evidence_bundle(bundle)

    assert reason_code in _reason_codes(report)


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "integrity",
        "integrityStatus",
        "artifactIntegrity",
        "reproducibility",
        "reproducibleBuild",
        "finalVerdict",
        "securityVerdict",
        "provenSafe",
        "isSafe",
    ],
)
def test_paper_contract_validator_blocks_integrity_reproducibility_and_final_verdict_aliases(
    forbidden_key: str,
) -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle

    bundle = _minimal_bundle()
    bundle["producer"][forbidden_key] = "verified"

    report = validate_paper_static_evidence_bundle(bundle)

    assert "FORBIDDEN_SEMANTIC_FIELD" in _reason_codes(report)


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


def test_file_backed_writer_emits_validation_for_live_equivalent_bundle(tmp_path: Path) -> None:
    from app.scanner.paper_static_evidence import validate_paper_static_evidence_bundle, write_paper_static_evidence_artifacts

    live_equivalent = _minimal_bundle()
    live_equivalent["evidence"] = [
        {
            "evidenceId": "ev:0000",
            "evidenceType": "sast-finding-message",
            "producer": "s4",
            "findingId": None,
            "sourceFileId": "src:0000",
            "text": "first deterministic reviewer-visible row",
            "consumerPolicy": "local_static_structure_only",
            "diagnosticRefs": [],
            "trace": {**live_equivalent["sourceFiles"][0]["trace"], "surface": "evidence", "rawObjectRef": "evidence[0]"},
        },
    ]
    live_equivalent["surfaceStatus"]["evidence"]["status"] = "produced"
    live_equivalent["surfaceStatus"]["evidence"]["count"] = 1

    expected_report = validate_paper_static_evidence_bundle(live_equivalent)
    report = write_paper_static_evidence_artifacts(tmp_path, live_equivalent)

    assert json.loads((tmp_path / "s4-static-evidence.raw.json").read_text()) == live_equivalent
    assert json.loads((tmp_path / "s4-static-evidence.validation.json").read_text()) == expected_report
    assert report == expected_report
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
async def test_live_endpoint_returns_failed_bundle_for_post_admission_static_contract_failure(
    client,
    tmp_path: Path,
) -> None:
    root = _make_source_root(tmp_path)
    execution = _execution_report()

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
        patch("app.routers.scan.include_resolver.resolve", AsyncMock(return_value=[])),
        patch("app.routers.scan.identify_libraries", AsyncMock(return_value=[])),
        patch("app.routers.scan.build_static_evidence_contract", side_effect=RuntimeError("SECRET /home/kosh/project traceback")),
    ):
        response = await client.post(
            "/v1/paper/static-evidence",
            headers={"X-Request-Id": "req-post-admission-failed-bundle"},
            json=_paper_request(root),
        )

    assert response.status_code == 200
    bundle = response.json()
    assert bundle["success"] is False
    assert bundle["bundleStatus"] == "failed"
    assert bundle["s4RequestId"] == "req-post-admission-failed-bundle"
    assert bundle["diagnostics"]
    assert bundle["surfaceStatus"]["staticEvidenceContract"]["status"] == "failed"
    assert bundle["surfaceStatus"]["staticEvidenceContract"]["diagnosticRefs"]
    assert "SECRET" not in json.dumps(bundle)
    assert "/home/kosh" not in json.dumps(bundle)

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


@pytest.mark.asyncio
async def test_paper_static_evidence_respond_async_uses_durable_ownership(client, tmp_path: Path) -> None:
    from app.runtime.request_ownership import request_ownership_store

    await request_ownership_store.reset()
    root = _make_source_root(tmp_path)
    gate = asyncio.Event()

    async def _slow_bundle(**_kwargs):
        await gate.wait()
        bundle = _minimal_bundle()
        bundle["s4RequestId"] = "owned-paper-static"
        return bundle

    try:
        with patch(
            "app.routers.scan.build_paper_static_evidence_bundle",
            AsyncMock(side_effect=_slow_bundle),
        ):
            submit = await client.post(
                "/v1/paper/static-evidence",
                headers={"X-Request-Id": "owned-paper-static", "Prefer": "respond-async"},
                json=_paper_request(root),
            )
            assert submit.status_code == 202
            assert submit.headers["Preference-Applied"] == "respond-async"
            submitted = submit.json()
            assert submitted["endpoint"] == "paper-static-evidence"
            assert submitted["resultReady"] is False
            assert submitted["statusUrl"] == "/v1/requests/owned-paper-static"
            assert submitted["resultUrl"] == "/v1/requests/owned-paper-static/result"

            for _ in range(20):
                status = await client.get("/v1/requests/owned-paper-static")
                status_payload = status.json()
                if status_payload["state"] == "running":
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("owned paper request did not expose running state")
            assert status_payload["resultReady"] is False
            assert status_payload["requestSummary"]["state"] == "running"

            health = await client.get("/v1/health", params={"requestId": "owned-paper-static"})
            health_payload = health.json()
            assert health_payload["activeRequestCount"] == 1
            health_summary = health_payload["requestSummary"]
            assert health_summary["requestId"] == "owned-paper-static"
            assert health_summary["endpoint"] == "paper-static-evidence"
            assert health_summary["state"] == "running"
            assert health_summary["ackStatus"] == "active"

            gate.set()
            result = await _wait_for_owned_result(client, "owned-paper-static")
            terminal_health = await client.get("/v1/health", params={"requestId": "owned-paper-static"})

        assert result["state"] == "completed"
        assert result["result"]["success"] is True
        assert result["result"]["bundleStatus"] == "produced"
        terminal_summary = terminal_health.json()["requestSummary"]
        assert terminal_summary["endpoint"] == "paper-static-evidence"
        assert terminal_summary["state"] == "completed"
        assert terminal_health.json()["activeRequestCount"] == 0
    finally:
        await request_ownership_store.reset()


@pytest.mark.asyncio
async def test_paper_static_evidence_respond_async_contract_error_is_retrievable_failure(
    client,
    tmp_path: Path,
) -> None:
    from app.runtime.request_ownership import request_ownership_store
    from app.scanner.paper_static_evidence import PaperStaticEvidenceContractError

    await request_ownership_store.reset()
    root = _make_source_root(tmp_path)

    try:
        with patch(
            "app.routers.scan.build_paper_static_evidence_bundle",
            AsyncMock(
                side_effect=PaperStaticEvidenceContractError(
                    "SOURCE_ROOT_UNREADABLE",
                    "Source root is unreadable.",
                ),
            ),
        ):
            submit = await client.post(
                "/v1/paper/static-evidence",
                headers={"X-Request-Id": "owned-paper-contract-error", "Prefer": "respond-async"},
                json=_paper_request(root),
            )
            assert submit.status_code == 202
            result = await _wait_for_owned_result(client, "owned-paper-contract-error")

        assert result["state"] == "failed"
        assert result["result"]["success"] is False
        assert result["result"]["errorDetail"]["code"] == "SOURCE_ROOT_UNREADABLE"
        assert result["result"]["errorDetail"]["requestId"] == "owned-paper-contract-error"
    finally:
        await request_ownership_store.reset()


@pytest.mark.asyncio
async def test_paper_static_evidence_respond_async_preflight_reject_does_not_create_owned_request(
    client,
    tmp_path: Path,
) -> None:
    from app.runtime.request_ownership import request_ownership_store

    await request_ownership_store.reset()
    root = _make_source_root(tmp_path)
    payload = _paper_request(root)
    payload["compileContext"]["type"] = "unsupported"

    try:
        response = await client.post(
            "/v1/paper/static-evidence",
            headers={"X-Request-Id": "owned-paper-invalid", "Prefer": "respond-async"},
            json=payload,
        )
        status = await client.get("/v1/requests/owned-paper-invalid")

        assert response.status_code == 400
        assert response.json()["errorDetail"]["code"] == "UNSUPPORTED_COMPILE_CONTEXT_TYPE"
        assert status.status_code == 404
    finally:
        await request_ownership_store.reset()


def test_b2_b4_rendering_order_uses_same_evidence_rows() -> None:
    from app.scanner.paper_static_evidence import paper_reviewer_visible_rows

    bundle = _minimal_bundle()
    diag_one = {
        "diagnosticId": "diag:0000:surface_production_failed",
        "severity": "warning",
        "category": "surface-error",
        "reasonCode": "SURFACE_PRODUCTION_FAILED",
        "surface": "functions",
        "message": "first deterministic diagnostic row",
        "consumerPolicy": "producer_diagnostic_not_security_evidence",
        "trace": {**bundle["sourceFiles"][0]["trace"], "surface": "diagnostics", "surfaceId": "surface:diagnostics", "rawObjectRef": "diagnostics[0]"},
    }
    diag_two = copy.deepcopy(diag_one)
    diag_two["diagnosticId"] = "diag:0001:surface_production_failed"
    diag_two["message"] = "second deterministic diagnostic row"
    diag_two["trace"]["rawObjectRef"] = "diagnostics[1]"
    bundle["diagnostics"] = [diag_one, diag_two]
    bundle["evidence"] = [
        {
            "evidenceId": "ev:0000",
            "evidenceType": "sast-finding-message",
            "producer": "s4",
            "findingId": None,
            "sourceFileId": "src:0000",
            "text": "first reviewer-visible evidence",
            "consumerPolicy": "local_static_structure_only",
            "diagnosticRefs": [],
            "trace": {**bundle["sourceFiles"][0]["trace"], "surface": "evidence", "rawObjectRef": "evidence[0]"},
        },
        {
            "evidenceId": "ev:0001",
            "evidenceType": "sast-finding-message",
            "producer": "s4",
            "findingId": None,
            "sourceFileId": "src:0000",
            "text": "second reviewer-visible evidence",
            "consumerPolicy": "local_static_structure_only",
            "diagnosticRefs": [],
            "trace": {**bundle["sourceFiles"][0]["trace"], "surface": "evidence", "rawObjectRef": "evidence[1]"},
        },
    ]
    bundle["surfaceStatus"]["evidence"]["status"] = "produced"
    bundle["surfaceStatus"]["evidence"]["count"] = 2

    b2_rows = paper_reviewer_visible_rows(bundle, packet_condition="B2")
    b4_rows = paper_reviewer_visible_rows(bundle, packet_condition="B4")

    assert b2_rows == b4_rows == [
        "first reviewer-visible evidence",
        "second reviewer-visible evidence",
        "first deterministic diagnostic row",
        "second deterministic diagnostic row",
    ]


@pytest.mark.asyncio
async def test_paper_static_evidence_observability_preserves_request_id_and_logs_lifecycle(
    client,
    tmp_path: Path,
    caplog,
) -> None:
    root = _make_source_root(tmp_path)

    async def _bundle(**kwargs):
        bundle = _minimal_bundle()
        bundle["s4RequestId"] = kwargs["request_id"]
        return bundle

    caplog.set_level("INFO", logger="aegis-sast-runner")
    with patch("app.routers.scan.build_paper_static_evidence_bundle", AsyncMock(side_effect=_bundle)):
        response = await client.post(
            "/v1/paper/static-evidence",
            headers={"X-Request-Id": "req-paper-observability"},
            json=_paper_request(root),
        )

    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "req-paper-observability"
    assert response.json()["s4RequestId"] == "req-paper-observability"
    lifecycle = [
        record for record in caplog.records
        if record.name == "aegis-sast-runner" and record.getMessage().startswith("paper static-evidence")
    ]
    assert [record.getMessage() for record in lifecycle] == [
        "paper static-evidence request start",
        "paper static-evidence request end",
    ]
    end = lifecycle[-1]
    assert end.requestId == "req-paper-observability"
    assert end.caseId == "case-001"
    assert end.buildTargetId == "target-001"
    assert end.paperRunId == "paper-run-001"
    assert end.status == 200
    assert isinstance(end.elapsedMs, int)
    assert end.bundleStatus == "produced"


@pytest.mark.asyncio
async def test_paper_static_evidence_observability_generates_request_id_when_missing(
    client,
    tmp_path: Path,
) -> None:
    root = _make_source_root(tmp_path)

    async def _bundle(**kwargs):
        bundle = _minimal_bundle()
        bundle["s4RequestId"] = kwargs["request_id"]
        return bundle

    with patch("app.routers.scan.build_paper_static_evidence_bundle", AsyncMock(side_effect=_bundle)):
        response = await client.post("/v1/paper/static-evidence", json=_paper_request(root))

    generated = response.headers["X-Request-Id"]
    assert response.status_code == 200
    assert generated.startswith("req-")
    assert response.json()["s4RequestId"] == generated


@pytest.mark.asyncio
async def test_paper_static_evidence_observability_logs_preflight_error_without_raw_input(
    client,
    tmp_path: Path,
    caplog,
) -> None:
    root = _make_source_root(tmp_path)
    payload = _paper_request(root)
    payload["checksum"] = "sha256:SECRET-/home/kosh/private"

    caplog.set_level("INFO", logger="aegis-sast-runner")
    response = await client.post(
        "/v1/paper/static-evidence",
        headers={"X-Request-Id": "req-paper-preflight-error"},
        json=payload,
    )

    assert response.status_code == 400
    body = response.json()
    assert body["success"] is False
    assert body["errorDetail"]["requestId"] == "req-paper-preflight-error"
    assert "SECRET" not in json.dumps(body)
    assert "/home/kosh" not in json.dumps(body)
    assert "SECRET" not in caplog.text
    assert "/home/kosh" not in caplog.text
    error = [
        record for record in caplog.records
        if record.getMessage() == "paper static-evidence request error"
    ][-1]
    assert error.requestId == "req-paper-preflight-error"
    assert error.status == 400
    assert error.code == "PAPER_STATIC_EVIDENCE_REQUEST_FORBIDDEN_FIELD"
    assert isinstance(error.elapsedMs, int)


@pytest.mark.asyncio
async def test_paper_static_evidence_observability_logs_async_acceptance(
    client,
    tmp_path: Path,
    caplog,
) -> None:
    from app.runtime.request_ownership import request_ownership_store

    await request_ownership_store.reset()
    root = _make_source_root(tmp_path)
    try:
        caplog.set_level("INFO", logger="aegis-sast-runner")
        with patch("app.routers.scan.build_paper_static_evidence_bundle", AsyncMock(return_value=_minimal_bundle())):
            response = await client.post(
                "/v1/paper/static-evidence",
                headers={"X-Request-Id": "req-paper-async-observability", "Prefer": "respond-async"},
                json=_paper_request(root),
            )
            result = await _wait_for_owned_result(client, "req-paper-async-observability")

        assert response.status_code == 202
        accepted = [
            record for record in caplog.records
            if record.getMessage() == "paper static-evidence request accepted"
        ][-1]
        assert accepted.requestId == "req-paper-async-observability"
        assert accepted.status == 202
        assert accepted.caseId == "case-001"
        assert accepted.paperRunId == "paper-run-001"
        assert isinstance(accepted.elapsedMs, int)
        assert result["state"] == "completed"
    finally:
        await request_ownership_store.reset()


@pytest.mark.asyncio
async def test_paper_static_evidence_422_generates_request_id_and_sanitized_common_envelope(
    client,
    caplog,
) -> None:
    caplog.set_level("WARNING", logger="aegis-sast-runner")

    response = await client.post("/v1/paper/static-evidence", json=["not-a-dict", "SECRET"])

    generated = response.headers["X-Request-Id"]
    body = response.json()
    assert response.status_code == 422
    assert generated.startswith("req-")
    assert body["success"] is False
    assert body["errorDetail"]["code"] == "REQUEST_VALIDATION_FAILED"
    assert body["errorDetail"]["requestId"] == generated
    assert "SECRET" not in json.dumps(body)
    assert "SECRET" not in caplog.text


def test_paper_static_evidence_route_has_no_outbound_http_client_calls() -> None:
    router_path = Path(__file__).resolve().parents[1] / "app" / "routers" / "scan.py"
    tree = ast.parse(router_path.read_text(encoding="utf-8"), filename=str(router_path))
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "paper_static_evidence"
    )
    source = ast.get_source_segment(router_path.read_text(encoding="utf-8"), function) or ""

    forbidden_tokens = ("httpx.", "requests.", "aiohttp.", "AsyncClient(", "HTTPConnection(")
    assert not any(token in source for token in forbidden_tokens)


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
