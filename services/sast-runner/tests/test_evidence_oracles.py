"""Oracle tests for deterministic S4 evidence-resolution semantics.

These tests are intentionally written as hand-authored fixtures before the
producer implementation.  They lock evidence semantics, not tool performance.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.scanner.library_identifier import LibraryIdentifier
from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.request import SnapshotProvenance
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    SastDataFlowStep,
    SastFinding,
    SastFindingLocation,
    SdkResolutionInfo,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "evidence_oracles"
VERDICT_KEYS = {"vulnerable", "safe", "affected", "clean", "riskScore", "securityVerdict"}


def _load_expected(case: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / case / "expected.json").read_text())


def _assert_no_verdict_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        forbidden = VERDICT_KEYS.intersection(value)
        assert not forbidden, f"verdict-like key(s) at {path}: {sorted(forbidden)}"
        for key, nested in value.items():
            _assert_no_verdict_keys(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_verdict_keys(nested, f"{path}[{index}]")


def _make_finding(
    *,
    tool_id: str,
    rule_id: str,
    file: str,
    line: int,
    column: int | None = None,
    cwe_id: str | None = None,
    data_flow: list[SastDataFlowStep] | None = None,
    origin: str | None = None,
) -> SastFinding:
    metadata = {"cweId": cwe_id, "cwe": [cwe_id]} if cwe_id else None
    return SastFinding(
        toolId=tool_id,
        ruleId=rule_id,
        severity="high",
        message="oracle finding",
        location=SastFindingLocation(file=file, line=line, column=column),
        dataFlow=data_flow,
        origin=origin,
        metadata=metadata,
    )


def test_fixture_inputs_are_small_controlled_c_projects() -> None:
    assert (FIXTURES_DIR / "sast_user_finding" / "src" / "vulnerable.c").is_file()
    assert (FIXTURES_DIR / "sast_unknown_semantics" / "src" / "incomplete.c").is_file()
    assert (FIXTURES_DIR / "sca_known_library" / "libraries" / "civetweb" / "CMakeLists.txt").is_file()
    assert (FIXTURES_DIR / "sca_versionless_library" / "libraries" / "civetweb" / "civetweb.c").is_file()


def test_allowed_sast_tool_set_remains_existing_six_tools() -> None:
    assert ALL_TOOLS == [
        "semgrep",
        "cppcheck",
        "flawfinder",
        "clang-tidy",
        "scan-build",
        "gcc-fanalyzer",
    ]


def test_sast_user_finding_oracle_matches_hand_authored_expected() -> None:
    from app.scanner.evidence import enrich_finding_evidence

    expected = _load_expected("sast_user_finding")
    finding = _make_finding(
        tool_id="semgrep",
        rule_id="c.security.strcpy",
        file="src/vulnerable.c",
        line=4,
        column=5,
        cwe_id="CWE-120",
        data_flow=[SastDataFlowStep(file="src/vulnerable.c", line=4, content="strcpy(dst, src);")],
    )

    enriched = enrich_finding_evidence(finding).model_dump(by_alias=True, exclude_none=False)

    assert enriched["metadata"]["evidenceResolution"] == expected["metadata"]["evidenceResolution"]
    assert enriched["metadata"]["cweId"] == "CWE-120"
    _assert_no_verdict_keys(enriched["metadata"]["evidenceResolution"])


def test_sast_unknown_semantics_oracle_is_not_safe_or_clean() -> None:
    from app.scanner.evidence import enrich_finding_evidence

    expected = _load_expected("sast_unknown_semantics")
    finding = _make_finding(
        tool_id="cppcheck",
        rule_id="unknown-rule",
        file="src/incomplete.c",
        line=2,
    )

    enriched = enrich_finding_evidence(finding).model_dump(by_alias=True, exclude_none=False)

    assert enriched["metadata"]["evidenceResolution"] == expected["metadata"]["evidenceResolution"]
    assert "CWE_UNKNOWN" in enriched["metadata"]["evidenceResolution"]["diagnostics"]
    assert "DATAFLOW_NOT_PROVIDED" in enriched["metadata"]["evidenceResolution"]["diagnostics"]
    _assert_no_verdict_keys(enriched)


def test_cross_boundary_origin_is_reflected_without_rewriting_legacy_origin() -> None:
    from app.scanner.evidence import enrich_finding_evidence

    finding = _make_finding(
        tool_id="scan-build",
        rule_id="core.CallAndMessage",
        file="/opt/sdk/include/vendor.h",
        line=10,
        cwe_id="CWE-476",
        origin="cross-boundary",
    )

    enriched = enrich_finding_evidence(finding)
    evidence = enriched.metadata["evidenceResolution"]

    assert enriched.origin == "cross-boundary"
    assert evidence["origin"] == {
        "status": "cross-boundary",
        "source": "top-level-origin",
    }


def test_finding_evidence_enrichment_is_idempotent() -> None:
    from app.scanner.evidence import enrich_finding_evidence

    finding = _make_finding(
        tool_id="semgrep",
        rule_id="c.security.strcpy",
        file="src/vulnerable.c",
        line=4,
        column=5,
        cwe_id="CWE-120",
        data_flow=[SastDataFlowStep(file="src/vulnerable.c", line=4, content="strcpy(dst, src);")],
    )

    once = enrich_finding_evidence(finding)
    twice = enrich_finding_evidence(once)

    assert twice.model_dump(by_alias=True, exclude_none=False) == once.model_dump(
        by_alias=True,
        exclude_none=False,
    )


def test_sca_known_library_oracle_preserves_legacy_fields_and_provenance() -> None:
    from app.scanner.evidence import project_library_evidence

    expected = _load_expected("sca_known_library")
    project = FIXTURES_DIR / "sca_known_library"
    lib = LibraryIdentifier().identify(project)[0]
    provenance = SnapshotProvenance(
        buildSnapshotId="bsnap-oracle",
        buildUnitId="bunit-oracle",
        snapshotSchemaVersion="build-snapshot-v1",
    )

    actual = project_library_evidence(lib, provenance=provenance, diff_computed=False)

    assert actual == expected["library"]
    assert {"name", "version", "path", "repoUrl"}.issubset(actual)
    _assert_no_verdict_keys(actual)


def test_sca_versionless_library_oracle_keeps_unknown_as_unknown() -> None:
    from app.scanner.evidence import project_library_evidence

    expected = _load_expected("sca_versionless_library")
    project = FIXTURES_DIR / "sca_versionless_library"
    lib = LibraryIdentifier().identify(project)[0]

    actual = project_library_evidence(lib, provenance=None, diff_computed=False)

    assert actual == expected["library"]
    assert actual["version"] is None
    assert actual["versionStatus"] == "unknown"
    assert actual["cveLookupEligible"] is False
    assert "VERSION_UNKNOWN" in actual["diagnostics"]
    _assert_no_verdict_keys(actual)


def test_git_library_oracle_preserves_commit_branch_repo_and_tag(tmp_path: Path) -> None:
    from app.scanner.evidence import project_library_evidence

    project = tmp_path / "project"
    lib_dir = project / "libraries" / "mosquitto"
    lib_dir.mkdir(parents=True)
    (lib_dir / "mosquitto.c").write_text("void mosquitto_stub(void) {}\n")

    subprocess.run(["git", "init", "-b", "main"], cwd=lib_dir, check=True, capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", "https://github.com/eclipse/mosquitto.git"], cwd=lib_dir, check=True)
    subprocess.run(["git", "add", "mosquitto.c"], cwd=lib_dir, check=True)
    subprocess.run(
        ["git", "-c", "user.email=s4@example.invalid", "-c", "user.name=S4 Test", "commit", "-m", "fixture"],
        cwd=lib_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "tag", "v2.0.22"], cwd=lib_dir, check=True)

    lib = LibraryIdentifier().identify(project)[0]
    actual = project_library_evidence(lib, provenance=None, diff_computed=False)

    assert actual["name"] == "mosquitto"
    assert actual["path"] == "libraries/mosquitto"
    assert actual["source"] == "git"
    assert actual["repoUrl"] == "https://github.com/eclipse/mosquitto.git"
    assert actual["commit"]
    assert actual["branch"] == "main"
    assert actual["tag"] == "v2.0.22"
    assert actual["nearestTag"] is None
    assert actual["versionStatus"] == "known"
    assert actual["cveLookupEligible"] is True
    _assert_no_verdict_keys(actual)


def test_evidence_module_has_no_s5_or_cve_lookup_references() -> None:
    evidence_module = Path(__file__).parents[1] / "app" / "scanner" / "evidence.py"
    text = evidence_module.read_text(encoding="utf-8").lower()

    assert "batch-lookup" not in text
    assert "/v1/cve" not in text
    assert "s5" not in text
    assert "httpx" not in text
    assert "requests" not in text


@pytest.mark.asyncio
async def test_scan_project_path_returns_enriched_sca_oracle(
    client: AsyncClient,
) -> None:
    project = FIXTURES_DIR / "sca_known_library"
    execution = ExecutionReport(
        toolsRun=["semgrep"],
        toolResults={},
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=False,
        degradeReasons=[],
    )

    with (
        patch("app.routers.scan.orchestrator.run", AsyncMock(return_value=([], execution))),
        patch("app.routers.scan.orchestrator.evaluate_policy", MagicMock(return_value=None)),
        patch("app.routers.scan.ast_dumper.dump_functions", AsyncMock(return_value={"functions": []})),
    ):
        resp = await client.post(
            "/v1/scan",
            json={
                "scanId": "evidence-oracle-scan",
                "projectId": "proj-evidence",
                "projectPath": str(project),
                "provenance": {
                    "buildSnapshotId": "bsnap-oracle",
                    "buildUnitId": "bunit-oracle",
                    "snapshotSchemaVersion": "build-snapshot-v1",
                },
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["sca"]["libraries"] == [_load_expected("sca_known_library")["library"]]
    _assert_no_verdict_keys(data["sca"]["libraries"])


@pytest.mark.asyncio
async def test_build_and_analyze_library_shape_matches_nested_scan_result(
    client: AsyncClient,
) -> None:
    from app.schemas.response import BuildEvidence, BuildReadiness, BuildResponse, ScanResponse, ScanStats

    expected_library = _load_expected("sca_known_library")["library"]
    provenance = SnapshotProvenance(
        buildSnapshotId="bsnap-oracle",
        buildUnitId="bunit-oracle",
        snapshotSchemaVersion="build-snapshot-v1",
    )
    build_response = BuildResponse(
        success=True,
        provenance=provenance,
        buildEvidence=BuildEvidence(
            requestedBuildCommand="make",
            effectiveBuildCommand="make",
            buildDir="/tmp/project",
            compileCommandsPath="/tmp/project/compile_commands.json",
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
    scan_response = ScanResponse(
        success=True,
        scanId="evidence-build-and-analyze",
        status="completed",
        provenance=provenance,
        findings=[],
        stats=ScanStats(filesScanned=1, rulesRun=1, findingsTotal=0, elapsedMs=1),
        execution=ExecutionReport(
            toolsRun=["semgrep"],
            toolResults={},
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
            degraded=False,
            degradeReasons=[],
        ),
        codeGraph={"functions": []},
        sca={"libraries": [expected_library]},
    )

    with (
        patch("pathlib.Path.is_dir", return_value=True),
        patch("app.routers.scan.build_runner.build", AsyncMock(return_value=build_response.model_dump(by_alias=True, exclude_none=True))),
        patch("app.routers.scan._run_scan_core", AsyncMock(return_value=scan_response)),
        patch("app.routers.scan.metadata_extractor.extract", AsyncMock(return_value={"compiler": "gcc"})),
    ):
        resp = await client.post(
            "/v1/build-and-analyze",
            json={
                "projectPath": "/tmp/project",
                "buildCommand": "make",
                "projectId": "proj-evidence",
                "provenance": provenance.model_dump(by_alias=True, exclude_none=True),
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["libraries"] == [expected_library]
    assert data["libraries"] == data["scan"]["sca"]["libraries"]
    _assert_no_verdict_keys(data["libraries"])
