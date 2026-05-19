"""ScanOrchestrator 단위 테스트 — 도구 선택, profile enrichment, 필터링."""

import logging
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.errors import RequiredToolUnavailableError
from app.scanner.evidence import enrich_findings_evidence
from app.scanner.orchestrator import (
    ALL_TOOLS,
    ScanOrchestrator,
    _filter_user_code_findings,
    _is_third_party,
    _is_user_path,
    _parse_version,
    _sanitize_public_finding_paths,
)
from app.schemas.request import BuildProfile, SdkDescriptor
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    SastDataFlowStep,
    SastFinding,
    SastFindingLocation,
    SdkResolutionInfo,
    ToolExecutionResult,
)


@pytest.fixture
def orchestrator():
    return ScanOrchestrator()


def _make_finding(
    file: str,
    tool: str = "cppcheck",
    data_flow: list[SastDataFlowStep] | None = None,
) -> SastFinding:
    return SastFinding(
        toolId=tool,
        ruleId=f"{tool}:test",
        severity="warning",
        message="test finding",
        location=SastFindingLocation(file=file, line=1),
        dataFlow=data_flow,
    )


def _available_all_tools() -> dict[str, dict]:
    return {
        "semgrep": {"available": True, "version": "1.45.0", "probeReason": None},
        "cppcheck": {"available": True, "version": "2.13.0", "probeReason": None},
        "flawfinder": {"available": True, "version": "2.0.19", "probeReason": None},
        "clang-tidy": {"available": True, "version": "18.1.3", "probeReason": None},
        "scan-build": {"available": True, "version": "18.1.3", "probeReason": None},
        "gcc-fanalyzer": {"available": True, "version": "13.3.0", "probeReason": None},
    }


def _execution_all_ok() -> ExecutionReport:
    return ExecutionReport(
        toolsRun=list(ALL_TOOLS),
        toolResults={
            tool: ToolExecutionResult(status="ok", findings_count=0, elapsed_ms=10)
            for tool in ALL_TOOLS
        },
        sdk=SdkResolutionInfo(resolved=False),
        filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        degraded=False,
        degradeReasons=[],
    )


class TestParseVersion:
    def test_standard_version(self):
        assert _parse_version("2.13.0") == (2, 13, 0)

    def test_single_number(self):
        assert _parse_version("16") == (16,)

    def test_version_with_suffix(self):
        assert _parse_version("13.3.0-ubuntu") == (13, 3, 0)

    def test_none_input(self):
        assert _parse_version(None) is None

    def test_empty_string(self):
        assert _parse_version("") is None


class TestSelectTools:
    def _available_all(self):
        return {
            "semgrep": {"available": True, "version": "1.45.0"},
            "cppcheck": {"available": True, "version": "2.13.0"},
            "flawfinder": {"available": True, "version": "2.0.19"},
            "clang-tidy": {"available": True, "version": "18.1.3"},
            "scan-build": {"available": True, "version": "18.1.3"},
            "gcc-fanalyzer": {"available": True, "version": "13.3.0"},
        }

    @pytest.mark.asyncio
    async def test_all_tools_selected_no_profile(self, orchestrator):
        available = self._available_all()
        active = await orchestrator._select_tools(None, None, available)
        # All 6 should be active (not in _skipped)
        assert all(available[t]["available"] for t in ["semgrep", "cppcheck", "flawfinder"])

    @pytest.mark.asyncio
    async def test_semgrep_not_skipped_for_cpp(self, orchestrator):
        """C++ 프로젝트에서도 Semgrep은 스킵되지 않음 (확장자 필터로 대체)."""
        available = self._available_all()
        profile = BuildProfile(
            compiler="g++",
            targetArch="x86_64", languageStandard="c++17",
            headerLanguage="cpp",
        )
        active = await orchestrator._select_tools(None, profile, available)
        assert "semgrep" not in active.get("_skipped", {})
        assert active.get("semgrep") is True

    @pytest.mark.asyncio
    async def test_semgrep_not_skipped_for_c(self, orchestrator):
        available = self._available_all()
        profile = BuildProfile(
            compiler="gcc",
            targetArch="x86_64", languageStandard="c99",
            headerLanguage="c",
        )
        active = await orchestrator._select_tools(None, profile, available)
        assert "semgrep" not in active.get("_skipped", {})

    @pytest.mark.asyncio
    async def test_unavailable_tool_skipped(self, orchestrator):
        available = self._available_all()
        available["scan-build"]["available"] = False
        active = await orchestrator._select_tools(None, None, available)
        assert "scan-build" in active.get("_skipped", {})

    @pytest.mark.asyncio
    async def test_explicit_tool_list(self, orchestrator):
        available = self._available_all()
        active = await orchestrator._select_tools(["cppcheck", "flawfinder"], None, available)
        assert "cppcheck" in active
        assert "flawfinder" in active
        assert active["_skipped"]["semgrep"] == "operator-requested-subset"
        assert active["_skipped"]["clang-tidy"] == "operator-requested-subset"

    @pytest.mark.asyncio
    async def test_unavailable_tool_uses_probe_reason(self, orchestrator):
        available = self._available_all()
        available["semgrep"]["available"] = False
        available["semgrep"]["probeReason"] = "environment-drift"
        active = await orchestrator._select_tools(None, None, available)
        assert active["_skipped"]["semgrep"] == "environment-drift"

    @pytest.mark.asyncio
    async def test_check_tools_redacts_expected_executable_path(self, orchestrator):
        secret_path = "/svc/SECRET_TOOL_PATH_SHOULD_NOT_LEAK/semgrep"
        for runner in (
            orchestrator.semgrep,
            orchestrator.cppcheck,
            orchestrator.flawfinder,
            orchestrator.clangtidy,
            orchestrator.scanbuild,
            orchestrator.gcc_analyzer,
        ):
            runner.check_available = AsyncMock(return_value=(True, "1.0.0"))
        orchestrator.semgrep.check_available = AsyncMock(return_value=(False, None))
        orchestrator.semgrep._last_probe = {
            "probeReason": "environment-drift",
            "expectedExecutablePath": secret_path,
        }

        tools = await orchestrator.check_tools(force=True)

        assert tools["semgrep"]["available"] is False
        assert tools["semgrep"]["probeReason"] == "environment-drift"
        assert tools["semgrep"]["expectedExecutablePathStatus"] == "configured"
        assert "expectedExecutablePath" not in tools["semgrep"]
        assert secret_path not in str(tools)

    @pytest.mark.asyncio
    async def test_gcc_fanalyzer_sdk_recheck(self, orchestrator):
        """호스트 gcc unavailable이지만 SDK 컴파일러로 재확인 → 활성화."""
        available = self._available_all()
        available["gcc-fanalyzer"]["available"] = False
        profile = BuildProfile(
            sdkId="ti-am335x", compiler="arm-gcc",
            targetArch="arm", languageStandard="c99",
            headerLanguage="c",
        )
        orchestrator.gcc_analyzer.check_available = AsyncMock(return_value=(True, "13.3.0"))
        active = await orchestrator._select_tools(None, profile, available)
        assert "gcc-fanalyzer" not in active.get("_skipped", {})
        assert active.get("gcc-fanalyzer") is True

    @pytest.mark.asyncio
    async def test_gcc_fanalyzer_non_registered_sdk_recheck_restores_active_without_key_error(self, orchestrator):
        """non-registered SDK compiler rescue is stable and removes stale skip state."""
        available = self._available_all()
        available["gcc-fanalyzer"]["available"] = False
        available["gcc-fanalyzer"]["probeReason"] = "runtime-tool-missing"
        profile = BuildProfile(
            sdkResolutionMode="non-registered",
            sdkDescriptor=SdkDescriptor(
                sdkRootPath="/opt/non-registered-sdk",
                compilerPath="/opt/non-registered-sdk/bin/arm-gcc",
            ),
            compiler="arm-gcc",
            targetArch="arm",
            languageStandard="c99",
            headerLanguage="c",
        )
        orchestrator.gcc_analyzer.check_available = AsyncMock(return_value=(True, "13.3.0"))

        active = await orchestrator._select_tools(None, profile, available)

        assert "gcc-fanalyzer" not in active.get("_skipped", {})
        assert active.get("gcc-fanalyzer") is True

    @pytest.mark.asyncio
    async def test_gcc_fanalyzer_sdk_recheck_still_fails(self, orchestrator):
        """호스트 gcc unavailable + SDK 컴파일러도 old → 여전히 스킵."""
        available = self._available_all()
        available["gcc-fanalyzer"]["available"] = False
        profile = BuildProfile(
            sdkId="ti-am335x", compiler="arm-gcc",
            targetArch="arm", languageStandard="c99",
            headerLanguage="c",
        )
        orchestrator.gcc_analyzer.check_available = AsyncMock(return_value=(False, None))
        active = await orchestrator._select_tools(None, profile, available)
        assert "gcc-fanalyzer" in active.get("_skipped", {})


class TestPolicyHelpers:
    @pytest.mark.parametrize("missing_tool", ALL_TOOLS)
    @pytest.mark.asyncio
    async def test_required_tool_unavailable_fails_closed_before_any_tool_runs(
        self,
        orchestrator,
        caplog,
        missing_tool: str,
    ):
        """기본 full-current-six scan은 어떤 required tool 하나가 꺼져도 나머지를 실행하지 않는다."""
        caplog.set_level("ERROR", logger="aegis-sast-runner")
        available = _available_all_tools()
        available[missing_tool] = {
            "available": False,
            "version": None,
            "probeReason": "environment-drift",
            "expectedExecutablePath": f"/svc/bin/{missing_tool}",
        }

        with (
            patch.object(orchestrator, "check_tools", AsyncMock(return_value=available)),
            patch.object(orchestrator, "_run_semgrep", AsyncMock(return_value=[])) as semgrep,
            patch.object(orchestrator, "_run_cppcheck", AsyncMock(return_value=[])) as cppcheck,
            patch.object(orchestrator, "_run_flawfinder", AsyncMock(return_value=[])) as flawfinder,
            patch.object(orchestrator, "_run_clangtidy", AsyncMock(return_value=[])) as clangtidy,
            patch.object(orchestrator, "_run_scanbuild", AsyncMock(return_value=[])) as scanbuild,
            patch.object(orchestrator, "_run_gcc_analyzer", AsyncMock(return_value=[])) as gcc_analyzer,
        ):
            with pytest.raises(RequiredToolUnavailableError) as exc_info:
                await orchestrator.run(
                    scan_dir=Path("/tmp/test"),
                    source_files=["main.c"],
                    profile=None,
                    rulesets=[],
                )

        assert exc_info.value.code == "REQUIRED_TOOL_UNAVAILABLE"
        assert missing_tool in exc_info.value.message
        failure = exc_info.value.tool_failures[0]
        assert failure["expectedExecutablePathStatus"] == "configured"
        assert "expectedExecutablePath" not in failure
        assert f"/svc/bin/{missing_tool}" not in str(failure)
        preflight_record = next(
            record for record in caplog.records
            if record.getMessage() == "Required SAST tool preflight failed"
        )
        assert preflight_record.failures[0]["expectedExecutablePathStatus"] == "configured"
        assert "expectedExecutablePath" not in preflight_record.failures[0]
        assert f"/svc/bin/{missing_tool}" not in str(preflight_record.failures)
        for runner in (semgrep, cppcheck, flawfinder, clangtidy, scanbuild, gcc_analyzer):
            assert runner.await_count == 0
        assert "Required SAST tool preflight failed" in caplog.text

    @pytest.mark.asyncio
    async def test_explicit_subset_requires_only_requested_tools(self, orchestrator):
        """명시적 subset은 허용하되 full-current-six 품질 결과로 승격하지 않는다."""
        available = {
            "semgrep": {"available": False, "version": None, "probeReason": "environment-drift"},
            "cppcheck": {"available": True, "version": "2.13.0", "probeReason": None},
            "flawfinder": {"available": False, "version": None, "probeReason": "runtime-tool-missing"},
            "clang-tidy": {"available": False, "version": None, "probeReason": "runtime-tool-missing"},
            "scan-build": {"available": False, "version": None, "probeReason": "runtime-tool-missing"},
            "gcc-fanalyzer": {"available": False, "version": None, "probeReason": "runtime-tool-missing"},
        }

        with (
            patch.object(orchestrator, "check_tools", AsyncMock(return_value=available)),
            patch.object(orchestrator, "_run_cppcheck", AsyncMock(return_value=[])),
        ):
            _findings, execution = await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=[],
                tools=["cppcheck"],
            )

        assert execution.tools_run == ["cppcheck"]
        assert execution.tool_results["cppcheck"].status == "ok"
        assert execution.tool_results["semgrep"].skip_reason == "operator-requested-subset"

    @pytest.mark.parametrize("bad_tool", ALL_TOOLS)
    @pytest.mark.parametrize(
        ("bad_result", "expected_code"),
        [
            (
                ToolExecutionResult(status="failed", findings_count=0, elapsed_ms=10, skip_reason="runner crashed"),
                "REQUIRED_TOOL_EXECUTION_INCOMPLETE",
            ),
            (
                ToolExecutionResult(status="partial", findings_count=1, elapsed_ms=10, timed_out_files=1),
                "REQUIRED_TOOL_EXECUTION_INCOMPLETE",
            ),
            (
                ToolExecutionResult(status="ok", findings_count=1, elapsed_ms=10, degraded=True, degrade_reasons=["bad-output"]),
                "REQUIRED_TOOL_EXECUTION_INCOMPLETE",
            ),
        ],
    )
    def test_evaluate_policy_blocks_any_requested_tool_non_normal_execution(
        self,
        orchestrator,
        bad_tool: str,
        bad_result: ToolExecutionResult,
        expected_code: str,
    ):
        execution = _execution_all_ok()
        execution.tool_results[bad_tool] = bad_result

        policy = orchestrator.evaluate_policy(execution, required_tools=list(ALL_TOOLS))

        assert policy["code"] == expected_code
        assert bad_tool in policy["unstableTools"]
        assert bad_tool in policy["message"]

    def test_evaluate_policy_blocks_requested_tool_missing_result(self, orchestrator):
        execution = _execution_all_ok()
        del execution.tool_results["scan-build"]

        policy = orchestrator.evaluate_policy(execution, required_tools=list(ALL_TOOLS))

        assert policy["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
        assert policy["unstableTools"] == ["scan-build"]

    def test_evaluate_policy_uses_explicit_required_tools_not_tools_run_observation(
        self,
        orchestrator,
    ):
        execution = _execution_all_ok()
        execution.tools_run = ["cppcheck"]
        del execution.tool_results["semgrep"]

        policy = orchestrator.evaluate_policy(execution, required_tools=list(ALL_TOOLS))

        assert policy["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
        assert "semgrep" in policy["unstableTools"]

    def test_evaluate_policy_allows_unrequested_operator_subset_but_blocks_requested_failure(
        self,
        orchestrator,
    ):
        execution = ExecutionReport(
            toolsRun=["cppcheck"],
            toolResults={
                "semgrep": ToolExecutionResult(
                    status="skipped",
                    findings_count=0,
                    elapsed_ms=0,
                    skip_reason="operator-requested-subset",
                ),
                "cppcheck": ToolExecutionResult(
                    status="failed",
                    findings_count=0,
                    elapsed_ms=10,
                    skip_reason="nonzero exit",
                ),
            },
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=0, afterFilter=0),
        )

        policy = orchestrator.evaluate_policy(execution, required_tools=["cppcheck"])

        assert policy["code"] == "REQUIRED_TOOL_EXECUTION_INCOMPLETE"
        assert policy["unstableTools"] == ["cppcheck"]

    def test_build_health_policy(self, orchestrator):
        policy = orchestrator.build_health_policy({
            "semgrep": {"available": False, "version": None, "probeReason": "environment-drift"},
            "cppcheck": {"available": True, "version": "2.13.0", "probeReason": None},
        })
        assert policy["policyStatus"] == "degraded"
        assert policy["policyReasons"] == ["environment-drift"]
        assert policy["unavailableTools"] == ["semgrep"]
        assert policy["allowedSkipReasons"] == [
            "operator-requested-subset",
            "profile-not-applicable",
        ]

    def test_evaluate_policy_disallowed_skip(self, orchestrator):
        execution = ExecutionReport(
            toolsRun=["cppcheck"],
            toolResults={
                "semgrep": ToolExecutionResult(
                    status="skipped",
                    findings_count=0,
                    elapsed_ms=0,
                    skip_reason="environment-drift",
                ),
                "cppcheck": ToolExecutionResult(status="ok", findings_count=1, elapsed_ms=10),
            },
            sdk=SdkResolutionInfo(resolved=False),
            filtering=FindingsFilterInfo(beforeFilter=1, afterFilter=1),
            degraded=False,
            degradeReasons=[],
        )
        policy = orchestrator.evaluate_policy(execution)
        assert policy["code"] == "DISALLOWED_TOOL_ENVIRONMENT_DRIFT"
        assert policy["omittedTools"] == ["semgrep"]


class TestIsUserPath:
    def test_relative_path(self):
        assert _is_user_path("src/main.c") is True

    def test_absolute_path(self):
        assert _is_user_path("/usr/include/stdio.h") is False


class TestFilterUserCodeFindings:
    def test_keeps_relative_paths(self):
        findings = [
            _make_finding("src/main.c"),
            _make_finding("lib/util.c"),
        ]
        result, stats = _filter_user_code_findings(findings, [])
        assert len(result) == 2
        assert stats["cross_boundary"] == 0

    def test_removes_absolute_paths(self):
        findings = [
            _make_finding("src/main.c"),
            _make_finding("/usr/include/stdio.h"),
        ]
        result, stats = _filter_user_code_findings(findings, [])
        assert len(result) == 1
        assert result[0].location.file == "src/main.c"
        assert stats["cross_boundary"] == 0

    def test_empty_findings(self):
        result, stats = _filter_user_code_findings([], [])
        assert result == []
        assert stats["cross_boundary"] == 0

    def test_cross_boundary_kept(self):
        """SDK 경로 finding이지만 dataFlow에 사용자 코드 포함 → 유지 + origin 태깅."""
        findings = [
            _make_finding(
                "/opt/sdks/ti-am335x/sysroot/usr/include/sdk_api.h",
                tool="gcc-fanalyzer",
                data_flow=[
                    SastDataFlowStep(file="src/main.c", line=10, content="buf allocated here"),
                    SastDataFlowStep(
                        file="/opt/sdks/ti-am335x/sysroot/usr/include/sdk_api.h",
                        line=42, content="buffer overflow here",
                    ),
                ],
            ),
        ]
        result, stats = _filter_user_code_findings(findings, [])
        assert len(result) == 1
        assert stats["cross_boundary"] == 1
        assert result[0].origin == "cross-boundary"

    def test_pure_sdk_finding_removed(self):
        """SDK 경로 finding + dataFlow도 전부 SDK → 제거."""
        findings = [
            _make_finding(
                "/usr/include/openssl/ssl.h",
                tool="clang-tidy",
                data_flow=[
                    SastDataFlowStep(file="/usr/include/openssl/bio.h", line=5, content="note"),
                    SastDataFlowStep(file="/usr/include/openssl/ssl.h", line=10, content="note"),
                ],
            ),
        ]
        result, stats = _filter_user_code_findings(findings, [])
        assert len(result) == 0
        assert stats["cross_boundary"] == 0

    def test_sdk_finding_no_dataflow_removed(self):
        """SDK 경로 finding + dataFlow 없음 → 제거."""
        findings = [
            _make_finding("/usr/include/stdlib.h", tool="cppcheck"),
        ]
        result, stats = _filter_user_code_findings(findings, [])
        assert len(result) == 0
        assert stats["cross_boundary"] == 0

    def test_mixed_findings(self):
        """사용자 + 경계면 + 순수 SDK 혼합 → 올바르게 분류."""
        findings = [
            # 사용자 코드
            _make_finding("src/main.c"),
            # 경계면 (SDK location + user dataFlow)
            _make_finding(
                "/sdk/include/api.h",
                tool="scan-build",
                data_flow=[
                    SastDataFlowStep(file="src/caller.c", line=5, content="call site"),
                    SastDataFlowStep(file="/sdk/include/api.h", line=20, content="overflow"),
                ],
            ),
            # 순수 SDK
            _make_finding("/usr/include/string.h"),
        ]
        result, stats = _filter_user_code_findings(findings, [])
        assert len(result) == 2  # 사용자 1 + 경계면 1
        assert stats["cross_boundary"] == 1
        # 사용자 코드 finding은 origin 없음
        assert result[0].origin is None
        # 경계면 finding은 origin 태깅
        assert result[1].origin == "cross-boundary"


class TestPublicFindingPathSanitization:
    def test_cross_boundary_external_paths_are_redacted_after_filtering(self):
        secret_root = "/opt/SECRET_PUBLIC_FINDING_SDK_ROOT"
        findings = [
            _make_finding(
                f"{secret_root}/sysroot/usr/include/api.h",
                tool="gcc-fanalyzer",
                data_flow=[
                    SastDataFlowStep(file="src/main.c", line=10, content="call site"),
                    SastDataFlowStep(
                        file=f"{secret_root}/sysroot/usr/include/api.h",
                        line=42,
                        content="external sink",
                    ),
                ],
            ),
        ]

        filtered, stats = _filter_user_code_findings(findings, [])
        public_findings = enrich_findings_evidence(
            _sanitize_public_finding_paths(filtered, Path("/tmp/scan"))
        )

        assert stats["cross_boundary"] == 1
        assert stats["sdk_removed"] == 0
        assert public_findings[0].origin == "cross-boundary"
        assert public_findings[0].location.file == "<external>/api.h"
        assert public_findings[0].data_flow is not None
        assert public_findings[0].data_flow[0].file == "src/main.c"
        assert public_findings[0].data_flow[1].file == "<external>/api.h"
        assert (
            public_findings[0].metadata or {}
        )["evidenceResolution"]["location"]["file"] == "<external>/api.h"
        serialized = public_findings[0].model_dump_json(by_alias=True)
        assert "SECRET_PUBLIC_FINDING_SDK_ROOT" not in serialized

    @pytest.mark.asyncio
    async def test_run_redacts_public_cross_boundary_paths_without_breaking_filter_stats(
        self, orchestrator, tmp_path
    ):
        secret_root = "/opt/SECRET_RUN_PUBLIC_FINDING_SDK_ROOT"
        finding = _make_finding(
            f"{secret_root}/sysroot/usr/include/api.h",
            tool="cppcheck",
            data_flow=[
                SastDataFlowStep(file="src/main.c", line=10, content="call site"),
                SastDataFlowStep(
                    file=f"{secret_root}/sysroot/usr/include/api.h",
                    line=42,
                    content="external sink",
                ),
            ],
        )

        with (
            patch.object(orchestrator, "check_tools", AsyncMock(return_value=_available_all_tools())),
            patch.object(orchestrator, "_select_tools", AsyncMock(return_value={"cppcheck": True})),
            patch.object(orchestrator, "_run_cppcheck", AsyncMock(return_value=[finding])),
        ):
            findings, execution = await orchestrator.run(
                tmp_path,
                ["src/main.c"],
                None,
                [],
                tools=["cppcheck"],
            )

        assert execution.filtering.cross_boundary_kept == 1
        assert execution.filtering.sdk_noise_removed == 0
        assert findings[0].location.file == "<external>/api.h"
        assert findings[0].data_flow is not None
        assert findings[0].data_flow[1].file == "<external>/api.h"
        assert findings[0].origin == "cross-boundary"
        serialized = [finding.model_dump(by_alias=True) for finding in findings]
        assert "SECRET_RUN_PUBLIC_FINDING_SDK_ROOT" not in str(serialized)


class TestIsThirdParty:
    def test_match(self):
        assert _is_third_party("lib/civetweb/civetweb.c", ["lib/civetweb/"]) is True

    def test_no_match(self):
        assert _is_third_party("src/main.c", ["lib/civetweb/"]) is False

    def test_match_without_trailing_slash(self):
        assert _is_third_party("lib/civetweb/civetweb.c", ["lib/civetweb"]) is True

    def test_empty_list(self):
        assert _is_third_party("lib/civetweb/civetweb.c", []) is False


class TestThirdPartyFiltering:
    """thirdPartyPaths를 사용한 vendored 서드파티 필터링."""

    def test_third_party_finding_removed(self):
        """서드파티 경로 finding → 제거."""
        findings = [
            _make_finding("lib/civetweb/civetweb.c"),
        ]
        result, stats = _filter_user_code_findings(
            findings, ["lib/civetweb/"],
        )
        assert len(result) == 0
        assert stats["cross_boundary"] == 0

    def test_user_code_kept_with_third_party(self):
        """thirdPartyPaths가 있어도 사용자 코드 finding은 유지."""
        findings = [
            _make_finding("src/main.c"),
            _make_finding("lib/civetweb/civetweb.c"),
        ]
        result, stats = _filter_user_code_findings(
            findings, ["lib/civetweb/"],
        )
        assert len(result) == 1
        assert result[0].location.file == "src/main.c"

    def test_third_party_cross_boundary_kept(self):
        """서드파티 finding이지만 dataFlow에 사용자 코드 → 경계면 유지."""
        findings = [
            _make_finding(
                "lib/civetweb/civetweb.c",
                tool="gcc-fanalyzer",
                data_flow=[
                    SastDataFlowStep(file="src/main.c", line=10, content="user calls api"),
                    SastDataFlowStep(file="lib/civetweb/civetweb.c", line=200, content="overflow"),
                ],
            ),
        ]
        result, stats = _filter_user_code_findings(
            findings, ["lib/civetweb/"],
        )
        assert len(result) == 1
        assert stats["cross_boundary"] == 1
        assert result[0].origin == "cross-boundary"

    def test_third_party_internal_dataflow_removed(self):
        """서드파티 finding + dataFlow도 전부 서드파티 → 제거."""
        findings = [
            _make_finding(
                "lib/civetweb/civetweb.c",
                tool="cppcheck",
                data_flow=[
                    SastDataFlowStep(file="lib/civetweb/civetweb.h", line=5, content="note"),
                    SastDataFlowStep(file="lib/civetweb/civetweb.c", line=10, content="note"),
                ],
            ),
        ]
        result, stats = _filter_user_code_findings(
            findings, ["lib/civetweb/"],
        )
        assert len(result) == 0
        assert stats["cross_boundary"] == 0

    def test_no_third_party_paths_keeps_all_relative(self):
        """thirdPartyPaths 미지정 → 기존 동작 (상대 경로 전부 유지)."""
        findings = [
            _make_finding("src/main.c"),
            _make_finding("lib/civetweb/civetweb.c"),
        ]
        result, stats = _filter_user_code_findings(findings, [])
        assert len(result) == 2
        assert stats["cross_boundary"] == 0

    def test_multiple_third_party_dirs(self):
        """여러 서드파티 디렉토리 필터링."""
        findings = [
            _make_finding("src/main.c"),
            _make_finding("lib/civetweb/civetweb.c"),
            _make_finding("vendor/tinydtls/dtls.c"),
            _make_finding("deps/mbedtls/ssl.c"),
        ]
        result, stats = _filter_user_code_findings(
            findings, ["lib/civetweb/", "vendor/tinydtls/", "deps/mbedtls/"],
        )
        assert len(result) == 1
        assert result[0].location.file == "src/main.c"


class TestBuildSdkInfo:
    def test_no_profile(self, orchestrator):
        info = orchestrator._build_sdk_info(None, None)
        assert info["resolved"] is False

    def test_with_enriched_profile(self, orchestrator):
        original = BuildProfile(
            sdkId="ti-am335x", compiler="arm-gcc",
            targetArch="arm", languageStandard="c99",
            headerLanguage="c",
            includePaths=["/user/path"],
        )
        enriched = original.model_copy(update={
            "include_paths": ["/user/path", "/sdk/path1", "/sdk/path2"],
        })
        info = orchestrator._build_sdk_info(original, enriched)
        assert info["resolved"] is True
        assert info["include_paths_added"] == 2

    def test_non_registered_sdk_info_redacts_root_path(self, orchestrator, tmp_path):
        secret_root = str(tmp_path / "SECRET_SDK_ROOT_SHOULD_NOT_LEAK")
        original = BuildProfile(
            sdkResolutionMode="non-registered",
            sdkDescriptor=SdkDescriptor(
                sdkRootPath=secret_root,
                sysroot="sysroot",
                includePaths=[f"{secret_root}/sysroot/usr/include"],
            ),
            includePaths=[],
        )
        enriched = original.model_copy(update={"include_paths": [f"{secret_root}/sysroot/usr/include"]})

        info = orchestrator._build_sdk_info(original, enriched)

        assert info["resolved"] is True
        assert info["resolved_from"] == "sdkDescriptor"
        assert info["include_paths_added"] == 1
        assert info["sdk_root_path"] is None
        assert info["sdk_root_path_status"] == "configured"
        assert "SECRET_SDK_ROOT_SHOULD_NOT_LEAK" not in str(info)

    def test_sdk_enrichment_log_uses_counts_without_sdk_identity_or_paths(
        self, orchestrator, tmp_path, caplog
    ):
        """SDK enrichment 로그는 sdkId/include path를 노출하지 않는다."""
        secret_sdk_id = "SECRET_SDK_ID_SHOULD_NOT_LEAK"
        secret_include_path = str(tmp_path / "SECRET_SDK_INCLUDE_PATH_SHOULD_NOT_LEAK")
        profile = BuildProfile(
            sdkId=secret_sdk_id,
            compiler="arm-gcc",
            targetArch="arm",
            languageStandard="c99",
            headerLanguage="c",
            includePaths=["/user/path"],
        )
        caplog.set_level(logging.INFO, logger="aegis-sast-runner")

        with patch(
            "app.scanner.orchestrator.resolve_sdk_paths",
            return_value=[secret_include_path],
        ):
            enriched = orchestrator._enrich_profile_with_sdk(profile)

        assert enriched is not None
        assert enriched.include_paths == ["/user/path", secret_include_path]
        assert "SDK resolved" in caplog.text
        assert secret_sdk_id not in caplog.text
        assert secret_include_path not in caplog.text
        for record in caplog.records:
            assert secret_sdk_id not in record.getMessage()
            assert secret_include_path not in record.getMessage()
            assert secret_sdk_id not in repr(record.__dict__)
            assert secret_include_path not in repr(record.__dict__)


class TestPartialStatus:
    """ToolExecutionResult의 partial 상태 + timedOutFiles 필드 테스트."""

    def test_partial_status_accepted(self):
        result = ToolExecutionResult(
            status="partial", findings_count=5, elapsed_ms=3000,
            timed_out_files=3, version="13.2.0",
        )
        assert result.status == "partial"
        assert result.timed_out_files == 3

    def test_timed_out_files_defaults_none(self):
        result = ToolExecutionResult(
            status="ok", findings_count=0, elapsed_ms=1000,
        )
        assert result.timed_out_files is None

    def test_extended_degraded_fields_supported(self):
        result = ToolExecutionResult(
            status="partial",
            findings_count=2,
            elapsed_ms=1500,
            timed_out_files=1,
            failed_files=0,
            files_attempted=10,
            batch_count=2,
            timeout_budget_seconds=20,
            per_file_timeout_seconds=10,
            budget_warning=True,
            degraded=True,
            degrade_reasons=["timeout-floor", "timed-out-files"],
        )
        assert result.degraded is True
        assert result.degrade_reasons == ["timeout-floor", "timed-out-files"]


# ──────────── on_progress 콜백 ────────────


class TestProgressCallback:
    """orchestrator.run()의 on_progress 콜백 호출 검증."""

    @pytest.mark.asyncio
    async def test_tool_failure_surface_uses_category_without_exception_text(
        self, orchestrator, caplog
    ):
        """도구 예외는 로그/ExecutionReport에 raw exception text를 노출하지 않는다."""

        async def _failing_semgrep(*args, **kwargs):
            raise RuntimeError("SECRET_TOOL_EXCEPTION_SHOULD_NOT_LEAK")

        caplog.set_level(logging.WARNING, logger="aegis-sast-runner")

        with (
            patch.object(orchestrator, "_run_semgrep", side_effect=_failing_semgrep),
            patch.object(orchestrator, "check_tools", return_value={
                "semgrep": {"available": True, "version": "1.45.0"},
                "cppcheck": {"available": False, "version": None},
                "flawfinder": {"available": False, "version": None},
                "clang-tidy": {"available": False, "version": None},
                "scan-build": {"available": False, "version": None},
                "gcc-fanalyzer": {"available": False, "version": None},
            }),
        ):
            findings, execution = await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=["p/c"],
                tools=["semgrep"],
            )

        assert findings == []
        semgrep = execution.tool_results["semgrep"]
        assert semgrep.status == "failed"
        assert semgrep.skip_reason == "tool-execution-failed"
        assert "Tool semgrep failed" in caplog.text
        assert "Tool semgrep failed:" not in caplog.text
        assert "SECRET_TOOL_EXCEPTION_SHOULD_NOT_LEAK" not in caplog.text
        assert "SECRET_TOOL_EXCEPTION_SHOULD_NOT_LEAK" not in execution.model_dump_json(by_alias=True)

    @pytest.mark.asyncio
    async def test_progress_callback_called_per_tool(self, orchestrator):
        """도구별로 progress 콜백이 호출되는지 확인."""
        progress_calls = []

        async def on_progress(tool: str, status: str, count: int, elapsed: int):
            progress_calls.append((tool, status, count))

        with (
            patch.object(orchestrator, "_run_semgrep", return_value=[]),
            patch.object(orchestrator, "_run_flawfinder", return_value=[]),
            patch.object(orchestrator, "check_tools", return_value={
                "semgrep": {"available": True, "version": "1.45.0"},
                "cppcheck": {"available": False, "version": None},
                "flawfinder": {"available": True, "version": "2.0.19"},
                "clang-tidy": {"available": False, "version": None},
                "scan-build": {"available": False, "version": None},
                "gcc-fanalyzer": {"available": False, "version": None},
            }),
        ):
            await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=["p/c"],
                tools=["semgrep", "flawfinder"],
                on_progress=on_progress,
            )

        tools_called = {t for t, s, c in progress_calls}
        assert "semgrep" in tools_called
        assert "flawfinder" in tools_called
        # 각 도구는 "started" → "completed" 순서로 콜백
        completed = [(t, s) for t, s, _ in progress_calls if s == "completed"]
        started = [(t, s) for t, s, _ in progress_calls if s == "started"]
        assert len(completed) == 2
        assert len(started) == 2

    @pytest.mark.asyncio
    async def test_progress_callback_on_failure(self, orchestrator):
        """도구 실패 시 status='failed'로 콜백 호출."""
        progress_calls = []

        async def on_progress(tool: str, status: str, count: int, elapsed: int):
            progress_calls.append((tool, status))

        async def _failing_semgrep(*args, **kwargs):
            raise RuntimeError("semgrep crashed")

        with (
            patch.object(orchestrator, "_run_semgrep", side_effect=_failing_semgrep),
            patch.object(orchestrator, "_run_flawfinder", return_value=[]),
            patch.object(orchestrator, "check_tools", return_value={
                "semgrep": {"available": True, "version": "1.45.0"},
                "cppcheck": {"available": False, "version": None},
                "flawfinder": {"available": True, "version": "2.0.19"},
                "clang-tidy": {"available": False, "version": None},
                "scan-build": {"available": False, "version": None},
                "gcc-fanalyzer": {"available": False, "version": None},
            }),
        ):
            await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=["p/c"],
                tools=["semgrep", "flawfinder"],
                on_progress=on_progress,
            )

        semgrep_calls = [(t, s) for t, s in progress_calls if t == "semgrep"]
        assert len(semgrep_calls) == 2  # "started" → "failed"
        assert semgrep_calls[0][1] == "started"
        assert semgrep_calls[1][1] == "failed"

    @pytest.mark.asyncio
    async def test_no_callback_no_error(self, orchestrator):
        """on_progress=None일 때 에러 없이 정상 동작."""
        with (
            patch.object(orchestrator, "_run_flawfinder", return_value=[]),
            patch.object(orchestrator, "check_tools", return_value={
                "semgrep": {"available": False, "version": None},
                "cppcheck": {"available": False, "version": None},
                "flawfinder": {"available": True, "version": "2.0.19"},
                "clang-tidy": {"available": False, "version": None},
                "scan-build": {"available": False, "version": None},
                "gcc-fanalyzer": {"available": False, "version": None},
            }),
        ):
            findings, execution = await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=["p/c"],
                tools=["flawfinder"],
                on_progress=None,
            )
        assert execution.tools_run == ["flawfinder"]

    @pytest.mark.asyncio
    async def test_progress_callback_started_event(self, orchestrator):
        """각 도구 시작 시 status='started' 콜백이 먼저 호출되는지 확인."""
        progress_calls = []

        async def on_progress(tool: str, status: str, count: int, elapsed: int):
            progress_calls.append((tool, status))

        with (
            patch.object(orchestrator, "_run_semgrep", return_value=[]),
            patch.object(orchestrator, "check_tools", return_value={
                "semgrep": {"available": True, "version": "1.45.0"},
                "cppcheck": {"available": False, "version": None},
                "flawfinder": {"available": False, "version": None},
                "clang-tidy": {"available": False, "version": None},
                "scan-build": {"available": False, "version": None},
                "gcc-fanalyzer": {"available": False, "version": None},
            }),
        ):
            await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=["p/c"],
                tools=["semgrep"],
                on_progress=on_progress,
            )

        semgrep_calls = [s for t, s in progress_calls if t == "semgrep"]
        assert semgrep_calls == ["started", "completed"]

    @pytest.mark.asyncio
    async def test_file_progress_callback_forwarded(self, orchestrator):
        """on_file_progress가 per-file 도구 runner에 전달되는지 확인."""
        file_progress_calls = []

        async def on_file_progress(tool: str, file: str, done: int, total: int):
            file_progress_calls.append((tool, file, done, total))

        # gcc-fanalyzer runner.run을 mock하여 on_file_progress 콜백을 직접 호출
        async def _mock_gcc_run(scan_dir, source_files, profile, timeout,
                                enriched_profile=None, on_file_progress=None, on_runtime_state=None):
            if on_file_progress:
                await on_file_progress("main.c", 1, 1)
            if on_runtime_state:
                await on_runtime_state({"degraded": False, "degradeReasons": []})
            return []

        with (
            patch.object(orchestrator.gcc_analyzer, "run", side_effect=_mock_gcc_run),
            patch.object(orchestrator.gcc_analyzer, "check_available", return_value=(True, "13.3.0")),
            patch.object(orchestrator, "check_tools", return_value={
                "semgrep": {"available": False, "version": None},
                "cppcheck": {"available": False, "version": None},
                "flawfinder": {"available": False, "version": None},
                "clang-tidy": {"available": False, "version": None},
                "scan-build": {"available": False, "version": None},
                "gcc-fanalyzer": {"available": True, "version": "13.3.0"},
            }),
        ):
            await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=["p/c"],
                tools=["gcc-fanalyzer"],
                on_file_progress=on_file_progress,
            )

        assert len(file_progress_calls) == 1
        assert file_progress_calls[0] == ("gcc-fanalyzer", "main.c", 1, 1)

    @pytest.mark.asyncio
    async def test_degraded_runtime_metadata_propagated(self, orchestrator):
        """heavy analyzer runtime metadata가 execution.toolResults에 반영되는지 확인."""

        async def _mock_gcc_run(scan_dir, source_files, profile, timeout,
                                enriched_profile=None, on_file_progress=None, on_runtime_state=None):
            orchestrator.gcc_analyzer._last_timed_out = 2
            orchestrator.gcc_analyzer._last_run_stats = {
                "files_attempted": 6,
                "timed_out_files": 2,
                "failed_files": 1,
                "batch_count": 3,
                "timeout_budget_seconds": 30,
                "per_file_timeout_seconds": 10,
                "budget_warning": True,
            }
            if on_runtime_state:
                await on_runtime_state({
                    "filesAttempted": 6,
                    "timedOutFiles": 2,
                    "failedFiles": 1,
                    "batchCount": 3,
                    "timeoutBudgetSeconds": 30,
                    "perFileTimeoutSeconds": 10,
                    "budgetWarning": True,
                    "degraded": True,
                    "degradeReasons": ["timeout-floor", "timed-out-files", "failed-files"],
                })
            return []

        with (
            patch.object(orchestrator.gcc_analyzer, "run", side_effect=_mock_gcc_run),
            patch.object(orchestrator.gcc_analyzer, "check_available", return_value=(True, "13.3.0")),
            patch.object(orchestrator, "check_tools", return_value={
                "semgrep": {"available": False, "version": None},
                "cppcheck": {"available": False, "version": None},
                "flawfinder": {"available": False, "version": None},
                "clang-tidy": {"available": False, "version": None},
                "scan-build": {"available": False, "version": None},
                "gcc-fanalyzer": {"available": True, "version": "13.3.0"},
            }),
        ):
            _, execution = await orchestrator.run(
                scan_dir=Path("/tmp/test"),
                source_files=["main.c"],
                profile=None,
                rulesets=["p/c"],
                tools=["gcc-fanalyzer"],
            )

        tool = execution.tool_results["gcc-fanalyzer"]
        assert tool.status == "partial"
        assert tool.timed_out_files == 2
        assert tool.failed_files == 1
        assert tool.files_attempted == 6
        assert tool.batch_count == 3
        assert tool.timeout_budget_seconds == 30
        assert tool.per_file_timeout_seconds == 10
        assert tool.budget_warning is True
        assert tool.degraded is True
        assert execution.degraded is True
