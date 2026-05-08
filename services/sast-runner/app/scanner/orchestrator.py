"""멀티 도구 오케스트레이터 — 6개 SAST 도구를 병렬 실행하고 결과를 합산."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

# Progress 콜백 타입: (tool_name, status, findings_count, elapsed_ms) -> None
ProgressCallback = Callable[[str, str, int, int], Awaitable[None]]
# File progress 콜백 타입: (tool_name, current_file, files_done, files_total) -> None
FileProgressCallback = Callable[[str, str, int, int], Awaitable[None]]
# Runtime 상태 콜백 타입: (tool_name, state_dict) -> None
RuntimeStateCallback = Callable[[str, dict[str, Any]], Awaitable[None]]

from app.scanner.clangtidy_runner import ClangTidyRunner
from app.scanner.cppcheck_runner import CppcheckRunner
from app.scanner.flawfinder_runner import FlawfinderRunner
from app.scanner.gcc_analyzer_runner import GccAnalyzerRunner
from app.scanner.ruleset_selector import detect_language_family, semgrep_include_extensions
from app.scanner.sarif_parser import parse_sarif
from app.scanner.scanbuild_runner import ScanbuildRunner
from app.scanner.sdk_resolver import get_sdk_compiler, resolve_sdk_paths
from app.scanner.semgrep_runner import SemgrepRunner
from app.schemas.request import BuildProfile
from app.schemas.response import (
    ExecutionReport,
    FindingsFilterInfo,
    SastFinding,
    SdkResolutionInfo,
    ToolExecutionResult,
)

logger = logging.getLogger("aegis-sast-runner")

ALL_TOOLS = ["semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"]
ALLOWED_SKIP_REASONS = ("operator-requested-subset", "profile-not-applicable")

# 최소 권장 버전 — 미만 시 경고 (차단하지 않음)
MIN_VERSIONS: dict[str, tuple[int, ...]] = {
    "semgrep": (1, 40),
    "cppcheck": (2, 13),
    "flawfinder": (2, 0, 19),
    "clang-tidy": (16,),
    "scan-build": (16,),
    "gcc-fanalyzer": (13,),
}


def _parse_version(ver_str: str | None) -> tuple[int, ...] | None:
    """버전 문자열에서 숫자 튜플 추출. '2.13.0' → (2, 13, 0)."""
    if not ver_str:
        return None
    parts = []
    for p in ver_str.split("."):
        digits = "".join(c for c in p if c.isdigit())
        if digits:
            parts.append(int(digits))
    return tuple(parts) if parts else None


_TOOL_CACHE_TTL = 300  # 도구 가용성 캐시 유효 시간 (초)


class ScanOrchestrator:
    """6개 SAST 도구를 병렬로 실행하고 결과를 합산한다."""

    def __init__(self) -> None:
        self.semgrep = SemgrepRunner()
        self.cppcheck = CppcheckRunner()
        self.flawfinder = FlawfinderRunner()
        self.clangtidy = ClangTidyRunner()
        self.scanbuild = ScanbuildRunner()
        self.gcc_analyzer = GccAnalyzerRunner()
        self._tool_cache: dict[str, dict] | None = None
        self._tool_cache_time: float = 0.0

    async def check_tools(self, *, force: bool = False) -> dict[str, dict]:
        """모든 도구의 가용 여부를 확인. 결과를 TTL 동안 캐시."""
        now = time.perf_counter()
        if not force and self._tool_cache and (now - self._tool_cache_time) < _TOOL_CACHE_TTL:
            return self._tool_cache

        results = await asyncio.gather(
            self.semgrep.check_available(),
            self.cppcheck.check_available(),
            self.flawfinder.check_available(),
            self.clangtidy.check_available(),
            self.scanbuild.check_available(),
            self.gcc_analyzer.check_available(),
        )

        names = ["semgrep", "cppcheck", "flawfinder", "clang-tidy", "scan-build", "gcc-fanalyzer"]
        runners = [
            self.semgrep,
            self.cppcheck,
            self.flawfinder,
            self.clangtidy,
            self.scanbuild,
            self.gcc_analyzer,
        ]
        tool_info: dict[str, dict[str, Any]] = {}
        for name, (avail, ver), runner in zip(names, results, runners):
            probe = getattr(runner, "_last_probe", None) or {}
            tool_info[name] = {
                "available": avail,
                "version": ver,
                "probeReason": probe.get("probeReason"),
                "expectedExecutablePath": probe.get("expectedExecutablePath"),
            }

        # 최소 버전 경고
        for name, info in tool_info.items():
            if not info["available"]:
                continue
            min_ver = MIN_VERSIONS.get(name)
            if not min_ver:
                continue
            parsed = _parse_version(info["version"])
            if parsed and parsed < min_ver:
                min_str = ".".join(str(v) for v in min_ver)
                logger.warning(
                    "Tool %s version %s is below minimum recommended %s",
                    name, info["version"], min_str,
                )

        self._tool_cache = tool_info
        self._tool_cache_time = now
        return tool_info

    def build_health_policy(self, available_tools: dict[str, dict]) -> dict[str, Any]:
        unavailable_tools = sorted(
            name for name, info in available_tools.items()
            if not info.get("available", False)
        )
        policy_reasons = sorted(
            {
                info.get("probeReason")
                for info in available_tools.values()
                if not info.get("available", False) and info.get("probeReason")
            },
        )
        return {
            "policyStatus": "degraded" if unavailable_tools else "ok",
            "policyReasons": policy_reasons,
            "unavailableTools": unavailable_tools,
            "allowedSkipReasons": list(ALLOWED_SKIP_REASONS),
        }

    def evaluate_policy(self, execution: ExecutionReport) -> dict[str, Any] | None:
        disallowed_tools: list[str] = []
        policy_reasons: list[str] = []
        for tool_name, result in execution.tool_results.items():
            reason = result.skip_reason
            if result.status == "skipped" and reason and reason not in ALLOWED_SKIP_REASONS:
                disallowed_tools.append(tool_name)
                if reason not in policy_reasons:
                    policy_reasons.append(reason)

        if not disallowed_tools:
            return None

        code = (
            "DISALLOWED_TOOL_ENVIRONMENT_DRIFT"
            if "environment-drift" in policy_reasons
            else "DISALLOWED_TOOL_OMISSION"
        )
        msg = (
            "Disallowed tool omission: "
            + ", ".join(f"{tool}({execution.tool_results[tool].skip_reason})" for tool in disallowed_tools)
        )
        return {
            "code": code,
            "message": msg,
            "omittedTools": disallowed_tools,
            "policyReasons": policy_reasons,
        }

    async def run(
        self,
        scan_dir: Path,
        source_files: list[str],
        profile: BuildProfile | None,
        rulesets: list[str],
        compile_commands: str | None = None,
        tools: list[str] | None = None,
        timeout: int = 120,
        third_party_paths: list[str] | None = None,
        on_progress: ProgressCallback | None = None,
        on_file_progress: FileProgressCallback | None = None,
        on_runtime_state: RuntimeStateCallback | None = None,
    ) -> tuple[list[SastFinding], ExecutionReport]:
        """도구들을 병렬 실행하고 합산된 findings + 실행 보고서를 반환.

        Returns:
            (findings, execution_report)
        """
        # 1. 도구 자동 선택
        available_tools = await self.check_tools(force=True)
        active_tools = await self._select_tools(
            tools, profile, available_tools,
        )

        # 2. SDK 경로 해석
        enriched_profile = self._enrich_profile_with_sdk(profile)
        sdk_info = self._build_sdk_info(profile, enriched_profile)

        # 3. scope-early: 서드파티 파일을 도구 실행 전에 제외 (OOM 방지)
        tp_paths = third_party_paths or []
        if tp_paths:
            scoped_files = _scope_user_files(source_files, tp_paths)
            files_scoped_out = len(source_files) - len(scoped_files)
            if files_scoped_out > 0:
                logger.info(
                    "Scope-early: %d third-party files excluded from heavy analyzers",
                    files_scoped_out,
                )
        else:
            scoped_files = source_files
            files_scoped_out = 0

        # 4. 도구별 태스크 생성
        # - clang-tidy, scan-build, gcc-fanalyzer: scoped_files (서드파티 제외)
        # - cppcheck: original profile, scan_dir 전체
        # - semgrep, flawfinder: scan_dir 전체 (텍스트/패턴 기반)
        task_map = {}
        if "semgrep" in active_tools:
            task_map["semgrep"] = self._run_semgrep(scan_dir, rulesets, timeout, profile)
        if "cppcheck" in active_tools:
            task_map["cppcheck"] = self._run_cppcheck(scan_dir, profile, timeout, compile_commands)
        if "flawfinder" in active_tools:
            task_map["flawfinder"] = self._run_flawfinder(scan_dir, timeout)
        if "clang-tidy" in active_tools:
            task_map["clang-tidy"] = self._run_clangtidy(
                scan_dir, scoped_files, enriched_profile, timeout, compile_commands,
            )
        if "scan-build" in active_tools:
            task_map["scan-build"] = self._run_scanbuild(
                scan_dir, scoped_files, enriched_profile, timeout,
                on_file_progress=on_file_progress,
                on_runtime_state=on_runtime_state,
            )
        if "gcc-fanalyzer" in active_tools:
            task_map["gcc-fanalyzer"] = self._run_gcc_analyzer(
                scan_dir, scoped_files, profile, enriched_profile, timeout,
                on_file_progress=on_file_progress,
                on_runtime_state=on_runtime_state,
            )

        # 5. 병렬 실행 (per-tool timing wrapper + progress callback)
        async def _timed(tool_name: str, coro):
            if on_progress:
                await on_progress(tool_name, "started", 0, 0)
            t = time.perf_counter()
            try:
                r = await coro
                elapsed = int((time.perf_counter() - t) * 1000)
                count = len(r) if isinstance(r, list) else 0
                if on_progress:
                    await on_progress(tool_name, "completed", count, elapsed)
                return r, elapsed
            except Exception as exc:
                elapsed = int((time.perf_counter() - t) * 1000)
                if on_progress:
                    await on_progress(tool_name, "failed", 0, elapsed)
                raise

        results = await asyncio.gather(
            *[_timed(name, coro) for name, coro in task_map.items()],
            return_exceptions=True,
        )

        # 결과 수집
        all_findings: list[SastFinding] = []
        tool_results: dict[str, ToolExecutionResult] = {}

        tool_versions = {
            name: info.get("version")
            for name, info in available_tools.items()
        }

        for tool_name, result in zip(task_map.keys(), results):
            if isinstance(result, Exception):
                logger.warning("Tool %s failed: %s", tool_name, str(result))
                tool_results[tool_name] = ToolExecutionResult(
                    status="failed", findings_count=0, elapsed_ms=0,
                    skip_reason=str(result), version=tool_versions.get(tool_name),
                )
            else:
                findings_list, elapsed = result
                all_findings.extend(findings_list)
                tool_results[tool_name] = ToolExecutionResult(
                    status="ok", findings_count=len(findings_list), elapsed_ms=elapsed,
                    version=tool_versions.get(tool_name),
                )
                logger.info("Tool %s completed: %d findings in %dms", tool_name, len(findings_list), elapsed)

            if tool_name in ("scan-build", "gcc-fanalyzer"):
                runner = self.scanbuild if tool_name == "scan-build" else self.gcc_analyzer
                runner_stats = getattr(runner, "_last_run_stats", None)
                if runner_stats:
                    degrade_reasons = []
                    if runner_stats.get("budget_warning"):
                        degrade_reasons.append("timeout-floor")
                    if runner_stats.get("timed_out_files", 0) > 0:
                        degrade_reasons.append("timed-out-files")
                    if runner_stats.get("failed_files", 0) > 0:
                        degrade_reasons.append("failed-files")
                    tool_results[tool_name] = tool_results[tool_name].model_copy(
                        update={
                            "failed_files": runner_stats.get("failed_files"),
                            "files_attempted": runner_stats.get("files_attempted"),
                            "batch_count": runner_stats.get("batch_count"),
                            "timeout_budget_seconds": runner_stats.get("timeout_budget_seconds"),
                            "per_file_timeout_seconds": runner_stats.get("per_file_timeout_seconds"),
                            "budget_warning": runner_stats.get("budget_warning"),
                            "degraded": bool(degrade_reasons),
                            "degrade_reasons": degrade_reasons or None,
                        },
                    )

        # partial 상태: 파일별 실행 도구 중 timeout 발생 시
        for tool_name in ("scan-build", "gcc-fanalyzer"):
            if tool_name in tool_results and tool_results[tool_name].status == "ok":
                runner = self.scanbuild if tool_name == "scan-build" else self.gcc_analyzer
                timed_out = getattr(runner, "_last_timed_out", 0)
                if timed_out > 0:
                    tool_results[tool_name] = tool_results[tool_name].model_copy(
                        update={"status": "partial", "timed_out_files": timed_out},
                    )

        # 스킵된 도구 기록
        for tool_name, reason in active_tools.get("_skipped", {}).items():
            tool_results[tool_name] = ToolExecutionResult(
                status="skipped", findings_count=0, elapsed_ms=0,
                skip_reason=reason, version=tool_versions.get(tool_name),
            )

        # 전 도구 실패 시 경고
        attempted = [n for n in task_map if n in tool_results]
        if attempted and all(tool_results[n].status == "failed" for n in attempted):
            logger.warning(
                "All %d attempted tools failed: %s",
                len(attempted), ", ".join(attempted),
            )

        # 6. 사용자 코드 + 경계면 필터링
        before = len(all_findings)
        all_findings, filter_stats = _filter_user_code_findings(
            all_findings, tp_paths,
        )
        logger.info(
            "Findings filter: sdk=%d, thirdParty=%d removed, %d cross-boundary kept (before=%d, after=%d)",
            filter_stats["sdk_removed"], filter_stats["third_party_removed"],
            filter_stats["cross_boundary"], before, len(all_findings),
        )

        # 7. 실행 보고서 조립
        execution = ExecutionReport(
            tools_run=list(task_map.keys()),
            tool_results=tool_results,
            sdk=SdkResolutionInfo(**sdk_info),
            filtering=FindingsFilterInfo(
                before_filter=before,
                after_filter=len(all_findings),
                sdk_noise_removed=filter_stats["sdk_removed"],
                third_party_removed=filter_stats["third_party_removed"],
                cross_boundary_kept=filter_stats["cross_boundary"],
                files_scoped_out=files_scoped_out,
            ),
            degraded=any(result.degraded for result in tool_results.values() if result.degraded is not None),
            degrade_reasons=sorted(
                {
                    reason
                    for result in tool_results.values()
                    for reason in (result.degrade_reasons or [])
                },
            ),
        )

        return all_findings, execution

    async def _select_tools(
        self,
        requested: list[str] | None,
        profile: BuildProfile | None,
        available: dict[str, dict],
    ) -> dict[str, Any]:
        """BuildProfile + 가용성을 보고 실행할 도구를 결정."""
        requested_set = set(requested or ALL_TOOLS)
        candidates = set(requested_set)
        active: dict[str, Any] = {"_skipped": {}}

        if requested is not None:
            for tool in ALL_TOOLS:
                if tool not in requested_set:
                    active["_skipped"][tool] = "operator-requested-subset"

        for tool in list(candidates):
            # 가용성 체크
            if not available.get(tool, {}).get("available", False):
                active["_skipped"][tool] = (
                    available.get(tool, {}).get("probeReason")
                    or "runtime-tool-missing"
                )
                candidates.discard(tool)
                continue

            # BuildProfile 기반 자동 스킵 (Semgrep은 확장자 필터로 대체)
            if tool == "gcc-fanalyzer" and profile:
                sdk_gcc = get_sdk_compiler(profile)
                if not sdk_gcc:
                    # SDK가 지정됐는데 크로스 컴파일러가 없으면 호스트 gcc 사용
                    pass  # 호스트 gcc로 폴백

        # gcc-fanalyzer: 호스트 gcc가 unavailable이지만 SDK 컴파일러가 지원할 수 있음
        if (
            "gcc-fanalyzer" in active["_skipped"]
            and active["_skipped"]["gcc-fanalyzer"] in {"runtime-tool-missing", "environment-drift", "tool-check-failed"}
            and profile
            and (profile.sdk_id or profile.sdk_resolution_mode == "non-registered")
        ):
            sdk_ok, sdk_ver = await self.gcc_analyzer.check_available(profile)
            if sdk_ok:
                del active["_skipped"]["gcc-fanalyzer"]
                candidates.add("gcc-fanalyzer")
                logger.info(
                    "gcc-fanalyzer available via SDK compiler (v%s)", sdk_ver,
                )
            else:
                probe = getattr(self.gcc_analyzer, "_last_probe", {}) or {}
                active["_skipped"]["gcc-fanalyzer"] = probe.get("probeReason") or active["_skipped"]["gcc-fanalyzer"]

        active.update({t: True for t in candidates})
        return active

    def _build_sdk_info(
        self,
        original: BuildProfile | None,
        enriched: BuildProfile | None,
    ) -> dict[str, Any]:
        """SDK 해석 정보를 dict로 반환 (SdkResolutionInfo 생성에 사용)."""
        if original is None:
            return {
                "resolved": False,
                "sdk_id": None,
                "include_paths_added": 0,
                "resolution_mode": None,
                "resolved_from": None,
                "sdk_root_path": None,
                "degrade_reasons": [],
            }

        original_paths = len(original.include_paths or [])
        enriched_paths = len(enriched.include_paths or []) if enriched else 0
        descriptor = original.sdk_descriptor
        resolution_mode = original.sdk_resolution_mode
        if resolution_mode is None:
            resolution_mode = "s4-registered" if original.sdk_id else None

        resolved_from: str | None = None
        if original.sdk_resolution_mode == "non-registered":
            resolved_from = "sdkDescriptor"
        elif original.sdk_id and enriched_paths > original_paths:
            resolved_from = "s4Registry"

        return {
            "resolved": (
                bool(descriptor)
                if original.sdk_resolution_mode == "non-registered"
                else enriched_paths > original_paths
            ),
            "sdk_id": original.sdk_id,
            "include_paths_added": enriched_paths - original_paths,
            "resolution_mode": resolution_mode,
            "resolved_from": resolved_from,
            "sdk_root_path": descriptor.sdk_root_path if descriptor else None,
            "degrade_reasons": [],
        }

    def _enrich_profile_with_sdk(
        self, profile: BuildProfile | None,
    ) -> BuildProfile | None:
        """BuildProfile에 SDK 인클루드 경로를 병합."""
        if profile is None:
            return None

        sdk_paths = resolve_sdk_paths(profile)
        if not sdk_paths:
            return profile

        existing = profile.include_paths or []
        merged = existing + [p for p in sdk_paths if p not in existing]

        logger.info(
            "SDK '%s' resolved %d include paths (total: %d)",
            profile.sdk_id, len(sdk_paths), len(merged),
        )
        return profile.model_copy(update={"include_paths": merged})

    # --- 개별 도구 실행 ---

    async def _run_semgrep(
        self, scan_dir: Path, rulesets: list[str], timeout: int,
        profile: BuildProfile | None = None,
    ) -> list[SastFinding]:
        include_exts = semgrep_include_extensions(profile)
        if include_exts:
            logger.info("Semgrep: filtering to extensions %s", include_exts)
        sarif = await self.semgrep.run(scan_dir, rulesets, timeout, include_extensions=include_exts)
        findings, _ = parse_sarif(sarif, scan_dir)
        return findings

    async def _run_cppcheck(
        self, scan_dir: Path, profile: BuildProfile | None, timeout: int,
        compile_commands: str | None = None,
    ) -> list[SastFinding]:
        return await self.cppcheck.run(scan_dir, profile, timeout, compile_commands)

    async def _run_flawfinder(
        self, scan_dir: Path, timeout: int,
    ) -> list[SastFinding]:
        return await self.flawfinder.run(scan_dir, timeout)

    async def _run_clangtidy(
        self, scan_dir: Path, source_files: list[str],
        profile: BuildProfile | None, timeout: int,
        compile_commands: str | None = None,
    ) -> list[SastFinding]:
        return await self.clangtidy.run(
            scan_dir, source_files, profile, timeout=timeout,
            compile_commands=compile_commands,
        )

    async def _run_scanbuild(
        self, scan_dir: Path, source_files: list[str],
        profile: BuildProfile | None, timeout: int,
        on_file_progress: FileProgressCallback | None = None,
        on_runtime_state: RuntimeStateCallback | None = None,
    ) -> list[SastFinding]:
        async def _file_cb(file: str, done: int, total: int):
            if on_file_progress:
                await on_file_progress("scan-build", file, done, total)
        async def _runtime_cb(state: dict[str, Any]):
            if on_runtime_state:
                await on_runtime_state("scan-build", state)
        kwargs: dict[str, Any] = {}
        if on_file_progress:
            kwargs["on_file_progress"] = _file_cb
        if on_runtime_state:
            kwargs["on_runtime_state"] = _runtime_cb
        return await self.scanbuild.run(
            scan_dir, source_files, profile, timeout,
            **kwargs,
        )

    async def _run_gcc_analyzer(
        self, scan_dir: Path, source_files: list[str],
        profile: BuildProfile | None, enriched_profile: BuildProfile | None,
        timeout: int,
        on_file_progress: FileProgressCallback | None = None,
        on_runtime_state: RuntimeStateCallback | None = None,
    ) -> list[SastFinding]:
        async def _file_cb(file: str, done: int, total: int):
            if on_file_progress:
                await on_file_progress("gcc-fanalyzer", file, done, total)
        async def _runtime_cb(state: dict[str, Any]):
            if on_runtime_state:
                await on_runtime_state("gcc-fanalyzer", state)
        kwargs: dict[str, Any] = {"enriched_profile": enriched_profile}
        if on_file_progress:
            kwargs["on_file_progress"] = _file_cb
        if on_runtime_state:
            kwargs["on_runtime_state"] = _runtime_cb
        return await self.gcc_analyzer.run(
            scan_dir, source_files, profile, timeout,
            **kwargs,
        )


def _is_user_path(path: str) -> bool:
    """상대 경로면 사용자 코드로 간주."""
    return not path.startswith("/")


def _is_third_party(path: str, third_party_paths: list[str]) -> bool:
    """경로가 서드파티 라이브러리 디렉토리에 속하는지 확인 (path segment 경계)."""
    for tp in third_party_paths:
        prefix = tp.rstrip("/") + "/"
        if path.startswith(prefix) or path == tp.rstrip("/"):
            return True
    return False


def _scope_user_files(
    source_files: list[str], third_party_paths: list[str],
) -> list[str]:
    """source_files에서 서드파티 경로 파일을 제거 (scope-early)."""
    return [f for f in source_files if not _is_third_party(f, third_party_paths)]


def _filter_user_code_findings(
    findings: list[SastFinding],
    third_party_paths: list[str],
) -> tuple[list[SastFinding], dict[str, int]]:
    """사용자 코드 findings + 경계면 findings를 남긴다.

    분류 기준 (3단계):
    1. 절대 경로 (SDK/시스템 헤더) → cross-boundary 검사 후 제거/유지
    2. thirdPartyPaths에 해당 (vendored 서드파티) → cross-boundary 검사 후 제거/유지
    3. 그 외 상대 경로 → 사용자 코드 (유지)

    Returns:
        (filtered_findings, {"sdk_removed": N, "third_party_removed": N, "cross_boundary": N})
    """
    result: list[SastFinding] = []
    sdk_removed = 0
    tp_removed = 0
    cross_boundary = 0

    for finding in findings:
        loc_file = finding.location.file

        # 1. 절대 경로 (SDK/시스템 헤더)
        if not _is_user_path(loc_file):
            if _check_cross_boundary(finding):
                finding = finding.model_copy(update={"origin": "cross-boundary"})
                result.append(finding)
                cross_boundary += 1
            else:
                sdk_removed += 1
            continue

        # 2. vendored 서드파티 라이브러리 (상대 경로지만 thirdPartyPaths에 해당)
        if third_party_paths and _is_third_party(loc_file, third_party_paths):
            if _check_cross_boundary(finding, third_party_paths):
                finding = finding.model_copy(update={"origin": "cross-boundary"})
                result.append(finding)
                cross_boundary += 1
            else:
                tp_removed += 1
            continue

        # 3. 사용자 코드 — 유지
        result.append(finding)

    return result, {
        "sdk_removed": sdk_removed,
        "third_party_removed": tp_removed,
        "cross_boundary": cross_boundary,
    }


def _check_cross_boundary(
    finding: SastFinding,
    third_party_paths: list[str] | None = None,
) -> bool:
    """finding의 dataFlow에 사용자 코드 step이 있으면 경계면으로 판정."""
    if not finding.data_flow:
        return False
    tp_paths = third_party_paths or []
    return any(
        _is_user_path(step.file) and not _is_third_party(step.file, tp_paths)
        for step in finding.data_flow
    )
