"""gcc -fanalyzer 실행기."""

from __future__ import annotations

import asyncio
import logging
import re
import threading
from pathlib import Path
from typing import Any

from app.errors import ScanTimeoutError
from app.scanner.path_utils import normalize_path
from app.scanner.sdk_resolver import get_sdk_compiler
from app.scanner.tool_probe import probe_command, service_toolchain_executable
from app.schemas.request import BuildProfile
from app.schemas.response import SastDataFlowStep, SastFinding, SastFindingLocation

logger = logging.getLogger("aegis-sast-runner")

# gcc -Wanalyzer flag → CWE 매핑
_GCC_ANALYZER_CWE_MAP: dict[str, list[str]] = {
    "-Wanalyzer-null-dereference": ["CWE-476"],
    "-Wanalyzer-possible-null-dereference": ["CWE-476"],
    "-Wanalyzer-possible-null-argument": ["CWE-476"],
    "-Wanalyzer-use-after-free": ["CWE-416"],
    "-Wanalyzer-double-free": ["CWE-415"],
    "-Wanalyzer-malloc-leak": ["CWE-401"],
    "-Wanalyzer-buffer-overflow": ["CWE-120"],
    "-Wanalyzer-out-of-bounds": ["CWE-787"],
    "-Wanalyzer-use-of-uninitialized-value": ["CWE-457"],
    "-Wanalyzer-write-to-const": ["CWE-787"],
    "-Wanalyzer-write-to-string-literal": ["CWE-787"],
    "-Wanalyzer-tainted-array-index": ["CWE-129"],
    "-Wanalyzer-tainted-allocation-size": ["CWE-190"],
    "-Wanalyzer-tainted-divisor": ["CWE-369"],
    "-Wanalyzer-fd-leak": ["CWE-775"],
    "-Wanalyzer-file-leak": ["CWE-775"],
}

# gcc 경고 패턴: file:line:col: warning: message [CWE-xxx] [-Wanalyzer-*]
# gcc 14+는 CWE를 직접 출력함: "dereference of NULL 'data' [CWE-476] [-Wanalyzer-null-dereference]"
_WARNING_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): (?P<severity>warning|error|note): (?P<message>.+?)(?:\s+\[(?P<cwe>CWE-\d+)\])?\s*(?:\[(?P<flag>-W[^\]]+)\])?$"
)


class GccAnalyzerRunner:
    """gcc -fanalyzer를 asyncio subprocess로 실행한다."""

    async def check_available(
        self, profile: BuildProfile | None = None,
    ) -> tuple[bool, str | None]:
        """gcc -fanalyzer가 사용 가능한지 확인.

        profile이 있으면 SDK 크로스 컴파일러를 먼저 확인.
        profile이 없으면 (startup check) 호스트 gcc만 확인.
        """
        gcc_bin = "gcc"
        if profile:
            sdk_gcc = get_sdk_compiler(profile)
            if sdk_gcc:
                gcc_bin = sdk_gcc

        expected_path = None
        if Path(gcc_bin).is_absolute():
            expected_path = Path(gcc_bin)
        else:
            expected_path = service_toolchain_executable(gcc_bin)

        probe = await probe_command(
            [gcc_bin, "--version"],
            version_parser=lambda output: (re.search(r"(\d+\.\d+\.\d+)", output).group(1)  # type: ignore[union-attr]
                                           if re.search(r"(\d+\.\d+\.\d+)", output)
                                           else "unknown"),
            expected_executable_path=expected_path,
        )
        self._last_probe = probe
        if probe["available"] and isinstance(probe["version"], str):
            version = probe["version"]
            major = int(version.split(".")[0]) if version != "unknown" else 0
            if major >= 10:
                return True, version
            probe["probeReason"] = "tool-check-failed"
            self._last_probe = probe
        return False, None

    async def run(
        self,
        scan_dir: Path,
        source_files: list[str],
        profile: BuildProfile | None,
        timeout: int = 120,
        enriched_profile: BuildProfile | None = None,
        on_file_progress=None,
        on_runtime_state=None,
    ) -> list[SastFinding]:
        c_cpp_files = [
            f for f in source_files
            if f.endswith((".c", ".cpp", ".cc", ".cxx"))
        ]
        if not c_cpp_files:
            return []

        gcc_bin = self._resolve_gcc(profile)
        # SDK 크로스 컴파일러 사용 시 enriched profile (SDK 헤더 포함 → 경계면 분석)
        # 호스트 gcc 폴백 시 original profile (ARM 헤더 불일치 방지)
        actual_profile = profile
        if gcc_bin != "gcc" and enriched_profile:
            actual_profile = enriched_profile
            logger.info("gcc-fanalyzer: using enriched profile (SDK compiler detected)")

        logger.info(
            "Running gcc -fanalyzer",
            extra={
                "filesCount": len(c_cpp_files),
                "customCompilerProvided": gcc_bin != "gcc",
            },
        )

        # 파일별 개별 실행 (동일 심볼 충돌 방지) + Semaphore 동시성 제한
        _concurrency = 8
        _sem = asyncio.Semaphore(_concurrency)
        _batches = -(-len(c_cpp_files) // _concurrency)  # ceil division
        per_file_timeout = max(timeout // max(_batches, 1), 10)
        budget_warning = per_file_timeout * _batches > timeout
        if budget_warning:
            logger.warning(
                "Per-file timeout floor (%ds) may exceed budget (%ds for %d batches)",
                per_file_timeout, timeout, _batches,
            )

        files_done = 0
        total_files = len(c_cpp_files)
        timed_out = 0
        failed = 0

        async def _emit_runtime_state() -> None:
            reasons = []
            if budget_warning:
                reasons.append("timeout-floor")
            if timed_out > 0:
                reasons.append("timed-out-files")
            if failed > 0:
                reasons.append("failed-files")
            if on_runtime_state:
                await on_runtime_state(
                    {
                        "filesCompleted": files_done,
                        "filesAttempted": total_files,
                        "timedOutFiles": timed_out,
                        "failedFiles": failed,
                        "batchCount": _batches,
                        "timeoutBudgetSeconds": timeout,
                        "perFileTimeoutSeconds": per_file_timeout,
                        "budgetWarning": budget_warning,
                        "degraded": bool(reasons),
                        "degradeReasons": reasons,
                    },
                )

        async def _guarded(f: str) -> list[SastFinding]:
            nonlocal files_done, timed_out, failed
            async with _sem:
                try:
                    result = await self._run_single(gcc_bin, scan_dir, f, actual_profile, per_file_timeout)
                    if result is None:
                        timed_out += 1
                    return result
                except Exception:
                    failed += 1
                    raise
                finally:
                    files_done += 1
                    if on_file_progress:
                        await on_file_progress(f, files_done, total_files)
                    await _emit_runtime_state()

        await _emit_runtime_state()

        results = await asyncio.gather(
            *[_guarded(f) for f in c_cpp_files], return_exceptions=True,
        )

        all_findings: list[SastFinding] = []
        for f, result in zip(c_cpp_files, results):
            if isinstance(result, Exception):
                logger.warning("gcc -fanalyzer failed")
            else:
                all_findings.extend(result or [])

        if timed_out > 0 or failed > 0:
            logger.info(
                "gcc -fanalyzer: %d files OK, %d timed out, %d failed",
                len(c_cpp_files) - timed_out - failed, timed_out, failed,
            )

        # orchestrator가 partial 판정에 사용할 수 있도록 메타데이터 첨부
        self._last_timed_out = timed_out
        self._last_failed = failed
        self._last_run_stats = {
            "files_attempted": total_files,
            "timed_out_files": timed_out,
            "failed_files": failed,
            "batch_count": _batches,
            "timeout_budget_seconds": timeout,
            "per_file_timeout_seconds": per_file_timeout,
            "budget_warning": budget_warning,
        }
        return all_findings

    async def _run_single(
        self,
        gcc_bin: str,
        scan_dir: Path,
        source_file: str,
        profile: BuildProfile | None,
        timeout: int,
    ) -> list[SastFinding] | None:
        """단일 파일에 대해 gcc -fanalyzer를 실행. timeout 시 None 반환."""
        target = str(scan_dir / source_file)
        cmd = self._build_command(gcc_bin, [target], profile, scan_dir)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            _, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("gcc -fanalyzer timed out (%ds)", timeout)
            return None  # sentinel: timeout

        output = stderr.decode()
        if not output.strip():
            return []

        return self._parse_output(output, scan_dir)

    def _resolve_gcc(self, profile: BuildProfile | None) -> str:
        """BuildProfile에서 SDK 크로스 컴파일러를 찾거나, 호스트 gcc를 반환.

        -fanalyzer는 GCC 10+에서만 지원. SDK 크로스컴파일러가 9.x면 호스트 gcc로 폴백.
        """
        if profile:
            sdk_gcc = get_sdk_compiler(profile)
            if sdk_gcc and self._gcc_supports_analyzer(sdk_gcc):
                return sdk_gcc
            elif sdk_gcc:
                logger.info(
                    "SDK gcc does not support -fanalyzer, falling back to host gcc",
                    extra={"sdkCompilerProvided": True},
                )
        return "gcc"

    _analyzer_support_cache: dict[str, bool] = {}
    _analyzer_cache_lock = threading.Lock()

    @classmethod
    def _gcc_supports_analyzer(cls, gcc_path: str) -> bool:
        """GCC가 -fanalyzer를 지원하는지 (10+) 확인. 결과 캐시 (thread-safe)."""
        with cls._analyzer_cache_lock:
            if gcc_path in cls._analyzer_support_cache:
                return cls._analyzer_support_cache[gcc_path]

        import subprocess
        supported = False
        try:
            result = subprocess.run(
                [gcc_path, "--version"], capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"(\d+)\.\d+\.\d+", result.stdout)
            if match:
                supported = int(match.group(1)) >= 10
        except Exception:
            pass

        with cls._analyzer_cache_lock:
            cls._analyzer_support_cache[gcc_path] = supported
        return supported

    def _build_command(
        self,
        gcc_bin: str,
        targets: list[str],
        profile: BuildProfile | None,
        scan_dir: Path,
    ) -> list[str]:
        cmd = [gcc_bin, "-fanalyzer", "-c", "-o", "/dev/null"]

        if profile:
            if profile.language_standard:
                cmd.append(f"-std={profile.language_standard.lower()}")
            if profile.include_paths:
                for inc in profile.include_paths:
                    inc_path = Path(inc)
                    if not inc_path.is_absolute():
                        inc_path = scan_dir / inc
                    cmd.extend(["-I", str(inc_path)])
            if profile.defines:
                for key, val in profile.defines.items():
                    cmd.append(f"-D{key}={val}" if val else f"-D{key}")
        else:
            from app.config import settings
            cmd.append(f"-std={settings.default_language_standard}")

        cmd.extend(targets)
        return cmd

    def _parse_output(
        self, output: str, scan_dir: Path,
    ) -> list[SastFinding]:
        """gcc stderr 출력 → SastFinding[].

        warning/error 뒤에 이어지는 note 라인을 dataFlow로 수집한다.
        경계면 분석: dataFlow에 사용자 코드와 SDK 경로가 섞이면 cross-boundary.
        """
        findings: list[SastFinding] = []
        seen: set[tuple[str, int, str]] = set()

        # 1단계: warning + note 그룹핑
        lines = output.splitlines()
        groups: list[tuple[re.Match, list[re.Match]]] = []  # (warning_match, [note_matches])

        for line in lines:
            match = _WARNING_RE.match(line)
            if not match:
                continue

            severity = match.group("severity")
            flag = match.group("flag") or ""

            # -fanalyzer 경고만 수집 (strict: flag 없는 일반 diagnostics 제외)
            if not flag.startswith("-Wanalyzer"):
                continue

            if severity in ("warning", "error"):
                groups.append((match, []))
            elif severity == "note" and groups:
                groups[-1][1].append(match)

        # 2단계: findings 조립
        for warning_match, note_matches in groups:
            file_path = normalize_path(warning_match.group("file"), scan_dir)
            line_num = int(warning_match.group("line"))
            col = int(warning_match.group("col"))
            message = warning_match.group("message")
            flag = warning_match.group("flag") or ""

            key = (file_path, line_num, message[:50])
            if key in seen:
                continue
            seen.add(key)

            rule_id = flag.replace("-W", "") if flag else "analyzer"
            metadata: dict[str, Any] = {}
            if flag:
                metadata["gccFlag"] = flag

            # CWE 추출
            gcc_cwe = warning_match.group("cwe")
            if gcc_cwe:
                metadata["cwe"] = [gcc_cwe]
                metadata["cweId"] = gcc_cwe
            elif flag:
                mapped = _GCC_ANALYZER_CWE_MAP.get(flag)
                if mapped:
                    metadata["cwe"] = mapped
                    metadata["cweId"] = mapped[0]

            # note → dataFlow
            data_flow: list[SastDataFlowStep] | None = None
            if note_matches:
                data_flow = [
                    SastDataFlowStep(
                        file=normalize_path(n.group("file"), scan_dir),
                        line=int(n.group("line")),
                        content=n.group("message"),
                    )
                    for n in note_matches
                ]

            findings.append(SastFinding(
                toolId="gcc-fanalyzer",
                ruleId=f"gcc-fanalyzer:{rule_id}",
                severity=warning_match.group("severity"),
                message=message,
                location=SastFindingLocation(
                    file=file_path, line=line_num, column=col,
                ),
                dataFlow=data_flow,
                metadata=metadata if metadata else None,
            ))

        return findings
