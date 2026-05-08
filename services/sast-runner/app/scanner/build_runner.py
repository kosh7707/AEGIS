"""빌드 자동 실행 — caller가 제공한 명령을 그대로 실행하고 compile_commands.json을 생성한다."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis-sast-runner")

_SHARED_LIBRARY_ERROR_RE = re.compile(
    r"error while loading shared libraries?: (?P<lib>[^\s:]+): cannot open shared object file",
    re.IGNORECASE,
)


class BuildRunner:
    """caller가 완전히 materialize한 build command를 실행한다."""

    _BUILD_FILES: list[tuple[str, str]] = [
        ("CMakeLists.txt", "cmake"),
        ("Makefile", "make"),
        ("meson.build", "meson"),
        ("configure", "autotools"),
    ]

    def discover_targets(self, project_path: Path) -> list[dict[str, str]]:
        """프로젝트 내 빌드 타겟(독립 빌드 단위)을 자동 탐색.

        이 endpoint는 identity-hint surface만 유지한다. build command는 더 이상 추론/제안하지 않는다.
        """
        skip_dirs = {".git", "build", "node_modules", ".venv", "__pycache__", "test", "tests", "examples"}

        raw_targets: list[dict[str, str]] = []
        for build_file, build_system in self._BUILD_FILES:
            for found in project_path.rglob(build_file):
                rel = found.relative_to(project_path)
                if any(part in skip_dirs for part in rel.parts[:-1]):
                    continue
                target_dir = found.parent
                rel_dir = str(target_dir.relative_to(project_path))
                if rel_dir == ".":
                    rel_dir = ""
                raw_targets.append(
                    {
                        "name": target_dir.name if rel_dir else project_path.name,
                        "relativePath": rel_dir + "/" if rel_dir else "",
                        "buildSystem": build_system,
                        "buildFile": str(rel),
                    },
                )

        raw_targets.sort(key=lambda t: t["relativePath"])
        accepted: list[dict[str, str]] = []
        accepted_paths: list[str] = []

        for target in raw_targets:
            path = target["relativePath"]
            is_nested = any(
                path.startswith(parent) and path != parent
                for parent in accepted_paths
                if parent
            )
            if not is_nested:
                accepted.append(target)
                accepted_paths.append(path)

        logger.info(
            "Discovered %d build targets in %s (scanned %d candidates)",
            len(accepted), project_path, len(raw_targets),
        )
        return accepted

    async def build(
        self,
        project_path: Path,
        build_command: str,
        timeout: int | None = 300,
        environment: dict[str, str] | None = None,
        wrap_with_bear: bool = True,
        on_runtime_state=None,
        timeout_seconds_for_evidence: int | None = None,
        timeout_mode: str | None = None,
        timeout_enforced: bool | None = None,
    ) -> dict[str, Any]:
        """caller가 제공한 build command를 그대로 실행하고 compile_commands.json을 생성한다."""
        import time

        t0 = time.perf_counter()
        cc_path = project_path / "compile_commands.json"
        effective_command = build_command
        exec_env = os.environ.copy()
        if environment:
            exec_env.update(environment)

        if wrap_with_bear:
            cmd = ["bear", "--", "bash", "-c", effective_command]
        else:
            cmd = ["bash", "-c", effective_command]
            logger.info("Bear wrapping disabled — raw build execution")

        logger.info(
            "Build started: %s in %s",
            build_command, project_path,
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(project_path),
            env=exec_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _emit_runtime_state(
            *,
            local_ack_state: str,
            last_ack_source: str,
            blocked_reason: str | None = None,
        ) -> None:
            if on_runtime_state:
                await on_runtime_state(
                    {
                        "localAckState": local_ack_state,
                        "lastAckSource": last_ack_source,
                        "blockedReason": blocked_reason,
                        "degraded": False,
                        "degradeReasons": [],
                    },
                )

        timeout_seconds = timeout_seconds_for_evidence if timeout_seconds_for_evidence is not None else (timeout or 0)
        resolved_timeout_mode = timeout_mode or ("sync-hard-deadline" if timeout is not None else "async-ownership-no-caller-deadline")
        resolved_timeout_enforced = timeout_enforced if timeout_enforced is not None else (timeout is not None)

        communicate_task: asyncio.Task[tuple[bytes, bytes]] | None = None
        try:
            heartbeat_interval = max(min(timeout, 5), 1) if timeout is not None else 5
            communicate_task = asyncio.create_task(proc.communicate())
            deadline = time.perf_counter() + timeout if timeout is not None else None
            await _emit_runtime_state(
                local_ack_state="transport-only",
                last_ack_source="build-subprocess-alive",
            )
            while True:
                wait_timeout = heartbeat_interval
                if deadline is not None:
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    wait_timeout = min(heartbeat_interval, remaining)
                try:
                    stdout, stderr = await asyncio.wait_for(
                        asyncio.shield(communicate_task),
                        timeout=wait_timeout,
                    )
                    break
                except asyncio.TimeoutError:
                    if communicate_task.done():
                        stdout, stderr = communicate_task.result()
                        break
                    await _emit_runtime_state(
                        local_ack_state="transport-only",
                        last_ack_source="build-subprocess-alive",
                    )
        except asyncio.TimeoutError:
            kill_result = proc.kill()
            if asyncio.iscoroutine(kill_result):
                await kill_result
            if communicate_task is not None:
                try:
                    await communicate_task
                except asyncio.TimeoutError:
                    await proc.communicate()
            elapsed = int((time.perf_counter() - t0) * 1000)
            readiness = self._build_readiness(
                compile_commands_path=None,
                entry_count=None,
                user_entry_count=None,
                exit_code=None,
            )
            return {
                "success": False,
                "buildEvidence": self._build_evidence(
                    project_path=project_path,
                    requested_command=build_command,
                    effective_command=effective_command,
                    compile_commands_path=None,
                    entries=None,
                    user_entries=None,
                    exit_code=None,
                    build_output=None,
                    wrap_with_bear=wrap_with_bear,
                    timeout=timeout_seconds,
                    environment=environment,
                    elapsed_ms=elapsed,
                    timeout_mode=resolved_timeout_mode,
                    timeout_enforced=resolved_timeout_enforced,
                ),
                "readiness": readiness,
                "failureDetail": self._failure_detail(
                    category="timeout",
                    summary=f"Build timed out after {timeout_seconds}s.",
                    matched_excerpt=None,
                    hint="Provide a valid build command and increase timeout only when the caller intentionally expects a long-running build.",
                    retryable=True,
                ),
            }
        await _emit_runtime_state(
            local_ack_state="phase-advancing",
            last_ack_source="build-phase-complete",
        )

        elapsed = int((time.perf_counter() - t0) * 1000)
        build_output = stdout.decode() + stderr.decode()
        base_evidence = self._build_evidence(
            project_path=project_path,
            requested_command=build_command,
            effective_command=effective_command,
            compile_commands_path=str(cc_path) if cc_path.exists() else None,
            entries=None,
            user_entries=None,
            exit_code=proc.returncode,
            build_output=build_output[-1000:],
            wrap_with_bear=wrap_with_bear,
            timeout=timeout_seconds,
            environment=environment,
            elapsed_ms=elapsed,
            timeout_mode=resolved_timeout_mode,
            timeout_enforced=resolved_timeout_enforced,
        )
        entry_count: int | None = None
        user_entry_count: int | None = None

        if not cc_path.exists():
            return {
                "success": False,
                "buildEvidence": base_evidence,
                "readiness": self._build_readiness(
                    compile_commands_path=None,
                    entry_count=None,
                    user_entry_count=None,
                    exit_code=proc.returncode,
                ),
                "failureDetail": self._diagnose_failure(
                    build_output=build_output,
                    exit_code=proc.returncode,
                    default_category="compile-commands-missing",
                    default_summary="bear did not generate compile_commands.json.",
                    default_hint="Caller must provide a build command that actually invokes the compiler under bear.",
                ),
            }

        try:
            entries = json.loads(cc_path.read_text())
            entry_count = len(entries)
        except json.JSONDecodeError:
            entry_count = 0

        if entry_count == 0:
            return {
                "success": False,
                "buildEvidence": self._build_evidence(
                    project_path=project_path,
                    requested_command=build_command,
                    effective_command=effective_command,
                    compile_commands_path=str(cc_path),
                    entries=entry_count,
                    user_entries=0,
                    exit_code=proc.returncode,
                    build_output=build_output[-1000:],
                    wrap_with_bear=wrap_with_bear,
                    timeout=timeout_seconds,
                    environment=environment,
                    elapsed_ms=elapsed,
                    timeout_mode=resolved_timeout_mode,
                    timeout_enforced=resolved_timeout_enforced,
                ),
                "readiness": self._build_readiness(
                    compile_commands_path=str(cc_path),
                    entry_count=entry_count,
                    user_entry_count=0,
                    exit_code=proc.returncode,
                ),
                "failureDetail": self._diagnose_failure(
                    build_output=build_output,
                    exit_code=proc.returncode,
                    default_category="compile-commands-empty",
                    default_summary="compile_commands.json is empty — build may have failed.",
                    default_hint="Caller must provide a build command that produces real compiler invocations under bear.",
                ),
            }

        user_entries = [e for e in entries if "CMakeFiles" not in e.get("file", "")]
        user_entry_count = len(user_entries)
        build_failed = proc.returncode != 0
        readiness = self._build_readiness(
            compile_commands_path=str(cc_path),
            entry_count=entry_count,
            user_entry_count=user_entry_count,
            exit_code=proc.returncode,
        )

        if user_entry_count == 0:
            logger.warning(
                "Build produced compile_commands without user entries (%d total entries, exit=%d, %dms)",
                entry_count, proc.returncode, elapsed,
            )
            return {
                "success": False,
                "buildEvidence": self._build_evidence(
                    project_path=project_path,
                    requested_command=build_command,
                    effective_command=effective_command,
                    compile_commands_path=str(cc_path),
                    entries=entry_count,
                    user_entries=user_entry_count,
                    exit_code=proc.returncode,
                    build_output=build_output[-1000:],
                    wrap_with_bear=wrap_with_bear,
                    timeout=timeout_seconds,
                    environment=environment,
                    elapsed_ms=elapsed,
                    timeout_mode=resolved_timeout_mode,
                    timeout_enforced=resolved_timeout_enforced,
                ),
                "readiness": readiness,
                "failureDetail": self._diagnose_failure(
                    build_output=build_output,
                    exit_code=proc.returncode,
                    default_category="compile-commands-no-user-entries",
                    default_summary="compile_commands.json does not contain any user source entries (for example, only CMake temporary entries).",
                    default_hint="Caller must provide a build command that materializes real user-target compiler invocations under bear.",
                ),
            }

        if build_failed and user_entry_count > 0:
            reason = f"build exited with code {proc.returncode}"
            logger.warning(
                "Build failed (partial compile_commands available): %s (%d total entries, %d user entries, %dms)",
                reason, entry_count, user_entry_count, elapsed,
            )
            return {
                "success": False,
                "buildEvidence": self._build_evidence(
                    project_path=project_path,
                    requested_command=build_command,
                    effective_command=effective_command,
                    compile_commands_path=str(cc_path),
                    entries=entry_count,
                    user_entries=user_entry_count,
                    exit_code=proc.returncode,
                    build_output=build_output[-1000:],
                    wrap_with_bear=wrap_with_bear,
                    timeout=timeout_seconds,
                    environment=environment,
                    elapsed_ms=elapsed,
                    timeout_mode=resolved_timeout_mode,
                    timeout_enforced=resolved_timeout_enforced,
                ),
                "readiness": readiness,
                "failureDetail": self._diagnose_failure(
                    build_output=build_output,
                    exit_code=proc.returncode,
                    default_category="build-process",
                    default_summary=reason,
                    default_hint=f"Partial compile_commands are available ({user_entry_count} user entries), but S4 will not compensate for caller-side build mistakes.",
                ),
            }

        logger.info(
            "Build completed: %d entries (%d user), exit=%d, %dms",
            entry_count, user_entry_count, proc.returncode, elapsed,
        )
        return {
            "success": True,
            "buildEvidence": self._build_evidence(
                project_path=project_path,
                requested_command=build_command,
                effective_command=effective_command,
                compile_commands_path=str(cc_path),
                entries=entry_count,
                user_entries=user_entry_count,
                exit_code=proc.returncode,
                build_output=build_output[-500:],
                wrap_with_bear=wrap_with_bear,
                timeout=timeout_seconds,
                environment=environment,
                elapsed_ms=elapsed,
                timeout_mode=resolved_timeout_mode,
                timeout_enforced=resolved_timeout_enforced,
            ),
            "readiness": readiness,
            "failureDetail": None,
        }

    def _build_evidence(
        self,
        *,
        project_path: Path,
        requested_command: str,
        effective_command: str,
        compile_commands_path: str | None,
        entries: int | None,
        user_entries: int | None,
        exit_code: int | None,
        build_output: str | None,
        wrap_with_bear: bool,
        timeout: int,
        environment: dict[str, str] | None,
        elapsed_ms: int,
        timeout_mode: str | None = None,
        timeout_enforced: bool | None = None,
    ) -> dict[str, Any]:
        return {
            "requestedBuildCommand": requested_command,
            "effectiveBuildCommand": effective_command,
            "buildDir": str(project_path),
            "compileCommandsPath": compile_commands_path,
            "entries": entries,
            "userEntries": user_entries,
            "exitCode": exit_code,
            "buildOutput": build_output,
            "wrapWithBear": wrap_with_bear,
            "timeoutSeconds": timeout,
            "timeoutMode": timeout_mode,
            "timeoutEnforced": timeout_enforced,
            "environmentKeys": sorted(environment.keys()) if environment else None,
            "elapsedMs": elapsed_ms,
        }

    def _diagnose_failure(
        self,
        *,
        build_output: str,
        exit_code: int | None,
        default_category: str,
        default_summary: str,
        default_hint: str,
    ) -> dict[str, Any]:
        lines = [line.strip() for line in build_output.splitlines() if line.strip()]
        excerpt = lines[-1] if lines else None

        lib_match = _SHARED_LIBRARY_ERROR_RE.search(build_output)
        if lib_match:
            return self._failure_detail(
                category="shared-library-load",
                summary="The supplied build environment could not load a required shared library.",
                matched_excerpt=lib_match.group(0),
                hint="Caller must provide a valid runtime/library environment for the build command.",
                retryable=False,
            )

        if exit_code == 127:
            return self._failure_detail(
                category="command-not-found",
                summary="The supplied build command referenced an unavailable executable or script (exit code 127).",
                matched_excerpt=excerpt,
                hint="Caller must provide a valid build command and executable paths.",
                retryable=False,
            )

        return self._failure_detail(
            category=default_category,
            summary=default_summary,
            matched_excerpt=excerpt,
            hint=default_hint,
            retryable=default_category == "timeout",
        )

    def _failure_detail(
        self,
        *,
        category: str,
        summary: str,
        matched_excerpt: str | None,
        hint: str,
        retryable: bool,
    ) -> dict[str, Any]:
        return {
            "category": category,
            "summary": summary,
            "matchedExcerpt": matched_excerpt,
            "hint": hint,
            "retryable": retryable,
        }

    def _build_readiness(
        self,
        *,
        compile_commands_path: str | None,
        entry_count: int | None,
        user_entry_count: int | None,
        exit_code: int | None,
    ) -> dict[str, Any]:
        if compile_commands_path and (user_entry_count or 0) > 0 and exit_code == 0:
            return {
                "status": "ready",
                "compileCommandsReady": True,
                "quickEligible": True,
                "summary": "compile_commands.json contains user-target entries and the build exited successfully.",
            }

        if compile_commands_path and (user_entry_count or 0) > 0:
            return {
                "status": "partial",
                "compileCommandsReady": False,
                "quickEligible": False,
                "summary": "compile_commands.json contains some user-target entries, but the build did not finish successfully.",
            }

        if compile_commands_path and entry_count == 0:
            return {
                "status": "not-ready",
                "compileCommandsReady": False,
                "quickEligible": False,
                "summary": "compile_commands.json exists but is empty.",
            }

        if compile_commands_path:
            return {
                "status": "not-ready",
                "compileCommandsReady": False,
                "quickEligible": False,
                "summary": "compile_commands.json exists but does not contain any user-target entries.",
            }

        return {
            "status": "not-ready",
            "compileCommandsReady": False,
            "quickEligible": False,
            "summary": "A usable compile_commands.json could not be confirmed.",
        }
