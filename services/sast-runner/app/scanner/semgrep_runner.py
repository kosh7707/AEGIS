"""Semgrep CLI 실행기."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from app.errors import ScanTimeoutError, SemgrepNotAvailableError, ToolOutputInvalidError
from app.scanner.tool_probe import probe_command, service_toolchain_executable

logger = logging.getLogger("aegis-sast-runner")


class SemgrepRunner:
    """Semgrep CLI를 asyncio subprocess로 실행한다."""

    def _semgrep_executable(self) -> str:
        """Return S4's canonical Semgrep executable, falling back to PATH only if absent."""
        executable = service_toolchain_executable("semgrep")
        return str(executable) if executable else "semgrep"

    async def check_available(self) -> tuple[bool, str | None]:
        """Semgrep 바이너리 가용 여부와 버전을 반환."""
        expected_executable = service_toolchain_executable("semgrep")
        probe = await probe_command(
            [str(expected_executable) if expected_executable else "semgrep", "--version"],
            version_parser=lambda output: output.strip(),
            expected_executable_path=expected_executable,
        )
        self._last_probe = probe
        return bool(probe["available"]), probe["version"] if isinstance(probe["version"], str) else None

    async def run(
        self,
        scan_dir: Path,
        rulesets: list[str],
        timeout: int = 120,
        include_extensions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Semgrep을 실행하고 SARIF JSON을 반환한다.

        Args:
            include_extensions: 파일 확장자 필터 (예: [".c", ".h"]).
                지정하면 --include 플래그로 해당 확장자만 스캔.

        Raises:
            SemgrepNotAvailableError: semgrep이 없을 때.
            ScanTimeoutError: 타임아웃 초과 시.
        """
        available, _ = await self.check_available()
        if not available:
            raise SemgrepNotAvailableError("Semgrep binary not found in PATH")

        cmd = self._build_command(scan_dir, rulesets, include_extensions)
        logger.info("Running Semgrep: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise ScanTimeoutError(
                f"Semgrep scan exceeded {timeout}s timeout"
            )

        # Semgrep은 findings가 있으면 exit code 1을 반환할 수 있다.
        # SARIF 출력이 있으면 성공으로 간주.
        raw = stdout.decode()
        if not raw.strip():
            # stderr에 에러가 있을 수 있음
            err_msg = stderr.decode().strip()
            if err_msg:
                logger.warning("Semgrep stderr: %s", err_msg)
            # 빈 결과를 SARIF 형태로 반환
            return {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # JSON이 아닌 출력 (에러 메시지 등)
            err_msg = stderr.decode().strip()
            logger.error("Semgrep non-JSON output: %s, stderr: %s", raw[:500], err_msg)
            raise ToolOutputInvalidError("Semgrep produced non-JSON SARIF output")

    def _build_command(
        self,
        scan_dir: Path,
        rulesets: list[str],
        include_extensions: list[str] | None = None,
    ) -> list[str]:
        """Semgrep CLI 명령 조립."""
        from app.config import settings

        cmd = [self._semgrep_executable(), "scan"]

        for ruleset in rulesets:
            cmd.extend(["--config", ruleset])

        # 커스텀 룰 디렉토리 추가
        if settings.custom_rules_dir:
            rules_path = Path(settings.custom_rules_dir)
            if not rules_path.is_absolute():
                rules_path = Path(__file__).resolve().parent.parent.parent / rules_path
            if rules_path.is_dir():
                cmd.extend(["--config", str(rules_path)])

        cmd.extend([
            "--sarif",              # SARIF JSON 출력
            "--timeout", str(settings.semgrep_per_rule_timeout),
            "--max-target-bytes", str(settings.semgrep_max_target_bytes),
            "--no-git-ignore",      # temp dir에는 .gitignore 없음
            "--metrics", "off",     # 텔레메트리 비활성화
        ])

        # 파일 확장자 필터 (C++ 프로젝트에서 C 파일만 스캔)
        if include_extensions:
            for ext in include_extensions:
                cmd.extend(["--include", f"*{ext}"])

        cmd.append(str(scan_dir))

        return cmd
