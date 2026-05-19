"""Flawfinder CLI 실행기."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from pathlib import Path
from typing import Any

from app.errors import ScanTimeoutError
from app.scanner.path_utils import normalize_path
from app.scanner.tool_probe import probe_command, service_toolchain_executable
from app.schemas.response import SastFinding, SastFindingLocation

logger = logging.getLogger("aegis-sast-runner")

# Flawfinder risk level → severity
_SEVERITY_MAP = {
    "5": "error",
    "4": "error",
    "3": "warning",
    "2": "warning",
    "1": "info",
    "0": "info",
}


class FlawfinderRunner:
    """Flawfinder를 asyncio subprocess로 실행한다."""

    async def check_available(self) -> tuple[bool, str | None]:
        probe = await probe_command(
            ["flawfinder", "--version"],
            version_parser=lambda output: output.strip(),
            expected_executable_path=service_toolchain_executable("flawfinder"),
        )
        self._last_probe = probe
        return bool(probe["available"]), probe["version"] if isinstance(probe["version"], str) else None

    async def run(
        self,
        scan_dir: Path,
        timeout: int = 120,
    ) -> list[SastFinding]:
        cmd = self._build_command(scan_dir)
        logger.info("Running Flawfinder")

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
            raise ScanTimeoutError(f"Flawfinder scan exceeded {timeout}s timeout")

        csv_output = stdout.decode()
        if not csv_output.strip():
            return []

        return self._parse_csv(csv_output, scan_dir)

    def _build_command(self, scan_dir: Path) -> list[str]:
        return [
            "flawfinder",
            "--csv",            # CSV 출력
            "--quiet",          # 헤더/푸터 제거
            "--minlevel=1",     # 최소 레벨 1부터
            str(scan_dir),
        ]

    def _parse_csv(
        self,
        csv_str: str,
        base_dir: Path,
    ) -> list[SastFinding]:
        """Flawfinder CSV → SastFinding[]."""
        findings: list[SastFinding] = []

        reader = csv.DictReader(io.StringIO(csv_str))
        for row in reader:
            file_path = _safe_cell(row.get("File"))
            line = _safe_positive_int(row.get("Line"))
            level_value = _safe_positive_int(row.get("Level")) or 1
            level = str(level_value)
            category = _safe_cell(row.get("Category"))
            name = _safe_cell(row.get("Name"))
            warning = _safe_cell(row.get("Warning"))
            context = _safe_cell(row.get("Context"))

            if not file_path or line is None:
                continue

            file_path = normalize_path(file_path, base_dir)

            severity = _SEVERITY_MAP.get(level, "info")
            column = _safe_positive_int(row.get("Column"))

            metadata: dict[str, Any] = {
                "flawfinderLevel": level_value,
                "category": category,
                "name": name,
            }
            if context:
                metadata["context"] = context.strip()

            # CWE 추출 (warning 텍스트에 CWE-XXX가 포함된 경우)
            import re
            cwe_matches = re.findall(r"CWE-\d+", warning)
            if cwe_matches:
                metadata["cwe"] = cwe_matches
                metadata["cweId"] = cwe_matches[0]

            findings.append(SastFinding(
                toolId="flawfinder",
                ruleId=f"flawfinder:{category}/{name}",
                severity=severity,
                message=warning,
                location=SastFindingLocation(
                    file=file_path,
                    line=line,
                    column=column,
                ),
                dataFlow=None,
                metadata=metadata,
            ))

        return findings


def _safe_cell(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _safe_positive_int(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed > 0 else None
