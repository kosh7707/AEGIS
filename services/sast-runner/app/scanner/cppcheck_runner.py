"""Cppcheck CLI 실행기."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from app.errors import ScanTimeoutError
from app.scanner.path_utils import normalize_path
from app.scanner.tool_probe import probe_command, service_toolchain_executable
from app.schemas.request import BuildProfile
from app.schemas.response import SastDataFlowStep, SastFinding, SastFindingLocation

logger = logging.getLogger("aegis-sast-runner")

# Cppcheck severity → SastFinding severity
_SEVERITY_MAP = {
    "error": "error",
    "warning": "warning",
    "style": "style",
    "performance": "performance",
    "portability": "portability",
    "information": "info",
}


class CppcheckRunner:
    """Cppcheck을 asyncio subprocess로 실행한다."""

    async def check_available(self) -> tuple[bool, str | None]:
        probe = await probe_command(
            ["cppcheck", "--version"],
            version_parser=lambda output: output.strip().replace("Cppcheck ", ""),
            expected_executable_path=service_toolchain_executable("cppcheck"),
        )
        self._last_probe = probe
        return bool(probe["available"]), probe["version"] if isinstance(probe["version"], str) else None

    async def run(
        self,
        scan_dir: Path,
        profile: BuildProfile | None,
        timeout: int = 120,
        compile_commands: str | None = None,
    ) -> list[SastFinding]:
        cmd = self._build_command(scan_dir, profile, compile_commands)
        logger.info(
            "Running Cppcheck",
            extra={
                "profileProvided": profile is not None,
                "compileCommandsProvided": bool(compile_commands),
            },
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            # Cppcheck은 결과를 stderr에 XML로 출력
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise ScanTimeoutError(f"Cppcheck scan exceeded {timeout}s timeout")

        xml_output = stderr.decode()
        if not xml_output.strip():
            return []

        return self._parse_xml(xml_output, scan_dir)

    def _build_command(
        self,
        scan_dir: Path,
        profile: BuildProfile | None,
        compile_commands: str | None = None,
    ) -> list[str]:
        cmd = [
            "cppcheck",
            "--enable=all",
            "--check-level=exhaustive",
            "--xml",
            "--quiet",
            "--suppress=missingIncludeSystem",
            "--suppress=missingInclude",
        ]

        # compile_commands.json이 있으면 --project로 사용 (BuildProfile보다 우선)
        if compile_commands:
            cc_path = Path(compile_commands)
            if not cc_path.is_absolute():
                cc_path = scan_dir / compile_commands
            if cc_path.exists():
                cmd.append(f"--project={cc_path}")
                return cmd

        if profile:
            # languageStandard → --std
            std = (profile.language_standard or "").lower()
            if std and (std.startswith("c++") or std.startswith("gnu++")):
                cmd.append(f"--std={std}")
            elif std.startswith("c") or std.startswith("gnu"):
                cmd.append(f"--std={std}")

            # includePaths → -I (상대 경로는 scan_dir 기준으로 변환)
            # 주의: orchestrator가 original profile(SDK 미병합)을 전달하므로
            #       여기에는 사용자가 명시한 경로만 들어온다.
            if profile.include_paths:
                for inc in profile.include_paths:
                    inc_path = Path(inc)
                    if not inc_path.is_absolute():
                        inc_path = scan_dir / inc
                    cmd.extend(["-I", str(inc_path)])

            # defines → -D
            if profile.defines:
                for key, val in profile.defines.items():
                    if val:
                        cmd.append(f"-D{key}={val}")
                    else:
                        cmd.append(f"-D{key}")
        else:
            from app.config import settings
            cmd.append(f"--std={settings.default_language_standard}")

        cmd.append(str(scan_dir))
        return cmd

    def _parse_xml(
        self,
        xml_str: str,
        base_dir: Path,
    ) -> list[SastFinding]:
        """Cppcheck XML → SastFinding[]."""
        findings: list[SastFinding] = []

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            logger.warning("Failed to parse Cppcheck XML output")
            return []

        for error in root.iter("error"):
            error_id = error.get("id", "")
            if error_id in ("missingInclude", "missingIncludeSystem", "checkersReport"):
                continue

            severity = _SEVERITY_MAP.get(error.get("severity", ""), "info")
            message = error.get("msg", "")
            verbose = error.get("verbose", "")
            cwe = error.get("cwe")

            # location 추출
            locations = list(error.iter("location"))
            if not locations:
                continue

            primary = locations[0]
            file_path = primary.get("file", "")
            line = int(primary.get("line", "0"))

            if not file_path or line == 0:
                continue

            file_path = normalize_path(file_path, base_dir)

            location = SastFindingLocation(
                file=file_path,
                line=line,
                column=int(primary.get("column", "0")) or None,
            )

            # 추가 위치가 있으면 data flow로
            data_flow: list[SastDataFlowStep] | None = None
            if len(locations) > 1:
                data_flow = []
                for loc in locations:
                    df_file = normalize_path(loc.get("file", ""), base_dir)
                    df_line = int(loc.get("line", "0"))
                    info = loc.get("info", "")
                    if df_file and df_line:
                        data_flow.append(SastDataFlowStep(
                            file=df_file,
                            line=df_line,
                            content=info if info else None,
                        ))

            metadata: dict[str, Any] = {"cppcheckId": error_id}
            if cwe:
                metadata["cwe"] = [f"CWE-{cwe}"]
                metadata["cweId"] = f"CWE-{cwe}"
            if verbose and verbose != message:
                metadata["verbose"] = verbose

            findings.append(SastFinding(
                toolId="cppcheck",
                ruleId=f"cppcheck:{error_id}",
                severity=severity,
                message=message,
                location=location,
                dataFlow=data_flow,
                metadata=metadata,
            ))

        return findings
