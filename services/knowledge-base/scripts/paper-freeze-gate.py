#!/usr/bin/env python3
"""Run the S5 paper-context freeze-gate audit suite and emit JSON."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))

from app.paper_context.freeze_gate import PASSED_CHECKS, REPORT_REF, SUITE_VERSION  # noqa: E402


def main() -> int:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests/test_paper_context_freeze_gate.py",
        "tests/test_paper_context_api_contract.py",
        "-q",
    ]
    start = time.monotonic()
    proc = subprocess.run(command, cwd=SERVICE_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    status = "pass" if proc.returncode == 0 else "fail"
    report = {
        "schemaVersion": "s5-freeze-gate-audit-wrapper-report-v1",
        "suiteVersion": SUITE_VERSION,
        "reportRef": REPORT_REF,
        "status": status,
        "scope": {
            "s5ProducerFixtureObligations": "pass" if status == "pass" else "fail",
            "s3ConsumerExecutionStatus": "pending_s3_owned_validation",
        },
        "passedChecks": PASSED_CHECKS if status == "pass" else [],
        "commandEvidence": [
            {
                "command": " ".join(command),
                "cwd": str(SERVICE_ROOT),
                "status": status,
                "exitCode": proc.returncode,
                "elapsedMs": elapsed_ms,
                "stdoutTail": "\n".join(proc.stdout.splitlines()[-40:]),
            }
        ],
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
