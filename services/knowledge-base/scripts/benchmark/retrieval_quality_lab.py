#!/usr/bin/env python3
"""Write the S5 Retrieval Quality Lab report."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.evaluation.retrieval_quality_lab import (  # noqa: E402
    DEFAULT_RETRIEVAL_QUALITY_LAB_PATH,
    write_retrieval_quality_report,
)


def _default_output() -> Path:
    return Path(__file__).resolve().parents[4] / ".omx" / "reports" / "s5-retrieval-quality-lab-20260511.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_RETRIEVAL_QUALITY_LAB_PATH))
    parser.add_argument("--output", default=str(_default_output()))
    args = parser.parse_args()
    report = write_retrieval_quality_report(args.output, args.manifest)
    status = report["systemStability"]["status"]
    print(f"wrote {args.output} status={status} cases={report['systemStability']['caseCount']}")
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
