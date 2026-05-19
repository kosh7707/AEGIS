from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import CaseStage, PaperCaseCreateRequest, StageProgress


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class CaseArtifacts:
    def __init__(self, root: Path):
        self.root = root
        self.audit_packets = root / "audit-packets"
        self.finding_packets = self.audit_packets / "findings"
        self.case_packets = self.audit_packets / "case-level"
        self.replay = root / "replay"

    @classmethod
    def from_request(cls, request: PaperCaseCreateRequest) -> "CaseArtifacts":
        return cls(Path(request.paperRunRoot) / "cases" / request.caseId)

    def ensure(self) -> None:
        for path in [self.root, self.audit_packets, self.finding_packets, self.case_packets, self.replay, self.root / "logs"]:
            path.mkdir(parents=True, exist_ok=True)

    def write_json(self, relative: str, data: Any) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        return path

    def append_jsonl(self, relative: str, data: Any) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(data, sort_keys=True, ensure_ascii=False) + "\n")
        return path

    def write_jsonl(self, relative: str, rows: Iterable[Any]) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        return path

    def list_files(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*") if p.is_file())


def write_initial_case(artifacts: CaseArtifacts, request: PaperCaseCreateRequest) -> None:
    artifacts.ensure()
    manifest = request.model_dump(mode="json")
    manifest["caseRoot"] = str(artifacts.root)
    manifest["createdAt"] = now_iso()
    artifacts.write_json("case-manifest.json", manifest)
    artifacts.write_json("replay/s3-paper-request.json", request.model_dump(mode="json"))
    artifacts.append_jsonl(
        "state-trace.jsonl",
        {
            "timestamp": now_iso(),
            "stage": CaseStage.CASE_REGISTERED.value,
            "status": StageProgress.DONE.value,
            "message": "case registered",
        },
    )


def trace_stage(
    artifacts: CaseArtifacts,
    stage: CaseStage,
    status: StageProgress,
    *,
    message: str | None = None,
    artifactRef: str | None = None,
    diagnostic: str | None = None,
) -> None:
    row: dict[str, Any] = {
        "timestamp": now_iso(),
        "stage": stage.value,
        "status": status.value,
    }
    if message:
        row["message"] = message
    if artifactRef:
        row["artifactRef"] = artifactRef
    if diagnostic:
        row["diagnostic"] = diagnostic
    artifacts.append_jsonl("state-trace.jsonl", row)


def read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text())


def read_jsonl(path: str | Path) -> list[Any]:
    rows = []
    for line in Path(path).read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows
