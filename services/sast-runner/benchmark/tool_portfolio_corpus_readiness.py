from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from benchmark.tool_portfolio_acquisition_manifest import build_acquisition_index
from benchmark.tool_portfolio_experiment_manifest import validate_corpus_manifest

CORPUS_READINESS_GATE_SCHEMA_VERSION = "s4-tool-portfolio-corpus-readiness-gate-v1"


def build_corpus_readiness_gate(
    *,
    acquisition_manifests: Sequence[Mapping[str, Any]],
    corpus_manifest: Mapping[str, Any],
    required_corpora: Sequence[str],
    base_path: Path | str | None = None,
) -> dict[str, Any]:
    """Build a deterministic local corpus-readiness gate for offline experiments.

    This gate is intentionally filesystem-local and offline. It validates that
    decision-grade required corpora are declared, present on disk, and that each
    referenced external case source file matches the pinned case checksum before
    S4 treats validation/test evidence as decision-grade.
    """

    base = Path(base_path).resolve() if base_path is not None else None
    acquisition_index = build_acquisition_index(acquisition_manifests)
    corpus_report = validate_corpus_manifest(corpus_manifest, acquisition_index=acquisition_index)
    cases = [
        dict(case)
        for case in corpus_manifest.get("cases", [])
        if isinstance(case, Mapping)
    ]

    acquisition_statuses: dict[str, dict[str, Any]] = {}
    case_statuses: list[dict[str, Any]] = []
    external_status: dict[str, dict[str, Any]] = {}
    gate_reasons: set[str] = set()

    for corpus_id in sorted(str(item) for item in required_corpora):
        corpus_name = _external_corpus_name(corpus_id)
        acquisition_record = acquisition_index.get(corpus_id)
        corpus_cases = sorted(
            [case for case in cases if case.get("acquisitionId") == corpus_id],
            key=lambda case: (str(case.get("caseId") or ""), str(case.get("sourcePath") or "")),
        )

        if acquisition_record is None:
            reason = _missing_corpus_reason(corpus_id)
            gate_reasons.add(reason)
            acquisition_statuses[corpus_id] = {
                "status": "blocked",
                "acquisitionId": corpus_id,
                "corpusName": corpus_name,
                "reasonCodes": [reason],
                "caseCount": 0,
            }
            external_status[corpus_name] = {"status": "blocked", "reasonCodes": [reason]}
            continue

        manifest = acquisition_record["manifest"]
        root_result = _resolve_local_path(manifest.get("localPath"), base)
        root = root_result.get("path")
        acquisition_reasons = list(root_result["reasonCodes"])

        if not corpus_cases:
            acquisition_reasons.append("CORPUS_REQUIRED_CASES_NOT_DECLARED")

        if root is None or not root.exists() or not root.is_dir():
            if "LOCAL_CORPUS_PATH_NOT_FOUND" not in acquisition_reasons:
                acquisition_reasons.append("LOCAL_CORPUS_PATH_NOT_FOUND")
            acquisition_reasons.append(_missing_corpus_reason(corpus_id))
            acquisition_statuses[corpus_id] = {
                "status": "blocked",
                "acquisitionId": corpus_id,
                "corpusName": corpus_name,
                "localPath": str(manifest.get("localPath")),
                "resolvedLocalPath": str(root) if root is not None else None,
                "reasonCodes": _sorted_unique(acquisition_reasons),
                "caseCount": len(corpus_cases),
            }
            gate_reasons.update(acquisition_statuses[corpus_id]["reasonCodes"])
            external_status[corpus_name] = {
                "status": "blocked",
                "reasonCodes": _external_reason_codes(corpus_id, acquisition_statuses[corpus_id]["reasonCodes"]),
            }
            continue

        for case in corpus_cases:
            status = _check_case_source(case, root)
            case_statuses.append(status)

        failing_case_reasons = [
            reason
            for status in case_statuses
            if status.get("acquisitionId") == corpus_id and status.get("status") != "available"
            for reason in status.get("reasonCodes", [])
        ]
        split_counts = Counter(str(case.get("split")) for case in corpus_cases)
        if split_counts.get("validation", 0) == 0 or split_counts.get("test", 0) == 0:
            failing_case_reasons.append("CORPUS_REQUIRED_SPLITS_MISSING")

        acquisition_reasons.extend(failing_case_reasons)
        acquisition_statuses[corpus_id] = {
            "status": "blocked" if acquisition_reasons else "available",
            "acquisitionId": corpus_id,
            "corpusName": corpus_name,
            "localPath": str(manifest.get("localPath")),
            "resolvedLocalPath": str(root),
            "manifestChecksum": acquisition_record.get("manifestChecksum"),
            "reasonCodes": _sorted_unique(acquisition_reasons),
            "caseCount": len(corpus_cases),
            "splitCounts": dict(sorted(split_counts.items())),
        }
        gate_reasons.update(acquisition_statuses[corpus_id]["reasonCodes"])
        if acquisition_statuses[corpus_id]["status"] == "available":
            external_status[corpus_name] = {"status": "available", "reasonCodes": []}
        else:
            external_status[corpus_name] = {
                "status": "blocked",
                "reasonCodes": _external_reason_codes(corpus_id, acquisition_statuses[corpus_id]["reasonCodes"]),
            }

    case_statuses.sort(key=lambda item: (str(item.get("acquisitionId") or ""), str(item.get("caseId") or ""), str(item.get("sourcePath") or "")))
    status = "available" if not gate_reasons else "blocked"
    return {
        "schemaVersion": CORPUS_READINESS_GATE_SCHEMA_VERSION,
        "status": status,
        "decisionGradeReady": status == "available",
        "requiredCorpora": sorted(str(item) for item in required_corpora),
        "reasonCodes": sorted(gate_reasons),
        "acquisitionStatuses": acquisition_statuses,
        "caseStatuses": case_statuses,
        "externalCorpusStatus": external_status,
        "summary": {
            "caseCount": corpus_report["caseCount"],
            "checkedCaseCount": len(case_statuses),
            "splitCounts": corpus_report["splitCounts"],
            "sliceCounts": corpus_report["sliceCounts"],
        },
        "consumerPolicy": "local_filesystem_readiness_only_not_quality_or_security_verdict",
    }


def default_not_run_corpus_readiness_gate() -> dict[str, Any]:
    return {
        "schemaVersion": CORPUS_READINESS_GATE_SCHEMA_VERSION,
        "status": "not_run",
        "decisionGradeReady": False,
        "requiredCorpora": [],
        "reasonCodes": ["CORPUS_READINESS_GATE_NOT_RUN"],
        "acquisitionStatuses": {},
        "caseStatuses": [],
        "externalCorpusStatus": {},
        "summary": {"checkedCaseCount": 0},
        "consumerPolicy": "no_decision_grade_corpus_readiness_claim",
    }


def external_corpus_status_from_readiness(readiness_gate: Mapping[str, Any]) -> dict[str, Any]:
    status = readiness_gate.get("externalCorpusStatus")
    if isinstance(status, Mapping):
        return {str(key): dict(value) for key, value in status.items() if isinstance(value, Mapping)}
    return {}


def _check_case_source(case: Mapping[str, Any], root: Path) -> dict[str, Any]:
    case_id = str(case.get("caseId") or "")
    source_path = str(case.get("sourcePath") or "")
    acquisition_id = str(case.get("acquisitionId") or "")
    expected_checksum = str(case.get("checksum") or "")
    unsafe = _unsafe_source_path(source_path)
    if unsafe:
        return {
            "status": "blocked",
            "acquisitionId": acquisition_id,
            "caseId": case_id,
            "sourcePath": source_path,
            "reasonCodes": ["CORPUS_CASE_SOURCE_PATH_UNSAFE"],
        }
    path = (root / source_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return {
            "status": "blocked",
            "acquisitionId": acquisition_id,
            "caseId": case_id,
            "sourcePath": source_path,
            "reasonCodes": ["CORPUS_CASE_SOURCE_PATH_UNSAFE"],
        }
    if not path.is_file():
        return {
            "status": "blocked",
            "acquisitionId": acquisition_id,
            "caseId": case_id,
            "sourcePath": source_path,
            "resolvedPath": str(path),
            "reasonCodes": ["CORPUS_CASE_SOURCE_MISSING"],
        }
    actual_checksum = _file_checksum(path)
    if actual_checksum != expected_checksum:
        return {
            "status": "blocked",
            "acquisitionId": acquisition_id,
            "caseId": case_id,
            "sourcePath": source_path,
            "resolvedPath": str(path),
            "expectedChecksum": expected_checksum,
            "actualChecksum": actual_checksum,
            "reasonCodes": ["CORPUS_CASE_CHECKSUM_MISMATCH"],
        }
    return {
        "status": "available",
        "acquisitionId": acquisition_id,
        "caseId": case_id,
        "sourcePath": source_path,
        "resolvedPath": str(path),
        "checksum": actual_checksum,
        "reasonCodes": [],
    }


def _resolve_local_path(local_path: Any, base_path: Path | None) -> dict[str, Any]:
    if not isinstance(local_path, str) or not local_path.strip():
        return {"path": None, "reasonCodes": ["LOCAL_CORPUS_PATH_NOT_FOUND"]}
    path = Path(local_path)
    if path.is_absolute():
        return {"path": path.resolve(), "reasonCodes": []}
    if base_path is None:
        return {"path": None, "reasonCodes": ["LOCAL_CORPUS_BASE_PATH_REQUIRED"]}
    return {"path": (base_path / path).resolve(), "reasonCodes": []}


def _unsafe_source_path(source_path: str) -> bool:
    path = Path(source_path)
    return path.is_absolute() or any(part == ".." for part in path.parts)


def _file_checksum(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _external_corpus_name(corpus_id: str) -> str:
    lowered = corpus_id.lower()
    if "juliet" in lowered:
        return "juliet"
    if "sard" in lowered:
        return "sard"
    return corpus_id


def _missing_corpus_reason(corpus_id: str) -> str:
    name = _external_corpus_name(corpus_id).upper().replace("-", "_")
    return f"LOCAL_{name}_CORPUS_NOT_PRESENT"


def _external_reason_codes(corpus_id: str, reason_codes: Sequence[str]) -> list[str]:
    reasons = set(reason_codes)
    if reason_codes and not any(str(reason).startswith("LOCAL_") and str(reason).endswith("_CORPUS_NOT_PRESENT") for reason in reasons):
        reasons.add(f"LOCAL_{_external_corpus_name(corpus_id).upper().replace('-', '_')}_CORPUS_INCOMPLETE")
    return sorted(str(reason) for reason in reasons)


def _sorted_unique(values: Sequence[Any]) -> list[str]:
    return sorted({str(value) for value in values if value})
