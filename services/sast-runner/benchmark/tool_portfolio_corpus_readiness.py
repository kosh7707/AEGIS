from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from benchmark.tool_portfolio_acquisition_manifest import build_acquisition_index
from benchmark.tool_portfolio_experiment_manifest import validate_corpus_manifest

CORPUS_READINESS_GATE_SCHEMA_VERSION = "s4-tool-portfolio-corpus-readiness-gate-v1"
CORPUS_REQUIRED_CORPUS_ID_INVALID = "CORPUS_REQUIRED_CORPUS_ID_INVALID"
REQUIRED_CORPUS_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
READINESS_STATUS_VALUES = {"available", "blocked", "not_run"}
LOCAL_PATH_STATUS_VALUES = {
    "available",
    "base_required",
    "missing",
    "not_declared",
    "not_resolved",
    "outside_base",
}
RESOLVED_LOCAL_PATH_STATUS_VALUES = {
    "available",
    "missing",
    "not_resolved",
    "outside_base",
}
CASE_RESOLVED_PATH_STATUS_VALUES = {
    "available",
    "checksum_mismatch",
    "missing",
    "outside_root",
    "unsafe",
}
SOURCE_PATH_STATUS_VALUES = {"unsafe"}


class _FixedDiagnosticArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ValueError("input validation failed")


READINESS_EXTERNAL_STATUS_KEYS = {"juliet", "sard", "external", "requiredCorpusReadiness"}
READINESS_REASON_CODE_ALLOWLIST = {
    "CORPUS_CASE_CHECKSUM_MISMATCH",
    "CORPUS_CASE_SOURCE_MISSING",
    "CORPUS_CASE_SOURCE_PATH_UNSAFE",
    "CORPUS_READINESS_GATE_INCONSISTENT",
    "CORPUS_READINESS_GATE_INPUT_INVALID",
    "CORPUS_READINESS_GATE_NOT_RUN",
    "CORPUS_READINESS_INPUT_INVALID",
    "CORPUS_READINESS_OUTPUT_WRITE_FAILED",
    "CORPUS_REQUIRED_CASES_NOT_DECLARED",
    "CORPUS_REQUIRED_CORPORA_NOT_DECLARED",
    "CORPUS_REQUIRED_CORPUS_ID_INVALID",
    "CORPUS_REQUIRED_SPLITS_MISSING",
    "LOCAL_CORPUS_BASE_PATH_REQUIRED",
    "LOCAL_CORPUS_PATH_NOT_FOUND",
    "LOCAL_CORPUS_PATH_OUTSIDE_BASE",
    "LOCAL_EXTERNAL_CORPUS_INCOMPLETE",
    "LOCAL_EXTERNAL_CORPUS_NOT_PRESENT",
    "LOCAL_JULIET_CORPUS_INCOMPLETE",
    "LOCAL_JULIET_CORPUS_NOT_PRESENT",
    "LOCAL_SARD_CORPUS_INCOMPLETE",
    "LOCAL_SARD_CORPUS_NOT_PRESENT",
}


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
    corpus_report = validate_corpus_manifest(
        corpus_manifest,
        acquisition_index=acquisition_index,
        allow_unsafe_source_path=True,
    )
    cases = [
        dict(case)
        for case in corpus_manifest.get("cases", [])
        if isinstance(case, Mapping)
    ]

    required_corpus_ids, required_corpus_id_failures = _normalize_required_corpora(required_corpora)
    acquisition_statuses: dict[str, dict[str, Any]] = {}
    case_statuses: list[dict[str, Any]] = []
    external_status: dict[str, dict[str, Any]] = {}
    gate_reasons: set[str] = set()

    if required_corpus_id_failures:
        gate_reasons.add(CORPUS_REQUIRED_CORPUS_ID_INVALID)
    elif not required_corpus_ids:
        gate_reasons.add("CORPUS_REQUIRED_CORPORA_NOT_DECLARED")

    for corpus_id in required_corpus_ids:
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
                "localPathStatus": "not_declared",
                "resolvedLocalPathStatus": "not_resolved",
                "reasonCodes": [reason],
                "caseCount": 0,
            }
            _record_external_status(external_status, corpus_name, corpus_id, "blocked", [reason])
            continue

        manifest = acquisition_record["manifest"]
        root_result = _resolve_local_path(manifest.get("localPath"), base)
        root = root_result.get("path")
        acquisition_reasons = list(root_result["reasonCodes"])

        if not corpus_cases:
            acquisition_reasons.append("CORPUS_REQUIRED_CASES_NOT_DECLARED")

        if acquisition_reasons:
            acquisition_statuses[corpus_id] = {
                "status": "blocked",
                "acquisitionId": corpus_id,
                "corpusName": corpus_name,
                **_local_path_status_fields(acquisition_reasons, root),
                "manifestChecksum": acquisition_record.get("manifestChecksum"),
                "reasonCodes": _sorted_unique(acquisition_reasons),
                "caseCount": len(corpus_cases),
            }
            gate_reasons.update(acquisition_statuses[corpus_id]["reasonCodes"])
            _record_external_status(
                external_status,
                corpus_name,
                corpus_id,
                "blocked",
                _external_reason_codes(corpus_id, acquisition_statuses[corpus_id]["reasonCodes"]),
            )
            continue

        if root is None or not root.exists() or not root.is_dir():
            if "LOCAL_CORPUS_PATH_NOT_FOUND" not in acquisition_reasons:
                acquisition_reasons.append("LOCAL_CORPUS_PATH_NOT_FOUND")
            acquisition_reasons.append(_missing_corpus_reason(corpus_id))
            acquisition_statuses[corpus_id] = {
                "status": "blocked",
                "acquisitionId": corpus_id,
                "corpusName": corpus_name,
                **_local_path_status_fields(acquisition_reasons, root),
                "reasonCodes": _sorted_unique(acquisition_reasons),
                "caseCount": len(corpus_cases),
            }
            gate_reasons.update(acquisition_statuses[corpus_id]["reasonCodes"])
            _record_external_status(
                external_status,
                corpus_name,
                corpus_id,
                "blocked",
                _external_reason_codes(corpus_id, acquisition_statuses[corpus_id]["reasonCodes"]),
            )
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
            **_local_path_status_fields(acquisition_reasons, root),
            "manifestChecksum": acquisition_record.get("manifestChecksum"),
            "reasonCodes": _sorted_unique(acquisition_reasons),
            "caseCount": len(corpus_cases),
            "splitCounts": dict(sorted(split_counts.items())),
        }
        gate_reasons.update(acquisition_statuses[corpus_id]["reasonCodes"])
        if acquisition_statuses[corpus_id]["status"] == "available":
            _record_external_status(external_status, corpus_name, corpus_id, "available", [])
        else:
            _record_external_status(
                external_status,
                corpus_name,
                corpus_id,
                "blocked",
                _external_reason_codes(corpus_id, acquisition_statuses[corpus_id]["reasonCodes"]),
            )

    case_statuses.sort(key=lambda item: (str(item.get("acquisitionId") or ""), str(item.get("caseId") or ""), str(item.get("sourcePath") or "")))
    status = "available" if not gate_reasons else "blocked"
    result = {
        "schemaVersion": CORPUS_READINESS_GATE_SCHEMA_VERSION,
        "status": status,
        "decisionGradeReady": status == "available",
        "requiredCorpora": required_corpus_ids,
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
    if required_corpus_id_failures:
        result["requiredCorpusInputValidation"] = {
            "status": "fail",
            "reasonCodes": [CORPUS_REQUIRED_CORPUS_ID_INVALID],
            "failures": required_corpus_id_failures,
        }
    return result


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
    readiness_status = _sanitize_readiness_status(readiness_gate.get("status"))
    reason_codes = _sanitize_readiness_reason_codes(readiness_gate.get("reasonCodes"))
    required_corpus_ids, _ = _normalize_required_corpora(readiness_gate.get("requiredCorpora") or [])
    projected = _sanitize_readiness_external_status(status, required_corpus_ids=required_corpus_ids)
    if readiness_status in {"blocked", "not_run"} or reason_codes:
        projected["requiredCorpusReadiness"] = {
            "status": readiness_status or "blocked",
            "reasonCodes": reason_codes or ["CORPUS_READINESS_GATE_NOT_RUN"],
        }
        return projected
    return projected


def main(argv: Sequence[str] | None = None) -> int:
    parser = _FixedDiagnosticArgumentParser(
        description="Build the S4 tool-portfolio corpus readiness preflight gate.",
    )
    parser.add_argument("--corpus-manifest", required=True, help="Path to s4-tool-portfolio-experiment-corpus-v1 JSON.")
    parser.add_argument(
        "--acquisition-manifest",
        action="append",
        default=[],
        help="Path to s4-tool-portfolio-acquisition-v1 JSON. May be repeated.",
    )
    parser.add_argument(
        "--required-corpus",
        action="append",
        default=[],
        help="Required acquisitionId for decision-grade readiness. May be repeated.",
    )
    parser.add_argument("--base-path", default=None, help="Explicit base path for relative acquisition localPath values.")
    parser.add_argument("--output", default=None, help="Write readiness JSON to this path instead of stdout.")
    try:
        args = parser.parse_args(argv)
    except ValueError as exc:
        _emit_cli_payload(_invalid_input_payload(exc), None)
        return 1

    try:
        corpus_manifest = _load_json_object(Path(args.corpus_manifest), "corpus manifest")
        acquisition_manifests = [
            _load_json_object(Path(path), "acquisition manifest")
            for path in args.acquisition_manifest
        ]
        gate = build_corpus_readiness_gate(
            acquisition_manifests=acquisition_manifests,
            corpus_manifest=corpus_manifest,
            required_corpora=args.required_corpus,
            base_path=args.base_path,
        )
        if not _emit_cli_payload(gate, args.output):
            return 1
        return 0 if gate.get("status") == "available" else 2
    except Exception as exc:  # pragma: no cover - exact exception type/message depends on input/OS.
        _emit_cli_payload(_invalid_input_payload(exc), args.output)
        return 1


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
            "sourcePath": "<unsafe>",
            "sourcePathStatus": "unsafe",
            "resolvedPathStatus": "unsafe",
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
            "sourcePathStatus": "unsafe",
            "resolvedPathStatus": "outside_root",
            "reasonCodes": ["CORPUS_CASE_SOURCE_PATH_UNSAFE"],
        }
    if not path.is_file():
        return {
            "status": "blocked",
            "acquisitionId": acquisition_id,
            "caseId": case_id,
            "sourcePath": source_path,
            "resolvedPathStatus": "missing",
            "reasonCodes": ["CORPUS_CASE_SOURCE_MISSING"],
        }
    actual_checksum = _file_checksum(path)
    if actual_checksum != expected_checksum:
        return {
            "status": "blocked",
            "acquisitionId": acquisition_id,
            "caseId": case_id,
            "sourcePath": source_path,
            "resolvedPathStatus": "checksum_mismatch",
            "expectedChecksum": expected_checksum,
            "actualChecksum": actual_checksum,
            "reasonCodes": ["CORPUS_CASE_CHECKSUM_MISMATCH"],
        }
    return {
        "status": "available",
        "acquisitionId": acquisition_id,
        "caseId": case_id,
        "sourcePath": source_path,
        "resolvedPathStatus": "available",
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
    base = base_path.resolve()
    candidate = (base / path).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return {"path": candidate, "reasonCodes": ["LOCAL_CORPUS_PATH_OUTSIDE_BASE"]}
    return {"path": candidate, "reasonCodes": []}


def _local_path_status_fields(reason_codes: Sequence[str], root: Path | None) -> dict[str, str]:
    reason_code_set = set(reason_codes)
    if "LOCAL_CORPUS_BASE_PATH_REQUIRED" in reason_code_set:
        return {"localPathStatus": "base_required", "resolvedLocalPathStatus": "not_resolved"}
    if "LOCAL_CORPUS_PATH_OUTSIDE_BASE" in reason_code_set:
        return {"localPathStatus": "outside_base", "resolvedLocalPathStatus": "outside_base"}
    if "LOCAL_CORPUS_PATH_NOT_FOUND" in reason_code_set:
        return {"localPathStatus": "missing", "resolvedLocalPathStatus": "missing"}
    if root is None:
        return {"localPathStatus": "not_resolved", "resolvedLocalPathStatus": "not_resolved"}
    return {"localPathStatus": "available", "resolvedLocalPathStatus": "available"}


def _unsafe_source_path(source_path: str) -> bool:
    normalized = source_path.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return True
    if len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/" and normalized[0].isalpha():
        return True
    return any(part == ".." for part in normalized.split("/"))


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
    return "external"


def _missing_corpus_reason(corpus_id: str) -> str:
    name = _external_corpus_name(corpus_id).upper().replace("-", "_")
    return f"LOCAL_{name}_CORPUS_NOT_PRESENT"


def _external_reason_codes(corpus_id: str, reason_codes: Sequence[str]) -> list[str]:
    reasons = set(reason_codes)
    if reason_codes and not any(str(reason).startswith("LOCAL_") and str(reason).endswith("_CORPUS_NOT_PRESENT") for reason in reasons):
        reasons.add(f"LOCAL_{_external_corpus_name(corpus_id).upper().replace('-', '_')}_CORPUS_INCOMPLETE")
    return sorted(str(reason) for reason in reasons)


def _record_external_status(
    external_status: dict[str, dict[str, Any]],
    corpus_name: str,
    corpus_id: str,
    status: str,
    reason_codes: Sequence[str],
) -> None:
    existing = external_status.get(corpus_name, {})
    acquisition_ids = {
        str(item)
        for item in existing.get("acquisitionIds", [])
        if str(item).strip()
    }
    acquisition_ids.add(corpus_id)
    merged_reason_codes = {
        str(reason)
        for reason in existing.get("reasonCodes", [])
        if str(reason).strip()
    }
    merged_reason_codes.update(str(reason) for reason in reason_codes if str(reason).strip())
    merged_status = "blocked" if status == "blocked" or existing.get("status") == "blocked" else "available"
    external_status[corpus_name] = {
        "status": merged_status,
        "reasonCodes": sorted(merged_reason_codes),
        "acquisitionIds": sorted(acquisition_ids),
    }


def _sanitize_readiness_external_status(
    status: Any,
    *,
    required_corpus_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    if not isinstance(status, Mapping):
        return {}

    required_corpus_id_set = set(required_corpus_ids)
    projected: dict[str, dict[str, Any]] = {}
    for key, value in status.items():
        if not isinstance(key, str) or not isinstance(value, Mapping):
            continue
        if key in READINESS_EXTERNAL_STATUS_KEYS:
            projected_key = key
        elif key in required_corpus_id_set:
            projected_key = _external_corpus_name(key)
        else:
            continue
        entry = _sanitize_readiness_external_status_entry(value, required_corpus_id_set=required_corpus_id_set)
        if not entry:
            continue
        existing = projected.get(projected_key)
        projected[projected_key] = _merge_sanitized_external_status(existing, entry)
    return projected


def _sanitize_readiness_external_status_entry(
    value: Mapping[str, Any],
    *,
    required_corpus_id_set: set[str],
) -> dict[str, Any]:
    status = _sanitize_readiness_status(value.get("status"))
    reason_codes = _sanitize_readiness_reason_codes(value.get("reasonCodes"))
    raw_acquisition_ids = value.get("acquisitionIds")
    acquisition_id_items = (
        raw_acquisition_ids
        if isinstance(raw_acquisition_ids, Sequence) and not isinstance(raw_acquisition_ids, (str, bytes, bytearray))
        else []
    )
    acquisition_ids = [
        item
        for item in acquisition_id_items
        if isinstance(item, str)
        and _valid_required_corpus_id(item)
        and item in required_corpus_id_set
    ]
    entry: dict[str, Any] = {"status": status or "blocked"}
    if "reasonCodes" in value or reason_codes:
        entry["reasonCodes"] = reason_codes
    if acquisition_ids:
        entry["acquisitionIds"] = sorted(set(acquisition_ids))
    return entry


def _merge_sanitized_external_status(existing: Mapping[str, Any] | None, entry: Mapping[str, Any]) -> dict[str, Any]:
    if existing is None:
        return dict(entry)
    merged_status = "blocked" if "blocked" in {existing.get("status"), entry.get("status")} else str(entry.get("status") or existing.get("status") or "blocked")
    reason_codes = sorted({
        str(reason)
        for reason in [*existing.get("reasonCodes", []), *entry.get("reasonCodes", [])]
        if str(reason) in READINESS_REASON_CODE_ALLOWLIST
    })
    acquisition_ids = sorted({
        str(item)
        for item in [*existing.get("acquisitionIds", []), *entry.get("acquisitionIds", [])]
        if _valid_required_corpus_id(str(item))
    })
    merged: dict[str, Any] = {"status": merged_status}
    if reason_codes:
        merged["reasonCodes"] = reason_codes
    if acquisition_ids:
        merged["acquisitionIds"] = acquisition_ids
    return merged


def _sanitize_readiness_status(value: Any) -> str:
    return value if isinstance(value, str) and value in READINESS_STATUS_VALUES else "blocked"


def _sanitize_readiness_reason_codes(value: Any) -> list[str]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return []
    return sorted({
        reason
        for reason in value
        if isinstance(reason, str) and reason in READINESS_REASON_CODE_ALLOWLIST
    })


def _normalize_required_corpora(required_corpora: Sequence[Any]) -> tuple[list[str], list[dict[str, Any]]]:
    if isinstance(required_corpora, (str, bytes, bytearray)) or not isinstance(required_corpora, Sequence):
        return [], [{"category": "invalid-container"}]

    corpus_ids: set[str] = set()
    failures: list[dict[str, Any]] = []
    for index, item in enumerate(required_corpora):
        if not isinstance(item, str):
            failures.append({"index": index, "category": "non_string"})
            continue
        if not _valid_required_corpus_id(item):
            failures.append({"index": index, "category": "invalid_string"})
            continue
        corpus_ids.add(item)
    return sorted(corpus_ids), failures


def _valid_required_corpus_id(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and not any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        and REQUIRED_CORPUS_ID_RE.match(value) is not None
    )


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a JSON object")
    return dict(value)


def _emit_json(payload: Mapping[str, Any], output: str | None) -> None:
    text = json.dumps(dict(payload), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return
    print(text, end="")


def _emit_cli_payload(payload: Mapping[str, Any], output: str | None) -> bool:
    try:
        _emit_json(payload, output)
        return True
    except Exception as exc:  # pragma: no cover - exact exception type depends on filesystem/stdio.
        _emit_json(_output_write_failed_payload(exc), None)
        return False


def _invalid_input_payload(exc: BaseException) -> dict[str, Any]:
    return {
        "schemaVersion": CORPUS_READINESS_GATE_SCHEMA_VERSION,
        "status": "invalid",
        "decisionGradeReady": False,
        "reasonCodes": ["CORPUS_READINESS_INPUT_INVALID"],
        "error": "input validation failed",
        "errorClass": type(exc).__name__,
        "consumerPolicy": "invalid_input_no_decision_grade_corpus_readiness_claim",
    }


def _output_write_failed_payload(exc: BaseException) -> dict[str, Any]:
    return {
        "schemaVersion": CORPUS_READINESS_GATE_SCHEMA_VERSION,
        "status": "invalid",
        "decisionGradeReady": False,
        "reasonCodes": ["CORPUS_READINESS_OUTPUT_WRITE_FAILED"],
        "error": "output write failed",
        "errorClass": type(exc).__name__,
        "consumerPolicy": "output_write_failed_no_decision_grade_corpus_readiness_claim",
    }


def _sorted_unique(values: Sequence[Any]) -> list[str]:
    return sorted({str(value) for value in values if value})


if __name__ == "__main__":
    raise SystemExit(main())
