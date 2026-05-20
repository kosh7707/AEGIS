from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.config import SERVICE_VERSION
from app.errors import RequiredToolUnavailableError
from app.scanner.orchestrator import ALL_TOOLS
from app.schemas.request import PaperStaticEvidenceRequest, SnapshotProvenance

SCHEMA_VERSION = "s4-paper-static-evidence-bundle-v1"
BUNDLE_PROFILE = "s4-paper-static-evidence-full-v1"
SURFACE_POLICY = "always_attempt_full_bundle"
VALIDATION_SCHEMA_VERSION = "s4-static-evidence-validation-v1"

CURRENT_SIX_TOOLS = tuple(ALL_TOOLS)
REQUIRED_SURFACES = (
    "findings",
    "evidence",
    "sourceFiles",
    "functions",
    "includeEdges",
    "libraries",
    "toolRuns",
    "targetMetadata",
    "staticEvidenceContract",
    "claimBoundaryMatrix",
    "claimBoundaries",
)
DIAGNOSTIC_CAPABLE_ARRAYS = (
    "findings",
    "evidence",
    "sourceFiles",
    "functions",
    "includeEdges",
    "libraries",
    "toolRuns",
)
ROW_ID_FIELDS = {
    "findings": "findingId",
    "evidence": "evidenceId",
    "sourceFiles": "sourceFileId",
    "functions": "functionId",
    "includeEdges": "includeEdgeId",
    "libraries": "libraryId",
    "toolRuns": "toolRunId",
}
REQUIRED_CLAIM_IDS = (
    "local-static-artifact",
    "reported-finding-positive-evidence",
    "absence-of-vulnerability",
    "cwe-absence",
    "build-configuration-dependent-negative-claim",
    "runtime-behavior",
    "external-vulnerability-affectedness",
    "semantic-graph-completeness",
    "exploitability-judgment",
    "final-security-verdict",
)

SURFACE_STATUSES = {
    "produced",
    "empty",
    "partial",
    "failed",
    "not_available",
    "skipped",
    "error",
}
NON_DIAGNOSTIC_SURFACE_STATUSES = {"produced", "empty"}
TOOL_RUN_SUCCESS_STATUSES = {"success"}
TOOL_RUN_STATUSES = {"success", "failed", "timeout", "not_available", "skipped"}
DIAGNOSTIC_CATEGORIES = {
    "request-contract",
    "input-consumption",
    "tool-execution",
    "producer-invariant",
    "surface-unavailable",
    "surface-error",
    "operational",
}
DIAGNOSTIC_REASON_CODES = {
    "PAPER_STATIC_EVIDENCE_REQUEST_INVALID",
    "PAPER_STATIC_EVIDENCE_REQUEST_FORBIDDEN_FIELD",
    "UNSUPPORTED_COMPILE_CONTEXT_TYPE",
    "COMPILE_CONTEXT_REF_MISMATCH",
    "SOURCE_ROOT_UNREADABLE",
    "COMPILE_CONTEXT_UNREADABLE",
    "COMPILE_CONTEXT_PARSE_FAILED",
    "COMPILE_CONTEXT_NO_ANALYZABLE_ENTRIES",
    "COMPILE_CONTEXT_SOURCE_UNRESOLVED",
    "REQUIRED_TOOL_UNAVAILABLE",
    "REQUIRED_TOOL_EXECUTION_INCOMPLETE",
    "SURFACE_NOT_AVAILABLE",
    "SURFACE_PRODUCTION_FAILED",
    "STATIC_EVIDENCE_CONTRACT_MISSING",
    "SURFACE_STATUS_INCOMPLETE",
    "ROW_TRACE_MISSING",
    "DUPLICATE_ROW_ID",
    "PRODUCER_INTERNAL_ERROR",
    # Existing deterministic producer projections.
    "TOOL_RUN_MISSING",
    "TOOL_EXECUTION_FAILED",
    "TOOL_EXECUTION_PARTIAL",
    "TOOL_EXECUTION_SKIPPED",
    "TOOL_EXECUTION_TIMEOUT",
    "RUNTIME_TOOL_MISSING",
    "ENVIRONMENT_DRIFT",
    "TOOL_CHECK_FAILED",
}
REQUIRED_TRACE_FIELDS = {
    "caseId",
    "buildTargetId",
    "bundleRef",
    "s4RequestId",
    "s4ProducerRunId",
    "sourceRootRef",
    "compileContextRef",
    "surfaceId",
    "surface",
    "rawObjectRef",
}
SINGLETON_SURFACES = {"targetMetadata", "staticEvidenceContract", "claimBoundaries"}
ARRAY_SURFACES = set(DIAGNOSTIC_CAPABLE_ARRAYS) | {"claimBoundaryMatrix"}
UNSAFE_DIAGNOSTIC_MESSAGE_PATTERNS = (
    re.compile(r"traceback", re.IGNORECASE),
    re.compile(r"\bFile\s+\"", re.IGNORECASE),
    re.compile(r"(^|\s)/(home|tmp|var|etc|root|Users)/"),
    re.compile(r"[A-Za-z]:\\\\"),
    re.compile(r"(secret|password|token)", re.IGNORECASE),
)

FORBIDDEN_REQUEST_FIELDS = {
    "buildCommand",
    "buildEnvironment",
    "requestedSurfaces",
    "tools",
    "sdkId",
    "verdict",
    "expectedLabel",
    "oracleLabel",
    "cveId",
    "advisoryId",
    "fixCommit",
    "checksum",
    "sha256",
    "hash",
    "digest",
    "fingerprint",
    "artifactHash",
    "replayHash",
    "integrity",
    "integrityStatus",
    "artifactIntegrity",
    "reproducibility",
    "reproducibleBuild",
    "finalVerdict",
    "securityVerdict",
    "provenSafe",
    "isSafe",
}
FORBIDDEN_BUNDLE_KEYS = {
    "verdict",
    "expectedLabel",
    "oracleLabel",
    "risk",
    "riskScore",
    "safe",
    "checksum",
    "sha256",
    "hash",
    "digest",
    "fingerprint",
    "artifactHash",
    "replayHash",
    "integrity",
    "integrityStatus",
    "artifactIntegrity",
    "reproducibility",
    "reproducibleBuild",
    "finalVerdict",
    "securityVerdict",
    "provenSafe",
    "isSafe",
}
FORBIDDEN_VALUES = {"TP", "FP", "UNKNOWN"}
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}


class PaperStaticEvidenceContractError(Exception):
    def __init__(self, reason_code: str, message: str, *, status_code: int = 400) -> None:
        self.reason_code = reason_code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class PaperCompileContextLoadResult:
    path: Path
    request_path: str
    ref: str
    compile_database_entries: int
    analyzable_source_files: list[str]


def _to_plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(by_alias=True, exclude_none=True)
    if isinstance(value, dict):
        return {k: _to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_plain(v) for v in value]
    return value


def _issue(reason_code: str, message: str, path: str = "$") -> dict[str, str]:
    return {"reasonCode": reason_code, "message": message, "path": path}


def _new_validation_report(bundle_ref: str | None) -> dict[str, Any]:
    return {
        "schemaVersion": VALIDATION_SCHEMA_VERSION,
        "bundleRef": bundle_ref,
        "overallStatus": "pass",
        "contractValidation": {"status": "pass", "errors": [], "warnings": []},
        "producerSanityValidation": {"status": "pass", "errors": [], "warnings": []},
    }


def _fail(report: dict[str, Any], section: str, reason_code: str, message: str, path: str = "$") -> None:
    report[section]["errors"].append(_issue(reason_code, message, path))
    report[section]["status"] = "fail"
    report["overallStatus"] = "fail"


def _warn(report: dict[str, Any], section: str, reason_code: str, message: str, path: str = "$") -> None:
    report[section]["warnings"].append(_issue(reason_code, message, path))


def _is_failed_bundle(bundle: dict[str, Any]) -> bool:
    return bundle.get("success") is False and bundle.get("bundleStatus") == "failed"


def _is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _is_list(value: Any) -> bool:
    return isinstance(value, list)


def _dict_get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _diagnostic_message_is_safe(message: Any) -> bool:
    if not isinstance(message, str) or not message.strip():
        return False
    return not any(pattern.search(message) for pattern in UNSAFE_DIAGNOSTIC_MESSAGE_PATTERNS)


def _validate_trace_object(
    trace: Any,
    report: dict[str, Any],
    *,
    path: str,
    section: str = "contractValidation",
) -> None:
    if not isinstance(trace, dict):
        _fail(report, section, "ROW_TRACE_MISSING", "Trace object is missing.", path)
        return
    missing = [
        field
        for field in sorted(REQUIRED_TRACE_FIELDS)
        if not isinstance(trace.get(field), str) or not trace.get(field)
    ]
    if missing:
        _fail(report, section, "ROW_TRACE_MISSING", "Trace object is missing required refs.", path)


def _surface_actual_count(bundle: dict[str, Any], surface: str) -> int | None:
    value = bundle.get(surface)
    if surface in ARRAY_SURFACES:
        return len(value) if isinstance(value, list) else None
    if surface in SINGLETON_SURFACES:
        return 1 if isinstance(value, dict) and bool(value) else 0 if isinstance(value, dict) else None
    return None


def contains_forbidden_request_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in FORBIDDEN_REQUEST_FIELDS:
                return True
            if key == "options" and isinstance(nested, dict) and "tools" in nested:
                return True
            if contains_forbidden_request_field(nested):
                return True
    elif isinstance(value, list):
        return any(contains_forbidden_request_field(item) for item in value)
    return False


def _scan_forbidden_semantics(
    value: Any,
    report: dict[str, Any],
    path: str = "$",
    *,
    parent_key: str | None = None,
) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            child_path = f"{path}.{key}"
            if key in FORBIDDEN_BUNDLE_KEYS:
                _fail(
                    report,
                    "contractValidation",
                    "FORBIDDEN_SEMANTIC_FIELD",
                    "Forbidden verdict/risk/integrity field is present.",
                    child_path,
                )
            _scan_forbidden_semantics(nested, report, child_path, parent_key=key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_forbidden_semantics(item, report, f"{path}[{index}]", parent_key=parent_key)
    elif isinstance(value, str):
        if value in FORBIDDEN_VALUES:
            _fail(
                report,
                "contractValidation",
                "FORBIDDEN_SEMANTIC_VALUE",
                "Forbidden TP/FP/UNKNOWN value is present.",
                path,
            )


def load_paper_compile_context(request: PaperStaticEvidenceRequest) -> PaperCompileContextLoadResult:
    source_root = Path(request.source_root)
    if not source_root.is_dir():
        raise PaperStaticEvidenceContractError("SOURCE_ROOT_UNREADABLE", "Source root is unreadable.")

    context_path = Path(request.compile_context.path)
    if not context_path.is_absolute():
        context_path = source_root / context_path
    if not context_path.is_file():
        raise PaperStaticEvidenceContractError(
            "COMPILE_CONTEXT_UNREADABLE",
            "Compile context is unreadable.",
        )

    try:
        payload = json.loads(context_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PaperStaticEvidenceContractError(
            "COMPILE_CONTEXT_PARSE_FAILED",
            "Compile context could not be parsed.",
        ) from exc
    if not isinstance(payload, list):
        raise PaperStaticEvidenceContractError(
            "COMPILE_CONTEXT_PARSE_FAILED",
            "Compile context shape is invalid.",
        )

    source_files: list[str] = []
    seen: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        raw_file = entry.get("file")
        if not isinstance(raw_file, str) or not raw_file.strip():
            continue
        file_path = Path(raw_file)
        if file_path.is_absolute():
            candidate_path = file_path
        else:
            raw_directory = entry.get("directory")
            directory = Path(raw_directory) if isinstance(raw_directory, str) and raw_directory.strip() else source_root
            if not directory.is_absolute():
                directory = source_root / directory
            candidate_path = directory / file_path
        try:
            rel_path = candidate_path.resolve(strict=False).relative_to(
                source_root.resolve(strict=False),
            )
            rel = rel_path.as_posix()
        except (OSError, ValueError, RuntimeError) as exc:
            raise PaperStaticEvidenceContractError(
                "COMPILE_CONTEXT_SOURCE_UNRESOLVED",
                "Compile context source entry is outside the admitted source root.",
            ) from exc
        if Path(rel).suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if rel not in seen:
            seen.add(rel)
            source_files.append(rel)

    if not source_files:
        raise PaperStaticEvidenceContractError(
            "COMPILE_CONTEXT_NO_ANALYZABLE_ENTRIES",
            "Compile context has no analyzable C/C++ source entries.",
        )

    return PaperCompileContextLoadResult(
        path=context_path,
        request_path=request.compile_context.path,
        ref=request.compile_context.ref,
        compile_database_entries=len(payload),
        analyzable_source_files=source_files,
    )


def _trace(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    surface: str,
    raw_object_ref: str,
    surface_id: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    trace = {
        "caseId": request.case_id,
        "buildTargetId": request.build_target_id,
        "bundleRef": bundle_ref,
        "s4RequestId": request_id,
        "s4ProducerRunId": producer_run_id,
        "sourceRootRef": request.provenance.source_root_ref,
        "compileContextRef": request.provenance.compile_context_ref,
        "surfaceId": surface_id or f"surface:{surface}",
        "surface": surface,
        "rawObjectRef": raw_object_ref,
    }
    trace.update(extra)
    return trace


def _diagnostic(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    index: int,
    severity: str,
    category: str,
    reason_code: str,
    surface: str,
    message: str,
) -> dict[str, Any]:
    diagnostic_id = f"diag:{index:04d}:{reason_code.lower()}"
    return {
        "diagnosticId": diagnostic_id,
        "severity": severity,
        "category": category,
        "reasonCode": reason_code,
        "surface": surface,
        "message": message,
        "consumerPolicy": "producer_diagnostic_not_security_evidence",
        "trace": _trace(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            surface="diagnostics",
            raw_object_ref=f"diagnostics[{index}]",
        ),
    }


def _reason_from_tool_result(tool_result: Any) -> str:
    value = _to_plain(tool_result)
    if not isinstance(value, dict):
        return "TOOL_EXECUTION_FAILED"
    reasons = value.get("degradeReasons") or value.get("degrade_reasons") or []
    if isinstance(reasons, list) and reasons:
        return str(reasons[0]).upper().replace("-", "_")
    skip = value.get("skipReason") or value.get("skip_reason")
    if isinstance(skip, str) and skip:
        return skip.upper().replace("-", "_")
    status = value.get("status")
    if status == "partial":
        return "TOOL_EXECUTION_PARTIAL"
    if status == "skipped":
        return "TOOL_EXECUTION_SKIPPED"
    return "TOOL_EXECUTION_FAILED"


def _paper_tool_status(tool_result: Any) -> str:
    value = _to_plain(tool_result)
    if not isinstance(value, dict):
        return "failed"
    status = value.get("status")
    if status == "ok":
        return "success"
    if status == "partial":
        return "timeout" if value.get("timedOutFiles") or value.get("timed_out_files") else "failed"
    if status == "failed":
        reason = value.get("skipReason") or value.get("skip_reason")
        if reason in {"runtime-tool-missing", "environment-drift", "tool-check-failed"}:
            return "not_available"
        return "failed"
    if status == "skipped":
        reason = value.get("skipReason") or value.get("skip_reason")
        if reason in {"runtime-tool-missing", "environment-drift", "tool-check-failed"}:
            return "not_available"
        return "skipped"
    if status in TOOL_RUN_STATUSES:
        return status
    return "failed"


def _make_surface_status(
    status: str,
    count: int,
    consumer_policy: str,
    reason_codes: list[str] | None = None,
    diagnostic_refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "count": count,
        "consumerPolicy": consumer_policy,
        "reasonCodes": list(reason_codes or []),
        "diagnosticRefs": list(diagnostic_refs or []),
    }


def _status_for_array(count: int, *, diagnostic_refs: list[str] | None = None) -> str:
    if diagnostic_refs:
        return "partial"
    if count == 0:
        return "empty"
    return "produced"


def _safe_cwe_candidates(finding: dict[str, Any]) -> list[str]:
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    cwe_id = metadata.get("cweId") or metadata.get("cwe")
    if isinstance(cwe_id, str) and cwe_id:
        return [cwe_id]
    evidence_resolution = metadata.get("evidenceResolution")
    if isinstance(evidence_resolution, dict):
        cwe = evidence_resolution.get("cwe")
        if isinstance(cwe, dict) and isinstance(cwe.get("value"), str):
            return [cwe["value"]]
    return []


def _project_findings(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    findings: list[Any],
    source_file_ids: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    for index, raw_finding in enumerate(findings):
        finding = _to_plain(raw_finding)
        if not isinstance(finding, dict):
            continue
        location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
        path = str(location.get("file") or "<unknown>")
        finding_id = f"finding:{index:04d}"
        evidence_id = f"evidence:{index:04d}:finding-message"
        source_file_id = source_file_ids.get(path)
        row = {
            "findingId": finding_id,
            "toolId": finding.get("toolId") or finding.get("tool_id") or "unknown",
            "ruleId": finding.get("ruleId") or finding.get("rule_id") or "unknown",
            "message": finding.get("message") or "S4 local static finding.",
            "severity": finding.get("severity") or "unknown",
            "cweCandidates": _safe_cwe_candidates(finding),
            "location": {
                "sourceFileId": source_file_id,
                "path": path,
                "startLine": location.get("line") or 1,
                "endLine": location.get("endLine") or location.get("end_line") or location.get("line") or 1,
            },
            "functionId": None,
            "evidenceRefs": [evidence_id],
            "diagnosticRefs": [],
            "trace": _trace(
                request=request,
                request_id=request_id,
                producer_run_id=producer_run_id,
                bundle_ref=bundle_ref,
                surface="findings",
                raw_object_ref=f"findings[{index}]",
                toolRunId=f"toolrun:{CURRENT_SIX_TOOLS.index(finding.get('toolId')):04d}:{finding.get('toolId')}"
                if finding.get("toolId") in CURRENT_SIX_TOOLS
                else None,
                sourceFileId=source_file_id,
            ),
        }
        evidence_rows.append(
            {
                "evidenceId": evidence_id,
                "evidenceType": "sast-finding-message",
                "producer": "s4",
                "findingId": finding_id,
                "sourceFileId": source_file_id,
                "text": row["message"],
                "consumerPolicy": "local_static_observation_not_verdict",
                "diagnosticRefs": [],
                "trace": _trace(
                    request=request,
                    request_id=request_id,
                    producer_run_id=producer_run_id,
                    bundle_ref=bundle_ref,
                    surface="evidence",
                    raw_object_ref=f"evidence[{index}]",
                    sourceFileId=source_file_id,
                ),
            },
        )
        rows.append(row)
    return rows, evidence_rows


def _project_source_files(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    compile_context: PaperCompileContextLoadResult,
) -> list[dict[str, Any]]:
    rows = []
    for index, source_path in enumerate(compile_context.analyzable_source_files):
        source_file_id = f"src:{index:04d}"
        language = "cpp" if Path(source_path).suffix.lower() in {".cc", ".cpp", ".cxx"} else "c"
        rows.append(
            {
                "sourceFileId": source_file_id,
                "path": source_path,
                "language": language,
                "compileContextRef": request.provenance.compile_context_ref,
                "diagnosticRefs": [],
                "trace": _trace(
                    request=request,
                    request_id=request_id,
                    producer_run_id=producer_run_id,
                    bundle_ref=bundle_ref,
                    surface="sourceFiles",
                    raw_object_ref=f"sourceFiles[{index}]",
                    sourceFileId=source_file_id,
                ),
            },
        )
    return rows


def _project_functions(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    functions_result: Any,
    source_file_ids: dict[str, str],
) -> list[dict[str, Any]]:
    payload = _to_plain(functions_result)
    functions = payload.get("functions", []) if isinstance(payload, dict) else []
    rows: list[dict[str, Any]] = []
    if not isinstance(functions, list):
        return rows
    for index, function in enumerate(functions):
        if not isinstance(function, dict):
            continue
        path = function.get("file") or function.get("path") or function.get("sourcePath") or "<unknown>"
        name = function.get("name") or function.get("qualifiedName") or "unknown"
        function_id = f"func:{index:04d}"
        rows.append(
            {
                "functionId": function_id,
                "sourceFileId": source_file_ids.get(str(path)),
                "name": name,
                "qualifiedName": function.get("qualifiedName") or name,
                "location": {
                    "startLine": function.get("startLine") or function.get("line") or 1,
                    "endLine": function.get("endLine") or function.get("line") or 1,
                },
                "diagnosticRefs": [],
                "trace": _trace(
                    request=request,
                    request_id=request_id,
                    producer_run_id=producer_run_id,
                    bundle_ref=bundle_ref,
                    surface="functions",
                    raw_object_ref=f"functions[{index}]",
                    functionId=function_id,
                    sourceFileId=source_file_ids.get(str(path)),
                ),
            },
        )
    return rows


def _project_include_edges(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    includes_result: Any,
    source_file_ids: dict[str, str],
) -> list[dict[str, Any]]:
    payload = _to_plain(includes_result)
    if isinstance(payload, dict):
        if isinstance(payload.get("includes"), list):
            includes = payload.get("includes", [])
        else:
            includes = []
            for from_path, include_list in payload.items():
                if not isinstance(include_list, list):
                    continue
                for include_text in include_list:
                    includes.append(
                        {
                            "file": from_path,
                            "includeText": include_text,
                            "resolved": isinstance(include_text, str) and include_text in source_file_ids,
                        },
                    )
    else:
        includes = payload
    rows: list[dict[str, Any]] = []
    if not isinstance(includes, list):
        return rows
    for index, edge in enumerate(includes):
        if not isinstance(edge, dict):
            continue
        from_path = edge.get("file") or edge.get("from") or edge.get("source") or "<unknown>"
        include_text = edge.get("include") or edge.get("includeText") or edge.get("header") or ""
        include_edge_id = f"include:{index:04d}"
        rows.append(
            {
                "includeEdgeId": include_edge_id,
                "fromSourceFileId": source_file_ids.get(str(from_path)),
                "includeText": include_text,
                "toSourceFileId": edge.get("toSourceFileId"),
                "resolved": bool(edge.get("resolved", False)),
                "diagnosticRefs": [],
                "trace": _trace(
                    request=request,
                    request_id=request_id,
                    producer_run_id=producer_run_id,
                    bundle_ref=bundle_ref,
                    surface="includeEdges",
                    raw_object_ref=f"includeEdges[{index}]",
                    includeEdgeId=include_edge_id,
                    sourceFileId=source_file_ids.get(str(from_path)),
                ),
            },
        )
    return rows


def _project_libraries(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    libraries_result: Any,
) -> list[dict[str, Any]]:
    libraries = _to_plain(libraries_result)
    rows: list[dict[str, Any]] = []
    if not isinstance(libraries, list):
        return rows
    for index, library in enumerate(libraries):
        if not isinstance(library, dict):
            continue
        library_id = f"lib:{index:04d}"
        name = library.get("name") or library.get("library") or "unknown"
        rows.append(
            {
                "libraryId": library_id,
                "name": name,
                "versionCandidates": library.get("versionCandidates") or library.get("versions") or [],
                "identityMethod": library.get("identityMethod") or "local-static-heuristic",
                "confidence": library.get("confidence") or "unknown",
                "sourcePath": library.get("path") or library.get("sourcePath") or "",
                "repoUrl": library.get("repoUrl"),
                "diffSummary": library.get("diffSummary"),
                "consumerPolicy": "bounded_library_identity_not_cve_affectedness",
                "diagnosticRefs": [],
                "trace": _trace(
                    request=request,
                    request_id=request_id,
                    producer_run_id=producer_run_id,
                    bundle_ref=bundle_ref,
                    surface="libraries",
                    raw_object_ref=f"libraries[{index}]",
                    libraryId=library_id,
                ),
            },
        )
    return rows


def _project_tool_runs(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    producer_run_id: str,
    bundle_ref: str,
    execution: Any,
    diagnostics: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    execution_map = _to_plain(execution)
    tool_results = execution_map.get("toolResults") or execution_map.get("tool_results") if isinstance(execution_map, dict) else {}
    if not isinstance(tool_results, dict):
        tool_results = {}
    rows: list[dict[str, Any]] = []
    tool_diagnostic_refs: list[str] = []
    for index, tool in enumerate(CURRENT_SIX_TOOLS):
        result = tool_results.get(tool)
        status = _paper_tool_status(result) if result is not None else "skipped"
        result_map = _to_plain(result) if result is not None else {}
        if not isinstance(result_map, dict):
            result_map = {}
        diagnostic_refs: list[str] = []
        if status != "success":
            reason = "TOOL_RUN_MISSING" if result is None else _reason_from_tool_result(result)
            diagnostic = _diagnostic(
                request=request,
                request_id=request_id,
                producer_run_id=producer_run_id,
                bundle_ref=bundle_ref,
                index=len(diagnostics),
                severity="warning",
                category="tool-execution",
                reason_code=reason,
                surface="toolRuns",
                message="A current-six SAST tool did not complete successfully.",
            )
            diagnostics.append(diagnostic)
            diagnostic_refs.append(diagnostic["diagnosticId"])
            tool_diagnostic_refs.extend(diagnostic_refs)
        rows.append(
            {
                "toolRunId": f"toolrun:{index:04d}:{tool}",
                "toolId": tool,
                "status": status,
                "findingsCount": result_map.get("findingsCount") or result_map.get("findings_count") or 0,
                "version": result_map.get("version"),
                "elapsedMs": result_map.get("elapsedMs") or result_map.get("elapsed_ms"),
                "degraded": bool(result_map.get("degraded", status != "success")),
                "degradeReasons": result_map.get("degradeReasons") or result_map.get("degrade_reasons") or [],
                "consumerPolicy": "local_tool_execution_state_only_not_vulnerability_verdict",
                "diagnosticRefs": diagnostic_refs,
                "trace": _trace(
                    request=request,
                    request_id=request_id,
                    producer_run_id=producer_run_id,
                    bundle_ref=bundle_ref,
                    surface="toolRuns",
                    raw_object_ref=f"toolRuns[{index}]",
                    toolRunId=f"toolrun:{index:04d}:{tool}",
                ),
            },
        )
    return rows, tool_diagnostic_refs


def _claim_boundary_fallback() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    matrix = [
        {
            "claimId": claim_id,
            "supportStatus": "unsupported"
            if claim_id
            not in {"local-static-artifact", "reported-finding-positive-evidence"}
            else "supported",
            "reasonCodes": [],
            "consumerPolicy": "claim_boundary_contract",
            "evidenceRefs": [],
            "summary": "S4 claim-boundary row.",
        }
        for claim_id in REQUIRED_CLAIM_IDS
    ]
    boundaries = {
        "negativeEvidencePolicy": "empty-or-missing-s4-evidence-is-not-negative-security-evidence",
        "mustNotSupportAlone": [
            "final-security-verdict",
            "vulnerability-absence",
            "cwe-absence",
            "exploitability-judgment",
            "external-affectedness",
            "semantic-graphrag-completeness",
            "s5-sufficiency",
        ],
    }
    return matrix, boundaries


def _paper_provenance(request: PaperStaticEvidenceRequest) -> dict[str, Any]:
    data = {
        "paperRunId": request.provenance.paper_run_id,
        "buildSnapshotId": request.provenance.build_snapshot_id,
        "buildUnitId": request.provenance.build_unit_id,
        "sourceRootRef": request.provenance.source_root_ref,
        "compileContextRef": request.provenance.compile_context_ref,
    }
    if request.provenance.dataset_root_ref is not None:
        data["datasetRootRef"] = request.provenance.dataset_root_ref
    return data


async def build_paper_static_evidence_bundle(
    *,
    request: PaperStaticEvidenceRequest,
    request_id: str,
    orchestrator: Any,
    ast_dumper: Any,
    include_resolver: Any,
    identify_libraries_func: Any,
    build_static_evidence_contract_func: Any,
    rulesets: list[str],
    timeout: int,
) -> dict[str, Any]:
    compile_context = load_paper_compile_context(request)
    source_root = Path(request.source_root)
    producer_run_id = f"s4-paper-static-evidence-run:{request.case_id}:{request.build_target_id}:{request_id}"
    bundle_ref = f"s4-bundle:{request.case_id}:{request.build_target_id}:{request_id}"
    diagnostics: list[dict[str, Any]] = []

    findings: list[Any] = []
    execution = None
    static_contract_policy_failure_reason_codes: list[str] = []
    try:
        findings, execution = await orchestrator.run(
            scan_dir=source_root,
            source_files=compile_context.analyzable_source_files,
            profile=None,
            rulesets=rulesets,
            compile_commands=str(compile_context.path),
            tools=None,
            timeout=timeout,
            third_party_paths=request.scope.third_party_paths,
        )
    except RequiredToolUnavailableError as exc:
        execution = exc.execution
        findings = []
    except Exception:
        diagnostic = _diagnostic(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            index=len(diagnostics),
            severity="error",
            category="tool-execution",
            reason_code="PRODUCER_INTERNAL_ERROR",
            surface="toolRuns",
            message="S4 tool orchestration failed.",
        )
        diagnostics.append(diagnostic)
        execution = None
        static_contract_policy_failure_reason_codes.append("PRODUCER_INTERNAL_ERROR")

    source_files = _project_source_files(
        request=request,
        request_id=request_id,
        producer_run_id=producer_run_id,
        bundle_ref=bundle_ref,
        compile_context=compile_context,
    )
    source_file_ids = {row["path"]: row["sourceFileId"] for row in source_files}
    finding_rows, evidence_rows = _project_findings(
        request=request,
        request_id=request_id,
        producer_run_id=producer_run_id,
        bundle_ref=bundle_ref,
        findings=findings,
        source_file_ids=source_file_ids,
    )

    surface_diag_refs: dict[str, list[str]] = {surface: [] for surface in REQUIRED_SURFACES}

    try:
        functions_result = await ast_dumper.dump_functions(
            source_root,
            compile_context.analyzable_source_files,
            None,
            libraries=[],
            skip_paths=request.scope.third_party_paths or None,
        )
        function_rows = _project_functions(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            functions_result=functions_result,
            source_file_ids=source_file_ids,
        )
    except Exception:
        diagnostic = _diagnostic(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            index=len(diagnostics),
            severity="warning",
            category="surface-error",
            reason_code="SURFACE_PRODUCTION_FAILED",
            surface="functions",
            message="Function extraction failed.",
        )
        diagnostics.append(diagnostic)
        surface_diag_refs["functions"].append(diagnostic["diagnosticId"])
        function_rows = []

    try:
        include_result = await include_resolver.resolve(
            source_root,
            compile_context.analyzable_source_files,
            None,
        )
        include_rows = _project_include_edges(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            includes_result=include_result,
            source_file_ids=source_file_ids,
        )
    except Exception:
        diagnostic = _diagnostic(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            index=len(diagnostics),
            severity="warning",
            category="surface-error",
            reason_code="SURFACE_PRODUCTION_FAILED",
            surface="includeEdges",
            message="Include-edge extraction failed.",
        )
        diagnostics.append(diagnostic)
        surface_diag_refs["includeEdges"].append(diagnostic["diagnosticId"])
        include_rows = []

    try:
        libraries_result = await identify_libraries_func(source_root)
        library_rows = _project_libraries(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            libraries_result=libraries_result,
        )
    except Exception:
        diagnostic = _diagnostic(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            index=len(diagnostics),
            severity="warning",
            category="surface-error",
            reason_code="SURFACE_PRODUCTION_FAILED",
            surface="libraries",
            message="Library identification failed.",
        )
        diagnostics.append(diagnostic)
        surface_diag_refs["libraries"].append(diagnostic["diagnosticId"])
        library_rows = []

    tool_runs, tool_diag_refs = _project_tool_runs(
        request=request,
        request_id=request_id,
        producer_run_id=producer_run_id,
        bundle_ref=bundle_ref,
        execution=execution,
        diagnostics=diagnostics,
    )
    surface_diag_refs["toolRuns"].extend(tool_diag_refs)
    surface_diag_refs["findings"].extend(tool_diag_refs)
    surface_diag_refs["evidence"].extend(tool_diag_refs)

    snapshot_provenance = SnapshotProvenance(
        buildSnapshotId=request.provenance.build_snapshot_id,
        buildUnitId=request.provenance.build_unit_id,
    )
    target_metadata = {
        "trace": _trace(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            surface="targetMetadata",
            raw_object_ref="targetMetadata",
        ),
        "language": "c/cpp",
        "sourceRootRef": request.provenance.source_root_ref,
        "compileContext": {
            "type": request.compile_context.type,
            "path": request.compile_context.path,
            "ref": request.compile_context.ref,
        },
        "scopeSummary": {
            "includePathCount": len(request.scope.include_paths),
            "excludePathCount": len(request.scope.exclude_paths),
            "thirdPartyPathCount": len(request.scope.third_party_paths),
        },
        "observedBuildProfile": {
            "compileDatabaseEntries": compile_context.compile_database_entries,
            "analyzableSourceFiles": len(compile_context.analyzable_source_files),
        },
    }
    code_graph = {"functions": function_rows} if function_rows else {"functions": []}
    sca = {"libraries": library_rows}
    try:
        static_contract = build_static_evidence_contract_func(
            success=True,
            provenance=snapshot_provenance,
            findings=findings,
            execution=execution,
            code_graph=code_graph,
            sca=sca,
            policy_failure_reason_codes=static_contract_policy_failure_reason_codes or None,
        )
    except Exception:
        diagnostic = _diagnostic(
            request=request,
            request_id=request_id,
            producer_run_id=producer_run_id,
            bundle_ref=bundle_ref,
            index=len(diagnostics),
            severity="error",
            category="producer-invariant",
            reason_code="PRODUCER_INTERNAL_ERROR",
            surface="staticEvidenceContract",
            message="S4 static-evidence producer failed after request admission.",
        )
        diagnostics.append(diagnostic)
        static_contract_diag_refs = [diagnostic["diagnosticId"]]
        claim_matrix, claim_boundaries = _claim_boundary_fallback()
        surface_status = {
            "findings": _make_surface_status(
                _status_for_array(len(finding_rows), diagnostic_refs=surface_diag_refs["findings"]),
                len(finding_rows),
                "empty_is_not_negative_evidence" if not finding_rows else "local_static_observation_only",
                ["TOOL_EXECUTION_PARTIAL"] if surface_diag_refs["findings"] else [],
                surface_diag_refs["findings"],
            ),
            "evidence": _make_surface_status(
                _status_for_array(len(evidence_rows), diagnostic_refs=surface_diag_refs["evidence"]),
                len(evidence_rows),
                "empty_is_not_negative_evidence" if not evidence_rows else "local_reviewer_visible_evidence",
                ["TOOL_EXECUTION_PARTIAL"] if surface_diag_refs["evidence"] else [],
                surface_diag_refs["evidence"],
            ),
            "sourceFiles": _make_surface_status("produced", len(source_files), "local_static_structure_only"),
            "functions": _make_surface_status(
                "failed" if surface_diag_refs["functions"] else _status_for_array(len(function_rows)),
                len(function_rows),
                "local_static_structure_only",
                ["SURFACE_PRODUCTION_FAILED"] if surface_diag_refs["functions"] else [],
                surface_diag_refs["functions"],
            ),
            "includeEdges": _make_surface_status(
                "failed" if surface_diag_refs["includeEdges"] else _status_for_array(len(include_rows)),
                len(include_rows),
                "local_static_structure_only",
                ["SURFACE_PRODUCTION_FAILED"] if surface_diag_refs["includeEdges"] else [],
                surface_diag_refs["includeEdges"],
            ),
            "libraries": _make_surface_status(
                "failed" if surface_diag_refs["libraries"] else _status_for_array(len(library_rows)),
                len(library_rows),
                "empty_is_not_no_vulnerable_dependencies" if not library_rows else "bounded_library_identity_only",
                ["SURFACE_PRODUCTION_FAILED"] if surface_diag_refs["libraries"] else [],
                surface_diag_refs["libraries"],
            ),
            "toolRuns": _make_surface_status(
                "partial" if surface_diag_refs["toolRuns"] else "produced",
                len(tool_runs),
                "local_tool_execution_state_only",
                ["TOOL_EXECUTION_PARTIAL"] if surface_diag_refs["toolRuns"] else [],
                surface_diag_refs["toolRuns"],
            ),
            "targetMetadata": _make_surface_status("produced", 1, "producer_metadata_only"),
            "staticEvidenceContract": _make_surface_status(
                "failed",
                0,
                "producer_diagnostic_not_security_evidence",
                ["PRODUCER_INTERNAL_ERROR"],
                static_contract_diag_refs,
            ),
            "claimBoundaryMatrix": _make_surface_status("produced", len(claim_matrix), "claim_boundary_contract"),
            "claimBoundaries": _make_surface_status("produced", 1, "claim_boundary_contract"),
        }
        return {
            "schemaVersion": SCHEMA_VERSION,
            "bundleProfile": BUNDLE_PROFILE,
            "surfacePolicy": SURFACE_POLICY,
            "success": False,
            "bundleStatus": "failed",
            "evidenceCompleteness": {
                "status": "bounded_partial",
                "consumerPolicy": "not_complete_security_evidence",
            },
            "caseId": request.case_id,
            "buildTargetId": request.build_target_id,
            "s4RequestId": request_id,
            "s4ProducerRunId": producer_run_id,
            "bundleRef": bundle_ref,
            "producer": {
                "service": "s4-sast-runner",
                "serviceVersion": SERVICE_VERSION,
                "deterministic": True,
            },
            "provenance": _paper_provenance(request),
            "surfaceStatus": surface_status,
            "diagnostics": diagnostics,
            "findings": finding_rows,
            "evidence": evidence_rows,
            "sourceFiles": source_files,
            "functions": function_rows,
            "includeEdges": include_rows,
            "libraries": library_rows,
            "toolRuns": tool_runs,
            "targetMetadata": target_metadata,
            "staticEvidenceContract": {},
            "claimBoundaryMatrix": claim_matrix,
            "claimBoundaries": claim_boundaries,
        }

    claim_matrix = static_contract.get("claimBoundaryMatrix")
    claim_boundaries = static_contract.get("claimBoundaries")
    if not isinstance(claim_matrix, list) or not isinstance(claim_boundaries, dict):
        claim_matrix, claim_boundaries = _claim_boundary_fallback()
        static_contract["claimBoundaryMatrix"] = claim_matrix
        static_contract["claimBoundaries"] = claim_boundaries

    surface_status = {
        "findings": _make_surface_status(
            _status_for_array(len(finding_rows), diagnostic_refs=surface_diag_refs["findings"]),
            len(finding_rows),
            "empty_is_not_negative_evidence" if not finding_rows else "local_static_observation_only",
            ["TOOL_EXECUTION_PARTIAL"] if surface_diag_refs["findings"] else [],
            surface_diag_refs["findings"],
        ),
        "evidence": _make_surface_status(
            _status_for_array(len(evidence_rows), diagnostic_refs=surface_diag_refs["evidence"]),
            len(evidence_rows),
            "empty_is_not_negative_evidence" if not evidence_rows else "local_reviewer_visible_evidence",
            ["TOOL_EXECUTION_PARTIAL"] if surface_diag_refs["evidence"] else [],
            surface_diag_refs["evidence"],
        ),
        "sourceFiles": _make_surface_status(
            "produced",
            len(source_files),
            "local_static_structure_only",
        ),
        "functions": _make_surface_status(
            "failed" if surface_diag_refs["functions"] else _status_for_array(len(function_rows)),
            len(function_rows),
            "local_static_structure_only",
            ["SURFACE_PRODUCTION_FAILED"] if surface_diag_refs["functions"] else [],
            surface_diag_refs["functions"],
        ),
        "includeEdges": _make_surface_status(
            "failed" if surface_diag_refs["includeEdges"] else _status_for_array(len(include_rows)),
            len(include_rows),
            "local_static_structure_only",
            ["SURFACE_PRODUCTION_FAILED"] if surface_diag_refs["includeEdges"] else [],
            surface_diag_refs["includeEdges"],
        ),
        "libraries": _make_surface_status(
            "failed" if surface_diag_refs["libraries"] else _status_for_array(len(library_rows)),
            len(library_rows),
            "empty_is_not_no_vulnerable_dependencies" if not library_rows else "bounded_library_identity_only",
            ["SURFACE_PRODUCTION_FAILED"] if surface_diag_refs["libraries"] else [],
            surface_diag_refs["libraries"],
        ),
        "toolRuns": _make_surface_status(
            "partial" if surface_diag_refs["toolRuns"] else "produced",
            len(tool_runs),
            "local_tool_execution_state_only",
            ["TOOL_EXECUTION_PARTIAL"] if surface_diag_refs["toolRuns"] else [],
            surface_diag_refs["toolRuns"],
        ),
        "targetMetadata": _make_surface_status("produced", 1, "producer_metadata_only"),
        "staticEvidenceContract": _make_surface_status("produced", 1, "claim_boundary_contract"),
        "claimBoundaryMatrix": _make_surface_status("produced", len(claim_matrix), "claim_boundary_contract"),
        "claimBoundaries": _make_surface_status("produced", 1, "claim_boundary_contract"),
    }

    return {
        "schemaVersion": SCHEMA_VERSION,
        "bundleProfile": BUNDLE_PROFILE,
        "surfacePolicy": SURFACE_POLICY,
        "success": True,
        "bundleStatus": "produced",
        "evidenceCompleteness": {
            "status": "bounded_partial",
            "consumerPolicy": "not_complete_security_evidence",
        },
        "caseId": request.case_id,
        "buildTargetId": request.build_target_id,
        "s4RequestId": request_id,
        "s4ProducerRunId": producer_run_id,
        "bundleRef": bundle_ref,
        "producer": {
            "service": "s4-sast-runner",
            "serviceVersion": SERVICE_VERSION,
            "deterministic": True,
        },
        "provenance": _paper_provenance(request),
        "surfaceStatus": surface_status,
        "diagnostics": diagnostics,
        "findings": finding_rows,
        "evidence": evidence_rows,
        "sourceFiles": source_files,
        "functions": function_rows,
        "includeEdges": include_rows,
        "libraries": library_rows,
        "toolRuns": tool_runs,
        "targetMetadata": target_metadata,
        "staticEvidenceContract": static_contract,
        "claimBoundaryMatrix": claim_matrix,
        "claimBoundaries": claim_boundaries,
    }


def _validate_diagnostics(bundle: dict[str, Any], report: dict[str, Any]) -> set[str]:
    diagnostics = bundle.get("diagnostics")
    if not isinstance(diagnostics, list):
        _fail(report, "contractValidation", "DIAGNOSTICS_MISSING", "diagnostics[] must be present.")
        return set()
    ids: set[str] = set()
    required = {"diagnosticId", "severity", "category", "reasonCode", "surface", "message", "consumerPolicy", "trace"}
    for index, diagnostic in enumerate(diagnostics):
        path = f"$.diagnostics[{index}]"
        if not isinstance(diagnostic, dict):
            _fail(report, "contractValidation", "DIAGNOSTIC_ROW_INVALID", "Diagnostic row is invalid.", path)
            continue
        missing = required - set(diagnostic)
        if missing:
            _fail(report, "contractValidation", "DIAGNOSTIC_ROW_INVALID", "Diagnostic row missing required fields.", path)
        diag_id = diagnostic.get("diagnosticId")
        if not isinstance(diag_id, str) or not diag_id:
            _fail(report, "contractValidation", "DIAGNOSTIC_ROW_INVALID", "Diagnostic id is invalid.", path)
        elif diag_id in ids:
            _fail(report, "contractValidation", "DUPLICATE_ROW_ID", "Duplicate diagnostic id.", path)
        else:
            ids.add(diag_id)
        if diagnostic.get("category") not in DIAGNOSTIC_CATEGORIES:
            _fail(report, "contractValidation", "DIAGNOSTIC_CATEGORY_INVALID", "Diagnostic category is invalid.", path)
        if diagnostic.get("reasonCode") not in DIAGNOSTIC_REASON_CODES:
            _fail(report, "contractValidation", "DIAGNOSTIC_REASON_INVALID", "Diagnostic reason code is invalid.", path)
        if not _diagnostic_message_is_safe(diagnostic.get("message")):
            _fail(report, "contractValidation", "DIAGNOSTIC_MESSAGE_UNSAFE", "Diagnostic message is unsafe.", path)
        _validate_trace_object(diagnostic.get("trace"), report, path=path)
    return ids


def _validate_diagnostic_refs(
    *,
    refs: Any,
    diagnostic_ids: set[str],
    report: dict[str, Any],
    path: str,
    section: str = "contractValidation",
) -> None:
    if not isinstance(refs, list):
        _fail(report, section, "DIAGNOSTIC_REFS_MISSING", "diagnosticRefs must be an array.", path)
        return
    for ref in refs:
        if not isinstance(ref, str) or ref not in diagnostic_ids:
            _fail(report, section, "DIAGNOSTIC_REF_UNRESOLVED", "diagnosticRefs must resolve to diagnostics[].", path)


def _validate_surface_status(bundle: dict[str, Any], report: dict[str, Any], diagnostic_ids: set[str]) -> None:
    status_map = bundle.get("surfaceStatus")
    if not isinstance(status_map, dict):
        _fail(report, "contractValidation", "SURFACE_STATUS_INCOMPLETE", "surfaceStatus is missing.")
        return
    for surface in REQUIRED_SURFACES:
        entry = status_map.get(surface)
        path = f"$.surfaceStatus.{surface}"
        if not isinstance(entry, dict):
            _fail(report, "contractValidation", "SURFACE_STATUS_INCOMPLETE", "Required surfaceStatus entry is missing.", path)
            continue
        refs = entry.get("diagnosticRefs")
        _validate_diagnostic_refs(refs=refs, diagnostic_ids=diagnostic_ids, report=report, path=path)
        status = entry.get("status")
        if status not in SURFACE_STATUSES:
            _fail(report, "contractValidation", "SURFACE_STATUS_INVALID", "Surface status is invalid.", path)
        count = entry.get("count")
        if not isinstance(count, int) or count < 0:
            _fail(report, "contractValidation", "SURFACE_STATUS_INVALID", "Surface count is invalid.", path)
            continue
        actual_count = _surface_actual_count(bundle, surface)
        if actual_count is not None and count != actual_count:
            _fail(report, "contractValidation", "SURFACE_COUNT_MISMATCH", "Surface count must match emitted surface.", path)
        if status == "empty" and count != 0:
            _fail(report, "contractValidation", "EMPTY_SURFACE_COUNT_MISMATCH", "empty surfaces must have count 0.", path)
        if status not in NON_DIAGNOSTIC_SURFACE_STATUSES and not refs:
            _fail(report, "producerSanityValidation", "SURFACE_DIAGNOSTIC_REQUIRED", "Non-produced/non-empty surface needs diagnostics.", path)


def _validate_rows(bundle: dict[str, Any], report: dict[str, Any], diagnostic_ids: set[str]) -> None:
    observed_ids: set[str] = set()
    for surface in DIAGNOSTIC_CAPABLE_ARRAYS:
        rows = bundle.get(surface)
        if not isinstance(rows, list):
            _fail(report, "contractValidation", "REQUIRED_SURFACE_MISSING", "Required row surface is missing.", f"$.{surface}")
            continue
        id_field = ROW_ID_FIELDS[surface]
        for index, row in enumerate(rows):
            path = f"$.{surface}[{index}]"
            if not isinstance(row, dict):
                _fail(report, "contractValidation", "ROW_INVALID", "Row is invalid.", path)
                continue
            row_id = row.get(id_field)
            if not isinstance(row_id, str) or not row_id:
                _fail(report, "contractValidation", "ROW_ID_MISSING", "Row id is missing.", path)
            elif row_id in observed_ids:
                _fail(report, "contractValidation", "DUPLICATE_ROW_ID", "Duplicate row id.", path)
            else:
                observed_ids.add(row_id)
            _validate_trace_object(row.get("trace"), report, path=path)
            _validate_diagnostic_refs(
                refs=row.get("diagnosticRefs"),
                diagnostic_ids=diagnostic_ids,
                report=report,
                path=path,
            )
    target_metadata = bundle.get("targetMetadata")
    target_surface = bundle.get("surfaceStatus", {}).get("targetMetadata") if isinstance(bundle.get("surfaceStatus"), dict) else None
    target_empty_failed = (
        _is_failed_bundle(bundle)
        and isinstance(target_metadata, dict)
        and not target_metadata
        and isinstance(target_surface, dict)
        and target_surface.get("count") == 0
        and target_surface.get("status") not in NON_DIAGNOSTIC_SURFACE_STATUSES
    )
    if isinstance(target_metadata, dict) and target_metadata and not target_empty_failed:
        _validate_trace_object(target_metadata.get("trace"), report, path="$.targetMetadata")
    elif not target_empty_failed:
        _fail(report, "contractValidation", "ROW_TRACE_MISSING", "targetMetadata trace is missing.", "$.targetMetadata")


def _validate_claim_boundaries(bundle: dict[str, Any], report: dict[str, Any]) -> None:
    static_contract = bundle.get("staticEvidenceContract")
    if not isinstance(static_contract, dict):
        _fail(report, "contractValidation", "STATIC_EVIDENCE_CONTRACT_MISSING", "staticEvidenceContract is missing.")
        return
    matrix = bundle.get("claimBoundaryMatrix")
    boundaries = bundle.get("claimBoundaries")
    if not isinstance(boundaries, dict):
        _fail(report, "contractValidation", "CLAIM_BOUNDARY_MATRIX_INVALID", "claimBoundaries is invalid.")
    if static_contract and (static_contract.get("claimBoundaryMatrix") != matrix or static_contract.get("claimBoundaries") != boundaries):
        _fail(
            report,
            "contractValidation",
            "CLAIM_BOUNDARY_MIRROR_MISMATCH",
            "Top-level claim-boundary mirrors must match staticEvidenceContract.",
        )
    if not isinstance(matrix, list):
        _fail(report, "contractValidation", "CLAIM_BOUNDARY_MATRIX_INVALID", "claimBoundaryMatrix is invalid.")
        return
    claim_ids = {
        row.get("claimId")
        for row in matrix
        if isinstance(row, dict) and isinstance(row.get("claimId"), str)
    }
    for claim_id in REQUIRED_CLAIM_IDS:
        if claim_id not in claim_ids:
            _fail(report, "contractValidation", "CLAIM_BOUNDARY_REQUIRED_CLAIM_MISSING", "Required claim-boundary row is missing.")
    for row in matrix:
        if not isinstance(row, dict):
            continue
        if row.get("claimId") in {"absence-of-vulnerability", "cwe-absence", "final-security-verdict"}:
            if row.get("supportStatus") != "unsupported":
                _fail(
                    report,
                    "contractValidation",
                    "CLAIM_BOUNDARY_NEGATIVE_CLAIM_UNSAFE",
                    "Negative/final claims must remain unsupported.",
                )


def _validate_tool_runs(bundle: dict[str, Any], report: dict[str, Any]) -> None:
    tool_runs = bundle.get("toolRuns")
    if not isinstance(tool_runs, list):
        _fail(report, "producerSanityValidation", "CURRENT_SIX_TOOL_RUN_MISSING", "toolRuns[] is missing.")
        return
    by_tool = {
        row.get("toolId"): row
        for row in tool_runs
        if isinstance(row, dict) and isinstance(row.get("toolId"), str)
    }
    for row in tool_runs:
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        if status not in TOOL_RUN_STATUSES:
            _fail(report, "producerSanityValidation", "TOOL_RUN_STATUS_INVALID", "ToolRun status is invalid.")
        if status not in TOOL_RUN_SUCCESS_STATUSES and not row.get("diagnosticRefs"):
            _fail(report, "producerSanityValidation", "TOOL_RUN_DIAGNOSTIC_REQUIRED", "Non-success toolRun needs diagnostics.")
    if _is_failed_bundle(bundle):
        return
    for tool in CURRENT_SIX_TOOLS:
        row = by_tool.get(tool)
        if row is None:
            _fail(report, "producerSanityValidation", "CURRENT_SIX_TOOL_RUN_MISSING", "Current-six toolRun row is missing.")
            continue


def _validate_top_level(bundle: dict[str, Any], report: dict[str, Any]) -> None:
    required = {
        "schemaVersion",
        "bundleProfile",
        "surfacePolicy",
        "success",
        "bundleStatus",
        "evidenceCompleteness",
        "caseId",
        "buildTargetId",
        "s4RequestId",
        "s4ProducerRunId",
        "bundleRef",
        "producer",
        "provenance",
        "surfaceStatus",
        "diagnostics",
        "findings",
        "evidence",
        "sourceFiles",
        "functions",
        "includeEdges",
        "libraries",
        "toolRuns",
        "targetMetadata",
        "staticEvidenceContract",
        "claimBoundaryMatrix",
        "claimBoundaries",
    }
    missing = sorted(required - set(bundle))
    for field in missing:
        _fail(report, "contractValidation", "REQUIRED_FIELD_MISSING", "Required top-level field is missing.", f"$.{field}")
    if bundle.get("schemaVersion") != SCHEMA_VERSION:
        _fail(report, "contractValidation", "SCHEMA_VERSION_UNSUPPORTED", "Unsupported paper bundle schema version.")
    if bundle.get("bundleProfile") != BUNDLE_PROFILE:
        _fail(report, "contractValidation", "BUNDLE_PROFILE_UNSUPPORTED", "Unsupported paper bundle profile.")
    if bundle.get("surfacePolicy") != SURFACE_POLICY:
        _fail(report, "contractValidation", "SURFACE_POLICY_UNSUPPORTED", "Unsupported surface policy.")
    if bundle.get("success") is True and bundle.get("bundleStatus") != "produced":
        _fail(report, "contractValidation", "BUNDLE_STATUS_INVALID", "success=true requires bundleStatus=produced.")
    if bundle.get("success") is False and bundle.get("bundleStatus") != "failed":
        _fail(report, "contractValidation", "BUNDLE_STATUS_INVALID", "success=false requires bundleStatus=failed.")
    if bundle.get("success") is False and bundle.get("bundleStatus") == "failed":
        diagnostics = bundle.get("diagnostics")
        if not isinstance(diagnostics, list) or not diagnostics:
            _fail(
                report,
                "contractValidation",
                "FAILED_BUNDLE_DIAGNOSTICS_REQUIRED",
                "failed bundle requires producer diagnostics.",
            )


def validate_paper_static_evidence_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    bundle_ref = bundle.get("bundleRef") if isinstance(bundle, dict) else None
    report = _new_validation_report(bundle_ref)
    if not isinstance(bundle, dict):
        _fail(report, "contractValidation", "BUNDLE_INVALID", "Paper static-evidence bundle must be an object.")
        return report

    _validate_top_level(bundle, report)
    _scan_forbidden_semantics(bundle, report)
    diagnostic_ids = _validate_diagnostics(bundle, report)
    _validate_surface_status(bundle, report, diagnostic_ids)
    _validate_rows(bundle, report, diagnostic_ids)
    _validate_claim_boundaries(bundle, report)
    _validate_tool_runs(bundle, report)
    return report


def write_paper_static_evidence_artifacts(case_root: Path | str, bundle: dict[str, Any]) -> dict[str, Any]:
    root = Path(case_root)
    root.mkdir(parents=True, exist_ok=True)
    report = validate_paper_static_evidence_bundle(bundle)
    (root / "s4-static-evidence.raw.json").write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "s4-static-evidence.validation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def validate_current_six_liveness(tool_availability: dict[str, dict[str, Any]]) -> dict[str, Any]:
    failures = []
    for tool in CURRENT_SIX_TOOLS:
        info = tool_availability.get(tool) or {}
        if not info.get("available", False):
            failures.append(
                {
                    "toolId": tool,
                    "reasonCode": info.get("probeReason") or "runtime-tool-missing",
                    "versionStatus": "present" if info.get("version") else "missing",
                    "expectedExecutablePathStatus": info.get("expectedExecutablePathStatus") or "not-configured",
                },
            )
    return {
        "schemaVersion": "s4-current-six-liveness-gate-v1",
        "gate": "current-six-liveness",
        "status": "fail" if failures else "pass",
        "requiredTools": list(CURRENT_SIX_TOOLS),
        "failures": failures,
    }


def paper_reviewer_visible_rows(bundle: dict[str, Any], *, packet_condition: str) -> list[str]:
    del packet_condition
    rows = bundle.get("evidence", [])
    result = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("text"), str):
                result.append(row["text"])
    diagnostics = bundle.get("diagnostics", [])
    if isinstance(diagnostics, list):
        for diagnostic in diagnostics:
            if isinstance(diagnostic, dict) and isinstance(diagnostic.get("message"), str):
                result.append(diagnostic["message"])
    return result
