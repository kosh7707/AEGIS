from __future__ import annotations

import re
from typing import Any

from .errors import PaperContractError

S4_REQUIRED_TOP = {
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
S4_REQUIRED_SURFACES = {
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
S4_SURFACE_STATUSES = {"produced", "empty", "partial", "not_available", "error", "failed", "skipped"}
S5_SURFACE_STATUSES = {"produced", "no_hit", "partial", "not_available", "error"}
FORBIDDEN_KEYS = {
    "verdict",
    "finalVerdict",
    "triageLabel",
    "truePositive",
    "falsePositive",
    "vulnerable",
    "safe",
    "clean",
    "affected",
    "affectednessProof",
    "notAffected",
    "exploitabilityProven",
    "absenceEvidence",
    "riskScore",
    "checksum",
    "sha256",
    "hash",
    "digest",
    "fingerprint",
    "artifactHash",
    "replayHash",
}
S5_FORBIDDEN_KEYS = FORBIDDEN_KEYS | {"TP", "FP", "UNKNOWN"}
FORBIDDEN_LEAKAGE_VALUES = [
    re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    re.compile(r"\bfix[-_ ]?commit\b", re.IGNORECASE),
    re.compile(r"\badvisory\b", re.IGNORECASE),
    re.compile(r"\bexploit\b", re.IGNORECASE),
    re.compile(r"\bpatch text\b", re.IGNORECASE),
]
FORBIDDEN_VERDICT_VALUE_RE = re.compile(
    r"\b(vulnerable|safe|affected|not[_ -]?affected|true positive|false positive)\b",
    re.IGNORECASE,
)


def _walk(obj: Any, path: str = ""):
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}" if path else str(key)
            yield child, key, value
            yield from _walk(value, child)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _walk(value, f"{path}[{i}]")


def _assert_no_forbidden_keys(obj: Any, forbidden: set[str], *, source: str) -> None:
    for path, key, _value in _walk(obj):
        if key in forbidden:
            raise PaperContractError(f"{source} emitted forbidden field {key!r} at {path}")


def validate_s4_bundle(bundle: dict[str, Any], *, case_id: str, build_target_id: str) -> None:
    missing = sorted(S4_REQUIRED_TOP - set(bundle))
    if missing:
        raise PaperContractError(f"S4 bundle missing required top-level fields: {missing}")
    _assert_no_forbidden_keys(bundle, FORBIDDEN_KEYS, source="S4")
    if bundle["caseId"] != case_id or bundle["buildTargetId"] != build_target_id:
        raise PaperContractError("S4 bundle case/buildTarget identity mismatch")
    if bundle.get("bundleStatus") not in {"produced", "failed"}:
        raise PaperContractError("S4 bundleStatus must be produced|failed")
    if bundle.get("success") is not True or bundle.get("bundleStatus") != "produced":
        raise PaperContractError("S4 bundle is non-consumable", detail={"bundleStatus": bundle.get("bundleStatus")})
    for array_name in ["findings", "evidence", "sourceFiles", "functions", "includeEdges", "libraries", "toolRuns", "diagnostics", "claimBoundaryMatrix"]:
        if not isinstance(bundle.get(array_name), list):
            raise PaperContractError(f"S4 {array_name} must be an array")
    diagnostic_ids: set[str] = set()
    for i, diagnostic in enumerate(bundle["diagnostics"]):
        if not isinstance(diagnostic, dict):
            raise PaperContractError(f"S4 diagnostics[{i}] must be an object")
        diagnostic_id = diagnostic.get("diagnosticId")
        if not isinstance(diagnostic_id, str) or not diagnostic_id.strip():
            raise PaperContractError(f"S4 diagnostics[{i}].diagnosticId must be a non-empty string")
        if diagnostic_id in diagnostic_ids:
            raise PaperContractError(f"S4 duplicate diagnosticId: {diagnostic_id}")
        diagnostic_ids.add(diagnostic_id)
    status = bundle.get("surfaceStatus") or {}
    missing_surfaces = sorted(S4_REQUIRED_SURFACES - set(status))
    if missing_surfaces:
        raise PaperContractError(f"S4 surfaceStatus missing required surfaces: {missing_surfaces}")
    diagnostic_statuses = {"partial", "failed", "skipped", "not_available", "error"}
    for surface, value in status.items():
        if not isinstance(value, dict):
            raise PaperContractError(f"S4 surfaceStatus.{surface} must be an object")
        surface_status = value.get("status")
        if surface_status not in S4_SURFACE_STATUSES:
            raise PaperContractError(f"S4 surfaceStatus.{surface}.status is unknown")
        for required in ["count", "consumerPolicy", "reasonCodes", "diagnosticRefs"]:
            if required not in value:
                raise PaperContractError(f"S4 surfaceStatus.{surface} missing {required}")
        if not isinstance(value["diagnosticRefs"], list):
            raise PaperContractError(f"S4 surfaceStatus.{surface}.diagnosticRefs must be an array")
        invalid_refs = [ref for ref in value["diagnosticRefs"] if not isinstance(ref, str) or not ref.strip()]
        if invalid_refs:
            raise PaperContractError(f"S4 surfaceStatus.{surface}.diagnosticRefs must contain non-empty strings")
        if surface_status in diagnostic_statuses and not value["diagnosticRefs"]:
            raise PaperContractError(f"S4 surfaceStatus.{surface}.{surface_status} requires diagnosticRefs")
        unresolved = [ref for ref in value["diagnosticRefs"] if ref not in diagnostic_ids]
        if unresolved:
            raise PaperContractError(f"S4 surfaceStatus.{surface}.diagnosticRefs unresolved: {unresolved}")
    for surface in ["findings", "evidence", "sourceFiles", "functions", "includeEdges", "libraries", "toolRuns"]:
        _validate_s4_rows(bundle[surface], surface, diagnostic_ids=diagnostic_ids)
    if not isinstance(bundle.get("targetMetadata"), dict) or "trace" not in bundle["targetMetadata"]:
        raise PaperContractError("S4 targetMetadata.trace is required")
    nested = bundle.get("staticEvidenceContract") or {}
    if isinstance(nested, dict):
        if "claimBoundaryMatrix" in nested and nested["claimBoundaryMatrix"] != bundle.get("claimBoundaryMatrix"):
            raise PaperContractError("S4 claimBoundaryMatrix top-level mirror mismatch")
        if "claimBoundaries" in nested and nested["claimBoundaries"] != bundle.get("claimBoundaries"):
            raise PaperContractError("S4 claimBoundaries top-level mirror mismatch")


def _validate_s4_rows(rows: list[Any], surface: str, *, diagnostic_ids: set[str]) -> None:
    id_fields = {
        "findings": "findingId",
        "evidence": "evidenceId",
        "sourceFiles": "sourceFileId",
        "functions": "functionId",
        "includeEdges": "includeEdgeId",
        "libraries": "libraryId",
        "toolRuns": "toolRunId",
    }
    seen: set[str] = set()
    id_field = id_fields[surface]
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise PaperContractError(f"S4 {surface}[{i}] must be an object")
        if "trace" not in row:
            raise PaperContractError(f"S4 {surface}[{i}] missing row-local trace")
        if "diagnosticRefs" not in row:
            raise PaperContractError(f"S4 {surface}[{i}] missing diagnosticRefs array")
        if not isinstance(row["diagnosticRefs"], list):
            raise PaperContractError(f"S4 {surface}[{i}].diagnosticRefs must be an array")
        unresolved = [ref for ref in row["diagnosticRefs"] if ref not in diagnostic_ids]
        if unresolved:
            raise PaperContractError(f"S4 {surface}[{i}].diagnosticRefs unresolved: {unresolved}")
        if surface == "toolRuns" and row.get("coverageDegraded") is True:
            coverage_reasons = row.get("coverageReasons")
            if not isinstance(coverage_reasons, list) or not coverage_reasons:
                raise PaperContractError(f"S4 {surface}[{i}].coverageDegraded requires coverageReasons")
            if not row["diagnosticRefs"]:
                raise PaperContractError(f"S4 {surface}[{i}].coverageDegraded requires diagnosticRefs")
        row_id = row.get(id_field)
        if not row_id:
            raise PaperContractError(f"S4 {surface}[{i}] missing {id_field}")
        if row_id in seen:
            raise PaperContractError(f"S4 duplicate {id_field}: {row_id}")
        seen.add(row_id)


def validate_s5_contract_snapshot(snapshot: dict[str, Any]) -> None:
    if snapshot.get("consumerBoundary") != "contextual_support_not_final_verdict":
        raise PaperContractError("S5 contract snapshot missing non-verdict consumer boundary")
    policies = snapshot.get("policies") or {}
    if policies.get("mainlineVisibilityMode") != "generic":
        raise PaperContractError("S5 contract snapshot must declare generic mainline visibility")
    endpoints = snapshot.get("endpoints") or []
    names = {e.get("toolName") for e in endpoints if isinstance(e, dict)}
    required = {"prepare_code_kb", "retrieve_finding_context", "retrieve_generic_threat_context"}
    if not required.issubset(names):
        raise PaperContractError("S5 contract snapshot missing required paper tools")


def validate_s5_response(
    data: dict[str, Any],
    *,
    expected_case_id: str,
    expected_build_target_id: str,
    expected_finding_id: str | None = None,
    require_rows: bool = False,
) -> None:
    _assert_no_forbidden_keys(data, S5_FORBIDDEN_KEYS, source="S5")
    if data.get("caseId") != expected_case_id or data.get("buildTargetId") != expected_build_target_id:
        raise PaperContractError("S5 response case/buildTarget identity mismatch")
    if expected_finding_id is not None and data.get("findingId") != expected_finding_id:
        raise PaperContractError("S5 response findingId mismatch")
    status = data.get("surfaceStatus")
    if status not in S5_SURFACE_STATUSES:
        raise PaperContractError("S5 response surfaceStatus is unknown")
    rows = data.get("rows", [])
    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise PaperContractError("S5 rows must be an array")
    if require_rows and status == "produced" and not rows:
        raise PaperContractError("S5 produced response must include rows")
    for i, row in enumerate(rows):
        validate_s5_row(row, index=i)
    for diag in data.get("diagnostics", []) or []:
        if diag.get("negativeEvidenceAllowed") is not False:
            raise PaperContractError("S5 diagnostics must set negativeEvidenceAllowed=false")
        policy = str(diag.get("consumerPolicy", ""))
        if "diagnostic" not in policy or "not_security_evidence" not in policy:
            raise PaperContractError("S5 diagnostics must be diagnostic-only, not security evidence")
        _assert_visible_text_safe(diag)
    trace = data.get("retrievalTrace")
    if trace is not None:
        if trace.get("b2b4StableRows") is not True:
            raise PaperContractError("S5 retrievalTrace.b2b4StableRows must be true")
        if not trace.get("orderingPolicy"):
            raise PaperContractError("S5 retrievalTrace.orderingPolicy is required")
        _assert_visible_text_safe(trace)


def validate_s5_row(row: Any, *, index: int = 0) -> None:
    if not isinstance(row, dict):
        raise PaperContractError(f"S5 rows[{index}] must be an object")
    required = ["retrievalRunId", "itemId", "sourceType", "queryIntent", "sourceEvidence", "surfaceStatus", "visibleLeakageClass", "text", "producerTrace"]
    missing = [name for name in required if name not in row]
    if missing:
        raise PaperContractError(f"S5 rows[{index}] missing required fields: {missing}")
    if row["surfaceStatus"] not in S5_SURFACE_STATUSES:
        raise PaperContractError(f"S5 rows[{index}].surfaceStatus is unknown")
    if row["visibleLeakageClass"] != "generic":
        raise PaperContractError("S5 mainline visible rows must have visibleLeakageClass=generic")
    _assert_visible_text_safe(row)


def _assert_visible_text_safe(obj: Any) -> None:
    for path, key, value in _walk(obj):
        for pattern in FORBIDDEN_LEAKAGE_VALUES:
            if pattern.search(str(key)):
                raise PaperContractError(f"S5 visible field contains forbidden leakage in key at {path}")
        if FORBIDDEN_VERDICT_VALUE_RE.search(str(key)):
            raise PaperContractError(f"S5 visible field contains verdict-like key at {path}")
        if isinstance(value, str):
            if FORBIDDEN_VERDICT_VALUE_RE.search(value):
                raise PaperContractError(f"S5 visible field contains verdict-like language at {path}")
            for pattern in FORBIDDEN_LEAKAGE_VALUES:
                if pattern.search(value):
                    raise PaperContractError(f"S5 visible field contains forbidden leakage at {path}")


def validate_no_status_to_verdict(status: str | None) -> None:
    if status in {"no_hit", "partial", "not_available", "error"}:
        return
