"""Executable source coverage matrix for S5 threat knowledge ETL.

The matrix is a data-quality/coverage gate, not service health. It answers
which source families support S5's C/C++ native Threat KB answer axes and
whether a manifest slice is allowed to make fixture, cached, or production
coverage claims.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

DEFAULT_SOURCE_COVERAGE_MATRIX_PATH = Path(__file__).resolve().parents[2] / "config" / "source-coverage-matrix-v1.json"
COVERAGE_GATE_KIND = "source_coverage_quality_gate_not_service_health"
PROFILE_ORDER = {
    "deferred": 0,
    "manifest_only": 0,
    "fixture_slice": 1,
    "cached_catalog_snapshot": 2,
    "production_snapshot": 3,
    "full_cwe_expected": 3,
}
NON_HEALTH_FIELDS = {"ready", "readiness", "health", "serviceHealth", "systemStability", "projectionFreshness", "neo4jReady", "qdrantReady"}
DEFAULT_FIRST_CLASS_SOURCE_KIND_ALLOWLIST = {
    "knowledge-corpus-v1",
    "golden-set-v1",
    "CWE",
    "CAPEC",
    "ATTACK_ENTERPRISE",
    "ATTACK_ICS",
    "OSV",
    "NVD_CVE",
    "GHSA",
    "package-identity",
    "CISA_KEV",
    "FIRST_EPSS",
    "semgrep",
    "cppcheck",
    "clang-tidy",
    "gcc-fanalyzer",
    "scan-build",
    "flawfinder",
}


def load_source_coverage_matrix(path: Path | str | None = None) -> dict[str, Any]:
    """Load the v1 source coverage matrix from JSON."""

    matrix_path = Path(path) if path is not None else DEFAULT_SOURCE_COVERAGE_MATRIX_PATH
    return json.loads(matrix_path.read_text(encoding="utf-8"))


def _sources(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    sources = manifest.get("sources")
    return sources if isinstance(sources, list) else []


def _diag(code: str, message: str, *, severity: str = "error", **extra: Any) -> dict[str, Any]:
    return {"code": code, "severity": severity, "message": message, **extra}


def _profile_at_least(actual: str, minimum: str) -> bool:
    return PROFILE_ORDER.get(actual, -1) >= PROFILE_ORDER.get(minimum, 999)


def _validate_native_scope(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    domain_first_class = {str(item) for item in matrix.get("domainScope", {}).get("firstClass", [])}
    language_first_class = {str(item) for item in matrix.get("languageScope", {}).get("firstClass", [])}
    excluded_first_class = {str(item) for item in matrix.get("languageScope", {}).get("excludedFirstClass", [])}
    if not {"native", "system"} <= domain_first_class:
        diagnostics.append(
            _diag(
                "NATIVE_DOMAIN_SCOPE_MISSING",
                "S5 source coverage must declare native/system first-class domain scope.",
                domainFirstClass=sorted(domain_first_class),
            )
        )
    if not {"c", "cpp"} <= language_first_class:
        diagnostics.append(
            _diag(
                "CPP_LANGUAGE_SCOPE_MISSING",
                "S5 source coverage must declare C and C++ as first-class languages.",
                languageFirstClass=sorted(language_first_class),
            )
        )
    illegal_first_class = sorted(language_first_class & excluded_first_class)
    if illegal_first_class:
        diagnostics.append(
            _diag(
                "EXCLUDED_LANGUAGE_MARKED_FIRST_CLASS",
                "Excluded/non-goal ecosystems cannot satisfy first-class S5 source coverage.",
                illegalFirstClass=illegal_first_class,
            )
        )
    non_native_only = language_first_class and not (language_first_class & {"c", "cpp"})
    if non_native_only:
        diagnostics.append(
            _diag(
                "NON_NATIVE_ONLY_SCOPE_REJECTED",
                "A non-native-only matrix cannot satisfy first-class S5 C/C++ coverage.",
                languageFirstClass=sorted(language_first_class),
            )
        )
    return diagnostics


def _role_state_for_missing(role: dict[str, Any], missing: list[str]) -> str:
    if not role.get("requiredSourceKinds") and role.get("deferredSourceKinds"):
        return "deferred_not_required_for_fixture_corpus"
    if missing:
        return "missing_required_source_kinds"
    return "present"


def evaluate_source_coverage(manifest: dict[str, Any], matrix: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate a source manifest against the S5 source coverage matrix."""

    matrix = copy.deepcopy(matrix if matrix is not None else load_source_coverage_matrix())
    diagnostics: list[dict[str, Any]] = []
    if matrix.get("schemaVersion") != "s5-source-coverage-matrix-v1":
        diagnostics.append(_diag("INVALID_MATRIX_SCHEMA", "matrix schemaVersion must be s5-source-coverage-matrix-v1"))
    if matrix.get("coverageGateKind") != COVERAGE_GATE_KIND:
        diagnostics.append(
            _diag(
                "INVALID_COVERAGE_GATE_KIND",
                "coverageGateKind must be source_coverage_quality_gate_not_service_health",
                actual=matrix.get("coverageGateKind"),
            )
        )
    diagnostics.extend(_validate_native_scope(matrix))

    source_by_kind: dict[str, list[dict[str, Any]]] = {}
    for source in _sources(manifest):
        source_by_kind.setdefault(str(source.get("sourceKind")), []).append(source)
    first_class_source_allowlist = {
        str(kind)
        for kind in matrix.get("firstClassSourceKindAllowlist", sorted(DEFAULT_FIRST_CLASS_SOURCE_KIND_ALLOWLIST))
    }

    roles: list[dict[str, Any]] = []
    present_role_count = 0
    deferred_role_count = 0
    hard_fail = False

    for role in matrix.get("roles", []):
        role_id = str(role.get("roleId"))
        required_kinds = [str(kind) for kind in role.get("requiredSourceKinds", [])]
        present_kinds = sorted(kind for kind in required_kinds if kind in source_by_kind)
        missing_kinds = sorted(kind for kind in required_kinds if kind not in source_by_kind)
        role_diags: list[dict[str, Any]] = []
        role_hard_fail = False
        non_native_required_kinds = sorted(kind for kind in required_kinds if kind not in first_class_source_allowlist)
        if non_native_required_kinds:
            role_diags.append(
                _diag(
                    "NON_NATIVE_SOURCE_KIND_NOT_ALLOWED_FOR_FIRST_CLASS_COVERAGE",
                    "A first-class S5 coverage role cannot be satisfied by non-native ecosystem-only source kinds.",
                    roleId=role_id,
                    nonNativeSourceKinds=non_native_required_kinds,
                    allowedSourceKinds=sorted(first_class_source_allowlist),
                )
            )
            role_hard_fail = True

        if role_id == "risk_exploitation_signal":
            if set(role.get("answerAxes", [])) != {"C"}:
                role_diags.append(
                    _diag(
                        "RISK_SIGNAL_AXIS_NOT_C_ONLY",
                        "Risk exploitation signals are prioritization-only axis C and cannot satisfy affectedness axis A.",
                        roleId=role_id,
                        answerAxes=role.get("answerAxes", []),
                    )
                )
                role_hard_fail = True
            if "CVSS" in required_kinds:
                role_diags.append(
                    _diag(
                        "CVSS_STANDALONE_SOURCE_KIND_FORBIDDEN_V1",
                        "CVSS is extracted from NVD_CVE in v1 and must not be a required standalone source kind.",
                        roleId=role_id,
                    )
                )
                role_hard_fail = True

        if missing_kinds and role.get("hardFailIfMissing") is True:
            role_diags.append(
                _diag(
                    "ROLE_REQUIRED_SOURCE_KINDS_MISSING",
                    "Required source kinds are missing for a hard-fail coverage role.",
                    roleId=role_id,
                    missingSourceKinds=missing_kinds,
                )
            )
            role_hard_fail = True

        allowed_profiles = {str(profile) for profile in role.get("allowedCoverageProfiles", [])}
        minimum_profile = str(role.get("minimumCoverageProfile", "fixture_slice"))
        role_sources: list[dict[str, Any]] = []
        profile_violations: list[dict[str, Any]] = []
        for kind in present_kinds:
            for source in source_by_kind.get(kind, []):
                profile = str(source.get("coverageProfile"))
                role_sources.append(
                    {
                        "sourceKind": kind,
                        "sourceId": source.get("sourceId"),
                        "coverageProfile": profile,
                        "coverageStatus": source.get("coverageStatus"),
                        "completedCoverage": source.get("completedCoverage"),
                    }
                )
                if allowed_profiles and profile not in allowed_profiles:
                    profile_violations.append({"sourceKind": kind, "coverageProfile": profile, "reason": "not_allowed_for_role"})
                if not _profile_at_least(profile, minimum_profile):
                    profile_violations.append(
                        {
                            "sourceKind": kind,
                            "coverageProfile": profile,
                            "minimumCoverageProfile": minimum_profile,
                            "reason": "below_minimum_profile",
                        }
                    )
                if minimum_profile in {"cached_catalog_snapshot", "production_snapshot", "full_cwe_expected"} and profile == "fixture_slice":
                    profile_violations.append(
                        {
                            "sourceKind": kind,
                            "coverageProfile": profile,
                            "minimumCoverageProfile": minimum_profile,
                            "reason": "fixture_slice_cannot_satisfy_catalog_or_production_claim",
                        }
                    )
        if profile_violations:
            role_diags.append(
                _diag(
                    "ROLE_COVERAGE_PROFILE_VIOLATION",
                    "One or more sources use a coverage profile that cannot satisfy the role.",
                    roleId=role_id,
                    profileViolations=profile_violations,
                )
            )
            role_hard_fail = role_hard_fail or role.get("hardFailIfMissing") is True

        if role.get("liveDownloadDefault") is not False:
            role_diags.append(
                _diag(
                    "LIVE_DOWNLOAD_DEFAULT_ENABLED",
                    "Loop 8 matrix must keep live download disabled by default.",
                    roleId=role_id,
                    liveDownloadDefault=role.get("liveDownloadDefault"),
                )
            )
            role_hard_fail = True

        state = _role_state_for_missing(role, missing_kinds)
        if state == "present" and not role_hard_fail:
            present_role_count += 1
        if state == "deferred_not_required_for_fixture_corpus":
            deferred_role_count += 1
        hard_fail = hard_fail or role_hard_fail
        diagnostics.extend(role_diags)
        roles.append(
            {
                "roleId": role_id,
                "state": state,
                "answerAxes": role.get("answerAxes", []),
                "requiredSourceKinds": required_kinds,
                "presentSourceKinds": present_kinds,
                "missingRequiredSourceKinds": missing_kinds,
                "deferredSourceKinds": role.get("deferredSourceKinds", []),
                "deferredReason": role.get("deferredReason"),
                "hardFailIfMissing": bool(role.get("hardFailIfMissing")),
                "manualCacheAllowed": bool(role.get("manualCacheAllowed")),
                "liveDownloadDefault": role.get("liveDownloadDefault"),
                "minimumCoverageProfile": minimum_profile,
                "allowedCoverageProfiles": sorted(allowed_profiles),
                "productionCoverageRequires": role.get("productionCoverageRequires", []),
                "sources": role_sources,
                "diagnostics": role_diags,
            }
        )

    error_count = sum(1 for item in diagnostics if item.get("severity") == "error")
    if hard_fail or error_count:
        status = "rejected"
        hard_fail = True
    elif deferred_role_count:
        status = "accepted_with_caveats"
    else:
        status = "accepted"

    return {
        "schemaVersion": "s5-source-coverage-evaluation-v1",
        "matrixId": matrix.get("matrixId"),
        "matrixVersion": matrix.get("matrixVersion"),
        "domainScope": matrix.get("domainScope", {}),
        "languageScope": matrix.get("languageScope", {}),
        "coverageGate": {
            "kind": COVERAGE_GATE_KIND,
            "status": status,
            "hardFail": hard_fail,
            "reasons": [diag["code"] for diag in diagnostics if diag.get("severity") == "error"],
            "scopeSemantic": "data_quality_coverage_only_not_runtime_readiness",
        },
        "hardFail": hard_fail,
        "roleCount": len(roles),
        "presentRoleCount": present_role_count,
        "deferredRoleCount": deferred_role_count,
        "roles": roles,
        "missingRequiredSourceKinds": sorted(
            {kind for role in roles for kind in role.get("missingRequiredSourceKinds", []) if role.get("hardFailIfMissing")}
        ),
        "sourceKindsEvaluated": sorted(source_by_kind),
        "coverageProfilesEvaluated": sorted({str(source.get("coverageProfile")) for source in _sources(manifest)}),
        "liveDownloadPolicy": {
            "default": "disabled",
            "networkAccess": "not_attempted",
            "manualCacheAllowedRoles": sorted(role["roleId"] for role in roles if role.get("manualCacheAllowed")),
        },
        "firstClassSourceKindAllowlist": sorted(first_class_source_allowlist),
        "diagnostics": diagnostics,
        "forbiddenHealthFieldsAbsent": not bool(NON_HEALTH_FIELDS & set(matrix.keys())),
    }


def validate_source_coverage(manifest: dict[str, Any], matrix: dict[str, Any] | None = None) -> list[str]:
    """Return human-readable coverage validation errors."""

    evaluation = evaluate_source_coverage(manifest, matrix)
    issues = [f"{diag['code']}: {diag['message']}" for diag in evaluation.get("diagnostics", []) if diag.get("severity") == "error"]
    if evaluation.get("coverageGate", {}).get("kind") != COVERAGE_GATE_KIND:
        issues.append("coverageGate.kind must be source_coverage_quality_gate_not_service_health")
    return issues
