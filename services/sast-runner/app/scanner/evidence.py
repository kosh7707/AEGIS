"""Deterministic evidence-resolution helpers for S4 outputs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from app.schemas.response import SastFinding

SCHEMA_VERSION = "s4-evidence-v1"
FINDING_EVIDENCE_KEY = "evidenceResolution"


def enrich_findings_evidence(findings: Iterable[SastFinding]) -> list[SastFinding]:
    """Return findings annotated with namespaced deterministic evidence."""
    return [enrich_finding_evidence(finding) for finding in findings]


def enrich_finding_evidence(finding: SastFinding) -> SastFinding:
    """Annotate a finding without changing its legacy top-level fields."""
    metadata: dict[str, Any] = dict(finding.metadata or {})
    cwe_id, cwe_source = _extract_cwe(metadata)
    data_flow = finding.data_flow or []
    diagnostics: list[str] = []

    if cwe_id is None:
        diagnostics.append("CWE_UNKNOWN")
    if not data_flow:
        diagnostics.append("DATAFLOW_NOT_PROVIDED")

    metadata[FINDING_EVIDENCE_KEY] = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "sast-finding",
        "toolId": finding.tool_id,
        "ruleId": finding.rule_id,
        "cwe": {
            "status": "known" if cwe_id else "unknown",
            "id": cwe_id,
            "source": cwe_source,
        },
        "location": {
            "status": "present",
            "file": finding.location.file,
            "line": finding.location.line,
            "column": finding.location.column,
            "endLine": finding.location.end_line,
            "endColumn": finding.location.end_column,
        },
        "dataFlow": {
            "present": bool(data_flow),
            "stepCount": len(data_flow),
        },
        "origin": {
            "status": finding.origin or "user-code",
            "source": "top-level-origin" if finding.origin else "default",
        },
        "diagnostics": diagnostics,
    }
    return finding.model_copy(update={"metadata": metadata})


def project_libraries_evidence(
    libraries: Iterable[Mapping[str, Any]],
    *,
    provenance: Any | None = None,
    diff_computed: bool,
) -> list[dict[str, Any]]:
    """Project library identification into an additive evidence shape."""
    return [
        project_library_evidence(
            library,
            provenance=provenance,
            diff_computed=diff_computed,
        )
        for library in libraries
    ]


def project_library_evidence(
    library: Mapping[str, Any],
    *,
    provenance: Any | None = None,
    diff_computed: bool,
) -> dict[str, Any]:
    """Preserve legacy library fields while adding deterministic diagnostics."""
    name = library.get("name")
    version = library.get("version")
    source = library.get("source")
    repo_url = library.get("repoUrl") or library.get("remoteUrl")
    diff = library.get("diff")
    diff_available = diff is not None
    diagnostics: list[str] = []

    if version is None:
        diagnostics.append("VERSION_UNKNOWN")
    if repo_url is None:
        diagnostics.append("REPO_URL_UNKNOWN")
    if diff_computed:
        if not diff_available:
            diagnostics.append("DIFF_UNAVAILABLE")
    else:
        diagnostics.append("DIFF_NOT_COMPUTED")

    return {
        "name": name,
        "version": version,
        "path": library.get("path"),
        "repoUrl": repo_url,
        "source": source,
        "commit": library.get("commit"),
        "branch": library.get("branch"),
        "tag": _library_tag(library),
        "nearestTag": library.get("nearestTag"),
        "identificationConfidence": _identification_confidence(source),
        "versionStatus": "known" if version is not None else "unknown",
        "versionConfidence": _version_confidence(source, version),
        "cveLookupEligible": bool(name and version),
        "versionEvidence": {
            "status": "observed" if version is not None else "missing",
            "source": source,
            "value": version,
        },
        "diagnostics": diagnostics,
        "diffAvailable": diff_available,
        "modificationStatus": _modification_status(diff) if diff_available else "unknown",
        "diffSummary": diff if diff_available else None,
        "provenance": _normalize_provenance(provenance, library.get("path")),
    }


def _extract_cwe(metadata: Mapping[str, Any]) -> tuple[str | None, str | None]:
    cwe_id = metadata.get("cweId")
    if cwe_id:
        return str(cwe_id), "metadata.cweId"

    cwe_values = metadata.get("cwe")
    if isinstance(cwe_values, list) and cwe_values:
        return str(cwe_values[0]), "metadata.cwe[0]"

    return None, None


def _library_tag(library: Mapping[str, Any]) -> Any | None:
    tag = library.get("tag")
    if tag is not None:
        return tag
    if library.get("source") == "git" and library.get("version") and not library.get("nearestTag"):
        return library.get("version")
    return None


def _identification_confidence(source: Any | None) -> str:
    if not source:
        return "low"
    source_text = str(source).lower()
    if source_text == "directory_name":
        return "low"
    if source_text.startswith("readme"):
        return "medium"
    return "high"


def _version_confidence(source: Any | None, version: Any | None) -> str:
    if version is None:
        return "none"
    if str(source or "").lower().startswith("readme"):
        return "medium"
    return "high"


def _modification_status(diff: Any) -> str:
    if not isinstance(diff, Mapping):
        return "unknown"

    for key in ("modifiedFiles", "modified_files"):
        value = diff.get(key)
        if isinstance(value, int):
            return "modified" if value > 0 else "unmodified"

    files = diff.get("files")
    if isinstance(files, list):
        return "modified" if files else "unmodified"

    return "unknown"


def _normalize_provenance(
    provenance: Any | None,
    library_path: Any | None,
) -> dict[str, Any] | None:
    if provenance is None:
        return None

    if hasattr(provenance, "model_dump"):
        normalized = provenance.model_dump(by_alias=True, exclude_none=True)
    elif isinstance(provenance, Mapping):
        normalized = {str(key): value for key, value in provenance.items() if value is not None}
    else:
        return None

    if library_path is not None:
        normalized["libraryPath"] = str(library_path)
    return normalized
