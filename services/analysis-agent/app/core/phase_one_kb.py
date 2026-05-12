"""KB/CVE/project-memory helpers for analysis-agent Phase 1."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import TYPE_CHECKING

import httpx

from app.clients.kb_error_utils import is_kb_not_ready_error, is_kb_timeout_error
from app.agent_runtime.context import get_request_id
from app.agent_runtime.observability import agent_log
from app.config import settings

if TYPE_CHECKING:
    from app.core.phase_one_types import Phase1Result


_CWE_RE = re.compile(r"CWE-(\d+)")
_DANGEROUS_FUNCS = {
    "popen", "system", "exec", "execl", "execlp", "execle", "execv", "execvp",
    "getenv", "readlink", "access", "mkstemp", "mktemp",
    "strcpy", "strcat", "sprintf", "gets", "scanf",
    "memcpy", "memmove", "alloca",
}
_DANGEROUS_FUNC_PATTERNS: dict[str, re.Pattern] = {
    func: re.compile(rf"\b{re.escape(func)}\b")
    for func in _DANGEROUS_FUNCS
}


def _diagnostic_codes(lib: dict) -> list[str]:
    diagnostics = lib.get("diagnostics")
    codes: list[str] = []
    if isinstance(diagnostics, list):
        for item in diagnostics:
            if isinstance(item, dict):
                code = item.get("code")
            else:
                code = item
            if isinstance(code, str) and code:
                codes.append(code)
    return codes


def _cve_skip_record(lib: dict, reason: str) -> dict:
    return {
        "name": lib.get("name"),
        "version": lib.get("version"),
        "path": lib.get("path"),
        "reason": reason,
        "versionStatus": lib.get("versionStatus"),
        "diagnostics": lib.get("diagnostics") if isinstance(lib.get("diagnostics"), list) else [],
    }


def _cve_entry_for_library(lib: dict) -> tuple[dict[str, str] | None, dict | None]:
    """Return S5 lookup entry or a structured skip diagnostic for an S4 SCA lib.

    S4 enriched fields are eligibility hints, not vulnerability verdicts.  S5
    batch lookup currently requires a concrete library version; therefore S3
    must not send versionless/unknown/ambiguous libraries and must preserve the
    skip reason as operational context.
    """
    name = lib.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, _cve_skip_record(lib, "MISSING_NAME")

    version = lib.get("version")
    if not isinstance(version, str) or not version.strip():
        reason = "VERSION_UNKNOWN"
        codes = _diagnostic_codes(lib)
        if "VERSION_UNKNOWN" in codes:
            reason = "VERSION_UNKNOWN"
        return None, _cve_skip_record(lib, reason)

    if lib.get("cveLookupEligible") is False:
        return None, _cve_skip_record(lib, "CVE_LOOKUP_INELIGIBLE")

    version_status = lib.get("versionStatus")
    # Legacy S4/SCA entries did not have versionStatus. Preserve compatibility:
    # name+version with absent status remains lookup-eligible.
    if isinstance(version_status, str) and version_status not in {"known"}:
        return None, _cve_skip_record(lib, f"VERSION_STATUS_{version_status.upper()}")

    entry: dict[str, str] = {"name": name.strip(), "version": version.strip()}
    if isinstance(lib.get("repoUrl"), str) and lib["repoUrl"].strip():
        entry["repoUrl"] = lib["repoUrl"].strip()
    if isinstance(lib.get("commit"), str) and lib["commit"].strip():
        entry["commit"] = lib["commit"].strip()
    return entry, None


def extract_cwe_ids(findings: list[dict]) -> set[str]:
    """findings에서 고유 CWE ID를 결정론적으로 추출한다."""
    cwe_ids: set[str] = set()
    for finding in findings:
        for field in (finding.get("ruleId", ""), finding.get("message", "")):
            for match in _CWE_RE.finditer(field):
                cwe_ids.add(f"CWE-{match.group(1)}")
        for cwe in finding.get("metadata", {}).get("cwe", []):
            if _CWE_RE.search(cwe):
                cwe_ids.add(cwe)
    return cwe_ids


def extract_dangerous_funcs(findings: list[dict]) -> set[str]:
    """findings에서 위험 함수명을 word boundary regex로 추출한다."""
    found: set[str] = set()
    for finding in findings:
        msg = finding.get("message", "").lower()
        for func, pattern in _DANGEROUS_FUNC_PATTERNS.items():
            if pattern.search(msg):
                found.add(func)
    return found


async def run_cve_lookup(
    kb_client: httpx.AsyncClient,
    result: Phase1Result,
    logger: logging.Logger,
) -> Phase1Result:
    """SCA 라이브러리+버전으로 S5 KB 실시간 CVE 조회."""
    libraries: list[dict[str, str]] = []
    skipped: list[dict] = []
    for lib in result.sca_libraries:
        if not isinstance(lib, dict):
            continue
        entry, skip = _cve_entry_for_library(lib)
        if skip is not None:
            skipped.append(skip)
        if entry is not None:
            libraries.append(entry)

    result.cve_lookup_skipped_libraries = skipped
    result.cve_lookup_eligible_count = len(libraries)

    if not libraries:
        return result

    result.cve_lookup_attempted = True

    agent_log(
        logger, "Phase 1: CVE 실시간 조회",
        component="phase_one", phase="cve_lookup_start",
        libraryCount=len(libraries),
    )

    start = time.monotonic()
    headers: dict[str, str] = {"X-Timeout-Ms": "30000"}
    request_id = get_request_id()
    if request_id:
        headers["X-Request-Id"] = request_id

    limit = settings.phase1_max_cve_libraries
    if len(libraries) > limit:
        result.cve_lookup_truncated = True
        result.cve_lookup_unqueried_eligible_count = len(libraries) - limit
        agent_log(
            logger, "Phase 1: CVE 라이브러리 목록 잘림",
            component="phase_one", phase="cve_truncated",
            total=len(libraries), limit=limit,
        )
    else:
        result.cve_lookup_truncated = False
        result.cve_lookup_unqueried_eligible_count = 0
    result.cve_lookup_attempted_libraries = libraries[:limit]
    request_body = {"libraries": result.cve_lookup_attempted_libraries}
    try:
        resp = await kb_client.post(
            "/v1/cve/batch-lookup",
            json=request_body,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        result.cve_lookup_completed = True
        for lib_result in data.get("results", []):
            for cve in lib_result.get("cves", []):
                cve["_library"] = lib_result.get("library", "")
                cve["_version"] = lib_result.get("version", "")
                result.cve_lookup.append(cve)
    except Exception as exc:
        result.cve_lookup_completed = False
        if is_kb_timeout_error(exc):
            result.cve_lookup_timed_out = True
            agent_log(
                logger, "Phase 1: CVE 조회 timeout",
                component="phase_one", phase="cve_lookup_timeout",
                requestBody=json.dumps(request_body, ensure_ascii=False)[:500],
                level=logging.WARNING,
            )
        else:
            result.cve_lookup_error = str(exc)
            agent_log(
                logger, "Phase 1: CVE 조회 실패",
                component="phase_one", phase="cve_lookup_error_detail",
                requestBody=json.dumps(request_body, ensure_ascii=False)[:500],
                level=logging.WARNING,
            )
        agent_log(
            logger, "Phase 1: CVE 조회 실패",
            component="phase_one", phase="cve_lookup_error",
            error=str(exc), level=logging.WARNING,
        )

    result.cve_lookup_duration_ms = int((time.monotonic() - start) * 1000)

    matched = sum(1 for cve in result.cve_lookup if cve.get("version_match") is True)
    agent_log(
        logger, "Phase 1: CVE 조회 완료",
        component="phase_one", phase="cve_lookup_end",
        totalCves=len(result.cve_lookup),
        versionMatched=matched,
        durationMs=result.cve_lookup_duration_ms,
    )
    return result


async def run_threat_query(
    kb_client: httpx.AsyncClient,
    result: Phase1Result,
    logger: logging.Logger,
) -> Phase1Result:
    """SAST findings에서 CWE ID 추출 → S5 KB 배치 위협 조회."""
    cwe_ids = extract_cwe_ids(result.sast_findings)
    if not cwe_ids:
        return result

    agent_log(
        logger, "Phase 1: KB 위협 조회 (배치)",
        component="phase_one", phase="threat_query_start",
        cweCount=len(cwe_ids),
    )

    start = time.monotonic()
    headers: dict[str, str] = {"X-Timeout-Ms": "30000"}
    request_id = get_request_id()
    if request_id:
        headers["X-Request-Id"] = request_id

    cwe_limit = settings.phase1_max_threat_cwes
    sorted_cwes = sorted(cwe_ids)
    if len(sorted_cwes) > cwe_limit:
        agent_log(
            logger, "Phase 1: 위협 쿼리 CWE 목록 잘림",
            component="phase_one", phase="threat_truncated",
            total=len(sorted_cwes), limit=cwe_limit,
        )
    queries = [{"query": cwe_id} for cwe_id in sorted_cwes[:cwe_limit]]

    try:
        resp = await kb_client.post(
            "/v1/search/batch",
            json={"queries": queries},
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        for query_result in data.get("results", []):
            result.threat_context.extend(query_result.get("hits", []))
        if data.get("degraded", False):
            result.kb_degraded = True
            agent_log(
                logger, "Phase 1: KB degraded 모드 (그래프 보강 불가)",
                component="phase_one", phase="kb_degraded",
                level=logging.WARNING,
            )
    except Exception as exc:
        if is_kb_timeout_error(exc):
            result.kb_timed_out = True
            agent_log(
                logger, "Phase 1: KB 위협 배치 조회 timeout",
                component="phase_one", phase="threat_query_timeout",
                level=logging.WARNING,
            )
        elif is_kb_not_ready_error(exc):
            result.kb_not_ready = True
            agent_log(
                logger, "Phase 1: KB not ready",
                component="phase_one", phase="kb_not_ready",
                level=logging.WARNING,
            )
        else:
            agent_log(
                logger, "Phase 1: KB 위협 배치 조회 실패",
                component="phase_one", phase="threat_query_error",
                error=str(exc), level=logging.WARNING,
            )

    result.threat_query_duration_ms = int((time.monotonic() - start) * 1000)

    agent_log(
        logger, "Phase 1: KB 위협 조회 완료",
        component="phase_one", phase="threat_query_end",
        hits=len(result.threat_context),
        degraded=result.kb_degraded,
        notReady=result.kb_not_ready,
        durationMs=result.threat_query_duration_ms,
    )
    return result


async def run_dangerous_callers(
    kb_client: httpx.AsyncClient,
    result: Phase1Result,
    project_id: str,
    logger: logging.Logger,
    *,
    provenance: dict | None = None,
) -> Phase1Result:
    """위험 함수(popen, system, getenv 등) 호출자 식별."""
    dangerous_funcs = extract_dangerous_funcs(result.sast_findings)
    if not dangerous_funcs:
        return result

    agent_log(
        logger, "Phase 1: 위험 호출자 조회",
        component="phase_one", phase="dangerous_callers_start",
        funcCount=len(dangerous_funcs),
    )

    start = time.monotonic()
    headers: dict[str, str] = {"X-Timeout-Ms": "10000"}
    request_id = get_request_id()
    if request_id:
        headers["X-Request-Id"] = request_id

    try:
        body: dict = {"dangerous_functions": list(dangerous_funcs)}
        build_snapshot_id = provenance.get("buildSnapshotId") if isinstance(provenance, dict) else None
        if build_snapshot_id:
            body["buildSnapshotId"] = build_snapshot_id
        resp = await kb_client.post(
            f"/v1/code-graph/{project_id}/dangerous-callers",
            json=body,
            headers=headers,
        )
        resp.raise_for_status()
        result.dangerous_callers = resp.json().get("results", [])
    except Exception as exc:
        if is_kb_timeout_error(exc):
            result.dangerous_callers_timed_out = True
            agent_log(
                logger, "Phase 1: 위험 호출자 조회 timeout",
                component="phase_one", phase="dangerous_callers_timeout",
                level=logging.WARNING,
            )
        agent_log(
            logger, "Phase 1: 위험 호출자 조회 실패",
            component="phase_one", phase="dangerous_callers_error",
            error=str(exc), level=logging.WARNING,
        )

    result.dangerous_callers_duration_ms = int((time.monotonic() - start) * 1000)

    agent_log(
        logger, "Phase 1: 위험 호출자 조회 완료",
        component="phase_one", phase="dangerous_callers_end",
        callers=len(result.dangerous_callers),
        durationMs=result.dangerous_callers_duration_ms,
    )
    return result


async def fetch_project_memory(
    kb_client: httpx.AsyncClient,
    project_id: str,
    request_id: str,
    logger: logging.Logger,
    revision_hint: str | None = None,
    provenance: dict | None = None,
) -> list[dict]:
    """S5 KB에서 프로젝트 메모리를 조회한다."""
    headers: dict[str, str] = {}
    if request_id:
        headers["X-Request-Id"] = request_id

    params: dict[str, str] = {}
    if revision_hint:
        params["revision"] = revision_hint
    if isinstance(provenance, dict):
        for key in ("buildSnapshotId", "buildUnitId", "sourceBuildAttemptId"):
            value = provenance.get(key)
            if value:
                params[key] = value

    try:
        resp = await kb_client.get(
            f"/v1/project-memory/{project_id}",
            headers=headers,
            params=params if params else None,
        )
        resp.raise_for_status()
        data = resp.json()
        memories = data.get("memories", [])
        if memories:
            agent_log(
                logger, "Phase 1: 프로젝트 메모리 조회",
                component="phase_one", phase="memory_loaded",
                memoryCount=len(memories),
                types=[memory.get("type") for memory in memories],
            )
        return memories
    except Exception as exc:
        agent_log(
            logger, "Phase 1: 프로젝트 메모리 조회 실패 (무시)",
            component="phase_one", phase="memory_error",
            error=str(exc), level=logging.WARNING,
        )
        return []
