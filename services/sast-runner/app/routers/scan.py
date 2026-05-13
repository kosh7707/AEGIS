"""SAST Runner API 라우터."""

from __future__ import annotations

import asyncio
import json as _json
import logging
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from fastapi import APIRouter, Request, Response
from fastapi import Query
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import settings
from app.context import set_request_id
from app.errors import (
    InvalidSdkProfileError,
    InvalidScanToolError,
    NoFilesError,
    PolicyViolationError,
    RequiredToolUnavailableError,
    SastRunnerError,
    SdkNotFoundError,
)
from app.runtime.request_ownership import request_ownership_store
from app.runtime.request_summary import request_summary_tracker
from app.scanner.ast_dumper import AstDumper
from app.scanner.build_metadata import BuildMetadataExtractor
from app.scanner.build_runner import BuildRunner
from app.scanner.evidence import enrich_findings_evidence, project_libraries_evidence
from app.scanner.static_evidence_contract import build_static_evidence_contract
from app.scanner.include_resolver import IncludeResolver
from app.scanner.orchestrator import ALL_TOOLS, ScanOrchestrator
from app.scanner.sca_service import analyze_libraries, identify_libraries
from app.scanner.sdk_resolver import profile_sdk_id, sdk_reference_exists
from app.scanner.ruleset_selector import resolve_rulesets
from app.schemas.request import (
    BuildAndAnalyzeRequest,
    BuildRequest,
    DiscoverTargetsRequest,
    ScanRequest,
    SnapshotProvenance,
)
from app.schemas.response import (
    BuildAndAnalyzeResponse,
    BuildEvidence,
    BuildFailureDetail,
    BuildReadiness,
    BuildResponse,
    ErrorDetail,
    HealthResponse,
    ScanResponse,
    ScanStats,
)

logger = logging.getLogger("aegis-sast-runner")

router = APIRouter(prefix="/v1", tags=["v1"])
orchestrator = ScanOrchestrator()
ast_dumper = AstDumper()
include_resolver = IncludeResolver()
metadata_extractor = BuildMetadataExtractor()
build_runner = BuildRunner()
_scan_semaphore = asyncio.Semaphore(settings.max_concurrent_scans)


DEFAULT_TIMEOUT_S = 600

_NDJSON_MEDIA = "application/x-ndjson"


def _wants_ndjson(request: Request) -> bool:
    """Accept 헤더에 application/x-ndjson이 있으면 스트리밍 모드."""
    accept = request.headers.get("accept", "")
    return _NDJSON_MEDIA in accept


def _wants_async_ownership(request: Request) -> bool:
    """Prefer: respond-async이면 durable ownership mode."""
    prefer = request.headers.get("prefer", "")
    return "respond-async" in prefer.lower()


def _ownership_response(payload: dict, status_code: int) -> JSONResponse:
    headers = {"X-Request-Id": payload.get("requestId", "")}
    if status_code == 202:
        headers["Preference-Applied"] = "respond-async"
    return JSONResponse(payload, status_code=status_code, headers=headers)


def _get_request_id(request: Request) -> str:
    return request.headers.get("X-Request-Id") or f"req-{uuid.uuid4()}"


def _get_timeout(request: Request, body_timeout: int | None = None) -> int:
    """타임아웃 해석: X-Timeout-Ms 헤더 > body > 기본값 600초."""
    header = request.headers.get("X-Timeout-Ms")
    if header:
        try:
            return max(int(header) // 1000, 1)
        except (ValueError, TypeError):
            pass
    if body_timeout and body_timeout != 120:  # 120은 ScanOptions 기본값이므로 명시적 지정만 존중
        return body_timeout
    return DEFAULT_TIMEOUT_S


def _validate_sdk_profile(profile) -> None:
    """analysis-path profile의 SDK reference mode를 검증한다.

    S4 accepts three SDK resolution contracts:
    - no profile / omitted SDK: native or SDK-independent analysis.
    - sdkResolutionMode="none": explicitly no SDK and no registry lookup.
    - sdkResolutionMode="non-registered": caller-resolved SDK descriptor.
    - sdkId without sdkResolutionMode: S4-local registered SDK reference.

    Unknown bare sdkId must fail early and stop; callers that resolve an SDK
    outside the S4 registry must use non-registered + sdkDescriptor instead.
    """
    if profile is None:
        return

    mode = profile.sdk_resolution_mode
    sdk_id = profile_sdk_id(profile)
    descriptor = profile.sdk_descriptor

    if mode == "none":
        if sdk_id is not None or descriptor is not None:
            raise InvalidSdkProfileError(
                "sdkResolutionMode='none' must omit sdkId and sdkDescriptor.",
            )
        return

    if mode == "non-registered":
        if descriptor is None or not descriptor.sdk_root_path:
            raise InvalidSdkProfileError(
                "sdkResolutionMode='non-registered' requires sdkDescriptor.sdkRootPath.",
            )
        return

    if descriptor is not None:
        raise InvalidSdkProfileError(
            "sdkDescriptor requires sdkResolutionMode='non-registered'.",
        )

    if sdk_id is None:
        return

    if sdk_reference_exists(profile):
        return
    raise SdkNotFoundError(
        f"Unknown sdkId '{sdk_id}'. Use a registered sdkId, "
        "sdkResolutionMode='non-registered' with sdkDescriptor for caller-resolved SDKs, "
        "or sdkResolutionMode='none' / omit sdkId for no-SDK analysis.",
    )


def _required_scan_tools(tools: list[str] | None) -> list[str]:
    """Return the authoritative required tool set for this request."""
    return list(tools or ALL_TOOLS)


def _validate_scan_tools(tools: list[str] | None) -> None:
    if tools is None:
        return
    unknown = sorted(set(tools) - set(ALL_TOOLS))
    if unknown:
        raise InvalidScanToolError(
            "Unknown SAST tool(s): "
            + ", ".join(unknown)
            + ". Allowed tools: "
            + ", ".join(ALL_TOOLS),
        )


def _scan_validation_error_response(
    *,
    body: ScanRequest,
    request_id: str,
    exc: SastRunnerError,
    response: Response,
) -> ScanResponse:
    """Build a typed ScanResponse for early scan validation failures."""
    response.status_code = exc.status_code
    return ScanResponse(
        success=False,
        scanId=body.scan_id,
        status="failed",
        provenance=body.provenance,
        error=exc.message,
        errorDetail=ErrorDetail(
            code=exc.code,
            message=exc.message,
            requestId=request_id,
            retryable=exc.retryable,
        ),
    )


def _error_response(
    request_id: str,
    exc: Exception,
    response: Response,
) -> dict:
    """observability.md 준수 에러 응답을 생성한다."""
    if isinstance(exc, SastRunnerError):
        response.status_code = exc.status_code
        code = exc.code
        message = exc.message
        retryable = exc.retryable
    else:
        response.status_code = 500
        code = "INTERNAL_ERROR"
        message = str(exc)
        retryable = False

    logger.error(
        "Request failed: %s", message,
        extra={"requestId": request_id, "code": code},
        exc_info=not isinstance(exc, SastRunnerError),
    )

    return {
        "success": False,
        "error": message,
        "errorDetail": {
            "code": code,
            "message": message,
            "requestId": request_id,
            "retryable": retryable,
        },
    }


def _prepare_scan_dir(body: ScanRequest) -> tuple[Path, list[str], bool]:
    """스캔 디렉토리를 준비한다.

    Returns:
        (scan_dir, source_files, should_cleanup)
        - projectPath가 있으면 → 파일시스템 직접 사용, cleanup=False
        - files[]가 있으면 → temp dir에 파일 쓰기, cleanup=True
    """
    if body.project_path:
        project_dir = Path(body.project_path)
        if not project_dir.is_dir():
            raise NoFilesError(f"projectPath not found: {body.project_path}")

        # 프로젝트 디렉토리에서 C/C++ 소스 파일 자동 탐색
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
        source_files = []
        for f in project_dir.rglob("*"):
            if f.suffix in extensions and f.is_file():
                rel = str(f.relative_to(project_dir))
                # libraries/, build/, .git 등 제외
                if not any(part.startswith(".") or part in ("build", "node_modules")
                           for part in rel.split("/")):
                    source_files.append(rel)

        return project_dir, source_files, False

    # 기존: files[] → temp dir
    scan_dir = Path(tempfile.mkdtemp(prefix="sast-scan-"))
    source_files = []
    for f in body.files:
        file_path = scan_dir / f.path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(f.content, encoding="utf-8")
        source_files.append(f.path)

    return scan_dir, source_files, True


def _validate_path(file_path: str) -> None:
    """경로 순회 공격 방지."""
    if os.path.isabs(file_path):
        raise NoFilesError(f"Absolute path not allowed: {file_path}")
    if ".." in Path(file_path).parts:
        raise NoFilesError(f"Path traversal not allowed: {file_path}")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _to_build_response(
    result: dict,
    provenance: SnapshotProvenance | None,
) -> BuildResponse:
    return BuildResponse(
        success=result["success"],
        provenance=provenance,
        buildEvidence=BuildEvidence(**result["buildEvidence"]),
        readiness=BuildReadiness(**result["readiness"]),
        failureDetail=(
            BuildFailureDetail(**result["failureDetail"])
            if result.get("failureDetail")
            else None
        ),
    )


def _execution_summary(execution) -> dict:
    tool_results = execution.tool_results
    return {
        "toolsRun": list(execution.tools_run),
        "findingsByTool": {
            name: result.findings_count
            for name, result in tool_results.items()
        },
        "elapsedByToolMs": {
            name: result.elapsed_ms
            for name, result in tool_results.items()
        },
        "toolStatuses": {
            name: result.status
            for name, result in tool_results.items()
        },
        "toolSkipReasons": {
            name: result.skip_reason
            for name, result in tool_results.items()
            if result.skip_reason
        },
    }


def _log_scan_execution_summary(
    *,
    request_id: str,
    body: ScanRequest,
    source_files: list[str],
    findings_count: int,
    execution,
    elapsed_ms: int,
    has_code_graph: bool,
    sca_libraries: int,
) -> None:
    filtering = execution.filtering
    sdk = execution.sdk
    summary = _execution_summary(execution)
    logger.info(
        "Scan execution summary",
        extra={
            "requestId": request_id,
            "scanId": body.scan_id,
            "projectId": body.project_id,
            "projectPath": body.project_path,
            "filesScanned": len(source_files),
            "compileCommandsProvided": bool(body.compile_commands),
            "sdkResolved": sdk.resolved,
            "sdkId": sdk.sdk_id,
            "includePathsAdded": sdk.include_paths_added,
            "findingsCount": findings_count,
            "findingsBeforeFilter": filtering.before_filter,
            "findingsAfterFilter": filtering.after_filter,
            "sdkNoiseRemoved": filtering.sdk_noise_removed,
            "thirdPartyRemoved": filtering.third_party_removed,
            "crossBoundaryKept": filtering.cross_boundary_kept,
            "filesScopedOut": filtering.files_scoped_out,
            "degraded": execution.degraded,
            "degradeReasons": execution.degrade_reasons,
            "hasCodeGraph": has_code_graph,
            "scaLibraries": sca_libraries,
            "elapsedMs": elapsed_ms,
            **summary,
        },
    )


def _log_build_execution_summary(
    *,
    request_id: str,
    endpoint: str,
    result: dict,
    project_path: str,
) -> None:
    evidence = result.get("buildEvidence") or {}
    readiness = result.get("readiness") or {}
    failure_detail = result.get("failureDetail") or {}
    logger.info(
        "Build execution summary",
        extra={
            "requestId": request_id,
            "endpoint": endpoint,
            "projectPath": project_path,
            "success": bool(result.get("success")),
            "requestedBuildCommand": evidence.get("requestedBuildCommand"),
            "effectiveBuildCommand": evidence.get("effectiveBuildCommand"),
            "compileCommandsPath": evidence.get("compileCommandsPath"),
            "entries": evidence.get("entries"),
            "userEntries": evidence.get("userEntries"),
            "exitCode": evidence.get("exitCode"),
            "wrapWithBear": evidence.get("wrapWithBear"),
            "timeoutSeconds": evidence.get("timeoutSeconds"),
            "environmentKeys": evidence.get("environmentKeys"),
            "buildElapsedMs": evidence.get("elapsedMs"),
            "readinessStatus": readiness.get("status"),
            "compileCommandsReady": readiness.get("compileCommandsReady"),
            "quickEligible": readiness.get("quickEligible"),
            "failureCategory": failure_detail.get("category"),
            "failureRetryable": failure_detail.get("retryable"),
        },
    )


def _log_terminal_request_summary(request_id: str) -> None:
    summary = request_summary_tracker.get_summary(request_id)
    logger.info(
        "Request terminal summary",
        extra={
            "requestId": request_id,
            "endpoint": summary.get("endpoint"),
            "state": summary.get("state"),
            "ackStatus": summary.get("ackStatus"),
            "localAckState": summary.get("localAckState"),
            "lastAckSource": summary.get("lastAckSource"),
            "degraded": summary.get("degraded"),
            "degradeReasons": summary.get("degradeReasons"),
            "activeTools": summary.get("activeTools"),
            "completedTools": summary.get("completedTools"),
            "findingsCount": summary.get("findingsCount"),
            "filesCompleted": summary.get("filesCompleted"),
            "filesTotal": summary.get("filesTotal"),
            "blockedReason": summary.get("blockedReason"),
        },
    )


async def _run_scan_core(
    request_id: str,
    body: ScanRequest,
    rulesets: list[str],
    timeout: int,
    on_progress=None,
    on_started=None,
    on_file_progress=None,
    on_runtime_state=None,
) -> ScanResponse:
    """scan 핵심 로직 — 동기/스트리밍 양쪽에서 공유.

    세마포어 획득, 디렉토리 준비, 도구 실행, codeGraph, SCA, 정리, ScanResponse 조립.
    실패 시 SastRunnerError 또는 Exception을 raise한다.
    """
    scan_id = body.scan_id
    t0 = time.perf_counter()

    async with _scan_semaphore:
        request_summary_tracker.mark_started(request_id)
        if on_started:
            await on_started()
        scan_dir, source_files, should_cleanup = _prepare_scan_dir(body)
        try:
            bp = body.build_profile
            logger.info(
                "Scan started",
                extra={
                    "requestId": request_id,
                    "scanId": scan_id,
                    "filesCount": len(source_files),
                    "rulesets": rulesets,
                    "projectPath": body.project_path,
                    "sdkId": bp.sdk_id if bp else None,
                    "languageStandard": bp.language_standard if bp else None,
                    "targetArch": bp.target_arch if bp else None,
                },
            )

            # 1. 멀티 도구 병렬 실행
            try:
                findings, execution = await orchestrator.run(
                    scan_dir=scan_dir,
                    source_files=source_files,
                    profile=bp,
                    rulesets=rulesets,
                    compile_commands=body.compile_commands,
                    tools=body.options.tools,
                    timeout=timeout,
                    third_party_paths=body.third_party_paths,
                    on_progress=on_progress,
                    on_file_progress=on_file_progress,
                    on_runtime_state=on_runtime_state,
                )
            except RequiredToolUnavailableError as exc:
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                execution = exc.execution
                failed_contract = build_static_evidence_contract(
                    success=False,
                    provenance=body.provenance,
                    findings=[],
                    execution=execution,
                    code_graph=None,
                    sca=None,
                    policy_failure_reason_codes=["REQUIRED_TOOL_UNAVAILABLE"],
                )
                failed_response = ScanResponse(
                    success=False,
                    scanId=scan_id,
                    status="failed",
                    provenance=body.provenance,
                    findings=[],
                    stats=ScanStats(
                        filesScanned=len(source_files),
                        rulesRun=0,
                        findingsTotal=0,
                        elapsedMs=elapsed_ms,
                    ),
                    execution=execution,
                    staticEvidenceContract=failed_contract,
                    error=exc.message,
                    errorDetail=ErrorDetail(
                        code=exc.code,
                        message=exc.message,
                        requestId=request_id,
                        retryable=exc.retryable,
                    ),
                )
                raise PolicyViolationError(
                    exc.message,
                    scan_response=failed_response,
                    code=exc.code,
                ) from exc
            findings = enrich_findings_evidence(findings)

            policy_violation = orchestrator.evaluate_policy(
                execution,
                required_tools=_required_scan_tools(body.options.tools),
            )
            if policy_violation:
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                failed_contract = build_static_evidence_contract(
                    success=False,
                    provenance=body.provenance,
                    findings=findings,
                    execution=execution,
                    code_graph=None,
                    sca=None,
                    policy_failure_reason_codes=["POLICY_VIOLATION", str(policy_violation["code"])],
                )
                failed_response = ScanResponse(
                    success=False,
                    scanId=scan_id,
                    status="failed",
                    provenance=body.provenance,
                    findings=findings,
                    stats=ScanStats(
                        filesScanned=len(source_files),
                        rulesRun=len(execution.tools_run),
                        findingsTotal=len(findings),
                        elapsedMs=elapsed_ms,
                    ),
                    execution=execution,
                    staticEvidenceContract=failed_contract,
                    error=policy_violation["message"],
                    errorDetail=ErrorDetail(
                        code=policy_violation["code"],
                        message=policy_violation["message"],
                        requestId=request_id,
                        retryable=False,
                    ),
                )
                logger.warning(
                    "Policy violation: %s",
                    policy_violation["message"],
                    extra={
                        "requestId": request_id,
                        "scanId": scan_id,
                        "omittedTools": policy_violation.get("omittedTools", []),
                        "unstableTools": policy_violation.get("unstableTools", []),
                        "policyReasons": policy_violation["policyReasons"],
                    },
                )
                raise PolicyViolationError(
                    policy_violation["message"],
                    scan_response=failed_response,
                    code=policy_violation["code"],
                )

            # 2. projectPath 모드: codeGraph + SCA
            code_graph_result = None
            sca_result = None
            if body.project_path:
                libs = await identify_libraries(scan_dir)
                sca_libs = project_libraries_evidence(
                    libs,
                    provenance=body.provenance,
                    diff_computed=False,
                )
                sca_result = {"libraries": sca_libs}

                lib_skip = [lib["path"] for lib in libs if lib.get("path")]
                func_skip = list(set((body.third_party_paths or []) + lib_skip))
                code_graph_result = await ast_dumper.dump_functions(
                    scan_dir, source_files, bp, libraries=libs,
                    skip_paths=func_skip if func_skip else None,
                )

        finally:
            if should_cleanup:
                shutil.rmtree(scan_dir, ignore_errors=True)

    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    scan_response = ScanResponse(
        success=True,
        scanId=scan_id,
        status="completed",
        provenance=body.provenance,
        findings=findings,
        stats=ScanStats(
            filesScanned=len(source_files),
            rulesRun=len(execution.tools_run),
            findingsTotal=len(findings),
            elapsedMs=elapsed_ms,
        ),
        execution=execution,
        codeGraph=code_graph_result,
        sca=sca_result,
        staticEvidenceContract=build_static_evidence_contract(
            success=True,
            provenance=body.provenance,
            findings=findings,
            execution=execution,
            code_graph=code_graph_result,
            sca=sca_result,
        ),
    )

    _log_scan_execution_summary(
        request_id=request_id,
        body=body,
        source_files=source_files,
        findings_count=len(findings),
        execution=execution,
        elapsed_ms=elapsed_ms,
        has_code_graph=code_graph_result is not None,
        sca_libraries=len(sca_result["libraries"]) if sca_result else 0,
    )

    logger.info(
        "Scan completed",
        extra={
            "requestId": request_id,
            "scanId": scan_id,
            "findingsCount": len(findings),
            "toolsRun": execution.tools_run,
            "hasCodeGraph": code_graph_result is not None,
            "scaLibraries": len(sca_result["libraries"]) if sca_result else 0,
            "elapsedMs": elapsed_ms,
        },
    )

    return scan_response


_HEARTBEAT_INTERVAL_S = 25


def _scan_streaming(
    request_id: str,
    body: ScanRequest,
    rulesets: list[str],
    timeout: int,
) -> StreamingResponse:
    """NDJSON 스트리밍 스캔 — 도구 진행 이벤트 + 주기적 heartbeat + 최종 결과.

    이벤트 타입:
      progress — 도구 시작/완료/실패 시
      heartbeat — 25초 간격 keepalive (status + progress 필드 포함)
      result — 최종 ScanResponse (동기 모드와 동일 스키마)
      error — 중간 실패 시
    """

    async def _generate():
        queue: asyncio.Queue = asyncio.Queue()

        # 공유 진행 상태
        state: dict = {
            "status": "queued",
            "activeTools": [],
            "completedTools": [],
            "findingsCount": 0,
            "filesCompleted": 0,
            "filesTotal": 0,
            "currentFile": None,
            "degraded": False,
            "degradeReasons": [],
            "toolStates": {},
        }
        file_progress_by_tool: dict = {}

        async def _on_started():
            state["status"] = "running"
            request_summary_tracker.mark_started(request_id)

        async def _on_progress(tool: str, status: str, count: int, elapsed: int):
            request_summary_tracker.mark_progress(request_id, tool, status, count)
            if status == "started":
                state["activeTools"].append(tool)
            elif status in ("completed", "failed"):
                if tool in state["activeTools"]:
                    state["activeTools"].remove(tool)
                state["completedTools"].append(tool)
                if status == "completed":
                    state["findingsCount"] += count
            await queue.put({
                "type": "progress",
                "tool": tool,
                "status": status,
                "findingsCount": count,
                "elapsedMs": elapsed,
                "timestamp": _now_ms(),
            })

        async def _on_file_progress(tool: str, file: str, done: int, total: int):
            request_summary_tracker.mark_file_progress(request_id, file, done, total)
            file_progress_by_tool[tool] = {"done": done, "total": total}
            state["filesCompleted"] = sum(t["done"] for t in file_progress_by_tool.values())
            state["filesTotal"] = sum(t["total"] for t in file_progress_by_tool.values())
            state["currentFile"] = file
            state["toolStates"].setdefault(tool, {}).update(
                {
                    "filesCompleted": done,
                    "filesAttempted": total,
                },
            )

        async def _on_runtime_state(tool: str, tool_state: dict):
            request_summary_tracker.mark_runtime_state(request_id, tool_state)
            state["toolStates"].setdefault(tool, {}).update(tool_state)
            reasons = sorted(
                {
                    reason
                    for runtime_state in state["toolStates"].values()
                    for reason in runtime_state.get("degradeReasons", [])
                },
            )
            state["degraded"] = bool(reasons)
            state["degradeReasons"] = reasons

        async def _heartbeat_loop():
            try:
                while True:
                    await asyncio.sleep(_HEARTBEAT_INTERVAL_S)
                    event: dict = {
                        "type": "heartbeat",
                        "timestamp": _now_ms(),
                        "status": state["status"],
                    }
                    if state["status"] == "running":
                        event["progress"] = {
                            "activeTools": list(state["activeTools"]),
                            "completedTools": list(state["completedTools"]),
                            "findingsCount": state["findingsCount"],
                            "filesCompleted": state["filesCompleted"],
                            "filesTotal": state["filesTotal"],
                            "currentFile": state["currentFile"],
                            "degraded": state["degraded"],
                            "degradeReasons": state["degradeReasons"],
                            "toolStates": state["toolStates"],
                        }
                    await queue.put(event)
            except asyncio.CancelledError:
                pass

        scan_task = asyncio.create_task(
            _run_scan_core(
                request_id, body, rulesets, timeout,
                on_progress=_on_progress,
                on_started=_on_started,
                on_file_progress=_on_file_progress,
                on_runtime_state=_on_runtime_state,
            ),
        )
        heartbeat_task = asyncio.create_task(_heartbeat_loop())

        try:
            while not scan_task.done():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield _json.dumps(event, ensure_ascii=False) + "\n"
                except asyncio.TimeoutError:
                    continue

            # 큐에 남은 이벤트 drain
            while not queue.empty():
                event = queue.get_nowait()
                yield _json.dumps(event, ensure_ascii=False) + "\n"

            # 최종 결과
            result = scan_task.result()
            request_summary_tracker.mark_completed(request_id)
            _log_terminal_request_summary(request_id)
            yield _json.dumps({
                "type": "result",
                "data": result.model_dump(by_alias=True, exclude_none=True),
            }, ensure_ascii=False) + "\n"

        except PolicyViolationError as exc:
            request_summary_tracker.mark_failed(request_id, exc.message)
            _log_terminal_request_summary(request_id)
            logger.warning(
                "NDJSON scan policy violation: %s",
                exc.message,
                extra={
                    "requestId": request_id,
                    "scanId": exc.scan_response.scan_id,
                    "code": exc.code,
                },
            )
            execution_payload = None
            if exc.scan_response.execution is not None:
                execution_payload = exc.scan_response.execution.model_dump(
                    by_alias=True,
                    exclude_none=True,
                )
            static_contract = exc.scan_response.static_evidence_contract
            yield _json.dumps({
                "type": "error",
                "code": exc.code,
                "message": exc.message,
                "retryable": exc.retryable,
                "requestId": request_id,
                "scanId": exc.scan_response.scan_id,
                "execution": execution_payload,
                "staticEvidenceContract": static_contract,
                "timestamp": _now_ms(),
            }, ensure_ascii=False) + "\n"

        except SastRunnerError as exc:
            request_summary_tracker.mark_failed(request_id, exc.message)
            _log_terminal_request_summary(request_id)
            logger.error(
                "NDJSON scan failed: %s",
                exc.message,
                extra={"requestId": request_id, "scanId": body.scan_id, "code": exc.code},
            )
            yield _json.dumps({
                "type": "error",
                "code": exc.code,
                "message": exc.message,
                "retryable": exc.retryable,
                "requestId": request_id,
                "timestamp": _now_ms(),
            }, ensure_ascii=False) + "\n"

        except Exception as exc:
            request_summary_tracker.mark_failed(request_id, str(exc))
            _log_terminal_request_summary(request_id)
            logger.error(
                "NDJSON scan failed unexpectedly: %s",
                str(exc),
                extra={"requestId": request_id, "scanId": body.scan_id},
                exc_info=True,
            )
            yield _json.dumps({
                "type": "error",
                "code": "INTERNAL_ERROR",
                "message": str(exc),
                "retryable": False,
                "requestId": request_id,
                "timestamp": _now_ms(),
            }, ensure_ascii=False) + "\n"

        finally:
            heartbeat_task.cancel()
            if not scan_task.done():
                scan_task.cancel()
            for t in (heartbeat_task, scan_task):
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

    return StreamingResponse(
        _generate(),
        media_type=_NDJSON_MEDIA,
        headers={"X-Request-Id": request_id},
    )


@router.post("/scan", response_model=ScanResponse, response_model_exclude_none=True)
async def scan(request: Request, body: ScanRequest, response: Response) -> ScanResponse | StreamingResponse:
    """소스 파일을 받아 멀티 도구 SAST 분석을 수행하고 SastFinding[]을 반환.

    Accept: application/x-ndjson 헤더가 있으면 하트비트 기반 NDJSON 스트리밍 모드로 동작.
    """
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    # Durable ownership mode wins over NDJSON compatibility streaming.
    if _wants_async_ownership(request):
        try:
            if not body.files and not body.project_path:
                raise NoFilesError("No files or projectPath provided for scanning")
            for f in body.files:
                _validate_path(f.path)
            _validate_sdk_profile(body.build_profile)
            _validate_scan_tools(body.options.tools)
        except SastRunnerError as exc:
            return _scan_validation_error_response(
                body=body,
                request_id=request_id,
                exc=exc,
                response=response,
            )
        rulesets = resolve_rulesets(
            body.rulesets, body.build_profile, settings.default_rulesets,
        )
        timeout = _get_timeout(request, body.options.timeout_seconds)

        async def _owned_scan() -> ScanResponse:
            async def _track_progress(tool: str, status: str, count: int, elapsed: int):
                request_summary_tracker.mark_progress(request_id, tool, status, count)

            async def _track_file_progress(tool: str, file: str, done: int, total: int):
                request_summary_tracker.mark_file_progress(request_id, file, done, total)

            async def _track_runtime_state(tool: str, tool_state: dict):
                request_summary_tracker.mark_runtime_state(request_id, tool_state)

            return await _run_scan_core(
                request_id,
                body,
                rulesets,
                timeout,
                on_progress=_track_progress,
                on_file_progress=_track_file_progress,
                on_runtime_state=_track_runtime_state,
            )

        payload, status_code = await request_ownership_store.submit(
            request_id,
            endpoint="scan",
            runner=_owned_scan,
        )
        return _ownership_response(payload, status_code)

    # NDJSON 스트리밍 모드 — 입력 검증 후 분기 (실패 시 일반 HTTP 에러)
    if _wants_ndjson(request):
        try:
            if not body.files and not body.project_path:
                raise NoFilesError("No files or projectPath provided for scanning")
            for f in body.files:
                _validate_path(f.path)
            _validate_sdk_profile(body.build_profile)
            _validate_scan_tools(body.options.tools)
        except SastRunnerError as exc:
            return _scan_validation_error_response(
                body=body,
                request_id=request_id,
                exc=exc,
                response=response,
            )
        request_summary_tracker.register(request_id, endpoint="scan")
        rulesets = resolve_rulesets(
            body.rulesets, body.build_profile, settings.default_rulesets,
        )
        timeout = _get_timeout(request, body.options.timeout_seconds)
        return _scan_streaming(request_id, body, rulesets, timeout)

    # 동기 모드 (기존 동작)
    t0 = time.perf_counter()

    try:
        if not body.files and not body.project_path:
            raise NoFilesError("No files or projectPath provided for scanning")
        for f in body.files:
            _validate_path(f.path)
        _validate_sdk_profile(body.build_profile)
        _validate_scan_tools(body.options.tools)
        request_summary_tracker.register(request_id, endpoint="scan")

        rulesets = resolve_rulesets(
            body.rulesets, body.build_profile, settings.default_rulesets,
        )
        timeout = _get_timeout(request, body.options.timeout_seconds)

        async def _track_progress(tool: str, status: str, count: int, elapsed: int):
            request_summary_tracker.mark_progress(request_id, tool, status, count)

        async def _track_file_progress(tool: str, file: str, done: int, total: int):
            request_summary_tracker.mark_file_progress(request_id, file, done, total)

        async def _track_runtime_state(tool: str, tool_state: dict):
            request_summary_tracker.mark_runtime_state(request_id, tool_state)

        result = await _run_scan_core(
            request_id,
            body,
            rulesets,
            timeout,
            on_progress=_track_progress,
            on_file_progress=_track_file_progress,
            on_runtime_state=_track_runtime_state,
        )
        request_summary_tracker.mark_completed(request_id)
        _log_terminal_request_summary(request_id)
        return result

    except PolicyViolationError as exc:
        request_summary_tracker.mark_failed(request_id, exc.message)
        _log_terminal_request_summary(request_id)
        response.status_code = exc.status_code
        return exc.scan_response

    except SastRunnerError as exc:
        request_summary_tracker.mark_failed(request_id, exc.message)
        _log_terminal_request_summary(request_id)
        logger.error(
            "Scan failed: %s",
            exc.message,
            extra={"requestId": request_id, "scanId": body.scan_id, "code": exc.code},
        )
        response.status_code = exc.status_code
        return ScanResponse(
            success=False,
            scanId=body.scan_id,
            status="failed",
            provenance=body.provenance,
            error=exc.message,
            errorDetail=ErrorDetail(
                code=exc.code,
                message=exc.message,
                requestId=request_id,
                retryable=exc.retryable,
            ),
        )

    except Exception as exc:
        request_summary_tracker.mark_failed(request_id, str(exc))
        _log_terminal_request_summary(request_id)
        logger.error(
            "Unexpected error: %s",
            str(exc),
            extra={"requestId": request_id, "scanId": body.scan_id},
            exc_info=True,
        )
        response.status_code = 500
        return ScanResponse(
            success=False,
            scanId=body.scan_id,
            status="failed",
            provenance=body.provenance,
            error=str(exc),
            errorDetail=ErrorDetail(
                code="INTERNAL_ERROR",
                message=str(exc),
                requestId=request_id,
                retryable=False,
            ),
        )


@router.post("/functions")
async def functions(request: Request, body: ScanRequest, response: Response):
    """소스 파일들에서 함수 목록 + 호출 관계를 추출.

    에이전트의 code_graph.get_callers() tool 백엔드용.
    """
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    if not body.files and not body.project_path:
        raise NoFilesError("No files or projectPath provided")

    for f in body.files:
        _validate_path(f.path)
    _validate_sdk_profile(body.build_profile)

    t0 = time.perf_counter()
    scan_dir, source_files, should_cleanup = _prepare_scan_dir(body)

    logger.info(
        "Functions extraction started",
        extra={"requestId": request_id, "filesCount": len(source_files), "projectPath": body.project_path},
    )

    try:
        # projectPath 모드: 라이브러리 식별 → origin 태깅 + 스킵 경로
        # include_diff=False: diff 없이 식별만 수행 (성능 — 44초 → ~1초)
        libs = None
        func_skip = None
        if body.project_path:
            libs = await analyze_libraries(scan_dir, include_diff=False)
            lib_skip = [lib["path"] for lib in (libs or []) if lib.get("path")]
            func_skip_list = list(set((body.third_party_paths or []) + lib_skip))
            func_skip = func_skip_list if func_skip_list else None

        result = await ast_dumper.dump_functions(
            scan_dir, source_files, body.build_profile, libraries=libs,
            skip_paths=func_skip,
        )

        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(
            "Functions extraction completed",
            extra={
                "requestId": request_id,
                "functionCount": len(result.get("functions", [])),
                "elapsedMs": elapsed_ms,
            },
        )
        return result
    except Exception as exc:
        return _error_response(request_id, exc, response)
    finally:
        if should_cleanup:
            shutil.rmtree(scan_dir, ignore_errors=True)


@router.post("/includes")
async def includes(request: Request, body: ScanRequest, response: Response):
    """파일별 인클루드 의존성 트리를 추출. gcc -E -M 기반."""
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    if not body.files and not body.project_path:
        raise NoFilesError("No files or projectPath provided")
    for f in body.files:
        _validate_path(f.path)
    _validate_sdk_profile(body.build_profile)

    t0 = time.perf_counter()
    scan_dir, source_files, should_cleanup = _prepare_scan_dir(body)
    try:
        result = await include_resolver.resolve(
            scan_dir, source_files, body.build_profile,
        )
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(
            "Include resolution completed",
            extra={"requestId": request_id, "filesCount": len(result), "elapsedMs": elapsed_ms,
                    "projectPath": body.project_path},
        )
        return {"includes": result}
    except Exception as exc:
        return _error_response(request_id, exc, response)
    finally:
        if should_cleanup:
            shutil.rmtree(scan_dir, ignore_errors=True)


@router.post("/metadata")
async def metadata(request: Request, body: ScanRequest, response: Response):
    """타겟 빌드 환경 매크로를 추출. gcc -E -dM 기반."""
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    try:
        _validate_sdk_profile(body.build_profile)
        result = await metadata_extractor.extract(body.build_profile)
        logger.info(
            "Build metadata extracted",
            extra={
                "requestId": request_id,
                "compiler": result.get("compiler"),
                "macroCount": len(result.get("macros", {})),
            },
        )
        return result
    except Exception as exc:
        return _error_response(request_id, exc, response)


@router.post("/libraries")
async def libraries(request: Request, body: ScanRequest, response: Response):
    """프로젝트 내 vendored 라이브러리 식별 + upstream diff.

    SCA (Software Composition Analysis) 엔드포인트.
    projectPath 필수. CVE 조회는 S5(KB) POST /v1/cve/batch-lookup으로 이관됨.
    """
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    if not body.project_path:
        raise NoFilesError("projectPath is required for library analysis")

    project_dir = Path(body.project_path)
    if not project_dir.is_dir():
        raise NoFilesError(f"projectPath not found: {body.project_path}")

    t0 = time.perf_counter()
    logger.info("Library analysis started", extra={"requestId": request_id, "projectPath": body.project_path})

    try:
        results = await analyze_libraries(project_dir)

        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(
            "Library analysis completed",
            extra={"requestId": request_id, "libraryCount": len(results), "elapsedMs": elapsed_ms},
        )

        return {"libraries": results, "elapsedMs": elapsed_ms}

    except Exception as exc:
        return _error_response(request_id, exc, response)


@router.post("/build-and-analyze")
async def build_and_analyze(
    request: Request,
    response: Response,
    body: BuildAndAnalyzeRequest,
) -> BuildAndAnalyzeResponse | dict:
    """빌드 실행 + 전체 분석 파이프라인 한 번에.

    사용자가 projectPath + buildCommand만 주면:
    1. bear -- buildCommand → compile_commands.json 자동 생성
    2. /v1/scan (compile_commands 사용)
    3. /v1/functions (projectPath)
    4. /v1/libraries (SCA)
    5. /v1/metadata (빌드 메타데이터)
    전부 한 번에 반환.
    """
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    project_path = body.project_path
    build_command = body.build_command

    if not project_path:
        response.status_code = 400
        return {"error": "projectPath is required"}

    project_dir = Path(project_path)
    if not project_dir.is_dir():
        response.status_code = 400
        return {"error": f"projectPath not found: {project_path}"}

    if not build_command:
        response.status_code = 400
        return {"error": "buildCommand is required"}

    scan_profile = body.scan_profile
    try:
        _validate_sdk_profile(scan_profile)
        _validate_scan_tools(body.options.tools)
    except SastRunnerError as exc:
        return _error_response(request_id, exc, response)

    if _wants_async_ownership(request):
        async def _owned_build_and_analyze() -> BuildAndAnalyzeResponse:
            t0_owned = time.perf_counter()
            request_summary_tracker.mark_started(
                request_id,
                last_ack_source="build-started",
                local_ack_state="phase-advancing",
            )

            async def _track_build_runtime(state: dict):
                request_summary_tracker.mark_runtime_state(
                    request_id,
                    state,
                    local_ack_state=state.get("localAckState"),
                    last_ack_source=state.get("lastAckSource"),
                )

            build_timeout = _get_timeout(request)
            logger.info("Build-and-analyze async ownership started", extra={"requestId": request_id, "projectPath": project_path})
            build_result = await build_runner.build(
                project_dir,
                build_command,
                environment=body.build_environment,
                on_runtime_state=_track_build_runtime,
                timeout=None,
                timeout_seconds_for_evidence=build_timeout,
                timeout_mode="async-ownership-no-caller-deadline",
                timeout_enforced=False,
            )
            _log_build_execution_summary(
                request_id=request_id,
                endpoint="build-and-analyze",
                result=build_result,
                project_path=project_path,
            )
            build_response = _to_build_response(build_result, body.provenance)
            if not build_result.get("success"):
                return BuildAndAnalyzeResponse(
                    success=False,
                    provenance=body.provenance,
                    build=build_response,
                    error="Build failed",
                )

            cc_path = build_result["buildEvidence"]["compileCommandsPath"]
            scan_req = ScanRequest(
                scanId=f"build-analyze-{request_id}",
                projectId=body.project_id,
                projectPath=project_path,
                compileCommands=cc_path,
                buildProfile=scan_profile,
                provenance=body.provenance,
                rulesets=body.rulesets,
                thirdPartyPaths=body.third_party_paths,
                options=body.options,
            )
            rulesets = resolve_rulesets(body.rulesets, scan_profile, settings.default_rulesets)
            timeout = _get_timeout(request, body.options.timeout_seconds)

            async def _track_progress(tool: str, status: str, count: int, elapsed: int):
                request_summary_tracker.mark_progress(request_id, tool, status, count)

            async def _track_file_progress(tool: str, file: str, done: int, total: int):
                request_summary_tracker.mark_file_progress(request_id, file, done, total)

            async def _track_runtime_state(tool: str, tool_state: dict):
                request_summary_tracker.mark_runtime_state(request_id, tool_state)

            try:
                scan_result = await _run_scan_core(
                    request_id,
                    scan_req,
                    rulesets,
                    timeout,
                    on_progress=_track_progress,
                    on_file_progress=_track_file_progress,
                    on_runtime_state=_track_runtime_state,
                )
            except PolicyViolationError as exc:
                scan_result = exc.scan_response
                return BuildAndAnalyzeResponse(
                    success=False,
                    provenance=body.provenance,
                    build=build_response,
                    scan=scan_result,
                    codeGraph=scan_result.code_graph,
                    libraries=(scan_result.sca or {}).get("libraries"),
                    staticEvidenceContract=build_static_evidence_contract(
                        success=False,
                        provenance=body.provenance,
                        findings=scan_result.findings,
                        execution=scan_result.execution,
                        code_graph=scan_result.code_graph,
                        sca=scan_result.sca,
                        policy_failure_reason_codes=["POLICY_VIOLATION", str(exc.code)],
                    ),
                    error=exc.message,
                    errorDetail=scan_result.error_detail,
                )

            meta = await metadata_extractor.extract(scan_profile)
            elapsed_ms = int((time.perf_counter() - t0_owned) * 1000)
            return BuildAndAnalyzeResponse(
                success=True,
                provenance=body.provenance,
                build=build_response,
                scan=scan_result,
                codeGraph=scan_result.code_graph,
                libraries=(scan_result.sca or {}).get("libraries"),
                metadata=meta,
                staticEvidenceContract=build_static_evidence_contract(
                    success=True,
                    provenance=body.provenance,
                    findings=scan_result.findings,
                    execution=scan_result.execution,
                    code_graph=scan_result.code_graph,
                    sca=scan_result.sca,
                    metadata=meta,
                ),
                elapsedMs=elapsed_ms,
            )

        payload, status_code = await request_ownership_store.submit(
            request_id,
            endpoint="build-and-analyze",
            runner=_owned_build_and_analyze,
        )
        return _ownership_response(payload, status_code)

    t0 = time.perf_counter()
    build_response: BuildResponse | None = None

    try:
        request_summary_tracker.register(request_id, endpoint="build-and-analyze")
        request_summary_tracker.mark_started(
            request_id,
            last_ack_source="build-started",
            local_ack_state="phase-advancing",
        )

        async def _track_build_runtime(state: dict):
            request_summary_tracker.mark_runtime_state(
                request_id,
                state,
                local_ack_state=state.get("localAckState"),
                last_ack_source=state.get("lastAckSource"),
            )

        # 1. 빌드 (bear)
        logger.info("Build-and-analyze started", extra={"requestId": request_id, "projectPath": project_path})
        build_result = await build_runner.build(
            project_dir,
            build_command,
            environment=body.build_environment,
            on_runtime_state=_track_build_runtime,
        )
        _log_build_execution_summary(
            request_id=request_id,
            endpoint="build-and-analyze",
            result=build_result,
            project_path=project_path,
        )
        build_response = _to_build_response(build_result, body.provenance)
        if not build_result.get("success"):
            failure_detail = build_result.get("failureDetail") or {}
            request_summary_tracker.mark_failed(
                request_id,
                failure_detail.get("summary") or "build failed",
            )
            _log_terminal_request_summary(request_id)
            return BuildAndAnalyzeResponse(
                success=False,
                provenance=body.provenance,
                build=build_response,
                error="Build failed",
            )

        cc_path = build_result["buildEvidence"]["compileCommandsPath"]

        # 2. 스캔 + 메타데이터
        scan_req = ScanRequest(
            scanId=f"build-analyze-{request_id}",
            projectId=body.project_id,
            projectPath=project_path,
            compileCommands=cc_path,
            buildProfile=scan_profile,
            provenance=body.provenance,
            rulesets=body.rulesets,
            thirdPartyPaths=body.third_party_paths,
            options=body.options,
        )
        rulesets = resolve_rulesets(body.rulesets, scan_profile, settings.default_rulesets)
        timeout = _get_timeout(request, body.options.timeout_seconds)

        async def _track_progress(tool: str, status: str, count: int, elapsed: int):
            request_summary_tracker.mark_progress(request_id, tool, status, count)

        async def _track_file_progress(tool: str, file: str, done: int, total: int):
            request_summary_tracker.mark_file_progress(request_id, file, done, total)

        async def _track_runtime_state(tool: str, tool_state: dict):
            request_summary_tracker.mark_runtime_state(request_id, tool_state)

        scan_result = await _run_scan_core(
            request_id,
            scan_req,
            rulesets,
            timeout,
            on_progress=_track_progress,
            on_file_progress=_track_file_progress,
            on_runtime_state=_track_runtime_state,
        )
        meta = await metadata_extractor.extract(scan_profile)

        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        request_summary_tracker.mark_completed(request_id)
        _log_terminal_request_summary(request_id)

        logger.info(
            "Build-and-analyze completed",
            extra={
                "requestId": request_id,
                "findingsCount": len(scan_result.findings or []),
                "functionsCount": len((scan_result.code_graph or {}).get("functions", [])),
                "libraryCount": len((scan_result.sca or {}).get("libraries", [])),
                "elapsedMs": elapsed_ms,
            },
        )

        return BuildAndAnalyzeResponse(
            success=True,
            provenance=body.provenance,
            build=build_response,
            scan=scan_result,
            codeGraph=scan_result.code_graph,
            libraries=(scan_result.sca or {}).get("libraries"),
            metadata=meta,
            staticEvidenceContract=build_static_evidence_contract(
                success=True,
                provenance=body.provenance,
                findings=scan_result.findings,
                execution=scan_result.execution,
                code_graph=scan_result.code_graph,
                sca=scan_result.sca,
                metadata=meta,
            ),
            elapsedMs=elapsed_ms,
        )

    except PolicyViolationError as exc:
        request_summary_tracker.mark_failed(request_id, exc.message)
        _log_terminal_request_summary(request_id)
        response.status_code = exc.status_code
        if build_response is None:
            return _error_response(request_id, exc, response)
        scan_result = exc.scan_response
        return BuildAndAnalyzeResponse(
            success=False,
            provenance=body.provenance,
            build=build_response,
            scan=scan_result,
            codeGraph=scan_result.code_graph,
            libraries=(scan_result.sca or {}).get("libraries"),
            staticEvidenceContract=build_static_evidence_contract(
                success=False,
                provenance=body.provenance,
                findings=scan_result.findings,
                execution=scan_result.execution,
                code_graph=scan_result.code_graph,
                sca=scan_result.sca,
                policy_failure_reason_codes=["POLICY_VIOLATION", str(exc.code)],
            ),
            error=exc.message,
            errorDetail=scan_result.error_detail,
        )

    except Exception as exc:
        request_summary_tracker.mark_failed(request_id, str(exc))
        _log_terminal_request_summary(request_id)
        return _error_response(request_id, exc, response)


@router.post("/build")
async def build(
    request: Request,
    response: Response,
    body: BuildRequest,
) -> BuildResponse | dict:
    """빌드만 수행 — bear → compile_commands.json 생성.

    스캔/SCA/코드그래프는 별도 호출. 서브 프로젝트 파이프라인의 빌드 단계용.
    """
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    project_path = body.project_path
    if not project_path:
        response.status_code = 400
        return {"success": False, "error": "projectPath is required"}

    project_dir = Path(project_path)
    if not project_dir.is_dir():
        response.status_code = 400
        return {"success": False, "error": f"projectPath not found: {project_path}"}

    build_command = body.build_command
    if not build_command:
        response.status_code = 400
        return {"success": False, "error": "buildCommand is required"}

    wrap_with_bear = body.wrap_with_bear
    build_timeout = _get_timeout(request)

    if _wants_async_ownership(request):
        async def _owned_build() -> BuildResponse:
            request_summary_tracker.mark_started(
                request_id,
                last_ack_source="build-started",
                local_ack_state="phase-advancing",
            )

            async def _track_build_runtime(state: dict):
                request_summary_tracker.mark_runtime_state(
                    request_id,
                    state,
                    local_ack_state=state.get("localAckState"),
                    last_ack_source=state.get("lastAckSource"),
                )

            result = await build_runner.build(
                project_dir,
                build_command,
                environment=body.build_environment,
                wrap_with_bear=wrap_with_bear,
                timeout=None,
                timeout_seconds_for_evidence=build_timeout,
                timeout_mode="async-ownership-no-caller-deadline",
                timeout_enforced=False,
                on_runtime_state=_track_build_runtime,
            )
            _log_build_execution_summary(
                request_id=request_id,
                endpoint="build",
                result=result,
                project_path=project_path,
            )
            return _to_build_response(result, body.provenance)

        payload, status_code = await request_ownership_store.submit(
            request_id,
            endpoint="build",
            runner=_owned_build,
        )
        return _ownership_response(payload, status_code)

    try:
        request_summary_tracker.register(request_id, endpoint="build")
        request_summary_tracker.mark_started(
            request_id,
            last_ack_source="build-started",
            local_ack_state="phase-advancing",
        )

        async def _track_build_runtime(state: dict):
            request_summary_tracker.mark_runtime_state(
                request_id,
                state,
                local_ack_state=state.get("localAckState"),
                last_ack_source=state.get("lastAckSource"),
            )

        logger.info(
            "Build started",
            extra={"requestId": request_id, "projectPath": project_path, "buildCommand": build_command,
                    "wrapWithBear": wrap_with_bear, "timeoutS": build_timeout},
        )
        result = await build_runner.build(
            project_dir,
            build_command,
            environment=body.build_environment,
            wrap_with_bear=wrap_with_bear,
            timeout=build_timeout,
            on_runtime_state=_track_build_runtime,
        )
        _log_build_execution_summary(
            request_id=request_id,
            endpoint="build",
            result=result,
            project_path=project_path,
        )
        if result.get("success"):
            request_summary_tracker.mark_completed(request_id)
        else:
            failure_detail = result.get("failureDetail") or {}
            request_summary_tracker.mark_failed(
                request_id,
                failure_detail.get("summary") or "build failed",
            )
        _log_terminal_request_summary(request_id)

        return _to_build_response(result, body.provenance)

    except Exception as exc:
        request_summary_tracker.mark_failed(
            request_id,
            exc.message if isinstance(exc, SastRunnerError) else str(exc),
        )
        _log_terminal_request_summary(request_id)
        return _error_response(request_id, exc, response)


@router.post("/discover-targets")
async def discover_targets(
    request: Request,
    response: Response,
    body: DiscoverTargetsRequest,
):
    """프로젝트 내 빌드 타겟(독립 빌드 단위)을 자동 탐색.

    빌드 파일(CMakeLists.txt, Makefile, meson.build 등)을 재귀 탐색하여
    각 빌드 단위를 반환한다. 빌드 실행 없이 파일시스템 스캔만 수행.
    """
    request_id = _get_request_id(request)
    set_request_id(request_id)
    response.headers["X-Request-Id"] = request_id

    project_path = body.project_path
    if not project_path:
        response.status_code = 400
        return {"error": "projectPath is required"}

    project_dir = Path(project_path)
    if not project_dir.is_dir():
        response.status_code = 400
        return {"error": f"projectPath not found: {project_path}"}

    try:
        t0 = time.perf_counter()
        targets = build_runner.discover_targets(project_dir)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
    except Exception as exc:
        return _error_response(request_id, exc, response)

    logger.info(
        "Target discovery completed",
        extra={
            "requestId": request_id,
            "projectPath": project_path,
            "targetCount": len(targets),
            "elapsedMs": elapsed_ms,
        },
    )

    return {"targets": targets, "elapsedMs": elapsed_ms}


@router.get("/requests/{request_id}")
async def request_status(request_id: str) -> JSONResponse:
    """Durable ownership status for async production requests."""
    payload, status_code = await request_ownership_store.get_status(request_id)
    return JSONResponse(payload, status_code=status_code)


@router.get("/requests/{request_id}/result")
async def request_result(request_id: str) -> JSONResponse:
    """Durable terminal result/failure retrieval for async production requests."""
    payload, status_code = await request_ownership_store.get_result(request_id)
    return JSONResponse(payload, status_code=status_code)


@router.delete("/requests/{request_id}")
async def cancel_request(request_id: str) -> JSONResponse:
    """Best-effort durable ownership cancellation for async production requests."""
    payload, status_code = await request_ownership_store.cancel(request_id)
    return _ownership_response(payload, status_code)


@router.get("/health", response_model=HealthResponse)
async def health(request_id: str | None = Query(default=None, alias="requestId")) -> HealthResponse:
    """서비스 상태 및 도구 가용성 확인."""
    tools = await orchestrator.check_tools(force=True)
    policy = orchestrator.build_health_policy(tools)

    return HealthResponse(
        semgrep=tools.get("semgrep", {}),
        tools=tools,
        defaultRulesets=settings.default_rulesets,
        policyStatus=policy["policyStatus"],
        policyReasons=policy["policyReasons"],
        unavailableTools=policy["unavailableTools"],
        allowedSkipReasons=policy["allowedSkipReasons"],
        activeRequestCount=request_summary_tracker.active_request_count(),
        requestSummary=request_summary_tracker.get_summary(request_id),
    )
