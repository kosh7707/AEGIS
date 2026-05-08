"""Execution helpers for analysis-agent Phase 1."""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from app.clients.kb_error_utils import is_kb_timeout_error
from app.clients.s4_ownership import S4OwnershipError, S4OwnershipUnsupported, post_and_wait_s4_ownership
from app.agent_runtime.observability import agent_log
from app.runtime.request_summary import request_summary_tracker

if TYPE_CHECKING:
    import httpx

    from app.core.phase_one_types import Phase1Result
    from app.agent_runtime.tools.base import ToolImplementation


def _s4_build_profile(build_profile) -> dict:
    """Normalize S4-facing buildProfile/scanProfile.

    S4 no longer accepts the legacy sdkId='custom' native-build sentinel. Native
    builds must omit sdkId entirely while preserving other profile hints.
    """
    if not isinstance(build_profile, dict):
        return {}
    normalized = {
        key: value
        for key, value in build_profile.items()
        if not (key == "sdkId" and value == "custom")
    }
    return normalized


async def run_build_and_analyze(
    sast_client: "httpx.AsyncClient",
    timeout_budget_ms: int,
    result: "Phase1Result",
    project_id,
    project_path,
    build_command,
    build_profile,
    request_id,
    logger: logging.Logger,
    *,
    build_environment: dict | None = None,
    provenance: dict | None = None,
    third_party_paths: list[str] | None = None,
) -> "Phase1Result | None":
    """S4 build-and-analyze 한 번에 호출. 실패 시 None 반환 (fallback 유도)."""
    agent_log(
        logger, "Phase 1: build-and-analyze",
        component="phase_one", phase="build_and_analyze_start",
        projectPath=project_path, hasBuildCommand=bool(build_command),
    )

    body: dict = {
        "projectPath": project_path,
        "projectId": project_id,
    }
    if build_command:
        body["buildCommand"] = build_command
    if isinstance(build_environment, dict) and build_environment:
        body["buildEnvironment"] = build_environment
    scan_profile = _s4_build_profile(build_profile)
    if scan_profile:
        body["scanProfile"] = scan_profile
    if isinstance(provenance, dict) and provenance:
        body["provenance"] = provenance
    if third_party_paths:
        body["thirdPartyPaths"] = third_party_paths

    ba_timeout = int(timeout_budget_ms * 0.8)
    headers: dict[str, str] = {"X-Timeout-Ms": str(ba_timeout)}
    if request_id:
        headers["X-Request-Id"] = request_id

    start = time.monotonic()
    status_code = 200
    try:
        request_summary_tracker.mark_transport_only(
            request_id or project_id,
            source="s4-build-and-analyze-wait",
        )
        try:
            ownership = await post_and_wait_s4_ownership(
                sast_client,
                base_url=str(sast_client.base_url).rstrip("/"),
                endpoint_path="/v1/build-and-analyze",
                payload=body,
                root_request_id=request_id,
                operation="phase1_build_and_analyze",
            )
            data = ownership.payload
        except S4OwnershipUnsupported:
            resp = await sast_client.post(
                "/v1/build-and-analyze",
                json=body,
                headers=headers,
            )
            status_code = resp.status_code
            data = resp.json()
        except S4OwnershipError as exc:
            if isinstance(exc.payload, dict):
                status_code = exc.status_code or 500
                data = exc.payload
            else:
                raise
    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        agent_log(
            logger, "Phase 1: build-and-analyze 실패",
            component="phase_one", phase="build_and_analyze_error",
            error=str(exc), latencyMs=elapsed,
            level=logging.WARNING,
        )
        return None

    elapsed = int((time.monotonic() - start) * 1000)

    if isinstance(data, dict):
        build_info = data.get("build", {})
        if not isinstance(build_info, dict):
            build_info = {}
        build_evidence = build_info.get("buildEvidence", {})
        if not isinstance(build_evidence, dict):
            build_evidence = {}
        compile_commands_path = build_evidence.get("compileCommandsPath")
        if isinstance(compile_commands_path, str) and compile_commands_path:
            result.build_compile_commands_path = compile_commands_path

        failure_detail = data.get("failureDetail", {})
        if isinstance(failure_detail, dict):
            result.build_failure_detail = failure_detail

    if status_code >= 400:
        agent_log(
            logger, "Phase 1: build-and-analyze HTTP 실패",
            component="phase_one", phase="build_and_analyze_http_error",
            statusCode=status_code,
            errorCode=result.build_failure_detail.get("code") or result.build_failure_detail.get("category"),
            compileCommandsPath=result.build_compile_commands_path,
            latencyMs=elapsed,
            level=logging.WARNING,
        )
        return None

    if not data.get("success", True):
        agent_log(
            logger, "Phase 1: build-and-analyze 비성공 응답",
            component="phase_one", phase="build_and_analyze_unsuccessful",
            error=data.get("error"),
            errorCode=result.build_failure_detail.get("code") or result.build_failure_detail.get("category"),
            compileCommandsPath=result.build_compile_commands_path,
            latencyMs=elapsed,
            level=logging.WARNING,
        )
        return None

    scan_data = data.get("scan")
    if not isinstance(scan_data, dict):
        agent_log(
            logger, "Phase 1: build-and-analyze scan 누락",
            component="phase_one", phase="build_and_analyze_missing_scan",
            latencyMs=elapsed,
            level=logging.WARNING,
        )
        return None
    result.sast_findings = scan_data.get("findings", [])
    result.sast_stats = scan_data.get("stats", {})
    result.sast_duration_ms = scan_data.get("execution", {}).get("elapsedMs", 0)

    for tool_name, tool_result in scan_data.get("execution", {}).get("toolResults", {}).items():
        status = tool_result.get("status", "ok")
        if status in ("partial", "failed"):
            result.sast_partial_tools.append(tool_name)
            result.sast_timed_out_files += tool_result.get("timedOutFiles", 0)

    code_graph = data.get("codeGraph", {})
    if not isinstance(code_graph, dict):
        code_graph = {}
    result.code_functions = code_graph.get("functions", [])
    result.code_graph_duration_ms = 0

    libraries = data.get("libraries", [])
    result.sca_libraries = libraries if isinstance(libraries, list) else []
    result.sca_duration_ms = 0

    build_info = data.get("build", {})
    if not isinstance(build_info, dict):
        build_info = {}

    agent_log(
        logger, "Phase 1: build-and-analyze 완료",
        component="phase_one", phase="build_and_analyze_end",
        buildSuccess=build_info.get("success"),
        findings=len(result.sast_findings),
        functions=len(result.code_functions),
        libraries=len(result.sca_libraries),
        totalMs=elapsed,
    )
    return result


async def run_individual_tools(
    result: "Phase1Result",
    files,
    project_id,
    project_path,
    build_profile,
    request_id,
    logger: logging.Logger,
    *,
    sast_tool: "ToolImplementation | None" = None,
    codegraph_tool: "ToolImplementation | None" = None,
    sca_tool: "ToolImplementation | None" = None,
    kb_client: "httpx.AsyncClient",
    codegraph_exclude_dirs: frozenset[str],
    third_party_paths: list[str] | None = None,
    sast_tools: list[str] | None = None,
    compile_commands_path: str | None = None,
    revision_hint: str | None = None,
    provenance: dict | None = None,
) -> "Phase1Result":
    """개별 도구 호출 (files 또는 projectPath 기반)."""
    if sast_tool and (files or project_path):
        result = await run_sast(
            sast_tool, result, files, project_id, build_profile, request_id, logger,
            third_party_paths=third_party_paths,
            project_path=project_path,
            compile_commands_path=compile_commands_path,
            sast_tools=sast_tools,
        )
    if codegraph_tool and (files or project_path):
        result = await run_codegraph(
            codegraph_tool, result, files, project_id, build_profile, request_id, logger,
            project_path=project_path,
            compile_commands_path=compile_commands_path,
        )
    if sca_tool and project_path:
        result = await run_sca(sca_tool, result, project_id, project_path, request_id, logger)

    if result.code_functions and project_id:
        await ingest_code_graph(
            kb_client, result, project_id, request_id, logger,
            codegraph_exclude_dirs=codegraph_exclude_dirs,
            revision_hint=revision_hint,
            provenance=provenance,
        )

    return result


async def ingest_code_graph(
    kb_client: "httpx.AsyncClient",
    result: "Phase1Result",
    project_id: str,
    request_id: str,
    logger: logging.Logger,
    *,
    codegraph_exclude_dirs: frozenset[str],
    revision_hint: str | None = None,
    provenance: dict | None = None,
) -> None:
    """코드 그래프를 S5 KB에 적재한다. 노이즈 디렉토리만 제외."""
    relevant_functions = [
        func for func in result.code_functions
        if func.get("origin") or not any(
            part in codegraph_exclude_dirs
            for part in func.get("file", "").split("/")
        )
    ]
    if not relevant_functions:
        return

    agent_log(
        logger, "Phase 1: KB 코드 그래프 적재",
        component="phase_one", phase="kb_ingest_start",
        functionCount=len(relevant_functions),
    )

    headers: dict[str, str] = {"X-Timeout-Ms": "90000"}
    if request_id:
        headers["X-Request-Id"] = request_id

    try:
        body: dict = {"functions": relevant_functions}
        if revision_hint:
            body["revisionHint"] = revision_hint
        if isinstance(provenance, dict) and provenance:
            body["provenance"] = provenance
        resp = await kb_client.post(
            f"/v1/code-graph/{project_id}/ingest",
            json=body,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        readiness = data.get("readiness", {}) if isinstance(data.get("readiness"), dict) else {}
        warnings = data.get("warnings", [])
        if not isinstance(warnings, list):
            warnings = []

        result.code_graph_status = data.get("status") if isinstance(data.get("status"), str) else result.code_graph_status

        if readiness:
            if "neo4jGraph" in readiness:
                result.code_graph_neo4j_ready = bool(readiness.get("neo4jGraph"))
            if "vectorIndex" in readiness:
                result.code_graph_vector_ready = bool(readiness.get("vectorIndex"))
            if "graphRag" in readiness:
                result.code_graph_graph_rag_ready = bool(readiness.get("graphRag"))
        else:
            node_count = data.get("nodeCount", 0)
            vector_count = data.get("vectorCount", node_count)
            if isinstance(node_count, int):
                result.code_graph_neo4j_ready = node_count > 0
            if isinstance(vector_count, int):
                result.code_graph_vector_ready = vector_count > 0
            if result.code_graph_neo4j_ready is not None and result.code_graph_vector_ready is not None:
                result.code_graph_graph_rag_ready = (
                    result.code_graph_neo4j_ready and result.code_graph_vector_ready
                )

        result.code_graph_warnings = [str(item) for item in warnings]

        agent_log(
            logger, "Phase 1: KB 코드 그래프 적재 완료",
            component="phase_one", phase="kb_ingest_end",
            nodeCount=data.get("nodeCount", 0),
            edgeCount=data.get("edgeCount", 0),
            codeGraphStatus=result.code_graph_status,
            neo4jReady=result.code_graph_neo4j_ready,
            vectorReady=result.code_graph_vector_ready,
            graphRagReady=result.code_graph_graph_rag_ready,
            warnings=result.code_graph_warnings,
        )
    except Exception as exc:
        if is_kb_timeout_error(exc):
            result.code_graph_ingest_timed_out = True
            agent_log(
                logger, "Phase 1: KB 코드 그래프 적재 timeout",
                component="phase_one", phase="kb_ingest_timeout",
                level=logging.WARNING,
            )
        agent_log(
            logger, "Phase 1: KB 코드 그래프 적재 실패",
            component="phase_one", phase="kb_ingest_error",
            error=str(exc), level=logging.WARNING,
        )


async def run_sast(
    sast_tool: "ToolImplementation",
    result: "Phase1Result",
    files,
    project_id,
    build_profile,
    request_id,
    logger: logging.Logger,
    *,
    third_party_paths: list[str] | None = None,
    project_path: str | None = None,
    compile_commands_path: str | None = None,
    sast_tools: list[str] | None = None,
) -> "Phase1Result":
    """SAST 스캔 실행."""
    agent_log(
        logger, "Phase 1: SAST 스캔",
        component="phase_one", phase="sast_start",
        fileCount=len(files) if files else 0,
        projectPath=project_path,
        thirdPartyPaths=len(third_party_paths) if third_party_paths else 0,
        tools=sast_tools,
    )

    args: dict = {
        "scanId": f"{request_id}-phase1",
        "projectId": project_id,
    }
    if project_path:
        args["projectPath"] = project_path
    if compile_commands_path:
        args["compileCommands"] = compile_commands_path
    normalized_build_profile = _s4_build_profile(build_profile)
    if normalized_build_profile:
        args["buildProfile"] = normalized_build_profile
    if third_party_paths:
        args["thirdPartyPaths"] = third_party_paths
    if sast_tools:
        args.setdefault("options", {})["tools"] = sast_tools

    start = time.monotonic()
    try:
        tool_result = await sast_tool.execute(args)
        result.sast_duration_ms = int((time.monotonic() - start) * 1000)

        if tool_result.success:
            data = json.loads(tool_result.content)
            result.sast_findings = data.get("findings", [])
            result.sast_stats = data.get("stats", {})

            for tool_name, tool_result_info in data.get("execution", {}).get("toolResults", {}).items():
                status = tool_result_info.get("status", "ok")
                if status in ("partial", "failed"):
                    result.sast_partial_tools.append(tool_name)
                    result.sast_timed_out_files += tool_result_info.get("timedOutFiles", 0)

            agent_log(
                logger, "Phase 1: SAST 완료",
                component="phase_one", phase="sast_end",
                findings=len(result.sast_findings),
                partialTools=result.sast_partial_tools or None,
                timedOutFiles=result.sast_timed_out_files or None,
                durationMs=result.sast_duration_ms,
            )
        else:
            agent_log(
                logger, "Phase 1: SAST 실패",
                component="phase_one", phase="sast_error",
                error=tool_result.error,
                level=logging.WARNING,
            )
    except Exception as exc:
        result.sast_duration_ms = int((time.monotonic() - start) * 1000)
        agent_log(
            logger, "Phase 1: SAST 예외",
            component="phase_one", phase="sast_error",
            error=str(exc), level=logging.ERROR,
        )

    return result


async def run_codegraph(
    codegraph_tool: "ToolImplementation",
    result: "Phase1Result",
    files,
    project_id,
    build_profile,
    request_id,
    logger: logging.Logger,
    *,
    project_path: str | None = None,
    compile_commands_path: str | None = None,
) -> "Phase1Result":
    """코드 그래프 추출."""
    agent_log(
        logger, "Phase 1: 코드 그래프 추출",
        component="phase_one", phase="codegraph_start",
    )

    args: dict = {
        "scanId": f"{request_id}-phase1-func",
        "projectId": project_id,
    }
    if project_path:
        args["projectPath"] = project_path
    if compile_commands_path:
        args["compileCommands"] = compile_commands_path
    normalized_build_profile = _s4_build_profile(build_profile)
    if normalized_build_profile:
        args["buildProfile"] = normalized_build_profile

    start = time.monotonic()
    try:
        tool_result = await codegraph_tool.execute(args)
        result.code_graph_duration_ms = int((time.monotonic() - start) * 1000)

        if tool_result.success:
            data = json.loads(tool_result.content)
            result.code_functions = data.get("functions", [])
            agent_log(
                logger, "Phase 1: 코드 그래프 완료",
                component="phase_one", phase="codegraph_end",
                functions=len(result.code_functions),
                durationMs=result.code_graph_duration_ms,
            )
        else:
            agent_log(
                logger, "Phase 1: 코드 그래프 실패",
                component="phase_one", phase="codegraph_error",
                error=tool_result.error,
                level=logging.WARNING,
            )
    except Exception as exc:
        result.code_graph_duration_ms = int((time.monotonic() - start) * 1000)
        agent_log(
            logger, "Phase 1: 코드 그래프 예외",
            component="phase_one", phase="codegraph_error",
            error=str(exc), level=logging.ERROR,
        )

    return result


async def run_sca(
    sca_tool: "ToolImplementation",
    result: "Phase1Result",
    project_id,
    project_path,
    request_id,
    logger: logging.Logger,
) -> "Phase1Result":
    """SCA 라이브러리 식별 + upstream diff."""
    agent_log(
        logger, "Phase 1: SCA 라이브러리 식별",
        component="phase_one", phase="sca_start",
        projectPath=project_path,
    )

    args = {
        "scanId": f"{request_id}-phase1-sca",
        "projectId": project_id,
        "projectPath": project_path,
    }

    start = time.monotonic()
    try:
        tool_result = await sca_tool.execute(args)
        result.sca_duration_ms = int((time.monotonic() - start) * 1000)

        if tool_result.success:
            data = json.loads(tool_result.content)
            result.sca_libraries = data.get("libraries", [])
            agent_log(
                logger, "Phase 1: SCA 완료",
                component="phase_one", phase="sca_end",
                libraries=len(result.sca_libraries),
                durationMs=result.sca_duration_ms,
            )
        else:
            agent_log(
                logger, "Phase 1: SCA 실패",
                component="phase_one", phase="sca_error",
                error=tool_result.error,
                level=logging.WARNING,
            )
    except Exception as exc:
        result.sca_duration_ms = int((time.monotonic() - start) * 1000)
        agent_log(
            logger, "Phase 1: SCA 예외",
            component="phase_one", phase="sca_error",
            error=str(exc), level=logging.ERROR,
        )

    return result
