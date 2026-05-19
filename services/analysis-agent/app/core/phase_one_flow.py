"""Execution flow helpers for analysis-agent Phase 1."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from app.agent_runtime.context import get_request_id
from app.agent_runtime.observability import agent_log
from app.core.phase_one_types import Phase1Result
from app.core.s4_static_evidence import extract_static_evidence_contract, summarize_static_evidence_contract
from app.core.s4_tool_portfolio_report import extract_tool_portfolio_report, summarize_tool_portfolio_report

if TYPE_CHECKING:
    from app.core.agent_session import AgentSession


def resolve_analysis_path(project_path: str | None, target_path: str | None, logger: logging.Logger) -> str | None:
    analysis_path = project_path
    if project_path and target_path:
        from app.agent_runtime.path_util import resolve_scoped_path

        scoped = resolve_scoped_path(project_path, target_path)
        if scoped is not None:
            return scoped

        agent_log(
            logger, "targetPath directory traversal 차단",
            component="phase_one", phase="security",
            targetPath=target_path, level=logging.WARNING,
        )
    return analysis_path


async def execute_phase_one(executor, session: "AgentSession", logger: logging.Logger) -> Phase1Result:
    """Phase 1 main orchestration flow."""
    result = Phase1Result()
    start = time.monotonic()

    trusted = session.request.context.trusted
    build_preparation = trusted.get("buildPreparation") if isinstance(trusted.get("buildPreparation"), dict) else {}
    quick_context = trusted.get("quickContext") if isinstance(trusted.get("quickContext"), dict) else {}
    graph_context = trusted.get("graphContext") if isinstance(trusted.get("graphContext"), dict) else {}
    files = trusted.get("files", [])
    project_path = trusted.get("projectPath")
    target_path = trusted.get("targetPath")
    project_id = (
        trusted.get("projectId")
        or graph_context.get("projectId")
        or quick_context.get("projectId")
        or session.request.taskId
    )
    revision_hint = (
        trusted.get("revisionHint")
        or trusted.get("commitSha")
        or graph_context.get("revisionHint")
        or graph_context.get("commitSha")
    )
    build_profile = (
        trusted.get("buildProfile")
        or build_preparation.get("buildProfile")
        or quick_context.get("buildProfile")
    )
    build_command = trusted.get("buildCommand") or build_preparation.get("buildCommand")
    build_environment = trusted.get("buildEnvironment") or build_preparation.get("buildEnvironment")
    third_party_paths = (
        trusted.get("thirdPartyPaths")
        or quick_context.get("thirdPartyPaths")
        or build_preparation.get("thirdPartyPaths")
        or []
    )
    sast_tools = trusted.get("sastTools") or quick_context.get("sastTools")
    request_id = get_request_id() or session.request.taskId
    raw_provenance = (
        trusted.get("provenance")
        or quick_context.get("provenance")
        or graph_context.get("provenance")
        or build_preparation.get("provenance")
    )
    provenance = raw_provenance if isinstance(raw_provenance, dict) else None

    graph_readiness = graph_context.get("readiness") if isinstance(graph_context.get("readiness"), dict) else {}
    if graph_readiness:
        if "neo4jGraph" in graph_readiness:
            result.code_graph_neo4j_ready = bool(graph_readiness.get("neo4jGraph"))
        if "vectorIndex" in graph_readiness:
            result.code_graph_vector_ready = bool(graph_readiness.get("vectorIndex"))
        if "graphRag" in graph_readiness:
            result.code_graph_graph_rag_ready = bool(graph_readiness.get("graphRag"))
    if isinstance(graph_context.get("status"), str):
        result.code_graph_status = graph_context.get("status")
    graph_warnings = graph_context.get("warnings")
    if isinstance(graph_warnings, list):
        result.code_graph_warnings = [str(item) for item in graph_warnings]
    graph_functions = graph_context.get("functions")
    if isinstance(graph_functions, list):
        result.code_functions = [func for func in graph_functions if isinstance(func, dict)]

    analysis_path = resolve_analysis_path(project_path, target_path, logger)

    if project_id:
        result.project_memory = await executor._fetch_project_memory(
            project_id, request_id, revision_hint, provenance=provenance,
        )

    pre_findings = trusted.get("sastFindings")
    if pre_findings is None:
        pre_findings = quick_context.get("sastFindings")
    pre_static_contract = extract_static_evidence_contract(trusted, quick_context)
    pre_tool_portfolio_report = extract_tool_portfolio_report(trusted, quick_context)
    if pre_tool_portfolio_report:
        result.s4_tool_portfolio_report = pre_tool_portfolio_report
        result.s4_tool_portfolio_diagnostics = summarize_tool_portfolio_report(pre_tool_portfolio_report)
        result.s4_tool_portfolio_quality_ready = bool(result.s4_tool_portfolio_diagnostics.get("qualityReady"))
    pre_sca = trusted.get("scaLibraries")
    if pre_sca is None:
        pre_sca = quick_context.get("scaLibraries")

    if pre_findings is not None:
        result.sast_findings = pre_findings
        result.sast_scan_attempted = True
        result.sast_scan_completed = True
        result.sast_static_evidence_contract = pre_static_contract
        result.sast_static_evidence_diagnostics = summarize_static_evidence_contract(pre_static_contract)
        result.sast_static_evidence_ready = bool(result.sast_static_evidence_diagnostics.get("ready"))
        if pre_sca is not None:
            result.sca_libraries = pre_sca
        agent_log(
            logger, "Phase 1: pre-computed 결과 사용 (SAST/SCA 스킵)",
            component="phase_one", phase="phase1_precomputed",
            findings=len(result.sast_findings),
            libraries=len(result.sca_libraries),
        )
    elif not files and not project_path:
        agent_log(
            logger, "Phase 1 스킵: files와 projectPath 모두 없음",
            component="phase_one", phase="skip",
        )
        return result
    else:
        agent_log(
            logger, "Phase 1 시작",
            component="phase_one", phase="phase1_start",
            fileCount=len(files), projectId=project_id,
            hasProjectPath=bool(project_path), targetPath=target_path,
            hasBuildCommand=bool(build_command),
        )

        if analysis_path and build_command:
            ba_result = await executor._run_build_and_analyze(
                result, project_id, analysis_path, build_command, build_profile, request_id,
                build_environment=build_environment,
                provenance=provenance,
                third_party_paths=third_party_paths,
            )
            if ba_result is not None:
                result = ba_result
                if result.code_functions and project_id:
                    await executor._ingest_code_graph(
                        result,
                        project_id,
                        request_id,
                        revision_hint=revision_hint,
                        provenance=provenance,
                        compile_commands_path=result.build_compile_commands_path,
                        build_profile=build_profile,
                        build_environment=build_environment,
                        build_target=target_path or analysis_path,
                    )
            else:
                agent_log(
                    logger, "Phase 1: build-and-analyze 실패, 개별 도구 fallback",
                    component="phase_one", phase="ba_fallback",
                    level=logging.WARNING,
                )
                result = await executor._run_individual_tools(
                    result, files, project_id, analysis_path, build_profile, request_id,
                    third_party_paths=third_party_paths,
                    sast_tools=sast_tools,
                    compile_commands_path=result.build_compile_commands_path,
                    revision_hint=revision_hint,
                    provenance=provenance,
                    build_environment=build_environment,
                )
        else:
            result = await executor._run_individual_tools(
                result, files, project_id, analysis_path, build_profile, request_id,
                third_party_paths=third_party_paths,
                sast_tools=sast_tools,
                compile_commands_path=result.build_compile_commands_path,
                revision_hint=revision_hint,
                provenance=provenance,
                build_environment=build_environment,
            )

    if pre_findings is not None and result.code_functions and project_id:
        await executor._ingest_code_graph(
            result,
            project_id,
            request_id,
            revision_hint=revision_hint,
            provenance=provenance,
            compile_commands_path=result.build_compile_commands_path,
            build_profile=build_profile,
            build_environment=build_environment,
            build_target=target_path or analysis_path,
        )

    if result.sca_libraries:
        result = await executor._run_cve_lookup(result)

    if result.sast_findings:
        result = await executor._run_threat_query(result)

    if result.sast_findings and project_id and result.code_graph_neo4j_ready is not False:
        result = await executor._run_dangerous_callers(result, project_id, provenance=provenance)
    elif result.sast_findings and project_id:
        agent_log(
            logger, "Phase 1: dangerous-callers 건너뜀 (code graph not ready)",
            component="phase_one", phase="dangerous_callers_skipped",
            codeGraphStatus=result.code_graph_status,
            graphWarnings=result.code_graph_warnings,
            level=logging.WARNING,
        )

    result.total_duration_ms = int((time.monotonic() - start) * 1000)

    agent_log(
        logger, "Phase 1 완료",
        component="phase_one", phase="phase1_end",
        findings=len(result.sast_findings),
        functions=len(result.code_functions),
        totalMs=result.total_duration_ms,
    )

    return result
