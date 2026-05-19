"""Phase 1 executor façade for analysis-agent."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from app.agent_runtime.llm.generation_policy import TimeoutDefaults
from app.core.phase_one_exec import (
    ingest_code_graph as _phase_one_ingest_code_graph,
    run_build_and_analyze as _phase_one_run_build_and_analyze,
    run_codegraph as _phase_one_run_codegraph,
    run_individual_tools as _phase_one_run_individual_tools,
    run_sast as _phase_one_run_sast,
    run_sca as _phase_one_run_sca,
)
from app.core.phase_one_flow import execute_phase_one as _phase_one_execute
from app.core.phase_one_kb import (
    extract_cwe_ids as _phase_one_extract_cwe_ids,
    extract_dangerous_funcs as _phase_one_extract_dangerous_funcs,
    fetch_project_memory as _phase_one_fetch_project_memory,
    run_cve_lookup as _phase_one_run_cve_lookup,
    run_dangerous_callers as _phase_one_run_dangerous_callers,
    run_threat_query as _phase_one_run_threat_query,
)
from app.core.phase_one_types import CODEGRAPH_EXCLUDE_DIRS, Phase1Result

if TYPE_CHECKING:
    from app.core.agent_session import AgentSession
    from app.agent_runtime.tools.base import ToolImplementation

logger = logging.getLogger(__name__)


class Phase1Executor:
    """LLM 없이 결정론적으로 SAST + 코드 그래프 + SCA + KB 위협 조회 + 위험 호출자를 실행한다."""

    def __init__(
        self,
        sast_tool: ToolImplementation | None = None,
        codegraph_tool: ToolImplementation | None = None,
        sca_tool: ToolImplementation | None = None,
        kb_endpoint: str = "http://localhost:8002",
        sast_endpoint: str = "http://localhost:9000",
        timeout_budget_ms: int = 540_000,
    ) -> None:
        self._sast_tool = sast_tool
        self._codegraph_tool = codegraph_tool
        self._sca_tool = sca_tool
        self._kb_endpoint = kb_endpoint
        self._timeout_budget_ms = timeout_budget_ms
        sast_timeout_s = max(TimeoutDefaults.TOOL_EXECUTION_SECONDS, timeout_budget_ms / 1000.0 * 0.8)
        kb_timeout_s = 100.0
        self._kb_client = httpx.AsyncClient(base_url=kb_endpoint, timeout=kb_timeout_s)
        self._sast_client = httpx.AsyncClient(base_url=sast_endpoint, timeout=sast_timeout_s)

    async def execute(self, session: AgentSession) -> Phase1Result:
        """Phase 1: SAST 스캔 + 코드 그래프 + SCA + KB 위협 조회 + 위험 호출자."""
        return await _phase_one_execute(self, session, logger)

    async def _run_build_and_analyze(
        self, result: Phase1Result, project_id, project_path, build_command, build_profile, request_id,
        *, build_environment: dict | None = None,
        provenance: dict | None = None,
        third_party_paths: list[str] | None = None,
    ) -> Phase1Result | None:
        return await _phase_one_run_build_and_analyze(
            self._sast_client,
            self._timeout_budget_ms,
            result,
            project_id,
            project_path,
            build_command,
            build_profile,
            request_id,
            logger,
            build_environment=build_environment,
            provenance=provenance,
            third_party_paths=third_party_paths,
        )

    async def _run_individual_tools(
        self, result: Phase1Result, files, project_id, project_path, build_profile, request_id,
        *, third_party_paths: list[str] | None = None,
        sast_tools: list[str] | None = None,
        compile_commands_path: str | None = None,
        revision_hint: str | None = None,
        provenance: dict | None = None,
        build_environment: dict | None = None,
    ) -> Phase1Result:
        return await _phase_one_run_individual_tools(
            result,
            files,
            project_id,
            project_path,
            build_profile,
            request_id,
            logger,
            sast_tool=self._sast_tool,
            codegraph_tool=self._codegraph_tool,
            sca_tool=self._sca_tool,
            kb_client=self._kb_client,
            codegraph_exclude_dirs=CODEGRAPH_EXCLUDE_DIRS,
            third_party_paths=third_party_paths,
            sast_tools=sast_tools,
            compile_commands_path=compile_commands_path,
            revision_hint=revision_hint,
            provenance=provenance,
            build_environment=build_environment,
        )

    async def _ingest_code_graph(
        self, result: Phase1Result, project_id: str, request_id: str,
        revision_hint: str | None = None,
        provenance: dict | None = None,
        compile_commands_path: str | None = None,
        build_profile: dict | None = None,
        build_environment: dict | None = None,
        build_target: str | None = None,
    ) -> None:
        await _phase_one_ingest_code_graph(
            self._kb_client,
            result,
            project_id,
            request_id,
            logger,
            codegraph_exclude_dirs=CODEGRAPH_EXCLUDE_DIRS,
            revision_hint=revision_hint,
            provenance=provenance,
            compile_commands_path=compile_commands_path,
            build_profile=build_profile,
            build_environment=build_environment,
            build_target=build_target,
        )

    async def _run_sast(
        self, result: Phase1Result, files, project_id, build_profile, request_id,
        *, third_party_paths: list[str] | None = None,
        project_path: str | None = None,
        compile_commands_path: str | None = None,
        sast_tools: list[str] | None = None,
        build_environment: dict | None = None,
    ) -> Phase1Result:
        return await _phase_one_run_sast(
            self._sast_tool,
            result,
            files,
            project_id,
            build_profile,
            request_id,
            logger,
            third_party_paths=third_party_paths,
            project_path=project_path,
            compile_commands_path=compile_commands_path,
            sast_tools=sast_tools,
            build_environment=build_environment,
        )

    async def _run_codegraph(
        self, result: Phase1Result, files, project_id, build_profile, request_id,
        *, project_path: str | None = None,
        compile_commands_path: str | None = None,
        build_environment: dict | None = None,
    ) -> Phase1Result:
        return await _phase_one_run_codegraph(
            self._codegraph_tool,
            result,
            files,
            project_id,
            build_profile,
            request_id,
            logger,
            project_path=project_path,
            compile_commands_path=compile_commands_path,
            build_environment=build_environment,
        )

    async def _run_sca(
        self, result: Phase1Result, project_id, project_path, request_id,
    ) -> Phase1Result:
        return await _phase_one_run_sca(
            self._sca_tool,
            result,
            project_id,
            project_path,
            request_id,
            logger,
        )

    async def _run_cve_lookup(self, result: Phase1Result) -> Phase1Result:
        return await _phase_one_run_cve_lookup(self._kb_client, result, logger)

    async def _run_threat_query(self, result: Phase1Result) -> Phase1Result:
        return await _phase_one_run_threat_query(self._kb_client, result, logger)

    async def _run_dangerous_callers(
        self,
        result: Phase1Result,
        project_id: str,
        *,
        provenance: dict | None = None,
    ) -> Phase1Result:
        return await _phase_one_run_dangerous_callers(
            self._kb_client, result, project_id, logger, provenance=provenance,
        )

    async def _fetch_project_memory(
        self, project_id: str, request_id: str,
        revision_hint: str | None = None,
        provenance: dict | None = None,
    ) -> list[dict]:
        return await _phase_one_fetch_project_memory(
            self._kb_client,
            project_id,
            request_id,
            logger,
            revision_hint=revision_hint,
            provenance=provenance,
        )

    @staticmethod
    def _extract_cwe_ids(findings: list[dict]) -> set[str]:
        return _phase_one_extract_cwe_ids(findings)

    @staticmethod
    def _extract_dangerous_funcs(findings: list[dict]) -> set[str]:
        return _phase_one_extract_dangerous_funcs(findings)

    async def aclose(self) -> None:
        """HTTP 클라이언트 종료."""
        await self._kb_client.aclose()
        await self._sast_client.aclose()
