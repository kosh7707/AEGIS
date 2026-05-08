"""Shared types/constants for analysis-agent Phase 1."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Phase1Result:
    """Phase 1 실행 결과."""

    sast_findings: list[dict] = field(default_factory=list)
    sast_stats: dict = field(default_factory=dict)
    sast_scan_attempted: bool = False
    sast_scan_completed: bool = False
    sast_failure_detail: dict = field(default_factory=dict)
    code_functions: list[dict] = field(default_factory=list)
    sca_libraries: list[dict] = field(default_factory=list)
    threat_context: list[dict] = field(default_factory=list)
    dangerous_callers: list[dict] = field(default_factory=list)
    cve_lookup: list[dict] = field(default_factory=list)
    project_memory: list[dict] = field(default_factory=list)
    kb_degraded: bool = False
    kb_not_ready: bool = False
    kb_timed_out: bool = False
    cve_lookup_timed_out: bool = False
    dangerous_callers_timed_out: bool = False
    code_graph_status: str | None = None
    code_graph_neo4j_ready: bool | None = None
    code_graph_vector_ready: bool | None = None
    code_graph_graph_rag_ready: bool | None = None
    code_graph_warnings: list[str] = field(default_factory=list)
    code_graph_ingest_timed_out: bool = False
    sast_partial_tools: list[str] = field(default_factory=list)
    sast_timed_out_files: int = 0
    build_compile_commands_path: str | None = None
    build_failure_detail: dict = field(default_factory=dict)
    sast_duration_ms: int = 0
    code_graph_duration_ms: int = 0
    sca_duration_ms: int = 0
    cve_lookup_duration_ms: int = 0
    threat_query_duration_ms: int = 0
    dangerous_callers_duration_ms: int = 0
    total_duration_ms: int = 0


CODEGRAPH_EXCLUDE_DIRS = frozenset({
    "test", "tests", "third_party", "vendor", "external",
    "deps", "node_modules", ".git",
})
