from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.config import SERVICE_VERSION
from app.schemas.request import SnapshotProvenance


# --- ExecutionReport (typed schema for scan execution metadata) ---


class ToolExecutionResult(BaseModel):
    """개별 도구 실행 결과."""
    status: Literal["ok", "partial", "failed", "skipped"]
    findings_count: int = Field(alias="findingsCount")
    elapsed_ms: int = Field(alias="elapsedMs")
    skip_reason: str | None = Field(default=None, alias="skipReason")
    timed_out_files: int | None = Field(default=None, alias="timedOutFiles")
    failed_files: int | None = Field(default=None, alias="failedFiles")
    files_attempted: int | None = Field(default=None, alias="filesAttempted")
    batch_count: int | None = Field(default=None, alias="batchCount")
    timeout_budget_seconds: int | None = Field(default=None, alias="timeoutBudgetSeconds")
    per_file_timeout_seconds: int | None = Field(default=None, alias="perFileTimeoutSeconds")
    budget_warning: bool | None = Field(default=None, alias="budgetWarning")
    degraded: bool | None = None
    degrade_reasons: list[str] | None = Field(default=None, alias="degradeReasons")
    version: str | None = None

    model_config = {"populate_by_name": True, "by_alias": True}


class SdkResolutionInfo(BaseModel):
    """SDK 경로 해석 결과."""
    resolved: bool
    sdk_id: str | None = Field(default=None, alias="sdkId")
    include_paths_added: int = Field(default=0, alias="includePathsAdded")
    resolution_mode: str | None = Field(default=None, alias="resolutionMode")
    resolved_from: str | None = Field(default=None, alias="resolvedFrom")
    sdk_root_path: str | None = Field(default=None, alias="sdkRootPath")
    sdk_root_path_status: str | None = Field(default=None, alias="sdkRootPathStatus")
    degrade_reasons: list[str] = Field(default_factory=list, alias="degradeReasons")

    model_config = {"populate_by_name": True, "by_alias": True}


class FindingsFilterInfo(BaseModel):
    """SDK/외부 노이즈 필터링 + scope-early 결과."""
    before_filter: int = Field(alias="beforeFilter")
    after_filter: int = Field(alias="afterFilter")
    sdk_noise_removed: int = Field(default=0, alias="sdkNoiseRemoved")
    third_party_removed: int = Field(default=0, alias="thirdPartyRemoved")
    cross_boundary_kept: int = Field(default=0, alias="crossBoundaryKept")
    files_scoped_out: int = Field(default=0, alias="filesScopedOut")

    model_config = {"populate_by_name": True, "by_alias": True}


class ExecutionReport(BaseModel):
    """SAST 스캔 실행 보고서 — 도구별 상태, SDK 해석, 필터링 결과."""
    tools_run: list[str] = Field(alias="toolsRun")
    tool_results: dict[str, ToolExecutionResult] = Field(alias="toolResults")
    sdk: SdkResolutionInfo
    filtering: FindingsFilterInfo
    degraded: bool = False
    degrade_reasons: list[str] = Field(default_factory=list, alias="degradeReasons")

    model_config = {"populate_by_name": True, "by_alias": True}


# --- SastFinding (mirrors docs/api/shared-models.md:253-289 exactly) ---

class SastFindingLocation(BaseModel):
    file: str
    line: int
    column: int | None = None
    end_line: int | None = Field(default=None, alias="endLine")
    end_column: int | None = Field(default=None, alias="endColumn")

    model_config = {"populate_by_name": True, "by_alias": True}


class SastDataFlowStep(BaseModel):
    file: str
    line: int
    content: str | None = None

    model_config = {"by_alias": True}


class SastFinding(BaseModel):
    tool_id: str = Field(alias="toolId")
    rule_id: str = Field(alias="ruleId")
    severity: str
    message: str
    location: SastFindingLocation
    data_flow: list[SastDataFlowStep] | None = Field(default=None, alias="dataFlow")
    origin: str | None = None
    metadata: dict[str, Any] | None = None

    model_config = {"populate_by_name": True, "by_alias": True}


# --- Scan response ---

class ScanStats(BaseModel):
    files_scanned: int = Field(alias="filesScanned")
    rules_run: int = Field(alias="rulesRun")
    findings_total: int = Field(alias="findingsTotal")
    elapsed_ms: int = Field(alias="elapsedMs")

    model_config = {"populate_by_name": True, "by_alias": True}


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str | None = Field(default=None, alias="requestId")
    retryable: bool = False

    model_config = {"populate_by_name": True, "by_alias": True}


class ScanResponse(BaseModel):
    success: bool
    scan_id: str = Field(alias="scanId")
    status: str
    provenance: SnapshotProvenance | None = None
    findings: list[SastFinding] | None = None
    stats: ScanStats | None = None
    execution: ExecutionReport | None = None
    code_graph: dict[str, Any] | None = Field(default=None, alias="codeGraph")
    sca: dict[str, Any] | None = None
    static_evidence_contract: dict[str, Any] | None = Field(default=None, alias="staticEvidenceContract")
    error: str | None = None
    error_detail: ErrorDetail | None = Field(default=None, alias="errorDetail")

    model_config = {"populate_by_name": True, "by_alias": True}


class BuildFailureDetail(BaseModel):
    category: str
    summary: str
    matched_excerpt: str | None = Field(default=None, alias="matchedExcerpt")
    hint: str | None = None
    retryable: bool = False

    model_config = {"populate_by_name": True, "by_alias": True}


class BuildEvidence(BaseModel):
    requested_build_command: str = Field(alias="requestedBuildCommand")
    effective_build_command: str = Field(alias="effectiveBuildCommand")
    build_dir: str = Field(alias="buildDir")
    compile_commands_path: str | None = Field(default=None, alias="compileCommandsPath")
    entries: int | None = None
    user_entries: int | None = Field(default=None, alias="userEntries")
    exit_code: int | None = Field(default=None, alias="exitCode")
    build_output: str | None = Field(default=None, alias="buildOutput")
    wrap_with_bear: bool = Field(alias="wrapWithBear")
    timeout_seconds: int = Field(alias="timeoutSeconds")
    timeout_mode: str | None = Field(default=None, alias="timeoutMode")
    timeout_enforced: bool | None = Field(default=None, alias="timeoutEnforced")
    environment_keys: list[str] | None = Field(default=None, alias="environmentKeys")
    elapsed_ms: int = Field(alias="elapsedMs")

    model_config = {"populate_by_name": True, "by_alias": True}


class BuildReadiness(BaseModel):
    status: Literal["ready", "partial", "not-ready"]
    compile_commands_ready: bool = Field(alias="compileCommandsReady")
    quick_eligible: bool = Field(alias="quickEligible")
    summary: str

    model_config = {"populate_by_name": True, "by_alias": True}


class BuildResponse(BaseModel):
    success: bool
    provenance: SnapshotProvenance | None = None
    build_evidence: BuildEvidence = Field(alias="buildEvidence")
    readiness: BuildReadiness
    failure_detail: BuildFailureDetail | None = Field(default=None, alias="failureDetail")

    model_config = {"populate_by_name": True, "by_alias": True}


class BuildAndAnalyzeResponse(BaseModel):
    success: bool
    provenance: SnapshotProvenance | None = None
    build: BuildResponse
    scan: ScanResponse | None = None
    code_graph: dict[str, Any] | None = Field(default=None, alias="codeGraph")
    libraries: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None
    static_evidence_contract: dict[str, Any] | None = Field(default=None, alias="staticEvidenceContract")
    elapsed_ms: int | None = Field(default=None, alias="elapsedMs")
    error: str | None = None
    error_detail: ErrorDetail | None = Field(default=None, alias="errorDetail")

    model_config = {"populate_by_name": True, "by_alias": True}


class HealthRequestSummary(BaseModel):
    request_id: str | None = Field(default=None, alias="requestId")
    endpoint: str = "scan"
    state: Literal["idle", "queued", "running", "completed", "failed", "cancelled"]
    ack_status: Literal["idle", "active", "broken"] = Field(alias="ackStatus")
    local_ack_state: Literal["phase-advancing", "transport-only", "ack-break"] | None = Field(
        default=None,
        alias="localAckState",
    )
    last_ack_at: int | None = Field(default=None, alias="lastAckAt")
    last_ack_source: str | None = Field(default=None, alias="lastAckSource")
    local_ack_sources: list[str] = Field(default_factory=list, alias="localAckSources")
    degraded: bool = False
    degrade_reasons: list[str] = Field(default_factory=list, alias="degradeReasons")
    active_tools: list[str] = Field(default_factory=list, alias="activeTools")
    completed_tools: list[str] = Field(default_factory=list, alias="completedTools")
    findings_count: int = Field(default=0, alias="findingsCount")
    files_completed: int = Field(default=0, alias="filesCompleted")
    files_total: int = Field(default=0, alias="filesTotal")
    current_file: str | None = Field(default=None, alias="currentFile")
    blocked_reason: str | None = Field(default=None, alias="blockedReason")

    model_config = {"populate_by_name": True, "by_alias": True}


class HealthResponse(BaseModel):
    service: str = "s4-sast"
    status: str = "ok"
    version: str = SERVICE_VERSION
    semgrep: dict[str, Any] = {}
    tools: dict[str, Any] = {}
    default_rulesets: list[str] = Field(default_factory=list, alias="defaultRulesets")
    policy_status: str = Field(default="ok", alias="policyStatus")
    policy_reasons: list[str] = Field(default_factory=list, alias="policyReasons")
    unavailable_tools: list[str] = Field(default_factory=list, alias="unavailableTools")
    allowed_skip_reasons: list[str] = Field(default_factory=list, alias="allowedSkipReasons")
    active_request_count: int = Field(default=0, alias="activeRequestCount")
    request_summary: HealthRequestSummary = Field(
        default_factory=lambda: HealthRequestSummary(state="idle", ackStatus="idle", localAckState=None),
        alias="requestSummary",
    )

    model_config = {"populate_by_name": True, "by_alias": True}
