import {
  Project,
  ProjectOwnerSummary,
  Adapter,
  AnalysisResult,
  AnalysisSummary,
  UploadedFile,
  DynamicAnalysisSession,
  DynamicTestConfig,
  DynamicTestResult,
  DynamicTestFinding,
  CanMessage,
  DynamicAlert,
  CanInjectionResponse,
  Run,
  Finding,
  EvidenceRef,
  FindingStatus,
  Severity,
  AuditLogEntry,
  GateResult,
  ApprovalRequest,
  ModuleReport,
  ProjectReport,
  AnalysisModule,
  SdkAnalyzedProfile,
  SdkErrorCode,
  SdkErrorPhase,
  SdkPhase,
  SdkPhaseDetail,
  SdkProfile,
  SdkProgressPhase,
  PocResponseData,
} from "./models";

// ============================================================
// 프로젝트
// ============================================================

export interface ProjectCreateRequest {
  name: string;
  description?: string;
}

export interface ProjectUpdateRequest {
  name?: string;
  description?: string;
}

export interface ProjectResponse {
  success: boolean;
  data?: Project;
  error?: string;
}

export interface ProjectListItem extends Project {
  lastAnalysisAt?: string;
  severitySummary?: { critical: number; high: number; medium: number; low: number };
  gateStatus?: "pass" | "fail" | "warning";
  unresolvedDelta?: number;
  /** Primary project owner. Omitted when S2 has no creator/owner data for migrated rows. */
  owner?: ProjectOwnerSummary;
}

export interface ProjectListResponse {
  success: boolean;
  data: ProjectListItem[];
}

// ============================================================
// 프로젝트 Overview (대시보드 대체)
// ============================================================

export interface ProjectOverviewResponse {
  project: Project;
  fileCount: number;
  summary: {
    totalVulnerabilities: number;
    bySeverity: AnalysisSummary;
    byModule: {
      static: number;
      deep: number;
      dynamic: number;
      test: number;
    };
  };
  targetSummary?: {
    total: number;
    ready: number;
    failed: number;
    running: number;
    discovered: number;
  };
  recentAnalyses: AnalysisResult[];
  trend?: {
    newFindings: number;
    resolvedFindings: number;
    unresolvedTotal: number;
  };
}

// ============================================================
// Finding 벌크 상태 변경
// ============================================================

export interface FindingBulkStatusRequest {
  findingIds: string[];
  status: FindingStatus;
  reason: string;
  actor?: string;
}

// ============================================================
// Finding fingerprint 이력
// ============================================================

export interface FindingHistoryEntry {
  findingId: string;
  runId: string;
  status: FindingStatus;
  createdAt: string;
}

// ============================================================
// 활동 타임라인
// ============================================================

export type ActivityType =
  | "run_completed"
  | "finding_status_changed"
  | "approval_decided"
  | "pipeline_completed";

export interface ActivityEntry {
  type: ActivityType;
  timestamp: string;
  summary: string;
  metadata: Record<string, unknown>;
}

// ============================================================
// 정적 분석
// ============================================================

export interface StaticAnalysisRequest {
  projectId: string;
  files: UploadedFile[];
  options?: Record<string, unknown>;
}

export interface StaticAnalysisResponse {
  success: boolean;
  data?: AnalysisResult;
  error?: string;
}

export interface GeneratePocRequest {
  projectId: string;
  findingId: string;
}

export interface GeneratePocResponse {
  success: boolean;
  data?: PocResponseData;
  error?: string;
}

// ============================================================
// 프로젝트 파일 관리
// ============================================================

export interface ProjectFilesResponse {
  success: boolean;
  data: UploadedFile[];
}

// ============================================================
// 동적 분석
// ============================================================

export interface DynamicAnalysisSessionRequest {
  projectId: string;
  adapterId: string;
}

export interface DynamicAnalysisSessionResponse {
  success: boolean;
  data?: DynamicAnalysisSession;
  error?: string;
}

// ============================================================
// WebSocket 이벤트 타입 레지스트리 (전 서비스 공유 계약)
// ============================================================

/**
 * AEGIS WS 이벤트 타입 — 모든 WS 메시지의 `type` 필드 값을 열거한다.
 *
 * 7개 WS 패밀리:
 * - 동적 분석 (/ws/dynamic-analysis): CAN 메시지 스트리밍 + 알림
 * - 동적 테스트 (/ws/dynamic-test): 퍼징/침투 테스트 진행률
 * - Quick→Deep 분석 (/ws/analysis): SAST+Agent 2단계 파이프라인
 * - 업로드 (/ws/upload): 소스코드 업로드 상태머신
 * - 파이프라인 (/ws/pipeline): BuildTarget 빌드→스캔→코드그래프
 * - SDK (/ws/sdk): SDK 등록/검증 파이프라인
 * - 알림 (/ws/notifications): 프로젝트 알림 push
 */
export type WsEventType =
  // 동적 분석 (CAN/ECU)
  | "message" | "alert" | "status" | "injection-result" | "injection-error"
  // 동적 테스트
  | "test-progress" | "test-finding" | "test-complete" | "test-error"
  // Quick→Deep 분석
  | "analysis-progress" | "analysis-quick-complete" | "analysis-deep-complete" | "analysis-error"
  // 업로드
  | "upload-progress" | "upload-complete" | "upload-error"
  // BuildTarget 파이프라인
  | "pipeline-target-status" | "pipeline-complete" | "pipeline-error"
  // SDK 등록
  | "sdk-progress" | "sdk-log" | "sdk-complete" | "sdk-error"
  // 공통 연결 상태
  | "heartbeat"
  // 알림
  | "notification";

/** WS 채널 식별자 */
export type WsChannel =
  | "dynamic-analysis"
  | "dynamic-test"
  | "analysis"
  | "upload"
  | "pipeline"
  | "sdk"
  | "notification";

/**
 * WS 공통 envelope 메타데이터.
 * 모든 WS 메시지에 선택적으로 첨부 가능 (하위 호환).
 * S1은 meta 필드가 없는 메시지도 처리할 수 있어야 한다.
 */
export interface WsEnvelopeMeta {
  /** WS 채널 (e.g. "pipeline") */
  channel: WsChannel;
  /** 현재 runtime에서는 broadcaster subscription key. project-scoped 채널에서는 real projectId와 동일하다. */
  projectId?: string;
  /** epoch ms */
  timestamp: number;
  /** 메시지 일련번호 (채널별 단조증가, gap 감지용) */
  seq?: number;
}

export interface WsHeartbeat {
  type: "heartbeat";
  payload: {
    /** epoch ms */
    timestamp: number;
  };
}

/**
 * WS 공통 envelope. runtime은 기존 메시지 객체에 `meta`를 평탄하게 덧붙인다.
 * 기존: { type: "pipeline-target-status", payload: {...} }
 * 새:   { type: "pipeline-target-status", payload: {...}, meta: {...} }
 */
export type WsEnvelope<T extends { type: string }> = T & {
  /** 공통 메타데이터 */
  meta: WsEnvelopeMeta;
};

// ============================================================
// 동적 분석 WS 메시지 (/ws/dynamic-analysis?sessionId=)
// Progress 의미론: messageCount/alertCount 카운터 기반
// ============================================================

/** @deprecated WsEventType으로 대체. 하위 호환용 */
export type WsMessageType = "message" | "alert" | "status" | "injection-result" | "injection-error";

export interface WsCanMessage {
  type: "message";
  payload: CanMessage;
}

export interface WsAlert {
  type: "alert";
  payload: DynamicAlert;
}

export interface WsStatus {
  type: "status";
  payload: {
    messageCount: number;
    alertCount: number;
  };
}

export interface WsInjectionResult {
  type: "injection-result";
  payload: CanInjectionResponse;
}

export interface WsInjectionError {
  type: "injection-error";
  payload: { error: string };
}

export type WsMessage = WsCanMessage | WsAlert | WsStatus | WsInjectionResult | WsInjectionError | WsHeartbeat;

// ============================================================
// 동적 테스트
// ============================================================

export interface DynamicTestRequest {
  projectId: string;
  config: DynamicTestConfig;
  adapterId: string;
}

export interface DynamicTestResponse {
  success: boolean;
  data?: DynamicTestResult;
  error?: string;
}

// ============================================================
// 동적 테스트 WS 메시지 (/ws/dynamic-test?testId=)
// Progress 의미론: current/total 입력 단위 + crashes/anomalies 누적
// ============================================================

export interface WsTestProgress {
  type: "test-progress";
  payload: {
    testId: string;
    current: number;
    total: number;
    crashes: number;
    anomalies: number;
    message: string;
  };
}

export interface WsTestFinding {
  type: "test-finding";
  payload: {
    testId: string;
    finding: DynamicTestFinding;
  };
}

export interface WsTestComplete {
  type: "test-complete";
  payload: { testId: string };
}

export interface WsTestError {
  type: "test-error";
  payload: {
    testId: string;
    error: string;
  };
}

export type WsTestMessage =
  | WsTestProgress
  | WsTestFinding
  | WsTestComplete
  | WsTestError
  | WsHeartbeat;

// ============================================================
// Quick → Deep 분석 WS 메시지 (/ws/analysis?analysisId=)
// Progress 의미론: phase 기반 상태 전이 + targetName/targetProgress 멀티 타겟
// Phase 전이: quick_sast → quick_graphing → quick_complete → deep_submitting → deep_analyzing → deep_complete
// ============================================================

export interface WsAnalysisProgress {
  type: "analysis-progress";
  payload: {
    analysisId: string;
    buildTargetId?: string;
    executionId?: string;
    phase: "quick_sast" | "quick_graphing" | "quick_complete" | "deep_submitting" | "deep_analyzing" | "deep_retrying" | "deep_complete";
    message: string;
    /** 현재 처리 중인 빌드 타겟 이름 */
    targetName?: string;
    /** 전체 타겟 진행률 */
    targetProgress?: { current: number; total: number };
  };
}

export interface WsAnalysisQuickComplete {
  type: "analysis-quick-complete";
  payload: {
    analysisId: string;
    buildTargetId?: string;
    executionId?: string;
    findingCount: number;
  };
}

export interface WsAnalysisDeepComplete {
  type: "analysis-deep-complete";
  payload: {
    analysisId: string;
    buildTargetId?: string;
    executionId?: string;
    findingCount: number;
    /**
     * S3 result-level outcomes. `analysis-deep-complete` means S3 returned a
     * schema-valid review envelope; consumers must use these fields for
     * clean-pass / inconclusive / rejected UI and hot-gate interpretation.
     */
    analysisOutcome?: import("./models").AgentAnalysisOutcome;
    qualityOutcome?: import("./models").AgentQualityOutcome;
    pocOutcome?: import("./models").AgentPocOutcome;
    cleanPass?: boolean;
  };
}

export interface WsAnalysisError {
  type: "analysis-error";
  payload: {
    analysisId: string;
    buildTargetId?: string;
    executionId?: string;
    phase: "quick" | "deep";
    error: string;
    retryable: boolean;
    /** LLM 부분 실패 여부 (도구 결과는 존재하나 LLM 합성 실패) */
    partial?: boolean;
  };
}

export type WsAnalysisMessage =
  | WsAnalysisProgress
  | WsAnalysisQuickComplete
  | WsAnalysisDeepComplete
  | WsAnalysisError
  | WsHeartbeat;

// ============================================================
// 소스코드 업로드 WS 메시지 (/ws/upload?uploadId=)
// Progress 의미론: phase 기반 상태머신
// Phase 전이: received → extracting → indexing → complete | failed
// ============================================================

/** 업로드 상태머신 단계 */
export type UploadPhase = "received" | "extracting" | "indexing" | "complete" | "failed";

export interface WsUploadProgress {
  type: "upload-progress";
  payload: {
    uploadId: string;
    phase: UploadPhase;
    message: string;
    fileCount?: number;
  };
}

export interface WsUploadComplete {
  type: "upload-complete";
  payload: {
    uploadId: string;
    fileCount: number;
    projectPath: string;
  };
}

export interface WsUploadError {
  type: "upload-error";
  payload: {
    uploadId: string;
    phase: UploadPhase;
    error: string;
  };
}

export type WsUploadMessage = WsUploadProgress | WsUploadComplete | WsUploadError | WsHeartbeat;

export interface UploadStatus {
  uploadId: string;
  phase: UploadPhase;
  message: string;
  fileCount?: number;
  projectPath?: string;
  error?: string;
}

export interface UploadAcceptedResponse {
  success: boolean;
  data?: {
    uploadId: string;
    status: "received";
  };
  error?: string;
}

export interface UploadStatusResponse {
  success: boolean;
  data?: UploadStatus;
  error?: string;
}

// ============================================================
// BuildTarget 파이프라인 WS 메시지 (/ws/pipeline?projectId=)
// Progress 의미론: BuildTargetStatus(16상태) → PipelinePhase(3단계) 매핑
// Phase 매핑: discovered|resolving|configured|resolve_failed → setup, building~graph_failed → build, ready → ready
// ============================================================

import type { BuildTargetStatus } from "./models";

/**
 * 파이프라인 UI 간소화 3단계.
 * - setup: 탐색/구성 중 (discovered, resolving, configured, resolve_failed)
 * - build: 빌드/스캔/코드그래프 진행 중 (building ~ graph_failed)
 * - ready: 완료
 */
export type PipelinePhase = "setup" | "build" | "ready";

export interface WsPipelineTargetStatus {
  type: "pipeline-target-status";
  payload: {
    pipelineId: string;
    projectId: string;
    targetId: string;
    targetName: string;
    status: BuildTargetStatus;
    message: string;
    phase: PipelinePhase;
  };
}

export interface WsPipelineComplete {
  type: "pipeline-complete";
  payload: {
    pipelineId: string;
    projectId: string;
    readyCount: number;
    failedCount: number;
    totalCount: number;
  };
}

export interface WsPipelineError {
  type: "pipeline-error";
  payload: {
    pipelineId: string;
    projectId: string;
    targetId: string;
    targetName: string;
    phase: string;
    error: string;
  };
}

export type WsPipelineMessage = WsPipelineTargetStatus | WsPipelineComplete | WsPipelineError | WsHeartbeat;

export interface PipelineTargetStatusSnapshot {
  id: string;
  name: string;
  status: BuildTargetStatus;
  phase: PipelinePhase;
  compileCommandsPath?: string;
  sastScanId?: string;
  codeGraphNodeCount?: number;
  lastBuiltAt?: string;
}

export interface PipelineStatusResponse {
  success: boolean;
  data?: {
    targets: PipelineTargetStatusSnapshot[];
    readyCount: number;
    failedCount: number;
    totalCount: number;
  };
  error?: string;
}

export interface PipelinePrepareRequest {
  targetIds?: string[];
}

export interface PipelinePrepareAcceptedResponse {
  success: boolean;
  data?: {
    preparationId: string;
    targetId?: string;
    status: "running";
  };
  error?: string;
}

// ============================================================
// SDK 등록/검증 WS 메시지 (/ws/sdk?projectId=)
// Progress 의미론: phase 기반 상태머신
// 대표 Phase 전이:
// uploading → uploaded → extracting|installing → extracted|installed → analyzing → verifying → ready
// 실패: upload_failed | extract_failed | install_failed | verify_failed
// ============================================================

export interface WsSdkProgress {
  type: "sdk-progress";
  payload: {
    sdkId: string;
    phase: SdkProgressPhase;
    message: string;
    percent?: number;
    uploadedBytes?: number;
    totalBytes?: number;
    fileName?: string;
    etaSeconds?: number;
    phaseStartedAt?: number;
    phaseDetail?: SdkPhaseDetail;
  };
}

export interface WsSdkLog {
  type: "sdk-log";
  payload: {
    sdkId: string;
    timestamp: string;
    source: "aegis" | "installer";
    kind: "lifecycle" | "heartbeat" | "output" | "terminal";
    stream?: "stdout" | "stderr";
    message: string;
    logPath?: string;
  };
}

export interface WsSdkComplete {
  type: "sdk-complete";
  payload: {
    sdkId: string;
    profile: SdkAnalyzedProfile;
    path?: string;
  };
}

export interface WsSdkError {
  type: "sdk-error";
  payload: {
    sdkId: string;
    phase: SdkErrorPhase;
    error: string;
    logPath?: string;
    code?: SdkErrorCode;
    retryable?: boolean;
    recoverable?: boolean;
    troubleshootingUrl?: string;
    userMessage?: string;
    technicalDetail?: string;
    failedAt?: number;
    correlationId?: string;
  };
}

export type WsSdkMessage = WsSdkProgress | WsSdkLog | WsSdkComplete | WsSdkError | WsHeartbeat;

// ============================================================
// 공통
// ============================================================

// ── 어댑터 ──

export interface AdapterCreateRequest {
  name: string;
  url: string;
}

export interface AdapterUpdateRequest {
  name?: string;
  url?: string;
}

export interface AdapterListResponse {
  success: boolean;
  data: Adapter[];
}

export interface AdapterResponse {
  success: boolean;
  data?: Adapter;
  error?: string;
}

export interface ServiceHealth {
  status: "ok" | "degraded" | "unreachable";
  detail?: Record<string, unknown>;
  control?: {
    activeRequestCount: number | null;
    requestId: string | null;
    endpoint: string | null;
    state: "idle" | "queued" | "running" | "completed" | "failed" | "cancelled" | "expired";
    localAckState: "phase-advancing" | "transport-only" | "ack-break" | null;
    degraded: boolean;
    degradeReasons: string[];
    lastAckAt: number | null;
    lastAckSource: string | null;
    blockedReason: string | null;
    pollDecision: "continue_waiting" | "chain_abort" | "no_active_request" | "inconclusive";
    decisionReasons: string[];
  };
}

export interface HealthResponse {
  service: string;
  status: "ok" | "degraded" | "unhealthy";
  version: string;
  controlPolicyVersion?: "health-control-signal-rollout-v2";
  requestIdQueried?: string;
  detail?: { version: string; uptime: number };
  llmGateway?: ServiceHealth | null;
  analysisAgent?: ServiceHealth | null;
  sastRunner?: ServiceHealth | null;
  knowledgeBase?: ServiceHealth | null;
  buildAgent?: ServiceHealth | null;
  adapters?: { total: number; connected: number };
}

// ============================================================
// Run
// ============================================================

export interface RunListResponse {
  success: boolean;
  data: Run[];
}

export interface RunDetailResponse {
  success: boolean;
  data?: {
    run: Run;
    gate?: GateResult;
    findings: Array<{ finding: Finding; evidenceRefs: EvidenceRef[] }>;
  };
  error?: string;
}

// ============================================================
// Finding
// ============================================================

export interface FindingListResponse {
  success: boolean;
  data: Finding[];
}

export interface FindingDetailResponse {
  success: boolean;
  data?: Finding & { evidenceRefs: EvidenceRef[]; auditLog: AuditLogEntry[] };
  error?: string;
}

export interface FindingStatusUpdateRequest {
  status: FindingStatus;
  reason: string;
  actor?: string;
}

export interface FindingsSummary {
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  byStatus: Partial<Record<FindingStatus, number>>;
}

export interface FindingSummaryResponse {
  success: boolean;
  data: FindingsSummary;
}

// ============================================================
// SDK aggregate / built-in profile API
// ============================================================

export type SdkMetricsPhaseKey = SdkPhase;

export interface SdkMetrics {
  /** Canonical count of project-registered SDK records. */
  totalRegistered: number;
  /** Compatibility alias for totalRegistered; retained for existing S2/S1 consumers. */
  sdkCount: number;
  readyCount: number;
  failedCount: number;
  averagePhaseDurationMs: Partial<Record<SdkMetricsPhaseKey, number>>;
}

export interface SdkMetricsResponse {
  success: boolean;
  data: SdkMetrics;
}

export interface SdkProfileListResponse {
  success: boolean;
  data: SdkProfile[];
}

export interface SdkProfileResponse {
  success: boolean;
  data?: SdkProfile;
  error?: string;
}

// ============================================================
// Quality Gate
// ============================================================

export interface GateResultResponse {
  success: boolean;
  data?: GateResult;
  error?: string;
}

export interface GateResultListResponse {
  success: boolean;
  data: GateResult[];
}

export interface GateOverrideRequest {
  reason: string;
  actor?: string;
}

// ============================================================
// Approval
// ============================================================

export interface ApprovalListResponse {
  success: boolean;
  data: ApprovalRequest[];
}

export interface ApprovalDetailResponse {
  success: boolean;
  data?: ApprovalRequest;
  error?: string;
}

export interface ApprovalDecisionRequest {
  decision: "approved" | "rejected";
  comment?: string;
  actor?: string;
}

export interface ApprovalCountResponse {
  success: boolean;
  data: { pending: number; total: number };
}

// ============================================================
// Report
// ============================================================

export interface ModuleReportResponse {
  success: boolean;
  data?: ModuleReport;
  error?: string;
}

export interface ProjectReportResponse {
  success: boolean;
  data?: ProjectReport;
  error?: string;
}

// ============================================================
// 분석 진행률 (Part A: 비동기 분석)
// ============================================================

export type AnalysisPhase =
  | "queued"
  | "rule_engine"
  | "llm_chunk"
  | "merging"
  | "complete"
  | "quick_sast"
  | "quick_graphing"
  | "quick_complete"
  | "deep_submitting"
  | "deep_analyzing"
  | "deep_retrying"
  | "deep_complete";
export type AnalysisTrackerStatus = "running" | "completed" | "failed" | "aborted";

export interface AnalysisProgress {
  analysisId: string;
  projectId: string;
  buildTargetId?: string;
  executionId?: string;
  status: AnalysisTrackerStatus;
  phase: AnalysisPhase;
  currentChunk: number;
  totalChunks: number;
  totalFiles?: number;
  processedFiles?: number;
  message: string;
  startedAt: string;
  updatedAt: string;
  endedAt?: string;
  error?: string;
}

export interface AnalysisStatusResponse {
  success: boolean;
  data?: AnalysisProgress;
  error?: string;
}

export interface AnalysisStatusListResponse {
  success: boolean;
  data: AnalysisProgress[];
}

export interface AnalysisQuickRequest {
  projectId: string;
  buildTargetId: string;
}

export interface AnalysisDeepRequest {
  projectId: string;
  buildTargetId: string;
  executionId: string;
}

export interface AnalysisRunAcceptedResponse {
  success: boolean;
  data?: {
    analysisId: string;
    buildTargetId: string;
    executionId: string;
    status: AnalysisTrackerStatus;
  };
  error?: string;
}

// ============================================================
// 정적 분석 대시보드 집계 (Part B)
// ============================================================

export interface StaticAnalysisDashboardSummary {
  // 분포
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  bySource: Record<string, number>;

  // 랭킹
  topFiles: Array<{ filePath: string; findingCount: number; topSeverity: string }>;
  topRules: Array<{ ruleId: string; hitCount: number }>;

  // 트렌드
  trend: Array<{ date: string; runCount: number; findingCount: number; gatePassCount: number }>;

  // KPI
  gateStats: { total: number; passed: number; failed: number; rate: number };
  unresolvedCount: { open: number; needsReview: number; needsRevalidation: number; sandbox: number };
}

export interface StaticDashboardResponse {
  success: boolean;
  data?: StaticAnalysisDashboardSummary;
  error?: string;
}

// ============================================================
// 알림 WS 메시지 (/ws/notifications?projectId=)
// ============================================================

export interface WsNotification {
  type: "notification";
  payload: import("./models").Notification;
}

export type WsNotificationMessage = WsNotification | WsHeartbeat;

// ============================================================
// Auth
// ============================================================

export interface LoginRequest {
  username: string;
  password: string;
  rememberMe?: boolean;
}

export interface LoginResponse {
  success: boolean;
  data?: { token: string; expiresAt: string; user: import("./models").User };
  error?: string;
}

export interface UserResponse {
  success: boolean;
  data?: import("./models").User;
  error?: string;
}

export interface OrganizationVerifyResponse {
  success: boolean;
  data?: import("./models").OrganizationVerifyPreview;
  error?: string;
}

export interface RegisterRequest {
  fullName: string;
  email: string;
  password: string;
  orgCode: string;
  termsAcceptedAt: string;
  auditAcceptedAt: string;
}

export interface RegisterResponse {
  success: boolean;
  data?: {
    registrationId: string;
    lookupToken: string;
    lookupExpiresAt: string;
    status: import("./models").RegistrationRequestStatus;
    createdAt: string;
  };
  error?: string;
}

export interface RegistrationLookupResponse {
  success: boolean;
  data?: import("./models").RegistrationRequest;
  error?: string;
}

export interface RegistrationApprovalRequest {
  role: import("./models").UserRole;
}

export interface RegistrationRejectRequest {
  reason: string;
}

export interface RegistrationRequestListResponse {
  success: boolean;
  data?: import("./models").RegistrationRequest[];
  error?: string;
}

export interface PasswordResetRequestBody {
  email: string;
}

export interface PasswordResetConfirmBody {
  token: string;
  newPassword: string;
}

export interface PasswordResetRequestResponse {
  success: boolean;
  data?: { accepted: true };
  error?: string;
}

export interface DevPasswordResetDeliveryResponse {
  success: boolean;
  data?: {
    available: boolean;
    delivery?: import("./models").DevPasswordResetDelivery;
  };
  error?: string;
}
