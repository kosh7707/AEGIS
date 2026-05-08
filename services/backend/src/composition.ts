/**
 * Composition Root — 전체 DAO + 서비스 + WS broadcaster 생성
 *
 * index.ts에서 호출되어 AppContext를 반환한다.
 * 의존성 와이어링 순서(4 tier)가 중요하므로 변경 시 주의.
 */
import type { Database as DatabaseType } from "better-sqlite3";
import type { AppConfig } from "./config";
import type {
  WsMessage,
  WsTestMessage,
  WsAnalysisMessage,
  WsUploadMessage,
  WsPipelineMessage,
  WsSdkMessage,
  WsNotificationMessage,
} from "@aegis/shared";

// DAO classes
import { RunDAO } from "./dao/run.dao";
import { FindingDAO } from "./dao/finding.dao";
import { EvidenceRefDAO } from "./dao/evidence-ref.dao";
import { GateResultDAO } from "./dao/gate-result.dao";
import { ApprovalDAO } from "./dao/approval.dao";
import { AuditLogDAO } from "./dao/audit-log.dao";
import { AnalysisResultDAO } from "./dao/analysis-result.dao";
import { AnalysisExecutionDAO } from "./dao/analysis-execution.dao";
import { FileStore } from "./dao/file-store";
import { DynamicSessionDAO } from "./dao/dynamic-session.dao";
import { DynamicAlertDAO } from "./dao/dynamic-alert.dao";
import { DynamicMessageDAO } from "./dao/dynamic-message.dao";
import { DynamicTestResultDAO } from "./dao/dynamic-test-result.dao";
import { ProjectDAO } from "./dao/project.dao";
import { AdapterDAO } from "./dao/adapter.dao";
import { ProjectSettingsDAO } from "./dao/project-settings.dao";
import { BuildTargetDAO } from "./dao/build-target.dao";
import { TargetLibraryDAO } from "./dao/target-library.dao";
import { SdkRegistryDAO } from "./dao/sdk-registry.dao";
import { NotificationDAO } from "./dao/notification.dao";
import { DevPasswordResetDeliveryDAO, OrganizationDAO, PasswordResetTokenDAO, RegistrationRequestDAO, UserDAO, SessionDAO } from "./dao/user.dao";
import { AuthRateLimitDAO } from "./dao/auth-rate-limit.dao";
import { SdkService } from "./services/sdk.service";

// Service classes
import { ProjectSettingsService } from "./services/project-settings.service";
import { ProjectService } from "./services/project.service";
import { ProjectDeletionService } from "./services/project-deletion.service";
import { LlmTaskClient } from "./services/llm-task-client";
import { CanRuleEngine } from "./can-rules/can-rule-engine";
import { FrequencyRule } from "./can-rules/frequency-rule";
import { UnauthorizedIdRule } from "./can-rules/unauthorized-id-rule";
import { AttackSignatureRule } from "./can-rules/attack-signature-rule";
import { WsBroadcaster } from "./services/ws-broadcaster";
import { DynamicAnalysisService } from "./services/dynamic-analysis.service";
import { DynamicTestService } from "./services/dynamic-test.service";
import { AdapterManager } from "./services/adapter-manager";
import { ResultNormalizer } from "./services/result-normalizer";
import { FindingService } from "./services/finding.service";
import { RunService } from "./services/run.service";
import { QualityGateService } from "./services/quality-gate.service";
import { ApprovalService } from "./services/approval.service";
import { ReportService } from "./services/report.service";
import { AnalysisTracker } from "./services/analysis-tracker";
import { SastClient } from "./services/sast-client";
import { AgentClient } from "./services/agent-client";
import { ProjectSourceService } from "./services/project-source.service";
import { AnalysisOrchestrator } from "./services/analysis-orchestrator";
import { BuildTargetService } from "./services/build-target.service";
import { KbClient } from "./services/kb-client";
import { BuildAgentClient } from "./services/build-agent-client";
import { PipelineOrchestrator } from "./services/pipeline-orchestrator";
import { ActivityService } from "./services/activity.service";
import { NotificationService } from "./services/notification.service";
import { UserService } from "./services/user.service";
import { getUploadWsSnapshot } from "./controllers/project-source.controller";

export interface AppContext {
  // DAOs
  runDAO: RunDAO;
  findingDAO: FindingDAO;
  evidenceRefDAO: EvidenceRefDAO;
  gateResultDAO: GateResultDAO;
  approvalDAO: ApprovalDAO;
  auditLogDAO: AuditLogDAO;
  analysisResultDAO: AnalysisResultDAO;
  analysisExecutionDAO: AnalysisExecutionDAO;
  fileStore: FileStore;
  dynamicSessionDAO: DynamicSessionDAO;
  dynamicAlertDAO: DynamicAlertDAO;
  dynamicMessageDAO: DynamicMessageDAO;
  dynamicTestResultDAO: DynamicTestResultDAO;
  projectDAO: ProjectDAO;
  adapterDAO: AdapterDAO;
  projectSettingsDAO: ProjectSettingsDAO;
  buildTargetDAO: BuildTargetDAO;
  targetLibraryDAO: TargetLibraryDAO;
  sdkRegistryDAO: SdkRegistryDAO;
  sdkService: SdkService;

  // Services
  adapterManager: AdapterManager;
  settingsService: ProjectSettingsService;
  projectSourceService: ProjectSourceService;
  buildTargetService: BuildTargetService;
  projectService: ProjectService;
  qualityGateService: QualityGateService;
  resultNormalizer: ResultNormalizer;
  approvalService: ApprovalService;
  findingService: FindingService;
  runService: RunService;
  dynamicAnalysisService: DynamicAnalysisService;
  dynamicTestService: DynamicTestService;
  analysisOrchestrator: AnalysisOrchestrator;
  pipelineOrchestrator: PipelineOrchestrator;
  activityService: ActivityService;
  notificationService: NotificationService;
  userService: UserService;
  reportService: ReportService;
  analysisTracker: AnalysisTracker;

  // External clients
  llmTaskClient: LlmTaskClient;
  sastClient: SastClient;
  agentClient: AgentClient;
  kbClient: KbClient;
  buildAgentClient: BuildAgentClient;

  // CAN rule engine
  canRuleEngine: CanRuleEngine;

  // WebSocket broadcasters
  dynamicAnalysisWs: WsBroadcaster<WsMessage>;
  dynamicTestWs: WsBroadcaster<WsTestMessage>;
  analysisWs: WsBroadcaster<WsAnalysisMessage>;
  uploadWs: WsBroadcaster<WsUploadMessage>;
  pipelineWs: WsBroadcaster<WsPipelineMessage>;
  notificationWs: WsBroadcaster<WsNotificationMessage>;
  sdkWs: WsBroadcaster<any>;
}

export function createAppContext(cfg: AppConfig, db: DatabaseType): AppContext {
  // ── Tier 0: DAOs ──
  const runDAO = new RunDAO(db);
  const findingDAO = new FindingDAO(db);
  const evidenceRefDAO = new EvidenceRefDAO(db);
  const gateResultDAO = new GateResultDAO(db);
  const approvalDAO = new ApprovalDAO(db);
  const auditLogDAO = new AuditLogDAO(db);
  const analysisResultDAO = new AnalysisResultDAO(db);
  const analysisExecutionDAO = new AnalysisExecutionDAO(db);
  const fileStore = new FileStore(db);
  const dynamicSessionDAO = new DynamicSessionDAO(db);
  const dynamicAlertDAO = new DynamicAlertDAO(db);
  const dynamicMessageDAO = new DynamicMessageDAO(db);
  const dynamicTestResultDAO = new DynamicTestResultDAO(db);
  const projectDAO = new ProjectDAO(db);
  const adapterDAO = new AdapterDAO(db);
  const projectSettingsDAO = new ProjectSettingsDAO(db);
  const buildTargetDAO = new BuildTargetDAO(db);
  const targetLibraryDAO = new TargetLibraryDAO(db);
  const sdkRegistryDAO = new SdkRegistryDAO(db);
  const notificationDAO = new NotificationDAO(db);
  const userDAO = new UserDAO(db);
  const sessionDAO = new SessionDAO(db);
  const authRateLimitDAO = new AuthRateLimitDAO(db);
  const organizationDAO = new OrganizationDAO(db);
  const registrationRequestDAO = new RegistrationRequestDAO(db);
  const passwordResetTokenDAO = new PasswordResetTokenDAO(db);
  const devPasswordResetDeliveryDAO = new DevPasswordResetDeliveryDAO(db);

  // ── Tier 1: 기본 서비스 + 외부 클라이언트 ──
  const llmTaskClient = new LlmTaskClient(cfg.llmGatewayUrl, cfg.llmConcurrency);
  const sastClient = new SastClient(cfg.sastRunnerUrl);
  const agentClient = new AgentClient(cfg.analysisAgentUrl);
  const kbClient = new KbClient(cfg.kbUrl);
  const buildAgentClient = new BuildAgentClient(cfg.buildAgentUrl);

  const adapterManager = new AdapterManager(adapterDAO);
  const settingsService = new ProjectSettingsService(projectSettingsDAO, sdkRegistryDAO);
  const projectSourceService = new ProjectSourceService(cfg.uploadsDir);

  // ── Tier 1.5: 알림 + 사용자 서비스 (순환 의존 방지를 위해 QualityGateService보다 먼저 생성) ──
  const notificationWs = new WsBroadcaster<WsNotificationMessage>("/ws/notifications", "projectId", "notification");
  const notificationService = new NotificationService(notificationDAO, notificationWs);
  const userService = new UserService(
    userDAO,
    sessionDAO,
    organizationDAO,
    registrationRequestDAO,
    passwordResetTokenDAO,
    authRateLimitDAO,
    devPasswordResetDeliveryDAO,
  );
  const analysisTracker = new AnalysisTracker();

  // ── Tier 2: 복합 서비스 (Tier 1 의존) ──
  const buildTargetService = new BuildTargetService(buildTargetDAO, settingsService, projectSourceService);
  const qualityGateService = new QualityGateService(findingDAO, evidenceRefDAO, gateResultDAO, runDAO, settingsService, notificationService);
  const resultNormalizer = new ResultNormalizer(db, runDAO, findingDAO, evidenceRefDAO, qualityGateService, notificationService);
  const findingService = new FindingService(findingDAO, evidenceRefDAO, auditLogDAO);
  const approvalService = new ApprovalService(approvalDAO, auditLogDAO, qualityGateService, notificationService, findingService);
  const runService = new RunService(runDAO, findingDAO, gateResultDAO, evidenceRefDAO);

  // ── WebSocket broadcasters ──
  const dynamicAnalysisWs = new WsBroadcaster<WsMessage>("/ws/dynamic-analysis", "sessionId", "dynamic-analysis");
  const dynamicTestWs = new WsBroadcaster<WsTestMessage>("/ws/dynamic-test", "testId", "dynamic-test");
  const analysisWs = new WsBroadcaster<WsAnalysisMessage>(
    "/ws/analysis",
    "analysisId",
    "analysis",
    (analysisId) => analysisTracker.getWsSnapshot(analysisId),
  );
  const uploadWs = new WsBroadcaster<WsUploadMessage>(
    "/ws/upload",
    "uploadId",
    "upload",
    (uploadId) => getUploadWsSnapshot(uploadId),
  );
  const pipelineWs = new WsBroadcaster<WsPipelineMessage>("/ws/pipeline", "projectId", "pipeline");
  const sdkWs = new WsBroadcaster<WsSdkMessage>("/ws/sdk", "projectId", "sdk");

  // ── CAN 룰 엔진 ──
  const canRuleEngine = new CanRuleEngine();
  canRuleEngine.registerRule(new FrequencyRule());
  canRuleEngine.registerRule(new UnauthorizedIdRule());
  canRuleEngine.registerRule(new AttackSignatureRule());

  // ── Tier 3: 파이프라인 서비스 (Tier 1+2 + WS 의존) ──
  const dynamicAnalysisService = new DynamicAnalysisService(
    dynamicSessionDAO, dynamicAlertDAO, dynamicMessageDAO, analysisResultDAO,
    canRuleEngine, llmTaskClient, dynamicAnalysisWs, adapterManager, settingsService, resultNormalizer,
  );
  const dynamicTestService = new DynamicTestService(
    dynamicTestResultDAO, analysisResultDAO,
    llmTaskClient, adapterManager, settingsService, dynamicTestWs, resultNormalizer,
  );
  const projectDeletionService = new ProjectDeletionService(
    db,
    projectSourceService,
    adapterManager,
    analysisTracker,
    dynamicSessionDAO,
    dynamicTestService,
    sdkRegistryDAO,
    buildTargetDAO,
  );
  const pipelineOrchestrator = new PipelineOrchestrator(
    projectSourceService, sastClient, kbClient, buildAgentClient, targetLibraryDAO,
    buildTargetDAO, analysisResultDAO, resultNormalizer, pipelineWs, notificationService, analysisExecutionDAO,
    sdkRegistryDAO, cfg.uploadsDir,
  );
  const analysisOrchestrator = new AnalysisOrchestrator(
    projectSourceService, sastClient, kbClient, agentClient,
    analysisResultDAO, settingsService, resultNormalizer, analysisWs, buildTargetService, targetLibraryDAO, analysisTracker, analysisExecutionDAO, pipelineOrchestrator,
  );
  const sdkService = new SdkService(sdkRegistryDAO, buildAgentClient, cfg.uploadsDir, sdkWs, notificationService);

  const activityService = new ActivityService(runDAO, auditLogDAO, buildTargetDAO, findingService, approvalService);
  const projectService = new ProjectService(
    projectDAO,
    analysisResultDAO,
    fileStore,
    adapterManager,
    settingsService,
    buildTargetService,
    findingDAO,
    runDAO,
    gateResultDAO,
    projectDeletionService,
  );

  // ── Tier 4: 보고서 (전체 의존) ──
  const reportService = new ReportService(
    evidenceRefDAO, auditLogDAO,
    projectService, runService, findingService, qualityGateService, approvalService,
  );

  return {
    runDAO, findingDAO, evidenceRefDAO, gateResultDAO, approvalDAO, auditLogDAO,
    analysisResultDAO, analysisExecutionDAO, fileStore, dynamicSessionDAO, dynamicAlertDAO, dynamicMessageDAO,
    dynamicTestResultDAO, projectDAO, adapterDAO, projectSettingsDAO, buildTargetDAO,
    adapterManager, settingsService, projectSourceService, buildTargetService, targetLibraryDAO, sdkRegistryDAO, sdkService,
    projectService, qualityGateService, resultNormalizer, approvalService, findingService,
    runService, dynamicAnalysisService, dynamicTestService,
    analysisOrchestrator, pipelineOrchestrator, activityService, notificationService, userService, reportService, analysisTracker,
    llmTaskClient, sastClient, agentClient, kbClient, buildAgentClient,
    canRuleEngine,
    dynamicAnalysisWs, dynamicTestWs, analysisWs, uploadWs, pipelineWs, notificationWs, sdkWs,
  };
}
