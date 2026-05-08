import crypto from "crypto";
import express from "express";
import fs from "fs";
import os from "os";
import path from "path";
import type { Database as DatabaseType } from "better-sqlite3";
import type { RegisteredSdk } from "@aegis/shared";
import { createTestDb } from "./test-db";
import { errorHandlerMiddleware } from "../middleware/error-handler.middleware";
import { createAuthMiddleware } from "../middleware/auth.middleware";
import { InvalidInputError, NotFoundError } from "../lib/errors";

// Contract tests intentionally seed legacy static/deep rows to prove aggregate filtering.
// Keep the production lineage guard enabled elsewhere, but allow explicit legacy fixtures here.
process.env.AEGIS_ALLOW_LEGACY_STATIC_FIXTURES = "1";

// DAOs
import { RunDAO } from "../dao/run.dao";
import { FindingDAO } from "../dao/finding.dao";
import { EvidenceRefDAO } from "../dao/evidence-ref.dao";
import { GateResultDAO } from "../dao/gate-result.dao";
import { ApprovalDAO } from "../dao/approval.dao";
import { AuditLogDAO } from "../dao/audit-log.dao";
import { AnalysisResultDAO } from "../dao/analysis-result.dao";
import { FileStore } from "../dao/file-store";
import { DynamicSessionDAO } from "../dao/dynamic-session.dao";
import { ProjectDAO } from "../dao/project.dao";
import { AdapterDAO } from "../dao/adapter.dao";
import { ProjectSettingsDAO } from "../dao/project-settings.dao";
import { BuildTargetDAO } from "../dao/build-target.dao";
import { SdkRegistryDAO } from "../dao/sdk-registry.dao";
import { NotificationDAO } from "../dao/notification.dao";
import { TargetLibraryDAO } from "../dao/target-library.dao";
import { DevPasswordResetDeliveryDAO, OrganizationDAO, PasswordResetTokenDAO, RegistrationRequestDAO, UserDAO, SessionDAO } from "../dao/user.dao";
import { AuthRateLimitDAO } from "../dao/auth-rate-limit.dao";

// Services
import { FindingService } from "../services/finding.service";
import { RunService } from "../services/run.service";
import { QualityGateService } from "../services/quality-gate.service";
import { ApprovalService } from "../services/approval.service";
import { ProjectService } from "../services/project.service";
import { ProjectDeletionService } from "../services/project-deletion.service";
import { AdapterManager } from "../services/adapter-manager";
import { ProjectSettingsService } from "../services/project-settings.service";
import { BuildTargetService } from "../services/build-target.service";
import { ReportService } from "../services/report.service";
import { ResultNormalizer } from "../services/result-normalizer";
import { ActivityService } from "../services/activity.service";
import { NotificationService } from "../services/notification.service";
import { UserService } from "../services/user.service";
import { ProjectSourceService } from "../services/project-source.service";

// Controllers
import { createProjectRouter } from "../controllers/project.controller";
import { createHealthRouter } from "../controllers/health.controller";
import { createFindingRouter, createFindingDetailRouter } from "../controllers/finding.controller";
import { createRunRouter, createRunDetailRouter } from "../controllers/run.controller";
import { createQualityGateRouter, createQualityGateDetailRouter } from "../controllers/quality-gate.controller";
import { createApprovalRouter, createApprovalDetailRouter } from "../controllers/approval.controller";
import { createReportRouter } from "../controllers/report.controller";
import { createFileRouter } from "../controllers/file.controller";
import { createBuildTargetRouter } from "../controllers/build-target.controller";
import { createSdkRouter } from "../controllers/sdk.controller";
import { createPipelineRouter } from "../controllers/pipeline.controller";
import { createProjectSourceRouter } from "../controllers/project-source.controller";
import { createAnalysisRouter } from "../controllers/analysis.controller";
import { createActivityRouter } from "../controllers/activity.controller";
import { createNotificationRouter, createNotificationDetailRouter } from "../controllers/notification.controller";
import { createAuthRouter } from "../controllers/auth.controller";
import { createProjectAdaptersRouter } from "../controllers/project-adapters.controller";
import { createTargetLibraryRouter } from "../controllers/target-library.controller";
import { createDynamicAnalysisRouter } from "../controllers/dynamic-analysis.controller";
import { createDynamicTestRouter } from "../controllers/dynamic-test.controller";
import { createGateProfileRouter, createProjectSettingsRouter, createSdkProfileRouter } from "../controllers/project-settings.controller";
import { SDK_PROFILES } from "../services/sdk-profiles";
import { AnalysisTracker } from "../services/analysis-tracker";

export interface TestAppContext {
  app: express.Express;
  db: DatabaseType;
  // DAOs exposed for seeding
  projectDAO: ProjectDAO;
  runDAO: RunDAO;
  findingDAO: FindingDAO;
  evidenceRefDAO: EvidenceRefDAO;
  gateResultDAO: GateResultDAO;
  approvalDAO: ApprovalDAO;
  auditLogDAO: AuditLogDAO;
  analysisResultDAO: AnalysisResultDAO;
  dynamicSessionDAO: DynamicSessionDAO;
  fileStore: FileStore;
  buildTargetDAO: BuildTargetDAO;
  targetLibraryDAO: TargetLibraryDAO;
  sdkRegistryDAO: SdkRegistryDAO;
  notificationDAO: NotificationDAO;
  userDAO: UserDAO;
  sessionDAO: SessionDAO;
  organizationDAO: OrganizationDAO;
  registrationRequestDAO: RegistrationRequestDAO;
  passwordResetTokenDAO: PasswordResetTokenDAO;
  devPasswordResetDeliveryDAO: DevPasswordResetDeliveryDAO;
  // Services exposed for seeding
  gateService: QualityGateService;
  normalizer: ResultNormalizer;
  buildTargetService: BuildTargetService;
  notificationService: NotificationService;
  userService: UserService;
  settingsService: ProjectSettingsService;
  analysisTracker: AnalysisTracker;
  pipelineRunCalls: Array<{ projectId: string; targetIds?: string[]; requestId?: string; pipelineId?: string }>;
  pipelinePrepareCalls: Array<{ projectId: string; targetIds?: string[]; requestId?: string; preparationId?: string }>;
  analysisQuickCalls: Array<{ projectId: string; analysisId: string; targetIds?: string[]; requestId?: string }>;
  analysisDeepCalls: Array<{ projectId: string; analysisId: string; buildTargetId: string; executionId: string; requestId?: string }>;
  agentTaskResponses: Array<Record<string, unknown>>;
  projectUploadsRoot: string;
  dynamicTestRunningProjects: Set<string>;
}

export function createTestApp(): TestAppContext {
  const db = createTestDb();
  // Contract tests still seed legacy static/deep rows to prove aggregate/read surfaces hide them.
  // Production schema keeps CHECK constraints enabled; only this test app relaxes them for legacy-fixture seeding.
  db.pragma("ignore_check_constraints = ON");
  const sdkUploadRoot = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-sdk-test-"));
  const projectUploadsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-project-delete-"));

  // ── Tier 0: DAOs ──
  const runDAO = new RunDAO(db);
  const findingDAO = new FindingDAO(db);
  const evidenceRefDAO = new EvidenceRefDAO(db);
  const gateResultDAO = new GateResultDAO(db);
  const approvalDAO = new ApprovalDAO(db);
  const auditLogDAO = new AuditLogDAO(db);
  const analysisResultDAO = new AnalysisResultDAO(db);
  const dynamicSessionDAO = new DynamicSessionDAO(db);
  const fileStore = new FileStore(db);
  const projectDAO = new ProjectDAO(db);
  const adapterDAO = new AdapterDAO(db);
  const projectSettingsDAO = new ProjectSettingsDAO(db);
  const buildTargetDAO = new BuildTargetDAO(db);
  const targetLibraryDAO = new TargetLibraryDAO(db as any);
  const sdkRegistryDAO = new SdkRegistryDAO(db);
  const notificationDAO = new NotificationDAO(db);
  const userDAO = new UserDAO(db);
  const sessionDAO = new SessionDAO(db);
  const authRateLimitDAO = new AuthRateLimitDAO(db);
  const organizationDAO = new OrganizationDAO(db);
  const registrationRequestDAO = new RegistrationRequestDAO(db);
  const passwordResetTokenDAO = new PasswordResetTokenDAO(db);
  const devPasswordResetDeliveryDAO = new DevPasswordResetDeliveryDAO(db);

  // ── Tier 1: 기본 서비스 ──
  const adapterManager = new AdapterManager(adapterDAO);
  const adapterClients = (adapterManager as any).clients as Map<string, {
    isConnected: () => boolean;
    isEcuConnected: () => boolean;
    getEcuMeta: () => undefined;
    disconnect: () => void;
  }>;
  adapterManager.connect = async (id: string) => {
    const row = adapterDAO.findById(id);
    if (!row) throw new NotFoundError("Adapter not found");
    adapterClients.set(id, {
      isConnected: () => true,
      isEcuConnected: () => false,
      getEcuMeta: () => undefined,
      disconnect: () => undefined,
    });
    return adapterManager.findById(id)!;
  };
  adapterManager.disconnect = (id: string) => {
    adapterClients.get(id)?.disconnect();
    adapterClients.delete(id);
    return adapterManager.findById(id);
  };
  const settingsService = new ProjectSettingsService(projectSettingsDAO, sdkRegistryDAO);
  const buildTargetSourceService = {
    getProjectPath(projectId: string) {
      return `/tmp/${projectId}`;
    },
    copyToBuildTargetSource(projectId: string, targetId: string) {
      return `/tmp/${projectId}/${targetId}`;
    },
  };
  const buildTargetService = new BuildTargetService(buildTargetDAO, settingsService, buildTargetSourceService as any);
  const deleteSourceService = new ProjectSourceService(projectUploadsRoot);

  // ── Tier 1.5: 알림 + 사용자 서비스 ──
  const notificationService = new NotificationService(notificationDAO);
  const userService = new UserService(
    userDAO,
    sessionDAO,
    organizationDAO,
    registrationRequestDAO,
    passwordResetTokenDAO,
    authRateLimitDAO,
    devPasswordResetDeliveryDAO,
  );
  const sdkStore = new Map<string, RegisteredSdk[]>();
  const sdkService = {
    listAll(projectId: string) {
      return {
        builtIn: SDK_PROFILES,
        registered: sdkStore.get(projectId) ?? [],
      };
    },
    findById(id: string) {
      return [...sdkStore.values()].flat().find((sdk) => sdk.id === id);
    },
    getInstallLog(id: string, tailLines: number = 200) {
      return {
        sdkId: id,
        logPath: `/tmp/logs/${id}.log`,
        content: `line 1\nline 2`,
        truncated: tailLines < 2,
      };
    },
    getInstallLogWindow(id: string, options?: { tailLines?: number; offset?: number; limit?: number }) {
      const lines = ["line 1", "line 2"];
      if (typeof options?.offset === "number" || typeof options?.limit === "number") {
        const offset = Math.max(0, options?.offset ?? 0);
        const limit = Math.max(1, options?.limit ?? 200);
        const selected = lines.slice(offset, offset + limit);
        const nextOffset = offset + selected.length < lines.length ? offset + selected.length : undefined;
        return {
          sdkId: id,
          logPath: `/tmp/logs/${id}.log`,
          content: selected.join("\n"),
          truncated: typeof nextOffset === "number",
          totalLines: lines.length,
          nextOffset,
        };
      }
      const tailLines = Math.max(1, options?.tailLines ?? 200);
      const selected = lines.length > tailLines ? lines.slice(-tailLines) : lines;
      return {
        sdkId: id,
        logPath: `/tmp/logs/${id}.log`,
        content: selected.join("\n"),
        truncated: lines.length > tailLines,
        totalLines: lines.length,
      };
    },
    getQuota(projectId: string) {
      return {
        usedBytes: 0,
        maxBytes: 50 * 1024 * 1024 * 1024,
        sdkCount: sdkStore.get(projectId)?.length ?? 0,
      };
    },
    getMetrics(projectId: string) {
      const registered = sdkStore.get(projectId) ?? [];
      return {
        totalRegistered: registered.length,
        sdkCount: registered.length,
        readyCount: registered.filter((sdk) => sdk.status === "ready").length,
        failedCount: registered.filter((sdk) => sdk.status.endsWith("_failed")).length,
        averagePhaseDurationMs: {},
      };
    },
    async register(
      projectId: string,
      input: { sdkId?: string; name: string; description?: string; files: Array<{ originalName: string; storedPath: string; size: number; relativePath?: string }> },
    ) {
      const now = new Date().toISOString();
      const primaryFile = input.files[0];
      const lowerName = primaryFile?.originalName?.toLowerCase() ?? "";
      const artifactKind = input.files.length > 1 ? "folder" : lowerName.endsWith(".bin") ? "bin" : "archive";
      const inferredPath = artifactKind === "bin"
        ? `/tmp/${projectId}/sdk/${input.sdkId ?? "uploaded"}/installed`
        : `/tmp/${projectId}/sdk/${input.sdkId ?? "uploaded"}/content`;
      const sdk: RegisteredSdk = {
        id: input.sdkId ?? `sdk-test-${sdkStore.size + 1}`,
        projectId,
        name: input.name,
        description: input.description,
        path: inferredPath,
        artifactKind,
        sdkVersion: artifactKind === "bin" ? "08.02.00.24" : artifactKind === "folder" ? "folder-virtual" : "1.0.0",
        targetSystem: artifactKind === "bin" ? "am335x-evm" : artifactKind === "folder" ? "folder-target" : "archive-target",
        profile: {
          artifactKind,
          sdkVersion: artifactKind === "bin" ? "08.02.00.24" : artifactKind === "folder" ? "folder-virtual" : "1.0.0",
          targetSystem: artifactKind === "bin" ? "am335x-evm" : artifactKind === "folder" ? "folder-target" : "archive-target",
        },
        status: "uploaded",
        verified: false,
        currentPhaseStartedAt: Date.now(),
        phaseHistory: [{ phase: "uploaded", startedAt: Date.now() }],
        retryCount: 0,
        retryable: false,
        createdAt: now,
        updatedAt: now,
      };
      const existing = sdkStore.get(projectId) ?? [];
      sdkStore.set(projectId, [...existing, sdk]);
      return sdk;
    },
    async remove(id: string) {
      for (const [projectId, items] of sdkStore.entries()) {
        const filtered = items.filter((sdk) => sdk.id !== id);
        if (filtered.length !== items.length) {
          sdkStore.set(projectId, filtered);
        }
      }
    },
    async retry(id: string) {
      const sdk = [...sdkStore.values()].flat().find((item) => item.id === id);
      if (!sdk) throw new Error(`SDK not found: ${id}`);
      const retried = { ...sdk, status: "ready" as const, verified: true, retryCount: (sdk.retryCount ?? 0) + 1 };
      const items = sdkStore.get(sdk.projectId) ?? [];
      sdkStore.set(sdk.projectId, items.map((item) => item.id === id ? retried : item));
      return retried;
    },
  };
  const testSourceService = {
    getProjectPath(projectId: string) {
      return `/tmp/${projectId}`;
    },
    async cloneGit(projectId: string) {
      return `/tmp/${projectId}/cloned`;
    },
    listFiles(_projectId: string, filter?: string | null) {
      const all = [
        { relativePath: "src/main.c", size: 128, language: "c", fileType: "source", previewable: true },
        { relativePath: "README.md", size: 64, language: "markdown", fileType: "doc", previewable: true },
      ];
      return filter === null ? all : all.filter((entry) => entry.fileType === "source");
    },
    listFilesForExplorer(_projectId: string, filter?: string | null) {
      const all = [
        { relativePath: "src/main.c", size: 128, language: "c", fileType: "source", previewable: true },
        { relativePath: "README.md", size: 64, language: "markdown", fileType: "doc", previewable: true },
      ];
      return filter === null ? all : all.filter((entry) => entry.fileType === "source");
    },
    computeComposition() {
      return {
        composition: { source: 1, doc: 1 },
        totalFiles: 2,
        totalSize: 192,
      };
    },
    computeCompositionForExplorer() {
      return {
        composition: { source: 1, doc: 1 },
        totalFiles: 2,
        totalSize: 192,
      };
    },
    readFile(_projectId: string, filePath: string) {
      return `contents:${filePath}`;
    },
    getFileMetadata(_projectId: string, filePath: string) {
      return {
        size: filePath.endsWith(".md") ? 64 : 128,
        language: filePath.endsWith(".md") ? "markdown" : "c",
        fileType: filePath.endsWith(".md") ? "doc" : "source",
        previewable: true,
        lineCount: 3,
      };
    },
    deleteSource() {},
    async extractArchive(projectId: string) {
      return `/tmp/${projectId}/archive`;
    },
    async saveFiles() {},
    copyToBuildTargetSource(projectId: string, targetId: string) {
      return `/tmp/${projectId}/${targetId}`;
    },
  };
  const testSastClient = {
    async discoverTargets() {
      return {
        targets: [
          { name: "auto-discovered", relativePath: "auto-discovered/", buildSystem: "cmake" },
        ],
        elapsedMs: 123,
      };
    },
  };
  const pipelineRunCalls: Array<{ projectId: string; targetIds?: string[]; requestId?: string; pipelineId?: string }> = [];
  const pipelinePrepareCalls: Array<{ projectId: string; targetIds?: string[]; requestId?: string; preparationId?: string }> = [];
  const pipelineOrchestrator = {
    async runPipeline(projectId: string, targetIds?: string[], requestId?: string, _signal?: AbortSignal, pipelineId?: string) {
      pipelineRunCalls.push({ projectId, targetIds, requestId, pipelineId });
    },
    async preparePipeline(projectId: string, targetIds?: string[], requestId?: string, _signal?: AbortSignal, preparationId?: string) {
      pipelinePrepareCalls.push({ projectId, targetIds, requestId, preparationId });
    },
  };
  const analysisQuickCalls: Array<{ projectId: string; analysisId: string; targetIds?: string[]; requestId?: string }> = [];
  const analysisDeepCalls: Array<{ projectId: string; analysisId: string; buildTargetId: string; executionId: string; requestId?: string }> = [];
  const agentTaskResponses: Array<Record<string, unknown>> = [];
  const analysisTracker = new AnalysisTracker();
  const analysisOrchestrator = {
    async preflightQuickRequest() {},
    async preflightDeepRequest() {},
    async runQuickAnalysis(projectId: string, analysisId: string, targetIds?: string[], requestId?: string) {
      analysisQuickCalls.push({ projectId, analysisId, targetIds, requestId });
    },
    async runDeepAnalysis(projectId: string, analysisId: string, buildTargetId: string, executionId: string, requestId?: string) {
      analysisDeepCalls.push({ projectId, analysisId, buildTargetId, executionId, requestId });
    },
  };
  const agentClient = {
    async submitTask() {
      return agentTaskResponses.shift() ?? {
        status: "completed",
        result: {
          claims: [{ statement: "demo poc", detail: "demo detail" }],
          pocOutcome: "poc_accepted",
          qualityOutcome: "accepted",
          cleanPass: true,
        },
        audit: { latencyMs: 1 },
      };
    },
    isSuccess() {
      return true;
    },
  };
  const dynamicSessions = new Map<string, any>();
  const dynamicInjectionHistory = new Map<string, any[]>();
  const dynamicAnalysisService = {
    createSession(projectId: string, adapterId: string) {
      const session = {
        id: `dyn-${crypto.randomUUID().slice(0, 8)}`,
        projectId,
        status: "connected",
        source: { type: "adapter", adapterId, adapterName: "Test Adapter" },
        messageCount: 0,
        alertCount: 0,
        startedAt: new Date().toISOString(),
      };
      dynamicSessions.set(session.id, session);
      dynamicInjectionHistory.set(session.id, []);
      return session;
    },
    findAllSessions(projectId?: string) {
      return [...dynamicSessions.values()].filter((session) => !projectId || session.projectId === projectId);
    },
    findSession(sessionId: string) {
      const session = dynamicSessions.get(sessionId);
      if (!session) return undefined;
      return { session, alerts: [], recentMessages: [] };
    },
    startSession(sessionId: string) {
      const session = dynamicSessions.get(sessionId);
      if (!session || session.status !== "connected") return undefined;
      const updated = { ...session, status: "monitoring" };
      dynamicSessions.set(sessionId, updated);
      return updated;
    },
    async stopSession(sessionId: string) {
      const session = dynamicSessions.get(sessionId);
      if (!session) return undefined;
      const updated = { ...session, status: "stopped", endedAt: new Date().toISOString() };
      dynamicSessions.set(sessionId, updated);
      return updated;
    },
    async injectMessage(sessionId: string, request: { canId: string; dlc: number; data: string; label?: string }) {
      const result = {
        id: `inj-${crypto.randomUUID().slice(0, 8)}`,
        request,
        ecuResponse: { success: true, data: "62 F1 90" },
        classification: "normal",
        injectedAt: new Date().toISOString(),
      };
      const history = dynamicInjectionHistory.get(sessionId) ?? [];
      history.push(result);
      dynamicInjectionHistory.set(sessionId, history);
      return result;
    },
    async injectScenario(sessionId: string, scenarioId: string) {
      const results = [
        {
          id: `inj-${crypto.randomUUID().slice(0, 8)}`,
          request: { canId: "0x7E0", dlc: 8, data: "02 10 03 00 00 00 00 00", label: scenarioId },
          ecuResponse: { success: true, data: "50 03" },
          classification: "normal",
          injectedAt: new Date().toISOString(),
        },
      ];
      const history = dynamicInjectionHistory.get(sessionId) ?? [];
      history.push(...results);
      dynamicInjectionHistory.set(sessionId, history);
      return results;
    },
    getInjectionHistory(sessionId: string) {
      return dynamicInjectionHistory.get(sessionId) ?? [];
    },
  };
  const dynamicTestResults = new Map<string, any>();
  const dynamicTestRunningProjects = new Set<string>();
  const dynamicTestService = {
    async runTest(projectId: string, config: any, adapterId: string, testId?: string) {
      dynamicTestRunningProjects.add(projectId);
      const result = {
        id: testId ?? `test-${crypto.randomUUID().slice(0, 8)}`,
        projectId,
        config,
        status: "completed",
        totalRuns: config.count ?? 1,
        crashes: 0,
        anomalies: 0,
        findings: [],
        adapterId,
        createdAt: new Date().toISOString(),
      };
      dynamicTestResults.set(result.id, result);
      dynamicTestRunningProjects.delete(projectId);
      return result;
    },
    isRunningForProject(projectId: string) {
      return dynamicTestRunningProjects.has(projectId);
    },
    findByProjectId(projectId: string) {
      return [...dynamicTestResults.values()].filter((result) => result.projectId === projectId);
    },
    findById(testId: string) {
      return dynamicTestResults.get(testId);
    },
    deleteById(testId: string) {
      return dynamicTestResults.delete(testId);
    },
  };
  const projectDeletionService = new ProjectDeletionService(
    db,
    deleteSourceService,
    adapterManager,
    analysisTracker,
    dynamicSessionDAO,
    dynamicTestService as any,
    sdkRegistryDAO,
    buildTargetDAO,
  );

  // ── Tier 2: 복합 서비스 ──
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
  const gateService = new QualityGateService(findingDAO, evidenceRefDAO, gateResultDAO, runDAO, settingsService, notificationService);
  const normalizer = new ResultNormalizer(db, runDAO, findingDAO, evidenceRefDAO, gateService, notificationService);
  const findingService = new FindingService(findingDAO, evidenceRefDAO, auditLogDAO);
  const approvalService = new ApprovalService(approvalDAO, auditLogDAO, gateService, notificationService, findingService);
  const runService = new RunService(runDAO, findingDAO, gateResultDAO, evidenceRefDAO);
  const activityService = new ActivityService(runDAO, auditLogDAO, buildTargetDAO, findingService, approvalService);
  const reportService = new ReportService(evidenceRefDAO, auditLogDAO, projectService, runService, findingService, gateService, approvalService);

  // App
  const app = express();
  app.use(express.json());
  app.use(createAuthMiddleware(userService, false));

  // Mount routes matching index.ts
  app.use("/api/projects/:pid/adapters", createProjectAdaptersRouter(adapterManager));
  app.use("/api/projects/:pid/settings", createProjectSettingsRouter(settingsService));
  app.use("/api/projects/:pid/runs", createRunRouter(runService));
  app.use("/api/projects/:pid/findings", createFindingRouter(findingService));
  app.use("/api/projects/:pid/gates", createQualityGateRouter(gateService));
  app.use("/api/projects/:pid/approvals", createApprovalRouter(approvalService));
  app.use("/api/projects/:pid/report", createReportRouter(reportService));
  app.use("/api/projects/:pid/targets", createBuildTargetRouter(buildTargetService, projectDAO, testSourceService as any, testSastClient as any));
  app.use("/api/projects/:pid/targets/:tid/libraries", createTargetLibraryRouter(targetLibraryDAO as any, buildTargetDAO, projectDAO));
  app.use("/api/projects/:pid/sdk", createSdkRouter(sdkService as any, projectDAO, undefined, notificationService, sdkUploadRoot));
  app.use("/api/projects/:pid/pipeline", createPipelineRouter(pipelineOrchestrator as any, projectDAO, buildTargetDAO));
  app.use("/api/projects/:pid/source", createProjectSourceRouter(testSourceService as any, projectDAO, undefined, buildTargetDAO, notificationService));
  app.use("/api/projects/:pid/activity", createActivityRouter(activityService));
  app.use("/api/projects/:pid/notifications", createNotificationRouter(notificationService));
  app.use("/api/sdk-profiles", createSdkProfileRouter());
  app.use("/health", createHealthRouter(
    { checkHealth: async () => ({ status: "ok" }) } as any,
    adapterManager,
    { checkHealth: async () => ({ status: "ok" }) } as any,
    { checkHealth: async () => ({ status: "ok" }) } as any,
    { checkHealth: async () => ({ status: "ok" }) } as any,
    { checkHealth: async () => ({ status: "ok" }) } as any,
  ));
  app.use("/api/projects", createProjectRouter(projectService));
  app.use("/api", createFileRouter(fileStore));
  app.use("/api/dynamic-analysis", createDynamicAnalysisRouter(dynamicAnalysisService as any));
  app.use("/api/dynamic-test", createDynamicTestRouter(dynamicTestService as any));
  app.use("/api/analysis", createAnalysisRouter(
    analysisOrchestrator as any,
    analysisResultDAO,
    analysisTracker,
    findingDAO,
    runDAO,
    gateResultDAO,
    agentClient as any,
    testSourceService as any,
  ));
  app.use("/api/runs", createRunDetailRouter(runService));
  app.use("/api/findings", createFindingDetailRouter(findingService));
  app.use("/api/gates", createQualityGateDetailRouter(gateService, approvalService));
  app.use("/api/approvals", createApprovalDetailRouter(approvalService));
  app.use("/api/notifications", createNotificationDetailRouter(notificationService));
  app.use("/api/auth", createAuthRouter(userService));
  app.use("/api/gate-profiles", createGateProfileRouter());

  app.use(errorHandlerMiddleware);

  return {
    app, db,
    projectDAO, runDAO, findingDAO, evidenceRefDAO, gateResultDAO,
    approvalDAO, auditLogDAO, analysisResultDAO, dynamicSessionDAO, fileStore,
    buildTargetDAO, targetLibraryDAO, sdkRegistryDAO, notificationDAO, userDAO, sessionDAO,
    organizationDAO, registrationRequestDAO, passwordResetTokenDAO, devPasswordResetDeliveryDAO,
    gateService, normalizer, buildTargetService,
    notificationService, userService, settingsService, analysisTracker, pipelineRunCalls, pipelinePrepareCalls, analysisQuickCalls, analysisDeepCalls,
    agentTaskResponses,
    projectUploadsRoot, dynamicTestRunningProjects,
  };
}
