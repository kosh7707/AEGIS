/**
 * BuildTarget 파이프라인 오케스트레이터
 *
 * 빌드(S4) → 스캔(S4) → 코드그래프 적재(S5) 순차 실행
 * BuildTarget별로 상태머신 관리 + WS 진행률 브로드캐스트
 */
import crypto from "crypto";
import fs from "fs";
import path from "path";
import type {
  BuildTarget,
  BuildTargetStatus,
  RegisteredSdk,
  SdkRegistryStatus,
  WsPipelineMessage,
  AnalysisResult,
  Vulnerability,
  Severity,
} from "@aegis/shared";
import type { PipelinePhase } from "@aegis/shared";
import { createLogger } from "../lib/logger";
import { NotFoundError, BuildAgentUnavailableError, BuildAgentTimeoutError, PipelineStepError, InvalidInputError } from "../lib/errors";
import type { ProjectSourceService } from "./project-source.service";
import type { SastAnalysisBuildProfile, SastClient, SastScanResponse } from "./sast-client";
import type { KbClient } from "./kb-client";
import type { BuildAgentClient, BuildResolveBuildContext, BuildResolveRequest } from "./build-agent-client";
import type { TargetLibraryDAO } from "../dao/target-library.dao";
import type { IBuildTargetDAO, IAnalysisExecutionDAO, IAnalysisResultDAO } from "../dao/interfaces";
import type { ResultNormalizer } from "./result-normalizer";
import type { WsBroadcaster } from "./ws-broadcaster";
import type { NotificationService } from "./notification.service";

const logger = createLogger("pipeline-orchestrator");

const SETUP_STATUSES: readonly string[] = ["discovered", "resolving", "configured", "resolve_failed"];
const SDK_MATERIALIZATION_UNUSABLE_STATUSES = new Set<SdkRegistryStatus>([
  "uploading",
  "uploaded",
  "extracting",
  "installing",
  "upload_failed",
]);

interface SdkRegistryLookup {
  findById(id: string): RegisteredSdk | undefined;
}

function statusToPhase(status: BuildTargetStatus): PipelinePhase {
  if (SETUP_STATUSES.includes(status)) return "setup";
  if (status === "ready") return "ready";
  return "build";
}

function resolveBuildMode(target: BuildTarget): "native" | "sdk" {
  const sdkId = target.buildProfile?.sdkId;
  if (target.sdkChoiceState === "sdk-selected" && sdkId && sdkId !== "none" && sdkId !== "custom") {
    return "sdk";
  }
  return "native";
}

export class PipelineOrchestrator {
  constructor(
    private sourceService: ProjectSourceService,
    private sastClient: SastClient,
    private kbClient: KbClient,
    private buildAgentClient: BuildAgentClient,
    private targetLibraryDAO: TargetLibraryDAO,
    private buildTargetDAO: IBuildTargetDAO,
    private analysisResultDAO: IAnalysisResultDAO,
    private resultNormalizer: ResultNormalizer,
    private ws?: WsBroadcaster<WsPipelineMessage>,
    private notificationService?: NotificationService,
    private analysisExecutionDAO?: IAnalysisExecutionDAO,
    private sdkRegistryLookup?: SdkRegistryLookup,
    private uploadsDir?: string,
  ) {}

  async runPipeline(
    projectId: string,
    targetIds?: string[],
    requestId?: string,
    signal?: AbortSignal,
    pipelineId: string = `pipe-${crypto.randomUUID().slice(0, 8)}`,
  ): Promise<void> {
    const projectPath = this.sourceService.getProjectPath(projectId);
    if (!projectPath) {
      throw new NotFoundError(`Project source not found: ${projectId}`);
    }

    let targets = this.buildTargetDAO.findByProjectId(projectId);
    if (targetIds?.length) {
      targets = targets.filter((t) => targetIds.includes(t.id));
    }
    if (targets.length === 0) {
      throw new NotFoundError("No build targets found for this project");
    }

    let readyCount = 0;
    let failedCount = 0;

    for (const target of targets) {
      if (signal?.aborted) break;

      try {
        await this.processTarget(projectId, pipelineId, projectPath, target, requestId, signal);
        readyCount++;
      } catch (err) {
        failedCount++;
        const errorMsg = err instanceof Error ? err.message : "Unknown error";
        logger.error({ err, targetId: target.id, targetName: target.name, requestId }, "Pipeline target failed");

        this.broadcast(projectId, {
          type: "pipeline-error",
          payload: {
            pipelineId,
            projectId,
            targetId: target.id,
            targetName: target.name,
            phase: "build",
            error: errorMsg,
          },
        });
      }
    }

    this.broadcast(projectId, {
      type: "pipeline-complete",
      payload: { pipelineId, projectId, readyCount, failedCount, totalCount: targets.length },
    });
    this.emitTerminalNotification(projectId, pipelineId, readyCount, failedCount, targets.length);

    logger.info({ pipelineId, projectId, readyCount, failedCount, total: targets.length, requestId }, "Pipeline completed");
  }

  async preparePipeline(
    projectId: string,
    targetIds?: string[],
    requestId?: string,
    signal?: AbortSignal,
    preparationId: string = `prep-${crypto.randomUUID().slice(0, 8)}`,
  ): Promise<void> {
    const projectPath = this.sourceService.getProjectPath(projectId);
    if (!projectPath) {
      throw new NotFoundError(`Project source not found: ${projectId}`);
    }

    let targets = this.buildTargetDAO.findByProjectId(projectId);
    if (targetIds?.length) {
      targets = targets.filter((t) => targetIds.includes(t.id));
    }
    if (targets.length === 0) {
      throw new NotFoundError("No build targets found for this project");
    }

    let preparedCount = 0;
    let failedCount = 0;

    for (const target of targets) {
      if (signal?.aborted) break;

      try {
        await this.prepareTarget(projectId, preparationId, projectPath, target, requestId, signal);
        preparedCount++;
      } catch (err) {
        failedCount++;
        const errorMsg = err instanceof Error ? err.message : "Unknown error";
        logger.error({ err, targetId: target.id, targetName: target.name, requestId }, "Build preparation target failed");
        this.broadcast(projectId, {
          type: "pipeline-error",
          payload: {
            pipelineId: preparationId,
            projectId,
            targetId: target.id,
            targetName: target.name,
            phase: "setup",
            error: errorMsg,
          },
        });
      }
    }

    logger.info({ preparationId, projectId, preparedCount, failedCount, total: targets.length, requestId }, "Build preparation completed");
  }

  private async processTarget(
    projectId: string,
    pipelineId: string,
    projectPath: string,
    target: BuildTarget,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const { scanPath } = await this.prepareTarget(projectId, pipelineId, projectPath, target, requestId, signal);

    if (signal?.aborted) return;

    const kbProjectId = `${projectId}:${target.name}`;

    // ── Step 1.5: Library Identification (S4) ──
    let thirdPartyPaths: string[] = [];
    try {
      const libs = await this.sastClient.identifyLibraries(scanPath, requestId, signal);
      if (libs.length > 0) {
        this.targetLibraryDAO.upsertFromScan(target.id, projectId, libs);
        thirdPartyPaths = this.targetLibraryDAO.getIncludedPaths(target.id);
        logger.info({ targetId: target.id, identified: libs.length, included: thirdPartyPaths.length }, "Libraries identified");
      }
    } catch (err) {
      logger.warn({ err, targetId: target.id }, "Library identification failed — continuing without");
    }

    if (signal?.aborted) return;

    // ── Step 2: SAST Scan ──
    this.updateStatus(projectId, pipelineId, target, "scanning", "SAST 스캔 + SCA 진행 중...");

    const scanId = `scan-${crypto.randomUUID().slice(0, 8)}`;
    await this.prepareExecutionForScan(projectId, scanId, target);
    const sastResponse = await this.sastClient.scan(
      {
        scanId,
        projectId,
        projectPath: scanPath,
        compileCommands: target.compileCommandsPath,
        buildProfile: this.buildSastScanProfile(projectId, target),
        thirdPartyPaths: thirdPartyPaths.length > 0 ? thirdPartyPaths : undefined,
      },
      requestId,
      signal,
    );

    if (sastResponse.status !== "completed") {
      await this.analysisExecutionDAO?.update(scanId, {
        quickSastStatus: "failed",
        quickGraphRagStatus: "failed",
        status: "failed",
      });
      this.buildTargetDAO.updatePipelineState(target.id, { status: "scan_failed" });
      this.updateStatus(projectId, pipelineId, target, "scan_failed", `스캔 실패: ${sastResponse.error}`);
      throw new PipelineStepError(`Scan failed for ${target.name}: ${sastResponse.error}`);
    }

    // Quick 결과 저장
    const quickResult = this.buildQuickResult(scanId, projectId, target, sastResponse);
    this.analysisResultDAO.save(quickResult);
    this.resultNormalizer.normalizeAnalysisResult(quickResult, { startedAt: new Date().toISOString() });
    await this.analysisExecutionDAO?.update(scanId, {
      quickSastStatus: "succeeded",
    });

    this.buildTargetDAO.updatePipelineState(target.id, {
      status: "scanned",
      sastScanId: scanId,
      scaLibraries: sastResponse.sca?.libraries,
    });
    this.updateStatus(projectId, pipelineId, target, "scanned", `스캔 완료 (${sastResponse.stats.findingsTotal} findings)`);

    if (signal?.aborted) return;

    // ── Step 3: Code Graph Ingest ──
    if (sastResponse.codeGraph) {
      // S5 notice (2026-04-14): code-graph readiness는 /ready가 아니라 ingest 응답(status + readiness.graphRag)이 authoritative.
      this.updateStatus(projectId, pipelineId, target, "graphing", "코드그래프 KB 적재 중...");

      try {
        const ingestResult = await this.kbClient.ingestCodeGraph(
          kbProjectId,
          sastResponse.codeGraph,
          requestId,
          signal,
        );

        if (!this.kbClient.isGraphReady(ingestResult)) {
          this.buildTargetDAO.updatePipelineState(target.id, {
            status: "graph_failed",
            codeGraphStatus: "failed",
          });
          this.updateStatus(projectId, pipelineId, target, "graph_failed", `코드그래프 미준비: ${ingestResult.status ?? "unknown"}`);
          throw new PipelineStepError(`Code graph not ready for ${target.name}: ${ingestResult.status ?? "unknown"}`);
        }

        const nodeCount = this.kbClient.getIngestNodeCount(ingestResult);
        this.buildTargetDAO.updatePipelineState(target.id, {
          status: "graphed",
          codeGraphStatus: "ingested",
          codeGraphNodeCount: nodeCount,
        });
        await this.analysisExecutionDAO?.update(scanId, {
          quickGraphRagStatus: "succeeded",
          status: "completed",
        });
        this.updateStatus(projectId, pipelineId, target, "graphed", `코드그래프 적재 완료 (${nodeCount} nodes)`);
      } catch (err) {
        this.buildTargetDAO.updatePipelineState(target.id, {
          status: "graph_failed",
          codeGraphStatus: "failed",
        });
        logger.warn({ err, targetId: target.id, requestId }, "Code graph ingest failed");
        await this.analysisExecutionDAO?.update(scanId, {
          quickGraphRagStatus: "failed",
          status: "failed",
        });
        if (err instanceof PipelineStepError) {
          this.updateStatus(projectId, pipelineId, target, "graph_failed", `코드그래프 미준비: ${err.message}`);
          throw err;
        }
        this.updateStatus(projectId, pipelineId, target, "graph_failed", "코드그래프 적재 실패");
        throw new PipelineStepError(`Code graph ingest failed for ${target.name}`);
      }
    } else {
      this.buildTargetDAO.updatePipelineState(target.id, {
        status: "graph_failed",
        codeGraphStatus: "failed",
      });
      await this.analysisExecutionDAO?.update(scanId, {
        quickGraphRagStatus: "failed",
        status: "failed",
      });
      this.updateStatus(projectId, pipelineId, target, "graph_failed", "코드그래프 결과 없음");
      throw new PipelineStepError(`Code graph missing for ${target.name}`);
    }

    // ── Step 4: Ready ──
    this.buildTargetDAO.updatePipelineState(target.id, { status: "ready" });
    this.updateStatus(projectId, pipelineId, target, "ready", "분석 준비 완료");
  }

  private async prepareTarget(
    projectId: string,
    pipelineId: string,
    projectPath: string,
    target: BuildTarget,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<{ scanPath: string }> {
    // 격리된 BuildTarget 경로 우선 사용 (없으면 원본 프로젝트 내 상대경로)
    const scanPath = target.sourcePath ?? path.join(projectPath, target.relativePath);
    const isIsolated = !!target.sourcePath;
    const buildAgentProjectPath = isIsolated ? scanPath : projectPath;
    const buildResolveRequest = (taskId: string): BuildResolveRequest => {
      const build = this.buildResolveBuildContext(projectId, target);
      return {
        taskType: "build-resolve",
        taskId,
        contractVersion: "build-resolve-v1",
        strictMode: true,
        context: {
          trusted: {
            projectPath: buildAgentProjectPath,
            buildTargetPath: isIsolated ? "." : target.relativePath,
            buildTargetName: target.name,
            build,
            targetPath: isIsolated ? "." : target.relativePath,
            targetName: target.name,
            targets: [
              {
                name: target.name,
                path: isIsolated ? "." : target.relativePath,
                buildSystem: target.buildSystem ?? "cmake",
                buildFiles: [],
              },
            ],
          },
        },
        constraints: { timeoutMs: 600_000 },
      };
    };

    // ── Step 0: Build Resolve (S3 Build Agent) ──
    if (target.status === "discovered" || !target.buildCommand) {
      this.updateStatus(projectId, pipelineId, target, "resolving", "빌드 명령어 자동 탐색 중 (Build Agent)...");

      try {
        let resolveResp = await this.buildAgentClient.submitTask(
          buildResolveRequest(`resolve-${crypto.randomUUID().slice(0, 8)}`),
          requestId,
          signal,
        );

        // 재시도: retryable 실패 시 1회 자동 재시도
        if (!this.buildAgentClient.isSuccess(resolveResp) && resolveResp.retryable && !signal?.aborted) {
          logger.info({ targetId: target.id, failureCode: resolveResp.failureCode }, "Retryable build failure, attempting retry (1/1)");
          this.updateStatus(projectId, pipelineId, target, "resolving", "빌드 재시도 중...");
          resolveResp = await this.buildAgentClient.submitTask(
            buildResolveRequest(`resolve-retry-${crypto.randomUUID().slice(0, 8)}`),
            requestId,
            signal,
          );
        }

        if (this.buildAgentClient.isSuccess(resolveResp)) {
          const br = resolveResp.result.buildResult;
          const buildPreparation = resolveResp.result.buildPreparation;
          const resolvedBuildCommand = buildPreparation?.buildCommand ?? br.buildCommand;
          const cleanPass = resolveResp.result.cleanPass ?? resolveResp.result.buildOutcome?.cleanPass ?? br.success;

          if (cleanPass === false) {
            const diagnostics = resolveResp.result.buildDiagnostics;
            const failureCode = diagnostics?.failureCode ?? resolveResp.result.buildOutcome?.outcome ?? "BUILD_NOT_CLEAN";
            const detail = br.errorLog ?? resolveResp.result.summary ?? failureCode;
            this.buildTargetDAO.updatePipelineState(target.id, {
              status: "resolve_failed",
              buildLog: `${failureCode}: ${detail}`,
            });
            this.updateStatus(projectId, pipelineId, target, "resolve_failed", `빌드 준비 실패(${failureCode}): ${detail}`);
            throw new PipelineStepError(`Build resolve did not clean-pass for ${target.name}: ${failureCode}`);
          }

          if (!br.success) {
            // 에이전트가 빌드 시도했지만 실패
            this.buildTargetDAO.updatePipelineState(target.id, {
              status: "resolve_failed",
              buildLog: br.errorLog ?? undefined,
            });
            this.updateStatus(projectId, pipelineId, target, "resolve_failed", `빌드 실패: ${br.errorLog ?? "unknown"}`);
            if (!target.buildProfile?.compiler) {
              throw new PipelineStepError(`Build resolve failed for ${target.name}: ${br.errorLog}`);
            }
            logger.warn({ targetId: target.id }, "Build Agent build failed, using existing profile");
          } else {
            // 빌드 성공 — buildCommand + buildScript 저장
            this.buildTargetDAO.updatePipelineState(target.id, {
              status: "configured",
              buildCommand: resolvedBuildCommand,
            });
            target.buildCommand = resolvedBuildCommand;
            this.updateStatus(
              projectId,
              pipelineId,
              target,
              "configured",
              `빌드 명령어 결정 완료 (confidence: ${resolveResp.result.confidence})`,
            );
          }
        } else {
          this.buildTargetDAO.updatePipelineState(target.id, { status: "resolve_failed" });
          this.updateStatus(projectId, pipelineId, target, "resolve_failed", resolveResp.failureDetail);
          if (!target.buildProfile?.compiler) {
            throw new PipelineStepError(`Build resolve failed for ${target.name}: ${resolveResp.failureDetail}`);
          }
          logger.warn({ targetId: target.id }, "Build resolve failed, using existing profile");
        }
      } catch (err) {
        if (err instanceof BuildAgentUnavailableError || err instanceof BuildAgentTimeoutError) {
          logger.warn({ err, targetId: target.id }, "Build Agent unavailable, using existing profile");
          if (!target.buildProfile?.compiler) {
            this.buildTargetDAO.updatePipelineState(target.id, { status: "resolve_failed" });
            throw err;
          }
        } else if (err instanceof InvalidInputError || err instanceof NotFoundError) {
          const detail = err instanceof Error ? err.message : String(err);
          this.buildTargetDAO.updatePipelineState(target.id, {
            status: "resolve_failed",
            buildLog: detail,
          });
          this.updateStatus(projectId, pipelineId, target, "resolve_failed", `빌드 준비 요청 생성 실패: ${detail}`);
          throw new PipelineStepError(`Build resolve request invalid for ${target.name}: ${detail}`);
        } else {
          throw err;
        }
      }
    }

    if (!target.buildCommand) {
      this.buildTargetDAO.updatePipelineState(target.id, { status: "resolve_failed" });
      this.updateStatus(projectId, pipelineId, target, "resolve_failed", "빌드 명령어 없음 — caller-materialized buildCommand 필요");
      throw new PipelineStepError(`Build command missing for ${target.name}`);
    }

    // ── Step 1: Build ──
    this.updateStatus(projectId, pipelineId, target, "building", "빌드 중 (bear → compile_commands.json)...");

    const buildResult = await this.sastClient.build(
      { projectPath: scanPath, buildCommand: target.buildCommand },
      requestId,
      signal,
    );

    if (!this.sastClient.isBuildReadyForQuick(buildResult)) {
      const reason = buildResult.error
        ?? (buildResult.readinessStatus
          ? `build readiness not satisfied (${buildResult.readinessStatus})`
          : "compile_commands 준비 실패");
      this.buildTargetDAO.updatePipelineState(target.id, {
        status: "build_failed",
        buildLog: buildResult.buildLog ?? reason,
      });
      this.updateStatus(projectId, pipelineId, target, "build_failed", `빌드 실패: ${reason}`);
      throw new PipelineStepError(`Build failed for ${target.name}: ${reason}`);
    }

    this.buildTargetDAO.updatePipelineState(target.id, {
      status: "built",
      compileCommandsPath: buildResult.compileCommandsPath,
      lastBuiltAt: new Date().toISOString(),
    });
    target.compileCommandsPath = buildResult.compileCommandsPath;
    this.updateStatus(projectId, pipelineId, target, "built", `빌드 완료 (${buildResult.userEntries ?? buildResult.entries ?? 0} entries)`);

    return { scanPath };
  }

  private buildResolveBuildContext(projectId: string, target: BuildTarget): BuildResolveBuildContext {
    const mode = resolveBuildMode(target);
    const build: BuildResolveBuildContext = {
      mode,
      ...(mode === "sdk" ? { sdkId: target.buildProfile.sdkId } : {}),
      ...(target.scriptHintPath ? { scriptHintPath: target.scriptHintPath } : {}),
    };

    if (mode !== "sdk" || !target.buildProfile.sdkId?.startsWith("sdk-")) {
      return build;
    }

    return {
      ...build,
      ...this.buildUploadedSdkDescriptor(projectId, target.buildProfile.sdkId),
    };
  }

  buildSastScanProfile(projectId: string, target: BuildTarget): SastAnalysisBuildProfile {
    const profile = target.buildProfile;
    if (profile.sdkId === "none") {
      const { sdkId: _sdkId, ...rest } = profile;
      return { ...rest, sdkResolutionMode: "none" };
    }
    if (!profile.sdkId?.startsWith("sdk-")) {
      return profile;
    }

    const descriptor = this.buildUploadedSdkDescriptor(projectId, profile.sdkId);
    if (!descriptor.sdkRootPath) {
      throw new InvalidInputError(`SDK materialization descriptor missing sdkRootPath: ${profile.sdkId}`);
    }

    const { sdkId: _sdkId, ...rest } = profile;
    return {
      ...rest,
      sdkResolutionMode: "non-registered",
      sdkDescriptor: {
        sdkRootPath: descriptor.sdkRootPath,
        ...(descriptor.setupScript ? { setupScript: descriptor.setupScript } : {}),
        ...(descriptor.sysroot ? { sysroot: descriptor.sysroot } : {}),
        ...(descriptor.toolchainTriplet ? { toolchainTriplet: descriptor.toolchainTriplet } : {}),
        ...(profile.compilerVersion ? { compilerVersion: profile.compilerVersion } : {}),
        ...(profile.targetArch ? { targetArch: profile.targetArch } : {}),
        ...(profile.languageStandard ? { languageStandard: profile.languageStandard } : {}),
        ...(profile.includePaths ? { includePaths: profile.includePaths } : {}),
        ...(profile.defines ? { defines: profile.defines } : {}),
        ...(descriptor.environment ? { environment: descriptor.environment } : {}),
      },
    };
  }

  private buildUploadedSdkDescriptor(
    projectId: string,
    sdkId: string,
  ): Partial<BuildResolveBuildContext> {
    if (!this.sdkRegistryLookup) {
      throw new InvalidInputError("Registered SDK lookup is required for SDK materialization descriptor production");
    }
    if (!this.uploadsDir) {
      throw new InvalidInputError("uploadsDir is required for SDK materialization descriptor production");
    }

    const sdk = this.sdkRegistryLookup.findById(sdkId);
    if (!sdk) throw new NotFoundError(`SDK not found: ${sdkId}`);
    if (sdk.projectId !== projectId) {
      throw new NotFoundError(`SDK not found for project: ${sdkId}`);
    }
    if (SDK_MATERIALIZATION_UNUSABLE_STATUSES.has(sdk.status)) {
      throw new InvalidInputError(`SDK is not materialized yet: ${sdkId} (${sdk.status})`);
    }

    const sdkRootPath = this.resolveProjectOwnedSdkRoot(projectId, sdk);
    const setupScript = normalizeSdkProfilePath(sdkRootPath, sdk.profile?.environmentSetup, "environmentSetup");
    const sysroot = normalizeSdkProfilePath(sdkRootPath, sdk.profile?.sysroot, "sysroot");
    const toolchainTriplet = normalizeToolchainTriplet(sdk.profile?.compilerPrefix);

    return {
      sdkRootPath,
      ...(setupScript ? { setupScript } : {}),
      ...(sysroot ? { sysroot } : {}),
      ...(toolchainTriplet ? { toolchainTriplet } : {}),
      environment: buildSdkDescriptorEnvironment(sdkRootPath, { setupScript, sysroot, toolchainTriplet }),
    };
  }

  private resolveProjectOwnedSdkRoot(projectId: string, sdk: RegisteredSdk): string {
    const uploadsSdkRoot = path.resolve(this.uploadsDir!, projectId, "sdk");
    const sdkRootPath = path.resolve(sdk.path);
    if (!isPathInside(uploadsSdkRoot, sdkRootPath)) {
      throw new InvalidInputError("SDK materialized root must stay inside the project SDK uploads root");
    }
    if (!fs.existsSync(sdkRootPath)) {
      throw new InvalidInputError(`SDK materialized root does not exist: ${sdk.id}`);
    }
    if (!fs.statSync(sdkRootPath).isDirectory()) {
      throw new InvalidInputError(`SDK materialized root is not a directory: ${sdk.id}`);
    }

    const realUploadsSdkRoot = fs.realpathSync(uploadsSdkRoot);
    const realSdkRootPath = fs.realpathSync(sdkRootPath);
    if (!isPathInside(realUploadsSdkRoot, realSdkRootPath)) {
      throw new InvalidInputError("SDK materialized root symlink escapes the project SDK uploads root");
    }
    const visibleEntries = fs.readdirSync(realSdkRootPath).filter((entry) => !entry.startsWith("."));
    if (visibleEntries.length === 0) {
      throw new InvalidInputError(`SDK materialized root is empty: ${sdk.id}`);
    }

    return realSdkRootPath;
  }

  private buildQuickResult(
    scanId: string,
    projectId: string,
    target: BuildTarget,
    sastResponse: SastScanResponse,
  ): AnalysisResult {
    const vulns: Vulnerability[] = sastResponse.findings.map((f, i) => ({
      id: `VULN-SAST-${Date.now()}-${i}`,
      severity: this.normalizeSeverity(f.severity),
      title: f.message.length > 120 ? f.message.slice(0, 117) + "..." : f.message,
      description: `[${f.toolId}] ${f.message}`,
      location: `${f.location.file}:${f.location.line}`,
      source: "rule" as const,
      ruleId: f.ruleId,
    }));

    const summary = { total: vulns.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulns) summary[v.severity]++;

    return {
      id: scanId,
      projectId,
      buildTargetId: target.id,
      analysisExecutionId: scanId,
      module: "static_analysis",
      status: "completed",
      vulnerabilities: vulns,
      summary,
      scaLibraries: sastResponse.sca?.libraries ? [...sastResponse.sca.libraries] : undefined,
      createdAt: new Date().toISOString(),
    };
  }

  private async prepareExecutionForScan(
    projectId: string,
    executionId: string,
    target: BuildTarget,
  ): Promise<void> {
    if (!this.analysisExecutionDAO) return;

    const existingActive = this.analysisExecutionDAO.findActiveByBuildTargetId(target.id);
    if (existingActive && existingActive.id !== executionId) {
      this.analysisExecutionDAO.update(existingActive.id, {
        status: "superseded",
        supersededByExecutionId: executionId,
      });
    }

    const now = new Date().toISOString();
    this.analysisExecutionDAO.save({
      id: executionId,
      projectId,
      buildTargetId: target.id,
      buildTargetName: target.name,
      buildTargetRelativePath: target.relativePath,
      buildProfileSnapshot: target.buildProfile,
      sdkChoiceState: target.sdkChoiceState,
      status: "active",
      quickBuildPrepStatus: "succeeded",
      quickGraphRagStatus: "pending",
      quickSastStatus: "running",
      deepStatus: "pending",
      createdAt: now,
      updatedAt: now,
    });
  }

  private normalizeSeverity(toolSeverity: string): Severity {
    const lower = toolSeverity.toLowerCase();
    if (lower === "error" || lower === "critical") return "critical";
    if (lower === "warning" || lower === "high") return "high";
    if (lower === "style" || lower === "medium") return "medium";
    if (lower === "info" || lower === "low") return "low";
    return "medium";
  }

  private updateStatus(
    projectId: string,
    pipelineId: string,
    target: BuildTarget,
    status: BuildTargetStatus,
    message: string,
  ): void {
    this.broadcast(projectId, {
      type: "pipeline-target-status",
      payload: {
        pipelineId,
        projectId,
        targetId: target.id,
        targetName: target.name,
        status,
        message,
        phase: statusToPhase(status),
      },
    });
  }

  private broadcast(projectId: string, msg: WsPipelineMessage): void {
    this.ws?.broadcast(projectId, msg);
  }

  private emitTerminalNotification(
    projectId: string,
    pipelineId: string,
    readyCount: number,
    failedCount: number,
    totalCount: number,
  ): void {
    try {
      this.notificationService?.emit({
        projectId,
        type: failedCount > 0 ? "gate_failed" : "analysis_complete",
        title: failedCount > 0 ? "파이프라인 완료 (일부 실패)" : "파이프라인 완료",
        body: `ready ${readyCount}/${totalCount}, failed ${failedCount}`,
        jobKind: "pipeline",
        resourceId: pipelineId,
        correlationId: pipelineId,
        severity: failedCount > 0 ? "medium" : "low",
      });
    } catch {
      // notification failure must not affect pipeline completion
    }
  }
}

function normalizeSdkProfilePath(
  sdkRootPath: string,
  rawPath: string | undefined,
  fieldName: string,
): string | undefined {
  const raw = rawPath?.trim();
  if (!raw) return undefined;
  if (raw.includes("\0")) {
    throw new InvalidInputError(`SDK ${fieldName} must not contain NUL bytes`);
  }
  const candidate = raw.replace(/\\/g, "/");
  const resolved = path.isAbsolute(candidate)
    ? path.resolve(candidate)
    : path.resolve(sdkRootPath, candidate);
  if (!isPathInside(sdkRootPath, resolved)) {
    throw new InvalidInputError(`SDK ${fieldName} must resolve inside sdkRootPath`);
  }
  if (!fs.existsSync(resolved)) {
    throw new InvalidInputError(`SDK ${fieldName} not found inside sdkRootPath: ${raw}`);
  }

  const relative = path.relative(sdkRootPath, fs.realpathSync(resolved)).split(path.sep).join("/");
  if (relative.startsWith("../") || relative === ".." || path.isAbsolute(relative)) {
    throw new InvalidInputError(`SDK ${fieldName} symlink escapes sdkRootPath`);
  }
  return relative || ".";
}

function normalizeToolchainTriplet(compilerPrefix: string | undefined): string | undefined {
  const normalized = compilerPrefix?.trim().replace(/-+$/, "");
  return normalized || undefined;
}

function buildSdkDescriptorEnvironment(
  sdkRootPath: string,
  descriptor: {
    setupScript?: string;
    sysroot?: string;
    toolchainTriplet?: string;
  },
): Record<string, string> {
  const environment: Record<string, string> = {
    AEGIS_SDK_ROOT: sdkRootPath,
    SDK_DIR: sdkRootPath,
  };
  if (descriptor.setupScript) {
    environment.AEGIS_SDK_SETUP_SCRIPT = path.join(sdkRootPath, descriptor.setupScript);
  }
  if (descriptor.sysroot) {
    const sysrootPath = path.join(sdkRootPath, descriptor.sysroot);
    environment.AEGIS_SDK_SYSROOT = sysrootPath;
    environment.SDKTARGETSYSROOT = sysrootPath;
  }
  if (descriptor.toolchainTriplet) {
    environment.AEGIS_TOOLCHAIN_TRIPLET = descriptor.toolchainTriplet;
  }
  return environment;
}

function isPathInside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!!relative && !relative.startsWith("..") && !path.isAbsolute(relative));
}
