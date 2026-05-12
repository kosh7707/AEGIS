/**
 * Quick → Deep 2단계 분석 오케스트레이터
 *
 * Quick: S4 SAST Runner (빌드 + 6도구, ~30초)
 * Deep:  S3 Analysis Agent (SAST + 코드그래프 + SCA + LLM, ~3분)
 */
import crypto from "crypto";
import path from "path";
import type {
  AnalysisExecution,
  AnalysisResult,
  Vulnerability,
  AnalysisSummary,
  Severity,
  SastFinding,
  BuildProfile,
  BuildTarget,
  WsAnalysisMessage,
} from "@aegis/shared";
import { createLogger } from "../lib/logger";
import { InvalidInputError, NotFoundError } from "../lib/errors";
import type { ProjectSourceService } from "./project-source.service";
import type { SastAnalysisBuildProfile, SastClient, SastScanResponse } from "./sast-client";
import type { KbClient, CodeGraphIngestResponse } from "./kb-client";
import type {
  AgentClient,
  AgentTaskRequest,
  AgentEvidenceRef,
  AgentResponseSuccess,
} from "./agent-client";
import type { IAnalysisExecutionDAO, IAnalysisResultDAO } from "../dao/interfaces";
import type { ProjectSettingsService } from "./project-settings.service";
import type { BuildTargetService } from "./build-target.service";
import type { ResultNormalizer, NormalizerContext } from "./result-normalizer";
import type { WsBroadcaster } from "./ws-broadcaster";
import type { TargetLibraryDAO } from "../dao/target-library.dao";
import type { AnalysisTracker } from "./analysis-tracker";
import type { PipelineOrchestrator } from "./pipeline-orchestrator";

const logger = createLogger("analysis-orchestrator");

export class AnalysisOrchestrator {
  constructor(
    private sourceService: ProjectSourceService,
    private sastClient: SastClient,
    private kbClient: KbClient,
    private agentClient: AgentClient,
    private analysisResultDAO: IAnalysisResultDAO,
    private settingsService: ProjectSettingsService,
    private resultNormalizer: ResultNormalizer,
    private ws?: WsBroadcaster<WsAnalysisMessage>,
    private buildTargetService?: BuildTargetService,
    private targetLibraryDAO?: TargetLibraryDAO,
    private analysisTracker?: AnalysisTracker,
    private analysisExecutionDAO?: IAnalysisExecutionDAO,
    private pipelineOrchestrator?: PipelineOrchestrator,
  ) {}

  async runAnalysis(
    projectId: string,
    analysisId: string,
    targetIds?: string[],
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.runQuickAnalysis(projectId, analysisId, targetIds, requestId, signal);
  }

  async runQuickAnalysis(
    projectId: string,
    analysisId: string,
    targetIds?: string[],
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<void> {
    if (!targetIds || targetIds.length !== 1) {
      throw new InvalidInputError("BuildTarget-only quick execution requires exactly one BuildTarget");
    }
    const target = this.preflightQuickRequest(projectId, targetIds[0]!);

    await this.prepareExecutionForQuick(projectId, analysisId, target, requestId, signal);
    const refreshedTarget = this.buildTargetService?.findById?.(target.id)
      ?? this.buildTargetService?.findByProjectId(projectId)?.find((candidate) => candidate.id === target.id)
      ?? target;
    if (!refreshedTarget.compileCommandsPath) {
      await this.analysisExecutionDAO?.update(analysisId, {
        quickBuildPrepStatus: "failed",
        status: "failed",
      });
      throw new InvalidInputError(`Quick build-prep did not produce compile_commands.json for BuildTarget ${refreshedTarget.name}`);
    }
    await this.analysisExecutionDAO?.update(analysisId, { quickBuildPrepStatus: "succeeded" });
    await this.runAnalysisInternal(projectId, analysisId, targetIds, requestId, signal, true);
  }

  async runDeepAnalysis(
    projectId: string,
    analysisId: string,
    buildTargetId: string,
    executionId: string,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const { projectPath, quickResult, target } = this.preflightDeepRequest(projectId, buildTargetId, executionId);
    const kbProjectId = target ? `${projectId}:${target.name}` : projectId;
    const execution = this.analysisExecutionDAO?.findById(executionId);
    if (execution) {
      await this.analysisExecutionDAO?.update(executionId, { deepStatus: "running" });
    }
    const graphStats = await this.kbClient.getCodeGraphStats(kbProjectId, requestId);
    if (!graphStats || this.kbClient.getStatsFunctionCount(graphStats) <= 0) {
      throw new InvalidInputError(`Quick graph context not ready for scope ${kbProjectId}`);
    }

    const settings = this.settingsService.getAll(projectId);
    const files = this.sourceService.listFiles(projectId);
    const startedAt = new Date().toISOString();

    this.analysisTracker?.update(analysisId, {
      phase: "deep_submitting",
      message: "Quick 결과 기반 심층 분석 에이전트 호출 중...",
      totalFiles: files.length,
      processedFiles: files.length,
    });
    this.broadcast(analysisId, {
      type: "analysis-progress",
      payload: {
        analysisId,
        buildTargetId: target?.id,
        executionId,
        phase: "deep_submitting",
        message: "Quick 결과 기반 심층 분석 에이전트 호출 중...",
      },
    });

    const evidenceRefs: AgentEvidenceRef[] = [{
      refId: "eref-project-source",
      artifactId: projectId,
      artifactType: "raw-source",
      locatorType: "lineRange",
      locator: {
        projectPath,
        fileCount: files.length,
        ...(target ? { targetName: target.name, targetPath: target.relativePath } : {}),
      },
    }];

    const quickContext = {
      executionId,
      summary: quickResult.summary,
      findingCount: quickResult.summary.total,
      vulnerabilities: quickResult.vulnerabilities,
      scaLibraries: quickResult.scaLibraries,
      ...(target ? { kbProjectId, targetName: target.name, targetPath: target.relativePath } : {}),
    };
    const graphContext = {
      kbProjectId,
      status: "ready",
      functionCount: this.kbClient.getStatsFunctionCount(graphStats),
      callEdgeCount: this.kbClient.getStatsCallEdgeCount(graphStats),
      ...(target ? { targetName: target.name, targetPath: target.relativePath } : {}),
    };

    const agentRequest: AgentTaskRequest = {
      taskType: "deep-analyze",
      taskId: `deep-${analysisId}`,
      context: {
        trusted: {
          objective: `${projectId} 보안 취약점 심층 분석${target ? ` (${target.name})` : ""}`,
          projectId,
          projectPath,
          ...(target ? { targetPath: target.relativePath } : {}),
          buildProfile: target?.buildProfile ?? settings.buildProfile,
          quickContext,
          graphContext,
          ...(quickResult.scaLibraries ? { scaLibraries: quickResult.scaLibraries } : {}),
        },
      },
      evidenceRefs,
      constraints: { maxTokens: 4096, timeoutMs: 300000 },
    };

    this.analysisTracker?.update(analysisId, {
      phase: "deep_analyzing",
      message: "에이전트가 심층 분석 중...",
    });
    this.broadcast(analysisId, {
      type: "analysis-progress",
      payload: {
        analysisId,
        buildTargetId: target?.id,
        executionId,
        phase: "deep_analyzing",
        message: "에이전트가 심층 분석 중...",
      },
    });

    let agentResponse = await this.agentClient.submitTask(agentRequest, requestId, signal);
    if (!this.agentClient.isSuccess(agentResponse) && agentResponse.retryable && !signal?.aborted) {
      this.analysisTracker?.update(analysisId, {
        phase: "deep_analyzing",
        message: "심층 분석 재시도 중...",
      });
      this.broadcast(analysisId, {
        type: "analysis-progress",
        payload: {
          analysisId,
          buildTargetId: target?.id,
          executionId,
          phase: "deep_retrying",
          message: "심층 분석 재시도 중...",
        },
      });
      agentResponse = await this.agentClient.submitTask(agentRequest, requestId, signal);
    }

    if (this.agentClient.isSuccess(agentResponse)) {
      const deepResult = this.buildDeepResult(`deep-${analysisId}`, projectId, agentResponse, startedAt, quickResult.scaLibraries, target?.id, executionId);
      this.analysisResultDAO.save(deepResult);
      this.resultNormalizer.normalizeAgentResult(deepResult, agentResponse, { startedAt, agentEvidenceRefs: evidenceRefs });
      const cleanPass = this.isCleanDeepPass(agentResponse);
      this.analysisTracker?.update(analysisId, {
        phase: "deep_complete",
        message: cleanPass ? "심층 분석 완료" : "심층 분석 완료 — 결과 품질/검토 상태 확인 필요",
      });
      this.broadcast(analysisId, {
        type: "analysis-deep-complete",
        payload: {
          analysisId,
          buildTargetId: target?.id,
          executionId,
          findingCount: agentResponse.result.claims.length,
          analysisOutcome: deepResult.analysisOutcome,
          qualityOutcome: deepResult.qualityOutcome,
          pocOutcome: deepResult.pocOutcome,
          cleanPass,
        },
      });
      await this.analysisExecutionDAO?.update(executionId, {
        deepStatus: "succeeded",
        status: "completed",
      });
      return;
    }

    const isPartialFailure = agentResponse.failureCode?.startsWith("llm_failure_partial");
    const failedResult: AnalysisResult = {
      id: `deep-${analysisId}`,
      projectId,
      buildTargetId: target?.id,
      analysisExecutionId: executionId,
      module: "deep_analysis",
      status: "failed",
      vulnerabilities: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      warnings: [
        { code: agentResponse.failureCode, message: agentResponse.failureDetail },
        ...(isPartialFailure ? [{ code: "PARTIAL_FAILURE", message: "LLM 실패로 부분 결과만 생성됨 (Quick 결과 기반)" }] : []),
      ],
      createdAt: startedAt,
    };
    this.analysisResultDAO.save(failedResult);
    await this.analysisExecutionDAO?.update(executionId, {
      deepStatus: "failed",
      status: "failed",
    });
    this.analysisTracker?.update(analysisId, {
      phase: "deep_analyzing",
      message: "심층 분석 실패",
    });
    this.broadcast(analysisId, {
      type: "analysis-error",
      payload: {
        analysisId,
        buildTargetId: target?.id,
        executionId,
        phase: "deep",
        error: `[${agentResponse.failureCode}] ${agentResponse.failureDetail}`,
        retryable: agentResponse.retryable ?? false,
        partial: isPartialFailure,
      },
    });
    throw new Error(`[${agentResponse.failureCode}] ${agentResponse.failureDetail}`);
  }

  private async runAnalysisInternal(
    projectId: string,
    analysisId: string,
    targetIds: string[] | undefined,
    requestId: string | undefined,
    signal: AbortSignal | undefined,
    quickOnly: boolean,
  ): Promise<void> {
    const projectPath = this.sourceService.getProjectPath(projectId);
    if (!projectPath) {
      throw new NotFoundError(`Project source not found. Upload source first: ${projectId}`);
    }

    // 빌드 타겟 조회
    let targets = this.buildTargetService?.findByProjectId(projectId) ?? [];
    if (targetIds?.length) {
      targets = targets.filter((t) => targetIds.includes(t.id));
    }

    if (targets.length === 0) {
      throw new InvalidInputError(`BuildTarget is required for analysis execution: ${projectId}`);
    }
    await this.runAnalysisWithTargets(projectId, analysisId, projectPath, targets, requestId, signal, quickOnly);
  }

  /** 타겟별 순차 분석 */
  private async runAnalysisWithTargets(
    projectId: string,
    analysisId: string,
    projectPath: string,
    targets: BuildTarget[],
    requestId?: string,
    signal?: AbortSignal,
    quickOnly: boolean = false,
  ): Promise<void> {
    for (const [i, target] of targets.entries()) {
      if (signal?.aborted) return;

      const scanPath = path.join(projectPath, target.relativePath);
      const targetProgress = { current: i + 1, total: targets.length };

      // 서드파티 라이브러리 경로 조회 (S4가 cross-boundary 필터링에 사용)
      const thirdPartyPaths = this.targetLibraryDAO?.getIncludedPaths(target.id) ?? [];

      const scanBuildProfile = this.pipelineOrchestrator?.buildSastScanProfile(projectId, target)
        ?? target.buildProfile;

      await this.runSingleAnalysis(
        projectId,
        `${analysisId}-${target.name}`,
        scanPath,
        scanBuildProfile,
        {
          id: target.id,
          name: target.name,
          relativePath: target.relativePath,
          progress: targetProgress,
          compileCommandsPath: target.compileCommandsPath,
        },
        requestId,
        signal,
        thirdPartyPaths.length > 0 ? thirdPartyPaths : undefined,
        analysisId,
        quickOnly,
      );
    }
  }

  /** 단일 경로에 대한 Quick→Deep 분석 */
  private async runSingleAnalysis(
    projectId: string,
    analysisId: string,
    scanPath: string,
    buildProfile: SastAnalysisBuildProfile | undefined,
    targetInfo?: { id: string; name: string; relativePath: string; progress?: { current: number; total: number }; compileCommandsPath?: string },
    requestId?: string,
    signal?: AbortSignal,
    thirdPartyPaths?: string[],
    wsAnalysisId: string = analysisId,
    quickOnly: boolean = false,
  ): Promise<void> {
    const prefix = targetInfo ? `[${targetInfo.name}] ` : "";
    const files = this.sourceService.listFiles(projectId);
    const startedAt = new Date().toISOString();

    // ── Phase Quick: S4 SAST ──
    this.analysisTracker?.update(wsAnalysisId, {
      phase: "quick_sast",
      message: `${prefix}SAST 스캔 시작`,
      totalFiles: files.length,
      processedFiles: 0,
    });
    this.broadcast(wsAnalysisId, {
      type: "analysis-progress",
      payload: {
        analysisId: wsAnalysisId,
        buildTargetId: targetInfo?.id,
        executionId: wsAnalysisId,
        phase: "quick_sast",
        message: `${prefix}SAST 스캔 시작`,
        targetName: targetInfo?.name,
        targetProgress: targetInfo?.progress,
      },
    });

    let sastFindings: SastFinding[] = [];
    let codeGraphSummary: unknown = undefined;
    let scaLibraries: unknown = undefined;
    let graphContext: Record<string, unknown> | undefined;
    let quickSastSucceeded = false;

    try {
      if (quickOnly && targetInfo && !targetInfo.compileCommandsPath) {
        throw new InvalidInputError(`Build preparation required before Quick for target ${targetInfo.name}`);
      }

      const scanId = `scan-${crypto.randomUUID().slice(0, 8)}`;
      const sastResponse = await this.sastClient.scan(
        {
          scanId,
          projectId,
          projectPath: scanPath,
          compileCommands: targetInfo?.compileCommandsPath,
          buildProfile,
          thirdPartyPaths,
        },
        requestId,
        signal,
      );

      if (sastResponse.status !== "completed") {
        logger.warn({
          analysisId,
          target: targetInfo?.name,
          requestId,
          error: sastResponse.error,
          errorCode: sastResponse.errorDetail?.code,
        }, "Quick phase returned failed scan response");
        this.broadcast(wsAnalysisId, {
          type: "analysis-error",
          payload: {
            analysisId: wsAnalysisId,
            buildTargetId: targetInfo?.id,
            executionId: wsAnalysisId,
            phase: "quick",
            error: sastResponse.error ?? "SAST scan failed",
            retryable: sastResponse.errorDetail?.retryable === true,
          },
        });
        throw new Error(sastResponse.error ?? "SAST scan failed");
      }

      sastFindings = sastResponse.findings;
      codeGraphSummary = sastResponse.codeGraph ?? undefined;
      scaLibraries = sastResponse.sca?.libraries ?? undefined;
      await this.analysisExecutionDAO?.update(wsAnalysisId, {
        quickSastStatus: "succeeded",
      });
      quickSastSucceeded = true;

      if (!sastResponse.codeGraph) {
        this.broadcast(wsAnalysisId, {
          type: "analysis-error",
          payload: {
            analysisId: wsAnalysisId,
            buildTargetId: targetInfo?.id,
            executionId: wsAnalysisId,
            phase: "quick",
            error: "Quick graph context missing from SAST response",
            retryable: false,
          },
        });
        throw new Error("Quick graph context missing from SAST response");
      }

      {
        const kbProjectId = targetInfo ? `${projectId}:${targetInfo.name}` : projectId;
        this.analysisTracker?.update(wsAnalysisId, {
          phase: "quick_graphing",
          message: `${prefix}Quick 그래프 컨텍스트 적재 중...`,
          processedFiles: files.length,
        });
        this.broadcast(wsAnalysisId, {
          type: "analysis-progress",
          payload: {
            analysisId: wsAnalysisId,
            buildTargetId: targetInfo?.id,
            executionId: wsAnalysisId,
            phase: "quick_graphing",
            message: `${prefix}Quick 그래프 컨텍스트 적재 중...`,
            targetName: targetInfo?.name,
            targetProgress: targetInfo?.progress,
          },
        });

        const ingestResult = await this.kbClient.ingestCodeGraph(
          kbProjectId,
          sastResponse.codeGraph,
          requestId,
          signal,
        );

        graphContext = this.buildGraphContext(kbProjectId, ingestResult);

        if (!this.kbClient.isGraphReady(ingestResult)) {
          logger.warn({
            analysisId,
            projectId,
            kbProjectId,
            status: ingestResult.status,
            readiness: ingestResult.readiness,
            warnings: ingestResult.warnings,
            requestId,
          }, "Quick graph ingest did not reach GraphRAG-ready state");

          this.broadcast(wsAnalysisId, {
            type: "analysis-error",
            payload: {
              analysisId: wsAnalysisId,
              buildTargetId: targetInfo?.id,
              executionId: wsAnalysisId,
              phase: "quick",
              error: ingestResult.error
                ?? `Quick graph context not ready (${ingestResult.status ?? "unknown"})`,
              retryable: true,
            },
          });
          throw new Error(
            ingestResult.error
            ?? `Quick graph context not ready (${ingestResult.status ?? "unknown"})`,
          );
        }
      }

      const quickResult = this.buildQuickResult(
        analysisId,
        projectId,
        sastResponse,
        startedAt,
        scaLibraries,
        targetInfo?.id,
        wsAnalysisId,
      );
      this.analysisResultDAO.save(quickResult);
      this.resultNormalizer.normalizeAnalysisResult(quickResult, { startedAt });
      await this.analysisExecutionDAO?.update(wsAnalysisId, {
        quickGraphRagStatus: "succeeded",
      });
      this.analysisTracker?.update(wsAnalysisId, {
        phase: "quick_complete",
        message: `${prefix}Quick 분석 완료`,
        processedFiles: files.length,
      });

      this.broadcast(wsAnalysisId, {
        type: "analysis-quick-complete",
        payload: {
          analysisId: wsAnalysisId,
          buildTargetId: targetInfo?.id,
          executionId: wsAnalysisId,
          findingCount: sastResponse.stats.findingsTotal,
        },
      });

      logger.info({
        analysisId, findingsTotal: sastResponse.stats.findingsTotal,
        target: targetInfo?.name, requestId,
      }, "Quick phase completed");
    } catch (err) {
      await this.analysisExecutionDAO?.update(wsAnalysisId, quickSastSucceeded
        ? {
            quickGraphRagStatus: "failed",
            status: "failed",
          }
        : {
            quickGraphRagStatus: "failed",
            quickSastStatus: "failed",
            status: "failed",
          });
      logger.error({ err, analysisId, target: targetInfo?.name, requestId }, "Quick phase failed");
      this.analysisTracker?.update(wsAnalysisId, {
        phase: "quick_sast",
        message: `${prefix}Quick 분석 실패`,
      });
      this.broadcast(wsAnalysisId, {
        type: "analysis-error",
        payload: {
          analysisId: wsAnalysisId,
          buildTargetId: targetInfo?.id,
          executionId: wsAnalysisId,
          phase: "quick",
          error: err instanceof Error ? err.message : "SAST scan failed",
          retryable: true,
        },
      });
      throw err;
    }

    if (quickOnly || signal?.aborted) return;

    // ── Phase Deep: S3 Agent ──
    this.analysisTracker?.update(wsAnalysisId, {
      phase: "deep_submitting",
      message: `${prefix}심층 분석 에이전트 호출 중...`,
      totalFiles: files.length,
      processedFiles: files.length,
    });
    this.broadcast(wsAnalysisId, {
      type: "analysis-progress",
      payload: {
        analysisId: wsAnalysisId,
        buildTargetId: targetInfo?.id,
        executionId: wsAnalysisId,
        phase: "deep_submitting",
        message: `${prefix}심층 분석 에이전트 호출 중...`,
        targetName: targetInfo?.name,
        targetProgress: targetInfo?.progress,
      },
    });

    try {
      const evidenceRefs: AgentEvidenceRef[] = [{
        refId: "eref-project-source",
        artifactId: projectId,
        artifactType: "raw-source",
        locatorType: "lineRange",
        locator: { projectPath: scanPath, fileCount: files.length },
      }];

      const agentRequest: AgentTaskRequest = {
        taskType: "deep-analyze",
        taskId: `deep-${analysisId}`,
        context: {
          trusted: {
            objective: `${projectId} 보안 취약점 심층 분석${targetInfo ? ` (${targetInfo.name})` : ""}`,
            projectId,
            projectPath: scanPath,
            targetPath: targetInfo?.relativePath,
            buildProfile,
            sastFindings,
            codeGraphSummary,
            scaLibraries,
            quickContext: {
              analysisId,
              findingCount: sastFindings.length,
              sastFindings,
              scaLibraries,
            },
            ...(graphContext ? { graphContext } : {}),
            thirdPartyPaths,
          },
        },
        evidenceRefs,
        constraints: { maxTokens: 4096, timeoutMs: 300000 },
      };

      this.analysisTracker?.update(wsAnalysisId, {
        phase: "deep_analyzing",
        message: `${prefix}에이전트가 분석 중... (SAST + 코드그래프 + SCA + LLM)`,
      });
      this.broadcast(wsAnalysisId, {
        type: "analysis-progress",
        payload: {
          analysisId: wsAnalysisId,
          buildTargetId: targetInfo?.id,
          executionId: wsAnalysisId,
          phase: "deep_analyzing",
          message: `${prefix}에이전트가 분석 중... (SAST + 코드그래프 + SCA + LLM)`,
          targetName: targetInfo?.name,
          targetProgress: targetInfo?.progress,
        },
      });

      let agentResponse = await this.agentClient.submitTask(agentRequest, requestId, signal);

      // 재시도: retryable 실패 시 1회 자동 재시도
      if (!this.agentClient.isSuccess(agentResponse) && agentResponse.retryable && !signal?.aborted) {
        logger.info({
          analysisId, failureCode: agentResponse.failureCode,
          target: targetInfo?.name, requestId,
        }, "Retryable failure, attempting retry (1/1)");
        this.analysisTracker?.update(wsAnalysisId, {
          phase: "deep_analyzing",
          message: `${prefix}재시도 중...`,
        });

        this.broadcast(wsAnalysisId, {
          type: "analysis-progress",
          payload: {
            analysisId: wsAnalysisId,
            buildTargetId: targetInfo?.id,
            executionId: wsAnalysisId,
            phase: "deep_retrying",
            message: `${prefix}재시도 중...`,
            targetName: targetInfo?.name,
          },
        });

        agentResponse = await this.agentClient.submitTask(agentRequest, requestId, signal);
      }

      if (this.agentClient.isSuccess(agentResponse)) {
        const deepResult = this.buildDeepResult(
          `deep-${analysisId}`,
          projectId,
          agentResponse,
          startedAt,
          scaLibraries,
          targetInfo?.id,
          wsAnalysisId,
        );
        this.analysisResultDAO.save(deepResult);

        const ctx: NormalizerContext = { startedAt, agentEvidenceRefs: evidenceRefs };
        this.resultNormalizer.normalizeAgentResult(deepResult, agentResponse, ctx);
        const cleanPass = this.isCleanDeepPass(agentResponse);
        this.analysisTracker?.update(wsAnalysisId, {
          phase: "deep_complete",
          message: cleanPass ? `${prefix}심층 분석 완료` : `${prefix}심층 분석 완료 — 결과 품질/검토 상태 확인 필요`,
        });

        this.broadcast(wsAnalysisId, {
          type: "analysis-deep-complete",
          payload: {
            analysisId: wsAnalysisId,
            buildTargetId: targetInfo?.id,
            executionId: wsAnalysisId,
            findingCount: agentResponse.result.claims.length,
            analysisOutcome: deepResult.analysisOutcome,
            qualityOutcome: deepResult.qualityOutcome,
            pocOutcome: deepResult.pocOutcome,
            cleanPass,
          },
        });

        logger.info({
          analysisId, claimCount: agentResponse.result.claims.length,
          analysisOutcome: deepResult.analysisOutcome,
          qualityOutcome: deepResult.qualityOutcome,
          pocOutcome: deepResult.pocOutcome,
          cleanPass,
          confidence: agentResponse.result.confidence,
          target: targetInfo?.name, requestId,
        }, "Deep phase completed");
      } else {
        const isPartialFailure = agentResponse.failureCode?.startsWith("llm_failure_partial");
        const failedResult: AnalysisResult = {
          id: `deep-${analysisId}`,
          projectId,
          buildTargetId: targetInfo?.id,
          analysisExecutionId: wsAnalysisId,
          module: "deep_analysis",
          status: "failed",
          vulnerabilities: [],
          summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          warnings: [
            { code: agentResponse.failureCode, message: agentResponse.failureDetail },
            ...(isPartialFailure ? [{ code: "PARTIAL_FAILURE", message: "LLM 실패로 부분 결과만 생성됨 (도구 결과 기반)" }] : []),
          ],
          createdAt: startedAt,
        };
        this.analysisResultDAO.save(failedResult);
        this.analysisTracker?.update(wsAnalysisId, {
          phase: "deep_analyzing",
          message: `${prefix}심층 분석 실패`,
        });

        this.broadcast(wsAnalysisId, {
          type: "analysis-error",
          payload: {
            analysisId: wsAnalysisId,
            buildTargetId: targetInfo?.id,
            executionId: wsAnalysisId,
            phase: "deep",
            error: `[${agentResponse.failureCode}] ${agentResponse.failureDetail}`,
            retryable: agentResponse.retryable ?? false,
            partial: isPartialFailure,
          },
        });

        logger.warn({
          analysisId, failureCode: agentResponse.failureCode,
          partial: isPartialFailure,
          target: targetInfo?.name, requestId,
        }, "Deep phase failed: %s", agentResponse.failureDetail);
        throw new Error(`[${agentResponse.failureCode}] ${agentResponse.failureDetail}`);
      }
    } catch (err) {
      logger.error({ err, analysisId, target: targetInfo?.name, requestId }, "Deep phase error");
      this.analysisTracker?.update(wsAnalysisId, {
        phase: "deep_analyzing",
        message: `${prefix}심층 분석 실패`,
      });
      this.broadcast(wsAnalysisId, {
        type: "analysis-error",
        payload: {
          analysisId: wsAnalysisId,
          buildTargetId: targetInfo?.id,
          executionId: wsAnalysisId,
          phase: "deep",
          error: err instanceof Error ? err.message : "Agent call failed",
          retryable: true,
        },
      });
      throw err;
    }
  }

  private buildQuickResult(
    analysisId: string,
    projectId: string,
    sastResponse: SastScanResponse,
    startedAt: string,
    scaLibraries?: unknown,
    buildTargetId?: string,
    analysisExecutionId?: string,
  ): AnalysisResult {
    const vulns: Vulnerability[] = sastResponse.findings.map((f, i) => ({
      id: `VULN-SAST-${Date.now()}-${i}`,
      severity: this.normalizeSastSeverity(f.severity),
      title: f.message.length > 120 ? f.message.slice(0, 117) + "..." : f.message,
      description: `[${f.toolId}] ${f.message}`,
      location: `${f.location.file}:${f.location.line}`,
      source: "rule" as const,
      ruleId: f.ruleId,
      cweId: (f.metadata?.cweId as string) ?? undefined,
    }));

    const summary = this.computeSummary(vulns);

    return {
      id: analysisId,
      projectId,
      buildTargetId,
      analysisExecutionId,
      module: "static_analysis",
      status: "completed",
      vulnerabilities: vulns,
      summary,
      scaLibraries: Array.isArray(scaLibraries) ? scaLibraries : undefined,
      createdAt: startedAt,
    };
  }

  private buildDeepResult(
    deepId: string,
    projectId: string,
    agentResponse: AgentResponseSuccess,
    startedAt: string,
    scaLibraries?: unknown,
    buildTargetId?: string,
    analysisExecutionId?: string,
  ): AnalysisResult {
    const assessment = agentResponse.result;
    const audit = agentResponse.audit;
    const severity = this.validateSeverity(assessment.suggestedSeverity);
    const analysisOutcome = assessment.analysisOutcome ?? (assessment.claims.length > 0 ? "accepted_claims" : "no_accepted_claims");
    const qualityOutcome = assessment.qualityOutcome ?? (assessment.caveats?.length ? "accepted_with_caveats" : "accepted");
    const pocOutcome = assessment.pocOutcome ?? "poc_not_requested";
    const cleanPass = this.isCleanDeepPass(agentResponse);

    const vulns: Vulnerability[] = assessment.claims.map((claim, i) => ({
      id: `VULN-AGENT-${Date.now()}-${i}`,
      severity,
      title: this.extractTitle(claim.statement),
      description: claim.statement,
      location: claim.location ?? undefined,
      source: "llm" as const,
      suggestion: assessment.recommendedNextSteps?.join("\n"),
      detail: claim.detail ?? undefined,
      cweId: assessment.policyFlags?.find((f: string) => /^CWE-\d+$/.test(f)) ?? undefined,
    }));

    const summary = this.computeSummary(vulns);

    return {
      id: deepId,
      projectId,
      buildTargetId,
      analysisExecutionId,
      module: "deep_analysis",
      status: "completed",
      vulnerabilities: vulns,
      summary,
      warnings: this.buildOutcomeWarnings(analysisOutcome, qualityOutcome, pocOutcome),
      caveats: assessment.caveats,
      confidenceScore: assessment.confidence,
      confidenceBreakdown: assessment.confidenceBreakdown,
      needsHumanReview: assessment.needsHumanReview || !cleanPass,
      recommendedNextSteps: assessment.recommendedNextSteps,
      policyFlags: assessment.policyFlags,
      analysisOutcome,
      qualityOutcome,
      pocOutcome,
      recoveryTrace: assessment.recoveryTrace,
      claimDiagnostics: assessment.claimDiagnostics,
      evidenceDiagnostics: assessment.evidenceDiagnostics,
      scaLibraries: Array.isArray(scaLibraries) ? scaLibraries : undefined,
      agentAudit: {
        latencyMs: audit.latencyMs,
        tokenUsage: audit.tokenUsage,
        turnCount: audit.agentAudit?.turn_count,
        toolCallCount: audit.agentAudit?.tool_call_count,
        terminationReason: audit.agentAudit?.termination_reason,
        modelName: agentResponse.modelProfile,
        promptVersion: agentResponse.promptVersion,
      },
      createdAt: startedAt,
    };
  }

  private isCleanDeepPass(agentResponse: AgentResponseSuccess): boolean {
    const assessment = agentResponse.result;
    const analysisOutcome = assessment.analysisOutcome ?? (assessment.claims.length > 0 ? "accepted_claims" : "no_accepted_claims");
    const qualityOutcome = assessment.qualityOutcome ?? (assessment.caveats?.length ? "accepted_with_caveats" : "accepted");
    return agentResponse.status === "completed"
      && analysisOutcome === "accepted_claims"
      && qualityOutcome === "accepted";
  }

  private buildOutcomeWarnings(
    analysisOutcome: NonNullable<AnalysisResult["analysisOutcome"]>,
    qualityOutcome: NonNullable<AnalysisResult["qualityOutcome"]>,
    pocOutcome: NonNullable<AnalysisResult["pocOutcome"]>,
  ): AnalysisResult["warnings"] {
    const warnings: NonNullable<AnalysisResult["warnings"]> = [];
    if (analysisOutcome !== "accepted_claims") {
      warnings.push({
        code: `AGENT_ANALYSIS_OUTCOME_${analysisOutcome.toUpperCase()}`,
        message: `S3 completed the task with analysisOutcome=${analysisOutcome}; this is not a clean deep pass.`,
      });
    }
    if (qualityOutcome !== "accepted") {
      warnings.push({
        code: `AGENT_QUALITY_OUTCOME_${qualityOutcome.toUpperCase()}`,
        message: `S3 completed the task with qualityOutcome=${qualityOutcome}; quality gate/UX must not treat completion as clean pass.`,
      });
    }
    if (pocOutcome !== "poc_not_requested" && pocOutcome !== "poc_accepted") {
      warnings.push({
        code: `AGENT_POC_OUTCOME_${pocOutcome.toUpperCase()}`,
        message: `S3 completed the task with pocOutcome=${pocOutcome}; PoC was not cleanly accepted.`,
      });
    }
    return warnings;
  }

  private normalizeSastSeverity(toolSeverity: string): Severity {
    const lower = toolSeverity.toLowerCase();
    if (lower === "error" || lower === "critical") return "critical";
    if (lower === "warning" || lower === "high") return "high";
    if (lower === "style" || lower === "medium") return "medium";
    if (lower === "info" || lower === "low") return "low";
    return "medium";
  }

  private validateSeverity(severity?: string | null): Severity {
    const valid = new Set(["critical", "high", "medium", "low", "info"]);
    if (severity && valid.has(severity)) return severity as Severity;
    return "medium";
  }

  private extractTitle(statement: string): string {
    const firstSentence = statement.split(/[.。]/)[0] ?? statement;
    return firstSentence.length > 120
      ? firstSentence.slice(0, 117) + "..."
      : firstSentence;
  }

  private computeSummary(vulns: Vulnerability[]): AnalysisSummary {
    const summary: AnalysisSummary = { total: vulns.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulns) summary[v.severity]++;
    return summary;
  }

  private broadcast(analysisId: string, msg: WsAnalysisMessage): void {
    this.ws?.broadcast(analysisId, msg);
  }

  private buildGraphContext(
    kbProjectId: string,
    ingestResult: CodeGraphIngestResponse,
  ): Record<string, unknown> {
    return {
      kbProjectId,
      status: ingestResult.status ?? "ready",
      readiness: ingestResult.readiness,
      replaceMode: ingestResult.replaceMode,
      operation: ingestResult.operation,
      nodesCreated: this.kbClient.getIngestNodeCount(ingestResult),
      edgesCreated: this.kbClient.getIngestEdgeCount(ingestResult),
      warnings: ingestResult.warnings,
    };
  }

  private async prepareExecutionForQuick(
    projectId: string,
    executionId: string,
    target: BuildTarget,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<void> {
    if (!this.analysisExecutionDAO) {
      await this.pipelineOrchestrator?.preparePipeline(projectId, [target.id], requestId, signal, `prep-${executionId}`);
      return;
    }

    const existingActive = this.analysisExecutionDAO?.findActiveByBuildTargetId(target.id);
    if (existingActive && existingActive.id !== executionId) {
      await this.analysisExecutionDAO.update(existingActive.id, {
        status: "superseded",
        supersededByExecutionId: executionId,
      });
    }

    const now = new Date().toISOString();
    if (!this.analysisExecutionDAO?.findById(executionId)) {
      const execution: AnalysisExecution = {
        id: executionId,
        projectId,
        buildTargetId: target.id,
        buildTargetName: target.name,
        buildTargetRelativePath: target.relativePath,
        buildProfileSnapshot: target.buildProfile,
        sdkChoiceState: target.sdkChoiceState,
        status: "active",
        quickBuildPrepStatus: "running",
        quickGraphRagStatus: "pending",
        quickSastStatus: "pending",
        deepStatus: "pending",
        createdAt: now,
        updatedAt: now,
      };
      this.analysisExecutionDAO.save(execution);
    } else {
      await this.analysisExecutionDAO.update(executionId, {
        sdkChoiceState: target.sdkChoiceState,
        status: "active",
        quickBuildPrepStatus: "running",
        quickGraphRagStatus: "pending",
        quickSastStatus: "pending",
        deepStatus: "pending",
      });
    }

    await this.pipelineOrchestrator?.preparePipeline(projectId, [target.id], requestId, signal, `prep-${executionId}`);
  }

  preflightQuickRequest(projectId: string, buildTargetId: string): BuildTarget {
    const projectPath = this.sourceService.getProjectPath(projectId);
    if (!projectPath) {
      throw new NotFoundError(`Project source not found. Upload source first: ${projectId}`);
    }

    const target = this.resolveBuildTarget(projectId, buildTargetId);
    if (target.sdkChoiceState === "sdk-unresolved") {
      throw new InvalidInputError(`BuildTarget ${target.name} is not Quick-eligible until SDK choice is explicit`);
    }
    return target;
  }

  preflightDeepRequest(
    projectId: string,
    buildTargetId: string,
    executionId: string,
  ): { projectPath: string; quickResult: AnalysisResult; target?: BuildTarget } {
    const projectPath = this.sourceService.getProjectPath(projectId);
    if (!projectPath) {
      throw new NotFoundError(`Project source not found. Upload source first: ${projectId}`);
    }

    const execution = this.analysisExecutionDAO?.findById(executionId);
    if (!execution || execution.projectId !== projectId) {
      throw new NotFoundError(`AnalysisExecution not found: ${executionId}`);
    }
    if (execution.buildTargetId !== buildTargetId) {
      throw new InvalidInputError(`AnalysisExecution ${executionId} does not belong to BuildTarget ${buildTargetId}`);
    }
    if (execution.status !== "active") {
      throw new InvalidInputError(`AnalysisExecution is not active: ${executionId}`);
    }
    if (
      execution.quickBuildPrepStatus !== "succeeded"
      || execution.quickGraphRagStatus !== "succeeded"
      || execution.quickSastStatus !== "succeeded"
    ) {
      throw new InvalidInputError(`Deep requires a Quick-complete AnalysisExecution: ${executionId}`);
    }

    const { quickResult, target } = this.resolveQuickExecutionContext(projectId, execution, buildTargetId);
    if (
      (quickResult.buildTargetId && quickResult.buildTargetId !== buildTargetId)
      || (target?.id && target.id !== buildTargetId)
    ) {
      throw new InvalidInputError(`AnalysisExecution ${executionId} does not belong to BuildTarget ${buildTargetId}`);
    }

    return { projectPath, quickResult, ...(target ? { target } : {}) };
  }

  private resolveQuickExecutionContext(
    projectId: string,
    execution: AnalysisExecution,
    buildTargetId: string,
  ): { quickResult: AnalysisResult; target?: BuildTarget } {
    const byExecution = this.analysisResultDAO.findByExecutionId?.(execution.id, "static_analysis")?.[0];
    if (byExecution && byExecution.projectId === projectId) {
      const target = this.buildTargetService?.findById?.(buildTargetId)
        ?? this.buildTargetService?.findByProjectId(projectId)?.find((candidate) => candidate.id === buildTargetId);
      return { quickResult: byExecution, ...(target ? { target } : {}) };
    }
    throw new NotFoundError(`Quick analysis result not found for AnalysisExecution ${execution.id}`);
  }

  private resolveBuildTarget(projectId: string, buildTargetId: string): BuildTarget {
    if (!buildTargetId) {
      throw new InvalidInputError("buildTargetId is required");
    }
    const target = this.buildTargetService?.findById?.(buildTargetId)
      ?? this.buildTargetService?.findByProjectId(projectId)?.find((candidate) => candidate.id === buildTargetId);
    if (!target || target.projectId !== projectId) {
      throw new NotFoundError(`BuildTarget not found: ${buildTargetId}`);
    }
    return target;
  }
}
