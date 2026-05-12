import { describe, expect, it, vi } from "vitest";
import { AnalysisOrchestrator } from "../analysis-orchestrator";
import { InvalidInputError } from "../../lib/errors";
import { createTestDb } from "../../test/test-db";
import { AnalysisExecutionDAO } from "../../dao/analysis-execution.dao";

describe("AnalysisOrchestrator", () => {
  const withKbContractCounters = <T extends Record<string, unknown>>(client: T) => ({
    getIngestNodeCount: vi.fn((response: any) => response?.nodeCount ?? response?.nodes_created ?? 0),
    getIngestEdgeCount: vi.fn((response: any) => response?.edgeCount ?? response?.edges_created ?? 0),
    getStatsFunctionCount: vi.fn((response: any) => response?.nodeCount ?? response?.function_count ?? 0),
    getStatsCallEdgeCount: vi.fn((response: any) => response?.edgeCount ?? response?.call_edge_count ?? 0),
    ...client,
  });

  it("quick execution keeps root executionId in WS while target-scoped result ids stay distinct", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(async () => ({
        success: true,
        scanId: "scan-1",
        status: "completed",
        findings: [],
        stats: { filesScanned: 1, rulesRun: 0, findingsTotal: 0, elapsedMs: 1 },
        execution: { toolsRun: [], toolResults: {} },
        codeGraph: { functions: [{ name: "main", file: "src/main.c", line: 1 }], callEdges: [] },
        sca: null,
      })),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(async () => ({
        success: true,
        project_id: "project-1:gateway",
        nodes_created: 1,
        edges_created: 0,
        elapsed_ms: 1,
        status: "ready",
        readiness: { graphRag: true },
      })),
      isGraphReady: vi.fn(() => true),
    });
    const agentClient = {
      submitTask: vi.fn(async () => ({
        result: {
          claims: [],
          confidence: 0.9,
        },
        audit: { latencyMs: 1 },
      })),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = {
      save: vi.fn(),
    };
    const settingsService = {
      getAll: vi.fn(() => ({})),
    };
    const resultNormalizer = {
      normalizeAnalysisResult: vi.fn(),
      normalizeAgentResult: vi.fn(),
    };
    const ws = {
      broadcast: vi.fn(),
    };
    const buildTargetService = {
      findById: vi.fn(() => ({
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
        buildProfile: { sdkId: "sdk-gateway", compiler: "arm-none-eabi-gcc", targetArch: "armv7-a", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      })),
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
        buildProfile: { sdkId: "sdk-default", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
    };
    const targetLibraryDAO = {
      getIncludedPaths: vi.fn(() => []),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      buildTargetService as any,
      targetLibraryDAO as any,
    );

    await orchestrator.runQuickAnalysis("project-1", "analysis-root", ["target-1"], "req-1");

    expect(sastClient.scan).toHaveBeenCalledWith(
      expect.objectContaining({
        compileCommands: "/tmp/project/gateway/compile_commands.json",
      }),
      "req-1",
      undefined,
    );

    expect(ws.broadcast).toHaveBeenCalled();
    for (const [broadcastKey, message] of ws.broadcast.mock.calls) {
      expect(broadcastKey).toBe("analysis-root");
      expect(message.payload.analysisId).toBe("analysis-root");
      expect(message.payload.buildTargetId).toBe("target-1");
      expect(message.payload.executionId).toBe("analysis-root");
    }

    expect(agentClient.submitTask).not.toHaveBeenCalled();
    expect(analysisResultDAO.save).toHaveBeenCalledOnce();
    expect(analysisResultDAO.save).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ id: "analysis-root-gateway", projectId: "project-1", module: "static_analysis" }),
    );
  });

  it("quick execution uses S4 non-registered SDK descriptor from pipeline profile builder", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "gateway/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(async () => ({
        success: true,
        scanId: "scan-1",
        status: "completed",
        findings: [],
        stats: { filesScanned: 1, rulesRun: 0, findingsTotal: 0, elapsedMs: 1 },
        execution: { toolsRun: [], toolResults: {} },
        codeGraph: { functions: [{ name: "main", file: "gateway/main.c", line: 1, calls: [] }], callEdges: [] },
        sca: null,
      })),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(async () => ({
        project_id: "project-1:gateway",
        nodeCount: 1,
        edgeCount: 0,
        status: "ready",
        readiness: { graphRag: true },
      })),
      isGraphReady: vi.fn(() => true),
    });
    const target = {
      id: "target-1",
      projectId: "project-1",
      name: "gateway",
      relativePath: "gateway/",
      compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
      buildProfile: { sdkId: "sdk-uploaded", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
      sdkChoiceState: "sdk-selected",
    };
    const pipelineOrchestrator = {
      preparePipeline: vi.fn(async () => undefined),
      buildSastScanProfile: vi.fn(() => ({
        compiler: "gcc",
        targetArch: "arm",
        languageStandard: "c11",
        headerLanguage: "c",
        sdkResolutionMode: "non-registered",
        sdkDescriptor: { sdkRootPath: "/tmp/project/sdk/sdk-uploaded/content" },
      })),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      { submitTask: vi.fn(), isSuccess: vi.fn(() => true) } as any,
      { save: vi.fn() } as any,
      { getAll: vi.fn(() => ({})) } as any,
      { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() } as any,
      undefined,
      { findByProjectId: vi.fn(() => [target]) } as any,
      { getIncludedPaths: vi.fn(() => []) } as any,
      undefined,
      undefined,
      pipelineOrchestrator as any,
    );

    await orchestrator.runQuickAnalysis("project-1", "analysis-1", ["target-1"], "req-1");

    expect(pipelineOrchestrator.buildSastScanProfile).toHaveBeenCalledWith("project-1", target);
    expect(sastClient.scan).toHaveBeenCalledWith(
      expect.objectContaining({
        buildProfile: expect.objectContaining({
          sdkResolutionMode: "non-registered",
          sdkDescriptor: expect.objectContaining({ sdkRootPath: "/tmp/project/sdk/sdk-uploaded/content" }),
        }),
      }),
      "req-1",
      undefined,
    );
    const scanRequest = (sastClient.scan as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as any;
    expect(scanRequest.buildProfile).not.toHaveProperty("sdkId");
  });

  it("stops after quick phase when S4 returns failed scan response", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(async () => ({
        success: false,
        scanId: "scan-omission",
        status: "failed",
        findings: [],
        stats: { filesScanned: 0, rulesRun: 0, findingsTotal: 0, elapsedMs: 0 },
        execution: { toolsRun: [], toolResults: {} },
        error: "Disallowed tool omission",
        errorDetail: { code: "DISALLOWED_TOOL_OMISSION", retryable: false },
      })),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(),
      isGraphReady: vi.fn(() => true),
    });
    const agentClient = {
      submitTask: vi.fn(),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = {
      save: vi.fn(),
    };
    const settingsService = {
      getAll: vi.fn(() => ({})),
    };
    const resultNormalizer = {
      normalizeAnalysisResult: vi.fn(),
      normalizeAgentResult: vi.fn(),
    };
    const ws = {
      broadcast: vi.fn(),
    };
    const buildTargetService = {
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
        buildProfile: { sdkId: "sdk-default", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      buildTargetService as any,
    );

    await expect(orchestrator.runAnalysis("project-1", "analysis-root", ["target-1"], "req-1"))
      .rejects.toThrow(/Disallowed tool omission/);

    expect(agentClient.submitTask).not.toHaveBeenCalled();
    expect(analysisResultDAO.save).not.toHaveBeenCalled();
    expect(ws.broadcast).toHaveBeenCalledWith(
      "analysis-root",
      expect.objectContaining({
        type: "analysis-error",
        payload: expect.objectContaining({
          phase: "quick",
          error: "Disallowed tool omission",
          retryable: false,
        }),
      }),
    );
  });

  it("runAnalysis completes BuildTarget-scoped Quick with GraphRAG-ready ingest without auto-starting Deep", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(async () => ({
        success: true,
        scanId: "scan-1",
        status: "completed",
        findings: [{ ruleId: "CK001", toolId: "cppcheck", severity: "warning", message: "Null pointer", location: { file: "src/main.c", line: 10 } }],
        stats: { filesScanned: 1, rulesRun: 1, findingsTotal: 1, elapsedMs: 1 },
        execution: { toolsRun: [], toolResults: {} },
        codeGraph: {
          functions: [{ name: "main", file: "src/main.c", line: 1 }],
          callEdges: [],
        },
        sca: { libraries: [{ name: "openssl", version: "1.1.1", path: "vendor/openssl" }] },
      })),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(async () => ({
        success: true,
        project_id: "project-1",
        nodes_created: 4,
        edges_created: 2,
        elapsed_ms: 3,
        status: "ready",
        readiness: { graphRag: true, neo4jGraph: true, vectorIndex: true },
      })),
      isGraphReady: vi.fn(() => true),
    });
    const agentClient = {
      submitTask: vi.fn(async () => ({
        status: "completed",
        result: {
          claims: [],
          confidence: 0.9,
          caveats: [],
          recommendedNextSteps: [],
          policyFlags: [],
          confidenceBreakdown: { grounding: 1, deterministicSupport: 1, ragCoverage: 1, schemaCompliance: 1 },
          needsHumanReview: false,
        },
        audit: { latencyMs: 1 },
      })),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = { save: vi.fn() };
    const settingsService = { getAll: vi.fn(() => ({})) };
    const resultNormalizer = { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() };
    const ws = { broadcast: vi.fn() };
    const buildTargetService = {
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
        buildProfile: { sdkId: "sdk-default", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      buildTargetService as any,
    );

    await orchestrator.runAnalysis("project-1", "analysis-1", ["target-1"], "req-1");

    expect(kbClient.ingestCodeGraph).toHaveBeenCalledOnce();
    expect(agentClient.submitTask).not.toHaveBeenCalled();
    expect(analysisResultDAO.save).toHaveBeenCalledOnce();
    expect(ws.broadcast).toHaveBeenCalledWith(
      "analysis-1",
      expect.objectContaining({
        type: "analysis-quick-complete",
        payload: expect.objectContaining({
          analysisId: "analysis-1",
          buildTargetId: "target-1",
          executionId: "analysis-1",
          findingCount: 1,
        }),
      }),
    );
  });

  it("stops after quick phase when GraphRAG ingest is not ready", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(async () => ({
        success: true,
        scanId: "scan-1",
        status: "completed",
        findings: [],
        stats: { filesScanned: 1, rulesRun: 0, findingsTotal: 0, elapsedMs: 1 },
        execution: { toolsRun: [], toolResults: {} },
        codeGraph: { functions: [{ name: "main", file: "src/main.c", line: 1 }], callEdges: [] },
        sca: null,
      })),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(async () => ({
        success: true,
        project_id: "project-1",
        nodes_created: 1,
        edges_created: 0,
        elapsed_ms: 1,
        status: "partial",
        readiness: { graphRag: false, neo4jGraph: true, vectorIndex: false },
        warnings: ["VECTOR_INDEX_INCOMPLETE"],
      })),
      isGraphReady: vi.fn(() => false),
    });
    const agentClient = {
      submitTask: vi.fn(),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = { save: vi.fn() };
    const settingsService = { getAll: vi.fn(() => ({})) };
    const resultNormalizer = { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() };
    const ws = { broadcast: vi.fn() };
    const buildTargetService = {
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
        buildProfile: { sdkId: "sdk-default", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      buildTargetService as any,
    );

    await expect(orchestrator.runAnalysis("project-1", "analysis-1", ["target-1"], "req-1"))
      .rejects.toThrow(/Quick graph context not ready/);

    expect(agentClient.submitTask).not.toHaveBeenCalled();
    expect(ws.broadcast).toHaveBeenCalledWith(
      "analysis-1",
      expect.objectContaining({
        type: "analysis-error",
        payload: expect.objectContaining({
          phase: "quick",
          error: expect.stringContaining("Quick graph context not ready"),
        }),
      }),
    );
  });

  it("runQuickAnalysis completes Quick without invoking Deep", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(async () => ({
        success: true,
        scanId: "scan-1",
        status: "completed",
        findings: [],
        stats: { filesScanned: 1, rulesRun: 0, findingsTotal: 0, elapsedMs: 1 },
        execution: { toolsRun: [], toolResults: {} },
        codeGraph: { functions: [{ name: "main", file: "src/main.c", line: 1 }], callEdges: [] },
        sca: null,
      })),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(async () => ({
        success: true,
        project_id: "project-1:gateway",
        nodes_created: 1,
        edges_created: 0,
        elapsed_ms: 1,
        status: "ready",
        readiness: { graphRag: true },
      })),
      isGraphReady: vi.fn(() => true),
      getCodeGraphStats: vi.fn(),
    });
    const agentClient = {
      submitTask: vi.fn(),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = { save: vi.fn() };
    const settingsService = { getAll: vi.fn(() => ({})) };
    const resultNormalizer = { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() };
    const ws = { broadcast: vi.fn() };
    const buildTargetService = {
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
        buildProfile: { sdkId: "sdk-default", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      buildTargetService as any,
    );

    await orchestrator.runQuickAnalysis("project-1", "analysis-1", ["target-1"], "req-1");

    expect(agentClient.submitTask).not.toHaveBeenCalled();
    expect(analysisResultDAO.save).toHaveBeenCalledOnce();
    expect(kbClient.ingestCodeGraph).toHaveBeenCalledOnce();
    expect(ws.broadcast).toHaveBeenCalledWith(
      "analysis-1",
      expect.objectContaining({ type: "analysis-quick-complete" }),
    );
  });

  it("runQuickAnalysis with target requires prepared compile_commands", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(),
      isGraphReady: vi.fn(() => true),
      getCodeGraphStats: vi.fn(),
    });
    const agentClient = {
      submitTask: vi.fn(),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = { save: vi.fn() };
    const settingsService = { getAll: vi.fn(() => ({})) };
    const resultNormalizer = { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() };
    const ws = { broadcast: vi.fn() };
    const buildTargetService = {
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        buildProfile: { sdkId: "sdk-default", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
    };
    const targetLibraryDAO = { getIncludedPaths: vi.fn(() => []) };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      buildTargetService as any,
      targetLibraryDAO as any,
    );

    await expect(orchestrator.runQuickAnalysis("project-1", "analysis-1", ["target-1"], "req-1"))
      .rejects.toThrow(/compile_commands/);
    expect(sastClient.scan).not.toHaveBeenCalled();
  });

  it("runDeepAnalysis uses prior execution context and KB graph stats", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(),
      isGraphReady: vi.fn(() => true),
      getCodeGraphStats: vi.fn(async () => ({ project_id: "project-1", function_count: 3, call_edge_count: 2 })),
    });
    const agentClient = {
      submitTask: vi.fn(async () => ({
        status: "completed",
        result: {
          claims: [],
          confidence: 0.9,
          caveats: [],
          recommendedNextSteps: [],
          policyFlags: [],
          confidenceBreakdown: { grounding: 1, deterministicSupport: 1, ragCoverage: 1, schemaCompliance: 1 },
          needsHumanReview: false,
        },
        audit: { latencyMs: 1 },
      })),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = {
      save: vi.fn(),
      findByExecutionId: vi.fn((id: string) => id === "analysis-quick-1" ? [{
        id: "analysis-quick-1",
        projectId: "project-1",
        buildTargetId: "target-1",
        analysisExecutionId: "analysis-quick-1",
        module: "static_analysis",
        status: "completed",
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        scaLibraries: [{ name: "openssl", version: "1.1.1" }],
        createdAt: new Date().toISOString(),
      }] : []),
      findById: vi.fn(),
    };
    const settingsService = { getAll: vi.fn(() => ({ buildProfile: { sdkId: "sdk-default" } })) };
    const resultNormalizer = { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() };
    const ws = { broadcast: vi.fn() };
    const analysisExecutionDAO = {
      findById: vi.fn((id: string) => id === "analysis-quick-1" ? {
        id,
        projectId: "project-1",
        buildTargetId: "target-1",
        buildTargetName: "gateway",
        buildTargetRelativePath: "gateway/",
        buildProfileSnapshot: { sdkId: "sdk-default" },
        sdkChoiceState: "sdk-selected",
        status: "active",
        quickBuildPrepStatus: "succeeded",
        quickGraphRagStatus: "succeeded",
        quickSastStatus: "succeeded",
        deepStatus: "pending",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      } : undefined),
      update: vi.fn(),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      undefined,
      undefined,
      undefined,
      analysisExecutionDAO as any,
    );

    await orchestrator.runDeepAnalysis("project-1", "analysis-deep-1", "target-1", "analysis-quick-1", "req-1");

    expect(kbClient.getCodeGraphStats).toHaveBeenCalledWith("project-1", "req-1");
    expect(agentClient.submitTask).toHaveBeenCalledWith(
      expect.objectContaining({
        constraints: { maxTokens: 4096, timeoutMs: 300000 },
        context: {
          trusted: expect.objectContaining({
            quickContext: expect.objectContaining({ executionId: "analysis-quick-1" }),
            graphContext: expect.objectContaining({ kbProjectId: "project-1", functionCount: 3 }),
          }),
        },
      }),
      "req-1",
      undefined,
    );
    expect(ws.broadcast).toHaveBeenCalledWith(
      "analysis-deep-1",
      expect.objectContaining({
        type: "analysis-deep-complete",
        payload: expect.objectContaining({
          analysisId: "analysis-deep-1",
          executionId: "analysis-quick-1",
        }),
      }),
    );
  });

  it("runDeepAnalysis resolves a target-scoped execution result and uses BuildTarget KB scope", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "gateway/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(),
    };
    const kbClient = withKbContractCounters({
      ingestCodeGraph: vi.fn(),
      isGraphReady: vi.fn(() => true),
      getCodeGraphStats: vi.fn(async () => ({ project_id: "project-1:gateway", function_count: 7, call_edge_count: 9 })),
    });
    const agentClient = {
      submitTask: vi.fn(async () => ({
        status: "completed",
        result: {
          claims: [],
          confidence: 0.9,
          caveats: [],
          recommendedNextSteps: [],
          policyFlags: [],
          confidenceBreakdown: { grounding: 1, deterministicSupport: 1, ragCoverage: 1, schemaCompliance: 1 },
          needsHumanReview: false,
        },
        audit: { latencyMs: 1 },
      })),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = {
      save: vi.fn(),
      findByExecutionId: vi.fn((id: string) => id === "analysis-quick-1" ? [{
        id: "analysis-quick-1-gateway",
        projectId: "project-1",
        buildTargetId: "target-1",
        analysisExecutionId: "analysis-quick-1",
        module: "static_analysis",
        status: "completed",
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        scaLibraries: [{ name: "openssl", version: "1.1.1" }],
        createdAt: new Date().toISOString(),
      }] : []),
      findById: vi.fn((id: string) => id === "analysis-quick-1-gateway" ? {
        id,
        projectId: "project-1",
        buildTargetId: "target-1",
        analysisExecutionId: "analysis-quick-1",
        module: "static_analysis",
        status: "completed",
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        scaLibraries: [{ name: "openssl", version: "1.1.1" }],
        createdAt: new Date().toISOString(),
      } : undefined),
    };
    const settingsService = { getAll: vi.fn(() => ({ buildProfile: { sdkId: "sdk-default" } })) };
    const resultNormalizer = { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() };
    const ws = { broadcast: vi.fn() };
    const buildTargetService = {
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        buildProfile: { sdkId: "sdk-gateway", compiler: "arm-none-eabi-gcc", targetArch: "armv7-a", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
      findById: vi.fn((id: string) => id === "target-1" ? {
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        buildProfile: { sdkId: "sdk-gateway", compiler: "arm-none-eabi-gcc", targetArch: "armv7-a", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      } : undefined),
    };
    const analysisExecutionDAO = {
      findById: vi.fn((id: string) => id === "analysis-quick-1" ? {
        id,
        projectId: "project-1",
        buildTargetId: "target-1",
        buildTargetName: "gateway",
        buildTargetRelativePath: "gateway/",
        buildProfileSnapshot: { sdkId: "sdk-gateway" },
        sdkChoiceState: "sdk-selected",
        status: "active",
        quickBuildPrepStatus: "succeeded",
        quickGraphRagStatus: "succeeded",
        quickSastStatus: "succeeded",
        deepStatus: "pending",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      } : undefined),
      update: vi.fn(),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      settingsService as any,
      resultNormalizer as any,
      ws as any,
      buildTargetService as any,
      undefined,
      undefined,
      analysisExecutionDAO as any,
    );

    await orchestrator.runDeepAnalysis("project-1", "analysis-deep-1", "target-1", "analysis-quick-1", "req-1");

    expect(kbClient.getCodeGraphStats).toHaveBeenCalledWith("project-1:gateway", "req-1");
    expect(agentClient.submitTask).toHaveBeenCalledWith(
      expect.objectContaining({
        constraints: { maxTokens: 4096, timeoutMs: 300000 },
        context: {
          trusted: expect.objectContaining({
            objective: "project-1 보안 취약점 심층 분석 (gateway)",
            targetPath: "gateway/",
            buildProfile: expect.objectContaining({ sdkId: "sdk-gateway" }),
            quickContext: expect.objectContaining({
              executionId: "analysis-quick-1",
              kbProjectId: "project-1:gateway",
              targetName: "gateway",
            }),
            graphContext: expect.objectContaining({
              kbProjectId: "project-1:gateway",
              functionCount: 7,
              targetPath: "gateway/",
            }),
          }),
        },
      }),
      "req-1",
      undefined,
    );
  });

  it("runDeepAnalysis rejects BuildTarget / execution lineage mismatches", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "gateway/main.c" }]),
    };
    const kbClient = withKbContractCounters({
      getCodeGraphStats: vi.fn(async () => ({ project_id: "project-1:gateway", function_count: 7, call_edge_count: 9 })),
    });
    const agentClient = {
      submitTask: vi.fn(),
      isSuccess: vi.fn(() => true),
    };
    const analysisResultDAO = {
      findByExecutionId: vi.fn(() => [{
        id: "analysis-quick-1-gateway",
        projectId: "project-1",
        buildTargetId: "target-1",
        analysisExecutionId: "analysis-quick-1",
        module: "static_analysis",
        status: "completed",
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        createdAt: new Date().toISOString(),
      }]),
      findById: vi.fn(),
    };
    const buildTargetService = {
      findByProjectId: vi.fn(() => [{
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        buildProfile: { sdkId: "sdk-gateway", compiler: "arm-none-eabi-gcc", targetArch: "armv7-a", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      }]),
    };
    const analysisExecutionDAO = {
      findById: vi.fn(() => ({
        id: "analysis-quick-1",
        projectId: "project-1",
        buildTargetId: "target-1",
        buildTargetName: "gateway",
        buildTargetRelativePath: "gateway/",
        buildProfileSnapshot: { sdkId: "sdk-gateway" },
        sdkChoiceState: "sdk-selected",
        status: "active",
        quickBuildPrepStatus: "succeeded",
        quickGraphRagStatus: "succeeded",
        quickSastStatus: "succeeded",
        deepStatus: "pending",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      })),
      update: vi.fn(),
    };

    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      {} as any,
      kbClient as any,
      agentClient as any,
      analysisResultDAO as any,
      { getAll: vi.fn(() => ({ buildProfile: { sdkId: "sdk-default" } })) } as any,
      { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() } as any,
      undefined,
      buildTargetService as any,
      undefined,
      undefined,
      analysisExecutionDAO as any,
    );

    await expect(
      orchestrator.runDeepAnalysis("project-1", "analysis-deep-1", "target-2", "analysis-quick-1", "req-1"),
    ).rejects.toBeInstanceOf(InvalidInputError);
    expect(agentClient.submitTask).not.toHaveBeenCalled();
  });

  it("runQuickAnalysis supersedes the prior active execution for the same BuildTarget and preserves history", async () => {
    const db = createTestDb();
    try {
      const target = {
        id: "target-1",
        projectId: "project-1",
        name: "gateway",
        relativePath: "gateway/",
        compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
        buildProfile: { sdkId: "sdk-gateway", compiler: "arm-none-eabi-gcc", targetArch: "armv7-a", languageStandard: "c11", headerLanguage: "c" },
        sdkChoiceState: "sdk-selected",
      };
      const sourceService = {
        getProjectPath: vi.fn(() => "/tmp/project"),
        listFiles: vi.fn(() => [{ relativePath: "gateway/main.c" }]),
      };
      const sastClient = {
        scan: vi.fn(async () => ({
          success: true,
          scanId: "scan-1",
          status: "completed",
          findings: [],
          stats: { filesScanned: 1, rulesRun: 0, findingsTotal: 0, elapsedMs: 1 },
          execution: { toolsRun: [], toolResults: {} },
          codeGraph: { functions: [{ name: "main", file: "gateway/main.c", line: 1 }], callEdges: [] },
          sca: null,
        })),
      };
      const orchestrator = new AnalysisOrchestrator(
        sourceService as any,
        sastClient as any,
        withKbContractCounters({ ingestCodeGraph: vi.fn(async () => ({ status: "ready", readiness: { graphRag: true } })), isGraphReady: vi.fn(() => true) }) as any,
        { submitTask: vi.fn(), isSuccess: vi.fn(() => true) } as any,
        { save: vi.fn() } as any,
        { getAll: vi.fn(() => ({ buildProfile: target.buildProfile })) } as any,
        { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() } as any,
        undefined,
        {
          findById: vi.fn(() => target),
          findByProjectId: vi.fn(() => [target]),
        } as any,
        { getIncludedPaths: vi.fn(() => []) } as any,
        undefined,
        new AnalysisExecutionDAO(db),
      );

      await orchestrator.runQuickAnalysis("project-1", "exec-1", ["target-1"], "req-1");
      await orchestrator.runQuickAnalysis("project-1", "exec-2", ["target-1"], "req-2");

      const executionDao = (orchestrator as any).analysisExecutionDAO as AnalysisExecutionDAO;
      const first = executionDao.findById("exec-1");
      const second = executionDao.findById("exec-2");

      expect(first).toMatchObject({
        id: "exec-1",
        status: "superseded",
        supersededByExecutionId: "exec-2",
        buildTargetId: "target-1",
        quickBuildPrepStatus: "succeeded",
        quickSastStatus: "succeeded",
        quickGraphRagStatus: "succeeded",
      });
      expect(second).toMatchObject({
        id: "exec-2",
        status: "active",
        buildTargetId: "target-1",
        quickBuildPrepStatus: "succeeded",
        quickSastStatus: "succeeded",
        quickGraphRagStatus: "succeeded",
      });
      expect(executionDao.findActiveByBuildTargetId("target-1")?.id).toBe("exec-2");
      expect(executionDao.findByBuildTargetId("target-1").map((execution) => execution.id)).toEqual(
        expect.arrayContaining(["exec-1", "exec-2"]),
      );
    } finally {
      db.close();
    }
  });

  it("runQuickAnalysis fails when the SAST response has no code graph to ingest", async () => {
    const sourceService = {
      getProjectPath: vi.fn(() => "/tmp/project"),
      listFiles: vi.fn(() => [{ relativePath: "src/main.c" }]),
    };
    const sastClient = {
      scan: vi.fn(async () => ({
        success: true,
        scanId: "scan-1",
        status: "completed",
        findings: [],
        stats: { filesScanned: 1, rulesRun: 0, findingsTotal: 0, elapsedMs: 1 },
        execution: { toolsRun: [], toolResults: {} },
        codeGraph: null,
        sca: null,
      })),
    };
    const ws = { broadcast: vi.fn() };
    const orchestrator = new AnalysisOrchestrator(
      sourceService as any,
      sastClient as any,
      { ingestCodeGraph: vi.fn(), isGraphReady: vi.fn(() => true) } as any,
      { submitTask: vi.fn(), isSuccess: vi.fn(() => true) } as any,
      { save: vi.fn() } as any,
      { getAll: vi.fn(() => ({ buildProfile: { sdkId: "sdk-default" } })) } as any,
      { normalizeAnalysisResult: vi.fn(), normalizeAgentResult: vi.fn() } as any,
      ws as any,
      {
        findByProjectId: vi.fn(() => [{
          id: "target-1",
          projectId: "project-1",
          name: "gateway",
          relativePath: "gateway/",
          compileCommandsPath: "/tmp/project/gateway/compile_commands.json",
          buildProfile: { sdkId: "sdk-default", compiler: "gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" },
          sdkChoiceState: "sdk-selected",
        }]),
      } as any,
    );

    await expect(orchestrator.runQuickAnalysis("project-1", "analysis-1", ["target-1"], "req-1"))
      .rejects.toThrow(/Quick graph context missing/);

    expect(ws.broadcast).toHaveBeenCalledWith(
      "analysis-1",
      expect.objectContaining({
        type: "analysis-error",
        payload: expect.objectContaining({
          phase: "quick",
          error: "Quick graph context missing from SAST response",
        }),
      }),
    );
  });

  it("preflightDeepRequest rejects superseded executions", async () => {
    const analysisExecutionDAO = {
      findById: vi.fn(() => ({
        id: "exec-old",
        projectId: "project-1",
        buildTargetId: "target-1",
        buildTargetName: "gateway",
        buildTargetRelativePath: "gateway/",
        buildProfileSnapshot: { sdkId: "sdk-gateway" },
        sdkChoiceState: "sdk-selected",
        status: "superseded",
        quickBuildPrepStatus: "succeeded",
        quickGraphRagStatus: "succeeded",
        quickSastStatus: "succeeded",
        deepStatus: "pending",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      })),
    };
    const orchestrator = new AnalysisOrchestrator(
      { getProjectPath: vi.fn(() => "/tmp/project"), listFiles: vi.fn(() => [{ relativePath: "gateway/main.c" }]) } as any,
      {} as any,
      {} as any,
      {} as any,
      {
        findByExecutionId: vi.fn(() => [{
          id: "analysis-exec-old-gateway",
          projectId: "project-1",
          buildTargetId: "target-1",
          analysisExecutionId: "exec-old",
          module: "static_analysis",
          status: "completed",
          vulnerabilities: [],
          summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          createdAt: new Date().toISOString(),
        }]),
        findById: vi.fn(),
      } as any,
      { getAll: vi.fn(() => ({ buildProfile: { sdkId: "sdk-gateway" } })) } as any,
      {} as any,
      undefined,
      {
        findByProjectId: vi.fn(() => [{
          id: "target-1",
          projectId: "project-1",
          name: "gateway",
          relativePath: "gateway/",
          buildProfile: { sdkId: "sdk-gateway", compiler: "arm-none-eabi-gcc", targetArch: "armv7-a", languageStandard: "c11", headerLanguage: "c" },
          sdkChoiceState: "sdk-selected",
        }]),
      } as any,
      undefined,
      undefined,
      analysisExecutionDAO as any,
    );

    expect(() => orchestrator.preflightDeepRequest("project-1", "target-1", "exec-old")).toThrow(
      /not active/,
    );
  });
});
