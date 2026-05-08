/**
 * 하위 서비스 클라이언트 계약 테스트
 *
 * AgentClient, SastClient, KbClient의 요청/응답 shape과
 * 에러 핸들링을 globalThis.fetch 모킹으로 검증한다.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AgentClient } from "../../services/agent-client";
import { SastClient } from "../../services/sast-client";
import { KbClient } from "../../services/kb-client";

// 원본 fetch 보존
const originalFetch = globalThis.fetch;

function mockFetch(response: object, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(response),
    text: () => Promise.resolve(JSON.stringify(response)),
  });
}

function mockFetchReject(error: Error) {
  return vi.fn().mockRejectedValue(error);
}

function mockFetch503ThenOk(response: object) {
  let calls = 0;
  return vi.fn().mockImplementation(() => {
    calls++;
    if (calls === 1) {
      return Promise.resolve({
        ok: false,
        status: 503,
        json: () => Promise.resolve({ error: "Service Unavailable" }),
        text: () => Promise.resolve("Service Unavailable"),
      });
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve(response),
      text: () => Promise.resolve(JSON.stringify(response)),
    });
  });
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.AEGIS_S4_OWNERSHIP_POLL_MS;
});

// ============================================================
// AgentClient
// ============================================================

describe("AgentClient contract", () => {
  const client = new AgentClient("http://localhost:8001");

  const successResponse = {
    taskId: "task-1",
    taskType: "deep-analyze",
    status: "completed",
    modelProfile: "Qwen/Qwen3.6-27B",
    promptVersion: "v2",
    schemaVersion: "1.0",
    validation: { valid: true, errors: [] },
    result: {
      summary: "1 critical vulnerability found",
      claims: [
        {
          id: "c-1",
          title: "Buffer overflow",
          severity: "high",
          confidence: 0.9,
          description: "Stack buffer overflow in parse()",
          location: "src/parse.c:42",
          evidenceRefs: [],
        },
      ],
      caveats: [],
      usedEvidenceRefs: [],
      confidence: 0.85,
      confidenceBreakdown: {
        grounding: 0.9,
        deterministicSupport: 0.85,
        ragCoverage: 0.8,
      },
      needsHumanReview: false,
      recommendedNextSteps: [],
      policyFlags: [],
      analysisOutcome: "accepted_claims",
      qualityOutcome: "accepted",
      pocOutcome: "poc_not_requested",
      recoveryTrace: [],
    },
    audit: {
      inputHash: "abc123",
      latencyMs: 12000,
      tokenUsage: { prompt: 3000, completion: 2000 },
      retryCount: 0,
      createdAt: "2026-03-25T00:00:00Z",
    },
  };

  const failureResponse = {
    taskId: "task-1",
    taskType: "deep-analyze",
    status: "timeout",
    failureCode: "TIMEOUT",
    failureDetail: "Analysis exceeded time limit",
    retryable: true,
  };

  it("POST /v1/tasks sends correct request shape", async () => {
    globalThis.fetch = mockFetch(successResponse);

    const request = {
      taskType: "deep-analyze" as const,
      taskId: "task-1",
      context: {
        trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp/test" },
        untrusted: {},
      },
      evidenceRefs: [],
    };

    await client.submitTask(request, "req-test");

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:8001/v1/tasks");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(opts.headers["X-Request-Id"]).toBe("req-test");
    const body = JSON.parse(opts.body);
    expect(body.taskType).toBe("deep-analyze");
    expect(body.taskId).toBe("task-1");
    expect(body).not.toHaveProperty("constraints");
  });

  it("passes optional camelCase generation overrides without inventing defaults", async () => {
    globalThis.fetch = mockFetch(successResponse);

    await client.submitTask({
      taskType: "deep-analyze",
      taskId: "task-generation",
      context: {
        trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp/test" },
      },
      evidenceRefs: [],
      constraints: {
        enableThinking: false,
        maxTokens: 8192,
        temperature: 0.2,
        topP: 0.9,
        topK: -1,
        minP: 0.01,
        presencePenalty: 0.1,
        repetitionPenalty: 1.05,
        timeoutMs: 300000,
      },
    });

    const [, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.constraints).toEqual({
      enableThinking: false,
      maxTokens: 8192,
      temperature: 0.2,
      topP: 0.9,
      topK: -1,
      minP: 0.01,
      presencePenalty: 0.1,
      repetitionPenalty: 1.05,
      timeoutMs: 300000,
    });
  });

  it("parses AgentResponseSuccess correctly", async () => {
    globalThis.fetch = mockFetch(successResponse);

    const result = await client.submitTask({
      taskType: "deep-analyze",
      taskId: "task-1",
      context: { trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp" } },
      evidenceRefs: [],
    });

    expect(client.isSuccess(result)).toBe(true);
    if (client.isSuccess(result)) {
      expect(result.status).toBe("completed");
      expect(result.result.claims).toHaveLength(1);
      expect(result.result.confidence).toBe(0.85);
      expect(result.result.analysisOutcome).toBe("accepted_claims");
      expect(result.result.qualityOutcome).toBe("accepted");
      expect(result.audit.tokenUsage.prompt).toBe(3000);
    }
  });

  it("parses AgentResponseFailure correctly", async () => {
    globalThis.fetch = mockFetch(failureResponse);

    const result = await client.submitTask({
      taskType: "deep-analyze",
      taskId: "task-1",
      context: { trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp" } },
      evidenceRefs: [],
    });

    expect(client.isSuccess(result)).toBe(false);
    if (!client.isSuccess(result)) {
      expect(result.status).toBe("timeout");
      expect(result.failureCode).toBe("TIMEOUT");
      expect(result.retryable).toBe(true);
    }
  });

  it("preserves completed S3-owned deficiency outcomes without treating completion as clean pass", async () => {
    globalThis.fetch = mockFetch({
      ...successResponse,
      result: {
        ...successResponse.result,
        claims: [],
        policyFlags: ["structured_finalizer", "recovery_classified"],
        analysisOutcome: "no_accepted_claims",
        qualityOutcome: "repair_exhausted",
        recoveryTrace: [{
          deficiency: "SCHEMA_DEFICIENT",
          action: "deterministic_scaffold",
          outcome: "classified",
          detail: "missing final fields were scaffolded without fabricating evidence",
        }],
      },
    });

    const success = await client.submitTask({
      taskType: "deep-analyze",
      taskId: "task-structured-finalizer",
      context: { trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp" } },
      evidenceRefs: [],
    });

    expect(client.isSuccess(success)).toBe(true);
    if (client.isSuccess(success)) {
      expect(success.result.policyFlags).toContain("structured_finalizer");
      expect(success.result.claims).toHaveLength(0);
      expect(success.result.analysisOutcome).toBe("no_accepted_claims");
      expect(success.result.qualityOutcome).toBe("repair_exhausted");
      expect(success.result.recoveryTrace?.[0]?.deficiency).toBe("SCHEMA_DEFICIENT");
    }
  });

  it("parses non-2xx true task failures as terminal AgentResponseFailure", async () => {
    globalThis.fetch = mockFetch({
      taskId: "task-invalid-input",
      taskType: "deep-analyze",
      status: "validation_failed",
      failureCode: "INVALID_CALLER_CONTRACT",
      failureDetail: "Missing required trusted input: projectPath or files",
      retryable: false,
      audit: successResponse.audit,
    }, 422);

    const failure = await client.submitTask({
      taskType: "deep-analyze",
      taskId: "task-invalid-input",
      context: { trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp" } },
      evidenceRefs: [],
    });

    expect(client.isSuccess(failure)).toBe(false);
    if (!client.isSuccess(failure)) {
      expect(failure.status).toBe("validation_failed");
      expect(failure.failureCode).toBe("INVALID_CALLER_CONTRACT");
      expect(failure.failureDetail).toContain("Missing required trusted input");
      expect(failure.audit?.latencyMs).toBe(12000);
    }
  });

  it("retries on 503 and succeeds", async () => {
    globalThis.fetch = mockFetch503ThenOk(successResponse);

    const result = await client.submitTask({
      taskType: "deep-analyze",
      taskId: "task-1",
      context: { trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp" } },
      evidenceRefs: [],
    });

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(client.isSuccess(result)).toBe(true);
  });

  it("throws AgentUnavailableError on network failure", async () => {
    globalThis.fetch = mockFetchReject(new Error("ECONNREFUSED"));

    await expect(
      client.submitTask({
        taskType: "deep-analyze",
        taskId: "task-1",
        context: { trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp" } },
        evidenceRefs: [],
      }),
    ).rejects.toThrow(/ECONNREFUSED|unavailable|네트워크/i);
  });

  it("throws AgentTimeoutError on timeout", async () => {
    globalThis.fetch = mockFetchReject(new Error("ETIMEDOUT"));

    await expect(
      client.submitTask({
        taskType: "deep-analyze",
        taskId: "task-1",
        context: { trusted: { objective: "analyze", projectId: "p-1", projectPath: "/tmp" } },
        evidenceRefs: [],
      }),
    ).rejects.toThrow(/timeout|ETIMEDOUT/i);
  });

  it("GET /v1/health returns null on failure", async () => {
    globalThis.fetch = mockFetchReject(new Error("ECONNREFUSED"));
    const result = await client.checkHealth();
    expect(result).toBeNull();
  });

  it("GET /v1/health returns data on success", async () => {
    const healthData = { status: "ok", service: "s3-agent" };
    globalThis.fetch = mockFetch(healthData);
    const result = await client.checkHealth();
    expect(result).toEqual(healthData);
  });
});

// ============================================================
// SastClient
// ============================================================

describe("SastClient contract", () => {
  const client = new SastClient("http://localhost:9000");

  const scanResponse = {
    success: true,
    scanId: "scan-1",
    status: "completed",
    findings: [
      { id: "sf-1", tool: "cppcheck", ruleId: "bufferOverflow", severity: "high", message: "Buffer overflow", file: "src/main.c", line: 42, column: 5 },
    ],
    stats: { filesScanned: 10, rulesRun: 50, findingsTotal: 1, elapsedMs: 5000 },
    execution: { toolsRun: ["cppcheck"], toolResults: {} },
    codeGraph: { functions: [], callEdges: [] },
    sca: { libraries: [] },
  };

  const buildResponse = {
    success: true,
    buildEvidence: {
      compileCommandsPath: "/tmp/compile_commands.json",
      entries: 42,
      userEntries: 42,
      elapsedMs: 3000,
      buildOutput: "build ok",
      environmentKeys: ["CC"],
    },
  };

  const discoverResponse = {
    targets: [
      { name: "gateway", relativePath: "gateway/", buildSystem: "cmake", buildFile: "CMakeLists.txt" },
    ],
    elapsedMs: 500,
  };

  it("POST /v1/scan sends correct request shape", async () => {
    globalThis.fetch = mockFetch(scanResponse);

    await client.scan({
      scanId: "scan-1",
      projectId: "p-1",
      projectPath: "/tmp/project",
    }, "req-test");

    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:9000/v1/scan");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Prefer"]).toBe("respond-async");
    expect(opts.headers["X-Request-Id"]).toMatch(/^req-test:s4:scan:/);
    const body = JSON.parse(opts.body);
    expect(body.scanId).toBe("scan-1");
    expect(body.projectPath).toBe("/tmp/project");
  });

  it("omits legacy buildProfile.sdkId custom sentinel for S4 native scans", async () => {
    globalThis.fetch = mockFetch(scanResponse);

    await client.scan({
      scanId: "scan-custom",
      projectId: "p-1",
      projectPath: "/tmp/project",
      buildProfile: {
        sdkId: "custom",
        compiler: "gcc",
        targetArch: "x86_64",
        languageStandard: "c11",
        headerLanguage: "auto",
      },
    });

    const [, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.buildProfile).toMatchObject({
      compiler: "gcc",
      targetArch: "x86_64",
      languageStandard: "c11",
      headerLanguage: "auto",
    });
    expect(body.buildProfile).not.toHaveProperty("sdkId");
  });

  it("parses SastScanResponse correctly", async () => {
    globalThis.fetch = mockFetch(scanResponse);

    const result = await client.scan({
      scanId: "scan-1",
      projectId: "p-1",
      projectPath: "/tmp/project",
    });

    expect(result.success).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.stats.filesScanned).toBe(10);
    expect(result.codeGraph).toBeDefined();
    expect(result.sca).toBeDefined();
  });

  it("POST /v1/build sends correct request shape", async () => {
    globalThis.fetch = mockFetch(buildResponse);

    await client.build({ projectPath: "/tmp/project", buildCommand: "make all" }, "req-build");

    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:9000/v1/build");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Prefer"]).toBe("respond-async");
    expect(opts.headers["X-Request-Id"]).toMatch(/^req-build:s4:build:/);
    const body = JSON.parse(opts.body);
    expect(body.projectPath).toBe("/tmp/project");
    expect(body.buildCommand).toBe("make all");
  });

  it("waits through S4 durable ownership queued/running/degraded states and returns retained scan result", async () => {
    process.env.AEGIS_S4_OWNERSHIP_POLL_MS = "1";
    let ownedRequestId = "";
    globalThis.fetch = vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url === "http://localhost:9000/v1/scan") {
        ownedRequestId = opts.headers["X-Request-Id"];
        return Promise.resolve({
          ok: true,
          status: 202,
          json: () => Promise.resolve({
            requestId: ownedRequestId,
            endpoint: "scan",
            state: "queued",
            resultReady: false,
            requestSummary: {
              requestId: ownedRequestId,
              endpoint: "scan",
              state: "queued",
              localAckState: "transport-only",
              blockedReason: null,
            },
          }),
          text: () => Promise.resolve(""),
        });
      }
      expect(url).toContain(`/v1/requests/${encodeURIComponent(ownedRequestId)}/result`);
      const callCount = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
      if (callCount === 2) {
        return Promise.resolve({
          ok: true,
          status: 202,
          json: () => Promise.resolve({
            requestId: ownedRequestId,
            endpoint: "scan",
            state: "queued",
            resultReady: false,
            requestSummary: {
              requestId: ownedRequestId,
              endpoint: "scan",
              state: "queued",
              localAckState: "transport-only",
              blockedReason: null,
            },
          }),
          text: () => Promise.resolve(""),
        });
      }
      if (callCount === 3) {
        return Promise.resolve({
          ok: true,
          status: 202,
          json: () => Promise.resolve({
            requestId: ownedRequestId,
            endpoint: "scan",
            state: "running",
            resultReady: false,
            requestSummary: {
              requestId: ownedRequestId,
              endpoint: "scan",
              state: "running",
              localAckState: "transport-only",
              degraded: true,
              blockedReason: null,
            },
          }),
          text: () => Promise.resolve(""),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          requestId: ownedRequestId,
          endpoint: "scan",
          state: "completed",
          resultReady: true,
          result: scanResponse,
          requestSummary: {
            requestId: ownedRequestId,
            endpoint: "scan",
            state: "completed",
            localAckState: null,
            blockedReason: null,
          },
        }),
        text: () => Promise.resolve(""),
      });
    }) as any;

    const result = await client.scan({ scanId: "scan-owned", projectId: "p-1", projectPath: "/tmp/project" }, "req-owned");

    expect(result.status).toBe("completed");
    expect(result.stats.findingsTotal).toBe(1);
    expect(globalThis.fetch).toHaveBeenCalledTimes(4);
  });

  it("recovers a S4 submit transport timeout when health proves owned work is still alive", async () => {
    process.env.AEGIS_S4_OWNERSHIP_POLL_MS = "1";
    let ownedRequestId = "";
    globalThis.fetch = vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url === "http://localhost:9000/v1/scan") {
        ownedRequestId = opts.headers["X-Request-Id"];
        return Promise.reject(new Error("ETIMEDOUT while waiting for response"));
      }
      if (url.startsWith("http://localhost:9000/v1/health")) {
        expect(url).toContain(encodeURIComponent(ownedRequestId));
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({
            status: "ok",
            activeRequestCount: 1,
            requestSummary: {
              requestId: ownedRequestId,
              endpoint: "scan",
              state: "running",
              localAckState: "transport-only",
              blockedReason: null,
            },
          }),
          text: () => Promise.resolve(""),
        });
      }
      expect(url).toContain(`/v1/requests/${encodeURIComponent(ownedRequestId)}/result`);
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          requestId: ownedRequestId,
          endpoint: "scan",
          state: "completed",
          resultReady: true,
          result: scanResponse,
          requestSummary: {
            requestId: ownedRequestId,
            endpoint: "scan",
            state: "completed",
            localAckState: null,
            blockedReason: null,
          },
        }),
        text: () => Promise.resolve(""),
      });
    }) as any;

    const result = await client.scan({ scanId: "scan-timeout-recovered", projectId: "p-1", projectPath: "/tmp/project" }, "req-owned-timeout");

    expect(result.status).toBe("completed");
    expect(result.scanId).toBe("scan-1");
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
  });

  it("aborts S4 durable ownership wait on ack-break instead of waiting by elapsed age", async () => {
    process.env.AEGIS_S4_OWNERSHIP_POLL_MS = "1";
    let ownedRequestId = "";
    globalThis.fetch = vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url === "http://localhost:9000/v1/build") {
        ownedRequestId = opts.headers["X-Request-Id"];
        return Promise.resolve({
          ok: true,
          status: 202,
          json: () => Promise.resolve({ requestId: ownedRequestId, endpoint: "build", state: "running" }),
          text: () => Promise.resolve(""),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 202,
        json: () => Promise.resolve({
          requestId: ownedRequestId,
          endpoint: "build",
          state: "running",
          resultReady: false,
          requestSummary: {
            requestId: ownedRequestId,
            endpoint: "build",
            state: "running",
            localAckState: "ack-break",
            blockedReason: "build-process-crashed",
          },
        }),
        text: () => Promise.resolve(""),
      });
    }) as any;

    await expect(client.build({ projectPath: "/tmp/project", buildCommand: "make" }, "req-build-owned"))
      .rejects.toThrow(/chain abort|ack-break|blocked/i);
  });

  it("surfaces S4 durable ownership expiry as ownership loss", async () => {
    let ownedRequestId = "";
    globalThis.fetch = vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url === "http://localhost:9000/v1/build") {
        ownedRequestId = opts.headers["X-Request-Id"];
        return Promise.resolve({
          ok: true,
          status: 202,
          json: () => Promise.resolve({ requestId: ownedRequestId, endpoint: "build", state: "queued" }),
          text: () => Promise.resolve(""),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 410,
        json: () => Promise.resolve({ error: "REQUEST_EXPIRED" }),
        text: () => Promise.resolve("REQUEST_EXPIRED"),
      });
    }) as any;

    await expect(client.build({ projectPath: "/tmp/project", buildCommand: "make" }, "req-expired"))
      .rejects.toThrow(/ownership loss|410|expired/i);
  });

  it("propagates explicit local cancellation while waiting for S4 durable result", async () => {
    process.env.AEGIS_S4_OWNERSHIP_POLL_MS = "25";
    const controller = new AbortController();
    let ownedRequestId = "";
    globalThis.fetch = vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url === "http://localhost:9000/v1/scan") {
        ownedRequestId = opts.headers["X-Request-Id"];
        return Promise.resolve({
          ok: true,
          status: 202,
          json: () => Promise.resolve({ requestId: ownedRequestId, endpoint: "scan", state: "queued" }),
          text: () => Promise.resolve(""),
        });
      }
      setTimeout(() => controller.abort(new Error("user cancelled")), 0);
      return Promise.resolve({
        ok: true,
        status: 202,
        json: () => Promise.resolve({
          requestId: ownedRequestId,
          endpoint: "scan",
          state: "running",
          requestSummary: {
            requestId: ownedRequestId,
            endpoint: "scan",
            state: "running",
            localAckState: "transport-only",
            blockedReason: null,
          },
        }),
        text: () => Promise.resolve(""),
      });
    }) as any;

    await expect(client.scan(
      { scanId: "scan-cancel", projectId: "p-1", projectPath: "/tmp/project" },
      "req-cancel",
      controller.signal,
    )).rejects.toThrow(/cancelled/i);
  });

  it("parses BuildResponse correctly", async () => {
    globalThis.fetch = mockFetch(buildResponse);
    const result = await client.build({ projectPath: "/tmp/project", buildCommand: "make all" });

    expect(result.success).toBe(true);
    expect(result.compileCommandsPath).toBe("/tmp/compile_commands.json");
    expect(result.entries).toBe(42);
    expect(result.buildLog).toBe("build ok");
    expect(result.environmentKeys).toEqual(["CC"]);
  });

  it("parses structured failed build responses with failureDetail", async () => {
    globalThis.fetch = mockFetch({
      success: false,
      buildEvidence: {
        compileCommandsPath: "/tmp/compile_commands.json",
        entries: 3,
        userEntries: 1,
        elapsedMs: 1234,
        buildOutput: "bash: missing: command not found",
      },
      failureDetail: {
        category: "command-not-found",
        summary: "The supplied build command referenced an unavailable executable or script.",
      },
    });

    const result = await client.build({ projectPath: "/tmp/project", buildCommand: "missing" });

    expect(result.success).toBe(false);
    expect(result.compileCommandsPath).toBe("/tmp/compile_commands.json");
    expect(result.entries).toBe(1);
    expect(result.failureCategory).toBe("command-not-found");
    expect(result.error).toContain("unavailable executable");
  });

  it("POST /v1/discover-targets sends projectPath", async () => {
    globalThis.fetch = mockFetch(discoverResponse);

    await client.discoverTargets("/tmp/project", "req-discover");

    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:9000/v1/discover-targets");
    expect(opts.method).toBe("POST");
    const body = JSON.parse(opts.body);
    expect(body.projectPath).toBe("/tmp/project");
  });

  it("parses DiscoverTargetsResponse correctly", async () => {
    globalThis.fetch = mockFetch(discoverResponse);
    const result = await client.discoverTargets("/tmp/project");

    expect(result.targets).toHaveLength(1);
    expect(result.targets[0].name).toBe("gateway");
    expect(result.targets[0].buildSystem).toBe("cmake");
  });

  it("retries on 503 and succeeds", async () => {
    globalThis.fetch = mockFetch503ThenOk(scanResponse);

    const result = await client.scan({
      scanId: "scan-1",
      projectId: "p-1",
      projectPath: "/tmp/project",
    });

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(result.success).toBe(true);
  });

  it("treats omission-policy 503 as authoritative failed scan without retry", async () => {
    const failureResponse = {
      success: false,
      scanId: "scan-omission",
      status: "failed",
      error: "Disallowed tool omission",
      errorDetail: {
        code: "DISALLOWED_TOOL_OMISSION",
        message: "runtime-tool-missing",
        retryable: false,
      },
    };
    globalThis.fetch = mockFetch(failureResponse, 503);

    const result = await client.scan({
      scanId: "scan-omission",
      projectId: "p-1",
      projectPath: "/tmp/project",
    });

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(result.status).toBe("failed");
    expect(result.errorDetail?.code).toBe("DISALLOWED_TOOL_OMISSION");
    expect(result.stats.findingsTotal).toBe(0);
  });

  it("throws SastUnavailableError on network failure", async () => {
    globalThis.fetch = mockFetchReject(new Error("ECONNREFUSED"));

    await expect(
      client.scan({ scanId: "scan-1", projectId: "p-1", projectPath: "/tmp" }),
    ).rejects.toThrow(/ECONNREFUSED|unavailable|네트워크/i);
  });
});

// ============================================================
// KbClient
// ============================================================

describe("KbClient contract", () => {
  const client = new KbClient("http://localhost:8002");

  const ingestResponse = {
    success: true,
    project_id: "p-1",
    nodes_created: 50,
    edges_created: 120,
    elapsed_ms: 800,
  };

  const statsResponse = {
    project_id: "p-1",
    function_count: 50,
    call_edge_count: 120,
  };

  it("POST /v1/code-graph/:projectId/ingest sends correct URL and body", async () => {
    globalThis.fetch = mockFetch(ingestResponse);

    await client.ingestCodeGraph(
      "p-1",
      { functions: [{ name: "main", file: "main.c", line: 1 }], callEdges: [] },
      "req-ingest",
    );

    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:8002/v1/code-graph/p-1/ingest");
    expect(opts.method).toBe("POST");
    expect(opts.headers["X-Request-Id"]).toBe("req-ingest");
    expect(opts.headers["X-Timeout-Ms"]).toBe("15000");
    const body = JSON.parse(opts.body);
    expect(body.functions).toHaveLength(1);
    expect(body.functions[0].name).toBe("main");
  });

  it("parses CodeGraphIngestResponse correctly", async () => {
    globalThis.fetch = mockFetch(ingestResponse);

    const result = await client.ingestCodeGraph(
      "p-1",
      { functions: [], callEdges: [] },
    );

    expect(result.success).toBe(true);
    expect(result.nodes_created).toBe(50);
    expect(result.edges_created).toBe(120);
  });

  it("GET /v1/code-graph/:projectId/stats returns stats", async () => {
    globalThis.fetch = mockFetch(statsResponse);

    const result = await client.getCodeGraphStats("p-1", "req-stats");

    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:8002/v1/code-graph/p-1/stats");
    expect(result).not.toBeNull();
    expect(result!.function_count).toBe(50);
  });

  it("GET /v1/code-graph/:projectId/stats returns null on failure", async () => {
    globalThis.fetch = mockFetchReject(new Error("ECONNREFUSED"));
    const result = await client.getCodeGraphStats("p-1");
    expect(result).toBeNull();
  });

  it("DELETE /v1/code-graph/:projectId returns true on success", async () => {
    globalThis.fetch = mockFetch({ success: true });

    const result = await client.deleteCodeGraph("p-1", "req-del");

    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:8002/v1/code-graph/p-1");
    expect(opts.method).toBe("DELETE");
    expect(result).toBe(true);
  });

  it("DELETE /v1/code-graph/:projectId returns false on failure", async () => {
    globalThis.fetch = mockFetchReject(new Error("ECONNREFUSED"));
    const result = await client.deleteCodeGraph("p-1");
    expect(result).toBe(false);
  });

  it("retries ingest on 503", async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({
          success: false,
          error: "Knowledge base not initialized",
          errorDetail: { code: "KB_NOT_READY", message: "Knowledge base not initialized", retryable: true },
        }),
        text: async () => JSON.stringify({
          success: false,
          error: "Knowledge base not initialized",
          errorDetail: { code: "KB_NOT_READY", message: "Knowledge base not initialized", retryable: true },
        }),
        clone() { return this; },
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ingestResponse,
        text: async () => JSON.stringify(ingestResponse),
        clone() { return this; },
      }) as any;

    const result = await client.ingestCodeGraph(
      "p-1",
      { functions: [], callEdges: [] },
    );

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(result.nodes_created).toBe(50);
  });

  it("surfaces real 408 timeout semantics from S5 ingest", async () => {
    globalThis.fetch = mockFetch({
      success: false,
      error: "Deadline exceeded",
      errorDetail: {
        code: "TIMEOUT",
        message: "Deadline exceeded",
        retryable: true,
        requestId: "req-kb-timeout",
      },
    }, 408);

    await expect(
      client.ingestCodeGraph("p-1", { functions: [], callEdges: [] }, "req-kb-timeout"),
    ).rejects.toThrow(/408.*TIMEOUT|TIMEOUT.*408/i);
  });

  it("encodes projectId with special characters in URL", async () => {
    globalThis.fetch = mockFetch(statsResponse);

    await client.getCodeGraphStats("proj:target-1");

    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:8002/v1/code-graph/proj%3Atarget-1/stats");
  });
});

// ============================================================
// BuildAgentClient
// ============================================================

import { BuildAgentClient } from "../../services/build-agent-client";
import { BuildAgentUnavailableError, BuildAgentTimeoutError } from "../../lib/errors";

describe("BuildAgentClient contract", () => {
  const client = new BuildAgentClient("http://localhost:8003");

  const successResponse = {
    taskId: "resolve-1",
    taskType: "build-resolve",
    status: "completed" as const,
    modelProfile: "build-v1",
    promptVersion: "build-resolve-v1",
    schemaVersion: "agent-v1",
    validation: { valid: true, errors: [] },
    result: {
      summary: "CMake 빌드 성공",
      claims: [{ statement: "cmake detected", supportingEvidenceRefs: [], location: "CMakeLists.txt" }],
      caveats: ["native build fallback"],
      usedEvidenceRefs: [],
      confidence: 0.92,
      confidenceBreakdown: { grounding: 0.95, deterministicSupport: 1.0, ragCoverage: 0.4, schemaCompliance: 1.0 },
      needsHumanReview: false,
      buildResult: {
        success: true,
        buildCommand: "bash build-aegis/aegis-build.sh",
        buildScript: "build-aegis/aegis-build.sh",
        buildDir: "build-aegis",
        errorLog: null,
      },
    },
    audit: { inputHash: "sha256:abc", latencyMs: 30000, tokenUsage: { prompt: 1500, completion: 800 }, retryCount: 0, createdAt: "2026-03-25T00:00:00Z" },
  };

  const failResponse = {
    taskId: "resolve-1",
    taskType: "build-resolve",
    status: "build_failed" as const,
    failureCode: "BUILD_FAILED",
    failureDetail: "cmake exited with code 1",
    retryable: false,
  };

  it("parses success response with buildResult", async () => {
    globalThis.fetch = mockFetch(successResponse);

    const result = await client.submitTask({
      taskType: "build-resolve",
      taskId: "resolve-1",
      context: { trusted: { projectPath: "/tmp/project", targetPath: "src/" } },
    }, "req-test");

    expect(client.isSuccess(result)).toBe(true);
    if (client.isSuccess(result)) {
      expect(result.result.buildResult.buildCommand).toContain("aegis-build");
      expect(result.result.buildResult.success).toBe(true);
      expect(result.result.confidence).toBe(0.92);
    }
  });

  it("passes optional camelCase generation overrides without inventing defaults", async () => {
    globalThis.fetch = mockFetch(successResponse);

    await client.submitTask({
      taskType: "build-resolve",
      taskId: "resolve-generation",
      context: { trusted: { projectPath: "/tmp/project", targetPath: "src/" } },
      constraints: {
        enableThinking: true,
        maxTokens: 12000,
        temperature: 0.4,
        topP: 0.92,
        topK: -1,
        minP: 0,
        presencePenalty: 0,
        repetitionPenalty: 1,
        timeoutMs: 600000,
      },
    });

    const [, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.constraints).toEqual({
      enableThinking: true,
      maxTokens: 12000,
      temperature: 0.4,
      topP: 0.92,
      topK: -1,
      minP: 0,
      presencePenalty: 0,
      repetitionPenalty: 1,
      timeoutMs: 600000,
    });
  });

  it("parses failure response with failureCode", async () => {
    globalThis.fetch = mockFetch(failResponse);

    const result = await client.submitTask({
      taskType: "build-resolve",
      taskId: "resolve-1",
      context: { trusted: { projectPath: "/tmp/project" } },
    });

    expect(client.isSuccess(result)).toBe(false);
    if (!client.isSuccess(result)) {
      expect(result.failureCode).toBe("BUILD_FAILED");
      expect(result.failureDetail).toContain("cmake");
    }
  });

  it("throws BuildAgentUnavailableError on network error", async () => {
    globalThis.fetch = mockFetchReject(new Error("ECONNREFUSED"));

    await expect(
      client.submitTask({
        taskType: "build-resolve",
        taskId: "resolve-1",
        context: { trusted: { projectPath: "/tmp" } },
      }),
    ).rejects.toThrow(BuildAgentUnavailableError);
  });

  it("throws BuildAgentTimeoutError on timeout", async () => {
    globalThis.fetch = mockFetchReject(new Error("ETIMEDOUT"));

    await expect(
      client.submitTask({
        taskType: "build-resolve",
        taskId: "resolve-1",
        context: { trusted: { projectPath: "/tmp" } },
      }),
    ).rejects.toThrow(BuildAgentTimeoutError);
  });

  it("retries on 503", async () => {
    globalThis.fetch = mockFetch503ThenOk(successResponse);

    const result = await client.submitTask({
      taskType: "build-resolve",
      taskId: "resolve-1",
      context: { trusted: { projectPath: "/tmp" } },
    });

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(client.isSuccess(result)).toBe(true);
  });

  it("sends X-Request-Id header", async () => {
    globalThis.fetch = mockFetch(successResponse);

    await client.submitTask({
      taskType: "build-resolve",
      taskId: "resolve-1",
      context: { trusted: { projectPath: "/tmp" } },
    }, "req-123");

    const [, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(opts.headers["X-Request-Id"]).toBe("req-123");
  });

  it("checkHealth returns null on failure", async () => {
    globalThis.fetch = mockFetchReject(new Error("ECONNREFUSED"));
    const result = await client.checkHealth();
    expect(result).toBeNull();
  });

  it("checkHealth returns data on success", async () => {
    globalThis.fetch = mockFetch({ status: "ok", version: "0.1.0" });
    const result = await client.checkHealth();
    expect(result).toMatchObject({ status: "ok" });
  });
});
