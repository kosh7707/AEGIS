import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock fetch before importing client
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock localStorage
const storage: Record<string, string> = {};
Object.defineProperty(global, "localStorage", {
  value: {
    getItem: (key: string) => storage[key] ?? null,
    setItem: (key: string, value: string) => { storage[key] = value; },
    removeItem: (key: string) => { delete storage[key]; },
  },
});

import {
  fetchBuildTargets,
  createBuildTarget,
  updateBuildTarget,
  deleteBuildTarget,
  discoverBuildTargets,
  runPipelineTarget,
  runAnalysis,
  generatePoc,
  fetchSourceFiles,
  fetchSourceFileContent,
  cloneSource,
} from "./client";

function mockResponse(data: unknown, status = 200) {
  mockFetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    headers: new Headers(),
  });
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe("fetchBuildTargets", () => {
  it("calls GET /api/projects/:pid/targets", async () => {
    const targets = [{ id: "t-1", name: "gateway" }];
    mockResponse({ success: true, data: targets });

    const result = await fetchBuildTargets("proj-1");
    expect(result).toEqual(targets);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/api/projects/proj-1/targets");
  });
});

describe("createBuildTarget", () => {
  it("sends POST with name and relativePath", async () => {
    const created = { id: "t-2", name: "body", relativePath: "body/" };
    mockResponse({ success: true, data: created });

    const result = await createBuildTarget("proj-1", {
      name: "body",
      relativePath: "body/",
    });
    expect(result).toEqual(created);

    const [, opts] = mockFetch.mock.calls[0];
    expect(opts.method).toBe("POST");
    const body = JSON.parse(opts.body);
    expect(body.name).toBe("body");
    expect(body.relativePath).toBe("body/");
  });

  it("forwards optional scriptHintPath when provided", async () => {
    mockResponse({ success: true, data: { id: "t-3" } });

    await createBuildTarget("proj-1", {
      name: "body",
      relativePath: "body/",
      scriptHintPath: "scripts/build.sh",
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.scriptHintPath).toBe("scripts/build.sh");
  });

  it("omits scriptHintPath key when not provided", async () => {
    mockResponse({ success: true, data: { id: "t-4" } });

    await createBuildTarget("proj-1", { name: "body", relativePath: "body/" });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body).not.toHaveProperty("scriptHintPath");
  });
});

describe("updateBuildTarget", () => {
  it("sends PUT with scriptHintPath when provided as a string", async () => {
    mockResponse({ success: true, data: { id: "t-1" } });

    await updateBuildTarget("proj-1", "t-1", { scriptHintPath: "scripts/build.sh" });

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toContain("/api/projects/proj-1/targets/t-1");
    expect(opts.method).toBe("PUT");
    const body = JSON.parse(opts.body);
    expect(body.scriptHintPath).toBe("scripts/build.sh");
  });

  it("sends PUT with scriptHintPath:null to clear (preserved through JSON.stringify)", async () => {
    mockResponse({ success: true, data: { id: "t-1" } });

    await updateBuildTarget("proj-1", "t-1", { scriptHintPath: null });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body).toHaveProperty("scriptHintPath");
    expect(body.scriptHintPath).toBeNull();
  });

  it("omits scriptHintPath key when undefined (no-op semantic)", async () => {
    mockResponse({ success: true, data: { id: "t-1" } });

    await updateBuildTarget("proj-1", "t-1", { name: "renamed" });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body).not.toHaveProperty("scriptHintPath");
    expect(body.name).toBe("renamed");
  });
});

describe("deleteBuildTarget", () => {
  it("sends DELETE to correct URL", async () => {
    mockResponse({ success: true });

    await deleteBuildTarget("proj-1", "t-1");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toContain("/api/projects/proj-1/targets/t-1");
    expect(opts.method).toBe("DELETE");
  });
});

describe("discoverBuildTargets", () => {
  it("sends POST to discover endpoint and returns full result shape", async () => {
    const discovered = [{ id: "t-3", name: "gateway" }];
    mockResponse({
      success: true,
      data: { discovered: 1, created: 1, targets: discovered, elapsedMs: 12 },
    });

    const result = await discoverBuildTargets("proj-1");
    expect(result.targets).toEqual(discovered);
    expect(result.discovered).toBe(1);
    expect(result.created).toBe(1);

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toContain("/api/projects/proj-1/targets/discover");
    expect(opts.method).toBe("POST");
  });
});

describe("runPipelineTarget", () => {
  it("uses the canonical pipelineId/targetId/status payload", async () => {
    mockResponse({ success: true, data: { pipelineId: "pipe-99", targetId: "t-7", status: "running" } });

    const result = await runPipelineTarget("proj-1", "t-7");
    expect(result.pipelineId).toBe("pipe-99");
    expect(result.targetId).toBe("t-7");
    expect(result.status).toBe("running");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toContain("/api/projects/proj-1/pipeline/run/t-7");
    expect(opts.method).toBe("POST");
  });
});

describe("runAnalysis", () => {
  it("sends BuildTarget-scoped quick request", async () => {
    mockResponse({ success: true, data: { analysisId: "a-1", buildTargetId: "t-1", executionId: "exec-1", status: "running" } });

    const result = await runAnalysis("proj-1", "t-1");
    expect(result.analysisId).toBe("a-1");
    expect(result.buildTargetId).toBe("t-1");
    expect(result.executionId).toBe("exec-1");

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.projectId).toBe("proj-1");
    expect(body.buildTargetId).toBe("t-1");
    expect(mockFetch.mock.calls[0][0]).toContain("/api/analysis/quick");
  });
});

describe("generatePoc", () => {
  it("sends POST with projectId and findingId and forwards outcome fields", async () => {
    const pocResult = {
      findingId: "f-1",
      poc: { statement: "PoC", detail: "```\ncode\n```" },
      audit: { latencyMs: 5000, tokenUsage: { prompt: 100, completion: 200 } },
      pocOutcome: "poc_accepted",
      qualityOutcome: "accepted",
      cleanPass: true,
    };
    mockResponse({ success: true, data: pocResult });

    const result = await generatePoc("proj-1", "f-1");
    expect(result.poc.statement).toBe("PoC");
    expect(result.audit.latencyMs).toBe(5000);
    expect(result.pocOutcome).toBe("poc_accepted");
    expect(result.qualityOutcome).toBe("accepted");
    expect(result.cleanPass).toBe(true);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.projectId).toBe("proj-1");
    expect(body.findingId).toBe("f-1");
  });

  it("forwards non-clean PoC outcomes with claimDiagnostics", async () => {
    const pocResult = {
      findingId: "f-2",
      poc: { statement: "", detail: "" },
      audit: { latencyMs: 8000 },
      pocOutcome: "poc_inconclusive",
      qualityOutcome: "inconclusive",
      cleanPass: false,
      claimDiagnostics: { lifecycleCounts: { rejected: 2, retried: 1 } },
    };
    mockResponse({ success: true, data: pocResult });

    const result = await generatePoc("proj-1", "f-2");
    expect(result.cleanPass).toBe(false);
    expect(result.pocOutcome).toBe("poc_inconclusive");
    expect(result.claimDiagnostics?.lifecycleCounts).toEqual({ rejected: 2, retried: 1 });
    expect(result.audit.tokenUsage).toBeUndefined();
  });
});

describe("fetchSourceFiles", () => {
  it("calls GET source/files", async () => {
    const files = [{ relativePath: "main.c", size: 100, language: "c" }];
    mockResponse({ success: true, data: files });

    const result = await fetchSourceFiles("proj-1");
    expect(result).toEqual(files);
    expect(mockFetch.mock.calls[0][0]).toContain("/source/files");
  });
});

describe("fetchSourceFileContent", () => {
  it("encodes path in URL", async () => {
    mockResponse({ success: true, data: { path: "src/main.c", content: "code", language: "c", size: 100 } });

    await fetchSourceFileContent("proj-1", "src/main.c");

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("path=src%2Fmain.c");
  });
});

describe("cloneSource", () => {
  it("sends POST source/clone with canonical { gitUrl, branch } body", async () => {
    mockResponse({ success: true, data: { fileCount: 0, files: [] } });

    await cloneSource("proj-1", "https://example.com/repo.git", "main");

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toContain("/api/projects/proj-1/source/clone");
    expect(opts.method).toBe("POST");
    const body = JSON.parse(opts.body);
    expect(body).toEqual({ gitUrl: "https://example.com/repo.git", branch: "main" });
    expect(body.url).toBeUndefined();
  });

  it("omits branch when not provided", async () => {
    mockResponse({ success: true, data: { fileCount: 0, files: [] } });

    await cloneSource("proj-1", "https://example.com/repo.git");

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.gitUrl).toBe("https://example.com/repo.git");
    expect(body.branch).toBeUndefined();
  });
});
