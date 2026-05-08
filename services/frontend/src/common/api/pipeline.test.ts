import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock apiFetch before importing pipeline module
vi.mock("./core", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "./core";
import {
  createBuildTarget,
  discoverBuildTargets,
  runPipelineTarget,
  preparePipeline,
  preparePipelineTarget,
  fetchPipelineStatus,
} from "./pipeline";
import type { PipelineStatusResponse } from "./pipeline";

const mockApiFetch = vi.mocked(apiFetch);

beforeEach(() => {
  vi.clearAllMocks();
});

// ── createBuildTarget ──

describe("createBuildTarget", () => {
  it("sends POST with buildSystem in body", async () => {
    const target = { id: "t-1", name: "gateway", projectId: "p-1" };
    mockApiFetch.mockResolvedValue({ success: true, data: target });

    const result = await createBuildTarget("p-1", {
      name: "gateway",
      relativePath: "gateway/",
      buildSystem: "cmake",
    });

    expect(result).toEqual(target);
    const [url, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/projects/p-1/targets");
    expect(opts.method).toBe("POST");
    const body = JSON.parse(opts.body as string);
    expect(body.buildSystem).toBe("cmake");
  });

  it("sends POST without buildSystem when not provided", async () => {
    const target = { id: "t-2", name: "body", projectId: "p-1" };
    mockApiFetch.mockResolvedValue({ success: true, data: target });

    await createBuildTarget("p-1", { name: "body", relativePath: "body/" });

    const [, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(opts.body as string);
    expect(body.buildSystem).toBeUndefined();
  });
});

// ── discoverBuildTargets ──

describe("discoverBuildTargets", () => {
  it("sends POST and returns full result shape with count fields", async () => {
    const targets = [{ id: "t-3", name: "discovered" }];
    mockApiFetch.mockResolvedValue({
      success: true,
      data: { discovered: 2, created: 1, targets, elapsedMs: 42 },
    });

    const result = await discoverBuildTargets("p-1");

    const [url, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/projects/p-1/targets/discover");
    expect((opts as RequestInit).method).toBe("POST");
    expect(result.discovered).toBe(2);
    expect(result.created).toBe(1);
    expect(result.elapsedMs).toBe(42);
    expect(result.targets).toEqual(targets);
  });

  it("defaults count fields to 0 when backend omits them", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: {} });

    const result = await discoverBuildTargets("p-1");

    expect(result.discovered).toBe(0);
    expect(result.created).toBe(0);
    expect(result.elapsedMs).toBe(0);
    expect(result.targets).toEqual([]);
  });
});

// ── runPipelineTarget ──

describe("runPipelineTarget", () => {
  it("sends POST and returns pipelineId + targetId + status", async () => {
    mockApiFetch.mockResolvedValue({
      success: true,
      data: { pipelineId: "pipe-99", targetId: "t-7", status: "running" },
    });

    const result = await runPipelineTarget("p-1", "t-7");

    const [url, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/projects/p-1/pipeline/run/t-7");
    expect((opts as RequestInit).method).toBe("POST");
    expect(result.pipelineId).toBe("pipe-99");
    expect(result.targetId).toBe("t-7");
    expect(result.status).toBe("running");
  });
});

// ── fetchPipelineStatus ──

describe("fetchPipelineStatus", () => {
  it("returns PipelineStatusResponse with message/error/isRunning fields", async () => {
    const statusData: PipelineStatusResponse = {
      targets: [
        {
          id: "t-1",
          name: "gateway",
          status: "building",
          phase: "build",
          message: "Compiling...",
          error: undefined,
        },
      ],
      isRunning: true,
      readyCount: 0,
      failedCount: 0,
      totalCount: 1,
    };
    mockApiFetch.mockResolvedValue({ success: true, data: statusData });

    const result = await fetchPipelineStatus("p-1");

    expect(result.isRunning).toBe(true);
    expect(result.targets[0].message).toBe("Compiling...");
    expect(result.targets[0].error).toBeUndefined();
  });
});

// ── preparePipeline ──

describe("preparePipeline", () => {
  it("sends POST to /pipeline/prepare and returns preparationId + status", async () => {
    mockApiFetch.mockResolvedValue({
      success: true,
      data: { preparationId: "prep-1", status: "running" },
    });

    const result = await preparePipeline("p-1");

    const [url, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/projects/p-1/pipeline/prepare");
    expect((opts as RequestInit).method).toBe("POST");
    expect(result.preparationId).toBe("prep-1");
    expect(result.status).toBe("running");
  });

  it("sends targetIds in body when provided", async () => {
    mockApiFetch.mockResolvedValue({
      success: true,
      data: { preparationId: "prep-2", status: "running" },
    });

    await preparePipeline("p-1", ["t-1", "t-2"]);

    const [, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((opts as RequestInit).body as string);
    expect(body.targetIds).toEqual(["t-1", "t-2"]);
    expect((opts.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("omits targetIds from body when not provided", async () => {
    mockApiFetch.mockResolvedValue({
      success: true,
      data: { preparationId: "prep-3", status: "running" },
    });

    await preparePipeline("p-1");

    const [, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((opts as RequestInit).body as string);
    expect(body.targetIds).toBeUndefined();
  });
});

// ── preparePipelineTarget ──

describe("preparePipelineTarget", () => {
  it("sends POST to /pipeline/prepare/:targetId and returns preparationId + targetId + status", async () => {
    mockApiFetch.mockResolvedValue({
      success: true,
      data: { preparationId: "prep-10", targetId: "t-5", status: "running" },
    });

    const result = await preparePipelineTarget("p-1", "t-5");

    const [url, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/projects/p-1/pipeline/prepare/t-5");
    expect((opts as RequestInit).method).toBe("POST");
    expect(result.preparationId).toBe("prep-10");
    expect(result.targetId).toBe("t-5");
    expect(result.status).toBe("running");
  });
});
