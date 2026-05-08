import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  runAnalysis,
  runDeepAnalysis,
  abortAnalysis,
  fetchAnalysisResultsList,
  deleteAnalysisResult,
  fetchFindingsSummary,
} from "./analysis";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("runAnalysis", () => {
  it("POSTs to /api/analysis/quick with projectId and buildTargetId", async () => {
    const responseData = { analysisId: "a1", buildTargetId: "bt1", executionId: "e1", status: "running" };
    mockApiFetch.mockResolvedValue({ success: true, data: responseData });

    const result = await runAnalysis("proj-1", "bt-1");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/analysis/quick",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ projectId: "proj-1", buildTargetId: "bt-1" }),
      }),
    );
    expect(result).toEqual(responseData);
  });
});

describe("runDeepAnalysis", () => {
  it("POSTs to /api/analysis/deep with projectId and buildTargetId", async () => {
    const responseData = { analysisId: "a2", buildTargetId: "bt2", executionId: "e2", status: "running" };
    mockApiFetch.mockResolvedValue({ success: true, data: responseData });

    const result = await runDeepAnalysis("proj-2", "bt-2");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/analysis/deep",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ projectId: "proj-2", buildTargetId: "bt-2" }),
      }),
    );
    expect(result).toEqual(responseData);
  });

  it("returns analysisId, buildTargetId, executionId, status from response", async () => {
    const responseData = { analysisId: "a3", buildTargetId: "bt3", executionId: "e3", status: "pending" };
    mockApiFetch.mockResolvedValue({ success: true, data: responseData });

    const result = await runDeepAnalysis("proj-3", "bt-3");

    expect(result.analysisId).toBe("a3");
    expect(result.status).toBe("pending");
  });
});

describe("abortAnalysis", () => {
  it("POSTs to /api/analysis/abort/:analysisId", async () => {
    mockApiFetch.mockResolvedValue({ success: true });

    await abortAnalysis("analysis-99");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/analysis/abort/analysis-99",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("resolves without returning a value", async () => {
    mockApiFetch.mockResolvedValue(undefined);

    const result = await abortAnalysis("analysis-50");

    expect(result).toBeUndefined();
  });
});

describe("fetchAnalysisResultsList", () => {
  it("GETs /api/analysis/results?projectId= and returns AnalysisResult[]", async () => {
    const results = [{ analysisId: "a1", status: "completed" }, { analysisId: "a2", status: "failed" }];
    mockApiFetch.mockResolvedValue({ success: true, data: results });

    const result = await fetchAnalysisResultsList("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/analysis/results?projectId=proj-1");
    expect(result).toEqual(results);
  });

  it("encodes projectId in query string", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: [] });

    await fetchAnalysisResultsList("proj/special id");

    expect(mockApiFetch).toHaveBeenCalledWith(
      expect.stringContaining("projectId=proj%2Fspecial%20id"),
    );
  });
});

describe("deleteAnalysisResult", () => {
  it("DELETEs /api/analysis/results/:analysisId", async () => {
    mockApiFetch.mockResolvedValue(undefined);

    await deleteAnalysisResult("analysis-42");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/analysis/results/analysis-42",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("resolves without returning a value", async () => {
    mockApiFetch.mockResolvedValue(undefined);

    const result = await deleteAnalysisResult("analysis-1");

    expect(result).toBeUndefined();
  });
});

describe("fetchFindingsSummary", () => {
  it("GETs /api/projects/:pid/findings/summary and returns typed FindingsSummary", async () => {
    const summary = {
      total: 10,
      bySeverity: { critical: 2, high: 5 },
      byStatus: { open: 8, fixed: 2 },
    };
    mockApiFetch.mockResolvedValue({ success: true, data: summary });

    const result = await fetchFindingsSummary("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/findings/summary");
    expect(result).toEqual(summary);
    // Typed access — no narrowing required.
    expect(result.total).toBe(10);
    expect(result.bySeverity?.critical).toBe(2);
    expect(result.byStatus?.open).toBe(8);
  });

  it("returns minimal shape with only total", async () => {
    const summary = { total: 0, bySeverity: {}, byStatus: {} };
    mockApiFetch.mockResolvedValue({ success: true, data: summary });

    const result = await fetchFindingsSummary("proj-2");

    expect(result.total).toBe(0);
    expect(result.bySeverity).toEqual({});
    expect(result.byStatus).toEqual({});
  });
});
