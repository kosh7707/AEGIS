import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchDynamicModuleReport,
  fetchProjectReport,
  fetchStaticModuleReport,
  fetchTestModuleReport,
  generateCustomReport,
} from "./report";

vi.mock("./core", async () => {
  const actual = await vi.importActual<typeof import("./core")>("./core");
  return {
    ...actual,
    apiFetch: vi.fn(),
  };
});

import { ApiError, apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

const emptyModuleReport = {
  meta: {
    generatedAt: "2026-04-10T01:00:00Z",
    projectId: "proj-1",
    projectName: "Payments",
    module: "static_analysis",
  },
  summary: {
    totalFindings: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byStatus: {},
    bySource: {},
  },
  runs: [],
  findings: [],
  gateResults: [],
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("fetchProjectReport", () => {
  it("GETs /api/projects/:pid/report without filters", async () => {
    const report = { projectId: "proj-1", findings: [] };
    mockApiFetch.mockResolvedValue({ success: true, data: report });

    const result = await fetchProjectReport("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/report");
    expect(result).toEqual(report);
  });

  it("GETs with query string when filters are provided", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: {} });

    await fetchProjectReport("proj-1", { severity: "high", runId: "run-1" });

    const calledUrl = mockApiFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("severity=high");
    expect(calledUrl).toContain("runId=run-1");
  });
});

describe.each([
  ["fetchStaticModuleReport", fetchStaticModuleReport, "static"],
  ["fetchDynamicModuleReport", fetchDynamicModuleReport, "dynamic"],
  ["fetchTestModuleReport", fetchTestModuleReport, "test"],
] as const)("%s", (_name, fetcher, slug) => {
  it(`GETs /api/projects/:pid/report/${slug} without filters and returns ModuleReport`, async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: emptyModuleReport });

    const result = await fetcher("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith(`/api/projects/proj-1/report/${slug}`);
    expect(result).toEqual(emptyModuleReport);
  });

  it(`serializes all ReportFilter params for /api/projects/:pid/report/${slug}`, async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: emptyModuleReport });

    await fetcher("proj-1", {
      from: "2026-04-01",
      to: "2026-04-30",
      severity: "high",
      status: "open",
      runId: "run-42",
    });

    const calledUrl = mockApiFetch.mock.calls[0][0] as string;
    expect(calledUrl.startsWith(`/api/projects/proj-1/report/${slug}?`)).toBe(true);
    expect(calledUrl).toContain("from=2026-04-01");
    expect(calledUrl).toContain("to=2026-04-30");
    expect(calledUrl).toContain("severity=high");
    expect(calledUrl).toContain("status=open");
    expect(calledUrl).toContain("runId=run-42");
  });

  it(`returns the empty ModuleReport shape when the module has no findings (${slug})`, async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: emptyModuleReport });

    const result = await fetcher("proj-1");

    expect(result.findings).toEqual([]);
    expect(result.runs).toEqual([]);
    expect(result.summary.totalFindings).toBe(0);
  });

  it(`propagates ApiError from the error envelope (${slug})`, async () => {
    mockApiFetch.mockRejectedValue(
      new ApiError("server fail", "INTERNAL_ERROR", false, "req-1"),
    );

    await expect(fetcher("proj-1")).rejects.toBeInstanceOf(ApiError);
  });
});

describe("generateCustomReport", () => {
  it("POSTs to /api/projects/:pid/report/custom and returns reportId", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: { reportId: "rpt-99" } });

    const result = await generateCustomReport("proj-1", { reportTitle: "My Report", language: "ko" });

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/projects/proj-1/report/custom",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ reportTitle: "My Report", language: "ko" }),
      }),
    );
    expect(result.reportId).toBe("rpt-99");
  });
});
