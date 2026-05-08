import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchProjectReport,
  generateCustomReport,
} from "./report";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

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
