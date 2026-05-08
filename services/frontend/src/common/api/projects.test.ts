import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "./core";
import {
  fetchProjectOverview,
  updateProject,
} from "./projects";

const mockApiFetch = vi.mocked(apiFetch);

beforeEach(() => {
  vi.clearAllMocks();
});

// ── fetchProjectOverview ──

describe("fetchProjectOverview", () => {
  it("unwraps data from envelope and returns ProjectOverviewResponse", async () => {
    const overviewData = {
      project: { id: "p-1", name: "AEGIS" },
      fileCount: 100,
      summary: {
        totalVulnerabilities: 5,
        bySeverity: { critical: 1, high: 2, medium: 2, low: 0, info: 0 },
        byModule: { static: 3, deep: 2, dynamic: 0, test: 0 },
      },
      recentAnalyses: [],
    };
    mockApiFetch.mockResolvedValue({ success: true, data: overviewData });

    const result = await fetchProjectOverview("p-1");

    const [url] = mockApiFetch.mock.calls[0] as [string, ...unknown[]];
    expect(url).toBe("/api/projects/p-1/overview");
    // Must return inner data shape, not the envelope
    expect(result).toEqual(overviewData);
    expect((result as Record<string, unknown>).success).toBeUndefined();
    expect(result.project.id).toBe("p-1");
    expect(result.fileCount).toBe(100);
  });
});

// ── updateProject ──

describe("updateProject", () => {
  it("sends PUT to /api/projects/:id with name body", async () => {
    const project = { id: "p-1", name: "Renamed Project" };
    mockApiFetch.mockResolvedValue({ success: true, data: project });

    const result = await updateProject("p-1", { name: "Renamed Project" });

    const [url, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/projects/p-1");
    expect(opts.method).toBe("PUT");
    const body = JSON.parse(opts.body as string);
    expect(body.name).toBe("Renamed Project");
    expect(result).toEqual(project);
  });

  it("returns the updated project from data field", async () => {
    const project = { id: "p-2", name: "New Name" };
    mockApiFetch.mockResolvedValue({ success: true, data: project });

    const result = await updateProject("p-2", { name: "New Name" });

    expect(result.id).toBe("p-2");
    expect(result.name).toBe("New Name");
  });
});
