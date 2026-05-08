import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchApprovalCount, fetchApprovalDetail } from "./approval";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("fetchApprovalCount", () => {
  it("GETs /api/projects/:pid/approvals/count and returns pending count", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: { pending: 3, total: 5 } });

    const result = await fetchApprovalCount("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/approvals/count");
    expect(result.pending).toBe(3);
  });

  it("returns total field (provisional, S1-added)", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: { pending: 1, total: 2 } });

    const result = await fetchApprovalCount("proj-2");

    expect(result.total).toBe(2);
  });
});

describe("fetchApprovalDetail", () => {
  it("GETs /api/approvals/:id and returns ApprovalRequest", async () => {
    const approval = {
      id: "appr-001",
      actionType: "gate.override",
      requestedBy: "user-1",
      targetId: "gate-1",
      projectId: "proj-1",
      reason: "emergency",
      status: "pending",
      expiresAt: "2026-06-01T00:00:00.000Z",
      createdAt: "2026-05-01T00:00:00.000Z",
    };
    mockApiFetch.mockResolvedValue({ success: true, data: approval });

    const result = await fetchApprovalDetail("appr-001");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/approvals/appr-001");
    expect(result).toEqual(approval);
  });

  it("encodes the approvalId in the URL path", async () => {
    const approval = {
      id: "appr/special",
      actionType: "gate.override",
      requestedBy: "user-1",
      targetId: "gate-1",
      projectId: "proj-1",
      reason: "test",
      status: "pending",
      expiresAt: "2026-06-01T00:00:00.000Z",
      createdAt: "2026-05-01T00:00:00.000Z",
    };
    mockApiFetch.mockResolvedValue({ success: true, data: approval });

    await fetchApprovalDetail("appr/special");

    expect(mockApiFetch).toHaveBeenCalledWith(
      expect.stringContaining("appr%2Fspecial"),
    );
  });

  it("returns impactSummary and targetSnapshot when present", async () => {
    const approval = {
      id: "appr-002",
      actionType: "gate.override",
      requestedBy: "user-2",
      targetId: "gate-2",
      projectId: "proj-1",
      reason: "override",
      status: "pending",
      impactSummary: { failedRules: 2, ignoredFindings: 5 },
      targetSnapshot: { runId: "run-1", commit: "abc123" },
      expiresAt: "2026-06-01T00:00:00.000Z",
      createdAt: "2026-05-01T00:00:00.000Z",
    };
    mockApiFetch.mockResolvedValue({ success: true, data: approval });

    const result = await fetchApprovalDetail("appr-002");

    expect(result.impactSummary?.failedRules).toBe(2);
    expect(result.targetSnapshot).toBeDefined();
  });
});
