import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { QualityGateRunSection } from "./QualityGateRunSection";

const mockFetchGateRunResults = vi.fn();

vi.mock("@/common/api/gate", () => ({
  fetchGateRunResults: (...args: unknown[]) => mockFetchGateRunResults(...args),
}));
vi.mock("@/common/api/core", () => ({ logError: vi.fn() }));

const mockGates = [
  {
    id: "g-run-1",
    runId: "r-42",
    projectId: "p-1",
    status: "pass",
    rules: [{ ruleId: "no-critical", result: "passed", message: "Critical 없음", linkedFindingIds: [], current: 0, threshold: 0, unit: "count" }],
    evaluatedAt: "2026-04-01T10:00:00Z",
    createdAt: "2026-04-01T10:00:00Z",
    profileId: "prof-1",
  },
  {
    id: "g-run-2",
    runId: "r-42",
    projectId: "p-1",
    status: "fail",
    rules: [{ ruleId: "high-threshold", result: "failed", message: "High 3건 발견", linkedFindingIds: ["f-1"], current: 3, threshold: 2, unit: "count" }],
    evaluatedAt: "2026-04-01T09:00:00Z",
    createdAt: "2026-04-01T09:00:00Z",
    profileId: null,
  },
];

function renderSection(overrides?: Partial<{ projectId: string; runId: string }>) {
  return render(
    <QualityGateRunSection
      projectId={overrides?.projectId ?? "p-1"}
      runId={overrides?.runId ?? "r-42"}
      gateProfilesById={{}}
      onRequestOverride={vi.fn()}
    />,
  );
}

describe("QualityGateRunSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchGateRunResults.mockResolvedValue(mockGates);
  });

  it("calls fetchGateRunResults with projectId and runId", async () => {
    renderSection();
    await waitFor(() => expect(mockFetchGateRunResults).toHaveBeenCalledWith("p-1", "r-42"));
  });

  it("shows loading state initially", () => {
    mockFetchGateRunResults.mockImplementation(() => new Promise(() => {}));
    renderSection();
    expect(screen.getByText("불러오는 중...")).toBeInTheDocument();
  });

  it("renders gate cards after data resolves", async () => {
    renderSection();
    await waitFor(() => expect(screen.getByText("Critical 없음")).toBeInTheDocument());
    expect(screen.getByText("High 3건 발견")).toBeInTheDocument();
  });

  it("renders the runId label in the section header", async () => {
    renderSection();
    await waitFor(() => expect(screen.getByText("#r-42")).toBeInTheDocument());
  });

  it("renders empty placeholder when no gates for run", async () => {
    mockFetchGateRunResults.mockResolvedValue([]);
    renderSection();
    await waitFor(() =>
      expect(screen.getByText("이 Run에는 게이트 결과가 없습니다.")).toBeInTheDocument(),
    );
  });

  it("renders error state when fetch rejects", async () => {
    mockFetchGateRunResults.mockRejectedValue(new Error("server error"));
    renderSection();
    await waitFor(() =>
      expect(
        screen.getByText("이 Run의 게이트 결과를 불러올 수 없습니다."),
      ).toBeInTheDocument(),
    );
  });
});
