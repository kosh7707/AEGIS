import React from "react";
import type { Run } from "@aegis/shared";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AnalysisHistoryPage } from "./AnalysisHistoryPage";

const mockNavigate = vi.fn();
const mockFetchProjectRuns = vi.fn();
const mockLogError = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("../../api/client", () => ({
  fetchProjectRuns: (...args: unknown[]) => mockFetchProjectRuns(...args),
  logError: (...args: unknown[]) => mockLogError(...args),
}));

vi.mock("../../contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

type HistoryRun = Run & {
  severitySummary?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
};

function makeRun(overrides: Partial<HistoryRun> = {}): HistoryRun {
  return {
    id: "run-1",
    projectId: "p-1",
    module: "static_analysis",
    status: "completed",
    analysisResultId: "analysis-1",
    findingCount: 3,
    createdAt: "2026-04-01T12:00:00Z",
    startedAt: "2026-04-01T12:00:00Z",
    endedAt: "2026-04-01T12:05:00Z",
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/p-1/analysis-history"]}>
      <Routes>
        <Route path="/projects/:projectId/analysis-history" element={<AnalysisHistoryPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("AnalysisHistoryPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchProjectRuns.mockResolvedValue([]);
  });

  it("renders runs sorted newest-first and navigates when a row is clicked", async () => {
    mockFetchProjectRuns.mockResolvedValue([
      makeRun({
        id: "run-older",
        module: "deep_analysis",
        status: "failed",
        createdAt: "2026-04-01T12:00:00Z",
        startedAt: "2026-04-01T12:00:00Z",
        endedAt: "2026-04-01T12:01:30Z",
      }),
      makeRun({
        id: "run-newer",
        module: "static_analysis",
        status: "completed",
        createdAt: "2026-04-02T12:00:00Z",
        startedAt: "2026-04-02T12:00:00Z",
        endedAt: "2026-04-02T12:02:00Z",
        severitySummary: { critical: 1, medium: 2 },
      }),
    ]);

    renderPage();

    await waitFor(() => expect(mockFetchProjectRuns).toHaveBeenCalledWith("p-1"));
    expect(await screen.findByRole("heading", { name: "Analysis History" })).toBeInTheDocument();
    expect(screen.getByText("2회 분석 실행됨")).toBeInTheDocument();

    const rows = screen.getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]!).getByText("정적 분석")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("심층 분석")).toBeInTheDocument();

    fireEvent.click(rows[1]!);
    expect(mockNavigate).toHaveBeenCalledWith("/projects/p-1/static-analysis");
  });

  it("shows a filter-specific empty state when no runs match the selected module", async () => {
    mockFetchProjectRuns.mockResolvedValue([
      makeRun({ id: "run-static", module: "static_analysis" }),
    ]);

    renderPage();

    await waitFor(() => expect(mockFetchProjectRuns).toHaveBeenCalledWith("p-1"));
    fireEvent.click(screen.getByRole("button", { name: "심층 분석" }));

    expect(await screen.findByText("해당 모듈의 분석 이력이 없습니다")).toBeInTheDocument();
  });

  it("logs and toasts when loading analysis history fails", async () => {
    const error = new Error("network down");
    mockFetchProjectRuns.mockRejectedValue(error);

    renderPage();

    await waitFor(() => expect(mockLogError).toHaveBeenCalledWith("Fetch analysis history", error));
    expect(mockToast.error).toHaveBeenCalledWith("분석 이력을 불러올 수 없습니다.");
    expect(await screen.findByText("아직 분석 이력이 없습니다")).toBeInTheDocument();
  });
});
