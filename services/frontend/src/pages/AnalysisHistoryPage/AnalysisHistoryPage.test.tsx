import React from "react";
import type { Run } from "@aegis/shared";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AnalysisHistoryPage } from "./AnalysisHistoryPage";

const mockNavigate = vi.fn();
const mockFetchProjectRuns = vi.fn();
const mockLogError = vi.fn();
const mockDeleteAnalysisResult = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("@/common/api/client", () => ({
  fetchProjectRuns: (...args: unknown[]) => mockFetchProjectRuns(...args),
  logError: (...args: unknown[]) => mockLogError(...args),
}));

vi.mock("@/common/api/analysis", () => ({
  deleteAnalysisResult: (...args: unknown[]) => mockDeleteAnalysisResult(...args),
}));

vi.mock("@/common/contexts/ToastContext", () => ({
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

function renderPage(
  initialEntries = ["/projects/p-1/analysis-history"],
  routePath = "/projects/:projectId/analysis-history",
) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <Routes>
        <Route path={routePath} element={<AnalysisHistoryPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("AnalysisHistoryPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchProjectRuns.mockResolvedValue([]);
  });

  it("shows loading feedback before the history request resolves", () => {
    mockFetchProjectRuns.mockImplementation(() => new Promise(() => {}));

    renderPage();

    expect(screen.getByText("분석 이력 로딩 중...")).toBeInTheDocument();
  });

  it("renders runs sorted newest-first with KPI, duration, and severity details, then navigates when a row is clicked", async () => {
    mockFetchProjectRuns.mockResolvedValue([
      makeRun({
        id: "run-older",
        module: "deep_analysis",
        status: "failed",
        analysisResultId: "analysis-deep",
        createdAt: "2026-04-01T12:00:00Z",
        startedAt: "2026-04-01T12:00:00Z",
        endedAt: "2026-04-01T12:01:30Z",
      }),
      makeRun({
        id: "run-newer",
        module: "static_analysis",
        status: "completed",
        analysisResultId: "analysis-static",
        createdAt: "2026-04-02T12:00:00Z",
        startedAt: "2026-04-02T12:00:00Z",
        endedAt: "2026-04-02T12:02:00Z",
        severitySummary: { critical: 1, medium: 2 },
      }),
    ]);

    renderPage();

    await waitFor(() => expect(mockFetchProjectRuns).toHaveBeenCalledWith("p-1"));
    expect(await screen.findByRole("heading", { name: "분석 이력" })).toBeInTheDocument();
    const toolbar = screen.getByRole("region", { name: "분석 이력 필터와 요약" });
    expect(within(toolbar).getByText("전체 실행")).toBeInTheDocument();
    expect(within(toolbar).getByText("완료")).toBeInTheDocument();
    expect(within(toolbar).getByText("실패")).toBeInTheDocument();
    expect(document.title).toBe("AEGIS — 분석 이력");

    const rows = screen.getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]!).getByText("정적 분석")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("1")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("2분")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("심층 분석")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("3")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("1분")).toBeInTheDocument();

    fireEvent.click(rows[1]!);
    expect(mockNavigate).toHaveBeenCalledWith("/projects/p-1/static-analysis?analysisId=analysis-static");

    fireEvent.click(rows[2]!);
    expect(mockNavigate).toHaveBeenCalledWith("/projects/p-1/static-analysis?analysisId=analysis-deep");
  });

  it("shows a filter-specific empty state when no runs match the selected module", async () => {
    mockFetchProjectRuns.mockResolvedValue([makeRun({ id: "run-static", module: "static_analysis" })]);

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

  it("does not fetch and shows the empty state when the route has no project id", async () => {
    render(
      <MemoryRouter initialEntries={["/analysis-history"]}>
        <Routes>
          <Route path="/analysis-history" element={<AnalysisHistoryPage />} />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("아직 분석 이력이 없습니다")).toBeInTheDocument());
    expect(mockFetchProjectRuns).not.toHaveBeenCalled();
    expect(mockToast.error).not.toHaveBeenCalled();
  });

  it("requests delete confirmation and reloads runs after delete succeeds", async () => {
    mockDeleteAnalysisResult.mockResolvedValue(undefined);
    mockFetchProjectRuns.mockResolvedValue([
      makeRun({
        id: "run-1",
        analysisResultId: "analysis-1",
        module: "static_analysis",
        status: "completed",
      }),
    ]);

    renderPage();

    await waitFor(() => expect(mockFetchProjectRuns).toHaveBeenCalledTimes(1));
    const deleteButton = await screen.findByRole("button", { name: /분석 결과 삭제/ });
    fireEvent.click(deleteButton);

    expect(await screen.findByText("분석 결과 삭제")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "삭제" }));

    await waitFor(() => expect(mockDeleteAnalysisResult).toHaveBeenCalledWith("analysis-1"));
    await waitFor(() => expect(mockFetchProjectRuns).toHaveBeenCalledTimes(2));
    expect(mockToast.success).toHaveBeenCalledWith("분석 결과를 삭제했습니다.");
  });

  it("toasts an error and keeps the row when delete fails", async () => {
    mockDeleteAnalysisResult.mockRejectedValue(new Error("nope"));
    mockFetchProjectRuns.mockResolvedValue([
      makeRun({ id: "run-1", analysisResultId: "analysis-1", status: "completed" }),
    ]);

    renderPage();

    await waitFor(() => expect(mockFetchProjectRuns).toHaveBeenCalledTimes(1));
    fireEvent.click(await screen.findByRole("button", { name: /분석 결과 삭제/ }));
    fireEvent.click(await screen.findByRole("button", { name: "삭제" }));

    await waitFor(() =>
      expect(mockToast.error).toHaveBeenCalledWith("분석 결과 삭제에 실패했습니다."),
    );
  });
});
