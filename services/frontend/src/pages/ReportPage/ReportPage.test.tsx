import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ProjectReport } from "@aegis/shared";
import { ApiError } from "@/common/api/client";
import { ReportPage } from "./ReportPage";

const mockFetchProjectReport = vi.fn();
const mockFetchStaticModuleReport = vi.fn();
const mockFetchDynamicModuleReport = vi.fn();
const mockFetchTestModuleReport = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("@/common/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/common/api/client")>("@/common/api/client");
  return {
    ...actual,
    fetchProjectReport: (...args: unknown[]) => mockFetchProjectReport(...args),
    fetchStaticModuleReport: (...args: unknown[]) => mockFetchStaticModuleReport(...args),
    fetchDynamicModuleReport: (...args: unknown[]) => mockFetchDynamicModuleReport(...args),
    fetchTestModuleReport: (...args: unknown[]) => mockFetchTestModuleReport(...args),
    logError: vi.fn(),
  };
});

vi.mock("@/common/contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

vi.mock("./components/CustomReportModal/CustomReportModal", () => ({
  CustomReportModal: ({ projectId, onClose }: { projectId: string; onClose: () => void }) => (
    <div data-testid="custom-report-modal">
      <span>custom report for {projectId}</span>
      <button onClick={onClose}>close custom report</button>
    </div>
  ),
}));

function makeReport(): ProjectReport {
  return {
    generatedAt: "2026-04-10T01:00:00Z",
    projectId: "project-1",
    projectName: "Payments Platform",
    modules: {
      static: {
        meta: {
          generatedAt: "2026-04-10T01:00:00Z",
          projectId: "project-1",
          projectName: "Payments Platform",
          module: "static_analysis",
        },
        summary: {
          totalFindings: 2,
          bySeverity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
          byStatus: { open: 1, fixed: 1 },
          bySource: { sast: 2 },
        },
        runs: [
          {
            run: {
              id: "run-1",
              projectId: "project-1",
              module: "static_analysis",
              status: "completed",
              trigger: "manual",
              createdAt: "2026-04-10T01:00:00Z",
              updatedAt: "2026-04-10T01:05:00Z",
              startedAt: "2026-04-10T01:00:00Z",
              completedAt: "2026-04-10T01:05:00Z",
              findingCount: 2,
            },
            gate: {
              id: "gate-1",
              runId: "run-1",
              projectId: "project-1",
              status: "pass",
              rules: [],
              evaluatedAt: "2026-04-10T01:05:00Z",
              createdAt: "2026-04-10T01:05:00Z",
            },
          },
        ],
        findings: [
          {
            finding: {
              id: "finding-1",
              projectId: "project-1",
              runId: "run-1",
              module: "static_analysis",
              severity: "critical",
              status: "open",
              sourceType: "sast",
              title: "Critical auth bypass",
              description: "Critical auth bypass description",
              location: "src/auth.ts:12",
              ruleId: "AUTH-001",
              evidenceCount: 1,
              createdAt: "2026-04-10T01:00:00Z",
            },
            evidenceRefs: [
              {
                id: "evidence-1",
                findingId: "finding-1",
                kind: "screenshot",
                label: "Screenshot",
                storagePath: "/tmp/evidence.png",
                uploadedAt: "2026-04-10T01:00:00Z",
              },
            ],
          },
          {
            finding: {
              id: "finding-2",
              projectId: "project-1",
              runId: "run-1",
              module: "static_analysis",
              severity: "high",
              status: "fixed",
              sourceType: "sast",
              title: "Weak crypto",
              description: "Weak crypto description",
              location: "src/crypto.ts:22",
              ruleId: "CRYPTO-002",
              evidenceCount: 0,
              createdAt: "2026-04-10T01:00:00Z",
            },
            evidenceRefs: [],
          },
        ],
        gateResults: [],
      },
    },
    totalSummary: {
      totalFindings: 2,
      bySeverity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
      byStatus: { open: 1, fixed: 1 },
      bySource: { sast: 2 },
    },
    approvals: [
      {
        id: "approval-1",
        actionType: "gate.override",
        requestedBy: "alice",
        targetId: "gate-1",
        projectId: "project-1",
        reason: "Business exception",
        status: "approved",
        decision: {
          decidedBy: "bob",
          decidedAt: "2026-04-10T02:00:00Z",
        },
        expiresAt: "2026-04-11T02:00:00Z",
        createdAt: "2026-04-10T01:30:00Z",
      },
    ],
    auditTrail: [
      {
        id: "audit-1",
        timestamp: "2026-04-10T01:00:00Z",
        actor: "alice",
        action: "Static analysis completed",
        resource: "run",
        resourceId: "run-1",
        detail: {},
      },
    ],
  } as unknown as ProjectReport;
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/project-1/report"]}>
      <Routes>
        <Route path="/projects/:projectId/report" element={<ReportPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

function makeModuleReport(overrides: Partial<{ findings: unknown[]; runs: unknown[] }> = {}) {
  return {
    meta: {
      generatedAt: "2026-04-10T01:00:00Z",
      projectId: "project-1",
      projectName: "Payments Platform",
      module: "static_analysis",
    },
    summary: {
      totalFindings: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byStatus: {},
      bySource: {},
    },
    runs: overrides.runs ?? [],
    findings: overrides.findings ?? [],
    gateResults: [],
  } as unknown as ReturnType<typeof makeReport>["modules"]["static"];
}

describe("ReportPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchProjectReport.mockResolvedValue(makeReport());
    mockFetchStaticModuleReport.mockResolvedValue(makeModuleReport());
    mockFetchDynamicModuleReport.mockResolvedValue(makeModuleReport());
    mockFetchTestModuleReport.mockResolvedValue(makeModuleReport());
  });

  it("shows loading feedback before the report resolves", () => {
    mockFetchProjectReport.mockImplementation(() => new Promise(() => {}));

    renderPage();

    expect(screen.getByText("보고서 생성 중...")).toBeInTheDocument();
  });

  it("renders report content and only applies pending filters after confirmation", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalledWith("project-1", {}));
    expect(await screen.findByRole("heading", { level: 1, name: "보고서" })).toBeInTheDocument();
    expect(screen.getByText(/Critical auth bypass/i)).toBeInTheDocument();
    expect(document.title).toBe("AEGIS — 보고서");

    fireEvent.click(screen.getByRole("button", { name: /필터/i }));
    const startDateInput = document.querySelector('input[type="date"]') as HTMLInputElement | null;
    expect(startDateInput).not.toBeNull();
    fireEvent.change(startDateInput as HTMLInputElement, { target: { value: "2026-04-01" } });

    expect(mockFetchProjectReport).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "적용" }));

    await waitFor(() => {
      expect(mockFetchProjectReport).toHaveBeenCalledTimes(2);
      expect(mockFetchProjectReport).toHaveBeenLastCalledWith("project-1", { from: "2026-04-01" });
    });
  });

  it("shows retry affordance for retryable load errors and retries the fetch", async () => {
    mockFetchProjectReport
      .mockRejectedValueOnce(new ApiError("temporary backend issue", "TEMP", true, "req-1"))
      .mockResolvedValueOnce(makeReport());

    renderPage();

    expect(await screen.findByText("보고서를 불러올 수 없습니다")).toBeInTheDocument();
    expect(mockToast.error).toHaveBeenCalled();
    expect(mockToast.error.mock.calls[0]?.[1]).toMatchObject({ label: "다시 시도" });

    fireEvent.click(screen.getByRole("button", { name: "다시 시도" }));

    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("heading", { level: 1, name: "보고서" })).toBeInTheDocument();
  });

  it("opens and closes the custom report modal", async () => {
    renderPage();

    await screen.findByRole("heading", { level: 1, name: "보고서" });
    fireEvent.click(screen.getByRole("button", { name: /커스텀 보고서/i }));

    expect(await screen.findByTestId("custom-report-modal")).toBeInTheDocument();
    expect(screen.getByText("custom report for project-1")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "close custom report" }));
    await waitFor(() => expect(screen.queryByTestId("custom-report-modal")).not.toBeInTheDocument());
  });

  it("lazy-loads the static module report when the Static tab is selected", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalledWith("project-1", {}));
    expect(mockFetchStaticModuleReport).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("tab", { name: "정적 분석" }));

    await waitFor(() => expect(mockFetchStaticModuleReport).toHaveBeenCalledWith("project-1", {}));
  });

  it("lazy-loads the dynamic module report when the Dynamic tab is selected", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalled());
    expect(mockFetchDynamicModuleReport).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("tab", { name: "동적 분석" }));

    await waitFor(() => expect(mockFetchDynamicModuleReport).toHaveBeenCalledWith("project-1", {}));
  });

  it("lazy-loads the test module report when the Test tab is selected", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalled());
    expect(mockFetchTestModuleReport).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("tab", { name: "동적 테스트" }));

    await waitFor(() => expect(mockFetchTestModuleReport).toHaveBeenCalledWith("project-1", {}));
  });

  it("applies per-module filters only to the active module fetch and leaves the aggregate fetch alone", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalledWith("project-1", {}));
    expect(mockFetchProjectReport).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("tab", { name: "정적 분석" }));
    await waitFor(() => expect(mockFetchStaticModuleReport).toHaveBeenCalledWith("project-1", {}));

    fireEvent.click(screen.getByRole("button", { name: /필터/i }));
    const startDateInput = document.querySelector('input[type="date"]') as HTMLInputElement | null;
    expect(startDateInput).not.toBeNull();
    fireEvent.change(startDateInput as HTMLInputElement, { target: { value: "2026-04-01" } });
    fireEvent.click(screen.getByRole("button", { name: "적용" }));

    await waitFor(() => {
      expect(mockFetchStaticModuleReport).toHaveBeenLastCalledWith("project-1", { from: "2026-04-01" });
    });

    // Aggregate endpoint must NOT receive the module-scoped filter.
    expect(mockFetchProjectReport).toHaveBeenCalledTimes(1);
  });

  it("renders an empty-module empty state when the module fetch returns no findings or runs", async () => {
    mockFetchDynamicModuleReport.mockResolvedValue(makeModuleReport({ findings: [], runs: [] }));

    renderPage();

    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("tab", { name: "동적 분석" }));

    expect(
      await screen.findByText("해당 모듈에 표시할 탐지 항목이 없습니다."),
    ).toBeInTheDocument();
  });

  it("surfaces a toast when the lazy module fetch fails", async () => {
    mockFetchTestModuleReport.mockRejectedValueOnce(
      new ApiError("module fetch failed", "INTERNAL_ERROR", false, "req-2"),
    );

    renderPage();
    await waitFor(() => expect(mockFetchProjectReport).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("tab", { name: "동적 테스트" }));

    await waitFor(() => expect(mockToast.error).toHaveBeenCalled());
  });

  it("shows the unavailable state without fetching when no project id is present", async () => {
    render(
      <MemoryRouter initialEntries={["/report"]}>
        <Routes>
          <Route path="/report" element={<ReportPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("보고서를 생성할 수 없습니다")).toBeInTheDocument();
    expect(screen.getByText("분석을 먼저 실행해주세요")).toBeInTheDocument();
    expect(mockFetchProjectReport).not.toHaveBeenCalled();
  });
});
