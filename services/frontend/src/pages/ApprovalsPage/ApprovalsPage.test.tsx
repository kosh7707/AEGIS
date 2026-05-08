import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ApprovalsPage } from "./ApprovalsPage";

const mockNavigate = vi.fn();
const futureDate = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();
const pastDate = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();

const mockApprovals = [
  {
    id: "APR-0058",
    actionType: "gate.override",
    requestedBy: "analyst-1",
    targetId: "g-2",
    projectId: "p-1",
    reason: "긴급 릴리즈 필요",
    status: "pending",
    expiresAt: futureDate(365),
    createdAt: "2026-03-25T10:00:00Z",
    impactSummary: {
      failedRules: 2,
      ignoredFindings: 5,
      severityBreakdown: { critical: 1, high: 3 },
    },
    targetSnapshot: {
      runId: "1284",
      commit: "f8a1c3d3e2",
      branch: "main",
      profile: "prod-strict-v3",
      action: "gate.override",
    },
  },
  {
    id: "APR-0042",
    actionType: "finding.accepted_risk",
    requestedBy: "dev-1",
    targetId: "f-5",
    projectId: "p-1",
    reason: "오탐",
    status: "approved",
    decision: { decidedBy: "lead-1", decidedAt: pastDate(2), comment: "확인함" },
    expiresAt: pastDate(1),
    createdAt: pastDate(3),
  },
] as const;

const mockFetchApprovals = vi.fn();
const mockDecideApproval = vi.fn();
const mockFetchApprovalDetail = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("@/common/api/approval", () => ({
  fetchProjectApprovals: (...args: unknown[]) => mockFetchApprovals(...args),
  decideApproval: (...args: unknown[]) => mockDecideApproval(...args),
  fetchApprovalDetail: (...args: unknown[]) => mockFetchApprovalDetail(...args),
}));

vi.mock("@/common/api/core", () => ({ logError: vi.fn() }));
vi.mock("@/common/contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

function renderPage(initialEntry = "/projects/p-1/approvals") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/projects/:projectId/approvals" element={<ApprovalsPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ApprovalsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchApprovals.mockResolvedValue([...mockApprovals]);
    mockDecideApproval.mockResolvedValue(mockApprovals[0]);
    mockFetchApprovalDetail.mockImplementation(async (id: string) => {
      const found = mockApprovals.find((a) => a.id === id);
      if (!found) throw new Error("not found");
      return found;
    });
  });

  it("shows loading feedback before approvals resolve", () => {
    mockFetchApprovals.mockImplementation(() => new Promise(() => {}));
    renderPage();
    expect(screen.getByText("승인 요청 로딩 중...")).toBeInTheDocument();
  });

  it("renders the pending row by default and exposes status counts on filter tabs", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchApprovals).toHaveBeenCalledWith("p-1"));
    expect(await screen.findByRole("heading", { name: "승인 큐" })).toBeInTheDocument();

    const filterTablist = screen.getByRole("tablist", { name: "승인 요청 상태 필터" });
    const pendingTab = within(filterTablist).getByRole("tab", { name: /대기/ });
    expect(pendingTab).toHaveAttribute("aria-selected", "true");
    expect(within(pendingTab).getByText("1")).toBeInTheDocument();

    const approvedTab = within(filterTablist).getByRole("tab", { name: /승인됨/ });
    expect(within(approvedTab).getByText("1")).toBeInTheDocument();

    // master rail + document title both render the action label
    expect(screen.getAllByText("Quality Gate 오버라이드").length).toBeGreaterThan(0);
    expect(screen.queryByText("Finding 위험 수용")).not.toBeInTheDocument();
  });

  it("renders the inline status sub line when there is pending work", async () => {
    renderPage();
    const status = await screen.findByLabelText("승인 큐 현재 상태");
    expect(status).toHaveClass("approvals-page__sub");
    // pending count is 1 — emphasized via the .num span
    expect(within(status).getByText("1")).toHaveClass("num");
  });

  it("filters to approved approvals and shows the decision blockquote", async () => {
    renderPage();

    await waitFor(() =>
      expect(screen.getAllByText("Quality Gate 오버라이드").length).toBeGreaterThan(0),
    );
    const filterTablist = screen.getByRole("tablist", { name: "승인 요청 상태 필터" });
    fireEvent.click(within(filterTablist).getByRole("tab", { name: /승인됨/ }));

    await waitFor(() => expect(screen.queryByText("Quality Gate 오버라이드")).not.toBeInTheDocument());
    expect(screen.getAllByText("Finding 위험 수용").length).toBeGreaterThan(0);
    expect(screen.getByText(/"확인함"/)).toBeInTheDocument();

    fireEvent.click(within(filterTablist).getByRole("tab", { name: /^거부/ }));
    expect(await screen.findByText("거부된 요청이 없습니다")).toBeInTheDocument();
  });

  it("routes approval targets to their project detail pages", async () => {
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /Gate 결과 보기/ })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /Gate 결과 보기/ }));

    const filterTablist = screen.getByRole("tablist", { name: "승인 요청 상태 필터" });
    fireEvent.click(within(filterTablist).getByRole("tab", { name: /승인됨/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Finding 보기/ }));

    expect(mockNavigate).toHaveBeenNthCalledWith(1, "/projects/p-1/quality-gate");
    expect(mockNavigate).toHaveBeenNthCalledWith(2, "/projects/p-1/vulnerabilities");
  });

  it("submits an approval decision with an inline comment and reloads the list", async () => {
    renderPage();

    await waitFor(() => expect(screen.getByText("긴급 릴리즈 필요")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText(/결정 사유/), {
      target: { value: "승인 사유" },
    });
    fireEvent.click(screen.getByRole("button", { name: "승인" }));

    await waitFor(() =>
      expect(mockDecideApproval).toHaveBeenCalledWith("APR-0058", "approved", undefined, "승인 사유"),
    );
    await waitFor(() => expect(mockFetchApprovals).toHaveBeenCalledTimes(2));
    expect(mockToast.success).toHaveBeenCalledWith("승인 완료");
  });

  it("submits a rejection decision without a comment and reloads the list", async () => {
    renderPage();

    await screen.findByText("긴급 릴리즈 필요");
    fireEvent.click(screen.getByRole("button", { name: "거부" }));

    await waitFor(() =>
      expect(mockDecideApproval).toHaveBeenCalledWith("APR-0058", "rejected", undefined, undefined),
    );
    await waitFor(() => expect(mockFetchApprovals).toHaveBeenCalledTimes(2));
    expect(mockToast.success).toHaveBeenCalledWith("거부 완료");
  });

  it("falls back to impactSummary text when findings are absent (S2 H4 contract)", async () => {
    renderPage();

    const tabPanel = await screen.findByRole("tabpanel");
    // impactSummary verbatim — no findings in mock so the doc shows the summary line
    expect(
      within(tabPanel).getByText("차단 규칙 2 / 무시 발견 5 / critical 1, high 3"),
    ).toBeInTheDocument();
  });

  it("renders targetSnapshot meta inline in the document header", async () => {
    renderPage();

    const tabPanel = await screen.findByRole("tabpanel");
    expect(within(tabPanel).getByText("Run")).toBeInTheDocument();
    expect(within(tabPanel).getByText("#1284")).toBeInTheDocument();
    expect(within(tabPanel).getByText("Commit")).toBeInTheDocument();
    expect(within(tabPanel).getByText("f8a1c3d")).toBeInTheDocument();
    expect(within(tabPanel).getByText("Profile")).toBeInTheDocument();
    expect(within(tabPanel).getByText("prod-strict-v3")).toBeInTheDocument();
  });

  it("logs and toasts when approvals fail to load", async () => {
    const error = new Error("load failed");
    mockFetchApprovals.mockRejectedValue(error);

    renderPage();

    await waitFor(() =>
      expect(mockToast.error).toHaveBeenCalledWith("승인 요청 목록을 불러올 수 없습니다."),
    );
    expect(await screen.findByText("처리할 승인 요청이 없습니다")).toBeInTheDocument();
  });

  it("does not fetch approvals and shows an empty state when the route has no project id", async () => {
    render(
      <MemoryRouter initialEntries={["/approvals"]}>
        <Routes>
          <Route path="/approvals" element={<ApprovalsPage />} />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(screen.getByText("처리할 승인 요청이 없습니다")).toBeInTheDocument(),
    );
    expect(mockFetchApprovals).not.toHaveBeenCalled();
    expect(mockToast.error).not.toHaveBeenCalled();
  });

  it("shows the empty state with 7-day stats hint when only resolved approvals exist", async () => {
    mockFetchApprovals.mockResolvedValue([
      {
        id: "APR-X",
        actionType: "gate.override",
        requestedBy: "u",
        targetId: "g",
        projectId: "p-1",
        reason: "r",
        status: "approved",
        decision: { decidedBy: "lead", decidedAt: pastDate(2), comment: "ok" },
        expiresAt: pastDate(1),
        createdAt: pastDate(3),
      },
    ]);
    renderPage();

    expect(await screen.findByText("처리할 승인 요청이 없습니다")).toBeInTheDocument();
    // pending=0 → inline sub line hides
    expect(screen.queryByLabelText("승인 큐 현재 상태")).not.toBeInTheDocument();
    expect(screen.getByText(/지난 7일.+결정.+평균/)).toBeInTheDocument();
  });

  it("supports keyboard ArrowDown navigation across the list rail", async () => {
    mockFetchApprovals.mockResolvedValue([
      mockApprovals[0],
      {
        ...mockApprovals[1],
        id: "APR-PEND-2",
        status: "pending" as const,
        expiresAt: futureDate(2),
        createdAt: pastDate(0.5),
        decision: undefined,
      },
    ]);

    renderPage();

    const masterList = await screen.findByRole("tablist", { name: "승인 요청 목록" });
    const initialTabs = within(masterList).getAllByRole("tab");
    expect(initialTabs[0]).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(masterList, { key: "ArrowDown" });

    await waitFor(() => {
      const updatedTabs = within(masterList).getAllByRole("tab");
      expect(updatedTabs[1]).toHaveAttribute("aria-selected", "true");
    });
  });

  it("fetches canonical detail (GET /api/approvals/:id) when a rail row is clicked", async () => {
    renderPage();

    await screen.findByText("긴급 릴리즈 필요");
    const masterList = await screen.findByRole("tablist", { name: "승인 요청 목록" });
    const tabs = within(masterList).getAllByRole("tab");
    fireEvent.click(tabs[0]);

    await waitFor(() =>
      expect(mockFetchApprovalDetail).toHaveBeenCalledWith("APR-0058"),
    );
  });

  it("does not crash when fetchApprovalDetail rejects (logs and falls back to list data)", async () => {
    mockFetchApprovalDetail.mockRejectedValueOnce(new Error("detail fetch boom"));

    renderPage();

    await screen.findByText("긴급 릴리즈 필요");
    const masterList = await screen.findByRole("tablist", { name: "승인 요청 목록" });
    const tabs = within(masterList).getAllByRole("tab");
    fireEvent.click(tabs[0]);

    // List-derived reason still renders since detail is optional/best-effort.
    expect(screen.getByText("긴급 릴리즈 필요")).toBeInTheDocument();
  });

  it("renders the missing-detail message when neither findings nor impactSummary exist", async () => {
    mockFetchApprovals.mockResolvedValue([
      {
        ...mockApprovals[0],
        id: "APR-NO-DETAIL",
        impactSummary: undefined,
        targetSnapshot: undefined,
      },
    ]);

    renderPage();

    const tabPanel = await screen.findByRole("tabpanel");
    expect(within(tabPanel).getByText("상세 항목이 첨부되지 않았습니다.")).toBeInTheDocument();
    // No targetSnapshot → meta header collapses (no doc__meta row rendered)
    expect(within(tabPanel).queryByText("Run")).not.toBeInTheDocument();
  });
});
