import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ApprovalsPage } from "./ApprovalsPage";

const mockNavigate = vi.fn();
const futureDate = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

const mockApprovals = [
  {
    id: "a-1",
    actionType: "gate.override",
    requestedBy: "analyst-1",
    targetId: "g-2",
    projectId: "p-1",
    reason: "긴급 릴리즈 필요",
    status: "pending",
    expiresAt: futureDate(365),
    createdAt: "2026-03-25T10:00:00Z",
  },
  {
    id: "a-2",
    actionType: "finding.accepted_risk",
    requestedBy: "dev-1",
    targetId: "f-5",
    projectId: "p-1",
    reason: "오탐",
    status: "approved",
    decision: { decidedBy: "lead-1", decidedAt: "2026-03-25T11:00:00Z", comment: "확인함" },
    expiresAt: "2026-03-26T10:00:00Z",
    createdAt: "2026-03-25T09:00:00Z",
  },
] as const;

const mockFetchApprovals = vi.fn();
const mockDecideApproval = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("../../api/approval", () => ({
  fetchProjectApprovals: (...args: unknown[]) => mockFetchApprovals(...args),
  decideApproval: (...args: unknown[]) => mockDecideApproval(...args),
}));

vi.mock("../../api/core", () => ({ logError: vi.fn() }));
vi.mock("../../contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/p-1/approvals"]}>
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
  });

  it("renders the approval list with pending summary and existing decisions", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchApprovals).toHaveBeenCalledWith("p-1"));
    expect(await screen.findByRole("heading", { name: "Approvals" })).toBeInTheDocument();
    expect(screen.getByText("1건의 승인 요청이 대기 중입니다")).toBeInTheDocument();
    expect(screen.getByText("Quality Gate 오버라이드")).toBeInTheDocument();
    expect(screen.getByText("Finding 위험 수용")).toBeInTheDocument();
    expect(screen.getByText(/"확인함"/)).toBeInTheDocument();
  });

  it("filters to approved approvals and shows an empty state for missing statuses", async () => {
    renderPage();

    await waitFor(() => expect(screen.getByText("Quality Gate 오버라이드")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "승인됨" }));

    await waitFor(() => expect(screen.queryByText("Quality Gate 오버라이드")).not.toBeInTheDocument());
    expect(screen.getByText("Finding 위험 수용")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "거부" }));
    expect(await screen.findByText("거부 상태의 요청이 없습니다")).toBeInTheDocument();
  });

  it("routes approval targets to their project detail pages", async () => {
    renderPage();

    await waitFor(() => expect(screen.getByRole("button", { name: "Gate 보기" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Gate 보기" }));
    fireEvent.click(screen.getByRole("button", { name: "Finding 보기" }));

    expect(mockNavigate).toHaveBeenNthCalledWith(1, "/projects/p-1/quality-gate");
    expect(mockNavigate).toHaveBeenNthCalledWith(2, "/projects/p-1/vulnerabilities");
  });

  it("submits an approval decision with an optional comment and reloads the list", async () => {
    renderPage();

    await waitFor(() => expect(screen.getByText("긴급 릴리즈 필요")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "승인" }));

    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByPlaceholderText("코멘트 (선택)"), { target: { value: "승인 사유" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "승인" }));

    await waitFor(() =>
      expect(mockDecideApproval).toHaveBeenCalledWith("a-1", "approved", undefined, "승인 사유"),
    );
    await waitFor(() => expect(mockFetchApprovals).toHaveBeenCalledTimes(2));
    expect(mockToast.success).toHaveBeenCalledWith("승인 완료");
  });

  it("shows the empty state when the project has no approvals", async () => {
    mockFetchApprovals.mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText("승인 요청이 없습니다")).toBeInTheDocument();
  });
});
