import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { Finding } from "@aegis/shared";
import { VulnerabilitiesPage } from "./VulnerabilitiesPage";

const mockFetchProjectFindings = vi.fn();
const mockBulkUpdateFindingStatus = vi.fn();
const mockFetchFindingGroups = vi.fn();
const mockFetchFindingsSummary = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("@/common/api/analysis", () => ({
  fetchProjectFindings: (...args: unknown[]) => mockFetchProjectFindings(...args),
  bulkUpdateFindingStatus: (...args: unknown[]) => mockBulkUpdateFindingStatus(...args),
  fetchFindingGroups: (...args: unknown[]) => mockFetchFindingGroups(...args),
  fetchFindingsSummary: (...args: unknown[]) => mockFetchFindingsSummary(...args),
}));

vi.mock("@/common/api/core", () => ({
  logError: vi.fn(),
}));

vi.mock("@/common/contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

vi.mock("@/common/ui/findings/FindingDetailView", () => ({
  FindingDetailView: ({ findingId, onBack }: { findingId: string; onBack: () => void }) => (
    <div>
      <p>Detail view: {findingId}</p>
      <button onClick={onBack}>Back</button>
    </div>
  ),
}));

function makeFinding(index: number, overrides: Partial<Finding> = {}): Finding {
  return {
    id: `finding-${index}`,
    runId: "run-1",
    projectId: "project-1",
    module: "static-analysis",
    status: "open",
    severity: "medium",
    confidence: "high",
    sourceType: "rule-engine",
    title: `Finding ${index}`,
    description: `Description ${index}`,
    location: `src/file-${index}.c:${index}`,
    ruleId: `RULE-${index}`,
    cweId: `CWE-12${index}`,
    createdAt: `2026-04-0${index}T00:00:00Z`,
    updatedAt: `2026-04-0${index}T01:00:00Z`,
    ...overrides,
  };
}

const findings = [
  makeFinding(1, {
    title: "Buffer overflow in parser",
    severity: "critical",
    sourceType: "agent",
    detail: "PoC possible",
  }),
  makeFinding(2, {
    title: "Weak crypto defaults",
    severity: "high",
    status: "needs_review",
    sourceType: "sast-tool",
  }),
  makeFinding(3, {
    title: "Informational banner mismatch",
    severity: "info",
    sourceType: "llm-assist",
  }),
];

function renderPage(initialEntry = "/projects/project-1/vulnerabilities") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/projects/:projectId/vulnerabilities" element={<VulnerabilitiesPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("VulnerabilitiesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchProjectFindings.mockResolvedValue(findings);
    mockBulkUpdateFindingStatus.mockResolvedValue({ updated: 1, failed: 0 });
    mockFetchFindingGroups.mockResolvedValue({
      groups: [{ key: "src/file-1.c:1", count: 1, topSeverity: "critical", findingIds: ["finding-1"] }],
    });
    mockFetchFindingsSummary.mockResolvedValue({});
  });

  it("shows loading feedback before findings resolve", () => {
    mockFetchProjectFindings.mockImplementation(() => new Promise(() => {}));

    renderPage();

    expect(screen.getByText("탐지 항목 로딩 중...")).toBeInTheDocument();
  });

  it("loads the routed project findings and respects the severity query filter", async () => {
    renderPage("/projects/project-1/vulnerabilities?severity=critical");

    await waitFor(() => expect(mockFetchProjectFindings).toHaveBeenCalledWith("project-1"));
    expect(await screen.findByRole("heading", { name: "취약점 목록" })).toBeInTheDocument();
    expect(screen.getByLabelText("활성 탐지 항목 요약")).toHaveTextContent("2");
    expect(screen.getByText("1건 / 3건 표시")).toBeInTheDocument();
    expect(screen.getByText("Buffer overflow in parser")).toBeInTheDocument();
    expect(screen.queryByText("Weak crypto defaults")).not.toBeInTheDocument();
    expect(screen.getByText(/심각도: Critical/)).toBeInTheDocument();
  });

  it("supports grouped display by location", async () => {
    renderPage();

    await screen.findByText("Buffer overflow in parser");

    fireEvent.change(screen.getByDisplayValue("그루핑: 없음"), { target: { value: "location" } });

    await waitFor(() => expect(mockFetchFindingGroups).toHaveBeenCalledWith("project-1", "location"));

    const groupHeader = await screen.findByText("src/file-1.c:1", { selector: ".vuln-group__key" });
    fireEvent.click(groupHeader.closest(".vuln-group__header") as HTMLElement);

    const groupBody = groupHeader.closest(".vuln-group") as HTMLElement;
    expect(within(groupBody).getByText("Buffer overflow in parser")).toBeInTheDocument();
  });

  it("applies bulk status updates and reloads findings", async () => {
    renderPage();

    await screen.findByText("Buffer overflow in parser");

    const findingCard = screen.getByText("Buffer overflow in parser").closest(".vuln-finding-card") as HTMLElement;
    fireEvent.click(within(findingCard).getByRole("checkbox").closest(".vuln-finding-card__check") as HTMLElement);
    const bulkBar = await screen.findByText("1건 선택");
    const bulkScope = within(bulkBar.closest(".vuln-bulk-bar") as HTMLElement);
    fireEvent.change(bulkScope.getByRole("combobox"), { target: { value: "fixed" } });
    fireEvent.change(bulkScope.getByPlaceholderText("사유 입력"), { target: { value: "Validated by regression test" } });
    fireEvent.click(bulkScope.getByRole("button", { name: "적용" }));

    await waitFor(() => {
      expect(mockBulkUpdateFindingStatus).toHaveBeenCalledWith(
        ["finding-1"],
        "fixed",
        "Validated by regression test",
      );
    });
    await waitFor(() => expect(mockFetchProjectFindings).toHaveBeenCalledTimes(2));
    expect(mockToast.success).toHaveBeenCalledWith("1건 상태 변경 완료");
  });

  it("opens the finding detail view and reloads findings when returning", async () => {
    renderPage();

    fireEvent.click(await screen.findByText("Buffer overflow in parser"));
    expect(await screen.findByText("Detail view: finding-1")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Back" }));

    await waitFor(() => expect(mockFetchProjectFindings).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Buffer overflow in parser")).toBeInTheDocument();
  });

  it("logs and toasts when loading findings fails", async () => {
    mockFetchProjectFindings.mockRejectedValue(new Error("load failed"));

    renderPage();

    await waitFor(() => expect(mockToast.error).toHaveBeenCalledWith("Finding 목록을 불러올 수 없습니다."));
    expect(await screen.findByText("조건에 맞는 탐지 항목이 없습니다")).toBeInTheDocument();
  });

  it("does not fetch findings and shows an empty state when no project id is present", async () => {
    render(
      <MemoryRouter initialEntries={["/vulnerabilities"]}>
        <Routes>
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("조건에 맞는 탐지 항목이 없습니다")).toBeInTheDocument());
    expect(mockFetchProjectFindings).not.toHaveBeenCalled();
    expect(mockToast.error).not.toHaveBeenCalled();
  });
});
