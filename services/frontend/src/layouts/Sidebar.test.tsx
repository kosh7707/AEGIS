import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "./Sidebar";

const mockGetProject = vi.fn();
const mockFetchApprovalCount = vi.fn();

vi.mock("../contexts/ProjectContext", () => ({
  useProjects: () => ({ getProject: mockGetProject }),
}));

vi.mock("../contexts/AnalysisGuardContext", () => ({
  useAnalysisGuard: () => ({ isBlocking: false }),
}));

vi.mock("../api/approval", () => ({
  fetchApprovalCount: (...args: unknown[]) => mockFetchApprovalCount(...args),
}));

describe("Sidebar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetProject.mockReturnValue({ id: "p-1", name: "Payments Platform" });
    mockFetchApprovalCount.mockResolvedValue({ pending: 2, total: 2 });
  });

  it("renders the project shell subtitle and approvals badge", async () => {
    render(
      <MemoryRouter initialEntries={["/projects/p-1/overview"]}>
        <Sidebar />
      </MemoryRouter>,
    );

    expect(screen.getByText("Payments Platform")).toBeInTheDocument();
    expect(screen.getByText("프로젝트 작업 공간")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /개요/i })).toHaveAttribute("href", "/projects/p-1/overview");
    await waitFor(() => expect(mockFetchApprovalCount).toHaveBeenCalledWith("p-1"));
    expect(await screen.findByText("2")).toBeInTheDocument();
  });

  it("renders the global shell subtitle outside project routes", () => {
    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Sidebar />
      </MemoryRouter>,
    );

    expect(screen.getByText("AEGIS")).toBeInTheDocument();
    expect(screen.getByText("보안 분석 워크스페이스")).toBeInTheDocument();
  });
});
