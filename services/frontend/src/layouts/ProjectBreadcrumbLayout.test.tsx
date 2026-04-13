import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ProjectBreadcrumbLayout } from "./ProjectBreadcrumbLayout";

const mockUseProjects = vi.fn();

vi.mock("../contexts/ProjectContext", () => ({
  useProjects: () => mockUseProjects(),
}));

function renderLayout(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/projects/:projectId" element={<ProjectBreadcrumbLayout />}>
          <Route path="overview" element={<div>overview child</div>} />
          <Route path="files/:fileId" element={<div>file child</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("ProjectBreadcrumbLayout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseProjects.mockReturnValue({
      getProject: (id: string) => (id === "p-1" ? { id: "p-1", name: "Payments Platform" } : null),
    });
  });

  it("renders project breadcrumbs with the current page highlighted", () => {
    renderLayout("/projects/p-1/overview");

    expect(screen.getByRole("navigation", { name: "프로젝트 경로" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "프로젝트" })).toHaveAttribute("href", "/dashboard");
    expect(screen.getByRole("link", { name: "Payments Platform" })).toHaveAttribute("href", "/projects/p-1/overview");
    expect(screen.getByText("개요").closest(".breadcrumb-current")).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("overview child")).toBeInTheDocument();
  });

  it("uses the file-detail label for nested file routes", () => {
    renderLayout("/projects/p-1/files/file-7");

    expect(screen.getByText("파일 상세").closest(".breadcrumb-current")).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("file child")).toBeInTheDocument();
  });

  it("renders a not-found title when the project context is missing", () => {
    mockUseProjects.mockReturnValue({
      getProject: () => null,
    });

    const { container } = renderLayout("/projects/p-404/overview");

    expect(screen.getByRole("heading", { name: "프로젝트를 찾을 수 없습니다" })).toBeInTheDocument();
    expect(screen.getByText("프로젝트")).toBeInTheDocument();
    expect(screen.getByText("삭제되었거나 현재 접근할 수 없는 프로젝트입니다.")).toBeInTheDocument();
    expect(container.querySelector(".page-header--plain")).not.toBeNull();
  });
});
