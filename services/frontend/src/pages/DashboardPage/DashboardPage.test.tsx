import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ProjectListItem } from "@aegis/shared";
import { DashboardPage } from "./DashboardPage";

const mockNavigate = vi.fn();
const mockCreateProject = vi.fn();
const mockUseProjects = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("../../contexts/ProjectContext", () => ({
  useProjects: () => mockUseProjects(),
}));

function makeProject(index: number, overrides: Partial<ProjectListItem> = {}): ProjectListItem {
  return {
    id: `p-${index}`,
    name: `Project ${index}`,
    description: `Description ${index}`,
    createdAt: `2026-04-${String(index).padStart(2, "0")}T00:00:00Z`,
    updatedAt: `2026-04-${String(index).padStart(2, "0")}T01:00:00Z`,
    lastAnalysisAt: `2026-04-${String(index).padStart(2, "0")}T02:00:00Z`,
    gateStatus: index % 2 === 0 ? "fail" : "pass",
    unresolvedDelta: index,
    severitySummary: {
      critical: index === 1 ? 1 : 0,
      high: index,
      medium: index + 1,
      low: index + 2,
    },
    ...overrides,
  };
}

const projects = Array.from({ length: 5 }, (_, i) => makeProject(i + 1));
const manyProjects = Array.from({ length: 12 }, (_, i) => makeProject(i + 1));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/dashboard"]}>
      <DashboardPage />
    </MemoryRouter>,
  );
}

describe("DashboardPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCreateProject.mockResolvedValue({ id: "p-created" });
    mockUseProjects.mockReturnValue({
      projects,
      loading: false,
      createProject: mockCreateProject,
    });
  });

  it("renders dashboard sections and keeps explorer, attention, and activity links interactive", async () => {
    mockUseProjects.mockReturnValue({
      projects: manyProjects,
      loading: false,
      createProject: mockCreateProject,
    });

    renderPage();

    expect(screen.getByRole("heading", { name: "프로젝트 탐색기" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "우선 확인" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "최근 활동" })).toBeInTheDocument();
    expect(screen.queryByText("Open")).not.toBeInTheDocument();

    const attentionSection = screen.getByRole("heading", { name: "우선 확인" }).closest("section");
    const activitySection = screen.getByRole("heading", { name: "최근 활동" }).closest("section");

    expect(attentionSection).not.toBeNull();
    expect(activitySection).not.toBeNull();

    expect(within(attentionSection as HTMLElement).getAllByRole("link")).toHaveLength(4);
    expect(within(activitySection as HTMLElement).getAllByRole("link")).toHaveLength(10);

    fireEvent.click(screen.getByRole("button", { name: "더 보기" }));
    expect(within(activitySection as HTMLElement).getAllByRole("link")).toHaveLength(12);
  });

  it("filters project explorer by search query", async () => {
    renderPage();

    const explorer = screen.getByLabelText("프로젝트 탐색기");
    fireEvent.change(screen.getByPlaceholderText("프로젝트 검색"), { target: { value: "Project 3" } });

    expect(within(explorer).getByRole("link", { name: /Project 3/i })).toBeInTheDocument();
    expect(within(explorer).queryByRole("link", { name: /Project 1/i })).not.toBeInTheDocument();
  });

  it("renders a refined explorer empty state for unmatched search and lets users reset it", async () => {
    renderPage();

    fireEvent.change(screen.getByPlaceholderText("프로젝트 검색"), { target: { value: "No Match" } });

    expect(screen.getByText("검색 결과가 없습니다")).toBeInTheDocument();
    expect(screen.getByText(/“No Match”와 일치하는 프로젝트가 없습니다/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "검색 초기화" }));
    expect(screen.queryByText("검색 결과가 없습니다")).not.toBeInTheDocument();
  });

  it("creates a project from the inline create form", async () => {
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: "새 프로젝트" }));
    fireEvent.change(screen.getByPlaceholderText("프로젝트 이름"), { target: { value: "  New Dashboard Project  " } });
    fireEvent.change(screen.getByPlaceholderText("설명 (선택)"), { target: { value: "  My desc  " } });
    fireEvent.click(screen.getByRole("button", { name: "만들기" }));

    await waitFor(() => expect(mockCreateProject).toHaveBeenCalledWith("New Dashboard Project", "My desc"));
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith("/projects/p-created/overview"));
  });

  it("renders a clearer explorer empty state when there are no projects yet", async () => {
    mockUseProjects.mockReturnValue({
      projects: [],
      loading: false,
      createProject: mockCreateProject,
    });

    renderPage();

    expect(screen.getByText("아직 프로젝트가 없습니다")).toBeInTheDocument();
    expect(screen.getByText(/첫 프로젝트를 만들면 이곳에서 상태와 최근 흐름을 바로 탐색할 수 있습니다/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "새 프로젝트 시작" }));
    expect(screen.getByPlaceholderText("프로젝트 이름")).toBeInTheDocument();
  });

  it("renders refined empty lane sections when there is no dashboard data", async () => {
    mockUseProjects.mockReturnValue({
      projects: [],
      loading: false,
      createProject: mockCreateProject,
    });

    renderPage();

    expect(screen.getByText("긴급 항목 없음")).toBeInTheDocument();
    expect(screen.getByText("아직 활동 없음")).toBeInTheDocument();
    expect(screen.getByText(/프로젝트를 생성하면 게이트 실패나 높은 위험 항목이 이곳에 우선 정렬됩니다/)).toBeInTheDocument();
    expect(screen.getByText(/첫 업로드, 분석, 승인 같은 작업이 시작되면 최근 흐름이 이 레인에 순서대로 쌓입니다/)).toBeInTheDocument();
  });

  it("keeps the calm lane informational when projects exist but no urgent items are present", async () => {
    const calmProjects = [
      makeProject(1, {
        gateStatus: "pass",
        unresolvedDelta: 0,
        severitySummary: { critical: 0, high: 0, medium: 0, low: 0 },
      }),
    ];

    mockUseProjects.mockReturnValue({
      projects: calmProjects,
      loading: false,
      createProject: mockCreateProject,
    });

    renderPage();

    expect(screen.getByText(/최근 프로젝트 상태를 한 번 점검해두면 충분합니다/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Project 1 열기" })).not.toBeInTheDocument();
  });

  it("shows a neutral latest-update activity before a project has ever been analyzed", async () => {
    mockUseProjects.mockReturnValue({
      projects: [
        makeProject(1, {
          lastAnalysisAt: undefined,
          gateStatus: undefined,
          unresolvedDelta: 0,
          severitySummary: { critical: 0, high: 0, medium: 0, low: 0 },
        }),
      ],
      loading: false,
      createProject: mockCreateProject,
    });

    renderPage();

    const activitySection = screen.getByRole("heading", { name: "최근 활동" }).closest("section");

    expect(activitySection).not.toBeNull();
    expect(within(activitySection as HTMLElement).getByText("가장 마지막 수정")).toBeInTheDocument();
    expect(within(activitySection as HTMLElement).getByText("Project 1")).toBeInTheDocument();
    expect(screen.queryByText("분석 완료")).not.toBeInTheDocument();
    expect(screen.queryByText("정적 분석이 완료되었습니다")).not.toBeInTheDocument();
  });
});
