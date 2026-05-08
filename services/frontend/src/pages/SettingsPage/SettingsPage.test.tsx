import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render as rtlRender, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { SettingsPage } from "./SettingsPage";

const mockGetBackendUrl = vi.fn();
const mockSetBackendUrl = vi.fn();
const mockHealthFetch = vi.fn();
const mockGetThemePreference = vi.fn();
const mockSetThemePreference = vi.fn();

vi.mock("@/common/api/client", () => ({
  getBackendUrl: () => mockGetBackendUrl(),
  setBackendUrl: (...args: unknown[]) => mockSetBackendUrl(...args),
  healthFetch: (...args: unknown[]) => mockHealthFetch(...args),
}));

const mockApplyTheme = vi.fn();

vi.mock("@/common/utils/theme", () => ({
  getThemePreference: () => mockGetThemePreference(),
  setThemePreference: (...args: unknown[]) => mockSetThemePreference(...args),
  applyTheme: (...args: unknown[]) => mockApplyTheme(...args),
  isThemePreferenceEnabled: () => true,
}));

vi.mock("@/common/contexts/ProjectContext", () => ({
  useProjects: () => ({
    projects: [],
    loading: false,
    refreshProjects: vi.fn(),
    createProject: vi.fn(),
    getProject: () => null,
  }),
}));

function render(ui: React.ReactElement) {
  return rtlRender(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetBackendUrl.mockReturnValue("http://localhost:3000");
    mockGetThemePreference.mockReturnValue("system");
    mockHealthFetch.mockResolvedValue({ ok: true, data: { service: "backend", version: "1.0.0" } });
  });

  it("saves a changed backend URL", () => {
    const { container } = render(<SettingsPage />);

    expect(screen.getByRole("heading", { name: "시스템 설정" })).toBeInTheDocument();
    expect(container.querySelector(".page-header--plain")).not.toBeNull();
    expect(document.title).toBe("AEGIS — Settings");

    fireEvent.change(screen.getByPlaceholderText("http://localhost:3000"), { target: { value: "http://api.internal:4000" } });
    fireEvent.click(screen.getAllByRole("button", { name: "저장" })[0]);

    expect(mockSetBackendUrl).toHaveBeenCalledWith("http://api.internal:4000");
  });

  it("tests backend connectivity and shows success details", async () => {
    render(<SettingsPage />);

    fireEvent.click(screen.getByRole("button", { name: "테스트" }));

    await waitFor(() => expect(mockHealthFetch).toHaveBeenCalledWith("http://localhost:3000", expect.any(String)));
    expect(await screen.findByText(/연결 성공/)).toBeInTheDocument();
  });

  it("shows an error message when backend connectivity fails", async () => {
    mockHealthFetch.mockResolvedValue({ ok: false, data: null });
    render(<SettingsPage />);

    fireEvent.click(screen.getByRole("button", { name: "테스트" }));

    await waitFor(() => expect(mockHealthFetch).toHaveBeenCalledWith("http://localhost:3000", expect.any(String)));
    expect(await screen.findByText("연결 실패")).toBeInTheDocument();
  });

  it("forwards a UUID requestId to healthFetch for correlation", async () => {
    render(<SettingsPage />);

    fireEvent.click(screen.getByRole("button", { name: "테스트" }));

    await waitFor(() => expect(mockHealthFetch).toHaveBeenCalled());
    const [, requestId] = mockHealthFetch.mock.calls[0] as [string, string];
    // UUID v4 pattern
    expect(requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it("resets the backend URL to the stored default and clears prior test feedback", async () => {
    render(<SettingsPage />);

    fireEvent.click(screen.getByRole("button", { name: "테스트" }));
    expect(await screen.findByText(/연결 성공/)).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText("http://localhost:3000"), { target: { value: "http://api.internal:4000" } });
    fireEvent.click(screen.getByRole("button", { name: "기본값으로 초기화" }));

    expect(screen.getByDisplayValue("http://localhost:3000")).toBeInTheDocument();
    expect(screen.queryByText(/연결 성공/)).not.toBeInTheDocument();
    expect(mockSetBackendUrl).toHaveBeenCalledWith("");
  });

  it("previews theme on click and persists only after save", () => {
    render(<SettingsPage />);

    fireEvent.click(screen.getByRole("button", { name: "라이트" }));

    expect(mockApplyTheme).toHaveBeenCalledWith("light");
    expect(mockSetThemePreference).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "저장" }));

    expect(mockSetThemePreference).toHaveBeenCalledWith("light");
  });

  it("reverts theme preview on cancel", () => {
    render(<SettingsPage />);

    fireEvent.click(screen.getByRole("button", { name: "다크" }));
    expect(mockApplyTheme).toHaveBeenLastCalledWith("dark");

    fireEvent.click(screen.getByRole("button", { name: "취소" }));

    expect(mockApplyTheme).toHaveBeenLastCalledWith("system");
    expect(mockSetThemePreference).not.toHaveBeenCalled();
  });

  it("resets the backend URL to the default value and clears stale test status", async () => {
    mockGetBackendUrl
      .mockReturnValueOnce("http://localhost:3000")
      .mockReturnValue("http://localhost:3000");
    mockHealthFetch.mockResolvedValueOnce({ ok: false });

    render(<SettingsPage />);

    fireEvent.change(screen.getByPlaceholderText("http://localhost:3000"), {
      target: { value: "http://api.internal:4000" },
    });
    fireEvent.click(screen.getByRole("button", { name: "테스트" }));
    expect(await screen.findByText("연결 실패")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "기본값으로 초기화" }));

    expect(mockSetBackendUrl).toHaveBeenCalledWith("");
    await waitFor(() =>
      expect(screen.getByDisplayValue("http://localhost:3000")).toBeInTheDocument(),
    );
    expect(screen.queryByText("연결 실패")).not.toBeInTheDocument();
  });

  it("shows an error message when the backend connectivity test fails", async () => {
    mockHealthFetch.mockResolvedValue({ ok: false });

    render(<SettingsPage />);

    fireEvent.click(screen.getByRole("button", { name: "테스트" }));

    await waitFor(() => expect(mockHealthFetch).toHaveBeenCalledWith("http://localhost:3000", expect.any(String)));
    expect(await screen.findByText("연결 실패")).toBeInTheDocument();
  });
});
