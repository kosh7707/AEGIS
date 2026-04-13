import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ProjectSettingsPage } from "./ProjectSettingsPage";

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  static CONNECTING = 0;
  static OPEN = 1;

  url: string;
  onmessage: ((evt: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = MockWebSocket.OPEN;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  close() {
    this.readyState = 3;
    this.onclose?.();
  }
}

const mockFetchProjectSdks = vi.fn();
const mockFetchSdkInstallLog = vi.fn();
const mockRegisterSdkByUpload = vi.fn();
const mockDeleteSdk = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("../../api/sdk", () => ({
  fetchProjectSdks: (...args: unknown[]) => mockFetchProjectSdks(...args),
  fetchSdkInstallLog: (...args: unknown[]) => mockFetchSdkInstallLog(...args),
  registerSdkByUpload: (...args: unknown[]) => mockRegisterSdkByUpload(...args),
  deleteSdk: (...args: unknown[]) => mockDeleteSdk(...args),
  getSdkWsUrl: vi.fn(() => "ws://localhost:3000/ws/sdk?projectId=p-1"),
}));

vi.mock("../../api/core", () => ({ logError: vi.fn() }));
vi.mock("../../contexts/ToastContext", () => ({ useToast: () => mockToast }));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/p-1/settings"]}>
      <Routes>
        <Route path="/projects/:projectId/settings" element={<ProjectSettingsPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ProjectSettingsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    MockWebSocket.instances = [];
    vi.stubGlobal("WebSocket", MockWebSocket);
    mockFetchProjectSdks.mockResolvedValue({ builtIn: [], registered: [] });
    mockFetchSdkInstallLog.mockResolvedValue({
      sdkId: "sdk-1",
      logPath: "/uploads/p-1/sdk/sdk-1/install.log",
      content: "",
      truncated: false,
    });
    mockRegisterSdkByUpload.mockResolvedValue({
      id: "sdk-1",
      projectId: "p-1",
      name: "SDK One",
      description: "Cross compile SDK",
      path: "/uploads/p-1/sdk/sdk-1",
      status: "uploading",
      verified: false,
      createdAt: "2026-04-04T00:00:00Z",
      updatedAt: "2026-04-04T00:00:00Z",
    });
    mockDeleteSdk.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the general section by default", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    expect(screen.getAllByText("General").length).toBeGreaterThan(0);
    expect(screen.getByPlaceholderText("프로젝트 이름")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("프로젝트 설명")).toBeInTheDocument();
  });

  it("shows the danger zone copy when the danger section is selected", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    fireEvent.click(screen.getByRole("button", { name: "Danger Zone" }));

    expect(screen.getByText("Delete this project")).toBeInTheDocument();
    expect(screen.getByText(/Once deleted, all historical data/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete Project" })).toBeInTheDocument();
  });

  it("renders three upload mode tabs (archive, binary, folder)", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    fireEvent.click(screen.getByText("SDK Management"));
    fireEvent.click(screen.getByRole("button", { name: /sdk 추가/i }));

    expect(screen.getByRole("button", { name: /아카이브/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /바이너리/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /폴더/i })).toBeInTheDocument();
    expect(screen.queryByLabelText("로컬 경로")).not.toBeInTheDocument();
  });

  it("shows SDK name and description fields in upload form", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    fireEvent.click(screen.getByText("SDK Management"));
    fireEvent.click(screen.getByRole("button", { name: /sdk 추가/i }));

    expect(screen.getByLabelText("SDK 이름")).toBeInTheDocument();
    expect(screen.getByLabelText("설명 \(선택\)")).toBeInTheDocument();
  });

  it("renders the canonical environmentSetup profile field", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [
        {
          id: "sdk-1",
          projectId: "p-1",
          name: "SDK One",
          path: "/opt/sdk-one",
          status: "ready",
          verified: true,
          createdAt: "2026-04-04T00:00:00Z",
          updatedAt: "2026-04-04T00:00:00Z",
          profile: {
            compiler: "arm-none-eabi-gcc",
            environmentSetup: "/opt/sdk-one/environment-setup",
          },
        },
      ],
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(screen.getByText("SDK One")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /분석된 프로파일/i }));

    expect(await screen.findByText("/opt/sdk-one/environment-setup")).toBeInTheDocument();
  });

  it("stepper renders 5 grouped phases for in-progress SDK", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Test SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "extracting",
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(screen.getByText("Test SDK")).toBeInTheDocument());

    expect(screen.getByText("업로드")).toBeInTheDocument();
    expect(screen.getByText("설치/압축해제")).toBeInTheDocument();
    expect(screen.getByText("AI 분석")).toBeInTheDocument();
    expect(screen.getByText("검증")).toBeInTheDocument();
    expect(screen.getByText("완료")).toBeInTheDocument();
  });

  it("stepper shows Group 1 as done and Group 2 as active for extracting status", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Test SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "extracting",
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(screen.getByText("Test SDK")).toBeInTheDocument());

    const uploadStep = screen.getByText("업로드").closest(".sdk-stepper__step");
    expect(uploadStep).toHaveClass("sdk-stepper__step--done");

    const extractStep = screen.getByText("설치/압축해제").closest(".sdk-stepper__step");
    expect(extractStep).toHaveClass("sdk-stepper__step--active");
  });

  it("install_failed marks Group 2 as failed and hides stepper", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Test SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "install_failed",
        verifyError: "설치 실패",
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(screen.getByText("Test SDK")).toBeInTheDocument());

    expect(screen.queryByText("설치/압축해제")).not.toBeInTheDocument();
    expect(screen.getAllByText("설치 실패").length).toBeGreaterThan(0);
  });

  it("ready status shows all groups as done (no stepper rendered)", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Test SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "ready",
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(screen.getByText("Test SDK")).toBeInTheDocument());

    expect(screen.queryByText("업로드")).not.toBeInTheDocument();
    expect(screen.getByText("사용 가능")).toBeInTheDocument();
  });

  it("renders byte-level SDK upload progress details from websocket updates", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Binary SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "uploading",
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(screen.getByText("Binary SDK")).toBeInTheDocument());

    act(() => {
      MockWebSocket.instances[0].onmessage?.({
        data: JSON.stringify({
          type: "sdk-progress",
          payload: {
            sdkId: "sdk-1",
            phase: "uploading",
            percent: 58,
            uploadedBytes: 1024,
            totalBytes: 2048,
            fileName: "sdk.bin",
          },
        }),
      });
    });

    expect(await screen.findByText("업로드 진행률")).toBeInTheDocument();
    expect(screen.getByText("58%")).toBeInTheDocument();
    expect(screen.getByText("sdk.bin")).toBeInTheDocument();
    expect(screen.getByText("1.0 KB / 2.0 KB")).toBeInTheDocument();
    expect(screen.getByLabelText("SDK upload progress")).toBeInTheDocument();
  });

  it("hydrates install log tail when reopening the sdk management surface", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Binary SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "installing",
        installLogPath: "/uploads/p-1/sdk/sdk-1/install.log",
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });
    mockFetchSdkInstallLog.mockResolvedValue({
      sdkId: "sdk-1",
      logPath: "/uploads/p-1/sdk/sdk-1/install.log",
      content: "[10:00:00] [aegis] install started\n[10:00:05] [aegis/heartbeat] installer still running",
      truncated: true,
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(mockFetchSdkInstallLog).toHaveBeenCalledWith("p-1", "sdk-1", 200));

    expect(await screen.findByText("Install log")).toBeInTheDocument();
    expect(screen.getByText(/install started/i)).toBeInTheDocument();
    expect(screen.getByText("최근 로그 tail 표시")).toBeInTheDocument();
  });

  it("appends live sdk-log websocket lines to the recovered install log", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Binary SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "installing",
        installLogPath: "/uploads/p-1/sdk/sdk-1/install.log",
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });
    mockFetchSdkInstallLog.mockResolvedValue({
      sdkId: "sdk-1",
      logPath: "/uploads/p-1/sdk/sdk-1/install.log",
      content: "[10:00:00] [aegis] install started",
      truncated: false,
    });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    expect(await screen.findByText("Install log")).toBeInTheDocument();

    act(() => {
      MockWebSocket.instances[0].onmessage?.({
        data: JSON.stringify({
          type: "sdk-log",
          payload: {
            sdkId: "sdk-1",
            timestamp: "2026-04-13T02:20:00Z",
            source: "installer",
            kind: "output",
            stream: "stdout",
            message: "install step running",
            logPath: "/uploads/p-1/sdk/sdk-1/install.log",
          },
        }),
      });
    });

    expect(await screen.findByText(/install step running/i)).toBeInTheDocument();
  });

  it("refreshes sdk metadata from the canonical list when sdk-complete arrives", async () => {
    mockFetchProjectSdks
      .mockResolvedValueOnce({
        builtIn: [],
        registered: [{
          id: "sdk-1",
          projectId: "p-1",
          name: "Binary SDK",
          path: "/uploads/p-1/sdk/sdk-1",
          status: "verifying",
          verified: false,
          createdAt: "2026-04-04T00:00:00Z",
          updatedAt: "2026-04-04T00:00:00Z",
        }],
      })
      .mockResolvedValueOnce({
        builtIn: [],
        registered: [{
          id: "sdk-1",
          projectId: "p-1",
          name: "Binary SDK",
          path: "/uploads/p-1/sdk/sdk-1/installed",
          status: "ready",
          verified: true,
          artifactKind: "bin",
          sdkVersion: "08.02.00.24",
          targetSystem: "am335x-evm",
          createdAt: "2026-04-04T00:00:00Z",
          updatedAt: "2026-04-04T00:01:00Z",
          profile: {
            compiler: "arm-none-eabi-gcc",
          },
        }],
      });

    renderPage();

    await waitFor(() => fireEvent.click(screen.getByText("SDK Management")));
    await waitFor(() => expect(screen.getByText("Binary SDK")).toBeInTheDocument());

    act(() => {
      MockWebSocket.instances[0].onmessage?.({
        data: JSON.stringify({
          type: "sdk-complete",
          payload: {
            sdkId: "sdk-1",
            profile: { compiler: "arm-none-eabi-gcc" },
          },
        }),
      });
    });

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("바이너리")).toBeInTheDocument();
    expect(screen.getByText("08.02.00.24")).toBeInTheDocument();
    expect(screen.getByText("am335x-evm")).toBeInTheDocument();
  });
});
