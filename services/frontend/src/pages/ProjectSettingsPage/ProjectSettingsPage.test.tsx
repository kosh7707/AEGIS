import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
const mockRegisterSdkByUpload = vi.fn();
const mockDeleteSdk = vi.fn();
const mockFetchProject = vi.fn();
const mockUpdateProjectSettings = vi.fn();
const mockUpdateProject = vi.fn();
const mockDeleteProject = vi.fn();
const mockRetrySdk = vi.fn();
const mockFetchSdkLog = vi.fn();
const mockFetchSdkQuota = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };

vi.mock("@/common/api/sdk", () => ({
  fetchProjectSdks: (...args: unknown[]) => mockFetchProjectSdks(...args),
  registerSdkByUpload: (...args: unknown[]) => mockRegisterSdkByUpload(...args),
  deleteSdk: (...args: unknown[]) => mockDeleteSdk(...args),
  retrySdk: (...args: unknown[]) => mockRetrySdk(...args),
  fetchSdkLog: (...args: unknown[]) => mockFetchSdkLog(...args),
  fetchSdkQuota: (...args: unknown[]) => mockFetchSdkQuota(...args),
  getSdkWsUrl: vi.fn(() => "ws://localhost:3000/ws/sdk?projectId=p-1"),
  getSdkLogDownloadUrl: vi.fn((pid: string, sdkId: string) => `http://localhost/api/projects/${pid}/sdk/${sdkId}/log?download=true`),
}));

vi.mock("@/common/api/projects", () => ({
  fetchProject: (...args: unknown[]) => mockFetchProject(...args),
  updateProjectSettings: (...args: unknown[]) => mockUpdateProjectSettings(...args),
  updateProject: (...args: unknown[]) => mockUpdateProject(...args),
  deleteProject: (...args: unknown[]) => mockDeleteProject(...args),
}));

vi.mock("@/common/api/core", () => ({
  logError: vi.fn(),
  ApiError: class ApiError extends Error {
    code: string;
    retryable: boolean;
    requestId: string;
    detailMessage?: string;
    constructor(message: string, code = "UNKNOWN", retryable = false, requestId = "test-rid", detailMessage?: string) {
      super(message);
      this.name = "ApiError";
      this.code = code;
      this.retryable = retryable;
      this.requestId = requestId;
      this.detailMessage = detailMessage;
    }
  },
}));
vi.mock("@/common/contexts/ToastContext", () => ({ useToast: () => mockToast }));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/p-1/settings"]}>
      <Routes>
        <Route path="/projects/:projectId/settings" element={<ProjectSettingsPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

function activateSection(name: RegExp) {
  const tab = screen.getByRole("tab", { name });
  fireEvent.pointerDown(tab);
  fireEvent.mouseDown(tab);
  fireEvent.click(tab);
}

describe("ProjectSettingsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    MockWebSocket.instances = [];
    vi.stubGlobal("WebSocket", MockWebSocket);
    mockFetchProjectSdks.mockResolvedValue({ builtIn: [], registered: [] });
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
    mockFetchProject.mockResolvedValue({
      id: "p-1",
      name: "Test Project",
      description: "",
      createdAt: "2026-04-04T00:00:00Z",
      updatedAt: "2026-04-04T00:00:00Z",
    });
    mockUpdateProjectSettings.mockResolvedValue({ id: "p-1" });
    mockUpdateProject.mockResolvedValue({ id: "p-1", name: "Renamed" });
    mockDeleteProject.mockResolvedValue(undefined);
    mockRetrySdk.mockResolvedValue({
      id: "sdk-1",
      projectId: "p-1",
      name: "Retry SDK",
      path: "/uploads/p-1/sdk/sdk-1",
      status: "verifying",
      verified: false,
      retryable: true,
      retryCount: 1,
      createdAt: "2026-04-04T00:00:00Z",
      updatedAt: "2026-04-04T00:01:00Z",
    });
    mockFetchSdkLog.mockResolvedValue({
      sdkId: "sdk-1",
      content: "log line 1\nlog line 2",
      truncated: false,
      totalLines: 2,
    });
    mockFetchSdkQuota.mockResolvedValue({
      usedBytes: 1024,
      maxBytes: 50 * 1024 * 1024 * 1024,
      sdkCount: 1,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows loading feedback before sdk settings resolve", () => {
    mockFetchProjectSdks.mockImplementation(() => new Promise(() => {}));

    renderPage();

    expect(screen.getByText("설정 로딩 중...")).toBeInTheDocument();
  });

  it("shows the general section by default", async () => {
    const { container } = renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    expect(screen.getByRole("heading", { name: "프로젝트 설정" })).toBeInTheDocument();
    expect(container.querySelector(".page-header--plain")).not.toBeNull();
    expect(screen.getAllByText("일반").length).toBeGreaterThan(0);
    expect(screen.getByPlaceholderText("프로젝트 이름")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("프로젝트 설명")).toBeInTheDocument();
    expect(document.title).toBe("AEGIS — Project Settings");
  });

  it("calls updateProject (PUT /api/projects/:id) when only the project name changes", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProject).toHaveBeenCalledWith("p-1"));
    const nameInput = await screen.findByPlaceholderText("프로젝트 이름");
    fireEvent.change(nameInput, { target: { value: "Renamed Project" } });

    fireEvent.click(screen.getByRole("button", { name: /저장$/ }));

    await waitFor(() => expect(mockUpdateProject).toHaveBeenCalledWith("p-1", { name: "Renamed Project" }));
    // Description didn't change → updateProjectSettings is not called.
    expect(mockUpdateProjectSettings).not.toHaveBeenCalled();
    expect(mockToast.success).toHaveBeenCalledWith("프로젝트 이름이 변경되었습니다.");
  });

  it("blocks save and toasts when the trimmed project name is empty", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProject).toHaveBeenCalledWith("p-1"));
    const nameInput = await screen.findByPlaceholderText("프로젝트 이름");
    fireEvent.change(nameInput, { target: { value: "   " } });

    fireEvent.click(screen.getByRole("button", { name: /저장$/ }));

    await waitFor(() =>
      expect(mockToast.error).toHaveBeenCalledWith("프로젝트 이름을 입력해 주세요."),
    );
    expect(mockUpdateProject).not.toHaveBeenCalled();
    expect(mockUpdateProjectSettings).not.toHaveBeenCalled();
  });

  it("shows the danger zone copy when the danger section is selected", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    activateSection(/위험 구역/i);

    expect(screen.getByRole("heading", { name: "프로젝트 삭제" })).toBeInTheDocument();
    expect(screen.getByText(/분석 이력, 스캔 결과/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /프로젝트 삭제/i })).toBeInTheDocument();
  });

  it("renders placeholder sections for not-yet-available settings areas", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));

    activateSection(/빌드 타겟/i);
    expect(await screen.findByText("빌드 타겟 설정은 준비 중입니다")).toBeInTheDocument();

    activateSection(/알림/i);
    expect(await screen.findByText("프로젝트 알림 설정은 준비 중입니다")).toBeInTheDocument();

    activateSection(/어댑터/i);
    expect(await screen.findByText("동적 분석 어댑터 설정은 준비 중입니다")).toBeInTheDocument();
  });

  it("renders three upload mode tabs (archive, binary, folder)", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    activateSection(/SDK 관리/i);
    fireEvent.click(screen.getByRole("button", { name: /sdk 추가/i }));

    expect(screen.getByRole("button", { name: /아카이브/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /바이너리/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /폴더/i })).toBeInTheDocument();
    expect(screen.queryByLabelText("로컬 경로")).not.toBeInTheDocument();
  });

  it("shows SDK name and description fields in upload form", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchProjectSdks).toHaveBeenCalledWith("p-1"));
    activateSection(/SDK 관리/i);
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

    await waitFor(() => activateSection(/SDK 관리/i));
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

    await waitFor(() => activateSection(/SDK 관리/i));
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

    await waitFor(() => activateSection(/SDK 관리/i));
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

    await waitFor(() => activateSection(/SDK 관리/i));
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

    await waitFor(() => activateSection(/SDK 관리/i));
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

    await waitFor(() => activateSection(/SDK 관리/i));
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

    await waitFor(() => activateSection(/SDK 관리/i));
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

  it("deletes a registered sdk after confirmation", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Delete Me SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "ready",
        verified: true,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => activateSection(/SDK 관리/i));
    expect(await screen.findByText("Delete Me SDK")).toBeInTheDocument();

    fireEvent.click(screen.getByTitle("삭제"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText('"Delete Me SDK" SDK를 삭제하시겠습니까?')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "삭제" }));

    await waitFor(() => expect(mockDeleteSdk).toHaveBeenCalledWith("p-1", "sdk-1"));
    await waitFor(() => expect(screen.queryByText("Delete Me SDK")).not.toBeInTheDocument());
    expect(mockToast.success).toHaveBeenCalledWith('SDK "Delete Me SDK" 삭제 완료');
  });

  it("renders Retry CTA enabled for failed retryable SDK and calls retrySdk on click", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Retry SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "verify_failed",
        verifyError: "검증 실패",
        retryable: true,
        retryCount: 0,
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => activateSection(/SDK 관리/i));
    await waitFor(() => expect(screen.getByText("Retry SDK")).toBeInTheDocument());

    const retryBtn = await screen.findByRole("button", { name: /^재시도$/ });
    expect(retryBtn).not.toBeDisabled();
    fireEvent.click(retryBtn);

    await waitFor(() => expect(mockRetrySdk).toHaveBeenCalledWith("p-1", "sdk-1"));
    expect(mockToast.success).toHaveBeenCalledWith('"Retry SDK" 재시도를 시작했습니다.');
  });

  it("disables Retry CTA when retryable=false and shows tooltip", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "No Retry SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "extract_failed",
        verifyError: "압축해제 실패",
        retryable: false,
        retryCount: 0,
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => activateSection(/SDK 관리/i));
    await waitFor(() => expect(screen.getByText("No Retry SDK")).toBeInTheDocument());

    const retryBtn = await screen.findByRole("button", { name: /^재시도$/ });
    expect(retryBtn).toBeDisabled();
    expect(retryBtn).toHaveAttribute("title", expect.stringMatching(/재시도할 수 없습니다/));
    expect(mockRetrySdk).not.toHaveBeenCalled();
  });

  it("renders quota indicator in panel head", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Quota SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "ready",
        verified: true,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });
    mockFetchSdkQuota.mockResolvedValue({
      usedBytes: 5 * 1024 * 1024 * 1024,
      maxBytes: 50 * 1024 * 1024 * 1024,
      sdkCount: 1,
    });

    renderPage();

    await waitFor(() => activateSection(/SDK 관리/i));
    await waitFor(() => expect(screen.getByText("Quota SDK")).toBeInTheDocument());

    expect(screen.getByText("QUOTA")).toBeInTheDocument();
    expect(screen.getByText(/5\.0 GB \/ 50\.0 GB/)).toBeInTheDocument();
  });

  it("renders structured error UX (userMessage + technicalDetail toggle + correlationId + troubleshooting link)", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Error SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "verify_failed",
        verifyError: "검증 실패",
        retryable: false,
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => activateSection(/SDK 관리/i));
    await waitFor(() => expect(screen.getByText("Error SDK")).toBeInTheDocument());

    act(() => {
      MockWebSocket.instances[0].onmessage?.({
        data: JSON.stringify({
          type: "sdk-error",
          payload: {
            sdkId: "sdk-1",
            phase: "verify_failed",
            error: "검증 실패",
            code: "VERIFY_PATH_MISSING",
            userMessage: "SDK 경로가 누락되었습니다.",
            technicalDetail: "sysroot=/opt/x not found",
            failedAt: 1714099299000,
            correlationId: "sdk-1",
            troubleshootingUrl: "https://example.test/troubleshoot/sdk#verify-path-missing",
            retryable: false,
            recoverable: false,
          },
        }),
      });
    });

    expect(await screen.findByText("SDK 경로가 누락되었습니다.")).toBeInTheDocument();
    expect(screen.getByText("VERIFY_PATH_MISSING")).toBeInTheDocument();
    expect(screen.getByText("sdk-1")).toBeInTheDocument();
    const guideLink = screen.getByRole("link", { name: /문제 해결 가이드/ });
    expect(guideLink).toHaveAttribute("href", "https://example.test/troubleshoot/sdk#verify-path-missing");
    // Tech detail collapsed by default
    expect(screen.queryByText("sysroot=/opt/x not found")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /기술 상세/ }));
    expect(await screen.findByText("sysroot=/opt/x not found")).toBeInTheDocument();
  });

  it("opens log panel and fetches log content from fetchSdkLog", async () => {
    mockFetchProjectSdks.mockResolvedValue({
      builtIn: [],
      registered: [{
        id: "sdk-1",
        projectId: "p-1",
        name: "Log SDK",
        path: "/uploads/p-1/sdk/sdk-1",
        status: "install_failed",
        verifyError: "설치 실패",
        installLogPath: "/var/log/sdk.log",
        retryable: false,
        verified: false,
        createdAt: "2026-04-04T00:00:00Z",
        updatedAt: "2026-04-04T00:00:00Z",
      }],
    });

    renderPage();

    await waitFor(() => activateSection(/SDK 관리/i));
    await waitFor(() => expect(screen.getByText("Log SDK")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /로그 보기/ }));

    await waitFor(() => expect(mockFetchSdkLog).toHaveBeenCalledWith("p-1", "sdk-1", { tailLines: 200 }));
    expect(await screen.findByText(/log line 1/)).toBeInTheDocument();
    // Download CTA renders as link
    expect(screen.getByRole("link", { name: /로그 다운로드/ })).toBeInTheDocument();
  });

  it("shows the general section without fetching when no project id is present", async () => {
    render(
      <MemoryRouter initialEntries={["/settings"]}>
        <Routes>
          <Route path="/settings" element={<ProjectSettingsPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByPlaceholderText("프로젝트 이름")).toBeInTheDocument();
    expect(mockFetchProjectSdks).not.toHaveBeenCalled();
    expect(mockToast.error).not.toHaveBeenCalled();
  });

  it("shows a toast when sdk loading fails", async () => {
    mockFetchProjectSdks.mockRejectedValue(new Error("load failed"));

    renderPage();

    await waitFor(() => expect(mockToast.error).toHaveBeenCalledWith("SDK 목록을 불러올 수 없습니다."));
    expect(await screen.findByPlaceholderText("프로젝트 이름")).toBeInTheDocument();
  });

  it("partial failure surfaces nameUpdated message when name saves but description fails", async () => {
    mockFetchProject.mockResolvedValue({
      id: "p-1",
      name: "Original Name",
      description: "original desc",
      createdAt: "2026-04-04T00:00:00Z",
      updatedAt: "2026-04-04T00:00:00Z",
    });
    mockUpdateProject.mockResolvedValue({ id: "p-1", name: "New Name" });
    mockUpdateProjectSettings.mockRejectedValue(new Error("network error"));

    renderPage();

    await waitFor(() => expect(mockFetchProject).toHaveBeenCalledWith("p-1"));
    const nameInput = await screen.findByPlaceholderText("프로젝트 이름");
    const descInput = await screen.findByPlaceholderText("프로젝트 설명");
    fireEvent.change(nameInput, { target: { value: "New Name" } });
    fireEvent.change(descInput, { target: { value: "new desc" } });

    fireEvent.click(screen.getByRole("button", { name: /저장$/ }));

    await waitFor(() => expect(mockUpdateProject).toHaveBeenCalledWith("p-1", { name: "New Name" }));
    await waitFor(() => expect(mockUpdateProjectSettings).toHaveBeenCalled());
    await waitFor(() =>
      expect(mockToast.error).toHaveBeenCalledWith(
        expect.stringContaining("이름은 저장됐지만"),
      ),
    );
    expect(mockToast.success).not.toHaveBeenCalled();
  });
});
