import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { FilesPage } from "./FilesPage";

const mockNavigate = vi.fn();
const mockFetchSourceFilesWithComposition = vi.fn();
const mockFetchSourceFileContent = vi.fn();
const mockFetchProjectFindings = vi.fn();
const mockUploadSource = vi.fn();
const mockDeleteSource = vi.fn();
const mockLogError = vi.fn();
const mockUseBuildTargets = vi.fn();
const mockUseUploadProgress = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), info: vi.fn() };
const mockUploadProgressApi = {
  phase: "idle",
  message: "",
  fileCount: null,
  error: null,
  connectionState: "disconnected",
  isActive: false,
  setUploading: vi.fn(),
  startTracking: vi.fn(),
  reset: vi.fn(),
};

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("@/common/api/client", () => {
  class ApiError extends Error {
    code: string;
    retryable: boolean;
    requestId: string;
    detailMessage?: string;
    constructor(message: string, code = "UNKNOWN", retryable = false, requestId = "rid", detailMessage?: string) {
      super(message);
      this.name = "ApiError";
      this.code = code;
      this.retryable = retryable;
      this.requestId = requestId;
      this.detailMessage = detailMessage;
    }
  }
  return {
    fetchSourceFilesWithComposition: (...args: unknown[]) => mockFetchSourceFilesWithComposition(...args),
    fetchSourceFileContent: (...args: unknown[]) => mockFetchSourceFileContent(...args),
    fetchProjectFindings: (...args: unknown[]) => mockFetchProjectFindings(...args),
    uploadSource: (...args: unknown[]) => mockUploadSource(...args),
    deleteSource: (...args: unknown[]) => mockDeleteSource(...args),
    logError: (...args: unknown[]) => mockLogError(...args),
    ApiError,
  };
});

vi.mock("@/common/hooks/useBuildTargets", () => ({
  useBuildTargets: (...args: unknown[]) => mockUseBuildTargets(...args),
}));

vi.mock("@/common/hooks/useUploadProgress", () => ({
  useUploadProgress: (...args: unknown[]) => mockUseUploadProgress(...args),
}));

vi.mock("@/common/contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

vi.mock("@/common/contexts/ProjectContext", () => ({
  useProjects: () => ({
    getProject: (id: string) => ({ id, name: `project-${id}` }),
    projects: [],
    loading: false,
    refreshProjects: vi.fn(),
    createProject: vi.fn(),
  }),
}));

vi.mock("./components/BuildTargetCreateDialog/BuildTargetCreateDialog", () => ({
  BuildTargetCreateDialog: () => null,
}));

vi.mock("./components/BuildLogViewer", () => ({
  BuildLogViewer: () => null,
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/p-1/files"]}>
      <Routes>
        <Route path="/projects/:projectId/files" element={<FilesPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("FilesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    mockFetchSourceFilesWithComposition.mockResolvedValue({ success: true, data: [], targetMapping: {} });
    mockFetchProjectFindings.mockResolvedValue([]);
    mockDeleteSource.mockResolvedValue(undefined);
    mockFetchSourceFileContent.mockResolvedValue({
      path: "src/main.c",
      content: "int main() {\n  return 0;\n}\n",
      language: "C",
      size: 27,
    });
    mockUseBuildTargets.mockReturnValue({
      targets: [],
      loading: false,
      discovering: false,
      load: vi.fn(),
      add: vi.fn(),
      update: vi.fn(),
      remove: vi.fn(),
      discover: vi.fn(),
    });
    Object.assign(mockUploadProgressApi, {
      phase: "idle",
      message: "",
      fileCount: null,
      error: null,
      connectionState: "disconnected",
      isActive: false,
    });
    mockUploadProgressApi.setUploading.mockReset();
    mockUploadProgressApi.startTracking.mockReset();
    mockUploadProgressApi.reset.mockReset();
    mockUseUploadProgress.mockReturnValue(mockUploadProgressApi);
  });

  it("shows loading feedback before source files resolve", () => {
    mockFetchSourceFilesWithComposition.mockImplementation(() => new Promise(() => {}));
    mockFetchProjectFindings.mockImplementation(() => new Promise(() => {}));

    renderPage();

    expect(screen.getByText("파일 로딩 중...")).toBeInTheDocument();
  });

  it("renders the empty upload state when no files are available", async () => {
    renderPage();

    await waitFor(() => expect(mockFetchSourceFilesWithComposition).toHaveBeenCalledWith("p-1"));
    expect(await screen.findByText("아직 업로드된 소스코드가 없습니다")).toBeInTheDocument();
    expect(screen.getByText(/소스코드 아카이브/)).toBeInTheDocument();
  });

  it("shows file previews and finding navigation for populated projects", async () => {
    mockFetchSourceFilesWithComposition.mockResolvedValue({
      success: true,
      data: [
        { relativePath: "src/main.c", size: 120, language: "C" },
        { relativePath: "README.md", size: 40, language: "Markdown" },
      ],
      targetMapping: {
        "src/main.c": { targetId: "target-1", targetName: "Firmware" },
      },
    });
    mockFetchProjectFindings.mockResolvedValue([
      {
        id: "finding-1",
        severity: "high",
        title: "Unsafe copy",
        location: "src/main.c:2",
      },
    ]);

    renderPage();

    await waitFor(() => expect(mockFetchProjectFindings).toHaveBeenCalledWith("p-1"));
    expect(await screen.findByRole("heading", { name: "파일 탐색기" })).toBeInTheDocument();
    expect(screen.getByText("README.md")).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/src\/main\.c 미리 보기/));

    await waitFor(() => expect(mockFetchSourceFileContent).toHaveBeenCalledWith("p-1", "src/main.c"));
    expect(await screen.findByText("Unsafe copy")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Unsafe copy"));
    expect(mockNavigate).toHaveBeenCalledWith("/projects/p-1/static-analysis?finding=finding-1");
  });

  it("supports collapsing, expanding, and resizing the source workspace", async () => {
    mockFetchSourceFilesWithComposition.mockResolvedValue({
      success: true,
      data: [
        { relativePath: "src/main.c", size: 120, language: "C" },
        { relativePath: "README.md", size: 40, language: "Markdown" },
      ],
      targetMapping: {},
    });

    renderPage();

    expect(await screen.findByRole("heading", { name: "파일 탐색기" })).toBeInTheDocument();
    expect(screen.getByText("main.c")).toBeInTheDocument();

    fireEvent.click(screen.getByTitle("폴더 전부 접기"));
    await waitFor(() => expect(screen.queryByText("main.c")).not.toBeInTheDocument());

    fireEvent.click(screen.getByTitle("폴더 전부 열기"));
    expect(await screen.findByText("main.c")).toBeInTheDocument();

    const workspace = screen.getByTestId("files-source-workspace");
    const splitter = screen.getByTestId("files-source-workspace-splitter");

    Object.defineProperty(workspace, "getBoundingClientRect", {
      value: () => ({ left: 0, width: 1000, top: 0, right: 1000, bottom: 600, height: 600, x: 0, y: 0, toJSON: () => ({}) }),
      configurable: true,
    });

    fireEvent.mouseDown(splitter, { clientX: 360 });
    fireEvent.mouseMove(window, { clientX: 480 });
    fireEvent.mouseUp(window);

    expect(workspace.style.getPropertyValue("--files-tree-panel-width")).toBe("480px");
  });

  it("starts upload tracking when files are selected from the hidden input", async () => {
    mockFetchSourceFilesWithComposition.mockResolvedValue({
      success: true,
      data: [{ relativePath: "src/main.c", size: 120, language: "C" }],
      targetMapping: {},
    });
    mockUploadSource.mockResolvedValue({ uploadId: "upload-1" });

    renderPage();

    expect(await screen.findByRole("heading", { name: "파일 탐색기" })).toBeInTheDocument();

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const archive = new File(["archive"], "project.zip", { type: "application/zip" });
    fireEvent.change(fileInput, { target: { files: [archive] } });

    await waitFor(() => expect(mockUploadProgressApi.setUploading).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockUploadSource).toHaveBeenCalledWith("p-1", [archive]));
    await waitFor(() => expect(mockUploadProgressApi.startTracking).toHaveBeenCalledWith("upload-1"));
  });

  it("shows a toast when source upload fails", async () => {
    mockFetchSourceFilesWithComposition.mockResolvedValue({
      success: true,
      data: [{ relativePath: "src/main.c", size: 120, language: "C" }],
      targetMapping: {},
    });
    mockUploadSource.mockRejectedValue(new Error("upload failed"));

    renderPage();

    expect(await screen.findByRole("heading", { name: "파일 탐색기" })).toBeInTheDocument();

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [new File(["archive"], "project.zip", { type: "application/zip" })] } });

    await waitFor(() => expect(mockUploadProgressApi.setUploading).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockToast.error).toHaveBeenCalledWith("파일 업로드에 실패했습니다."));
    expect(mockUploadProgressApi.startTracking).not.toHaveBeenCalled();
  });

  it("calls deleteSource (DELETE /api/projects/:pid/source) when bulk delete is confirmed", async () => {
    mockFetchSourceFilesWithComposition.mockResolvedValue({
      success: true,
      data: [{ relativePath: "src/main.c", size: 120, language: "C" }],
      targetMapping: {},
    });

    renderPage();

    expect(await screen.findByRole("heading", { name: "파일 탐색기" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /소스 일괄 삭제/ }));

    expect(
      screen.getByText(/프로젝트의 모든 소스 파일을 삭제합니다\. 이 작업은 되돌릴 수 없습니다\. 정말 삭제하시겠습니까\?/),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "삭제" }));

    await waitFor(() => expect(mockDeleteSource).toHaveBeenCalledWith("p-1"));
    await waitFor(() =>
      expect(mockToast.success).toHaveBeenCalledWith("프로젝트 소스를 모두 삭제했습니다."),
    );
  });

  it("surfaces the 409 backend detail message when deleteSource is blocked", async () => {
    mockFetchSourceFilesWithComposition.mockResolvedValue({
      success: true,
      data: [{ relativePath: "src/main.c", size: 120, language: "C" }],
      targetMapping: {},
    });
    const { ApiError } = await import("@/common/api/client");
    mockDeleteSource.mockRejectedValue(
      new (ApiError as new (
        message: string,
        code: string,
        retryable: boolean,
        requestId: string,
        detailMessage?: string,
      ) => Error)(
        "이미 실행 중인 작업이 있습니다.",
        "CONFLICT",
        false,
        "rid-1",
        "다음 항목이 활성 상태이므로 삭제할 수 없습니다: active analysis, dynamic session",
      ),
    );

    renderPage();

    expect(await screen.findByRole("heading", { name: "파일 탐색기" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /소스 일괄 삭제/ }));
    fireEvent.click(screen.getByRole("button", { name: "삭제" }));

    await waitFor(() =>
      expect(mockToast.error).toHaveBeenCalledWith(
        "다음 항목이 활성 상태이므로 삭제할 수 없습니다: active analysis, dynamic session",
      ),
    );
  });
});
