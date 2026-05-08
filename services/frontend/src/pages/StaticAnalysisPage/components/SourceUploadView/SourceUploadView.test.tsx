import React from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SourceUploadView } from "./SourceUploadView";

const mockFetchSourceFiles = vi.fn();
const mockUploadSource = vi.fn();
const mockCloneSource = vi.fn();
const mockLogError = vi.fn();

vi.mock("@/common/api/client", () => ({
  fetchSourceFiles: (...args: unknown[]) => mockFetchSourceFiles(...args),
  uploadSource: (...args: unknown[]) => mockUploadSource(...args),
  cloneSource: (...args: unknown[]) => mockCloneSource(...args),
  logError: (...args: unknown[]) => mockLogError(...args),
}));

vi.mock("@/common/contexts/ToastContext", () => ({
  useToast: () => ({ error: vi.fn(), success: vi.fn(), warning: vi.fn() }),
}));

vi.mock("@/common/hooks/useUploadProgress", () => ({
  useUploadProgress: () => ({
    phase: "idle",
    isActive: false,
    message: "",
    error: null,
    connectionState: "disconnected",
    setUploading: vi.fn(),
    startTracking: vi.fn(),
    reset: vi.fn(),
  }),
}));

describe("SourceUploadView — Prepare button", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchSourceFiles.mockResolvedValue([
      { relativePath: "a.c", language: "c", size: 100 },
    ]);
  });

  it("calls onPrepare when빌드 검증 button is clicked", async () => {
    const onPrepare = vi.fn();
    render(
      <SourceUploadView
        projectId="p1"
        onAnalysisStart={vi.fn()}
        onPrepare={onPrepare}
        isPreparing={false}
      />,
    );

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /빌드 검증/ })).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: /빌드 검증/ }));
    expect(onPrepare).toHaveBeenCalledTimes(1);
  });

  it("disables빌드 검증 button while isPreparing", async () => {
    render(
      <SourceUploadView
        projectId="p1"
        onAnalysisStart={vi.fn()}
        onPrepare={vi.fn()}
        isPreparing={true}
      />,
    );

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /빌드 검증 중/ })).toBeInTheDocument(),
    );

    expect(screen.getByRole("button", { name: /빌드 검증 중/ })).toBeDisabled();
  });

  it("does not render빌드 검증 button when onPrepare is not provided", async () => {
    render(<SourceUploadView projectId="p1" onAnalysisStart={vi.fn()} />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /분석 실행/ })).toBeInTheDocument(),
    );

    expect(screen.queryByRole("button", { name: /빌드 검증/ })).not.toBeInTheDocument();
  });
});

describe("SourceUploadView — Quick/Deep mode toggle", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchSourceFiles.mockResolvedValue([
      { relativePath: "a.c", language: "c", size: 100 },
    ]);
  });

  it("invokes onAnalysisStart with 'quick' by default", async () => {
    const onAnalysisStart = vi.fn();
    render(<SourceUploadView projectId="p1" onAnalysisStart={onAnalysisStart} />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /분석 실행/ })).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: /분석 실행/ }));
    expect(onAnalysisStart).toHaveBeenCalledWith("quick");
  });

  it("switches to deep mode when DEEP segment selected", async () => {
    const onAnalysisStart = vi.fn();
    render(<SourceUploadView projectId="p1" onAnalysisStart={onAnalysisStart} />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /분석 실행/ })).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("radio", { name: "DEEP" }));
    expect(screen.getByRole("radio", { name: "DEEP" })).toHaveAttribute("aria-checked", "true");
    fireEvent.click(screen.getByRole("button", { name: /분석 실행/ }));
    expect(onAnalysisStart).toHaveBeenCalledWith("deep");
  });

  it("arrow-key navigation toggles between QUICK and DEEP", async () => {
    render(<SourceUploadView projectId="p1" onAnalysisStart={vi.fn()} />);

    await waitFor(() =>
      expect(screen.getByRole("radiogroup", { name: "분석 모드" })).toBeInTheDocument(),
    );

    const radiogroup = screen.getByRole("radiogroup", { name: "분석 모드" });

    // Initial state: QUICK is checked
    expect(screen.getByRole("radio", { name: "QUICK" })).toHaveAttribute("aria-checked", "true");

    // ArrowRight → DEEP
    fireEvent.keyDown(radiogroup, { key: "ArrowRight" });
    expect(screen.getByRole("radio", { name: "DEEP" })).toHaveAttribute("aria-checked", "true");

    // ArrowLeft → QUICK
    fireEvent.keyDown(radiogroup, { key: "ArrowLeft" });
    expect(screen.getByRole("radio", { name: "QUICK" })).toHaveAttribute("aria-checked", "true");

    // End → DEEP
    fireEvent.keyDown(radiogroup, { key: "End" });
    expect(screen.getByRole("radio", { name: "DEEP" })).toHaveAttribute("aria-checked", "true");

    // Home → QUICK
    fireEvent.keyDown(radiogroup, { key: "Home" });
    expect(screen.getByRole("radio", { name: "QUICK" })).toHaveAttribute("aria-checked", "true");
  });
});
