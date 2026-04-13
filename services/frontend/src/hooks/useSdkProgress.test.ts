import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { verifyReconnectableHook } from "../test-utils/testReconnectionBehavior";

// Mock createReconnectingWs to capture handlers
let capturedOptions: Record<string, unknown> = {};
let mockWs: { onmessage: ((e: MessageEvent) => void) | null };

vi.mock("../utils/wsEnvelope", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../utils/wsEnvelope")>();
  return {
    ...actual,
    createReconnectingWs: vi.fn((_urlFactory: () => string, options?: Record<string, unknown>) => {
      capturedOptions = options ?? {};
      mockWs = { onmessage: null };
      return {
        getWs: () => mockWs,
        get connectionState() { return "connected" as const; },
        close: vi.fn(),
        resetRetries: vi.fn(),
      };
    }),
  };
});

vi.mock("../api/sdk", () => ({
  fetchProjectSdks: vi.fn().mockResolvedValue({ builtIn: [], registered: [] }),
  getSdkWsUrl: vi.fn((pid: string) => `ws://localhost:3000/ws/sdk?projectId=${pid}`),
  deleteSdk: vi.fn(),
  registerSdkByPath: vi.fn(),
  fetchSdkInstallLog: vi.fn(),
}));

vi.mock("../api/core", () => ({
  logError: vi.fn(),
}));

// Must import AFTER mocks
import { useSdkProgress } from "./useSdkProgress";

beforeEach(() => {
  capturedOptions = {};
  vi.clearAllMocks();
});

function simulateMessage(data: unknown) {
  const event = { data: JSON.stringify(data) } as MessageEvent;
  mockWs.onmessage?.(event);
}

describe("useSdkProgress", () => {
  it("exposes connectionState (ReconnectableHookResult)", () => {
    const { result } = renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError: vi.fn(),
        onLog: vi.fn(),
      }),
    );

    verifyReconnectableHook(result.current);
  });

  it("calls onProgress on sdk-progress message", () => {
    const onProgress = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress,
        onComplete: vi.fn(),
        onError: vi.fn(),
        onLog: vi.fn(),
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-progress",
        payload: { sdkId: "sdk-1", phase: "analyzing" },
      });
    });

    expect(onProgress).toHaveBeenCalledWith("sdk-1", "analyzing", {});
  });

  it("calls onComplete on sdk-complete message", () => {
    const onComplete = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete,
        onError: vi.fn(),
        onLog: vi.fn(),
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-complete",
        payload: { sdkId: "sdk-1", profile: { name: "TestSDK" } },
      });
    });

    expect(onComplete).toHaveBeenCalledWith("sdk-1", { name: "TestSDK" });
  });

  it("calls onError on sdk-error message", () => {
    const onError = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError,
        onLog: vi.fn(),
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-error",
        payload: { sdkId: "sdk-1", error: "분석 실패" },
      });
    });

    expect(onError).toHaveBeenCalledWith("sdk-1", "분석 실패", undefined, undefined);
  });

  it("calls onProgress with details when WS payload includes percent", () => {
    const onProgress = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress,
        onComplete: vi.fn(),
        onError: vi.fn(),
        onLog: vi.fn(),
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-progress",
        payload: {
          sdkId: "sdk-1",
          phase: "uploading",
          percent: 45,
          uploadedBytes: 1024,
          totalBytes: 2048,
          fileName: "sdk.tar.gz",
        },
      });
    });

    expect(onProgress).toHaveBeenCalledWith("sdk-1", "uploading", {
      percent: 45,
      uploadedBytes: 1024,
      totalBytes: 2048,
      fileName: "sdk.tar.gz",
    });
  });

  it("calls onProgress for new phases (uploaded, extracted, installing, installed)", () => {
    const onProgress = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress,
        onComplete: vi.fn(),
        onError: vi.fn(),
        onLog: vi.fn(),
      }),
    );

    const newPhases = ["uploaded", "extracted", "installing", "installed"];
    act(() => {
      for (const phase of newPhases) {
        simulateMessage({
          type: "sdk-progress",
          payload: { sdkId: "sdk-1", phase },
        });
      }
    });

    expect(onProgress).toHaveBeenCalledTimes(newPhases.length);
    for (const phase of newPhases) {
      expect(onProgress).toHaveBeenCalledWith("sdk-1", phase, {});
    }
  });

  it("calls onError with phase and logPath", () => {
    const onError = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError,
        onLog: vi.fn(),
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-error",
        payload: {
          sdkId: "sdk-1",
          phase: "install_failed",
          error: "설치 실패",
          logPath: "/var/log/sdk.log",
        },
      });
    });

    expect(onError).toHaveBeenCalledWith("sdk-1", "설치 실패", "install_failed", "/var/log/sdk.log");
  });

  it("calls onError for all error phases (upload_failed, extract_failed, install_failed)", () => {
    const onError = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError,
        onLog: vi.fn(),
      }),
    );

    const errorPhases = ["upload_failed", "extract_failed", "install_failed"];
    act(() => {
      for (const phase of errorPhases) {
        simulateMessage({
          type: "sdk-error",
          payload: { sdkId: "sdk-1", phase, error: `${phase} error` },
        });
      }
    });

    expect(onError).toHaveBeenCalledTimes(errorPhases.length);
    for (const phase of errorPhases) {
      expect(onError).toHaveBeenCalledWith("sdk-1", `${phase} error`, phase, undefined);
    }
  });

  it("does not connect when projectId is undefined", () => {
    const { result } = renderHook(() =>
      useSdkProgress({
        projectId: undefined,
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError: vi.fn(),
        onLog: vi.fn(),
      }),
    );

    // Should still expose connectionState as disconnected
    expect(result.current.connectionState).toBe("disconnected");
  });

  it("calls onLog on sdk-log message", () => {
    const onLog = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError: vi.fn(),
        onLog,
      }),
    );

    act(() => {
      simulateMessage({
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
      });
    });

    expect(onLog).toHaveBeenCalledWith("sdk-1", {
      sdkId: "sdk-1",
      timestamp: "2026-04-13T02:20:00Z",
      source: "installer",
      kind: "output",
      stream: "stdout",
      message: "install step running",
      logPath: "/uploads/p-1/sdk/sdk-1/install.log",
    });
  });
});
