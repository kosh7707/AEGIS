import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { verifyReconnectableHook } from "@/test-setup/testReconnectionBehavior";

// Mock createReconnectingWs to capture handlers
let capturedOptions: Record<string, unknown> = {};
let mockWs: { onmessage: ((e: MessageEvent) => void) | null };

vi.mock("@/common/utils/wsEnvelope", async (importOriginal) => {
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

vi.mock("@/common/api/sdk", () => ({
  fetchProjectSdks: vi.fn().mockResolvedValue({ builtIn: [], registered: [] }),
  getSdkWsUrl: vi.fn((pid: string) => `ws://localhost:3000/ws/sdk?projectId=${pid}`),
  deleteSdk: vi.fn(),
}));

vi.mock("@/common/api/core", () => ({
  logError: vi.fn(),
}));

// Must import AFTER mocks
import { useSdkProgress } from "./useSdkProgress";
import { createReconnectingWs } from "@/common/utils/wsEnvelope";

beforeEach(() => {
  capturedOptions = {};
  vi.clearAllMocks();
});

afterEach(() => {
  vi.unstubAllEnvs();
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
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-error",
        payload: { sdkId: "sdk-1", error: "분석 실패" },
      });
    });

    expect(onError).toHaveBeenCalledWith("sdk-1", "분석 실패", undefined, undefined, undefined);
  });

  it("calls onProgress with extended details (etaSeconds, phaseStartedAt, phaseDetail)", () => {
    const onProgress = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress,
        onComplete: vi.fn(),
        onError: vi.fn(),
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-progress",
        payload: {
          sdkId: "sdk-1",
          phase: "uploading",
          percent: 42,
          uploadedBytes: 100,
          totalBytes: 200,
          etaSeconds: 12,
          phaseStartedAt: 1714099200000,
          phaseDetail: { kind: "sdk.uploading", params: { fileName: "sdk.tar.gz" } },
        },
      });
    });

    expect(onProgress).toHaveBeenCalledWith("sdk-1", "uploading", {
      percent: 42,
      uploadedBytes: 100,
      totalBytes: 200,
      etaSeconds: 12,
      phaseStartedAt: 1714099200000,
      phaseDetail: { kind: "sdk.uploading", params: { fileName: "sdk.tar.gz" } },
    });
  });

  it("calls onError with structured fields (code/userMessage/technicalDetail/failedAt/correlationId/troubleshootingUrl/retryable/recoverable)", () => {
    const onError = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError,
      }),
    );

    act(() => {
      simulateMessage({
        type: "sdk-error",
        payload: {
          sdkId: "sdk-1",
          phase: "verify_failed",
          error: "검증 실패",
          logPath: "/var/log/sdk.log",
          code: "VERIFY_PATH_MISSING",
          userMessage: "SDK 경로가 누락되었습니다.",
          technicalDetail: "sysroot=/opt/x not found",
          failedAt: 1714099299000,
          correlationId: "sdk-1",
          troubleshootingUrl: "wiki/canon/troubleshooting/sdk#verify-path-missing",
          retryable: true,
          recoverable: true,
        },
      });
    });

    expect(onError).toHaveBeenCalledWith(
      "sdk-1",
      "검증 실패",
      "verify_failed",
      "/var/log/sdk.log",
      {
        code: "VERIFY_PATH_MISSING",
        userMessage: "SDK 경로가 누락되었습니다.",
        technicalDetail: "sysroot=/opt/x not found",
        failedAt: 1714099299000,
        correlationId: "sdk-1",
        troubleshootingUrl: "wiki/canon/troubleshooting/sdk#verify-path-missing",
        retryable: true,
        recoverable: true,
      },
    );
  });

  it("calls onLog when sdk-log WS message arrives and onLog is provided", () => {
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
          timestamp: "2026-04-25T10:00:00Z",
          source: "installer",
          kind: "output",
          stream: "stdout",
          message: "extracting...",
          logPath: "/var/log/sdk.log",
        },
      });
    });

    expect(onLog).toHaveBeenCalledWith("sdk-1", {
      timestamp: "2026-04-25T10:00:00Z",
      source: "installer",
      kind: "output",
      stream: "stdout",
      message: "extracting...",
      logPath: "/var/log/sdk.log",
    });
  });

  it("calls onProgress with details when WS payload includes percent", () => {
    const onProgress = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress,
        onComplete: vi.fn(),
        onError: vi.fn(),
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

    expect(onError).toHaveBeenCalledWith("sdk-1", "설치 실패", "install_failed", "/var/log/sdk.log", undefined);
  });

  it("calls onError for all error phases (upload_failed, extract_failed, install_failed)", () => {
    const onError = vi.fn();
    renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError,
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
      expect(onError).toHaveBeenCalledWith("sdk-1", `${phase} error`, phase, undefined, undefined);
    }
  });

  it("does not connect when projectId is undefined", () => {
    const { result } = renderHook(() =>
      useSdkProgress({
        projectId: undefined,
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError: vi.fn(),
      }),
    );

    // Should still expose connectionState as disconnected
    expect(result.current.connectionState).toBe("disconnected");
  });

  it("surfaces giveUpReason and disconnected when onGiveUp fires (close 4000 / retry exhausted)", () => {
    const { result, rerender } = renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError: vi.fn(),
      }),
    );

    expect(result.current.disconnected).toBe(false);
    expect(result.current.giveUpReason).toBeNull();

    act(() => {
      (capturedOptions.onGiveUp as () => void)();
    });
    rerender();

    expect(result.current.giveUpReason).not.toBeNull();
    expect(typeof result.current.giveUpReason).toBe("string");
  });

  it("does not connect in mock mode", () => {
    vi.stubEnv("VITE_MOCK", "true");
    const { result } = renderHook(() =>
      useSdkProgress({
        projectId: "p-1",
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError: vi.fn(),
      }),
    );

    expect(result.current.connectionState).toBe("disconnected");
    expect(vi.mocked(createReconnectingWs)).not.toHaveBeenCalled();
  });
});
