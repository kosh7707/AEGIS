import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";

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

vi.mock("@/common/api/client", () => ({
  runDynamicTest: vi.fn().mockImplementation(() => new Promise(() => {})), // never resolves so cleanup is not triggered
  getWsBaseUrl: () => "ws://localhost:3000",
}));

// Must import AFTER mocks
import { useDynamicTest } from "./useDynamicTest";

beforeEach(() => {
  capturedOptions = {};
  vi.clearAllMocks();
});

function simulateMessage(data: unknown) {
  const event = { data: JSON.stringify(data) } as MessageEvent;
  mockWs.onmessage?.(event);
}

describe("useDynamicTest", () => {
  it("uses maxRetries: 8 (consistency with sibling hooks)", async () => {
    const { result } = renderHook(() => useDynamicTest("p-1"));

    await act(async () => {
      void result.current.startTest({ count: 5 } as never, "adapter-1");
    });

    expect(capturedOptions.maxRetries).toBe(8);
  });

  it("registers onGiveUp; flips disconnected=true when invoked", async () => {
    const { result, rerender } = renderHook(() => useDynamicTest("p-1"));

    await act(async () => {
      void result.current.startTest({ count: 5 } as never, "adapter-1");
    });

    expect(typeof capturedOptions.onGiveUp).toBe("function");
    expect(result.current.disconnected).toBe(false);

    act(() => {
      (capturedOptions.onGiveUp as () => void)();
    });
    rerender();

    expect(result.current.disconnected).toBe(true);
  });

  it("sets testComplete=true on test-complete WS frame (race-safe terminal flag)", async () => {
    const { result, rerender } = renderHook(() => useDynamicTest("p-1"));

    await act(async () => {
      void result.current.startTest({ count: 5 } as never, "adapter-1");
    });

    expect(result.current.testComplete).toBe(false);

    act(() => {
      simulateMessage({ type: "test-complete", payload: {} });
    });
    rerender();

    expect(result.current.testComplete).toBe(true);
  });

  it("warns on seq gap via createSeqTracker", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { result } = renderHook(() => useDynamicTest("p-1"));

    await act(async () => {
      void result.current.startTest({ count: 5 } as never, "adapter-1");
    });

    act(() => {
      simulateMessage({
        type: "test-progress",
        payload: { current: 1, total: 5, crashes: 0, anomalies: 0, message: "" },
        meta: { channel: "dynamic-test", timestamp: 1, seq: 1 },
      });
      simulateMessage({
        type: "test-progress",
        payload: { current: 5, total: 5, crashes: 0, anomalies: 0, message: "" },
        meta: { channel: "dynamic-test", timestamp: 2, seq: 5 },
      });
    });

    const gapWarn = warnSpy.mock.calls.find((args) =>
      args.some((a) => typeof a === "string" && a.includes("seq gap")),
    );
    expect(gapWarn).toBeDefined();
    warnSpy.mockRestore();
  });
});
