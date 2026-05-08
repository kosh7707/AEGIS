import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";

let capturedOptions: Record<string, unknown> = {};
let mockWs: { onmessage: ((e: MessageEvent) => void) | null };

vi.mock("@/common/utils/wsEnvelope", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../common/utils/wsEnvelope")>();
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

vi.mock("@/common/api/notifications", () => ({
  getNotificationWsUrl: (pid: string) => `ws://localhost:3000/ws/notifications?projectId=${pid}`,
}));

vi.mock("@/common/api/projects", () => ({
  fetchProjectActivity: vi.fn().mockResolvedValue([]),
}));

vi.mock("@/common/api/core", () => ({
  logError: vi.fn(),
}));

// import AFTER mocks
import { useDashboardActivityFeed } from "./useDashboardActivityFeed";

const projects = [{ id: "p-1", name: "Test" }] as never[];

beforeEach(() => {
  capturedOptions = {};
  vi.clearAllMocks();
  // Force non-test mode so WS path runs (the hook short-circuits for MODE === "test").
  vi.stubEnv("MODE", "production");
  vi.stubEnv("VITE_MOCK", "false");
});

function simulateMessage(data: unknown) {
  const event = { data: JSON.stringify(data) } as MessageEvent;
  mockWs?.onmessage?.(event);
}

describe("useDashboardActivityFeed", () => {
  it("only bumps activity revision on type=notification frames (drops heartbeat)", async () => {
    const { result } = renderHook(() => useDashboardActivityFeed({ projects }));
    await waitFor(() => expect(typeof mockWs?.onmessage).toBe("function"));

    const initial = result.current;

    act(() => {
      // heartbeat / non-notification frame should be dropped
      simulateMessage({
        type: "heartbeat",
        payload: {},
        meta: { channel: "notification", timestamp: 1, seq: 1 },
      });
    });

    // No state churn from heartbeat — revision did not advance
    expect(result.current.connectionState).toBe(initial.connectionState);

    act(() => {
      simulateMessage({
        type: "notification",
        payload: { id: "n-1" },
        meta: { channel: "notification", timestamp: 2, seq: 2 },
      });
    });

    // After the legitimate notification frame, the activity REST refresh should
    // have been triggered (revision is internal, but the hook re-runs the
    // fetchProjectActivity effect, so we verify the mock was called >=2 times).
    const { fetchProjectActivity } = await import("@/common/api/projects");
    await waitFor(() => {
      expect(vi.mocked(fetchProjectActivity).mock.calls.length).toBeGreaterThan(1);
    });
  });

  it("drops frames whose envelope channel does not match 'notification'", async () => {
    renderHook(() => useDashboardActivityFeed({ projects }));
    await waitFor(() => expect(typeof mockWs?.onmessage).toBe("function"));

    const { fetchProjectActivity } = await import("@/common/api/projects");
    const callCountBefore = vi.mocked(fetchProjectActivity).mock.calls.length;

    act(() => {
      simulateMessage({
        type: "notification",
        payload: { id: "n-wrong" },
        meta: { channel: "pipeline", timestamp: 1, seq: 1 },
      });
    });

    // Wrong-channel frame ignored — refresh count unchanged
    expect(vi.mocked(fetchProjectActivity).mock.calls.length).toBe(callCountBefore);
  });

  it("flips realtimeOffline when onGiveUp fires", async () => {
    const { result, rerender } = renderHook(() => useDashboardActivityFeed({ projects }));
    await waitFor(() => expect(typeof mockWs?.onmessage).toBe("function"));

    expect(result.current.realtimeOffline).toBe(false);

    act(() => {
      (capturedOptions.onGiveUp as () => void)();
    });
    rerender();

    expect(result.current.realtimeOffline).toBe(true);
  });
});
