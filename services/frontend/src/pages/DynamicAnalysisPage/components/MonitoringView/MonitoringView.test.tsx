import React from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MonitoringView } from "./MonitoringView";

const mockFetchScenarios = vi.fn();
const mockFetchInjections = vi.fn();
const mockFetchDynamicSessionDetail = vi.fn();
const mockStopDynamicSession = vi.fn();
const mockInjectCanMessage = vi.fn();
const mockInjectScenario = vi.fn();
const mockToast = { error: vi.fn(), success: vi.fn(), warning: vi.fn(), info: vi.fn() };
const fakeWs: { onmessage: ((event: { data: string }) => void) | null; close: ReturnType<typeof vi.fn> } = {
  onmessage: null,
  close: vi.fn(),
};

vi.mock("@/common/api/client", () => ({
  fetchScenarios: (...args: unknown[]) => mockFetchScenarios(...args),
  fetchInjections: (...args: unknown[]) => mockFetchInjections(...args),
  fetchDynamicSessionDetail: (...args: unknown[]) => mockFetchDynamicSessionDetail(...args),
  stopDynamicSession: (...args: unknown[]) => mockStopDynamicSession(...args),
  injectCanMessage: (...args: unknown[]) => mockInjectCanMessage(...args),
  injectScenario: (...args: unknown[]) => mockInjectScenario(...args),
  getWsBaseUrl: () => "ws://localhost:3000",
  logError: vi.fn(),
}));

vi.mock("@/common/contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

let capturedOptions: Record<string, unknown> = {};

vi.mock("@/common/utils/wsEnvelope", () => ({
  createReconnectingWs: (_urlFactory: () => string, options?: Record<string, unknown>) => {
    capturedOptions = options ?? {};
    (options?.onStateChange as ((state: string) => void) | undefined)?.("connected");
    return {
      getWs: () => fakeWs,
      close: vi.fn(),
      resetRetries: vi.fn(),
      connectionState: "connected",
    };
  },
  createSeqTracker: () => ({ check: vi.fn(), reset: vi.fn() }),
  parseWsMessage: (data: string) => JSON.parse(data),
}));

function makeSession() {
  return {
    id: "session-1",
    source: {
      adapterName: "CAN Adapter",
    },
  } as any;
}

describe("MonitoringView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fakeWs.onmessage = null;
    mockFetchScenarios.mockResolvedValue([
      {
        id: "scenario-1",
        name: "Diagnostic flood",
        description: "진단 요청 범람을 시뮬레이션합니다.",
        severity: "high",
        steps: [{}, {}],
      },
    ]);
    mockFetchInjections.mockResolvedValue([]);
    mockFetchDynamicSessionDetail.mockResolvedValue({
      session: { id: "session-1", status: "running" },
      alerts: [],
      recentMessages: [],
    });
    mockStopDynamicSession.mockResolvedValue(undefined);
    mockInjectCanMessage.mockResolvedValue(undefined);
    mockInjectScenario.mockResolvedValue([]);
  });

  it("renders the waiting empty state and loads scenario/injection data", async () => {
    render(<MonitoringView session={makeSession()} onBack={vi.fn()} onStopped={vi.fn()} />);

    expect(screen.getByText("어댑터에서 데이터 대기 중...")).toBeInTheDocument();
    await waitFor(() => expect(mockFetchScenarios).toHaveBeenCalledWith());
    await waitFor(() => expect(mockFetchInjections).toHaveBeenCalledWith("session-1"));
    expect(screen.getByRole("tab", { name: "CAN 주입" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "세션 목록으로" })).toBeInTheDocument();
  });

  it("surfaces failed connection state through ConnectionStatusBanner when onGiveUp fires", async () => {
    render(<MonitoringView session={makeSession()} onBack={vi.fn()} onStopped={vi.fn()} />);
    await waitFor(() => expect(typeof capturedOptions.onStateChange).toBe("function"));

    act(() => {
      // The real createReconnectingWs always calls setState("failed") -> onStateChange("failed")
      // before invoking onGiveUp. Simulate that sequence here.
      (capturedOptions.onStateChange as (state: string) => void)("failed");
    });

    // The MonitoringView passes wsConnectionState to the banner; once it
    // transitions to "failed", the connection badge reflects a disconnected state.
    expect(screen.getAllByText("연결 끊김").length).toBeGreaterThan(0);
  });

  it("renders websocket messages, flagged packets, and alerts", async () => {
    render(<MonitoringView session={makeSession()} onBack={vi.fn()} onStopped={vi.fn()} />);

    await waitFor(() => expect(fakeWs.onmessage).toBeTypeOf("function"));

    act(() => {
      fakeWs.onmessage?.({
        data: JSON.stringify({
          type: "message",
          payload: {
            id: "0x7DF",
            dlc: 8,
            data: "FF FF FF FF FF FF FF FF",
            timestamp: "2026-04-20T11:50:00Z",
            flagged: true,
            injected: true,
          },
        }),
      });
      fakeWs.onmessage?.({
        data: JSON.stringify({
          type: "alert",
          payload: {
            id: "alert-1",
            severity: "high",
            title: "Diagnostic anomaly",
            description: "비정상 응답 패턴 감지",
            detectedAt: "2026-04-20T11:50:01Z",
            llmAnalysis: "LLM 보조 분석 결과",
          },
        }),
      });
      fakeWs.onmessage?.({
        data: JSON.stringify({
          type: "status",
          payload: {
            messageCount: 1,
            alertCount: 1,
          },
        }),
      });
    });

    expect(screen.queryByText("어댑터에서 데이터 대기 중...")).not.toBeInTheDocument();
    expect(screen.getAllByText("0x7DF").length).toBeGreaterThan(0);
    expect(screen.getByText("알림 패킷 (1)")).toBeInTheDocument();
    expect(screen.getByText("Diagnostic anomaly")).toBeInTheDocument();
    expect(screen.getByText("LLM 보조 분석 결과")).toBeInTheDocument();
  });

  it("fires REST fallback via fetchDynamicSessionDetail on reconnect and merges alerts", async () => {
    mockFetchDynamicSessionDetail.mockResolvedValue({
      session: { id: "session-1", status: "running" },
      alerts: [
        {
          id: "alert-2",
          severity: "medium",
          title: "Replay attack detected",
          description: "재생 공격 감지",
          detectedAt: "2026-05-08T10:00:00Z",
        },
      ],
      recentMessages: [
        {
          id: "0x123",
          dlc: 4,
          data: "DE AD BE EF",
          timestamp: "2026-05-08T10:00:01Z",
          flagged: false,
          injected: false,
        },
      ],
    });

    render(<MonitoringView session={makeSession()} onBack={vi.fn()} onStopped={vi.fn()} />);
    await waitFor(() => expect(typeof capturedOptions.onReconnect).toBe("function"));

    await act(async () => {
      await (capturedOptions.onReconnect as () => Promise<void>)();
    });

    expect(mockFetchDynamicSessionDetail).toHaveBeenCalledWith("session-1");
    expect(screen.getByText("Replay attack detected")).toBeInTheDocument();
    expect(screen.getByText("DE AD BE EF")).toBeInTheDocument();
  });

  it("logs a warning but does not break reconnect cycle when REST recovery fails", async () => {
    mockFetchDynamicSessionDetail.mockRejectedValue(new Error("network error"));
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    render(<MonitoringView session={makeSession()} onBack={vi.fn()} onStopped={vi.fn()} />);
    await waitFor(() => expect(typeof capturedOptions.onReconnect).toBe("function"));

    await act(async () => {
      await (capturedOptions.onReconnect as () => Promise<void>)();
    });

    expect(mockFetchDynamicSessionDetail).toHaveBeenCalledWith("session-1");
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("[WS:dynamic-analysis] REST recovery failed:"),
      expect.any(Error),
    );
    // WS handlers still re-wired — onmessage should be a function
    expect(typeof fakeWs.onmessage).toBe("function");

    warnSpy.mockRestore();
  });
});
