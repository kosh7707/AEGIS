import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createReconnectingWs,
  type ConnectionState,
  type ReconnectOptions,
} from "./wsEnvelope";

// ── Mock WebSocket ──

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  static autoOpen = true;
  readyState = WebSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  private listeners = new Map<string, Set<(e: unknown) => void>>();
  sent: string[] = [];

  constructor(public url: string) {
    MockWebSocket.instances.push(this);
    if (MockWebSocket.autoOpen) {
      setTimeout(() => this.simulateOpen(), 0);
    }
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.readyState = WebSocket.CLOSED;
    this.onclose?.();
  }

  addEventListener(type: string, listener: (e: unknown) => void) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type)!.add(listener);
  }

  removeEventListener(type: string, listener: (e: unknown) => void) {
    this.listeners.get(type)?.delete(listener);
  }

  simulateOpen() {
    if (this.readyState === WebSocket.OPEN) return;
    this.readyState = WebSocket.OPEN;
    this.onopen?.();
  }

  simulateMessage(data: unknown) {
    const event = { data: JSON.stringify(data) } as MessageEvent;
    this.onmessage?.(event);
    this.listeners.get("message")?.forEach((fn) => fn(event));
  }

  simulateClose() {
    this.readyState = WebSocket.CLOSED;
    this.onclose?.();
  }

  static reset() {
    MockWebSocket.instances = [];
    MockWebSocket.autoOpen = true;
  }
}

const WS_CTOR = MockWebSocket as unknown as typeof WebSocket;

beforeEach(() => {
  vi.useFakeTimers();
  MockWebSocket.reset();
});

afterEach(() => {
  vi.useRealTimers();
});

// ── createReconnectingWs Tests ──

describe("createReconnectingWs", () => {
  it("connects and fires onStateChange('connected')", async () => {
    const states: ConnectionState[] = [];
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      onStateChange: (s) => states.push(s),
    });

    await vi.advanceTimersByTimeAsync(0);
    expect(rws.connectionState).toBe("connected");
    expect(states).toContain("connected");
    expect(MockWebSocket.instances).toHaveLength(1);
    rws.close();
  });

  it("reconnects with exponential backoff on close", () => {
    MockWebSocket.autoOpen = false;
    const onDisconnect = vi.fn();
    const onReconnect = vi.fn();
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 100,
      backoffFactor: 2,
      jitterFactor: 0,
      maxRetries: 3,
      onDisconnect,
      onReconnect,
    });

    // Initial connection
    MockWebSocket.instances[0].simulateOpen();
    expect(rws.connectionState).toBe("connected");

    // Simulate disconnect
    MockWebSocket.instances[0].simulateClose();
    expect(onDisconnect).toHaveBeenCalledTimes(1);
    expect(rws.connectionState).toBe("reconnecting");

    // First retry after 100ms
    vi.advanceTimersByTime(100);
    expect(MockWebSocket.instances).toHaveLength(2);
    MockWebSocket.instances[1].simulateOpen();
    expect(rws.connectionState).toBe("connected");
    expect(onReconnect).toHaveBeenCalledTimes(1);

    rws.close();
  });

  it("gives up after maxRetries and fires onGiveUp", async () => {
    MockWebSocket.autoOpen = false;
    const onGiveUp = vi.fn();
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 50,
      backoffFactor: 1,
      jitterFactor: 0,
      maxRetries: 2,
      onGiveUp,
    });

    // Open first connection, then disconnect
    MockWebSocket.instances[0].simulateOpen();
    MockWebSocket.instances[0].simulateClose();

    // Retry 1 — fails to connect
    vi.advanceTimersByTime(50);
    expect(MockWebSocket.instances).toHaveLength(2);
    MockWebSocket.instances[1].simulateClose();

    // Retry 2 — fails to connect
    vi.advanceTimersByTime(50);
    expect(MockWebSocket.instances).toHaveLength(3);
    MockWebSocket.instances[2].simulateClose();

    // Max retries reached
    expect(rws.connectionState).toBe("failed");
    expect(onGiveUp).toHaveBeenCalledTimes(1);

    rws.close();
  });

  it("backoff delays increase exponentially", () => {
    MockWebSocket.autoOpen = false;
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 100,
      backoffFactor: 2,
      jitterFactor: 0,
      maxRetries: 4,
    });

    MockWebSocket.instances[0].simulateOpen();
    MockWebSocket.instances[0].simulateClose();

    // Retry 1 at 100ms (100 * 2^0)
    vi.advanceTimersByTime(99);
    expect(MockWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(MockWebSocket.instances).toHaveLength(2);
    MockWebSocket.instances[1].simulateClose();

    // Retry 2 at 200ms (100 * 2^1)
    vi.advanceTimersByTime(199);
    expect(MockWebSocket.instances).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(MockWebSocket.instances).toHaveLength(3);
    MockWebSocket.instances[2].simulateClose();

    // Retry 3 at 400ms (100 * 2^2)
    vi.advanceTimersByTime(399);
    expect(MockWebSocket.instances).toHaveLength(3);
    vi.advanceTimersByTime(1);
    expect(MockWebSocket.instances).toHaveLength(4);

    rws.close();
  });

  it("close() cancels pending retry timers", async () => {
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 1000,
      jitterFactor: 0,
      maxRetries: 5,
    });

    await vi.advanceTimersByTimeAsync(0);
    MockWebSocket.instances[0].simulateClose();
    expect(rws.connectionState).toBe("reconnecting");

    // Close before retry fires
    rws.close();
    await vi.advanceTimersByTimeAsync(5000);

    // No new WebSocket created after close
    expect(MockWebSocket.instances).toHaveLength(1);
  });

  it("resetRetries resets the retry counter", async () => {
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 50,
      backoffFactor: 1,
      jitterFactor: 0,
      maxRetries: 1,
    });

    await vi.advanceTimersByTimeAsync(0);
    MockWebSocket.instances[0].simulateClose();
    await vi.advanceTimersByTimeAsync(50);
    await vi.advanceTimersByTimeAsync(0);

    // Reconnected — resetRetries should allow future retries
    rws.resetRetries();
    MockWebSocket.instances[1].simulateClose();
    await vi.advanceTimersByTimeAsync(50);
    await vi.advanceTimersByTimeAsync(0);

    // Should have reconnected again (not failed)
    expect(MockWebSocket.instances).toHaveLength(3);

    rws.close();
  });

  it("successful reconnect resets retry counter automatically", () => {
    MockWebSocket.autoOpen = false;
    const onGiveUp = vi.fn();
    const states: ConnectionState[] = [];
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 50,
      backoffFactor: 1,
      jitterFactor: 0,
      maxRetries: 2,
      onGiveUp,
      onStateChange: (s) => states.push(s),
    });

    MockWebSocket.instances[0].simulateOpen();
    expect(rws.connectionState).toBe("connected");
    MockWebSocket.instances[0].simulateClose();
    expect(rws.connectionState).toBe("reconnecting");

    // Retry succeeds
    vi.advanceTimersByTime(50);
    expect(MockWebSocket.instances).toHaveLength(2);
    // Check that onopen is actually set on the new instance
    expect(MockWebSocket.instances[1].onopen).toBeTruthy();
    MockWebSocket.instances[1].simulateOpen();
    expect(states).toContain("connected");
    expect(rws.connectionState).toBe("connected");

    // Second disconnect — should have fresh retry budget
    MockWebSocket.instances[1].simulateClose();
    vi.advanceTimersByTime(50);
    expect(MockWebSocket.instances).toHaveLength(3);
    MockWebSocket.instances[2].simulateOpen();
    expect(rws.connectionState).toBe("connected");
    expect(onGiveUp).not.toHaveBeenCalled();

    rws.close();
  });

  it("applies jitter to backoff delays", () => {
    MockWebSocket.autoOpen = false;
    vi.spyOn(Math, "random").mockReturnValue(0.75);
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 100,
      backoffFactor: 1,
      jitterFactor: 0.2,
      maxRetries: 2,
    });

    MockWebSocket.instances[0].simulateOpen();
    MockWebSocket.instances[0].simulateClose();

    // random=0.75: jitter = 100 * 0.2 * (2*0.75 - 1) = 10 → delay = 110ms
    vi.advanceTimersByTime(109);
    expect(MockWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(MockWebSocket.instances).toHaveLength(2);

    vi.spyOn(Math, "random").mockRestore();
    rws.close();
  });

  it("caps delay at maxDelay", () => {
    MockWebSocket.autoOpen = false;
    const rws = createReconnectingWs(() => "ws://test", {
      WebSocketCtor: WS_CTOR,
      initialDelay: 1000,
      backoffFactor: 100,
      maxDelay: 500,
      jitterFactor: 0,
      maxRetries: 2,
    });

    MockWebSocket.instances[0].simulateOpen();
    MockWebSocket.instances[0].simulateClose();

    // Should be capped at 500ms
    vi.advanceTimersByTime(499);
    expect(MockWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(MockWebSocket.instances).toHaveLength(2);

    rws.close();
  });
});
