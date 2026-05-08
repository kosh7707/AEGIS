/**
 * WS Envelope meta handling — seq gap detection and server timestamp extraction.
 *
 * S2 backend sends WS messages in **flattened** shape:
 *   { type, ...fields, meta?: { channel, projectId?, timestamp, seq? } }
 *
 * parseWsMessage normalizes flattened → internal nested shape:
 *   { type, payload: { ...fields }, meta? }
 *
 * This allows hook code to use the consistent msg.payload.X access pattern.
 */

export interface WsEnvelopeMeta {
  channel: string;
  projectId?: string;
  timestamp: number;
  seq?: number;
}

export interface WsMessage<T = unknown> {
  type: string;
  payload: T;
  meta?: WsEnvelopeMeta;
}

/**
 * Creates a seq tracker for a single WS connection.
 * Call `check(meta)` on each message to detect gaps.
 */
export function createSeqTracker(channelLabel: string) {
  let lastSeq: number | null = null;

  return {
    /** Check for seq gap. Returns gap size (0 = ok, >0 = missed messages). */
    check(meta?: WsEnvelopeMeta): number {
      if (!meta?.seq) return 0;
      const gap = lastSeq !== null ? meta.seq - lastSeq - 1 : 0;
      if (gap > 0) {
        console.warn(
          `[WS:${channelLabel}] seq gap detected: expected ${lastSeq! + 1}, got ${meta.seq} (${gap} message(s) missed)`,
        );
      }
      lastSeq = meta.seq;
      return Math.max(0, gap);
    },

    /** Reset tracker (e.g., on reconnect). */
    reset() {
      lastSeq = null;
    },
  };
}

/**
 * Parse WS message data with envelope support.
 * Normalizes S2's flattened shape { type, ...fields, meta } into
 * internal nested shape { type, payload: { ...fields }, meta }.
 * Also handles legacy nested shape for backward compatibility.
 */
export function parseWsMessage<T = unknown>(data: string): WsMessage<T> {
  const raw = JSON.parse(data);
  // Already in nested shape (has payload field) — pass through
  if (raw.payload !== undefined) {
    return raw as WsMessage<T>;
  }
  // Flattened shape from S2: { type, ...fields, meta } → { type, payload, meta }
  const { type, meta, ...rest } = raw;
  return { type, payload: rest as T, meta };
}

// ── Reconnection & Heartbeat Utilities ──

export type ConnectionState = "connected" | "disconnected" | "reconnecting" | "failed";

/** Interface that all reconnectable hooks must satisfy for connectionState exposure */
export interface ReconnectableHookResult {
  connectionState: ConnectionState;
}

export interface ReconnectOptions {
  maxRetries?: number;
  initialDelay?: number;
  maxDelay?: number;
  backoffFactor?: number;
  jitterFactor?: number;
  onStateChange?: (state: ConnectionState) => void;
  onDisconnect?: () => void;
  onReconnect?: () => void;
  onGiveUp?: () => void;
  /** Override WebSocket constructor (for testing) */
  WebSocketCtor?: typeof WebSocket;
}

interface ReconnectingWs {
  getWs(): WebSocket | null;
  connectionState: ConnectionState;
  close(): void;
  resetRetries(): void;
}

const RECONNECT_DEFAULTS = {
  maxRetries: 10,
  initialDelay: 500,
  maxDelay: 30_000,
  backoffFactor: 2,
  jitterFactor: 0.2,
} as const;

function applyJitter(delay: number, factor: number): number {
  const jitter = delay * factor * (2 * Math.random() - 1);
  return Math.max(0, delay + jitter);
}

/**
 * Creates a reconnecting WebSocket wrapper with exponential backoff + jitter.
 *
 * Each hook wires `onStateChange` to a `useState<ConnectionState>` setter
 * for React re-renders. `close()` cancels all pending timers — safe for
 * React cleanup effects.
 */
export function createReconnectingWs(
  urlFactory: () => string,
  options?: ReconnectOptions,
): ReconnectingWs {
  const { WebSocketCtor = WebSocket, ...restOpts } = { ...RECONNECT_DEFAULTS, ...options };
  const opts = restOpts;
  let ws: WebSocket | null = null;
  let state: ConnectionState = "disconnected";
  let retryCount = 0;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;

  function setState(next: ConnectionState) {
    if (state === next) return;
    state = next;
    opts.onStateChange?.(next);
  }

  function clearTimer() {
    if (retryTimer !== null) {
      clearTimeout(retryTimer);
      retryTimer = null;
    }
  }

  function connect() {
    if (closed) return;
    try {
      ws = new WebSocketCtor(urlFactory());
    } catch {
      scheduleRetry();
      return;
    }

    ws.onopen = () => {
      retryCount = 0;
      const wasReconnecting = state === "reconnecting";
      setState("connected");
      if (wasReconnecting) opts.onReconnect?.();
    };

    ws.onclose = (event) => {
      if (closed) return;
      ws = null;
      opts.onDisconnect?.();
      // S2 close code 4000 = missing subscription key (shared WsBroadcaster, applies to all WS channels).
      // Permanent failure — retrying would loop forever.
      if (event?.code === 4000) {
        setState("failed");
        opts.onGiveUp?.();
        return;
      }
      scheduleRetry();
    };

    ws.onerror = () => {
      // onclose will fire after onerror — reconnect is handled there
    };
  }

  function scheduleRetry() {
    if (closed) return;
    if (retryCount >= opts.maxRetries) {
      setState("failed");
      opts.onGiveUp?.();
      return;
    }
    setState("reconnecting");
    const baseDelay = Math.min(
      opts.initialDelay * Math.pow(opts.backoffFactor, retryCount),
      opts.maxDelay,
    );
    const delay = applyJitter(baseDelay, opts.jitterFactor);
    retryCount++;
    retryTimer = setTimeout(connect, delay);
  }

  connect();

  return {
    getWs: () => ws,
    get connectionState() {
      return state;
    },
    close() {
      closed = true;
      clearTimer();
      if (ws) {
        const sock = ws;
        ws = null;
        sock.onclose = null;
        sock.onerror = null;
        // readyState: 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
        if (sock.readyState === 1 || sock.readyState === 2) {
          sock.close();
        } else if (sock.readyState === 0) {
          // WS hasn't connected yet — close once handshake completes to avoid
          // browser warning "WebSocket is closed before the connection is established"
          sock.onopen = () => sock.close();
        }
      }
    },
    resetRetries() {
      retryCount = 0;
    },
  };
}
