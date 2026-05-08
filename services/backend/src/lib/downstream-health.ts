export type HealthRequestState = "idle" | "queued" | "running" | "completed" | "failed" | "cancelled" | "expired";
export type HealthLocalAckState = "phase-advancing" | "transport-only" | "ack-break";
export type HealthPollDecision = "continue_waiting" | "chain_abort" | "no_active_request" | "inconclusive";
export type DownstreamServiceStatus = "ok" | "degraded" | "unreachable";

export interface DownstreamControlSummary {
  activeRequestCount: number | null;
  requestId: string | null;
  endpoint: string | null;
  state: HealthRequestState;
  localAckState: HealthLocalAckState | null;
  degraded: boolean;
  degradeReasons: string[];
  lastAckAt: number | null;
  lastAckSource: string | null;
  blockedReason: string | null;
  pollDecision: HealthPollDecision;
  decisionReasons: string[];
}

export interface DownstreamServiceHealth {
  status: DownstreamServiceStatus;
  detail?: Record<string, unknown>;
  control?: DownstreamControlSummary;
}

const REQUEST_STATES = ["idle", "queued", "running", "completed", "failed", "cancelled", "expired"] as const;
const LOCAL_ACK_STATES = ["phase-advancing", "transport-only", "ack-break"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseRequestState(value: unknown): HealthRequestState | null {
  return REQUEST_STATES.includes(value as HealthRequestState)
    ? value as HealthRequestState
    : null;
}

function parseLocalAckState(value: unknown): HealthLocalAckState | null {
  return LOCAL_ACK_STATES.includes(value as HealthLocalAckState)
    ? value as HealthLocalAckState
    : null;
}

function mapAckStatus(value: unknown): HealthLocalAckState | null {
  const ackStatus = asString(value);
  if (ackStatus === "broken") return "ack-break";
  if (ackStatus === "active") return "phase-advancing";
  return null;
}

export function buildHealthCheckUrl(baseUrl: string, requestId?: string): string {
  const url = new URL(baseUrl);
  url.pathname = "/v1/health";
  url.search = "";
  if (requestId) {
    url.searchParams.set("requestId", requestId);
  }
  return url.toString();
}

export function normalizeControlSummary(
  data: Record<string, unknown>,
): DownstreamControlSummary | undefined {
  const requestSummary = data.requestSummary;
  if (!isRecord(requestSummary)) return undefined;

  const state = parseRequestState(requestSummary.state) ?? "idle";
  const localAckState = parseLocalAckState(requestSummary.localAckState)
    ?? mapAckStatus(requestSummary.ackStatus);
  const degraded = asBoolean(requestSummary.degraded) ?? false;
  const blockedReason = asString(requestSummary.blockedReason);
  const activeRequestCount = asNumber(data.activeRequestCount);
  const degradeReasons = asStringArray(requestSummary.degradeReasons);

  let pollDecision: HealthPollDecision = "inconclusive";
  const decisionReasons: string[] = [];

  if (blockedReason) {
    pollDecision = "chain_abort";
    decisionReasons.push("blocked-reason-present");
  } else if (localAckState === "ack-break") {
    pollDecision = "chain_abort";
    decisionReasons.push("local-ack-break");
  } else if (state === "failed") {
    pollDecision = "chain_abort";
    decisionReasons.push("state-failed");
  } else if (state === "cancelled") {
    pollDecision = "chain_abort";
    decisionReasons.push("state-cancelled");
  } else if (state === "expired") {
    pollDecision = "chain_abort";
    decisionReasons.push("state-expired");
  } else if (state === "idle") {
    pollDecision = "no_active_request";
    decisionReasons.push("state-idle");
  } else if (state === "completed") {
    pollDecision = "no_active_request";
    decisionReasons.push("state-completed");
  } else if (state === "queued") {
    pollDecision = "continue_waiting";
    decisionReasons.push("state-queued");
  } else if (state === "running" && localAckState === "phase-advancing") {
    pollDecision = "continue_waiting";
    decisionReasons.push("running-phase-advancing");
  } else if (state === "running" && localAckState === "transport-only") {
    pollDecision = "continue_waiting";
    decisionReasons.push("running-transport-only");
  } else if (degraded) {
    pollDecision = "continue_waiting";
    decisionReasons.push("degraded-without-ack-break");
  } else {
    decisionReasons.push("insufficient-request-summary");
  }

  return {
    activeRequestCount,
    requestId: asString(requestSummary.requestId),
    endpoint: asString(requestSummary.endpoint),
    state,
    localAckState,
    degraded,
    degradeReasons,
    lastAckAt: asNumber(requestSummary.lastAckAt),
    lastAckSource: asString(requestSummary.lastAckSource),
    blockedReason,
    pollDecision,
    decisionReasons,
  };
}

export function toDownstreamServiceHealth(data: Record<string, unknown> | null): DownstreamServiceHealth {
  if (!data) return { status: "unreachable" };

  const childStatus = asString(data.status);
  const policyStatus = asString(data.policyStatus);
  const topLevelDegraded = asBoolean(data.degraded) === true;
  const control = normalizeControlSummary(data);
  const hasIssue = topLevelDegraded
    || (childStatus !== null && childStatus !== "ok")
    || (policyStatus !== null && policyStatus !== "ok")
    || control?.degraded === true
    || control?.pollDecision === "chain_abort";

  return {
    status: hasIssue ? "degraded" : "ok",
    detail: data,
    ...(control ? { control } : {}),
  };
}
