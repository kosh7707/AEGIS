import type {
  GateProfile,
  GateResult as SharedGateResult,
  GateRuleResult as SharedGateRuleResult,
  GateRuleMetric,
  GateRuleMetricUnit,
  GateRuleId as SharedGateRuleId,
  GateStatus as SharedGateStatus,
} from "@aegis/shared";
import { apiFetch } from "./core";

/* ── Types ── */

export type GateStatus = SharedGateStatus;
export type GateRuleId = SharedGateRuleId;
export type { GateRuleMetric, GateRuleMetricUnit };

export type GateRuleResult = SharedGateRuleResult;
export type GateResult = SharedGateResult;

/* ── API ── */

export async function fetchProjectGates(projectId: string): Promise<GateResult[]> {
  const res = await apiFetch<{ success: boolean; data: GateResult[] }>(
    `/api/projects/${projectId}/gates`,
  );
  return res.data;
}

export async function overrideGate(
  gateId: string,
  reason: string,
  actor?: string,
): Promise<void> {
  await apiFetch(`/api/gates/${gateId}/override`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason, actor }),
  });
}

// ── Gate Profiles ──

export async function fetchGateProfile(profileId: string): Promise<GateProfile> {
  const res = await apiFetch<{ success: boolean; data: GateProfile }>(
    `/api/gate-profiles/${profileId}`,
  );
  return res.data;
}

// ── Run-scoped Gate Results ──

export async function fetchGateRunResults(projectId: string, runId: string): Promise<GateResult[]> {
  const res = await apiFetch<{ success: boolean; data: GateResult[] }>(
    `/api/projects/${projectId}/gates/runs/${runId}`,
  );
  return res.data;
}
