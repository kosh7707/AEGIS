import type {
  StaticAnalysisDashboardSummary,
  StaticDashboardResponse,
  RunDetailResponse,
  AnalysisProgress,
  AnalysisResult,
  AnalysisStatusListResponse,
  Run,
  Finding,
  FindingStatus,
  RunListResponse,
  FindingListResponse,
  FindingDetailResponse,
  FindingStatusUpdateRequest,
  EvidenceRef,
  AuditLogEntry,
  PocResponseData,
  FindingsSummary,
  FindingSummaryResponse,
} from "@aegis/shared";
import { apiFetch } from "./core";

export type { PocResponseData, FindingsSummary } from "@aegis/shared";

// ── Analysis Status (active analysis polling) ──

export async function fetchAllAnalysisStatuses(): Promise<AnalysisProgress[]> {
  const res = await apiFetch<AnalysisStatusListResponse>("/api/analysis/status");
  return res.data;
}

// ── Per-Analysis Recovery (WR endpoints) ──

export async function fetchAnalysisStatus(analysisId: string): Promise<AnalysisProgress> {
  const res = await apiFetch<{ success: boolean; data: AnalysisProgress }>(
    `/api/analysis/status/${analysisId}`,
  );
  return res.data;
}

export async function fetchAnalysisResults(
  analysisId: string,
): Promise<AnalysisResult> {
  const res = await apiFetch<{
    success: boolean;
    data: AnalysisResult;
  }>(`/api/analysis/results/${analysisId}`);
  return res.data;
}

// ── Analysis API ──

export async function runAnalysis(
  projectId: string,
  buildTargetId: string,
): Promise<{ analysisId: string; buildTargetId: string; executionId: string; status: string }> {
  const body = { projectId, buildTargetId };
  const res = await apiFetch<{
    success: boolean;
    data: { analysisId: string; buildTargetId: string; executionId: string; status: string };
  }>(
    "/api/analysis/quick",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  return res.data;
}

export async function runDeepAnalysis(
  projectId: string,
  buildTargetId: string,
): Promise<{ analysisId: string; buildTargetId: string; executionId: string; status: string }> {
  const body = { projectId, buildTargetId };
  const res = await apiFetch<{
    success: boolean;
    data: { analysisId: string; buildTargetId: string; executionId: string; status: string };
  }>(
    "/api/analysis/deep",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  return res.data;
}

export async function abortAnalysis(analysisId: string): Promise<void> {
  await apiFetch(
    `/api/analysis/abort/${encodeURIComponent(analysisId)}`,
    { method: "POST" },
  );
}

export async function generatePoc(
  projectId: string,
  findingId: string,
): Promise<PocResponseData> {
  const res = await apiFetch<{ success: boolean; data: PocResponseData }>(
    "/api/analysis/poc",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ projectId, findingId }),
    },
  );
  return res.data;
}

export async function fetchAnalysisResultsList(projectId: string): Promise<AnalysisResult[]> {
  const res = await apiFetch<{ success: boolean; data: AnalysisResult[] }>(
    `/api/analysis/results?projectId=${encodeURIComponent(projectId)}`,
  );
  return res.data;
}

export async function deleteAnalysisResult(analysisId: string): Promise<void> {
  await apiFetch(
    `/api/analysis/results/${encodeURIComponent(analysisId)}`,
    { method: "DELETE" },
  );
}

// ── Findings Summary ──

export async function fetchFindingsSummary(projectId: string): Promise<FindingsSummary> {
  const res = await apiFetch<FindingSummaryResponse>(
    `/api/projects/${encodeURIComponent(projectId)}/findings/summary`,
  );
  return res.data;
}

// ── Dashboard Summary ──

export async function fetchStaticDashboardSummary(
  projectId: string,
  period: string = "30d",
): Promise<StaticAnalysisDashboardSummary> {
  const res = await apiFetch<StaticDashboardResponse>(
    `/api/analysis/summary?projectId=${encodeURIComponent(projectId)}&period=${period}`,
  );
  return res.data!;
}

// ── Runs & Findings ──

export async function fetchProjectRuns(projectId: string): Promise<Run[]> {
  const res = await apiFetch<RunListResponse>(`/api/projects/${projectId}/runs`);
  return res.data;
}

export async function fetchRunDetail(runId: string): Promise<RunDetailResponse["data"]> {
  const res = await apiFetch<RunDetailResponse>(`/api/runs/${runId}`);
  return res.data!;
}

export async function fetchProjectFindings(
  projectId: string,
  filters?: { status?: string; severity?: string; module?: string; q?: string; sort?: string; order?: string; sourceType?: string },
): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (filters?.status) params.set("status", filters.status);
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.module) params.set("module", filters.module);
  if (filters?.q) params.set("q", filters.q);
  if (filters?.sort) params.set("sort", filters.sort);
  if (filters?.order) params.set("order", filters.order);
  if (filters?.sourceType) params.set("sourceType", filters.sourceType);
  const qs = params.toString();
  const res = await apiFetch<FindingListResponse>(
    `/api/projects/${projectId}/findings${qs ? `?${qs}` : ""}`,
  );
  return res.data;
}

export async function fetchFindingDetail(
  findingId: string,
): Promise<Finding & { evidenceRefs: EvidenceRef[]; auditLog: AuditLogEntry[] }> {
  const res = await apiFetch<FindingDetailResponse>(`/api/findings/${findingId}`);
  return res.data!;
}

export async function updateFindingStatus(
  findingId: string,
  status: FindingStatus,
  reason: string,
): Promise<Finding> {
  const res = await apiFetch<{ success: boolean; data: Finding }>(`/api/findings/${findingId}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, reason } satisfies FindingStatusUpdateRequest),
  });
  return res.data;
}

// ── Bulk Status Change ──

export async function bulkUpdateFindingStatus(
  findingIds: string[],
  status: FindingStatus,
  reason: string,
  actor?: string,
): Promise<{ updated: number; failed: number }> {
  const res = await apiFetch<{ success: boolean; data: { updated: number; failed: number } }>(
    "/api/findings/bulk-status",
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findingIds, status, reason, actor }),
    },
  );
  return res.data;
}

// ── Finding History (fingerprint-based) ──

export interface FindingHistoryEntry {
  findingId: string;
  runId: string;
  status: FindingStatus;
  createdAt: string;
}

export async function fetchFindingHistory(findingId: string): Promise<FindingHistoryEntry[]> {
  const res = await apiFetch<{ success: boolean; data: FindingHistoryEntry[] }>(
    `/api/findings/${findingId}/history`,
  );
  return res.data;
}

// ── Finding Groups ──

export interface FindingGroup {
  key: string;
  count: number;
  topSeverity: string;
  findingIds: string[];
}

export async function fetchFindingGroups(
  projectId: string,
  groupBy: "ruleId" | "location" = "ruleId",
): Promise<{ groups: FindingGroup[] }> {
  const res = await apiFetch<{ success: boolean; data: { groups: FindingGroup[] } }>(
    `/api/projects/${projectId}/findings/groups?groupBy=${groupBy}`,
  );
  return res.data;
}
