import { apiFetch, getBaseUrl, getWsBaseUrl } from "./core";
import type {
  SdkRegistryStatus as _SdkRegistryStatus,
  SdkArtifactKind as _SdkArtifactKind,
  SdkAnalyzedProfile as _SdkAnalyzedProfile,
  RegisteredSdk as _RegisteredSdk,
  SdkErrorCode as _SdkErrorCode,
  SdkErrorPhase as _SdkErrorPhase,
  SdkPhaseDetail as _SdkPhaseDetail,
  SdkProgressPhase as _SdkProgressPhase,
  SdkPhaseHistoryEntry as _SdkPhaseHistoryEntry,
  SdkProfile as _SdkProfile,
  SdkMetrics as _SdkMetrics,
  SdkProfileListResponse,
  SdkProfileResponse,
  SdkMetricsResponse,
} from "@aegis/shared";

/* ── Re-exported shared types ── */

export type SdkRegistryStatus = _SdkRegistryStatus;
export type SdkArtifactKind = _SdkArtifactKind;
export type SdkAnalyzedProfile = _SdkAnalyzedProfile;
export type RegisteredSdk = _RegisteredSdk;
export type SdkErrorCode = _SdkErrorCode;
export type SdkErrorPhase = _SdkErrorPhase;
export type SdkPhaseDetail = _SdkPhaseDetail;
export type SdkProgressPhase = _SdkProgressPhase;
export type SdkPhaseHistoryEntry = _SdkPhaseHistoryEntry;
export type SdkProfile = _SdkProfile;
export type SdkMetrics = _SdkMetrics;

/* ── SDK quota / retry / log response shapes ── */

export interface SdkQuota {
  usedBytes: number;
  maxBytes: number;
  sdkCount: number;
}

export interface SdkLogResponse {
  sdkId: string;
  logPath?: string;
  content: string;
  truncated: boolean;
  totalLines?: number;
  nextOffset?: number;
}

export type SdkRetryFromPhase = "analyzing" | "verifying";

export interface SdkListResponse {
  builtIn: SdkProfile[];
  registered: RegisteredSdk[];
}

/* ── API ── */

export async function fetchProjectSdks(projectId: string): Promise<SdkListResponse> {
  const res = await apiFetch<{ success: boolean; data: SdkListResponse }>(
    `/api/projects/${projectId}/sdk`,
  );
  return res.data;
}

export async function fetchSdkDetail(projectId: string, sdkId: string): Promise<RegisteredSdk> {
  const res = await apiFetch<{ success: boolean; data: RegisteredSdk }>(
    `/api/projects/${projectId}/sdk/${sdkId}`,
  );
  return res.data;
}

export async function registerSdkByUpload(
  projectId: string,
  name: string,
  files: File[],
  description?: string,
  relativePaths?: string[],
): Promise<RegisteredSdk> {
  const formData = new FormData();
  formData.append("name", name);
  if (description) formData.append("description", description);
  if (relativePaths && relativePaths.length > 0) {
    for (let i = 0; i < files.length; i++) {
      formData.append("relativePath", relativePaths[i]);
      formData.append("file", files[i]);
    }
  } else {
    for (const f of files) formData.append("file", f);
  }
  const res = await apiFetch<{ success: boolean; data: RegisteredSdk }>(
    `/api/projects/${projectId}/sdk`,
    { method: "POST", body: formData },
  );
  return res.data;
}

export async function deleteSdk(projectId: string, sdkId: string): Promise<void> {
  await apiFetch(`/api/projects/${projectId}/sdk/${sdkId}`, { method: "DELETE" });
}

export function getSdkWsUrl(projectId: string): string {
  return `${getWsBaseUrl()}/ws/sdk?projectId=${encodeURIComponent(projectId)}`;
}

/* ── Retry / Log / Quota (S2 SDK second follow-up runtime surfaces) ── */

export async function retrySdk(
  projectId: string,
  sdkId: string,
  opts?: { fromPhase?: SdkRetryFromPhase },
): Promise<RegisteredSdk> {
  const init: RequestInit = { method: "POST" };
  if (opts?.fromPhase) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify({ fromPhase: opts.fromPhase });
  }
  const res = await apiFetch<{ success: boolean; data: RegisteredSdk }>(
    `/api/projects/${projectId}/sdk/${sdkId}/retry`,
    init,
  );
  return res.data;
}

export async function fetchSdkLog(
  projectId: string,
  sdkId: string,
  opts?: { tailLines?: number; offset?: number; limit?: number },
): Promise<SdkLogResponse> {
  const params = new URLSearchParams();
  if (opts?.tailLines != null) params.set("tailLines", String(opts.tailLines));
  if (opts?.offset != null) params.set("offset", String(opts.offset));
  if (opts?.limit != null) params.set("limit", String(opts.limit));
  const qs = params.toString();
  const path = `/api/projects/${projectId}/sdk/${sdkId}/log${qs ? `?${qs}` : ""}`;
  const res = await apiFetch<{ success: boolean; data: SdkLogResponse }>(path);
  return res.data;
}

export function getSdkLogDownloadUrl(projectId: string, sdkId: string): string {
  return `${getBaseUrl()}/api/projects/${projectId}/sdk/${sdkId}/log?download=true`;
}

export async function fetchSdkQuota(projectId: string): Promise<SdkQuota> {
  const res = await apiFetch<{ success: boolean; data: SdkQuota }>(
    `/api/projects/${projectId}/sdk/quota`,
  );
  return res.data;
}

/* ── SDK Profiles (GET /api/sdk-profiles) ── */

export async function fetchSdkProfiles(): Promise<SdkProfile[]> {
  const res = await apiFetch<SdkProfileListResponse>("/api/sdk-profiles");
  return res.data;
}

export async function fetchSdkProfile(profileId: string): Promise<SdkProfile> {
  const res = await apiFetch<SdkProfileResponse>(
    `/api/sdk-profiles/${profileId}`,
  );
  if (!res.data) {
    throw new Error(res.error ?? "SDK profile not found");
  }
  return res.data;
}

/* ── SDK Metrics (GET /api/projects/:pid/sdk/metrics) ── */

export async function fetchSdkMetrics(projectId: string): Promise<SdkMetrics> {
  const res = await apiFetch<SdkMetricsResponse>(
    `/api/projects/${projectId}/sdk/metrics`,
  );
  return res.data;
}
