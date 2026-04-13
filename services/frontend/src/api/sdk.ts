import { apiFetch, getWsBaseUrl } from "./core";
import type {
  SdkRegistryStatus as _SdkRegistryStatus,
  SdkArtifactKind as _SdkArtifactKind,
  SdkAnalyzedProfile as _SdkAnalyzedProfile,
  RegisteredSdk as _RegisteredSdk,
} from "@aegis/shared";

/* ── Re-exported shared types ── */

export type SdkRegistryStatus = _SdkRegistryStatus;
export type SdkArtifactKind = _SdkArtifactKind;
export type SdkAnalyzedProfile = _SdkAnalyzedProfile;
export type RegisteredSdk = _RegisteredSdk;

export type SdkLogSource = "aegis" | "installer";
export type SdkLogKind = "lifecycle" | "heartbeat" | "output" | "terminal";
export type SdkLogStream = "stdout" | "stderr";

export interface SdkLogEvent {
  sdkId: string;
  timestamp: string;
  source: SdkLogSource;
  kind: SdkLogKind;
  stream?: SdkLogStream;
  message: string;
  logPath?: string;
}

export interface SdkLogTailResponse {
  sdkId: string;
  logPath?: string;
  content: string;
  truncated: boolean;
}

/* ── Local types (NOT migrated — SdkProfile.defaults shape differs from shared) ── */

export interface SdkProfile {
  id: string;
  name: string;
  vendor: string;
  description: string;
  defaults: {
    compiler: string;
    targetArch: string;
    languageStandard: string;
    headerLanguage: string;
    includePaths?: string[];
    defines?: Record<string, string>;
  };
}

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

export async function fetchSdkInstallLog(
  projectId: string,
  sdkId: string,
  tailLines = 200,
): Promise<SdkLogTailResponse> {
  const params = new URLSearchParams();
  params.set("tailLines", String(tailLines));
  const res = await apiFetch<{ success: boolean; data: SdkLogTailResponse }>(
    `/api/projects/${projectId}/sdk/${sdkId}/log?${params.toString()}`,
  );
  return res.data;
}

/** @deprecated Use registerSdkByUpload instead. Will be removed after S2 confirms localPath removal. */
export async function registerSdkByPath(
  projectId: string,
  name: string,
  localPath: string,
  description?: string,
): Promise<RegisteredSdk> {
  const res = await apiFetch<{ success: boolean; data: RegisteredSdk }>(
    `/api/projects/${projectId}/sdk`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, localPath, description }),
    },
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
