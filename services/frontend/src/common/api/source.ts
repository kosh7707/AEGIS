import type {
  ProjectFilesResponse,
  UploadedFile,
} from "@aegis/shared";
import { apiFetch, ApiError, getBaseUrl } from "./core";

// ── Source File Types ──

export interface SourceFileEntry {
  relativePath: string;
  size: number;
  language: string;
  fileType?: "source" | "config" | "build" | "script" | "doc" | "linker" | "executable" | "object" | "shared-lib" | "archive" | "image" | "unknown";
  previewable?: boolean;
}

export interface SourceUploadAccepted {
  uploadId: string;
  status: string;
}

export interface SourceUploadResponse {
  projectPath?: string;
  fileCount: number;
  savedCount?: number;
  files: SourceFileEntry[];
  mode?: "archive" | "files";
}

export interface TargetMappingEntry {
  targetId: string;
  targetName: string;
}

export interface SourceFilesResponse {
  success: boolean;
  data: SourceFileEntry[];
  composition?: Record<string, { count: number; bytes: number }>;
  totalFiles?: number;
  totalSize?: number;
  targetMapping?: Record<string, TargetMappingEntry>;
}

export interface SourceFileContentResponse {
  path: string;
  content: string;
  language: string;
  size: number;
  fileType?: string;
  previewable?: boolean;
  lineCount?: number;
}

export interface FileContentResponse {
  id: string;
  name: string;
  path: string;
  language: string;
  content: string;
}

// ── Source Management ──

/**
 * Unified source upload — handles both archives and individual files.
 * POST /api/projects/:pid/source/upload (FormData, field "file", 1~N files)
 * Returns 202 Accepted with uploadId for WS progress tracking.
 */
export async function uploadSource(projectId: string, fileOrFiles: File | File[]): Promise<SourceUploadAccepted> {
  const formData = new FormData();
  const files = Array.isArray(fileOrFiles) ? fileOrFiles : [fileOrFiles];
  for (const f of files) formData.append("file", f);
  const res = await apiFetch<{ success: boolean; data: SourceUploadAccepted }>(
    `/api/projects/${projectId}/source/upload`,
    { method: "POST", body: formData },
  );
  return res.data;
}

export async function cloneSource(projectId: string, gitUrl: string, branch?: string): Promise<SourceUploadResponse> {
  const res = await apiFetch<{ success: boolean; data: SourceUploadResponse }>(
    `/api/projects/${projectId}/source/clone`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ gitUrl, branch: branch || undefined }),
    },
  );
  return res.data;
}

export async function fetchSourceFiles(
  projectId: string,
  filter?: "source",
): Promise<SourceFileEntry[]> {
  const query = filter ? `?filter=${encodeURIComponent(filter)}` : "";
  const res = await apiFetch<SourceFilesResponse>(
    `/api/projects/${projectId}/source/files${query}`,
  );
  return res.data;
}

export async function fetchSourceFilesWithComposition(
  projectId: string,
  filter?: "source",
): Promise<SourceFilesResponse> {
  const query = filter ? `?filter=${encodeURIComponent(filter)}` : "";
  return apiFetch<SourceFilesResponse>(
    `/api/projects/${projectId}/source/files${query}`,
  );
}

export async function fetchSourceFileContent(
  projectId: string,
  path: string,
): Promise<SourceFileContentResponse> {
  const res = await apiFetch<{ success: boolean; data: SourceFileContentResponse }>(
    `/api/projects/${projectId}/source/file?path=${encodeURIComponent(path)}`,
  );
  return res.data;
}

// ── Project Files ──

export async function fetchProjectFiles(projectId: string): Promise<UploadedFile[]> {
  const res = await apiFetch<ProjectFilesResponse>(`/api/projects/${projectId}/files`);
  return res.data;
}

export async function downloadFile(fileId: string): Promise<string> {
  const requestId = crypto.randomUUID();
  const res = await fetch(`${getBaseUrl()}/api/files/${fileId}/download`, {
    headers: { "X-Request-Id": requestId },
  });
  if (!res.ok) throw new ApiError(`Download failed: ${res.status}`, "DOWNLOAD_ERROR", false, requestId);
  return res.text();
}

export async function fetchFileContent(fileId: string): Promise<FileContentResponse> {
  const res = await apiFetch<{ success: boolean; data: FileContentResponse }>(`/api/files/${fileId}/content`);
  return res.data;
}

export async function deleteProjectFile(projectId: string, fileId: string): Promise<void> {
  await apiFetch(`/api/projects/${projectId}/files/${fileId}`, { method: "DELETE" });
}

// ── Upload Status Recovery ──

export interface UploadStatusSnapshot {
  phase: string;
  message?: string;
  fileCount?: number;
  projectPath?: string;
  error?: string;
}

export async function fetchUploadStatus(
  projectId: string,
  uploadId: string,
): Promise<UploadStatusSnapshot> {
  const res = await apiFetch<{ success: boolean; data: UploadStatusSnapshot }>(
    `/api/projects/${projectId}/source/upload-status/${uploadId}`,
  );
  return res.data;
}

export async function deleteSource(projectId: string): Promise<void> {
  await apiFetch(`/api/projects/${projectId}/source`, { method: "DELETE" });
}
