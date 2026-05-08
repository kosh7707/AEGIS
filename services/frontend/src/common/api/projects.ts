import type {
  Project,
  ProjectListItem,
  ProjectCreateRequest,
  ProjectResponse,
  ProjectListResponse,
  ProjectOverviewResponse,
  ProjectSettings,
} from "@aegis/shared";
import { apiFetch } from "./core";

// ── Projects ──

export async function fetchProjects(): Promise<ProjectListItem[]> {
  const res = await apiFetch<ProjectListResponse>("/api/projects");
  return res.data;
}

export async function fetchProject(id: string): Promise<Project> {
  const res = await apiFetch<ProjectResponse>(`/api/projects/${id}`);
  return res.data!;
}

export async function createProject(req: ProjectCreateRequest): Promise<Project> {
  const res = await apiFetch<ProjectResponse>("/api/projects", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  return res.data!;
}

export async function deleteProject(id: string): Promise<void> {
  await apiFetch(`/api/projects/${id}`, { method: "DELETE" });
}

// ── Project Settings ──

export async function fetchProjectSettings(projectId: string): Promise<ProjectSettings> {
  const res = await apiFetch<{ success: boolean; data: ProjectSettings }>(`/api/projects/${projectId}/settings`);
  return res.data;
}

export async function updateProjectSettings(projectId: string, settings: Partial<ProjectSettings>): Promise<ProjectSettings> {
  const res = await apiFetch<{ success: boolean; data: ProjectSettings }>(`/api/projects/${projectId}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(settings),
  });
  return res.data;
}

// ── Project Overview ──

export async function fetchProjectOverview(projectId: string): Promise<ProjectOverviewResponse> {
  // Contract: GET /api/projects/:id/overview returns { success, data: ProjectOverviewResponse }
  const res = await apiFetch<{ success: boolean; data: ProjectOverviewResponse }>(
    `/api/projects/${projectId}/overview`,
  );
  return res.data;
}

// ── Project Update ──

export async function updateProject(projectId: string, body: { name: string }): Promise<Project> {
  // Contract: PUT /api/projects/:id — trims name; 400 on empty
  const res = await apiFetch<ProjectResponse>(`/api/projects/${projectId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.data!;
}

// ── Activity Timeline ──

export type ActivityType = "run_completed" | "finding_status_changed" | "approval_decided" | "pipeline_completed" | "source_uploaded";

export interface ActivityEntry {
  type: ActivityType;
  timestamp: string;
  summary: string;
  metadata: Record<string, unknown>;
}

export async function fetchProjectActivity(projectId: string, limit: number = 10): Promise<ActivityEntry[]> {
  const res = await apiFetch<{ success: boolean; data: ActivityEntry[] }>(
    `/api/projects/${projectId}/activity?limit=${limit}`,
  );
  return res.data;
}
