import type {
  ModuleReport,
  ModuleReportResponse,
  ProjectReport,
  ProjectReportResponse,
} from "@aegis/shared";
import { apiFetch } from "./core";

export interface ReportFilters {
  from?: string;
  to?: string;
  severity?: string;
  status?: string;
  runId?: string;
}

function buildReportQuery(filters?: ReportFilters): string {
  if (!filters) return "";
  const params = new URLSearchParams();
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.status) params.set("status", filters.status);
  if (filters.runId) params.set("runId", filters.runId);
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export async function fetchProjectReport(projectId: string, filters?: ReportFilters): Promise<ProjectReport> {
  const res = await apiFetch<ProjectReportResponse>(`/api/projects/${projectId}/report${buildReportQuery(filters)}`);
  return res.data!;
}

async function fetchModuleReport(
  projectId: string,
  moduleSlug: "static" | "dynamic" | "test",
  filters?: ReportFilters,
): Promise<ModuleReport> {
  const res = await apiFetch<ModuleReportResponse>(
    `/api/projects/${projectId}/report/${moduleSlug}${buildReportQuery(filters)}`,
  );
  return res.data!;
}

export async function fetchStaticModuleReport(projectId: string, filters?: ReportFilters): Promise<ModuleReport> {
  return fetchModuleReport(projectId, "static", filters);
}

export async function fetchDynamicModuleReport(projectId: string, filters?: ReportFilters): Promise<ModuleReport> {
  return fetchModuleReport(projectId, "dynamic", filters);
}

export async function fetchTestModuleReport(projectId: string, filters?: ReportFilters): Promise<ModuleReport> {
  return fetchModuleReport(projectId, "test", filters);
}

// ── Custom Report ──

export interface CustomReportOptions {
  reportTitle?: string;
  executiveSummary?: string;
  companyName?: string;
  logoUrl?: string;
  language?: string;
}

export async function generateCustomReport(
  projectId: string,
  customization: CustomReportOptions,
): Promise<{ reportId: string }> {
  const res = await apiFetch<{ success: boolean; data: { reportId: string } }>(
    `/api/projects/${projectId}/report/custom`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(customization),
    },
  );
  return res.data;
}
