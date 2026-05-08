/**
 * Dev-time mock API handler.
 * Replaces real fetch when VITE_MOCK=true.
 * Route map mirrors e2e/helpers/api-mocker.ts 1:1.
 */
import { ApiError } from "./core";
import * as data from "../../../e2e/fixtures/mock-data";

function delay<T>(value: T): Promise<T> {
  return new Promise((r) => setTimeout(() => r(value), 50));
}

const MOCK_REGISTERED_SDK = {
  id: "sdk-registered-1",
  projectId: "p-1",
  name: "GNU Arm Embedded 13",
  description: "로컬 SDK 마운트",
  path: "/opt/toolchains/gcc-arm-none-eabi",
  profile: {
    compiler: "arm-none-eabi-gcc",
    compilerPrefix: "arm-none-eabi-",
    gccVersion: "13.3.1",
    targetArch: "arm",
    languageStandard: "c11",
    sysroot: "/opt/toolchains/gcc-arm-none-eabi/sysroot",
    environmentSetup: "source /opt/toolchains/gcc-arm-none-eabi/env.sh",
    includePaths: ["/opt/toolchains/gcc-arm-none-eabi/include"],
    defines: { TARGET_MCU: "stm32" },
  },
  status: "ready",
  verified: true,
  createdAt: "2026-03-26T09:00:00Z",
  updatedAt: "2026-03-26T09:10:00Z",
};

const MOCK_PIPELINE_STATUS = {
  targets: [
    {
      id: "t-1",
      name: "gateway-main",
      status: "ready",
      phase: "ready",
      compileCommandsPath: "/workspace/p-1/targets/t-1/compile_commands.json",
      sastScanId: "scan-1",
      codeGraphNodeCount: 1024,
      lastBuiltAt: "2026-03-25T10:00:00Z",
    },
    {
      id: "t-2",
      name: "crypto-lib",
      status: "building",
      phase: "build",
    },
  ],
  readyCount: 1,
  failedCount: 0,
  totalCount: 2,
};

export async function mockApiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const method = options?.method?.toUpperCase() ?? "GET";
  const url = new URL(path, "http://localhost:3000");
  const p = url.pathname;

  // ── Health ──
  if (p === "/health") return delay(data.HEALTH_OK as T);

  // ── Auth ──
  if (p === "/api/auth/me") return delay(data.AUTH_ME_RESPONSE as T);
  if (p === "/api/auth/login" && method === "POST") return delay(data.LOGIN_RESPONSE as T);
  if (p === "/api/auth/logout") return delay({ success: true } as T);
  if (p === "/api/auth/users") return delay({ success: true, data: [data.AUTH_USER] } as T);
  if (p === "/api/auth/password-reset/request" && method === "POST") {
    return delay({ success: true, data: { accepted: true } } as T);
  }
  if (p === "/api/auth/password-reset/confirm" && method === "POST") {
    return delay({ success: true, data: { token: "mock-token:reset", user: data.AUTH_USER } } as T);
  }
  {
    const orgVerifyMatch = p.match(/^\/api\/auth\/orgs\/([^/]+)\/verify$/);
    if (orgVerifyMatch && method === "GET") {
      return delay({ success: true, data: { ...data.ORG_VERIFY_PREVIEW, code: decodeURIComponent(orgVerifyMatch[1]) } } as T);
    }
  }
  if (p === "/api/auth/register" && method === "POST") {
    return delay({ success: true, data: data.REGISTRATION_CREATED } as T);
  }
  {
    const lookupMatch = p.match(/^\/api\/auth\/registrations\/lookup\/([^/]+)$/);
    if (lookupMatch && method === "GET") {
      return delay({ success: true, data: data.REGISTRATION_LOOKUP } as T);
    }
  }
  if (p === "/api/auth/registration-requests" && method === "GET") {
    return delay({ success: true, data: [data.REGISTRATION_LOOKUP] } as T);
  }
  {
    const regRequestMatch = p.match(/^\/api\/auth\/registration-requests\/([^/]+)$/);
    if (regRequestMatch && method === "GET") {
      return delay({ success: true, data: { ...data.REGISTRATION_LOOKUP, id: regRequestMatch[1] } } as T);
    }
  }
  {
    const approveMatch = p.match(/^\/api\/auth\/registration-requests\/([^/]+)\/approve$/);
    if (approveMatch && method === "POST") {
      return delay({
        success: true,
        data: { ...data.REGISTRATION_LOOKUP, id: approveMatch[1], status: "approved", approvedAt: new Date().toISOString() },
      } as T);
    }
    const rejectMatch = p.match(/^\/api\/auth\/registration-requests\/([^/]+)\/reject$/);
    if (rejectMatch && method === "POST") {
      return delay({
        success: true,
        data: { ...data.REGISTRATION_LOOKUP, id: rejectMatch[1], status: "rejected", rejectedAt: new Date().toISOString() },
      } as T);
    }
  }

  // ── Analysis Status (global) ──
  if (p === "/api/analysis/status") return delay(data.ANALYSIS_STATUS_EMPTY as T);
  if (p.startsWith("/api/analysis/summary")) return delay(data.DASHBOARD_SUMMARY as T);

  // ── Analysis quick/deep/abort/results (POST/DELETE/GET) ──
  if (p === "/api/analysis/quick" && method === "POST") {
    return delay({ success: true, data: { analysisId: "mock-analysis-1", buildTargetId: "target-1", executionId: "mock-analysis-1", status: "running" } } as T);
  }
  if (p === "/api/analysis/deep" && method === "POST") {
    const body = options?.body ? JSON.parse(options.body as string) : {};
    return delay({ success: true, data: { analysisId: "mock-analysis-deep-1", buildTargetId: body.buildTargetId ?? "target-1", executionId: "mock-exec-1", status: "running" } } as T);
  }
  if (p === "/api/analysis/poc" && method === "POST") {
    return delay({ success: true, data: { findingId: "find-1", poc: { statement: "Mock PoC", detail: "Mock detail" }, audit: { latencyMs: 500, tokenUsage: { prompt: 100, completion: 50 } } } } as T);
  }
  {
    const abortMatch = p.match(/^\/api\/analysis\/abort\/([^/]+)$/);
    if (abortMatch && method === "POST") {
      return delay({ success: true, data: {} } as T);
    }
  }
  if (p.startsWith("/api/analysis/results") && method === "GET") {
    return delay({ success: true, data: [] } as T);
  }
  {
    const deleteResultMatch = p.match(/^\/api\/analysis\/results\/([^/]+)$/);
    if (deleteResultMatch && method === "DELETE") {
      return delay({ success: true, data: {} } as T);
    }
  }

  // ── Gate Profiles (global) ──
  if (p === "/api/gate-profiles") return delay({ success: true, data: data.GATE_PROFILES } as T);
  for (const gp of data.GATE_PROFILES) {
    if (p === `/api/gate-profiles/${gp.id}`) return delay({ success: true, data: gp } as T);
  }

  // ── SDK Profiles (global) ──
  if (p === "/api/sdk-profiles" && method === "GET") {
    return delay({ success: true, data: [] } as T);
  }
  {
    const sdkProfileMatch = p.match(/^\/api\/sdk-profiles\/([^/]+)$/);
    if (sdkProfileMatch && method === "GET") {
      return delay({ success: true, data: { id: sdkProfileMatch[1], name: "mock" } } as T);
    }
  }

  // ── Projects list ──
  if (p === "/api/projects" && method === "GET") return delay({ success: true, data: data.PROJECTS } as T);
  if (p === "/api/projects" && method === "POST") {
    return delay({ success: true, data: { ...data.PROJECTS[0], id: "p-new", name: "새 프로젝트" } } as T);
  }
  {
    const projectUpdateMatch = p.match(/^\/api\/projects\/([^/]+)$/);
    if (projectUpdateMatch && method === "PUT") {
      const body = options?.body ? JSON.parse(options.body as string) : {};
      const existing = data.PROJECTS.find((proj) => proj.id === projectUpdateMatch[1]) ?? data.PROJECTS[0];
      return delay({ success: true, data: { ...existing, ...body, id: projectUpdateMatch[1] } } as T);
    }
  }

  // ── Run Detail (no project prefix) ──
  if (p === "/api/runs/run-1") {
    return delay({
      success: true,
      data: {
        run: data.RUNS[0],
        gate: data.GATES[0],
        findings: data.FINDINGS.slice(0, 4).map((f) => ({ finding: f, evidenceRefs: [] })),
      },
    } as T);
  }
  if (p === "/api/runs/run-2") {
    return delay({
      success: true,
      data: {
        run: data.RUNS[1],
        findings: data.FINDINGS.slice(4).map((f) => ({ finding: f, evidenceRefs: [] })),
      },
    } as T);
  }

  // ── Individual Finding Detail ──
  for (const f of data.FINDINGS) {
    if (p === `/api/findings/${f.id}`) {
      const evidenceRefs = data.EVIDENCE_REFS.filter((e) => e.findingId === f.id);
      const auditLog = data.AUDIT_LOG_ENTRIES.filter((a) => a.resourceId === f.id);
      return delay({ success: true, data: { ...f, evidenceRefs, auditLog } } as T);
    }
  }

  // ── Finding History / Status ──
  if (p.includes("/api/findings/") && p.endsWith("/history")) {
    return delay({ success: true, data: [] } as T);
  }
  if (p.includes("/api/findings/") && p.endsWith("/status") && method === "PATCH") {
    return delay({ success: true, data: data.FINDINGS[0] } as T);
  }
  if (p === "/api/findings/bulk-status" && method === "PATCH") {
    return delay({ success: true, data: { updated: 1, failed: 0 } } as T);
  }

  // ── Gate override ──
  if (p.includes("/api/gates/") && p.endsWith("/override") && method === "POST") {
    return delay({ success: true } as T);
  }

  // ── Approval detail (top-level) ──
  {
    const approvalDetailMatch = p.match(/^\/api\/approvals\/([^/]+)$/);
    if (approvalDetailMatch && method === "GET") {
      const existing = data.APPROVALS.find((a) => a.id === approvalDetailMatch[1]) ?? data.APPROVALS[0];
      return delay({ success: true, data: existing } as T);
    }
    const approvalDecideMatch = p.match(/^\/api\/approvals\/([^/]+)\/decide$/);
    if (approvalDecideMatch && method === "POST") {
      const existing = data.APPROVALS.find((a) => a.id === approvalDecideMatch[1]) ?? data.APPROVALS[0];
      const body = options?.body ? JSON.parse(options.body as string) : {};
      return delay({ success: true, data: { ...existing, status: body.decision ?? "approved" } } as T);
    }
  }

  // ── Project-scoped routes ──
  const pidMatch = p.match(/^\/api\/projects\/([^/]+)/);
  if (pidMatch) {
    const pid = pidMatch[1];
    const sub = p.slice(`/api/projects/${pid}`.length);

    // Overview (Pattern A)
    if (sub === "/overview") return delay(data.projectOverview(pid) as T);

    // Source
    if (sub === "/source/files") return delay(data.SOURCE_FILES_RESPONSE as T);
    if (sub.startsWith("/source/file")) return delay(data.FILE_CONTENT_RESPONSE as T);

    // Files
    if (sub === "/files" && method === "GET") return delay({ success: true, data: data.FILES } as T);

    // Targets
    if (sub === "/targets" && method === "GET") return delay({ success: true, data: data.TARGETS } as T);
    if (sub === "/targets/discover" && method === "POST") {
      return delay({
        success: true,
        data: {
          discovered: data.TARGETS.length,
          created: 0,
          targets: data.TARGETS,
          elapsedMs: 128,
        },
      } as T);
    }

    // Build log (per target)
    if (sub === "/targets/t-1/build-log") {
      return delay({ success: true, data: { buildLog: data.BUILD_LOG, status: "ready", updatedAt: "2026-03-25T09:56:05Z" } } as T);
    }
    if (sub === "/targets/t-2/build-log") {
      return delay({ success: true, data: { buildLog: null, status: "building", updatedAt: "2026-03-27T09:00:00Z" } } as T);
    }

    // Target libraries
    if (sub.match(/\/targets\/[^/]+\/libraries/)) return delay({ success: true, data: [] } as T);

    // Findings
    if (sub === "/findings" && method === "GET") return delay({ success: true, data: data.FINDINGS } as T);
    if (sub === "/findings/groups") return delay({ success: true, data: data.FINDING_GROUPS } as T);

    // Runs
    if (sub === "/runs") return delay({ success: true, data: data.RUNS } as T);

    // Gates
    if (sub === "/gates") return delay({ success: true, data: data.GATES } as T);

    // Approvals
    if (sub === "/approvals" && method === "GET") return delay({ success: true, data: data.APPROVALS } as T);
    if (sub === "/approvals/count") return delay(data.APPROVAL_COUNT as T);

    // Activity
    if (sub.startsWith("/activity")) {
      const limit = Number(url.searchParams.get("limit") ?? "10");
      const activity = data.ACTIVITIES
        .filter((entry) => {
          const activityProjectId = typeof entry.metadata?.projectId === "string" ? entry.metadata.projectId : pid;
          return activityProjectId === pid;
        })
        .slice(0, Number.isFinite(limit) && limit > 0 ? limit : data.ACTIVITIES.length);

      return delay({ success: true, data: activity } as T);
    }

    // SDK
    if (sub === "/sdk" && method === "GET") {
      return delay({ success: true, data: { builtIn: [], registered: [MOCK_REGISTERED_SDK] } } as T);
    }
    if (sub === "/sdk" && method === "POST") {
      return delay({
        success: true,
        data: {
          ...MOCK_REGISTERED_SDK,
          id: "sdk-uploading-1",
          status: "uploading",
          verified: false,
          updatedAt: "2026-03-26T09:12:00Z",
        },
      } as T);
    }

    // Settings
    if (sub === "/settings" && method === "GET") {
      return delay({ success: true, data: { llmUrl: "http://localhost:8080", gateProfileId: "gp-default" } } as T);
    }
    if (sub === "/settings" && method === "PUT") {
      return delay({ success: true, data: { llmUrl: "http://localhost:8080", gateProfileId: "gp-default" } } as T);
    }

    // Report
    if (sub === "/report" && method === "GET") return delay(data.PROJECT_REPORT as T);
    if (sub === "/report/custom" && method === "POST") return delay({ success: true, data: data.CUSTOM_REPORT_RESPONSE } as T);

    // Pipeline
    if (sub === "/pipeline/status") {
      return delay({ success: true, data: MOCK_PIPELINE_STATUS } as T);
    }
    if (sub === "/pipeline/run" && method === "POST") {
      return delay({ success: true, data: { pipelineId: "mock-pipeline-1", status: "running" } } as T);
    }
    if (sub.startsWith("/pipeline/run/") && method === "POST") {
      return delay({ success: true, data: { targetId: sub.slice("/pipeline/run/".length), status: "running" } } as T);
    }
    if (sub === "/pipeline/prepare" && method === "POST") {
      return delay({ success: true, data: { preparationId: "mock-prep-1", status: "running" } } as T);
    }
    {
      const prepTargetMatch = sub.match(/^\/pipeline\/prepare\/([^/]+)$/);
      if (prepTargetMatch && method === "POST") {
        return delay({ success: true, data: { preparationId: "mock-prep-1", targetId: prepTargetMatch[1], status: "running" } } as T);
      }
    }

    // Findings summary
    if (sub === "/findings/summary" && method === "GET") {
      return delay({ success: true, data: { total: 0 } } as T);
    }

    // SDK metrics
    if (sub === "/sdk/metrics" && method === "GET") {
      return delay({ success: true, data: {} } as T);
    }

    // Gates runs
    {
      const gateRunMatch = sub.match(/^\/gates\/runs\/([^/]+)$/);
      if (gateRunMatch && method === "GET") {
        return delay({ success: true, data: [] } as T);
      }
    }

    // Notifications
    if (sub === "/notifications" && method === "GET") return delay({ success: true, data: data.NOTIFICATIONS } as T);
    if (sub === "/notifications/count") return delay(data.NOTIFICATION_COUNT as T);
    if (sub === "/notifications/read-all" && method === "PATCH") return delay({ success: true } as T);

    // Source bulk delete — simulate 409 blocker when ?simulateBlocker=1 or pid === "p-blocked"
    if (sub === "/source" && method === "DELETE") {
      if (url.searchParams.get("simulateBlocker") === "1" || pid === "p-blocked") {
        throw new ApiError(
          "이미 실행 중인 작업이 있습니다.",
          "CONFLICT",
          false,
          "mock-request-id",
          "다음 항목이 활성 상태이므로 소스를 삭제할 수 없습니다: [활성 분석 1건, 빌드 타겟 2개]",
          { blockers: ["활성 분석 1건", "빌드 타겟 2개"] },
        );
      }
      return delay({ success: true } as T);
    }

    // Delete operations
    if (method === "DELETE") return delay({ success: true } as T);
  }

  // ── Top-level file content (FileDetailPage mock) ──
  if (p.match(/^\/api\/files\/[^/]+\/content$/) && method === "GET") {
    const fileId = p.split("/")[3];
    const file = data.FILES.find((entry) => entry.id === fileId);
    return delay({
      success: true,
      data: {
        ...data.FILE_CONTENT_RESPONSE.data,
        path: file?.path ?? data.FILE_CONTENT_RESPONSE.data.path,
        language: file?.language ?? data.FILE_CONTENT_RESPONSE.data.language,
      },
    } as T);
  }

  // ── Notification mark read ──
  if (p.startsWith("/api/notifications/") && method === "PATCH") return delay({ success: true } as T);

  // ── Fallback ──
  console.warn(`[MOCK] Unhandled: ${method} ${p}`);
  return delay({ success: true, data: [] } as T);
}
