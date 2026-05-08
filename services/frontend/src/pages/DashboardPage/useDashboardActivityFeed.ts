import { useEffect, useMemo, useState } from "react";
import { logError } from "@/common/api/core";
import { getNotificationWsUrl } from "@/common/api/notifications";
import { fetchProjectActivity, type ActivityEntry } from "@/common/api/projects";
import {
  createReconnectingWs,
  createSeqTracker,
  parseWsMessage,
  type ConnectionState,
} from "@/common/utils/wsEnvelope";
import type { ActivityEvent, ActivityIcon, ActivityTone, DashboardProject } from "./dashboardTypes";
import {
  latestProjectTimestamp,
  projectIsRunning,
  projectOwner,
  projectPendingApprovals,
  totalFindings,
} from "./dashboardProjectSignals";

interface UseDashboardActivityFeedOptions {
  projects: DashboardProject[];
  pageSize?: number;
}

interface ActivityEnvelope {
  project: DashboardProject;
  entry: ActivityEntry;
}

type ActivityVariant =
  | "analysis_completed"
  | "analysis_started"
  | "approval_requested"
  | "accepted_risk"
  | "build_target_added"
  | "dynamic_test_passed"
  | "gate_blocked"
  | "needs_revalidation";

export function useDashboardActivityFeed({
  projects,
  pageSize = 10,
}: UseDashboardActivityFeedOptions) {
  const [visibleActivityCount, setVisibleActivityCount] = useState(pageSize);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [hasPotentialMore, setHasPotentialMore] = useState(false);
  const [activityRevision, setActivityRevision] = useState(0);
  const [connectionState, setConnectionState] = useState<ConnectionState>(() => (
    import.meta.env.VITE_MOCK === "true" || import.meta.env.MODE === "test"
      ? "connected"
      : "disconnected"
  ));
  const [realtimeOffline, setRealtimeOffline] = useState(false);

  const primaryProjectId = projects[0]?.id;

  useEffect(() => {
    setVisibleActivityCount(pageSize);
  }, [pageSize, projects]);

  useEffect(() => {
    let cancelled = false;

    if (projects.length === 0) {
      setActivity([]);
      setHasPotentialMore(false);
      return () => {
        cancelled = true;
      };
    }

    const requestLimit = Math.max(pageSize, visibleActivityCount);

    Promise.all(
      projects.map(async (project) => ({
        project,
        entries: await fetchProjectActivity(project.id, requestLimit),
      })),
    )
      .then((responses) => {
        if (cancelled) {
          return;
        }

        const nextActivity = buildRemoteActivity(responses);
        setHasPotentialMore(responses.some(({ entries }) => entries.length >= requestLimit));
        setActivity(nextActivity.length > 0 ? nextActivity : buildFallbackActivity(projects));
      })
      .catch((error) => {
        logError("DashboardPage.activity", error);
        if (cancelled) {
          return;
        }
        setHasPotentialMore(false);
        setActivity(buildFallbackActivity(projects));
      });

    return () => {
      cancelled = true;
    };
  }, [activityRevision, pageSize, projects, visibleActivityCount]);

  useEffect(() => {
    if (!primaryProjectId) {
      setConnectionState("disconnected");
      return;
    }

    if (import.meta.env.VITE_MOCK === "true" || import.meta.env.MODE === "test" || typeof WebSocket === "undefined") {
      setConnectionState("connected");
      return;
    }

    setRealtimeOffline(false);
    const seqTracker = createSeqTracker("notification");

    function wireActivityRefresh(ws: WebSocket | null) {
      if (!ws) {
        return;
      }

      ws.onmessage = (event) => {
        try {
          const msg = parseWsMessage(event.data);
          // Drop frames whose envelope channel does not match this consumer.
          if (msg.meta && msg.meta.channel !== "notification") return;
          seqTracker.check(msg.meta);
          // Only notification frames bump activity — drop heartbeat / other types
          // (audit DRIFT: previously every frame triggered an unnecessary REST refresh).
          if (msg.type !== "notification") return;
          setActivityRevision((current) => current + 1);
        } catch {
          // ignore non-JSON / malformed messages
        }
      };
    }

    let socket: ReturnType<typeof createReconnectingWs> | null = null;
    socket = createReconnectingWs(() => getNotificationWsUrl(primaryProjectId), {
      onStateChange: setConnectionState,
      onDisconnect() {
        seqTracker.reset();
      },
      onReconnect() {
        wireActivityRefresh(socket.getWs());
        setActivityRevision((current) => current + 1);
      },
      onGiveUp() {
        // Activity feed has REST refresh fallback already (refreshed on visibleActivityCount/projects changes).
        setRealtimeOffline(true);
      },
    });
    wireActivityRefresh(socket.getWs());

    return () => {
      socket?.close();
    };
  }, [primaryProjectId]);

  const visibleActivity = useMemo(
    () => activity.slice(0, visibleActivityCount),
    [activity, visibleActivityCount],
  );

  const loadMore = () => setVisibleActivityCount((count) => count + pageSize);

  return {
    visibleActivity,
    hasMore: hasPotentialMore || activity.length > visibleActivity.length,
    loadMore,
    connectionState,
    realtimeOffline,
  };
}

function buildRemoteActivity(responses: Array<{ project: DashboardProject; entries: ActivityEntry[] }>): ActivityEvent[] {
  const seen = new Set<string>();

  return responses
    .flatMap(({ project, entries }) => entries.map((entry) => ({ project, entry })))
    .filter(({ project, entry }) => {
      const key = remoteActivityKey(project, entry);
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .map((envelope) => mapRemoteActivity(envelope))
    .sort((left, right) => new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime());
}

function remoteActivityKey(project: DashboardProject, entry: ActivityEntry): string {
  const metadata = entry.metadata ?? {};
  return [
    readString(metadata.projectId) ?? project.id,
    readString(metadata.variant) ?? entry.type,
    readString(metadata.runId),
    readString(metadata.findingId),
    readString(metadata.approvalId),
    readString(metadata.targetName),
    entry.timestamp,
    entry.summary,
  ].filter(Boolean).join(":");
}

function mapRemoteActivity({ project, entry }: ActivityEnvelope): ActivityEvent {
  const metadata = entry.metadata ?? {};
  const projectId = readString(metadata.projectId) ?? project.id;
  const projectName = readString(metadata.projectName) ?? project.name;
  const variant = readVariant(metadata.variant);

  return {
    id: remoteActivityKey(project, entry),
    projectId,
    projectName,
    timestamp: entry.timestamp,
    tone: readTone(metadata.tone) ?? toneFromVariant(variant, entry.type),
    icon: readIcon(metadata.icon) ?? iconFromVariant(variant, entry.type),
    html: buildRemoteActivityHtml(entry, projectName, variant),
  };
}

function buildRemoteActivityHtml(entry: ActivityEntry, projectName: string, variant: ActivityVariant | null): string {
  const metadata = entry.metadata ?? {};
  const escapedProject = escapeHtml(projectName);
  const projectMarkup = `<b><span class="proj">${escapedProject}</span></b>`;
  const actor = readString(metadata.actor);
  const agent = readString(metadata.agent);
  const targetName = readString(metadata.targetName);
  const approvalId = readString(metadata.approvalId);
  const findingId = readString(metadata.findingId);
  const findingStatus = readString(metadata.findingStatus);
  const critical = readNumber(metadata.critical);
  const high = readNumber(metadata.high);
  const blockedRules = readNumber(metadata.blockedRules);
  const totalRules = readNumber(metadata.totalRules);
  const passed = readNumber(metadata.passed);
  const total = readNumber(metadata.total);

  switch (variant) {
    case "analysis_completed":
      if ((critical ?? 0) > 0 || (high ?? 0) > 0) {
        return `${projectMarkup} 정적 분석 완료 · <span class="n critical">${critical ?? 0} crit</span>, <span class="n high">${high ?? 0} high</span> 신규`;
      }
      return `${projectMarkup} 정적 분석 완료 · 신규 없음`;
    case "analysis_started":
      return `${projectMarkup} 정적 분석 시작 · Agent <span class="n">${escapeHtml(agent ?? "taint-flow")}</span> 활성`;
    case "gate_blocked":
      return `${projectMarkup} Quality Gate <b>BLOCKED</b> — 룰 <span class="n">${blockedRules ?? 0}/${totalRules ?? 7}</span> 실패`;
    case "accepted_risk":
      return `<b>${escapeHtml(actor ?? "담당자")}</b>이 ${projectMarkup} finding <span class="n">#${escapeHtml(findingId ?? "F-0000")}</span> 를 <b>accepted-risk</b> 로 승인`;
    case "approval_requested":
      return `<b>${escapeHtml(actor ?? "담당자")}</b>가 ${projectMarkup} 에 승인 요청 <span class="n">#${escapeHtml(approvalId ?? "A-000")}</span> 제출`;
    case "build_target_added":
      return `${projectMarkup} 빌드 타깃 <b>${escapeHtml(targetName ?? "Target")}</b> 추가`;
    case "dynamic_test_passed":
      return `${projectMarkup} 동적 테스트 통과 · <span class="n">${passed ?? 0}/${total ?? 0}</span>`;
    case "needs_revalidation":
      return `${projectMarkup} finding <span class="n">#${escapeHtml(findingId ?? "F-0000")}</span> 재검증 필요 (${escapeHtml(findingStatus ?? "needs-revalidation")})`;
    default:
      return `${projectMarkup} ${escapeHtml(entry.summary)}`;
  }
}

function toneFromVariant(variant: ActivityVariant | null, type: ActivityEntry["type"]): ActivityTone {
  switch (variant) {
    case "analysis_started":
      return "primary";
    case "gate_blocked":
    case "needs_revalidation":
      return "critical";
    case "analysis_completed":
    case "dynamic_test_passed":
      return "success";
    case "accepted_risk":
    case "approval_requested":
    case "build_target_added":
      return "muted";
    default:
      return toneFromType(type);
  }
}

function iconFromVariant(variant: ActivityVariant | null, type: ActivityEntry["type"]): ActivityIcon {
  switch (variant) {
    case "analysis_started":
      return "play";
    case "build_target_added":
      return "branch";
    case "accepted_risk":
    case "approval_requested":
      return "user";
    case "gate_blocked":
    case "needs_revalidation":
      return "alert";
    case "analysis_completed":
    case "dynamic_test_passed":
      return "check";
    default:
      return iconFromType(type);
  }
}

function toneFromType(type: ActivityEntry["type"]): ActivityTone {
  switch (type) {
    case "approval_decided":
    case "source_uploaded":
      return "muted";
    case "pipeline_completed":
      return "critical";
    case "run_completed":
      return "success";
    case "finding_status_changed":
      return "primary";
    default:
      return "muted";
  }
}

function iconFromType(type: ActivityEntry["type"]): ActivityIcon {
  switch (type) {
    case "approval_decided":
      return "user";
    case "source_uploaded":
      return "branch";
    case "pipeline_completed":
      return "alert";
    case "finding_status_changed":
      return "clock";
    case "run_completed":
    default:
      return "check";
  }
}

function readVariant(value: unknown): ActivityVariant | null {
  const next = readString(value);
  if (!next) {
    return null;
  }

  const variants: ActivityVariant[] = [
    "analysis_completed",
    "analysis_started",
    "approval_requested",
    "accepted_risk",
    "build_target_added",
    "dynamic_test_passed",
    "gate_blocked",
    "needs_revalidation",
  ];

  return variants.includes(next as ActivityVariant) ? (next as ActivityVariant) : null;
}

function readTone(value: unknown): ActivityTone | null {
  const next = readString(value);
  return next === "success" || next === "critical" || next === "primary" || next === "muted"
    ? next
    : null;
}

function readIcon(value: unknown): ActivityIcon | null {
  const next = readString(value);
  return next === "check" || next === "alert" || next === "play" || next === "user" || next === "branch" || next === "clock"
    ? next
    : null;
}

function readString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function readNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function buildFallbackActivity(projects: DashboardProject[]): ActivityEvent[] {
  return projects
    .map((project) => buildPrimaryActivityEvent(project))
    .filter((event): event is ActivityEvent => event !== null)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

function buildPrimaryActivityEvent(project: DashboardProject): ActivityEvent | null {
  const timestamp = latestProjectTimestamp(project);
  if (!timestamp) {
    return null;
  }

  const owner = projectOwner(project);
  const ownerDisplay = owner?.name ?? "담당자";
  const approvals = projectPendingApprovals(project);
  const critical = project.severitySummary?.critical ?? 0;
  const high = project.severitySummary?.high ?? 0;
  const open = totalFindings(project);

  if (!project.lastAnalysisAt) {
    return {
      id: `${project.id}-activity-latest-update`,
      projectId: project.id,
      projectName: project.name,
      timestamp,
      tone: "muted",
      icon: "clock",
      html: `<b><span class="proj">${escapeHtml(project.name)}</span></b> 가장 마지막 수정`,
    };
  }

  if (projectIsRunning(project)) {
    return {
      id: `${project.id}-activity-running`,
      projectId: project.id,
      projectName: project.name,
      timestamp,
      tone: "primary",
      icon: "play",
      html: `<b><span class="proj">${escapeHtml(project.name)}</span></b> 정적 분석 시작 · Agent <span class="n">taint-flow</span> 활성`,
    };
  }

  if (project.gateStatus === "fail") {
    return {
      id: `${project.id}-activity-gate-fail`,
      projectId: project.id,
      projectName: project.name,
      timestamp,
      tone: "critical",
      icon: "alert",
      html: `<b><span class="proj">${escapeHtml(project.name)}</span></b> Quality Gate <b>BLOCKED</b> — 룰 <span class="n">${Math.max(1, critical + 2)}/7</span> 실패`,
    };
  }

  if (approvals > 0) {
    return {
      id: `${project.id}-activity-approval`,
      projectId: project.id,
      projectName: project.name,
      timestamp,
      tone: "muted",
      icon: "user",
      html: `<b>${escapeHtml(ownerDisplay)}</b>가 <b><span class="proj">${escapeHtml(project.name)}</span></b> 승인 요청 <span class="n">#A-${project.id.replace(/[^0-9]/g, "") || "101"}</span> 제출`,
    };
  }

  return {
    id: `${project.id}-analysis-complete`,
    projectId: project.id,
    projectName: project.name,
    timestamp,
    tone: "success",
    icon: "check",
    html: `<b><span class="proj">${escapeHtml(project.name)}</span></b> 정적 분석 완료 · <span class="n critical">${critical}</span> crit, <span class="n high">${high}</span> high · 총 <span class="n">${open}</span>건`,
  };
}
