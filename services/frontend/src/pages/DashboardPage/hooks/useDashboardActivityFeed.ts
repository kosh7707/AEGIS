import { useMemo, useState } from "react";
import type { ActivityEvent, DashboardProject } from "../dashboardTypes";

interface UseDashboardActivityFeedOptions {
  projects: DashboardProject[];
  pageSize?: number;
}

export function useDashboardActivityFeed({
  projects,
  pageSize = 10,
}: UseDashboardActivityFeedOptions) {
  const [visibleActivityCount, setVisibleActivityCount] = useState(pageSize);
  const activity = useMemo(() => buildActivity(projects), [projects]);

  const visibleActivity = useMemo(
    () => activity.slice(0, visibleActivityCount),
    [activity, visibleActivityCount],
  );

  const loadMore = () => setVisibleActivityCount((count) => count + pageSize);

  return {
    visibleActivity,
    hasMore: activity.length > visibleActivity.length,
    loadMore,
  };
}

function buildActivity(projects: DashboardProject[]): ActivityEvent[] {
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

  return {
    id: `${project.id}-latest-update`,
    projectId: project.id,
    projectName: project.name,
    description: "가장 마지막 수정",
    timestamp,
  };
}

function latestProjectTimestamp(project: DashboardProject): string | null {
  const candidates = [project.updatedAt, project.lastAnalysisAt].filter((value): value is string => Boolean(value));
  if (candidates.length === 0) {
    return null;
  }

  return candidates.sort((left, right) => new Date(right).getTime() - new Date(left).getTime())[0] ?? null;
}
