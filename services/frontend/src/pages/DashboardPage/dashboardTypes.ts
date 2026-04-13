import type { ProjectListItem } from "@aegis/shared";

export type DashboardProject = ProjectListItem;

export interface ActivityEvent {
  id: string;
  projectId: string;
  projectName: string;
  description: string;
  timestamp: string;
}
