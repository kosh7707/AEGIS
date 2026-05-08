import type { Notification } from "@aegis/shared";
import { apiFetch, getWsBaseUrl } from "./core";

export async function fetchNotifications(
  projectId: string,
  unread?: boolean,
): Promise<Notification[]> {
  const params = new URLSearchParams();
  if (unread !== undefined) params.set("unread", String(unread));
  const qs = params.toString();
  const res = await apiFetch<{ success: boolean; data: Notification[] }>(
    `/api/projects/${projectId}/notifications${qs ? `?${qs}` : ""}`,
  );
  return res.data;
}

export async function fetchNotificationCount(
  projectId: string,
): Promise<{ unread: number }> {
  const res = await apiFetch<{ success: boolean; data: { unread: number } }>(
    `/api/projects/${projectId}/notifications/count`,
  );
  return res.data;
}

export async function markNotificationRead(notificationId: string): Promise<void> {
  await apiFetch(`/api/notifications/${notificationId}/read`, { method: "PATCH" });
}

export async function markAllNotificationsRead(projectId: string): Promise<void> {
  await apiFetch(`/api/projects/${projectId}/notifications/read-all`, { method: "PATCH" });
}

export function getNotificationWsUrl(projectId: string): string {
  return `${getWsBaseUrl()}/ws/notifications?projectId=${encodeURIComponent(projectId)}`;
}
