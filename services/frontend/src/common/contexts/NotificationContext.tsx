import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from "react";
import type { Notification } from "@aegis/shared";
import {
  fetchNotifications,
  fetchNotificationCount,
  markNotificationRead as apiMarkRead,
  markAllNotificationsRead as apiMarkAllRead,
  getNotificationWsUrl,
} from "@/common/api/notifications";
import { logError } from "@/common/api/core";
import { createSeqTracker, parseWsMessage, createReconnectingWs } from "@/common/utils/wsEnvelope";
import { useToast } from "./ToastContext";

interface NotificationContextValue {
  notifications: Notification[];
  unreadCount: number;
  loading: boolean;
  /** True after WS retry budget exhausted; consumers may render an offline banner. */
  realtimeOffline: boolean;
  markRead: (id: string) => Promise<void>;
  markAllRead: () => Promise<void>;
  refresh: () => Promise<void>;
}

const NotificationContext = createContext<NotificationContextValue | null>(null);

function formatToastMessage(notification: Notification): string {
  return notification.body ? `${notification.title} — ${notification.body}` : notification.title;
}

function getToastKind(notification: Notification): "error" | "warning" | "success" {
  if (notification.severity === "critical") return "error";
  if (notification.type.endsWith("_failed")) return "error";
  if (notification.type === "critical_finding") return "warning";
  if (notification.severity === "medium") return "warning";
  return "success";
}

export function NotificationProvider({
  projectId,
  children,
}: {
  projectId: string | undefined;
  children: React.ReactNode;
}) {
  const toast = useToast();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [realtimeOffline, setRealtimeOffline] = useState(false);
  const seenIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    seenIdsRef.current.clear();
    setNotifications([]);
    setUnreadCount(0);
  }, [projectId]);

  const refresh = useCallback(async () => {
    if (!projectId) return;
    setLoading(true);
    try {
      const [list, count] = await Promise.all([
        fetchNotifications(projectId),
        fetchNotificationCount(projectId),
      ]);
      setNotifications(list);
      setUnreadCount(count.unread);
      seenIdsRef.current = new Set(list.map((notification) => notification.id));
    } catch (e) {
      logError("NotificationContext.refresh", e);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // WebSocket connection for real-time notifications (with reconnection)
  useEffect(() => {
    if (!projectId) return;
    if (import.meta.env.VITE_MOCK === "true") return;

    setRealtimeOffline(false);
    const seqTracker = createSeqTracker("notification");

    const rws = createReconnectingWs(() => getNotificationWsUrl(projectId), {
      maxRetries: 10,
      onDisconnect() {
        seqTracker.reset();
      },
      async onReconnect() {
        // Catch up on missed notifications via REST
        try {
          const [list, count] = await Promise.all([
            fetchNotifications(projectId),
            fetchNotificationCount(projectId),
          ]);
          setNotifications(list);
          setUnreadCount(count.unread);
          seenIdsRef.current = new Set(list.map((notification) => notification.id));
        } catch (e) {
          logError("NotificationContext.reconnect", e);
        }
        wireHandlers(rws.getWs());
      },
      onGiveUp() {
        setRealtimeOffline(true);
      },
    });

    function wireHandlers(ws: WebSocket | null) {
      if (!ws) return;
      ws.onmessage = (event) => {
        try {
          const msg = parseWsMessage(event.data);
          // Drop frames whose envelope channel does not match this consumer.
          if (msg.meta && msg.meta.channel !== "notification") return;
          seqTracker.check(msg.meta);
          const payload = msg;
          if (payload.type === "notification" && payload.payload) {
            const notif = payload.payload as Notification;
            if (seenIdsRef.current.has(notif.id)) return;
            seenIdsRef.current.add(notif.id);
            setNotifications((prev) => [notif, ...prev]);
            if (!notif.read) setUnreadCount((c) => c + 1);
            const toastMessage = formatToastMessage(notif);
            const toastKind = getToastKind(notif);
            if (toastKind === "error") {
              toast.error(toastMessage);
            } else if (toastKind === "warning") {
              toast.warning(toastMessage);
            } else {
              toast.success(toastMessage);
            }
          }
        } catch {
          // ignore non-JSON messages
        }
      };
    }
    wireHandlers(rws.getWs());

    return () => {
      rws.close();
    };
  }, [projectId, toast]);

  const markRead = useCallback(async (id: string) => {
    await apiMarkRead(id);
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
    setUnreadCount((c) => Math.max(0, c - 1));
  }, []);

  const markAllRead = useCallback(async () => {
    if (!projectId) return;
    await apiMarkAllRead(projectId);
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    setUnreadCount(0);
  }, [projectId]);

  return (
    <NotificationContext.Provider value={{ notifications, unreadCount, loading, realtimeOffline, markRead, markAllRead, refresh }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error("useNotifications must be used within NotificationProvider");
  return ctx;
}
