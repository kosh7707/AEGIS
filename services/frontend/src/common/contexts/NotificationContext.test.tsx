import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import { NotificationProvider, useNotifications } from "./NotificationContext";

let capturedOptions: Record<string, unknown> = {};
let mockWs: { onmessage: ((evt: { data: string }) => void) | null };

const mockFetchNotifications = vi.fn();
const mockFetchNotificationCount = vi.fn();
const mockMarkNotificationRead = vi.fn();
const mockMarkAllNotificationsRead = vi.fn();
const mockToast = { error: vi.fn(), warning: vi.fn(), success: vi.fn() };

vi.mock("@/common/utils/wsEnvelope", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../utils/wsEnvelope")>();
  return {
    ...actual,
    createReconnectingWs: vi.fn((_urlFactory: () => string, options?: Record<string, unknown>) => {
      capturedOptions = options ?? {};
      mockWs = { onmessage: null };
      return {
        getWs: () => mockWs,
        close: vi.fn(),
      };
    }),
  };
});

vi.mock("@/common/api/notifications", () => ({
  fetchNotifications: (...args: unknown[]) => mockFetchNotifications(...args),
  fetchNotificationCount: (...args: unknown[]) => mockFetchNotificationCount(...args),
  markNotificationRead: (...args: unknown[]) => mockMarkNotificationRead(...args),
  markAllNotificationsRead: (...args: unknown[]) => mockMarkAllNotificationsRead(...args),
  getNotificationWsUrl: vi.fn((pid: string) => `ws://localhost:3000/ws/notifications?projectId=${pid}`),
}));

vi.mock("@/common/api/core", () => ({ logError: vi.fn() }));
vi.mock("./ToastContext", () => ({ useToast: () => mockToast }));

function Consumer() {
  const { unreadCount, notifications, realtimeOffline } = useNotifications();
  return (
    <div>
      <span data-testid="unread-count">{unreadCount}</span>
      <span data-testid="notification-title">{notifications[0]?.title ?? ""}</span>
      <span data-testid="realtime-offline">{realtimeOffline ? "offline" : "online"}</span>
    </div>
  );
}

describe("NotificationContext", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    capturedOptions = {};
    mockFetchNotifications.mockResolvedValue([]);
    mockFetchNotificationCount.mockResolvedValue({ unread: 0 });
    mockMarkNotificationRead.mockResolvedValue(undefined);
    mockMarkAllNotificationsRead.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("appends live notifications once and surfaces a toast", async () => {
    render(
      <NotificationProvider projectId="p-1">
        <Consumer />
      </NotificationProvider>,
    );

    await waitFor(() => expect(mockFetchNotifications).toHaveBeenCalledWith("p-1"));

    act(() => {
      mockWs.onmessage?.({
        data: JSON.stringify({
          type: "notification",
          payload: {
            id: "notif-1",
            projectId: "p-1",
            type: "sdk_ready",
            title: "SDK 등록 완료",
            body: "ARM SDK 사용 가능",
            read: false,
            createdAt: "2026-04-10T09:00:00Z",
          },
        }),
      });
    });

    expect(screen.getByTestId("unread-count").textContent).toBe("1");
    expect(screen.getByTestId("notification-title").textContent).toBe("SDK 등록 완료");
    expect(mockToast.success).toHaveBeenCalledWith("SDK 등록 완료 — ARM SDK 사용 가능");

    act(() => {
      mockWs.onmessage?.({
        data: JSON.stringify({
          type: "notification",
          payload: {
            id: "notif-1",
            projectId: "p-1",
            type: "sdk_ready",
            title: "SDK 등록 완료",
            body: "ARM SDK 사용 가능",
            read: false,
            createdAt: "2026-04-10T09:00:00Z",
          },
        }),
      });
    });

    expect(screen.getByTestId("unread-count").textContent).toBe("1");
    expect(mockToast.success).toHaveBeenCalledTimes(1);
  });

  it("hydrates seen ids during reconnect catch-up so the same notification is not re-appended", async () => {
    const existingNotification = {
      id: "notif-1",
      projectId: "p-1",
      type: "sdk_ready",
      title: "SDK 등록 완료",
      body: "ARM SDK 사용 가능",
      read: false,
      createdAt: "2026-04-10T09:00:00Z",
    };

    mockFetchNotifications
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([existingNotification]);
    mockFetchNotificationCount
      .mockResolvedValueOnce({ unread: 0 })
      .mockResolvedValueOnce({ unread: 1 });

    render(
      <NotificationProvider projectId="p-1">
        <Consumer />
      </NotificationProvider>,
    );

    await waitFor(() => expect(mockFetchNotifications).toHaveBeenCalledWith("p-1"));

    await act(async () => {
      await (capturedOptions.onReconnect as () => Promise<void>)();
    });

    expect(screen.getByTestId("unread-count").textContent).toBe("1");
    expect(screen.getByTestId("notification-title").textContent).toBe("SDK 등록 완료");

    act(() => {
      mockWs.onmessage?.({
        data: JSON.stringify({
          type: "notification",
          payload: existingNotification,
        }),
      });
    });

    expect(screen.getByTestId("unread-count").textContent).toBe("1");
    expect(mockToast.success).not.toHaveBeenCalled();
  });

  it("flips realtimeOffline when onGiveUp fires (retry exhausted)", async () => {
    render(
      <NotificationProvider projectId="p-1">
        <Consumer />
      </NotificationProvider>,
    );

    await waitFor(() => expect(mockFetchNotifications).toHaveBeenCalledWith("p-1"));
    expect(screen.getByTestId("realtime-offline").textContent).toBe("online");

    act(() => {
      (capturedOptions.onGiveUp as () => void)();
    });

    await waitFor(() => expect(screen.getByTestId("realtime-offline").textContent).toBe("offline"));
  });

  it("drops frames whose envelope channel does not match 'notification'", async () => {
    render(
      <NotificationProvider projectId="p-1">
        <Consumer />
      </NotificationProvider>,
    );

    await waitFor(() => expect(mockFetchNotifications).toHaveBeenCalledWith("p-1"));

    act(() => {
      mockWs.onmessage?.({
        data: JSON.stringify({
          type: "notification",
          payload: {
            id: "notif-99",
            projectId: "p-1",
            type: "sdk_ready",
            title: "WRONG CHANNEL",
            body: "should be dropped",
            read: false,
            createdAt: "2026-04-10T09:00:00Z",
          },
          meta: { channel: "pipeline", timestamp: 1, seq: 1 },
        }),
      });
    });

    expect(screen.getByTestId("unread-count").textContent).toBe("0");
    expect(screen.getByTestId("notification-title").textContent).toBe("");
    expect(mockToast.success).not.toHaveBeenCalled();
  });
});
