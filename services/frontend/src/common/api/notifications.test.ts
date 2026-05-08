import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchNotificationCount, fetchNotifications, markNotificationRead, markAllNotificationsRead } from "./notifications";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
  getWsBaseUrl: vi.fn(() => "ws://localhost:3000"),
}));

import { apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("fetchNotificationCount", () => {
  it("GETs /api/projects/:pid/notifications/count and unwraps envelope data", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: { unread: 5 } });

    const result = await fetchNotificationCount("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/notifications/count");
    expect(result).toEqual({ unread: 5 });
  });

  it("returns unread count from response data", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: { unread: 0 } });

    const result = await fetchNotificationCount("proj-2");

    expect(result.unread).toBe(0);
  });
});

describe("fetchNotifications", () => {
  it("GETs /api/projects/:pid/notifications without query when unread is not specified", async () => {
    const notifications = [{ id: "n1", message: "test" }];
    mockApiFetch.mockResolvedValue({ success: true, data: notifications });

    const result = await fetchNotifications("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/notifications");
    expect(result).toEqual(notifications);
  });

  it("GETs with ?unread=true when unread=true", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: [] });

    await fetchNotifications("proj-1", true);

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/notifications?unread=true");
  });
});

describe("markNotificationRead", () => {
  it("PATCHes /api/notifications/:id/read", async () => {
    mockApiFetch.mockResolvedValue({ success: true });

    await markNotificationRead("notif-1");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/notifications/notif-1/read",
      expect.objectContaining({ method: "PATCH" }),
    );
  });
});

describe("markAllNotificationsRead", () => {
  it("PATCHes /api/projects/:pid/notifications/read-all", async () => {
    mockApiFetch.mockResolvedValue({ success: true });

    await markAllNotificationsRead("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/projects/proj-1/notifications/read-all",
      expect.objectContaining({ method: "PATCH" }),
    );
  });
});
