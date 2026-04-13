import React from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Navbar } from "./Navbar";

const mockMarkRead = vi.fn();
const mockMarkAllRead = vi.fn();

const mockNotificationContext = {
  notifications: [
    {
      id: "notif-1",
      projectId: "p-1",
      type: "sdk_ready",
      title: "SDK 등록 완료",
      body: "ARM SDK 사용 가능",
      read: false,
      createdAt: "2026-04-10T09:00:00Z",
      jobKind: "sdk",
    },
    {
      id: "notif-2",
      projectId: "p-1",
      type: "analysis_complete",
      title: "분석 완료",
      body: "정적 분석 완료",
      read: true,
      createdAt: "2026-04-10T10:00:00Z",
      jobKind: "analysis",
    },
  ],
  unreadCount: 1,
  loading: false,
  markRead: (...args: unknown[]) => mockMarkRead(...args),
  markAllRead: (...args: unknown[]) => mockMarkAllRead(...args),
  refresh: vi.fn(),
};

vi.mock("../contexts/NotificationContext", () => ({
  useNotifications: () => mockNotificationContext,
}));

describe("Navbar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockMarkRead.mockResolvedValue(undefined);
    mockMarkAllRead.mockResolvedValue(undefined);
  });

  it("labels the global dashboard route as projects", () => {
    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Navbar />
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: "프로젝트" })).toHaveAttribute("href", "/dashboard");
  });

  it("shows unread badge and exposes notification dropdown actions", async () => {
    render(
      <MemoryRouter initialEntries={["/projects/p-1/overview"]}>
        <Navbar />
      </MemoryRouter>,
    );

    expect(screen.getByText("1")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /notifications/i }));

    expect(screen.getByText("SDK 등록 완료")).toBeInTheDocument();
    expect(screen.getByText("ARM SDK 사용 가능")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "모두 읽음" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "읽음" }));
    expect(mockMarkRead).toHaveBeenCalledWith("notif-1");

    fireEvent.click(screen.getByRole("button", { name: "모두 읽음" }));
    expect(mockMarkAllRead).toHaveBeenCalled();
  });
});
