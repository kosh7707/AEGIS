import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Shield, Bell } from "lucide-react";
import type { Notification } from "@aegis/shared";
import { useNotifications } from "../contexts/NotificationContext";
import "./Navbar.css";

function getNotificationToneClass(notification: Notification): string {
  if (notification.type.endsWith("_failed") || notification.severity === "critical") {
    return "navbar-notification--error";
  }
  if (notification.type === "critical_finding" || notification.severity === "medium" || notification.severity === "high") {
    return "navbar-notification--warning";
  }
  return "navbar-notification--success";
}

export const Navbar: React.FC = () => {
  const location = useLocation();
  const isDashboard = location.pathname === "/dashboard";
  const isProjectRoute = location.pathname.startsWith("/projects/");
  const { notifications, unreadCount, loading, markRead, markAllRead } = useNotifications();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const recentNotifications = useMemo(() => notifications.slice(0, 6), [notifications]);

  useEffect(() => {
    setDropdownOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!dropdownOpen) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (!dropdownRef.current?.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    };
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDropdownOpen(false);
      }
    };

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [dropdownOpen]);

  const toggleDropdown = () => setDropdownOpen((prev) => !prev);

  return (
    <header className="navbar">
      <div className="navbar-left">
        <Link to="/dashboard" className="navbar-brand" aria-label="AEGIS home">
          <span className="navbar-brand__icon">
            <Shield size={18} />
          </span>
        </Link>
        <Link
          to="/dashboard"
          className={`navbar-navlink${isDashboard ? " navbar-navlink--active" : ""}`}
          aria-current={isDashboard ? "page" : undefined}
        >
          프로젝트
        </Link>
      </div>

      <div className="navbar-actions">
        <div className="navbar-notifications" ref={dropdownRef}>
          <button
            className={`navbar-actions__btn${dropdownOpen ? " navbar-actions__btn--active" : ""}`}
            title="Notifications"
            aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ""}`}
            aria-expanded={dropdownOpen}
            aria-haspopup="dialog"
            onClick={toggleDropdown}
          >
            <Bell size={16} />
            {unreadCount > 0 && (
              <span className="navbar-actions__badge">{unreadCount > 99 ? "99+" : unreadCount}</span>
            )}
          </button>

          {dropdownOpen && (
            <div className="navbar-notifications__dropdown" role="dialog" aria-label="Project notifications">
              <div className="navbar-notifications__header">
                <div>
                  <div className="navbar-notifications__title">알림</div>
                  <div className="navbar-notifications__subtitle">
                    {isProjectRoute ? "현재 프로젝트 비동기 작업 상태" : "프로젝트 화면에서 알림을 확인할 수 있습니다"}
                  </div>
                </div>
                {unreadCount > 0 && (
                  <button
                    className="navbar-notifications__mark-all"
                    type="button"
                    onClick={() => void markAllRead()}
                  >
                    모두 읽음
                  </button>
                )}
              </div>

              <div className="navbar-notifications__body">
                {loading ? (
                  <div className="navbar-notifications__empty">알림을 불러오는 중...</div>
                ) : recentNotifications.length === 0 ? (
                  <div className="navbar-notifications__empty">
                    {isProjectRoute ? "아직 프로젝트 알림이 없습니다." : "프로젝트 내부에서 생성된 알림이 여기에 표시됩니다."}
                  </div>
                ) : (
                  recentNotifications.map((notification) => (
                    <div
                      key={notification.id}
                      className={`navbar-notification ${getNotificationToneClass(notification)}${notification.read ? "" : " navbar-notification--unread"}`}
                    >
                      <div className="navbar-notification__content">
                        <div className="navbar-notification__title-row">
                          <span className="navbar-notification__title">{notification.title}</span>
                          {!notification.read && <span className="navbar-notification__dot" aria-hidden="true" />}
                        </div>
                        {notification.body && (
                          <div className="navbar-notification__body-text">{notification.body}</div>
                        )}
                        <div className="navbar-notification__meta">
                          {notification.jobKind && <span>{notification.jobKind}</span>}
                          <span>{new Date(notification.createdAt).toLocaleString("ko-KR")}</span>
                        </div>
                      </div>
                      {!notification.read && (
                        <button
                          className="navbar-notification__mark-read"
                          type="button"
                          onClick={() => void markRead(notification.id)}
                        >
                          읽음
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
        <span className="navbar-actions__divider" />
        <div className="navbar-actions__avatar" title="Kosh (Admin)">K</div>
      </div>
    </header>
  );
};
