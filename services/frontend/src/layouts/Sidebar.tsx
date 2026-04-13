import React, { useState, useCallback, useEffect } from "react";
import { NavLink, useMatch, useNavigate } from "react-router-dom";
import {
  FolderOpen,
  Settings,
  ChevronLeft,
  LayoutDashboard,
  FileSearch,
  Shield,
  ShieldCheck,
  ClipboardCheck,
  Files,
  Clock,
  FileText,
  Activity,
  Zap,
} from "lucide-react";
import { useProjects } from "../contexts/ProjectContext";
import { useAnalysisGuard } from "../contexts/AnalysisGuardContext";
import { ConfirmDialog } from "../shared/ui";
import { fetchApprovalCount } from "../api/approval";
import "./Sidebar.css";

const ICON_SIZE = 18;

const projectNavItems = [
  { sub: "overview", label: "개요", icon: LayoutDashboard, comingSoon: false },
  { sub: "files", label: "파일 탐색기", icon: Files, comingSoon: false },
  { sub: "vulnerabilities", label: "취약점 목록", icon: Shield, comingSoon: false },
  { sub: "static-analysis", label: "정적 분석", icon: FileSearch, comingSoon: false },
  { sub: "dynamic-analysis", label: "동적 분석", icon: Activity, comingSoon: false },
  { sub: "dynamic-test", label: "동적 테스트", icon: Zap, comingSoon: false },
  { sub: "quality-gate", label: "Quality Gate", icon: ShieldCheck, comingSoon: false },
  { sub: "approvals", label: "Approval Queue", icon: ClipboardCheck, comingSoon: false },
  { sub: "analysis-history", label: "분석 이력", icon: Clock, comingSoon: false },
  { sub: "report", label: "보고서", icon: FileText, comingSoon: false },
];

export const Sidebar: React.FC = () => {
  const projectMatch = useMatch("/projects/:projectId/*");
  const projectId = projectMatch?.params.projectId;
  const { getProject } = useProjects();
  const project = projectId ? getProject(projectId) : null;
  const navigate = useNavigate();
  const { isBlocking } = useAnalysisGuard();
  const [pendingNav, setPendingNav] = useState<string | null>(null);
  const [pendingApprovals, setPendingApprovals] = useState(0);

  useEffect(() => {
    if (!projectId) return;
    fetchApprovalCount(projectId)
      .then((data) => setPendingApprovals(data.pending))
      .catch(() => setPendingApprovals(0));
  }, [projectId]);

  const handleNavClick = useCallback((e: React.MouseEvent, to: string) => {
    if (isBlocking) {
      e.preventDefault();
      setPendingNav(to);
    }
  }, [isBlocking]);

  const confirmNav = useCallback(() => {
    if (pendingNav) {
      navigate(pendingNav);
      setPendingNav(null);
    }
  }, [pendingNav, navigate]);

  return (
    <nav className="sidebar">
      {projectId ? (
        <>
          <div
            className="sidebar-header sidebar-header-clickable"
            onClick={(e) => {
              if (isBlocking) {
                setPendingNav("/projects");
              } else {
                navigate("/projects");
              }
            }}
          >
            <div className="sidebar-header-row">
              <ChevronLeft size={20} className="sidebar-header-icon" />
              <div className="sidebar-header-text">
                <span className="sidebar-title">{project?.name ?? "알 수 없는 프로젝트"}</span>
                <span className="sidebar-subtitle">프로젝트 작업 공간</span>
              </div>
            </div>
          </div>

          <ul className="sidebar-nav">
            {projectNavItems.map((item) => (
              <li key={item.sub}>
                <NavLink
                  to={`/projects/${projectId}/${item.sub}`}
                  className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}
                  onClick={(e) => handleNavClick(e, `/projects/${projectId}/${item.sub}`)}
                >
                  <item.icon size={ICON_SIZE} />
                  <span className="sidebar-link__label">{item.label}</span>
                  {item.sub === "approvals" && pendingApprovals > 0 && (
                    <span className="sidebar-badge">{pendingApprovals}</span>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>

          <div className="sidebar-divider" />
          <ul className="sidebar-nav sidebar-nav-bottom">
            <li>
              <NavLink
                to={`/projects/${projectId}/settings`}
                className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}
                onClick={(e) => handleNavClick(e, `/projects/${projectId}/settings`)}
              >
                <Settings size={ICON_SIZE} />
                <span className="sidebar-link__label">설정</span>
              </NavLink>
            </li>
          </ul>
        </>
      ) : (
        <>
          <div className="sidebar-header">
            <div className="sidebar-header-row">
              <Shield size={20} className="sidebar-header-icon" />
              <div className="sidebar-header-text">
                <span className="sidebar-title">AEGIS</span>
                <span className="sidebar-subtitle">보안 분석 워크스페이스</span>
              </div>
            </div>
          </div>

          <ul className="sidebar-nav">
            <li>
              <NavLink
                to="/dashboard"
                end
                className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}
              >
                <FolderOpen size={ICON_SIZE} />
                <span className="sidebar-link__label">프로젝트</span>
              </NavLink>
            </li>
          </ul>

          <div className="sidebar-divider" />
          <ul className="sidebar-nav sidebar-nav-bottom">
            <li>
              <NavLink
                to="/settings"
                className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}
              >
                <Settings size={ICON_SIZE} />
                <span className="sidebar-link__label">설정</span>
              </NavLink>
            </li>
          </ul>
        </>
      )}

      <ConfirmDialog
        open={!!pendingNav}
        title="분석 진행 중"
        message="분석이 진행 중입니다. 이동하시겠습니까? (분석은 백그라운드에서 계속됩니다)"
        confirmLabel="이동"
        onConfirm={confirmNav}
        onCancel={() => setPendingNav(null)}
      />
    </nav>
  );
};
