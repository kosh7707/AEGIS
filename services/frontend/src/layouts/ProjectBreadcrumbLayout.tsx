import React from "react";
import { Outlet, useParams, Link, useLocation } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { useProjects } from "../contexts/ProjectContext";
import { PageHeader } from "../shared/ui";
import "./ProjectBreadcrumbLayout.css";

const pageNames: Record<string, string> = {
  overview: "개요",
  "static-analysis": "정적 분석",
  files: "파일 탐색기",
  vulnerabilities: "취약점 목록",
  "analysis-history": "분석 이력",
  report: "보고서",
  settings: "프로젝트 설정",
  "quality-gate": "Quality Gate",
  approvals: "Approval Queue",
  "dynamic-analysis": "동적 분석",
  "dynamic-test": "동적 테스트",
};

export const ProjectBreadcrumbLayout: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const { getProject } = useProjects();
  const project = projectId ? getProject(projectId) : null;
  const location = useLocation();

  // /projects/:id/files/:fileId → "파일 상세"
  const pathSegments = location.pathname.split("/").filter(Boolean);
  const isFilePage = pathSegments.includes("files");
  const currentPage = pathSegments[pathSegments.length - 1] ?? "";
  const pageName = isFilePage ? "파일 상세" : (pageNames[currentPage] ?? currentPage);

  if (!project) {
    return (
      <div className="page-enter">
        <PageHeader
          surface="plain"
          eyebrow="프로젝트"
          title="프로젝트를 찾을 수 없습니다"
          subtitle="삭제되었거나 현재 접근할 수 없는 프로젝트입니다."
        />
      </div>
    );
  }

  return (
    <>
      <nav className="breadcrumb" aria-label="프로젝트 경로">
        <ol className="breadcrumb__list">
          <li className="breadcrumb__item">
            <Link to="/dashboard" className="breadcrumb-link">
              <span className="breadcrumb-link__label">프로젝트</span>
            </Link>
          </li>

          <li className="breadcrumb__item" aria-hidden="true">
            <ChevronRight size={12} className="breadcrumb-sep" />
          </li>

          <li className="breadcrumb__item">
            <Link to={`/projects/${projectId}/overview`} className="breadcrumb-link" title={project.name}>
              <span className="breadcrumb-link__label">{project.name}</span>
            </Link>
          </li>

          <li className="breadcrumb__item" aria-hidden="true">
            <ChevronRight size={12} className="breadcrumb-sep" />
          </li>

          <li className="breadcrumb__item">
            <span className="breadcrumb-current" title={pageName} aria-current="page">
              <span className="breadcrumb-current__label">{pageName}</span>
            </span>
          </li>
        </ol>
      </nav>
      <Outlet />
    </>
  );
};
