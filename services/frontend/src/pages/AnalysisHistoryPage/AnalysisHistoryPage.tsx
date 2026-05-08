import React, { useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ConfirmDialog, PageHeader, Spinner } from "@/common/ui/primitives";
import { useToast } from "@/common/contexts/ToastContext";
import { getModuleRoute } from "@/common/constants/modules";
import { AnalysisHistoryToolbar } from "./components/AnalysisHistoryToolbar/AnalysisHistoryToolbar";
import { AnalysisHistoryRunsTable } from "./components/AnalysisHistoryRunsTable/AnalysisHistoryRunsTable";
import { useAnalysisHistoryPageController } from "./useAnalysisHistoryPageController";
import "./AnalysisHistoryPage.css";

export const AnalysisHistoryPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const {
    loading,
    runs,
    filter,
    setFilter,
    filteredRuns,
    completedCount,
    failedCount,
    confirmDeleteId,
    deleting,
    requestDelete,
    cancelDelete,
    confirmDelete,
  } = useAnalysisHistoryPageController(projectId, toast);

  useEffect(() => {
    document.title = "AEGIS — 분석 이력";
  }, []);

  if (loading) {
    return (
      <div className="page-shell history-page history-loading-shell">
        <Spinner size={36} label="분석 이력 로딩 중..." />
      </div>
    );
  }

  const subtitleNode =
    runs.length > 0 ? (
      <span className="history-page__sub" aria-label="분석 이력 요약">
        총 <span className="num">{runs.length}</span>건
        {completedCount > 0 ? (
          <>
            <span className="sep" aria-hidden="true"> · </span>
            완료 <span className="num">{completedCount}</span>
          </>
        ) : null}
        {failedCount > 0 ? (
          <>
            <span className="sep" aria-hidden="true"> · </span>
            실패 <span className="num">{failedCount}</span>
          </>
        ) : null}
      </span>
    ) : undefined;

  return (
    <div className="page-shell history-page">
      <PageHeader title="분석 이력" subtitle={subtitleNode} />

      <AnalysisHistoryToolbar
        filter={filter}
        onFilterChange={setFilter}
        totalCount={runs.length}
        completedCount={completedCount}
        failedCount={failedCount}
      />

      <AnalysisHistoryRunsTable
        filter={filter}
        runs={filteredRuns}
        onOpenRun={(run) => {
          if (!projectId) {
            return;
          }
          navigate(getModuleRoute(run.module, projectId, run.analysisResultId));
        }}
        onDeleteRun={(run) => {
          if (run.analysisResultId) {
            requestDelete(run.analysisResultId);
          }
        }}
      />

      <ConfirmDialog
        open={confirmDeleteId !== null}
        title="분석 결과 삭제"
        message="이 분석 결과를 삭제하시겠습니까? 이 작업은 되돌릴 수 없습니다."
        confirmLabel={deleting ? "삭제 중..." : "삭제"}
        danger
        onConfirm={confirmDelete}
        onCancel={cancelDelete}
      />
    </div>
  );
};
