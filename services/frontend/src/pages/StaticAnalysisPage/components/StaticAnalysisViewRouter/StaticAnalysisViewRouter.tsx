import "./StaticAnalysisViewRouter.css";
import React from "react";
import { BackButton, ConfirmDialog, ConnectionStatusBanner, Spinner } from "@/common/ui/primitives";
import { FindingDetailView } from "@/common/ui/findings/FindingDetailView";
import { AnalysisResultsView } from "../AnalysisResultsView/AnalysisResultsView";
import { RunDetailView } from "../RunDetailView/RunDetailView";
import { StaticAnalysisUploadScreen } from "../StaticAnalysisUploadScreen/StaticAnalysisUploadScreen";
import { StaticAnalysisEmptyState } from "../StaticAnalysisEmptyState/StaticAnalysisEmptyState";
import { StaticDashboard } from "../StaticDashboard/StaticDashboard";
import { TargetSelectDialog } from "../TargetSelectDialog/TargetSelectDialog";
import { TwoStageProgressView } from "../TwoStageProgressView/TwoStageProgressView";
import type { AnalysisMode } from "@/common/hooks/useAnalysisWebSocket";

type StaticAnalysisViewRouterProps = {
  projectId: string;
  dashboard: {
    loading: boolean;
    summary: unknown;
    recentRuns: unknown[];
    activeAnalysis: unknown;
    latestRunDetail: unknown;
    latestRunLoading: boolean;
    latestAnalysisResult: unknown;
    period: string;
    setPeriod: (period: never) => void;
  };
  analysis: {
    analysisId: string | null;
    buildTargetId?: string | null;
    executionId?: string | null;
    stage: unknown;
    message: string;
    quickFindingCount: number | null;
    deepFindingCount: number | null;
    error: string | null;
    errorPhase: "quick" | "deep" | null;
    retryable: boolean;
    targetName: string | null;
    targetProgress: { current: number; total: number } | null;
    connectionState: string;
  };
  buildTargets: {
    targets: unknown[];
  };
  state: {
    view: string;
    analysisResult: unknown;
    analysisResultLoading: boolean;
    selectedFindingId: string | null;
    setSelectedFindingId: (value: string | null) => void;
    runDetail: unknown;
    setView: (view: never) => void;
    runDetailLoading: boolean;
    goToDashboard: () => void;
    handleSelectFinding: (findingId: string) => void;
    handleRetry: () => void;
    handleViewResults: () => void;
    sourceFiles: unknown[];
    findings: unknown[];
    handleAnalysisStart: (mode?: AnalysisMode) => void;
    handleBrowseTree: () => void;
    handleDiscoverTargets: () => void;
    handleNewAnalysis: () => void;
    handlePrepare?: () => void;
    isPreparing?: boolean;
    handleViewRun: (runId: string) => void;
    handleResumeAnalysis: () => void;
    handleFileClick: (filePath: string) => void;
    showTargetSelect: boolean;
    setShowTargetSelect: (open: boolean) => void;
    handleAnalysisWithTargets: (selectedTargetId: string) => void;
    confirmAbortId: string | null;
    aborting: boolean;
    handleRequestAbortAnalysis: (analysisId: string) => void;
    handleConfirmAbortAnalysis: () => void;
    handleCancelAbortAnalysis: () => void;
  };
};

export function StaticAnalysisViewRouter({
  projectId,
  dashboard,
  analysis,
  buildTargets,
  state,
}: StaticAnalysisViewRouterProps) {
  const targetSelectDialog = (
    <TargetSelectDialog
      open={state.showTargetSelect}
      targets={buildTargets.targets as never}
      onConfirm={state.handleAnalysisWithTargets}
      onCancel={() => state.setShowTargetSelect(false)}
    />
  );

  if (state.view === "findingDetail" && state.selectedFindingId) {
    return (
      <FindingDetailView
        findingId={state.selectedFindingId}
        projectId={projectId}
        onBack={() => {
          state.setSelectedFindingId(null);
          state.setView((state.runDetail ? "runDetail" : "dashboard") as never);
        }}
      />
    );
  }

  if (state.view === "runDetail") {
    if (state.runDetailLoading || !state.runDetail) {
      return (
        <div className="page-enter">
          <BackButton onClick={state.goToDashboard} label="대시보드로" />
          <div className="static-analysis-router-loading">
            <Spinner label="Run 로딩 중..." />
          </div>
        </div>
      );
    }

    return (
      <RunDetailView
        runDetail={state.runDetail as never}
        analysisResult={null}
        projectId={projectId}
        onBack={state.goToDashboard}
        onSelectFinding={state.handleSelectFinding}
        onViewLegacyResult={() => {}}
      />
    );
  }

  if (state.view === "progress") {
    return (
      <>
        <TwoStageProgressView
          analysisId={analysis.analysisId}
          buildTargetId={analysis.buildTargetId}
          executionId={analysis.executionId}
          stage={analysis.stage as never}
          message={analysis.message}
          quickFindingCount={analysis.quickFindingCount}
          deepFindingCount={analysis.deepFindingCount}
          error={analysis.error}
          errorPhase={analysis.errorPhase}
          retryable={analysis.retryable}
          targetName={analysis.targetName}
          targetProgress={analysis.targetProgress}
          onRetry={state.handleRetry}
          onViewResults={state.handleViewResults}
          onBack={state.goToDashboard}
          onAbort={state.handleRequestAbortAnalysis}
        />
        <ConfirmDialog
          open={state.confirmAbortId !== null}
          title="분석 중단"
          message="진행 중인 분석을 중단하시겠습니까? 중단하면 결과가 저장되지 않습니다."
          confirmLabel={state.aborting ? "중단 중..." : "중단"}
          danger
          onConfirm={state.handleConfirmAbortAnalysis}
          onCancel={state.handleCancelAbortAnalysis}
        />
      </>
    );
  }

  if (state.view === "analysisResults") {
    if (state.analysisResultLoading || !state.analysisResult) {
      return (
        <div className="page-enter">
          <BackButton onClick={state.goToDashboard} label="대시보드로" />
          <div className="static-analysis-router-loading">
            <Spinner label="분석 결과 로딩 중..." />
          </div>
        </div>
      );
    }

    return (
      <AnalysisResultsView
        result={state.analysisResult as never}
        onSelectVuln={(vuln) => state.handleSelectFinding(vuln.id)}
        onNewAnalysis={state.goToDashboard}
      />
    );
  }

  if (state.view === "sourceUpload") {
    return (
      <>
        <StaticAnalysisUploadScreen
          projectId={projectId}
          onBack={state.goToDashboard}
          onAnalysisStart={state.handleAnalysisStart}
          onBrowseTree={state.handleBrowseTree}
          onDiscoverTargets={state.handleDiscoverTargets}
          onPrepare={state.handlePrepare}
          isPreparing={state.isPreparing}
        />
        {targetSelectDialog}
      </>
    );
  }

  if (dashboard.loading) {
    return (
      <div className="page-enter">
        <div className="static-analysis-router-loading">
          <Spinner label="대시보드 로딩 중..." />
        </div>
      </div>
    );
  }

  if (!dashboard.summary) {
    return <StaticAnalysisEmptyState onUpload={() => state.setView("sourceUpload" as never)} />;
  }

  const activeAnalysisId =
    (dashboard.activeAnalysis as { analysisId?: string } | null)?.analysisId ?? null;

  return (
    <>
      <ConnectionStatusBanner connectionState={analysis.connectionState} />
      <StaticDashboard
        projectId={projectId}
        summary={dashboard.summary as never}
        recentRuns={dashboard.recentRuns as never}
        activeAnalysis={dashboard.activeAnalysis as never}
        latestRunDetail={dashboard.latestRunDetail as never}
        latestRunLoading={dashboard.latestRunLoading}
        latestAnalysisResult={dashboard.latestAnalysisResult as never}
        period={dashboard.period as never}
        onPeriodChange={dashboard.setPeriod}
        onNewAnalysis={state.handleNewAnalysis}
        onViewRun={state.handleViewRun}
        onSelectFinding={state.handleSelectFinding}
        onResumeAnalysis={state.handleResumeAnalysis}
        onAbortAnalysis={() => {
          if (activeAnalysisId) {
            state.handleRequestAbortAnalysis(activeAnalysisId);
          }
        }}
        onFileClick={state.handleFileClick}
        onBrowseTree={state.sourceFiles.length > 0 ? state.handleBrowseTree : undefined}
      />

      {targetSelectDialog}

      <ConfirmDialog
        open={state.confirmAbortId !== null}
        title="분석 중단"
        message="진행 중인 분석을 중단하시겠습니까? 중단하면 결과가 저장되지 않습니다."
        confirmLabel={state.aborting ? "중단 중..." : "중단"}
        danger
        onConfirm={state.handleConfirmAbortAnalysis}
        onCancel={state.handleCancelAbortAnalysis}
      />
    </>
  );
}
