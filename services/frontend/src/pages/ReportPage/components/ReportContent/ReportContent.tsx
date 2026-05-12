import "./ReportContent.css";
import React from "react";
import type { AnalysisResult, ProjectReport } from "@aegis/shared";
import { Spinner } from "@/common/ui/primitives";
import { CustomReportModal } from "../CustomReportModal/CustomReportModal";
import { ReportApprovalsSection } from "../ReportApprovalsSection/ReportApprovalsSection";
import { ReportAuditTimeline } from "../ReportAuditTimeline/ReportAuditTimeline";
import { ReportCaveats } from "../ReportCaveats/ReportCaveats";
import { ReportFiltersPanel } from "../ReportFiltersPanel/ReportFiltersPanel";
import { ReportFindingsSection } from "../ReportFindingsSection/ReportFindingsSection";
import { ReportHeader } from "../ReportHeader/ReportHeader";
import { ReportModuleBreakdown } from "../ReportModuleBreakdown/ReportModuleBreakdown";
import { ReportOutcomes } from "../ReportOutcomes/ReportOutcomes";
import { ReportRunsSection } from "../ReportRunsSection/ReportRunsSection";
import { ReportSevRow } from "../ReportSevRow/ReportSevRow";
import {
  ReportStatStrip,
  computeStatStripInputs,
} from "../ReportStatStrip/ReportStatStrip";
import {
  MODULE_TAB_LABELS,
  type ModuleTab,
  type ReportModuleEntry,
} from "../../reportPresentation";
import type { ReportFilters } from "@/common/api/client";

type FindingsEntry = ProjectReport["modules"][keyof ProjectReport["modules"]] extends infer T
  ? T extends { findings: infer F }
    ? F extends Array<infer U>
      ? U
      : never
    : never
  : never;

type RunsEntry = ProjectReport["modules"][keyof ProjectReport["modules"]] extends infer T
  ? T extends { runs: infer F }
    ? F extends Array<infer U>
      ? U
      : never
    : never
  : never;

type ReportContentProps = {
  projectId?: string;
  report: ProjectReport;
  activeTab: ModuleTab;
  setActiveTab: (tab: ModuleTab) => void;
  showFilters: boolean;
  setShowFilters: (value: boolean) => void;
  showCustomReport: boolean;
  setShowCustomReport: (value: boolean) => void;
  pendingFilters: ReportFilters;
  setPendingFilters: (filters: ReportFilters) => void;
  hasActiveFilters: boolean;
  handleApplyFilters: () => void;
  handleClearFilters: () => void;
  moduleEntries: ReportModuleEntry[];
  allFindings: FindingsEntry[];
  allRuns: RunsEntry[];
  sevCounts: { critical: number; high: number; medium: number; low: number };
  deepResult?: AnalysisResult | null;
  moduleTabLoading?: boolean;
  moduleTabEmpty?: boolean;
};

export function ReportContent({
  projectId,
  report,
  activeTab,
  setActiveTab,
  showFilters,
  setShowFilters,
  showCustomReport,
  setShowCustomReport,
  pendingFilters,
  setPendingFilters,
  hasActiveFilters,
  handleApplyFilters,
  handleClearFilters,
  moduleEntries,
  allFindings,
  allRuns,
  sevCounts,
  deepResult,
  moduleTabLoading = false,
  moduleTabEmpty = false,
}: ReportContentProps) {
  const summary =
    activeTab === "all"
      ? report.totalSummary
      : moduleEntries[0]?.mod?.summary ?? report.totalSummary;

  const statInputs = computeStatStripInputs(
    summary,
    allRuns,
    activeTab === "all" ? report.approvals : [],
    sevCounts,
  );

  const scopeLabel = activeTab === "all" ? "모듈 합계" : MODULE_TAB_LABELS[activeTab];
  const tabHintLabel = activeTab === "all" ? "전체" : MODULE_TAB_LABELS[activeTab];

  const showOutcomes = activeTab === "all" || activeTab === "deep";
  const caveats = deepResult?.caveats ?? [];
  const showCaveats =
    showOutcomes &&
    deepResult?.qualityOutcome === "accepted_with_caveats" &&
    caveats.length > 0;

  return (
    <div className="page-shell report-page page-enter">
      <ReportHeader
        report={report}
        projectId={projectId}
        hasActiveFilters={hasActiveFilters}
        onToggleFilters={() => setShowFilters(!showFilters)}
        onOpenCustomReport={() => setShowCustomReport(true)}
        onPrint={() => window.print()}
      />

      {showFilters ? (
        <ReportFiltersPanel
          pendingFilters={pendingFilters}
          setPendingFilters={setPendingFilters}
          hasActiveFilters={hasActiveFilters}
          onApply={handleApplyFilters}
          onClear={handleClearFilters}
        />
      ) : null}

      <div className="report-frame">
        <div
          className="report-tabs print-hide"
          role="tablist"
          aria-label="보고서 모듈 필터"
        >
          {(Object.keys(MODULE_TAB_LABELS) as ModuleTab[]).map((tab) => (
            <button
              key={tab}
              type="button"
              role="tab"
              aria-selected={activeTab === tab}
              className="report-tabs__tab"
              onClick={() => setActiveTab(tab)}
            >
              {MODULE_TAB_LABELS[tab]}
            </button>
          ))}
          <span className="report-tabs__hint" aria-hidden="true">
            현재 <b>{tabHintLabel}</b> 기준
          </span>
        </div>

        <div className="report-doc">
          <ReportStatStrip {...statInputs} scopeLabel={scopeLabel} />

          <ReportSevRow sevCounts={sevCounts} />

          {showOutcomes && deepResult ? (
            <div className="report-section">
              <div className="report-section__h">심층 분석 결과</div>
              <ReportOutcomes deepResult={deepResult} />
            </div>
          ) : null}

          {showCaveats ? (
            <div className="report-section">
              <div className="report-section__h">
                분석 한계
                <span className="count">{caveats.length}</span>
              </div>
              <ReportCaveats caveats={caveats} />
            </div>
          ) : null}

          {activeTab === "all" ? (
            <div className="report-section">
              <div className="report-section__h">모듈별 현황</div>
              <ReportModuleBreakdown moduleEntries={moduleEntries} />
            </div>
          ) : null}

          {moduleTabLoading ? (
            <div className="page-loading-shell" role="status" aria-live="polite">
              <Spinner label="모듈 보고서 불러오는 중..." />
            </div>
          ) : moduleTabEmpty ? (
            <div className="report-empty-line" role="status">
              해당 모듈에 표시할 탐지 항목이 없습니다.
            </div>
          ) : (
            <>
              <div className="report-section">
                <div className="report-section__h">
                  탐지 항목
                  <span className="count">{allFindings.length}</span>
                </div>
                <ReportFindingsSection
                  findings={allFindings}
                  showModule={activeTab === "all"}
                />
              </div>

              <div className="report-section">
                <div className="report-section__h">
                  실행 이력
                  <span className="count">{allRuns.length}</span>
                </div>
                <ReportRunsSection runs={allRuns} showModule={activeTab === "all"} />
              </div>
            </>
          )}

          {activeTab === "all" ? (
            <div className="report-section">
              <div className="report-section__h">
                관련 승인
                <span className="count">{report.approvals.length}</span>
              </div>
              <ReportApprovalsSection approvals={report.approvals} />
            </div>
          ) : null}

          {activeTab === "all" ? (
            <div className="report-section">
              <div className="report-section__h">
                감사 추적
                <span className="count">{report.auditTrail.length}</span>
              </div>
              <ReportAuditTimeline auditTrail={report.auditTrail} />
            </div>
          ) : null}
        </div>
      </div>

      {showCustomReport && projectId ? (
        <CustomReportModal projectId={projectId} onClose={() => setShowCustomReport(false)} />
      ) : null}
    </div>
  );
}
