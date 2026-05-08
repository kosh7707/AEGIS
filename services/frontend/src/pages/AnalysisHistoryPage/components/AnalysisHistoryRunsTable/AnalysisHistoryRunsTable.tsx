import "./AnalysisHistoryRunsTable.css";
import React from "react";
import type {
  AgentAnalysisOutcome,
  AgentPocOutcome,
  AgentQualityOutcome,
  Run,
} from "@aegis/shared";
import { ChevronRight, Trash2 } from "lucide-react";
import { EmptyState } from "@/common/ui/primitives";
import { OutcomeChip } from "@/common/ui/primitives/OutcomeChip";
import { deriveDominantOutcome } from "@/common/ui/analysis/deepOutcome";
import { MODULE_META } from "@/common/constants/modules";
import { formatDateTime, formatUptime } from "@/common/utils/format";
import type { AnalysisHistoryFilter } from "../../useAnalysisHistoryPageController";

type HistoryRun = Run & {
  severitySummary?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
  /** Optional Deep outcome enums when present on the run row (forward compat). */
  analysisOutcome?: AgentAnalysisOutcome;
  qualityOutcome?: AgentQualityOutcome;
  pocOutcome?: AgentPocOutcome;
};

const STATUS_LABELS: Record<string, string> = {
  completed: "완료",
  running: "실행 중",
  failed: "실패",
  queued: "대기",
  pending: "대기",
};

const EMPTY_TITLES: Record<AnalysisHistoryFilter, string> = {
  all: "아직 분석 이력이 없습니다",
  static_analysis: "해당 모듈의 분석 이력이 없습니다",
  deep_analysis: "해당 모듈의 분석 이력이 없습니다",
};

const EMPTY_DESCRIPTIONS: Record<AnalysisHistoryFilter, string> = {
  all: "소스 아카이브를 업로드하고 분석을 실행하면 이력, 심각도 분포, 소요 시간 정보를 이곳에서 확인할 수 있습니다.",
  static_analysis: "정적 분석을 실행하면 이력이 이곳에 표시됩니다.",
  deep_analysis: "심층 분석을 실행하면 이력이 이곳에 표시됩니다.",
};

/** Map run.status to canonical .run-status--* modifier */
const getRunStatusMod = (status: string): string => {
  const map: Record<string, string> = {
    completed: "completed",
    running: "running",
    failed: "failed",
    queued: "pending",
    pending: "pending",
  };
  return map[status] ?? "pending";
};

interface AnalysisHistoryRunsTableProps {
  filter: AnalysisHistoryFilter;
  runs: HistoryRun[];
  onOpenRun: (run: HistoryRun) => void;
  onDeleteRun?: (run: HistoryRun) => void;
}

export const AnalysisHistoryRunsTable: React.FC<AnalysisHistoryRunsTableProps> = ({
  filter,
  runs,
  onOpenRun,
  onDeleteRun,
}) => {
  if (runs.length === 0) {
    return (
      <div className="history-empty-shell">
        <EmptyState
          className="empty-state--workspace"
          title={EMPTY_TITLES[filter]}
          description={EMPTY_DESCRIPTIONS[filter]}
        />
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h3>
          최근 실행
          <span className="count">{runs.length}</span>
        </h3>
        <span className="panel-hint" aria-hidden="true">분석 시점, 심각도 요약, 소요 시간</span>
      </div>

      <div className="panel-body panel-body--scroll panel-body--flush">
        <table className="history-runs-table">
          <thead>
            <tr>
              <th>실행</th>
              <th>시각</th>
              <th>모듈</th>
              <th>상태</th>
              <th className="cell-center">탐지 요약 (치명/높음/보통/낮음)</th>
              <th>소요 시간</th>
              <th aria-hidden="true" />
            </tr>
          </thead>
          <tbody>
            {runs.map((run, index) => {
              const meta = MODULE_META[run.module] ?? { label: run.module, icon: null };
              const durationSec =
                run.startedAt && run.endedAt
                  ? (new Date(run.endedAt).getTime() - new Date(run.startedAt).getTime()) / 1000
                  : 0;
              const sev = run.severitySummary;
              const statusMod = getRunStatusMod(run.status);
              const isDeepRun = run.module === "deep_analysis";
              const deepOutcome = isDeepRun
                ? deriveDominantOutcome({
                    status: run.status,
                    analysisOutcome: run.analysisOutcome,
                    qualityOutcome: run.qualityOutcome,
                  })
                : null;

              return (
                <tr
                  key={run.id}
                  className="run-row"
                  tabIndex={0}
                  onClick={() => onOpenRun(run)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onOpenRun(run);
                    }
                  }}
                  aria-label={`실행 #${index + 1} — ${meta.label} — ${STATUS_LABELS[run.status] ?? run.status}`}
                >
                  <td>
                    <span className="run-index">#{index + 1}</span>
                  </td>
                  <td>
                    <span className="run-timestamp">{formatDateTime(run.createdAt)}</span>
                  </td>
                  <td>
                    <span className="run-module-cell">
                      <span className="run-module-cell__icon" aria-hidden="true">
                        {meta.icon}
                      </span>
                      {meta.label}
                    </span>
                  </td>
                  <td>
                    {/* Canonical run-status--* vocab from handoff/components/status.css */}
                    <span className="history-run-status-cell">
                      <span className={`run-status run-status--${statusMod}`}>
                        <span className="run-status__dot" aria-hidden="true" />
                        {STATUS_LABELS[run.status] ?? run.status}
                      </span>
                      {deepOutcome && (
                        <OutcomeChip
                          kind="cleanPass"
                          value={null}
                          tone={deepOutcome.tone}
                          label={deepOutcome.label}
                          size="sm"
                        />
                      )}
                    </span>
                  </td>
                  <td className="cell-center">
                    {sev ? (
                      <span className="hist-sev-summary" aria-label={`치명 ${sev.critical ?? 0} 높음 ${sev.high ?? 0} 보통 ${sev.medium ?? 0} 낮음 ${sev.low ?? 0}`}>
                        <span className={`hist-sev-summary__val${(sev.critical ?? 0) > 0 ? " hist-sev-summary__val--critical" : ""}`}>
                          {sev.critical ?? 0}
                        </span>
                        <span className="hist-sev-summary__sep" aria-hidden="true">/</span>
                        <span className={`hist-sev-summary__val${(sev.high ?? 0) > 0 ? " hist-sev-summary__val--high" : ""}`}>
                          {sev.high ?? 0}
                        </span>
                        <span className="hist-sev-summary__sep" aria-hidden="true">/</span>
                        <span className={`hist-sev-summary__val${(sev.medium ?? 0) > 0 ? " hist-sev-summary__val--medium" : ""}`}>
                          {sev.medium ?? 0}
                        </span>
                        <span className="hist-sev-summary__sep" aria-hidden="true">/</span>
                        <span className={`hist-sev-summary__val${(sev.low ?? 0) > 0 ? " hist-sev-summary__val--low" : ""}`}>
                          {sev.low ?? 0}
                        </span>
                      </span>
                    ) : run.findingCount > 0 ? (
                      <span className="run-duration">{run.findingCount}</span>
                    ) : (
                      <span className="run-timestamp">—</span>
                    )}
                  </td>
                  <td>
                    <span className="run-duration">
                      {durationSec > 0 ? formatUptime(durationSec) : "—"}
                    </span>
                  </td>
                  <td className="history-run-actions-cell">
                    {onDeleteRun && run.analysisResultId ? (
                      <button
                        type="button"
                        className="btn btn-ghost btn-icon-sm history-run-delete-btn"
                        title="분석 결과 삭제"
                        aria-label={`실행 #${index + 1} 분석 결과 삭제`}
                        onClick={(event) => {
                          event.stopPropagation();
                          onDeleteRun(run);
                        }}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            event.stopPropagation();
                            onDeleteRun(run);
                          }
                        }}
                      >
                        <Trash2 size={14} aria-hidden="true" />
                      </button>
                    ) : null}
                    <span className="run-chev-cell" aria-hidden="true">
                      <ChevronRight size={16} />
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
