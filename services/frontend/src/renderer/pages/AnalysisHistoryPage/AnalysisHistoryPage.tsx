import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import type { Run } from "@aegis/shared";
import { ChevronRight } from "lucide-react";
import { fetchProjectRuns, logError } from "../api/client";
import { useToast } from "../contexts/ToastContext";
import { EmptyState, Spinner } from "../components/ui";
import { formatDateTime, formatUptime } from "../utils/format";
import { MODULE_META } from "../constants/modules";
import "./AnalysisHistoryPage.css";

const FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: "all", label: "전체" },
  { value: "static_analysis", label: "정적 분석" },
  { value: "deep_analysis", label: "심층 분석" },
];

const STATUS_LABELS: Record<string, string> = {
  completed: "완료",
  running: "실행 중",
  failed: "실패",
  queued: "대기",
};

export const AnalysisHistoryPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");
  const toast = useToast();

  useEffect(() => {
    document.title = "AEGIS — Analysis History";
  }, []);

  useEffect(() => {
    if (!projectId) return;
    setLoading(true);
    fetchProjectRuns(projectId)
      .then((data) => {
        const sorted = [...data].sort(
          (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
        );
        setRuns(sorted);
      })
      .catch((e) => { logError("Fetch analysis history", e); toast.error("분석 이력을 불러올 수 없습니다."); })
      .finally(() => setLoading(false));
  }, [projectId, toast]);

  const filtered = filter === "all"
    ? runs
    : runs.filter((r) => r.module === filter);

  const completedCount = runs.filter((r) => r.status === "completed").length;
  const failedCount = runs.filter((r) => r.status === "failed").length;

  if (loading) {
    return (
      <div className="page-enter centered-loader">
        <Spinner size={36} label="분석 이력 로딩 중..." />
      </div>
    );
  }

  return (
    <div className="page-enter">
      {/* v6: page header */}
      <div className="history-page-header">
        <div>
          <h1 className="history-page-header__title">Analysis History</h1>
          <p className="history-page-header__subtitle">{runs.length}회 분석 실행됨</p>
        </div>
      </div>

      {/* Filter bar */}
      <div className="history-filter-bar">
        <div className="history-filter">
          {FILTER_OPTIONS.map((f) => (
            <button
              key={f.value}
              className={`history-filter__btn${filter === f.value ? " active" : ""}`}
              onClick={() => setFilter(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div className="history-kpi-strip">
          <div className="history-kpi">
            <span className="history-kpi__value">{runs.length}</span>
            <span className="history-kpi__label">전체</span>
          </div>
          <div className="history-kpi">
            <span className="history-kpi__value history-kpi__value--cds-support-success">{completedCount}</span>
            <span className="history-kpi__label">완료</span>
          </div>
          <div className="history-kpi">
            <span className="history-kpi__value history-kpi__value--cds-support-error">{failedCount}</span>
            <span className="history-kpi__label">실패</span>
          </div>
        </div>
      </div>

      {/* v6: table */}
      <div className="card history-table-card">
        {filtered.length === 0 ? (
          <EmptyState
            icon={<ChevronRight size={28} />}
            title={filter === "all" ? "아직 분석 이력이 없습니다" : "해당 모듈의 분석 이력이 없습니다"}
          />
        ) : (
          <table className="history-table">
            <thead>
              <tr className="history-table__head-row">
                <th className="history-table__th">Run #</th>
                <th className="history-table__th">Date &amp; Time</th>
                <th className="history-table__th">Module</th>
                <th className="history-table__th">Status</th>
                <th className="history-table__th history-table__th--center">Findings (C/H/M/L)</th>
                <th className="history-table__th">Duration</th>
                <th className="history-table__th"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, idx) => {
                const meta = MODULE_META[r.module] ?? { label: r.module, icon: null };
                const durationSec = r.startedAt && r.endedAt
                  ? (new Date(r.endedAt).getTime() - new Date(r.startedAt).getTime()) / 1000
                  : 0;
                const isEven = idx % 2 === 0;
                const sev = (r as any).severitySummary;
                return (
                  <tr
                    key={r.id}
                    className={`history-table__row${isEven ? "" : " history-table__row--stripe"}`}
                    onClick={() => navigate(`/projects/${projectId}/static-analysis`)}
                  >
                    <td className="history-table__td history-table__td--run">#{idx + 1}</td>
                    <td className="history-table__td history-table__td--mono">{formatDateTime(r.createdAt)}</td>
                    <td className="history-table__td">
                      <span className="history-table__module">
                        <span className="history-table__module-icon">{meta.icon}</span>
                        {meta.label}
                      </span>
                    </td>
                    <td className="history-table__td">
                      <span className={`history-table__status history-table__status--${r.status === "completed" ? "pass" : r.status === "failed" ? "fail" : "running"}`}>
                        {STATUS_LABELS[r.status] ?? r.status}
                      </span>
                    </td>
                    <td className="history-table__td history-table__td--center history-table__td--mono">
                      {sev ? (
                        <>
                          <span className={`history-sev history-sev--critical${!sev.critical ? " history-sev--zero" : ""}`}>{sev.critical ?? 0}</span>
                          <span className="history-sev__sep">/</span>
                          <span className={`history-sev history-sev--high${!sev.high ? " history-sev--zero" : ""}`}>{sev.high ?? 0}</span>
                          <span className="history-sev__sep">/</span>
                          <span className={`history-sev history-sev--medium${!sev.medium ? " history-sev--zero" : ""}`}>{sev.medium ?? 0}</span>
                          <span className="history-sev__sep">/</span>
                          <span className={`history-sev history-sev--low${!sev.low ? " history-sev--zero" : ""}`}>{sev.low ?? 0}</span>
                        </>
                      ) : (
                        r.findingCount > 0
                          ? <span className="history-table__finding-count">{r.findingCount}</span>
                          : <span className="history-sev--zero">—</span>
                      )}
                    </td>
                    <td className="history-table__td history-table__td--mono">
                      {durationSec > 0 ? formatUptime(durationSec) : "—"}
                    </td>
                    <td className="history-table__td history-table__td--action">
                      <ChevronRight size={16} className="history-table__chevron" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
