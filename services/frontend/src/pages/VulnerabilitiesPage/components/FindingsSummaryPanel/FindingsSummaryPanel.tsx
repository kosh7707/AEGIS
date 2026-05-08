import "./FindingsSummaryPanel.css";
import React from "react";
import type { FindingsSummary } from "@/common/api/analysis";
import type { FindingStatus, Severity } from "@aegis/shared";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "치명",
  high: "높음",
  medium: "보통",
  low: "낮음",
  info: "정보",
};

const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

const STATUS_LABEL: Record<FindingStatus, string> = {
  open: "OPEN",
  needs_review: "REVIEW",
  accepted_risk: "ACCEPTED",
  false_positive: "FALSE POS",
  fixed: "FIXED",
  needs_revalidation: "REVALIDATE",
  sandbox: "SANDBOX",
};

/** Status → review-tone token. NEVER severity-bound. Status is a process
 *  state, not a risk level — it uses the review-tone vocabulary
 *  (`--success` / `--warning` / `--danger` / `--primary`) per handoff §3.3. */
// STATUS_TONE: review-tone palette (handoff §2.1). `muted` slot = neutral-review tone
// (no border tint, --foreground-muted text); used for terminal/non-actionable statuses
// (accepted_risk = decided, false_positive = dismissed).
const STATUS_TONE: Record<FindingStatus, "success" | "warning" | "danger" | "primary" | "muted"> = {
  open: "danger",
  needs_review: "warning",
  needs_revalidation: "warning",
  accepted_risk: "muted",
  false_positive: "muted",
  fixed: "success",
  sandbox: "primary",
};

const STATUS_ORDER: readonly FindingStatus[] = [
  "open",
  "needs_review",
  "needs_revalidation",
  "accepted_risk",
  "false_positive",
  "fixed",
  "sandbox",
] as const;

interface Props {
  summary: FindingsSummary | null;
}

/**
 * Renders the aggregate findings/summary panel using the typed S2 contract:
 *   - `total` (number)
 *   - `bySeverity` (severity-keyed numeric record)
 *   - `byStatus` (status-keyed numeric record, review-tone)
 */
export const FindingsSummaryPanel: React.FC<Props> = ({ summary }) => {
  if (!summary || typeof summary.total !== "number") {
    return (
      <section className="findings-summary-panel" aria-label="탐지 항목 집계">
        <p className="findings-summary-panel__empty">정보 없음</p>
      </section>
    );
  }

  const bySeverity = summary.bySeverity ?? {};
  const severityKpis = SEVERITY_ORDER
    .map((key) => ({ key, value: bySeverity[key] }))
    .filter((entry): entry is { key: Severity; value: number } => typeof entry.value === "number");

  const byStatus = summary.byStatus ?? {};
  const statusEntries = STATUS_ORDER
    .map((key) => ({ key, value: byStatus[key] }))
    .filter((entry): entry is { key: FindingStatus; value: number } => typeof entry.value === "number");

  return (
    <section className="findings-summary-panel" aria-label="탐지 항목 집계">
      <dl className="kpi findings-summary-panel__row">
        <div className="findings-summary-panel__cell">
          <dt>TOTAL</dt>
          <dd>{summary.total.toLocaleString()}</dd>
        </div>
        {severityKpis.map(({ key, value }) => (
          <div key={key} className="findings-summary-panel__cell">
            <dt>{SEVERITY_LABEL[key]}</dt>
            <dd className={`findings-summary-panel__num findings-summary-panel__num--${key}`}>
              {value.toLocaleString()}
            </dd>
          </div>
        ))}
      </dl>
      {statusEntries.length > 0 ? (
        <ul className="findings-summary-panel__status-row" role="list">
          {statusEntries.map(({ key, value }) => (
            <li
              key={key}
              className={`findings-summary-panel__status-pill findings-summary-panel__status-pill--${STATUS_TONE[key]}`}
            >
              <span className="findings-summary-panel__status-label">{STATUS_LABEL[key]}</span>
              <span className="findings-summary-panel__status-count">{value.toLocaleString()}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
};
