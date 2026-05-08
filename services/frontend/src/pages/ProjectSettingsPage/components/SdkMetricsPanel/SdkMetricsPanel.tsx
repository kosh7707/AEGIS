import "./SdkMetricsPanel.css";
import React, { useEffect, useState } from "react";
import { fetchSdkMetrics, type SdkMetrics } from "@/common/api/sdk";
import { logError } from "@/common/api/core";
import type { SdkPhase } from "@aegis/shared";

interface SdkMetricsPanelProps {
  projectId: string;
}

const PHASE_LABEL: Record<SdkPhase, string> = {
  uploading: "UPLOAD",
  uploaded: "UPLOADED",
  extracting: "EXTRACT",
  extracted: "EXTRACTED",
  installing: "INSTALL",
  installed: "INSTALLED",
  analyzing: "ANALYZE",
  verifying: "VERIFY",
  ready: "READY",
  upload_failed: "업로드 실패",
  extract_failed: "압축 해제 실패",
  install_failed: "설치 실패",
  verify_failed: "검증 실패",
};

/** Compact KPI row of SDK aggregate metrics — typed `SdkMetrics` from
 *  the shared contract. Surfaces canonical counters (totalRegistered /
 *  readyCount / failedCount) plus average phase durations when present. */
export const SdkMetricsPanel: React.FC<SdkMetricsPanelProps> = ({ projectId }) => {
  const [metrics, setMetrics] = useState<SdkMetrics | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const data = await fetchSdkMetrics(projectId);
        if (!cancelled) {
          setMetrics(data);
          setLoaded(true);
        }
      } catch (error) {
        logError("Fetch SDK metrics", error);
        if (!cancelled) {
          setMetrics(null);
          setLoaded(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  if (!loaded) return null;

  if (!metrics) {
    return (
      <section className="sdk-metrics-panel" aria-label="SDK 집계 지표">
        <p className="sdk-metrics-panel__empty">정보 없음</p>
      </section>
    );
  }

  // Prefer canonical totalRegistered; fall back to compat sdkCount only if
  // totalRegistered is null/undefined (per S2 guidance).
  const total = metrics.totalRegistered ?? metrics.sdkCount;
  const ready = metrics.readyCount;
  const failed = metrics.failedCount;

  const phaseDurations = Object.entries(metrics.averagePhaseDurationMs ?? {})
    .filter((entry): entry is [string, number] => entry[1] !== undefined);

  return (
    <section className="sdk-metrics-panel" aria-label="SDK 집계 지표">
      <dl className="kpi sdk-metrics-panel__row">
        <div className="sdk-metrics-panel__cell">
          <dt>TOTAL REGISTERED</dt>
          <dd>{Number.isFinite(total) ? total.toLocaleString() : "—"}</dd>
        </div>
        <div className="sdk-metrics-panel__cell">
          <dt>READY</dt>
          <dd>{Number.isFinite(ready) ? ready.toLocaleString() : "—"}</dd>
        </div>
        <div className="sdk-metrics-panel__cell">
          <dt>FAILED</dt>
          <dd>{Number.isFinite(failed) ? failed.toLocaleString() : "—"}</dd>
        </div>
      </dl>
      {phaseDurations.length > 0 ? (
        <dl className="kpi sdk-metrics-panel__row sdk-metrics-panel__row--phases">
          {phaseDurations.map(([phase, ms]) => (
            <div key={phase} className="sdk-metrics-panel__cell">
              <dt>{PHASE_LABEL[phase] ?? phase.toUpperCase()}</dt>
              <dd>{`${Math.round(ms).toLocaleString()} ms`}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </section>
  );
};
