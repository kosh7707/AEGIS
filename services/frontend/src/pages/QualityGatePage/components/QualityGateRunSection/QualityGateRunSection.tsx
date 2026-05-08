import "./QualityGateRunSection.css";
import React, { useEffect, useState } from "react";
import { GitBranch } from "lucide-react";
import type { GateProfile } from "@aegis/shared";
import type { GateResult } from "@/common/api/gate";
import { fetchGateRunResults } from "@/common/api/gate";
import { logError } from "@/common/api/core";
import { sortGatesByEvaluatedAt } from "../../qualityGatePresentation";
import { QualityGateCard } from "../QualityGateCard/QualityGateCard";

interface QualityGateRunSectionProps {
  projectId: string;
  runId: string;
  gateProfilesById: Record<string, GateProfile>;
  onRequestOverride: (gateId: string) => void;
}

/** Run-scoped gate results — shown when the URL carries `?runId=...`.
 *  Reuses `QualityGateCard` directly; no new gate visualization is invented. */
export const QualityGateRunSection: React.FC<QualityGateRunSectionProps> = ({
  projectId,
  runId,
  gateProfilesById,
  onRequestOverride,
}) => {
  const [gates, setGates] = useState<GateResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setErrored(false);
    void (async () => {
      try {
        const data = await fetchGateRunResults(projectId, runId);
        if (!cancelled) {
          setGates([...data].sort(sortGatesByEvaluatedAt));
        }
      } catch (error) {
        logError("Load run-scoped gate results", error);
        if (!cancelled) {
          setGates([]);
          setErrored(true);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [projectId, runId]);

  return (
    <section
      className="quality-gate-run-section"
      aria-label={`Run ${runId}의 게이트 결과`}
    >
      <header className="quality-gate-run-section__head">
        <h2 className="quality-gate-run-section__title">
          <GitBranch size={14} aria-hidden="true" />
          이 Run의 게이트 결과
        </h2>
        <span className="quality-gate-run-section__run">
          RUN <code>#{runId}</code>
        </span>
      </header>

      {loading ? (
        <p className="quality-gate-run-section__status">불러오는 중...</p>
      ) : errored ? (
        <p className="quality-gate-run-section__status">
          이 Run의 게이트 결과를 불러올 수 없습니다.
        </p>
      ) : gates.length === 0 ? (
        <p className="quality-gate-run-section__status">
          이 Run에는 게이트 결과가 없습니다.
        </p>
      ) : (
        <div className="quality-gate-run-section__list">
          {gates.map((gate) => (
            <QualityGateCard
              key={gate.id}
              gate={gate}
              profile={gate.profileId ? gateProfilesById[gate.profileId] : undefined}
              onRequestOverride={onRequestOverride}
            />
          ))}
        </div>
      )}
    </section>
  );
};
