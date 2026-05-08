import "./TwoStageProgressView.css";
import React, { useState } from "react";
import { AlertTriangle, ArrowLeft, CheckCircle, Loader, XCircle } from "lucide-react";
import { cn } from "@/common/utils/cn";
import type { AnalysisStage } from "@/common/hooks/useAnalysisWebSocket";
import { useElapsedTimer } from "@/common/hooks/useElapsedTimer";
import { ConfirmDialog } from "@/common/ui/primitives";

interface Props {
  analysisId: string | null;
  buildTargetId?: string | null;
  executionId?: string | null;
  stage: AnalysisStage;
  message: string;
  quickFindingCount: number | null;
  deepFindingCount: number | null;
  error: string | null;
  errorPhase: "quick" | "deep" | null;
  retryable: boolean;
  targetName?: string | null;
  targetProgress?: { current: number; total: number } | null;
  onRetry: () => void;
  onViewResults: () => void;
  onBack: () => void;
  onAbort?: (analysisId: string) => void;
}

const STAGES: { key: AnalysisStage; label: string }[] = [
  { key: "quick_sast", label: "빠른 분석 (SAST)" },
  { key: "deep_analyzing", label: "심층 분석 (Agent)" },
];

function isStageComplete(stageKey: string, currentStage: AnalysisStage): boolean {
  if (stageKey === "quick_sast") {
    return ["quick_complete", "deep_submitting", "deep_analyzing", "deep_retrying", "deep_complete"].includes(currentStage);
  }
  if (stageKey === "deep_analyzing") {
    return currentStage === "deep_complete";
  }
  return false;
}

function isStageActive(stageKey: string, currentStage: AnalysisStage): boolean {
  if (stageKey === "quick_sast") {
    return currentStage === "quick_sast" || currentStage === "quick_graphing";
  }
  if (stageKey === "deep_analyzing") {
    return currentStage === "deep_submitting" || currentStage === "deep_analyzing" || currentStage === "deep_retrying";
  }
  return false;
}

export const TwoStageProgressView: React.FC<Props> = ({
  analysisId,
  buildTargetId,
  executionId,
  stage,
  message,
  quickFindingCount,
  deepFindingCount,
  error,
  errorPhase,
  retryable,
  targetName,
  targetProgress,
  onRetry,
  onViewResults,
  onBack,
  onAbort,
}) => {
  const [showAbortConfirm, setShowAbortConfirm] = useState(false);
  const timerActive = stage !== "deep_complete" && stage !== "error" && stage !== "idle";
  const { timeStr } = useElapsedTimer(timerActive, analysisId);

  const isComplete = stage === "deep_complete";
  const isError = stage === "error";

  const titleText = isComplete ? "분석 완료" : isError ? "분석 오류" : "분석 진행 중";
  const gateKind = isComplete ? "pass" : isError ? "blocked" : "running";

  return (
    <div className="page-shell two-stage-shell" data-chore>
      <header className="page-head chore c-1">
        <div>
          <button type="button" className="back-link" onClick={onBack}>
            <ArrowLeft aria-hidden="true" /> 대시보드로
          </button>
          <h1>{titleText}</h1>
          <div className="sub">
            <span className={`cell-gate ${gateKind}`}>
              {isComplete ? "COMPLETE" : isError ? "ERROR" : "RUNNING"}
            </span>
            <span className="sep" aria-hidden="true">·</span>
            <span className="sub-caps">ELAPSED</span>
            <b>{timeStr}</b>
            {buildTargetId ? (
              <>
                <span className="sep" aria-hidden="true">·</span>
                <span className="sub-caps">BUILD TARGET</span>
                <b className="mono-code">{buildTargetId}</b>
              </>
            ) : null}
            {executionId ? (
              <>
                <span className="sep" aria-hidden="true">·</span>
                <span className="sub-caps">EXECUTION</span>
                <b className="mono-code">{executionId}</b>
              </>
            ) : null}
            {targetProgress && targetProgress.total > 1 ? (
              <>
                <span className="sep" aria-hidden="true">·</span>
                <span className="sub-caps">TARGET</span>
                <b>
                  {targetProgress.current} / {targetProgress.total}
                  {targetName ? ` · ${targetName}` : ""}
                </b>
              </>
            ) : null}
          </div>
        </div>
        <div className="actions">
          {isComplete ? (
            <button type="button" className="btn btn-primary btn-sm" onClick={onViewResults}>
              결과 보기
            </button>
          ) : isError ? (
            <button type="button" className="btn btn-outline btn-sm" onClick={onBack}>
              돌아가기
            </button>
          ) : (
            <button
              type="button"
              className="btn btn-danger btn-sm"
              onClick={() => setShowAbortConfirm(true)}
            >
              <AlertTriangle size={14} />
              분석 중단
            </button>
          )}
        </div>
      </header>

      <section className="chore c-2" aria-labelledby="progress-head">
        <div className="section-head">
          <h2 id="progress-head">
            진행 단계
            <span className="count">{STAGES.length}</span>
          </h2>
          {message ? <span className="hint">{message}</span> : null}
        </div>
        <div className="panel">
          <div className="two-stage-steps">
            {STAGES.map((stageInfo, index) => {
              const complete = isStageComplete(stageInfo.key, stage);
              const active = isStageActive(stageInfo.key, stage);
              const stateClass = complete ? "is-complete" : active ? "is-active" : "is-pending";

              return (
                <div key={stageInfo.key} className={cn("two-stage-step", stateClass)}>
                  <div className="two-stage-step__marker">
                    {complete ? (
                      <CheckCircle size={18} />
                    ) : active ? (
                      <Loader size={18} className="two-stage-step__spinner" />
                    ) : (
                      <span className="two-stage-step__index">{index + 1}</span>
                    )}
                  </div>
                  <div className="two-stage-step__copy">
                    <div className="two-stage-step__title">{stageInfo.label}</div>
                    {stageInfo.key === "quick_sast" && complete && quickFindingCount !== null ? (
                      <div className="two-stage-step__success">
                        <span className="sub-caps">QUICK FINDINGS</span>
                        <b>{quickFindingCount}</b>
                      </div>
                    ) : null}
                    {stageInfo.key === "deep_analyzing" && complete && deepFindingCount !== null ? (
                      <div className="two-stage-step__success">
                        <span className="sub-caps">DEEP ADDED</span>
                        <b>{deepFindingCount}</b>
                      </div>
                    ) : null}
                    {active && message ? (
                      <div className="two-stage-step__message">{message}</div>
                    ) : null}
                  </div>
                  {index < STAGES.length - 1 ? (
                    <div className={cn("two-stage-step__line", complete && "is-complete")} />
                  ) : null}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {isError && error ? (
        <section className="chore c-3" aria-labelledby="error-head">
          <div className="section-head">
            <h2 id="error-head">오류</h2>
          </div>
          <div className="panel two-stage-error">
            <div className="two-stage-error__head">
              <XCircle size={16} aria-hidden="true" />
              <span>
                {errorPhase === "quick" ? "빠른 분석" : errorPhase === "deep" ? "심층 분석" : "분석"} 중 오류 발생
              </span>
            </div>
            <p className="two-stage-error__copy">{error}</p>
            {retryable ? (
              <div className="two-stage-error__actions">
                <button type="button" className="btn btn-primary btn-sm" onClick={onRetry}>
                  다시 시도
                </button>
              </div>
            ) : null}
          </div>
        </section>
      ) : null}

      {stage === "deep_submitting" || stage === "deep_analyzing" ? (
        <section className="chore c-4" aria-labelledby="handoff-head">
          <div className="section-head">
            <h2 id="handoff-head">먼저 확인</h2>
            <span className="hint">QUICK 결과 준비됨</span>
          </div>
          <div className="panel two-stage-handoff">
            <CheckCircle size={16} aria-hidden="true" />
            <span>빠른 분석 결과를 먼저 확인할 수 있습니다.</span>
            <button type="button" className="btn btn-outline btn-sm" onClick={onViewResults}>
              Quick 결과 보기
            </button>
          </div>
        </section>
      ) : null}

      <ConfirmDialog
        open={showAbortConfirm}
        title="분석 중단"
        message="진행 중인 분석을 중단하시겠습니까? 중단하면 결과가 저장되지 않습니다."
        confirmLabel="중단"
        danger
        onConfirm={() => {
          setShowAbortConfirm(false);
          if (onAbort && analysisId) {
            onAbort(analysisId);
          } else {
            onBack();
          }
        }}
        onCancel={() => setShowAbortConfirm(false)}
      />
    </div>
  );
};
