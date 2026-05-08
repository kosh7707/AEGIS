import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import type { AnalysisProgress, WsAnalysisMessage } from "@aegis/shared";
import { ApiError, runAnalysis, getWsBaseUrl, logError } from "@/common/api/client";
import { fetchAnalysisStatus, runDeepAnalysis } from "@/common/api/analysis";

export type AnalysisMode = "quick" | "deep";
import { createSeqTracker, parseWsMessage, createReconnectingWs } from "@/common/utils/wsEnvelope";
import type { ConnectionState, ReconnectableHookResult } from "@/common/utils/wsEnvelope";

export type AnalysisStage =
  | "idle"
  | "quick_sast"
  | "quick_graphing"
  | "quick_complete"
  | "deep_submitting"
  | "deep_analyzing"
  | "deep_retrying"
  | "deep_complete"
  | "error";

const RUNNING_STAGES = new Set<AnalysisStage>([
  "quick_sast",
  "quick_graphing",
  "quick_complete",
  "deep_submitting",
  "deep_analyzing",
  "deep_retrying",
]);

const PHASE_LABELS: Record<string, string> = {
  quick_sast: "빌드 + SAST 스캔 중...",
  quick_graphing: "코드 그래프 컨텍스트 적재 중...",
  quick_complete: "빠른 분석 완료",
  deep_submitting: "심층 분석 에이전트 호출 중...",
  deep_analyzing: "에이전트가 분석 중... (SAST + 코드그래프 + SCA + LLM)",
  deep_retrying: "심층 분석 재시도 중...",
  deep_complete: "심층 분석 완료",
};

function toStage(phase: string | undefined, fallback: AnalysisStage): AnalysisStage {
  if (phase === "quick_complete" || phase === "deep_complete") {
    return phase;
  }
  return RUNNING_STAGES.has(phase as AnalysisStage) ? phase as AnalysisStage : fallback;
}

function buildStatusState(status: AnalysisProgress): AnalysisWsState {
  const stage = toStage(status.phase, "idle");
  return {
    analysisId: status.analysisId,
    buildTargetId: status.buildTargetId ?? null,
    executionId: status.executionId ?? null,
    stage,
    message: PHASE_LABELS[stage] ?? status.message ?? "",
    quickFindingCount: null,
    deepFindingCount: null,
    error: status.error ?? null,
    errorPhase: status.error
      ? (status.phase?.startsWith("deep_") ? "deep" : "quick")
      : null,
    targetName: null,
    targetProgress: null,
  };
}

export interface AnalysisWsState {
  analysisId: string | null;
  buildTargetId: string | null;
  executionId?: string | null;
  stage: AnalysisStage;
  message: string;
  quickFindingCount: number | null;
  deepFindingCount: number | null;
  error: string | null;
  errorPhase: "quick" | "deep" | null;
  targetName: string | null;
  targetProgress: { current: number; total: number } | null;
}

const INITIAL_STATE: AnalysisWsState = {
  analysisId: null,
  buildTargetId: null,
  executionId: null,
  stage: "idle",
  message: "",
  quickFindingCount: null,
  deepFindingCount: null,
  error: null,
  errorPhase: null,
  targetName: null,
  targetProgress: null,
};

export function useAnalysisWebSocket(): AnalysisWsState & ReconnectableHookResult & {
  isRunning: boolean;
  startAnalysis: (projectId: string, buildTargetId: string, mode?: AnalysisMode) => Promise<void>;
  resumeAnalysis: (analysisId: string, initialStatus?: AnalysisProgress) => Promise<void>;
  reset: () => void;
} {
  const [state, setState] = useState<AnalysisWsState>(INITIAL_STATE);
  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
  const rwsRef = useRef<ReturnType<typeof createReconnectingWs> | null>(null);

  const isRunning = RUNNING_STAGES.has(state.stage);

  const cleanup = useCallback(() => {
    if (rwsRef.current) {
      rwsRef.current.close();
      rwsRef.current = null;
    }
  }, []);

  useEffect(() => cleanup, [cleanup]);

  const wireWsHandlers = useCallback((ws: WebSocket | null, seqTracker: ReturnType<typeof createSeqTracker>) => {
    if (!ws) return;
    ws.onmessage = (evt) => {
      try {
        const parsed = parseWsMessage(evt.data);
        seqTracker.check(parsed.meta);
        const msg = parsed as unknown as WsAnalysisMessage;
        switch (msg.type) {
          case "analysis-progress": {
            const { phase, message: msg2, targetName, targetProgress, buildTargetId, executionId } = msg.payload;
            setState((prev) => ({
              ...prev,
              buildTargetId: buildTargetId ?? prev.buildTargetId,
              executionId: executionId ?? prev.executionId,
              stage: (RUNNING_STAGES.has(phase as AnalysisStage) ? phase : prev.stage) as AnalysisStage,
              message: PHASE_LABELS[phase] ?? msg2 ?? prev.message,
              targetName: targetName ?? prev.targetName,
              targetProgress: targetProgress ?? prev.targetProgress,
            }));
            break;
          }
          case "analysis-quick-complete":
            setState((prev) => ({
              ...prev,
              buildTargetId: msg.payload.buildTargetId ?? prev.buildTargetId,
              executionId: msg.payload.executionId ?? prev.executionId,
              stage: "quick_complete",
              message: PHASE_LABELS.quick_complete,
              quickFindingCount: msg.payload.findingCount,
            }));
            break;
          case "analysis-deep-complete":
            setState((prev) => ({
              ...prev,
              buildTargetId: msg.payload.buildTargetId ?? prev.buildTargetId,
              executionId: msg.payload.executionId ?? prev.executionId,
              stage: "deep_complete",
              message: PHASE_LABELS.deep_complete,
              deepFindingCount: msg.payload.findingCount,
            }));
            cleanup();
            break;
          case "analysis-error":
            setState((prev) => ({
              ...prev,
              buildTargetId: msg.payload.buildTargetId ?? prev.buildTargetId,
              executionId: msg.payload.executionId ?? prev.executionId,
              stage: "error",
              message: "",
              error: msg.payload.error,
              errorPhase: (msg.payload.phase ?? null) as "quick" | "deep" | null,
              targetName: null,
              targetProgress: null,
            }));
            cleanup();
            break;
        }
      } catch (e) {
        console.warn("[WS:analysis] malformed message:", e);
      }
    };
  }, [cleanup]);

  const connectToAnalysis = useCallback((analysisId: string) => {
    const wsUrl = `${getWsBaseUrl()}/ws/analysis?analysisId=${analysisId}`;
    const seqTracker = createSeqTracker("analysis");

    const rws = createReconnectingWs(() => wsUrl, {
      maxRetries: 10,
      onStateChange: setConnectionState,
      onDisconnect() {
        seqTracker.reset();
      },
      async onReconnect() {
        try {
          const status = await fetchAnalysisStatus(analysisId);
          setState((prev) => {
            if (prev.stage === "deep_complete" || prev.stage === "error") return prev;
            const stage = toStage(status.phase, prev.stage);
            return {
              ...prev,
              buildTargetId: status.buildTargetId ?? prev.buildTargetId,
              executionId: status.executionId ?? prev.executionId,
              stage,
              message: PHASE_LABELS[stage] ?? status.message ?? prev.message,
            };
          });
        } catch (e) {
          logError("Analysis recovery", e);
        }
        wireWsHandlers(rws.getWs(), seqTracker);
      },
      onGiveUp() {
        setState((prev) => {
          if (!RUNNING_STAGES.has(prev.stage)) return prev;
          return {
            ...prev,
            stage: "error",
            error: "WebSocket 연결이 끊어졌습니다.",
          };
        });
      },
    });
    rwsRef.current = rws;
    wireWsHandlers(rws.getWs(), seqTracker);
  }, [wireWsHandlers]);

  const startAnalysis = useCallback(async (projectId: string, buildTargetId: string, mode: AnalysisMode = "quick") => {
    cleanup();
    const initialStage: AnalysisStage = mode === "deep" ? "deep_submitting" : "quick_sast";
    setState({
      ...INITIAL_STATE,
      buildTargetId,
      stage: initialStage,
      message: "분석 준비 중...",
    });

    try {
      const runner = mode === "deep" ? runDeepAnalysis : runAnalysis;
      const { analysisId, executionId } = await runner(projectId, buildTargetId);
      setState((prev) => ({
        ...prev,
        analysisId,
        buildTargetId,
        executionId: executionId ?? analysisId,
      }));
      connectToAnalysis(analysisId);
    } catch (e) {
      logError("Start analysis", e);
      setState({
        ...INITIAL_STATE,
        stage: "error",
        error: e instanceof ApiError
          ? e.detailMessage ?? e.message
          : e instanceof Error
            ? e.message
            : "분석 실행에 실패했습니다.",
      });
    }
  }, [cleanup, connectToAnalysis]);

  const resumeAnalysis = useCallback(async (analysisId: string, initialStatus?: AnalysisProgress) => {
    cleanup();
    try {
      const status = initialStatus ?? await fetchAnalysisStatus(analysisId);
      setState(buildStatusState(status));
      if (status.status === "running") {
        connectToAnalysis(analysisId);
      } else {
        setConnectionState("disconnected");
      }
    } catch (e) {
      logError("Resume analysis", e);
      setState({
        ...INITIAL_STATE,
        analysisId,
        stage: "error",
        error: e instanceof Error ? e.message : "분석 상태 복구에 실패했습니다.",
      });
    }
  }, [cleanup, connectToAnalysis]);

  const reset = useCallback(() => {
    cleanup();
    setState(INITIAL_STATE);
    setConnectionState("disconnected");
  }, [cleanup]);

  return useMemo(
    () => ({ ...state, connectionState, isRunning, startAnalysis, resumeAnalysis, reset }),
    [state, connectionState, isRunning, startAnalysis, resumeAnalysis, reset],
  );
}
