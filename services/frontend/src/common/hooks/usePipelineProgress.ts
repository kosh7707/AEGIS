import { useState, useCallback, useRef, useEffect } from "react";
import type { BuildTargetStatus, PipelinePhase, WsPipelineMessage } from "@aegis/shared";
import { runPipeline, runPipelineTarget, getWsBaseUrl, logError } from "@/common/api/client";
import { fetchPipelineStatus, preparePipeline, preparePipelineTarget } from "@/common/api/pipeline";
import { createSeqTracker, parseWsMessage, createReconnectingWs } from "@/common/utils/wsEnvelope";
import type { ConnectionState, ReconnectableHookResult } from "@/common/utils/wsEnvelope";

export interface PipelineTargetState {
  name: string;
  status: BuildTargetStatus;
  phase: PipelinePhase;
  message: string;
  error?: string;
}

export interface PipelineState {
  targets: Map<string, PipelineTargetState>;
  isRunning: boolean;
  isPreparing: boolean;
  readyCount: number;
  failedCount: number;
  totalCount: number;
  pipelineId: string | null;
  preparationId: string | null;
}

const INITIAL: PipelineState = {
  targets: new Map(),
  isRunning: false,
  isPreparing: false,
  readyCount: 0,
  failedCount: 0,
  totalCount: 0,
  pipelineId: null,
  preparationId: null,
};

function toFailedStatus(
  phase: PipelinePhase,
  existingStatus?: BuildTargetStatus,
): BuildTargetStatus {
  if (existingStatus?.endsWith("_failed")) return existingStatus;
  if (phase === "setup") return "resolve_failed";
  return "build_failed";
}

export function usePipelineProgress(): PipelineState & ReconnectableHookResult & {
  startPipeline: (projectId: string, targetIds?: string[]) => Promise<void>;
  retryTarget: (projectId: string, targetId: string) => Promise<void>;
  startPreparation: (projectId: string, targetIds?: string[]) => Promise<void>;
  prepareTarget: (projectId: string, targetId: string) => Promise<void>;
  reset: () => void;
} {
  const [state, setState] = useState<PipelineState>(INITIAL);
  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
  const rwsRef = useRef<ReturnType<typeof createReconnectingWs> | null>(null);
  const projectIdRef = useRef<string | null>(null);

  const cleanup = useCallback(() => {
    if (rwsRef.current) {
      rwsRef.current.close();
      rwsRef.current = null;
    }
  }, []);

  useEffect(() => cleanup, [cleanup]);

  function wireWsHandlers(ws: WebSocket | null, seqTracker: ReturnType<typeof createSeqTracker>) {
    if (!ws) return;
    ws.onmessage = (evt) => {
      try {
        const parsed = parseWsMessage(evt.data);
        seqTracker.check(parsed.meta);
        const msg = parsed as unknown as WsPipelineMessage;
        switch (msg.type) {
          case "pipeline-target-status":
            setState((prev) => {
              const next = new Map(prev.targets);
              next.set(msg.payload.targetId, {
                name: msg.payload.targetName,
                status: msg.payload.status,
                phase: msg.payload.phase,
                message: msg.payload.message,
              });
              return { ...prev, targets: next };
            });
            break;
          case "pipeline-complete":
            setState((prev) => ({
              ...prev,
              isRunning: false,
              isPreparing: false,
              readyCount: msg.payload.readyCount,
              failedCount: msg.payload.failedCount,
              totalCount: msg.payload.totalCount,
            }));
            cleanup();
            break;
          case "pipeline-error":
            setState((prev) => {
              const next = new Map(prev.targets);
              const existing = next.get(msg.payload.targetId);
              next.set(msg.payload.targetId, {
                ...existing,
                name: msg.payload.targetName,
                status: toFailedStatus(msg.payload.phase as PipelinePhase, existing?.status),
                phase: msg.payload.phase as PipelinePhase,
                message: "",
                error: msg.payload.error,
              });
              return { ...prev, targets: next };
            });
            break;
        }
      } catch (e) {
        console.warn("[WS:pipeline] malformed message:", e);
      }
    };
  }

  const connectWs = useCallback((projectId: string) => {
    cleanup();
    projectIdRef.current = projectId;
    const wsUrl = `${getWsBaseUrl()}/ws/pipeline?projectId=${encodeURIComponent(projectId)}`;
    const seqTracker = createSeqTracker("pipeline");

    const rws = createReconnectingWs(() => wsUrl, {
      maxRetries: 10,
      onStateChange: setConnectionState,
      onDisconnect() {
        seqTracker.reset();
      },
      async onReconnect() {
        // REST fallback: restore target states from pipeline/status
        try {
          const status = await fetchPipelineStatus(projectId);
          setState((prev) => {
            const next = new Map(prev.targets);
            for (const target of status.targets ?? []) {
              next.set(target.id, {
                name: target.name,
                status: target.status,
                phase: target.phase,
                message: target.message ?? "",
                error: target.error,
              });
            }
            return {
              ...prev,
              targets: next,
              isRunning: status.isRunning ?? prev.isRunning,
              readyCount: status.readyCount ?? prev.readyCount,
              failedCount: status.failedCount ?? prev.failedCount,
              totalCount: status.totalCount ?? prev.totalCount,
            };
          });
        } catch (e) {
          logError("Pipeline recovery", e);
        }
        wireWsHandlers(rws.getWs(), seqTracker);
      },
      onGiveUp() {
        setState((prev) => ({
          ...prev,
          isRunning: false,
          isPreparing: false,
        }));
      },
    });
    rwsRef.current = rws;
    wireWsHandlers(rws.getWs(), seqTracker);
  }, [cleanup]);

  const startPipeline = useCallback(async (projectId: string, targetIds?: string[]) => {
    setState({ ...INITIAL, isRunning: true, pipelineId: null });
    try {
      const { pipelineId } = await runPipeline(projectId, targetIds);
      setState((prev) => ({ ...prev, pipelineId }));
      connectWs(projectId);
    } catch (e) {
      logError("Start pipeline", e);
      setState((prev) => ({ ...prev, isRunning: false }));
      throw e;
    }
  }, [connectWs]);

  const retryTarget = useCallback(async (projectId: string, targetId: string) => {
    try {
      await runPipelineTarget(projectId, targetId);
      if (!rwsRef.current) connectWs(projectId);
      setState((prev) => ({ ...prev, isRunning: true }));
    } catch (e) {
      logError("Retry pipeline target", e);
      throw e;
    }
  }, [connectWs]);

  const startPreparation = useCallback(async (projectId: string, targetIds?: string[]) => {
    setState({ ...INITIAL, isPreparing: true });
    try {
      const { preparationId } = await preparePipeline(projectId, targetIds);
      setState((prev) => ({ ...prev, preparationId }));
      connectWs(projectId);
    } catch (e) {
      logError("Start pipeline preparation", e);
      setState((prev) => ({ ...prev, isPreparing: false }));
      throw e;
    }
  }, [connectWs]);

  const prepareTarget = useCallback(async (projectId: string, targetId: string) => {
    try {
      const { preparationId } = await preparePipelineTarget(projectId, targetId);
      if (!rwsRef.current) connectWs(projectId);
      setState((prev) => ({ ...prev, isPreparing: true, preparationId }));
    } catch (e) {
      logError("Prepare pipeline target", e);
      throw e;
    }
  }, [connectWs]);

  const reset = useCallback(() => {
    cleanup();
    setState(INITIAL);
    setConnectionState("disconnected");
    projectIdRef.current = null;
  }, [cleanup]);

  return { ...state, connectionState, startPipeline, retryTarget, startPreparation, prepareTarget, reset };
}
