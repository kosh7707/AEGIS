import { useEffect, useRef, useCallback, useState } from "react";
import type {
  SdkRegistryStatus,
  RegisteredSdk,
  SdkErrorCode,
  SdkPhaseDetail,
} from "@/common/api/sdk";
import { fetchProjectSdks, getSdkWsUrl } from "@/common/api/sdk";
import { logError } from "@/common/api/core";
import { createSeqTracker, parseWsMessage, createReconnectingWs } from "@/common/utils/wsEnvelope";
import type { ConnectionState, ReconnectableHookResult } from "@/common/utils/wsEnvelope";

export interface SdkProgressDetails {
  percent?: number;
  uploadedBytes?: number;
  totalBytes?: number;
  fileName?: string;
  /** Backend ETA seconds (currently upload-only — see shared-models §4.5). */
  etaSeconds?: number;
  /** Backend epoch-ms when current phase started. */
  phaseStartedAt?: number;
  /** Structured phase detail (kind + params). Prefer over free-text `message`. */
  phaseDetail?: SdkPhaseDetail;
}

export interface SdkErrorEventDetails {
  code?: SdkErrorCode;
  userMessage?: string;
  technicalDetail?: string;
  failedAt?: number;
  correlationId?: string;
  troubleshootingUrl?: string;
  retryable?: boolean;
  recoverable?: boolean;
}

export interface SdkLogEventPayload {
  timestamp: string;
  source: "aegis" | "installer";
  kind: "lifecycle" | "heartbeat" | "output" | "terminal";
  stream?: "stdout" | "stderr";
  message: string;
  logPath?: string;
}

export interface SdkProgressEvent {
  type: "sdk-progress" | "sdk-complete" | "sdk-error";
  sdkId: string;
  phase?: SdkRegistryStatus;
  profile?: RegisteredSdk["profile"];
  error?: string;
  details?: SdkProgressDetails;
  logPath?: string;
  // Structured error fields (sdk-error only)
  code?: SdkErrorCode;
  userMessage?: string;
  technicalDetail?: string;
  failedAt?: number;
  correlationId?: string;
  troubleshootingUrl?: string;
  retryable?: boolean;
  recoverable?: boolean;
}

interface UseSdkProgressOptions {
  projectId: string | undefined;
  onProgress: (sdkId: string, phase: SdkRegistryStatus, details?: SdkProgressDetails) => void;
  onComplete: (sdkId: string, profile: RegisteredSdk["profile"]) => void;
  onError: (
    sdkId: string,
    error: string,
    phase?: string,
    logPath?: string,
    details?: SdkErrorEventDetails,
  ) => void;
  /** Optional sdk-log WS handler; backward-compat (callers may omit). */
  onLog?: (sdkId: string, payload: SdkLogEventPayload) => void;
}

export interface UseSdkProgressResult extends ReconnectableHookResult {
  /** True after retry budget exhausted or close 4000 — UX should surface a banner. */
  disconnected: boolean;
  /** Human-readable reason populated when disconnected becomes true. */
  giveUpReason: string | null;
}

export function useSdkProgress({
  projectId,
  onProgress,
  onComplete,
  onError,
  onLog,
}: UseSdkProgressOptions): UseSdkProgressResult {
  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
  const [giveUpReason, setGiveUpReason] = useState<string | null>(null);
  const rwsRef = useRef<ReturnType<typeof createReconnectingWs> | null>(null);
  const callbacksRef = useRef({ onProgress, onComplete, onError, onLog });
  callbacksRef.current = { onProgress, onComplete, onError, onLog };

  const cleanup = useCallback(() => {
    if (rwsRef.current) {
      rwsRef.current.close();
      rwsRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!projectId) return;

    if (import.meta.env.VITE_MOCK === "true") {
      setConnectionState("disconnected");
      return;
    }

    setGiveUpReason(null);
    const seqTracker = createSeqTracker("sdk");
    const wsUrl = getSdkWsUrl(projectId);

    function wireHandlers(ws: WebSocket | null) {
      if (!ws) return;
      ws.onmessage = (evt) => {
        try {
          const parsed = parseWsMessage(evt.data);
          seqTracker.check(parsed.meta);
          const { type, payload } = parsed;
          if (type === "sdk-progress") {
            const details: SdkProgressDetails = {};
            if (payload.percent != null) details.percent = payload.percent;
            if (payload.uploadedBytes != null) details.uploadedBytes = payload.uploadedBytes;
            if (payload.totalBytes != null) details.totalBytes = payload.totalBytes;
            if (payload.fileName != null) details.fileName = payload.fileName;
            if (payload.etaSeconds != null) details.etaSeconds = payload.etaSeconds;
            if (payload.phaseStartedAt != null) details.phaseStartedAt = payload.phaseStartedAt;
            if (payload.phaseDetail != null) details.phaseDetail = payload.phaseDetail;
            callbacksRef.current.onProgress(payload.sdkId, payload.phase as SdkRegistryStatus, details);
          } else if (type === "sdk-complete") {
            callbacksRef.current.onComplete(payload.sdkId, payload.profile);
          } else if (type === "sdk-error") {
            const errDetails: SdkErrorEventDetails = {};
            if (payload.code != null) errDetails.code = payload.code;
            if (payload.userMessage != null) errDetails.userMessage = payload.userMessage;
            if (payload.technicalDetail != null) errDetails.technicalDetail = payload.technicalDetail;
            if (payload.failedAt != null) errDetails.failedAt = payload.failedAt;
            if (payload.correlationId != null) errDetails.correlationId = payload.correlationId;
            if (payload.troubleshootingUrl != null) errDetails.troubleshootingUrl = payload.troubleshootingUrl;
            if (payload.retryable != null) errDetails.retryable = payload.retryable;
            if (payload.recoverable != null) errDetails.recoverable = payload.recoverable;
            callbacksRef.current.onError(
              payload.sdkId,
              payload.error,
              payload.phase,
              payload.logPath,
              Object.keys(errDetails).length > 0 ? errDetails : undefined,
            );
          } else if (type === "sdk-log") {
            const logCb = callbacksRef.current.onLog;
            if (logCb) {
              const logPayload: SdkLogEventPayload = {
                timestamp: payload.timestamp,
                source: payload.source,
                kind: payload.kind,
                message: payload.message,
              };
              if (payload.stream != null) logPayload.stream = payload.stream;
              if (payload.logPath != null) logPayload.logPath = payload.logPath;
              logCb(payload.sdkId, logPayload);
            }
          }
        } catch (e) {
          console.warn("[WS:sdk] malformed message:", e);
        }
      };
    }

    const rws = createReconnectingWs(() => wsUrl, {
      maxRetries: 8,
      onStateChange: setConnectionState,
      onDisconnect() {
        seqTracker.reset();
      },
      async onReconnect() {
        // REST fallback: restore SDK list on reconnect
        try {
          const data = await fetchProjectSdks(projectId);
          for (const sdk of data.registered) {
            if (sdk.status === "ready") {
              callbacksRef.current.onComplete(sdk.id, sdk.profile);
            } else if (sdk.status.endsWith("_failed")) {
              callbacksRef.current.onError(sdk.id, sdk.verifyError ?? "Unknown error");
            } else {
              callbacksRef.current.onProgress(sdk.id, sdk.status);
            }
          }
        } catch (e) {
          logError("SDK recovery", e);
        }
        wireHandlers(rws.getWs());
      },
      onGiveUp() {
        setGiveUpReason("SDK 실시간 진행 상황 연결이 끊어졌습니다. 페이지를 새로고침해 주세요.");
      },
    });
    rwsRef.current = rws;
    wireHandlers(rws.getWs());

    return () => {
      cleanup();
    };
  }, [projectId, cleanup]);

  return {
    connectionState,
    disconnected: connectionState === "failed",
    giveUpReason,
  };
}
