import { useEffect, useRef, useCallback, useState } from "react";
import type { SdkRegistryStatus, RegisteredSdk, SdkLogEvent } from "../api/sdk";
import { fetchProjectSdks, getSdkWsUrl } from "../api/sdk";
import { logError } from "../api/core";
import { createSeqTracker, parseWsMessage, createReconnectingWs } from "../utils/wsEnvelope";
import type { ConnectionState, ReconnectableHookResult } from "../utils/wsEnvelope";

export interface SdkProgressDetails {
  percent?: number;
  uploadedBytes?: number;
  totalBytes?: number;
  fileName?: string;
}

export interface SdkProgressEvent {
  type: "sdk-progress" | "sdk-complete" | "sdk-error" | "sdk-log";
  sdkId: string;
  phase?: SdkRegistryStatus;
  profile?: RegisteredSdk["profile"];
  error?: string;
  details?: SdkProgressDetails;
  logPath?: string;
}

interface UseSdkProgressOptions {
  projectId: string | undefined;
  onProgress: (sdkId: string, phase: SdkRegistryStatus, details?: SdkProgressDetails) => void;
  onComplete: (sdkId: string, profile: RegisteredSdk["profile"]) => void;
  onError: (sdkId: string, error: string, phase?: string, logPath?: string) => void;
  onLog?: (sdkId: string, entry: SdkLogEvent) => void;
}

export function useSdkProgress({
  projectId,
  onProgress,
  onComplete,
  onError,
  onLog,
}: UseSdkProgressOptions): ReconnectableHookResult {
  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected");
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
            callbacksRef.current.onProgress(payload.sdkId, payload.phase as SdkRegistryStatus, details);
          } else if (type === "sdk-complete") {
            callbacksRef.current.onComplete(payload.sdkId, payload.profile);
          } else if (type === "sdk-error") {
            callbacksRef.current.onError(payload.sdkId, payload.error, payload.phase, payload.logPath);
          } else if (type === "sdk-log") {
            callbacksRef.current.onLog?.(payload.sdkId, {
              sdkId: payload.sdkId,
              timestamp: payload.timestamp,
              source: payload.source,
              kind: payload.kind,
              stream: payload.stream,
              message: payload.message,
              logPath: payload.logPath,
            });
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
          // Notify parent of any state changes via callbacks
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
    });
    rwsRef.current = rws;
    wireHandlers(rws.getWs());

    return () => {
      cleanup();
    };
  }, [projectId, cleanup]);

  return { connectionState };
}
