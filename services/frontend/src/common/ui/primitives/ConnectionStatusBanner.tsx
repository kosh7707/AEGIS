import React from "react";
import { WifiOff, AlertTriangle } from "lucide-react";
import { cn } from "@/common/utils/cn";
import type { ConnectionState } from "@/common/utils/wsEnvelope";
import type { LlmGatewayHealthDetail } from "@/common/api/core";
import "./ConnectionStatusBanner.css";

interface Props {
  connectionState: ConnectionState;
  retryCount?: number;
  /**
   * Optional LLM Gateway readiness detail from S2 `/health` (forwarded from S7).
   * When `degraded === true` or `llmReady === false`, renders a caution-review
   * tone banner indicating LLM partial unreadiness. Critical connection banner
   * (failed / reconnecting) still takes precedence so users see the most severe
   * signal first.
   */
  llmGatewayDetail?: LlmGatewayHealthDetail | null;
}

/**
 * Maps S7-forwarded `blockedReason` codes to user-facing Korean copy. Returns
 * `null` for unknown / absent codes so callers can fall back to generic copy.
 */
export function describeLlmBlockedReason(
  blockedReason?: string | null,
): string | null {
  switch (blockedReason) {
    case "backend_unreachable":
      return "LLM 백엔드 연결 불가";
    case "circuit_open":
      return "LLM 회로 차단";
    case "circuit_half_open":
      return "LLM 복구 탐침 중";
    default:
      return null;
  }
}

function isLlmDegraded(detail?: LlmGatewayHealthDetail | null): boolean {
  if (!detail) return false;
  return detail.degraded === true || detail.llmReady === false;
}

export const ConnectionStatusBanner: React.FC<Props> = ({
  connectionState,
  retryCount,
  llmGatewayDetail,
}) => {
  const llmDegraded = isLlmDegraded(llmGatewayDetail);

  if (connectionState === "connected" || connectionState === "disconnected") {
    if (!llmDegraded) return null;

    const blockedCopy = describeLlmBlockedReason(llmGatewayDetail?.blockedReason);
    const description = blockedCopy ?? "일부 기능이 제한될 수 있습니다";

    return (
      <div
        role="status"
        className={cn("connection-status-banner", "is-llm-degraded")}
      >
        <AlertTriangle size={16} className="connection-status-banner__icon" aria-hidden="true" />
        <div className="connection-status-banner__copy">
          <strong className="connection-status-banner__title">LLM 일부 준비 안 됨</strong>
          <span className="connection-status-banner__description">{description}</span>
        </div>
      </div>
    );
  }

  const isFailed = connectionState === "failed";
  const title = isFailed ? "연결 실패" : "연결 끊김";
  const description = isFailed
    ? "새로고침 필요"
    : `재연결 중...${retryCount != null ? ` (시도 ${retryCount})` : ""}`;

  return (
    <div
      role="status"
      className={cn(
        "connection-status-banner",
        isFailed ? "is-failed" : "is-reconnecting",
      )}
    >
      <WifiOff size={16} className="connection-status-banner__icon" aria-hidden="true" />
      <div className="connection-status-banner__copy">
        <strong className="connection-status-banner__title">{title}</strong>
        <span className="connection-status-banner__description">{description}</span>
      </div>
      {isFailed ? (
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="btn btn-outline btn-sm connection-status-banner__action"
        >
          새로고침
        </button>
      ) : null}
    </div>
  );
};
