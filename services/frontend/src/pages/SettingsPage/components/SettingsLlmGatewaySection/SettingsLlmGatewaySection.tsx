import "./SettingsLlmGatewaySection.css";
import React from "react";
import { cn } from "@/common/utils/cn";
import type { LlmGatewayHealthEntry } from "@/common/api/core";
import { describeLlmBlockedReason } from "@/common/ui/primitives/ConnectionStatusBanner";

/**
 * SettingsPage LLM Gateway health row.
 *
 * Renders S2 `/health` `llmGateway` aggregate status. When the forwarded S7
 * readiness detail indicates partial unreadiness
 * (`detail.degraded === true` OR `detail.llmReady === false`), shows a
 * caution-review sub-caption with the mapped Korean copy for `blockedReason`.
 *
 * Source contract: WR
 * `s2-to-s1-reply-s2-health-forwards-s7-readiness-fields-under-llmgateway.detail`.
 *
 * Display-only — caller owns fetch/polling. Pass `null`/`undefined` to render
 * an idle row (no health data yet).
 */
export interface SettingsLlmGatewaySectionProps {
  llmGateway?: LlmGatewayHealthEntry | null;
}

function getStatusLabel(entry?: LlmGatewayHealthEntry | null): string {
  if (!entry) return "Idle";
  if (entry.status === "ok") return "OK";
  if (entry.status === "degraded") return "Degraded";
  if (entry.status === "unreachable") return "Unreachable";
  return entry.status;
}

function getStatusDotClass(entry?: LlmGatewayHealthEntry | null): string {
  if (!entry) return "settings-kv__dot--idle";
  if (entry.status === "ok") return "settings-kv__dot--ok";
  if (entry.status === "unreachable") return "settings-kv__dot--error";
  // "degraded" — review-tone caution surface, expressed via dedicated dot class
  if (entry.status === "degraded") return "settings-kv__dot--caution";
  return "settings-kv__dot--idle";
}

function isLlmDegraded(entry?: LlmGatewayHealthEntry | null): boolean {
  const detail = entry?.detail;
  if (!detail) return false;
  return detail.degraded === true || detail.llmReady === false;
}

export function SettingsLlmGatewaySection({ llmGateway }: SettingsLlmGatewaySectionProps) {
  const degraded = isLlmDegraded(llmGateway);
  const blockedCopy = degraded
    ? describeLlmBlockedReason(llmGateway?.detail?.blockedReason)
    : null;
  const subCaption = degraded
    ? blockedCopy ?? "LLM 일부 준비 안 됨"
    : null;

  return (
    <div className="settings-kv">
      <div className="settings-kv__row">
        <span className="settings-kv__key">LLM Gateway</span>
        <span className="settings-kv__value">
          <span
            className={cn("settings-kv__dot", getStatusDotClass(llmGateway))}
            aria-hidden="true"
          />
          <span className="settings-kv__value--mono">{getStatusLabel(llmGateway)}</span>
          {subCaption ? (
            <span
              className="settings-llm-gateway__sub"
              data-testid="settings-llm-gateway-sub"
            >
              {subCaption}
            </span>
          ) : null}
        </span>
      </div>
    </div>
  );
}
