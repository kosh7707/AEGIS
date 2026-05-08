import { Router } from "express";
import type { LlmTaskClient } from "../services/llm-task-client";
import type { AdapterManager } from "../services/adapter-manager";
import type { AgentClient } from "../services/agent-client";
import type { SastClient } from "../services/sast-client";
import type { KbClient } from "../services/kb-client";
import type { BuildAgentClient } from "../services/build-agent-client";
import { asyncHandler } from "../middleware/async-handler";
import { toDownstreamServiceHealth } from "../lib/downstream-health";
import type { DownstreamControlSummary } from "../lib/downstream-health";

type ServiceStatus = "ok" | "degraded" | "unreachable";
type OverallStatus = "ok" | "degraded" | "unhealthy";

interface ServiceHealth {
  status: ServiceStatus;
  detail?: Record<string, unknown>;
  control?: DownstreamControlSummary;
}

export function createHealthRouter(
  llmClient: LlmTaskClient,
  adapterManager: AdapterManager,
  agentClient?: AgentClient,
  sastClient?: SastClient,
  kbClient?: KbClient,
  buildAgentClient?: BuildAgentClient,
): Router {
  const router = Router();
  const startedAt = Date.now();

  router.get("/", asyncHandler(async (req, res) => {
    const requestedRequestId = typeof req.query.requestId === "string" && req.query.requestId.trim().length > 0
      ? req.query.requestId.trim()
      : undefined;
    const [llmHealth, agentHealth, sastHealth, kbHealth, buildAgentHealth] = await Promise.all([
      llmClient.checkHealth(requestedRequestId).catch(() => null),
      agentClient?.checkHealth(requestedRequestId).catch(() => null) ?? null,
      sastClient?.checkHealth(requestedRequestId).catch(() => null) ?? null,
      kbClient?.checkHealth(requestedRequestId).catch(() => null) ?? null,
      buildAgentClient?.checkHealth(requestedRequestId).catch(() => null) ?? null,
    ]);

    const adapters = adapterManager.findAll();
    const connectedCount = adapters.filter((a) => a.connected).length;

    const services: Record<string, ServiceHealth> = {
      llmGateway: toServiceHealth(llmHealth),
      analysisAgent: toServiceHealth(agentHealth),
      sastRunner: toServiceHealth(sastHealth),
      knowledgeBase: toServiceHealth(kbHealth),
      buildAgent: toServiceHealth(buildAgentHealth),
    };

    // 종합 판정:
    // - 핵심 서비스(SAST, Agent) 모두 ok → "ok"
    // - 일부 unreachable → "degraded"
    // - 핵심 서비스(SAST + Agent) 모두 unreachable → "unhealthy"
    const coreServices = [services.sastRunner, services.analysisAgent];
    const allServices = Object.values(services);
    const coreDown = coreServices.every((s) => s.status === "unreachable");
    const anyIssue = allServices.some((s) => s.status !== "ok");

    let status: OverallStatus;
    if (coreDown) status = "unhealthy";
    else if (anyIssue) status = "degraded";
    else status = "ok";

    res.json({
      service: "aegis-core-service",
      status,
      version: "0.2.0",
      controlPolicyVersion: "health-control-signal-rollout-v2",
      ...(requestedRequestId ? { requestIdQueried: requestedRequestId } : {}),
      detail: {
        version: "0.2.0",
        uptime: Math.floor((Date.now() - startedAt) / 1000),
      },
      ...services,
      adapters: {
        total: adapters.length,
        connected: connectedCount,
      },
    });
  }));

  return router;
}

function toServiceHealth(data: Record<string, unknown> | null): ServiceHealth {
  return toDownstreamServiceHealth(data);
}
