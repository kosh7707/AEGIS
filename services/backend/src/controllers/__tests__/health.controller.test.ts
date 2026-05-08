import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createHealthRouter } from "../health.controller";

describe("health.controller", () => {
  it("treats S4 policy degradation as degraded service health", async () => {
    const app = express();
    app.use(createHealthRouter(
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { findAll: vi.fn().mockReturnValue([]) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok", policyStatus: "failed", policyReasons: ["runtime-tool-missing"] }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
    ));

    const res = await request(app).get("/");

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("degraded");
    expect(res.body.sastRunner.status).toBe("degraded");
    expect(res.body.sastRunner.detail.policyStatus).toBe("failed");
  });

  it("passes requestId to downstream health checks and exposes continue-waiting control summary", async () => {
    const llmHealth = { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any;
    const agentHealth = {
      checkHealth: vi.fn().mockResolvedValue({
        status: "ok",
        activeRequestCount: 1,
        requestSummary: {
          requestId: "req-deep-001",
          endpoint: "tasks",
          state: "running",
          localAckState: "transport-only",
          degraded: true,
          degradeReasons: ["llm-inference"],
          lastAckAt: 1776081000000,
          lastAckSource: "llm-inference",
          blockedReason: null,
        },
      }),
    } as any;
    const app = express();
    app.use(createHealthRouter(
      llmHealth,
      { findAll: vi.fn().mockReturnValue([]) } as any,
      agentHealth,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
    ));

    const res = await request(app).get("/?requestId=req-deep-001");

    expect(res.status).toBe(200);
    expect(agentHealth.checkHealth).toHaveBeenCalledWith("req-deep-001");
    expect(llmHealth.checkHealth).toHaveBeenCalledWith("req-deep-001");
    expect(res.body.controlPolicyVersion).toBe("health-control-signal-rollout-v2");
    expect(res.body.requestIdQueried).toBe("req-deep-001");
    expect(res.body.analysisAgent.control).toMatchObject({
      requestId: "req-deep-001",
      endpoint: "tasks",
      state: "running",
      localAckState: "transport-only",
      degraded: true,
      pollDecision: "continue_waiting",
    });
  });

  it("maps legacy ackStatus=broken into chain_abort", async () => {
    const app = express();
    app.use(createHealthRouter(
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { findAll: vi.fn().mockReturnValue([]) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({
        status: "ok",
        requestSummary: {
          requestId: "req-scan-123",
          endpoint: "scan",
          state: "failed",
          ackStatus: "broken",
          blockedReason: "tool-process-crashed",
          degraded: true,
          degradeReasons: ["tool-failure"],
        },
      }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
      { checkHealth: vi.fn().mockResolvedValue({ status: "ok" }) } as any,
    ));

    const res = await request(app).get("/");

    expect(res.status).toBe(200);
    expect(res.body.sastRunner.status).toBe("degraded");
    expect(res.body.sastRunner.control).toMatchObject({
      requestId: "req-scan-123",
      state: "failed",
      localAckState: "ack-break",
      blockedReason: "tool-process-crashed",
      pollDecision: "chain_abort",
    });
  });
});
