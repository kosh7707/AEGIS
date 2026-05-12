import { describe, expect, it, vi } from "vitest";
import type { Finding, GateResult, Project, Run } from "@aegis/shared";
import { ReportService } from "../report.service";
import type { IEvidenceRefDAO, IAuditLogDAO } from "../../dao/interfaces";
import type { ProjectService } from "../project.service";
import type { RunService } from "../run.service";
import type { FindingService } from "../finding.service";
import type { QualityGateService } from "../quality-gate.service";
import type { ApprovalService } from "../approval.service";

const now = "2026-05-11T00:00:00.000Z";

function finding(id: string, module: Finding["module"], runId: string): Finding {
  return {
    id,
    runId,
    projectId: "p-perf",
    module,
    ...(module === "static_analysis" || module === "deep_analysis"
      ? { buildTargetId: "bt-perf", analysisExecutionId: `exec-${runId}` }
      : {}),
    status: "open",
    severity: "high",
    confidence: "high",
    sourceType: "sast-tool",
    title: id,
    description: id,
    createdAt: now,
    updatedAt: now,
  };
}

function run(id: string, module: Run["module"]): Run {
  return {
    id,
    projectId: "p-perf",
    module,
    ...(module === "static_analysis" || module === "deep_analysis"
      ? { buildTargetId: "bt-perf", analysisExecutionId: `exec-${id}` }
      : {}),
    status: "completed",
    analysisResultId: `ar-${id}`,
    findingCount: 1,
    createdAt: now,
  };
}

function gate(id: string, runId: string): GateResult {
  return {
    id,
    runId,
    projectId: "p-perf",
    status: "pass",
    rules: [],
    profileId: "default",
    requestedBy: "system",
    evaluatedAt: now,
    createdAt: now,
  };
}

describe("ReportService aggregate performance guard", () => {
  it("reuses project/run/gate lookups across module slices while generating aggregate reports", () => {
    const project: Project = {
      id: "p-perf",
      name: "Perf Project",
      description: "",
      createdAt: now,
      updatedAt: now,
    };
    const runs = [
      run("run-static", "static_analysis"),
      run("run-deep", "deep_analysis"),
      run("run-dynamic", "dynamic_analysis"),
      run("run-test", "dynamic_testing"),
    ];
    const findings = [
      finding("finding-static", "static_analysis", "run-static"),
      finding("finding-deep", "deep_analysis", "run-deep"),
      finding("finding-dynamic", "dynamic_analysis", "run-dynamic"),
      finding("finding-test", "dynamic_testing", "run-test"),
    ];
    const gates = runs.map((r) => gate(`gate-${r.id}`, r.id));

    const evidenceRefDAO = {
      findByFindingIds: vi.fn(() => new Map()),
    } as unknown as IEvidenceRefDAO;
    const auditLogDAO = {
      findByResourceIds: vi.fn(() => []),
    } as unknown as IAuditLogDAO;
    const projectService = {
      findById: vi.fn(() => project),
    } as unknown as ProjectService;
    const runService = {
      findByProjectId: vi.fn(() => runs),
    } as unknown as RunService;
    const findingService = {
      findByProjectId: vi.fn((_projectId: string, filters?: { module?: Finding["module"] }) =>
        findings.filter((f) => !filters?.module || f.module === filters.module),
      ),
    } as unknown as FindingService;
    const gateService = {
      getByRunId: vi.fn((runId: string) => gates.find((g) => g.runId === runId)),
      getByProjectId: vi.fn(() => gates),
      getById: vi.fn(),
    } as unknown as QualityGateService;
    const approvalService = {
      getByProjectId: vi.fn(() => []),
    } as unknown as ApprovalService;

    const service = new ReportService(
      evidenceRefDAO,
      auditLogDAO,
      projectService,
      runService,
      findingService,
      gateService,
      approvalService,
    );

    const report = service.generateProjectReport("p-perf");

    expect(report?.totalSummary.totalFindings).toBe(4);
    expect(Object.keys(report?.modules ?? {}).sort()).toEqual(["deep", "dynamic", "static", "test"]);

    expect(projectService.findById).toHaveBeenCalledTimes(1);
    expect(runService.findByProjectId).toHaveBeenCalledTimes(1);
    expect(gateService.getByProjectId).toHaveBeenCalledTimes(1);
    expect(gateService.getByRunId).not.toHaveBeenCalled();
  });
});
