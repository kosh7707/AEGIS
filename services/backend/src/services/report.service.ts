import type {
  AnalysisModule,
  Finding,
  FindingStatus,
  Severity,
  ModuleReport,
  ProjectReport,
  ReportSummary,
  FindingReportEntry,
  RunReportEntry,
} from "@aegis/shared";
import type { IEvidenceRefDAO, IAuditLogDAO } from "../dao/interfaces";
import { ProjectService } from "./project.service";
import { RunService } from "./run.service";
import { FindingService } from "./finding.service";
import { QualityGateService } from "./quality-gate.service";
import { ApprovalService } from "./approval.service";
import { isVisibleAnalysisArtifact } from "../lib/analysis-visibility";

const MODULE_KEY_MAP: Record<AnalysisModule, "static" | "dynamic" | "test" | "deep"> = {
  static_analysis: "static",
  dynamic_analysis: "dynamic",
  dynamic_testing: "test",
  deep_analysis: "deep",
};

const ALL_MODULES: AnalysisModule[] = [
  "static_analysis",
  "deep_analysis",
  "dynamic_analysis",
  "dynamic_testing",
];

interface ReportLookupContext {
  project: NonNullable<ReturnType<ProjectService["findById"]>>;
  allRuns: ReturnType<RunService["findByProjectId"]>;
  gateResults: ReturnType<QualityGateService["getByProjectId"]>;
  gateByRunId: Map<string, ReturnType<QualityGateService["getByRunId"]>>;
}

export interface ReportFilters {
  severity?: Severity[];
  status?: FindingStatus[];
  runId?: string;
  from?: string;
  to?: string;
}

export class ReportService {
  constructor(
    private evidenceRefDAO: IEvidenceRefDAO,
    private auditLogDAO: IAuditLogDAO,
    private projectService: ProjectService,
    private runService: RunService,
    private findingService: FindingService,
    private gateService: QualityGateService,
    private approvalService: ApprovalService,
  ) {}

  generateModuleReport(
    projectId: string,
    module: AnalysisModule,
    filters?: ReportFilters,
  ): ModuleReport | undefined {
    const project = this.projectService.findById(projectId);
    if (!project) return undefined;
    return this.buildModuleReport(module, filters, this.createLookupContext(project));
  }

  private buildModuleReport(
    module: AnalysisModule,
    filters: ReportFilters | undefined,
    context: ReportLookupContext,
  ): ModuleReport {
    const { project } = context;
    const findings = this.findingService.findByProjectId(project.id, {
      module,
      ...filters,
    }).filter((finding) => this.isAggregateVisibleFinding(finding));
    const evidenceMap = this.evidenceRefDAO.findByFindingIds(findings.map((f) => f.id));
    const findingEntries: FindingReportEntry[] = findings.map((f) => ({
      finding: f,
      evidenceRefs: evidenceMap.get(f.id) ?? [],
    }));

    // Collect unique runIds from findings
    const runIdSet = new Set(findings.map((f) => f.runId));
    const moduleRuns = context.allRuns.filter(
      (r) => r.module === module && runIdSet.has(r.id) && this.isAggregateVisibleRun(r),
    );
    const moduleRunIds = new Set(moduleRuns.map((r) => r.id));

    const runEntries: RunReportEntry[] = moduleRuns.map((run) => ({
      run,
      gate: context.gateByRunId.get(run.id),
    }));

    const gateResults = context.gateResults.filter((g) => moduleRunIds.has(g.runId));

    const summary = this.buildSummary(findings);

    return {
      meta: {
        generatedAt: new Date().toISOString(),
        projectId: project.id,
        projectName: project.name,
        module,
      },
      summary,
      runs: runEntries,
      findings: findingEntries,
      gateResults,
    };
  }

  generateProjectReport(projectId: string, filters?: ReportFilters): ProjectReport | undefined {
    const project = this.projectService.findById(projectId);
    if (!project) return undefined;
    const context = this.createLookupContext(project);

    const modules: ProjectReport["modules"] = {};
    const allSummaries: ReportSummary[] = [];

    for (const mod of ALL_MODULES) {
      const report = this.buildModuleReport(mod, filters, context);
      if (report && report.findings.length > 0) {
        modules[MODULE_KEY_MAP[mod]] = report;
        allSummaries.push(report.summary);
      }
    }

    const totalSummary = this.mergeSummaries(allSummaries);
    const approvals = this.approvalService
      .getByProjectId(projectId)
      .filter((approval) => this.isAggregateVisibleApproval(approval));

    // Collect audit logs from all findings + approvals, limit 100
    const findingIds = Object.values(modules)
      .filter((m): m is ModuleReport => m != null)
      .flatMap((m) => m.findings.map((f) => f.finding.id));
    const approvalIds = approvals.map((a) => a.id);
    const resourceIds = [...findingIds, ...approvalIds];

    const auditTrail = this.auditLogDAO.findByResourceIds(resourceIds, 100);

    return {
      generatedAt: new Date().toISOString(),
      projectId,
      projectName: project.name,
      modules,
      totalSummary,
      approvals,
      auditTrail,
    };
  }

  private buildSummary(
    findings: { severity: string; status: string; sourceType: string }[],
  ): ReportSummary {
    const bySeverity: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    const bySource: Record<string, number> = {};

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
      bySource[f.sourceType] = (bySource[f.sourceType] ?? 0) + 1;
    }

    return { totalFindings: findings.length, bySeverity, byStatus, bySource };
  }

  generateCustomReport(
    projectId: string,
    options: {
      filters?: ReportFilters;
      findingIds?: string[];
      includeSections?: { executiveSummary?: boolean; static?: boolean; dynamic?: boolean; test?: boolean; deep?: boolean; approvals?: boolean; auditTrail?: boolean };
      customization?: { executiveSummary?: string; companyName?: string; logoUrl?: string; language?: string; reportTitle?: string };
    },
  ): ProjectReport | undefined {
    const project = this.projectService.findById(projectId);
    if (!project) return undefined;
    const context = this.createLookupContext(project);

    const { filters, findingIds, includeSections, customization } = options;
    const include = includeSections ?? {};
    const modules: ProjectReport["modules"] = {};
    const allSummaries: ReportSummary[] = [];

    const moduleEntries: Array<{ key: "static" | "dynamic" | "test" | "deep"; mod: AnalysisModule }> = [
      { key: "static", mod: "static_analysis" },
      { key: "dynamic", mod: "dynamic_analysis" },
      { key: "test", mod: "dynamic_testing" },
      { key: "deep", mod: "deep_analysis" },
    ];

    for (const { key, mod } of moduleEntries) {
      if (include[key] === false) continue;
      const report = this.buildModuleReport(mod, filters, context);
      if (!report) continue;

      // findingIds 필터링
      if (findingIds) {
        const idSet = new Set(findingIds);
        report.findings = report.findings.filter((f) => idSet.has(f.finding.id));
        const filteredSummary = this.buildSummary(report.findings.map((f) => f.finding));
        (report as any).summary = filteredSummary;
      }

      if (report.findings.length > 0) {
        modules[key] = report;
        allSummaries.push(report.summary);
      }
    }

    const totalSummary = this.mergeSummaries(allSummaries);
    const approvals = include.approvals !== false
      ? this.approvalService.getByProjectId(projectId).filter((approval) => this.isAggregateVisibleApproval(approval))
      : [];
    let auditTrail: import("@aegis/shared").AuditLogEntry[] = [];
    if (include.auditTrail !== false) {
      const ids = Object.values(modules)
        .filter((m): m is ModuleReport => m != null)
        .flatMap((m) => m.findings.map((f) => f.finding.id));
      auditTrail = this.auditLogDAO.findByResourceIds([...ids, ...approvals.map((a) => a.id)], 100);
    }

    return {
      generatedAt: new Date().toISOString(),
      projectId,
      projectName: project.name,
      modules,
      totalSummary,
      approvals,
      auditTrail,
      customization,
    };
  }

  private createLookupContext(project: NonNullable<ReturnType<ProjectService["findById"]>>): ReportLookupContext {
    const allRuns = this.runService.findByProjectId(project.id);
    const gateResults = this.gateService.getByProjectId(project.id);
    return {
      project,
      allRuns,
      gateResults,
      gateByRunId: new Map(gateResults.map((gate) => [gate.runId, gate])),
    };
  }

  private mergeSummaries(summaries: ReportSummary[]): ReportSummary {
    const merged: ReportSummary = {
      totalFindings: 0,
      bySeverity: {},
      byStatus: {},
      bySource: {},
    };

    for (const s of summaries) {
      merged.totalFindings += s.totalFindings;
      for (const [k, v] of Object.entries(s.bySeverity))
        merged.bySeverity[k] = (merged.bySeverity[k] ?? 0) + v;
      for (const [k, v] of Object.entries(s.byStatus))
        merged.byStatus[k] = (merged.byStatus[k] ?? 0) + v;
      for (const [k, v] of Object.entries(s.bySource))
        merged.bySource[k] = (merged.bySource[k] ?? 0) + v;
    }

    return merged;
  }

  private isAggregateVisibleRun(run: RunReportEntry["run"]): boolean {
    return isVisibleAnalysisArtifact(run);
  }

  private isAggregateVisibleFinding(finding: Finding): boolean {
    return isVisibleAnalysisArtifact(finding);
  }

  private isAggregateVisibleApproval(approval: import("@aegis/shared").ApprovalRequest): boolean {
    if (approval.actionType === "gate.override") {
      return !!this.gateService.getById(approval.targetId);
    }
    if (approval.actionType === "finding.accepted_risk") {
      return !!this.findingService.findById(approval.targetId);
    }
    return true;
  }
}
