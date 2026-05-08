import crypto from "crypto";
import type {
  Finding,
  FindingStatus,
  EvidenceRef,
  AuditLogEntry,
  Severity,
  AnalysisModule,
  FindingsSummary,
} from "@aegis/shared";
import type { IFindingDAO, IEvidenceRefDAO, IAuditLogDAO } from "../dao/interfaces";
import { InvalidInputError, NotFoundError } from "../lib/errors";
import { createLogger } from "../lib/logger";
import { isVisibleAnalysisArtifact } from "../lib/analysis-visibility";

const logger = createLogger("finding-service");

// 상태 전이 규칙
// 유연 워크플로우: 분석가가 직접 분류 가능. sandbox→sandbox 제외 (시스템 전용).
const VALID_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  open: ["needs_review", "accepted_risk", "false_positive", "fixed"],
  sandbox: ["needs_review", "open", "false_positive"],
  needs_review: ["accepted_risk", "false_positive", "fixed", "open"],
  accepted_risk: ["needs_review", "open"],
  false_positive: ["needs_review", "open"],
  fixed: ["needs_revalidation", "open"],
  needs_revalidation: ["open", "fixed", "false_positive"],
};

export class FindingService {
  constructor(
    private findingDAO: IFindingDAO,
    private evidenceRefDAO: IEvidenceRefDAO,
    private auditLogDAO: IAuditLogDAO,
  ) {}

  findById(id: string): (Finding & { evidenceRefs: EvidenceRef[]; auditLog: AuditLogEntry[] }) | undefined {
    const finding = this.findingDAO.findById(id);
    if (!finding || !isVisibleAnalysisArtifact(finding)) return undefined;

    const evidenceRefs = this.evidenceRefDAO.findByFindingId(id);
    const auditLog = this.auditLogDAO.findByResourceId(id);
    return { ...finding, evidenceRefs, auditLog };
  }

  findByProjectId(
    projectId: string,
    filters?: import("../dao/interfaces").FindingFilters,
  ): Finding[] {
    return this.findingDAO.findByProjectId(projectId, filters).filter((finding) => isVisibleAnalysisArtifact(finding));
  }

  findByRunId(runId: string): Finding[] {
    return this.findingDAO.findByRunId(runId);
  }

  updateStatus(
    findingId: string,
    newStatus: FindingStatus,
    actor: string,
    reason: string,
    requestId?: string
  ): Finding {
    const finding = this.findingDAO.findById(findingId);
    if (!finding || !isVisibleAnalysisArtifact(finding)) throw new NotFoundError("Finding not found");

    const allowed = VALID_TRANSITIONS[finding.status];
    if (!allowed || !allowed.includes(newStatus)) {
      throw new InvalidInputError(
        `Invalid status transition: ${finding.status} → ${newStatus}. Allowed: ${allowed?.join(", ") ?? "none"}`
      );
    }

    this.findingDAO.updateStatus(findingId, newStatus);

    // audit log 기록
    const logEntry: AuditLogEntry = {
      id: `audit-${crypto.randomUUID()}`,
      timestamp: new Date().toISOString(),
      actor,
      action: "finding.status_change",
      resource: "finding",
      resourceId: findingId,
      detail: {
        from: finding.status,
        to: newStatus,
        reason,
      },
      requestId,
    };
    this.auditLogDAO.save(logEntry);

    logger.info({
      findingId,
      from: finding.status,
      to: newStatus,
      actor,
      requestId,
    }, "Finding status updated");

    return { ...finding, status: newStatus, updatedAt: new Date().toISOString() };
  }

  bulkUpdateStatus(
    findingIds: string[],
    newStatus: FindingStatus,
    actor: string,
    reason: string,
    requestId?: string,
  ): { updated: number; failed: number } {
    let updated = 0;
    let failed = 0;

    this.findingDAO.withTransaction(() => {
      const findings = this.findingDAO.findByIds(findingIds);
      const findingMap = new Map(
        findings
          .filter((finding) => isVisibleAnalysisArtifact(finding))
          .map((f) => [f.id, f]),
      );

      for (const id of findingIds) {
        const finding = findingMap.get(id);
        if (!finding) { failed++; continue; }

        const allowed = VALID_TRANSITIONS[finding.status];
        if (!allowed || !allowed.includes(newStatus)) { failed++; continue; }

        this.findingDAO.updateStatus(id, newStatus);
        this.auditLogDAO.save({
          id: `audit-${crypto.randomUUID()}`,
          timestamp: new Date().toISOString(),
          actor,
          action: "finding.status_change",
          resource: "finding",
          resourceId: id,
          detail: { from: finding.status, to: newStatus, reason, bulk: true },
          requestId,
        });
        updated++;
      }
    });

    logger.info({ updated, failed, newStatus, actor, requestId }, "Bulk status update completed");
    return { updated, failed };
  }

  getHistory(findingId: string): Array<{ findingId: string; runId: string; status: FindingStatus; createdAt: string }> | undefined {
    const finding = this.findingDAO.findById(findingId);
    if (!finding || !isVisibleAnalysisArtifact(finding)) return undefined;
    if (!finding.fingerprint) return [];

    const siblings = this.findingDAO
      .findAllByFingerprint(finding.projectId, finding.fingerprint)
      .filter((sibling) => isVisibleAnalysisArtifact(sibling));
    return siblings.map((f) => ({
      findingId: f.id,
      runId: f.runId,
      status: f.status,
      createdAt: f.createdAt,
    }));
  }

  getSummary(projectId: string): FindingsSummary {
    const findings = this.findByProjectId(projectId);
    const byStatus: Partial<Record<FindingStatus, number>> = {};
    const bySeverity: Partial<Record<Severity, number>> = {};

    for (const finding of findings) {
      byStatus[finding.status] = (byStatus[finding.status] ?? 0) + 1;
      bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
    }

    return { byStatus, bySeverity, total: findings.length };
  }

  getGroups(projectId: string, groupBy: "ruleId" | "location"): Array<{ key: string; count: number; topSeverity: string; findingIds: string[] }> {
    const severityOrder: Record<Finding["severity"], number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1,
    };

    const grouped = new Map<string, { count: number; topSeverity: Finding["severity"]; findingIds: string[] }>();
    for (const finding of this.findByProjectId(projectId)) {
      const key = groupBy === "ruleId" ? finding.ruleId : finding.location;
      if (!key) continue;

      const existing = grouped.get(key);
      if (existing) {
        existing.count += 1;
        existing.findingIds.push(finding.id);
        if (severityOrder[finding.severity] > severityOrder[existing.topSeverity]) {
          existing.topSeverity = finding.severity;
        }
      } else {
        grouped.set(key, {
          count: 1,
          topSeverity: finding.severity,
          findingIds: [finding.id],
        });
      }
    }

    return [...grouped.entries()]
      .map(([key, value]) => ({ key, ...value }))
      .sort((a, b) => b.count - a.count);
  }
}
