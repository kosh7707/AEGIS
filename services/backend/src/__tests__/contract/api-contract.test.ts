import { describe, it, expect, beforeEach, afterEach } from "vitest";
import request from "supertest";
import type { Database as DatabaseType } from "better-sqlite3";
import type express from "express";
import fs from "fs";
import path from "path";
import { createTestApp, type TestAppContext } from "../../test/create-test-app";
import {
  makeProject,
  makeRun,
  makeFinding,
  makeEvidenceRef,
  makeGateResult,
  makeApproval,
  makeAuditLog,
  makeAnalysisResult,
  makeStoredFile,
  makeBuildTarget,
  makeNotification,
  makeDynamicSession,
} from "../../test/factories";

describe("API Contract Tests", () => {
  let ctx: TestAppContext;
  let app: express.Express;

  beforeEach(() => {
    ctx = createTestApp();
    app = ctx.app;
  });
  afterEach(() => {
    ctx.db.close();
  });

  // ── Projects ──

  describe("GET /api/projects", () => {
    it("returns { success, data: Project[] }", async () => {
      ctx.projectDAO.save(makeProject({ id: "p1", name: "A" }));
      ctx.projectDAO.save(makeProject({ id: "p2", name: "B" }));

      const res = await request(app).get("/api/projects");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(2);

      const proj = res.body.data[0];
      expect(proj).toHaveProperty("id");
      expect(proj).toHaveProperty("name");
      expect(proj).toHaveProperty("description");
      expect(proj).toHaveProperty("createdAt");
      expect(proj).toHaveProperty("updatedAt");
    });

    it("omits owner for migrated rows without owner data and returns creator profile for authenticated-created rows", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-owner-legacy", name: "Legacy" }));
      ctx.userService.createUser("owner01", "Pass1234!", "김보안", "analyst", { email: "owner01@example.com" });
      const login = ctx.userService.authenticate("owner01", "Pass1234!");

      const createRes = await request(app)
        .post("/api/projects")
        .set("Authorization", `Bearer ${login.token}`)
        .send({ name: "Owned Project", description: "owned" });
      expect(createRes.status).toBe(201);
      expect(createRes.body.data.owner).toEqual({
        id: login.user.id,
        name: "김보안",
        avatar: "김보",
        kind: "user",
      });

      const res = await request(app).get("/api/projects");
      expect(res.status).toBe(200);
      const legacy = res.body.data.find((project: any) => project.id === "p-owner-legacy");
      const owned = res.body.data.find((project: any) => project.name === "Owned Project");
      expect(legacy).not.toHaveProperty("owner");
      expect(owned.owner).toEqual({
        id: login.user.id,
        name: "김보안",
        avatar: "김보",
        kind: "user",
      });
    });

    it("aggregates only BuildTarget-owned analysis records in project summaries", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-agg", name: "Aggregate Project" }));

      ctx.runDAO.save(makeRun({
        id: "run-modern",
        projectId: "p-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
        findingCount: 2,
        endedAt: "2026-03-26T10:00:00Z",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-modern-critical",
        runId: "run-modern",
        projectId: "p-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
        severity: "critical",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-modern-high",
        runId: "run-modern",
        projectId: "p-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
        severity: "high",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-modern", runId: "run-modern", projectId: "p-agg", status: "fail" }));

      ctx.runDAO.save(makeRun({
        id: "run-legacy",
        projectId: "p-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        module: "static_analysis",
        findingCount: 99,
        endedAt: "2026-03-26T09:00:00Z",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-legacy",
        runId: "run-legacy",
        projectId: "p-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        module: "static_analysis",
        severity: "critical",
      }));

      const res = await request(app).get("/api/projects");

      expect(res.status).toBe(200);
      const aggregate = res.body.data.find((project: any) => project.id === "p-agg");
      expect(aggregate).toMatchObject({
        id: "p-agg",
        lastAnalysisAt: "2026-03-26T10:00:00Z",
        gateStatus: "fail",
        severitySummary: { critical: 1, high: 1, medium: 0, low: 0 },
      });
    });
  });

  describe("POST /api/projects", () => {
    it("creates project and returns { success, data: Project }", async () => {
      const res = await request(app)
        .post("/api/projects")
        .send({ name: "New Project", description: "test" });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty("id");
      expect(res.body.data.name).toBe("New Project");
    });
  });

  describe("PUT /api/projects/:id", () => {
    it("updates project metadata and returns Project", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-update", name: "Old", description: "before" }));

      const res = await request(app)
        .put("/api/projects/p-update")
        .send({ name: "New", description: "after" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        id: "p-update",
        name: "New",
        description: "after",
      });
    });

    it("rejects blank project names", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-update-invalid", name: "Old" }));

      const res = await request(app)
        .put("/api/projects/p-update-invalid")
        .send({ name: "   " });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ success: false, error: "name is required" });
    });
  });

  describe("DELETE /api/projects/:id", () => {
    it("deletes the project and returns { success: true }", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-delete", name: "Delete Me" }));

      const res = await request(app).delete("/api/projects/p-delete");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });

      const missing = await request(app).get("/api/projects/p-delete");
      expect(missing.status).toBe(404);
    });

    it("returns 409 with blocker details when active work exists", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-delete-blocked", name: "Blocked" }));
      ctx.analysisTracker.start("analysis-delete-blocked", "p-delete-blocked");

      const res = await request(app).delete("/api/projects/p-delete-blocked");

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.errorDetail.code).toBe("CONFLICT");
      expect(res.body.errorDetail.blockers).toMatchObject({
        activeAnalysis: { analysisId: "analysis-delete-blocked" },
      });
    });

    it("removes uploads root and representative project rows on success", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-delete-clean", name: "Delete Clean" }));
      ctx.fileStore.save(makeStoredFile({ id: "f-delete-clean", projectId: "p-delete-clean", name: "main.c" }));
      ctx.analysisResultDAO.save(makeAnalysisResult({ id: "analysis-delete-clean", projectId: "p-delete-clean" }));
      ctx.dynamicSessionDAO.save(makeDynamicSession({ id: "dyn-delete-clean", projectId: "p-delete-clean", status: "stopped" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t-delete-clean", projectId: "p-delete-clean", status: "ready" }));

      const projectRoot = path.join(ctx.projectUploadsRoot, "p-delete-clean");
      fs.mkdirSync(path.join(projectRoot, "sdk", "sdk-1"), { recursive: true });
      fs.writeFileSync(path.join(projectRoot, "main.c"), "int main() {}");

      const res = await request(app).delete("/api/projects/p-delete-clean");

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
      expect(fs.existsSync(projectRoot)).toBe(false);
      expect(ctx.projectDAO.findById("p-delete-clean")).toBeUndefined();
      expect(ctx.fileStore.findByProjectId("p-delete-clean")).toHaveLength(0);
      expect(ctx.analysisResultDAO.findByProjectId("p-delete-clean")).toHaveLength(0);
      expect(ctx.dynamicSessionDAO.findByProjectId("p-delete-clean")).toHaveLength(0);
      expect(ctx.buildTargetDAO.findByProjectId("p-delete-clean")).toHaveLength(0);
    });
  });

  describe("GET /api/projects/:id", () => {
    it("returns { success, data: Project }", async () => {
      ctx.projectDAO.save(makeProject({ id: "p1", name: "Test" }));

      const res = await request(app).get("/api/projects/p1");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe("p1");
    });

    it("returns 404 for nonexistent project", async () => {
      const res = await request(app).get("/api/projects/nonexistent");
      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });
  });

  describe("GET /api/projects/:id/overview", () => {
    it("returns raw ProjectOverviewResponse without the success envelope", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-overview", name: "Overview" }));

      const res = await request(app).get("/api/projects/p-overview/overview");
      expect(res.status).toBe(200);
      expect(res.body.success).toBeUndefined();
      expect(res.body).toHaveProperty("project");
      expect(res.body.project.id).toBe("p-overview");
    });

    it("excludes legacy project-owned static analysis rows from aggregate overview semantics", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-overview-agg", name: "Overview Aggregate" }));
      ctx.analysisResultDAO.save(makeAnalysisResult({
        id: "analysis-modern",
        projectId: "p-overview-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
        summary: { total: 3, critical: 1, high: 1, medium: 1, low: 0, info: 0 },
      }));
      ctx.analysisResultDAO.save(makeAnalysisResult({
        id: "analysis-legacy",
        projectId: "p-overview-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        module: "static_analysis",
        summary: { total: 99, critical: 99, high: 0, medium: 0, low: 0, info: 0 },
      }));

      const res = await request(app).get("/api/projects/p-overview-agg/overview");

      expect(res.status).toBe(200);
      expect(res.body.summary.totalVulnerabilities).toBe(3);
      expect(res.body.summary.bySeverity).toMatchObject({
        total: 3,
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
        info: 0,
      });
      expect(res.body.recentAnalyses).toHaveLength(1);
      expect(res.body.recentAnalyses[0].id).toBe("analysis-modern");
    });
  });

  // ── Files ──

  describe("GET /api/projects/:pid/files", () => {
    it("returns { success, data: UploadedFile[] }", async () => {
      ctx.projectDAO.save(makeProject({ id: "p1" }));
      ctx.fileStore.save(makeStoredFile({ id: "f1", projectId: "p1", name: "main.c" }));

      const res = await request(app).get("/api/projects/p1/files");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0]).toHaveProperty("id");
      expect(res.body.data[0]).toHaveProperty("name");
      expect(res.body.data[0]).toHaveProperty("size");
    });
  });

  describe("GET /api/files/:fileId/content", () => {
    it("returns JSON file content payload", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-file-content" }));
      ctx.fileStore.save(makeStoredFile({
        id: "f-content",
        projectId: "p-file-content",
        name: "main.c",
        path: "src/main.c",
        language: "c",
        content: "int main(void) { return 0; }",
      }));

      const res = await request(app).get("/api/files/f-content/content");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        id: "f-content",
        name: "main.c",
        path: "src/main.c",
        language: "c",
        content: "int main(void) { return 0; }",
      });
    });
  });

  describe("GET /api/files/:fileId/download", () => {
    it("returns raw text/plain file content", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-file-download" }));
      ctx.fileStore.save(makeStoredFile({
        id: "f-download",
        projectId: "p-file-download",
        name: "README.md",
        content: "hello download",
      }));

      const res = await request(app).get("/api/files/f-download/download");
      expect(res.status).toBe(200);
      expect(res.headers["content-type"]).toContain("text/plain");
      expect(res.text).toBe("hello download");
    });
  });

  describe("DELETE /api/projects/:projectId/files/:fileId", () => {
    it("deletes the project file and returns { success: true }", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-file-delete" }));
      ctx.fileStore.save(makeStoredFile({ id: "f-delete", projectId: "p-file-delete", name: "old.c" }));

      const res = await request(app).delete("/api/projects/p-file-delete/files/f-delete");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });

      const missing = await request(app).get("/api/files/f-delete/content");
      expect(missing.status).toBe(404);
    });
  });

  // ── Runs ──

  describe("GET /api/projects/:pid/runs", () => {
    it("returns { success, data: Run[] }", async () => {
      ctx.projectDAO.save(makeProject({ id: "p1" }));
      ctx.runDAO.save(makeRun({ id: "run-1", projectId: "p1" }));

      const res = await request(app).get("/api/projects/p1/runs");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);

      if (res.body.data.length > 0) {
        const run = res.body.data[0];
        expect(run).toHaveProperty("id");
        expect(run).toHaveProperty("projectId");
        expect(run).toHaveProperty("module");
        expect(run).toHaveProperty("status");
        expect(run).toHaveProperty("findingCount");
      }
    });

    it("filters legacy static/deep runs without full BuildTarget execution lineage", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-run-agg" }));
      ctx.runDAO.save(makeRun({
        id: "run-modern",
        projectId: "p-run-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.runDAO.save(makeRun({
        id: "run-legacy",
        projectId: "p-run-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));

      const res = await request(app).get("/api/projects/p-run-agg/runs");
      expect(res.status).toBe(200);
      expect(res.body.data.map((run: any) => run.id)).toEqual(["run-modern"]);
    });
  });

  describe("GET /api/runs/:id", () => {
    it("returns run detail with gate and findings", async () => {
      ctx.runDAO.save(makeRun({ id: "run-1", projectId: "p1" }));
      ctx.findingDAO.save(makeFinding({ id: "f1", runId: "run-1", projectId: "p1" }));

      const res = await request(app).get("/api/runs/run-1");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty("run");
      expect(res.body.data.run.id).toBe("run-1");
      expect(res.body.data).toHaveProperty("findings");
      expect(Array.isArray(res.body.data.findings)).toBe(true);
    });

    it("returns 404 for nonexistent run", async () => {
      const res = await request(app).get("/api/runs/nonexistent");
      expect(res.status).toBe(404);
    });
  });

  // ── Findings ──

  describe("GET /api/projects/:pid/findings", () => {
    it("returns { success, data: Finding[] }", async () => {
      ctx.findingDAO.save(makeFinding({ id: "f1", projectId: "p1", severity: "high", status: "open" }));

      const res = await request(app).get("/api/projects/p1/findings");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);

      if (res.body.data.length > 0) {
        const finding = res.body.data[0];
        expect(finding).toHaveProperty("id");
        expect(finding).toHaveProperty("severity");
        expect(finding).toHaveProperty("status");
        expect(finding).toHaveProperty("title");
        expect(finding).toHaveProperty("sourceType");
      }
    });

    it("filters legacy static/deep findings without full BuildTarget execution lineage", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "finding-modern",
        projectId: "p-find-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-legacy",
        projectId: "p-find-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));

      const res = await request(app).get("/api/projects/p-find-agg/findings");
      expect(res.status).toBe(200);
      expect(res.body.data.map((finding: any) => finding.id)).toEqual(["finding-modern"]);
    });
  });

  describe("GET /api/findings/:id", () => {
    it("returns finding with evidenceRefs and auditLog", async () => {
      const finding = makeFinding({ id: "f1", projectId: "p1" });
      ctx.findingDAO.save(finding);
      ctx.evidenceRefDAO.save(makeEvidenceRef({ findingId: "f1" }));

      const res = await request(app).get("/api/findings/f1");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty("id", "f1");
      expect(res.body.data).toHaveProperty("evidenceRefs");
      expect(res.body.data).toHaveProperty("auditLog");
      expect(Array.isArray(res.body.data.evidenceRefs)).toBe(true);
    });

    it("returns 404 for nonexistent finding", async () => {
      const res = await request(app).get("/api/findings/nonexistent");
      expect(res.status).toBe(404);
    });
  });

  describe("PATCH /api/findings/:id/status", () => {
    it("updates finding status and returns updated finding", async () => {
      ctx.findingDAO.save(makeFinding({ id: "f1", projectId: "p1", status: "open" }));

      const res = await request(app)
        .patch("/api/findings/f1/status")
        .send({ status: "needs_review", actor: "analyst", reason: "review needed" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe("needs_review");
    });

    it("returns 400 for invalid transition", async () => {
      ctx.findingDAO.save(makeFinding({ id: "f1", projectId: "p1", status: "open" }));

      const res = await request(app)
        .patch("/api/findings/f1/status")
        .send({ status: "sandbox", actor: "analyst", reason: "bad transition" });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Quality Gates ──

  describe("GET /api/projects/:pid/gates", () => {
    it("returns { success, data: GateResult[] }", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-1",
        projectId: "p1",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "g1",
        projectId: "p1",
        runId: "run-1",
        profileId: "prod-strict-v3",
        commit: "f8a1c3d",
        branch: "main",
        requestedBy: "김민지",
        rules: [{
          ruleId: "high-threshold",
          result: "warning",
          message: "활성 high finding 9건 — 임계치 이내",
          linkedFindingIds: [],
          current: 9,
          threshold: 10,
          unit: "count",
          meta: { current: 9, threshold: 10, unit: "count" },
        }],
      }));

      const res = await request(app).get("/api/projects/p1/gates");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);

      if (res.body.data.length > 0) {
        const gate = res.body.data[0];
        expect(gate).toHaveProperty("id");
        expect(gate).toHaveProperty("status");
        expect(gate).toHaveProperty("rules");
        expect(gate).toMatchObject({
          profileId: "prod-strict-v3",
          commit: "f8a1c3d",
          branch: "main",
          requestedBy: "김민지",
        });
        expect(gate.rules[0]).toMatchObject({ current: 9, threshold: 10, unit: "count" });
        expect(gate).toHaveProperty("evaluatedAt");
      }
    });

    it("filters legacy static/deep gate results whose runs lack BuildTarget execution lineage", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-gate-agg" }));
      ctx.runDAO.save(makeRun({
        id: "run-gate-modern",
        projectId: "p-gate-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "gate-modern",
        projectId: "p-gate-agg",
        runId: "run-gate-modern",
      }));
      ctx.runDAO.save(makeRun({
        id: "run-gate-legacy",
        projectId: "p-gate-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "gate-legacy",
        projectId: "p-gate-agg",
        runId: "run-gate-legacy",
      }));

      const res = await request(app).get("/api/projects/p-gate-agg/gates");
      expect(res.status).toBe(200);
      expect(res.body.data.map((gate: any) => gate.id)).toEqual(["gate-modern"]);
    });
  });

  describe("GET /api/gates/:id", () => {
    it("returns gate result detail", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-1",
        projectId: "p1",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "g1", runId: "run-1", projectId: "p1" }));

      const res = await request(app).get("/api/gates/g1");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe("g1");
      expect(res.body.data).toHaveProperty("status");
      expect(res.body.data).toHaveProperty("rules");
    });

    it("returns 404 for nonexistent gate", async () => {
      const res = await request(app).get("/api/gates/nonexistent");
      expect(res.status).toBe(404);
    });
  });

  // ── Approvals ──

  describe("GET /api/projects/:pid/approvals", () => {
    it("returns { success, data: ApprovalRequest[] }", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-ap-1",
        projectId: "p1",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-ap-1", projectId: "p1", runId: "run-ap-1" }));
      ctx.approvalDAO.save(makeApproval({
        id: "ap-1",
        projectId: "p1",
        targetId: "gate-ap-1",
        impactSummary: { failedRules: 1, ignoredFindings: 3, severityBreakdown: { critical: 1, high: 2 } },
        targetSnapshot: { runId: "run-ap-1", commit: "f8a1c3d", branch: "main", profile: "prod-strict-v3", action: "gate.override" },
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      const res = await request(app).get("/api/projects/p1/approvals");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);

      if (res.body.data.length > 0) {
        const approval = res.body.data[0];
        expect(approval).toHaveProperty("id");
        expect(approval).toHaveProperty("actionType");
        expect(approval).toHaveProperty("status");
        expect(approval).toMatchObject({
          impactSummary: { failedRules: 1, ignoredFindings: 3, severityBreakdown: { critical: 1, high: 2 } },
          targetSnapshot: { runId: "run-ap-1", commit: "f8a1c3d", branch: "main", profile: "prod-strict-v3", action: "gate.override" },
        });
        expect(approval).toHaveProperty("expiresAt");
      }
    });

    it("filters legacy approvals tied to hidden static/deep lineage", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-ap-modern",
        projectId: "p-approvals-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "gate-ap-modern",
        projectId: "p-approvals-agg",
        runId: "run-ap-modern",
      }));
      ctx.approvalDAO.save(makeApproval({
        id: "approval-modern",
        projectId: "p-approvals-agg",
        targetId: "gate-ap-modern",
        actionType: "gate.override",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      ctx.runDAO.save(makeRun({
        id: "run-ap-legacy",
        projectId: "p-approvals-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "gate-ap-legacy",
        projectId: "p-approvals-agg",
        runId: "run-ap-legacy",
      }));
      ctx.approvalDAO.save(makeApproval({
        id: "approval-legacy",
        projectId: "p-approvals-agg",
        targetId: "gate-ap-legacy",
        actionType: "gate.override",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      const res = await request(app).get("/api/projects/p-approvals-agg/approvals");
      expect(res.status).toBe(200);
      expect(res.body.data.map((approval: any) => approval.id)).toEqual(["approval-modern"]);
    });
  });

  describe("POST /api/approvals/:id/decide", () => {
    it("approves and returns updated approval", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "finding-approval-target",
        projectId: "p1",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.approvalDAO.save(makeApproval({
        id: "ap-1",
        projectId: "p1",
        status: "pending",
        actionType: "finding.accepted_risk",
        targetId: "finding-approval-target",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      const res = await request(app)
        .post("/api/approvals/ap-1/decide")
        .send({ decision: "approved", actor: "admin", comment: "ok" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBe("approved");
      expect(res.body.data).toHaveProperty("decision");
    });
  });

  // ── Reports ──

  describe("GET /api/projects/:pid/report", () => {
    it("returns project report when data exists", async () => {
      ctx.projectDAO.save(makeProject({ id: "p1", name: "Test" }));
      ctx.runDAO.save(makeRun({ id: "run-1", projectId: "p1", module: "static_analysis", findingCount: 1 }));
      ctx.findingDAO.save(makeFinding({ id: "f1", runId: "run-1", projectId: "p1", module: "static_analysis" }));
      ctx.gateResultDAO.save(makeGateResult({ id: "g1", runId: "run-1", projectId: "p1" }));

      const res = await request(app).get("/api/projects/p1/report");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty("modules");
      expect(res.body.data).toHaveProperty("totalSummary");
    });

    it("returns 200 with empty report when project has no findings", async () => {
      ctx.projectDAO.save(makeProject({ id: "p2", name: "Empty" }));

      const res = await request(app).get("/api/projects/p2/report");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.totalSummary.totalFindings).toBe(0);
    });

    it("returns 404 for nonexistent project", async () => {
      const res = await request(app).get("/api/projects/nonexistent/report");
      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });

    it("filters legacy static-analysis rows without BuildTarget ownership out of aggregate reports", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-report-agg", name: "Aggregate Report" }));
      ctx.runDAO.save(makeRun({
        id: "run-modern",
        projectId: "p-report-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
        findingCount: 1,
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-modern",
        runId: "run-modern",
        projectId: "p-report-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
      }));

      ctx.runDAO.save(makeRun({
        id: "run-legacy",
        projectId: "p-report-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        module: "static_analysis",
        findingCount: 1,
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-legacy",
        runId: "run-legacy",
        projectId: "p-report-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        module: "static_analysis",
      }));

      const res = await request(app).get("/api/projects/p-report-agg/report");

      expect(res.status).toBe(200);
      expect(res.body.data.modules.static.findings).toHaveLength(1);
      expect(res.body.data.modules.static.findings[0].finding.id).toBe("finding-modern");
      expect(res.body.data.modules.static.runs).toHaveLength(1);
      expect(res.body.data.modules.static.runs[0].run.id).toBe("run-modern");
    });
  });

  describe("GET /api/projects/:pid/report/static", () => {
    it("returns module report when data exists", async () => {
      ctx.projectDAO.save(makeProject({ id: "p1", name: "Test" }));
      ctx.runDAO.save(makeRun({ id: "run-1", projectId: "p1", module: "static_analysis" }));
      ctx.findingDAO.save(makeFinding({ id: "f1", runId: "run-1", projectId: "p1", module: "static_analysis" }));

      const res = await request(app).get("/api/projects/p1/report/static");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty("summary");
      expect(res.body.data).toHaveProperty("findings");
      expect(res.body.data).toHaveProperty("runs");
    });

    it("returns 404 for nonexistent project", async () => {
      const res = await request(app).get("/api/projects/nonexistent/report/static");
      expect(res.status).toBe(404);
    });

    it("filters legacy static-analysis rows without BuildTarget ownership out of module reports", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-report-static-agg", name: "Static Aggregate" }));
      ctx.runDAO.save(makeRun({
        id: "run-static-modern",
        projectId: "p-report-static-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-static-modern",
        runId: "run-static-modern",
        projectId: "p-report-static-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        module: "static_analysis",
      }));

      ctx.runDAO.save(makeRun({
        id: "run-static-legacy",
        projectId: "p-report-static-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        module: "static_analysis",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-static-legacy",
        runId: "run-static-legacy",
        projectId: "p-report-static-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        module: "static_analysis",
      }));

      const res = await request(app).get("/api/projects/p-report-static-agg/report/static");

      expect(res.status).toBe(200);
      expect(res.body.data.findings).toHaveLength(1);
      expect(res.body.data.findings[0].finding.id).toBe("finding-static-modern");
      expect(res.body.data.runs).toHaveLength(1);
      expect(res.body.data.runs[0].run.id).toBe("run-static-modern");
    });
  });

  // ── Error response structure ──

  describe("Error response contract", () => {
    it("returns { success: false, error: string } for inline controller errors", async () => {
      const res = await request(app).get("/api/projects/nonexistent");
      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
      expect(typeof res.body.error).toBe("string");
    });

    it("returns { success: false, error, errorDetail } for AppError middleware errors", async () => {
      // Invalid status transition → InvalidInputError → error handler middleware
      ctx.findingDAO.save(makeFinding({ id: "f-err", projectId: "p1", status: "open" }));

      const res = await request(app)
        .patch("/api/findings/f-err/status")
        .send({ status: "sandbox", actor: "test", reason: "test" });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(typeof res.body.error).toBe("string");
      expect(res.body.errorDetail).toHaveProperty("code", "INVALID_INPUT");
      expect(res.body.errorDetail).toHaveProperty("message");
      expect(res.body.errorDetail.retryable).toBe(false);
    });
  });

  // ── Finding Bulk Status ──

  describe("PATCH /api/findings/bulk-status", () => {
    it("updates multiple findings and returns counts", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fb1", projectId: "p1", status: "open" }));
      ctx.findingDAO.save(makeFinding({ id: "fb2", projectId: "p1", status: "open" }));

      const res = await request(app)
        .patch("/api/findings/bulk-status")
        .send({ findingIds: ["fb1", "fb2"], status: "needs_review", reason: "batch review", actor: "analyst" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual({ updated: 2, failed: 0 });

      // verify actual status changed
      const f1 = ctx.findingDAO.findById("fb1");
      expect(f1?.status).toBe("needs_review");
    });

    it("returns 400 when findingIds is empty", async () => {
      const res = await request(app)
        .patch("/api/findings/bulk-status")
        .send({ findingIds: [], status: "fixed", reason: "test" });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it("returns 400 when findingIds exceeds 100", async () => {
      const ids = Array.from({ length: 101 }, (_, i) => `f-${i}`);
      const res = await request(app)
        .patch("/api/findings/bulk-status")
        .send({ findingIds: ids, status: "fixed", reason: "test" });

      expect(res.status).toBe(400);
    });

    it("returns 400 when status or reason missing", async () => {
      const res = await request(app)
        .patch("/api/findings/bulk-status")
        .send({ findingIds: ["fb1"] });

      expect(res.status).toBe(400);
    });

    it("counts invalid transitions as failed", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fb-inv", projectId: "p1", status: "open" }));

      const res = await request(app)
        .patch("/api/findings/bulk-status")
        .send({ findingIds: ["fb-inv", "fb-ghost"], status: "sandbox", reason: "bad", actor: "x" });

      expect(res.status).toBe(200);
      // open→sandbox invalid + fb-ghost not found = both fail
      expect(res.body.data).toEqual({ updated: 0, failed: 2 });
    });
  });

  // ── Finding History ──

  describe("GET /api/findings/:id/history", () => {
    it("returns fingerprint history", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fh1", runId: "run-h1", projectId: "p1", fingerprint: "fp-abc", status: "fixed", createdAt: "2026-03-20T00:00:00Z" }));
      ctx.findingDAO.save(makeFinding({ id: "fh2", runId: "run-h2", projectId: "p1", fingerprint: "fp-abc", status: "open", createdAt: "2026-03-25T00:00:00Z" }));

      const res = await request(app).get("/api/findings/fh2/history");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data).toHaveLength(2);
      expect(res.body.data[0]).toHaveProperty("findingId");
      expect(res.body.data[0]).toHaveProperty("runId");
      expect(res.body.data[0]).toHaveProperty("status");
      expect(res.body.data[0]).toHaveProperty("createdAt");
    });

    it("returns empty array when finding has no fingerprint", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fh-nofp", projectId: "p1" }));

      const res = await request(app).get("/api/findings/fh-nofp/history");
      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([]);
    });

    it("returns 404 for nonexistent finding", async () => {
      const res = await request(app).get("/api/findings/no-such/history");
      expect(res.status).toBe(404);
    });
  });

  // ── Finding Filters/Sort ──

  describe("GET /api/projects/:pid/findings — extended filters", () => {
    it("filters by text search (q)", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fq1", projectId: "p-fq", title: "Buffer overflow in main.c" }));
      ctx.findingDAO.save(makeFinding({ id: "fq2", projectId: "p-fq", title: "SQL injection" }));

      const res = await request(app).get("/api/projects/p-fq/findings?q=Buffer");
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].id).toBe("fq1");
    });

    it("filters by sourceType", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fst1", projectId: "p-fst", sourceType: "agent" }));
      ctx.findingDAO.save(makeFinding({ id: "fst2", projectId: "p-fst", sourceType: "sast-tool" }));

      const res = await request(app).get("/api/projects/p-fst/findings?sourceType=agent");
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].id).toBe("fst1");
    });

    it("sorts by severity asc", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fs1", projectId: "p-fs", severity: "low" }));
      ctx.findingDAO.save(makeFinding({ id: "fs2", projectId: "p-fs", severity: "critical" }));

      const res = await request(app).get("/api/projects/p-fs/findings?sort=severity&order=asc");
      expect(res.status).toBe(200);
      expect(res.body.data[0].severity).toBe("critical");
      expect(res.body.data[1].severity).toBe("low");
    });
  });

  // ── Approval Count ──

  describe("GET /api/projects/:pid/approvals/count", () => {
    it("returns pending and total counts", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-count-1",
        projectId: "p-ac",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-count-1", projectId: "p-ac", runId: "run-count-1" }));
      ctx.runDAO.save(makeRun({
        id: "run-count-2",
        projectId: "p-ac",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-count-2", projectId: "p-ac", runId: "run-count-2" }));
      ctx.approvalDAO.save(makeApproval({
        id: "ac-1", projectId: "p-ac", status: "pending",
        targetId: "gate-count-1",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));
      ctx.approvalDAO.save(makeApproval({
        id: "ac-2", projectId: "p-ac", status: "pending",
        targetId: "gate-count-2",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      const res = await request(app).get("/api/projects/p-ac/approvals/count");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({ pending: 2, total: 2 });
    });

    it("ignores legacy approvals tied to hidden static/deep lineage", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-count-modern",
        projectId: "p-ac-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-count-modern", projectId: "p-ac-agg", runId: "run-count-modern" }));
      ctx.approvalDAO.save(makeApproval({
        id: "ac-modern",
        projectId: "p-ac-agg",
        status: "pending",
        targetId: "gate-count-modern",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      ctx.runDAO.save(makeRun({
        id: "run-count-legacy",
        projectId: "p-ac-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-count-legacy", projectId: "p-ac-agg", runId: "run-count-legacy" }));
      ctx.approvalDAO.save(makeApproval({
        id: "ac-legacy",
        projectId: "p-ac-agg",
        status: "pending",
        targetId: "gate-count-legacy",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      const res = await request(app).get("/api/projects/p-ac-agg/approvals/count");
      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({ pending: 1, total: 1 });
    });

    it("returns zero counts when no approvals", async () => {
      const res = await request(app).get("/api/projects/p-empty/approvals/count");
      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({ pending: 0, total: 0 });
    });
  });

  // ── Activity Timeline ──

  describe("GET /api/projects/:pid/activity", () => {
    it("returns timeline entries sorted by timestamp", async () => {
      ctx.runDAO.save(makeRun({ id: "ra-1", projectId: "p-act", status: "completed", module: "static_analysis", findingCount: 3, endedAt: "2026-03-26T09:00:00Z" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "ta-1", projectId: "p-act", name: "gw", status: "ready", updatedAt: "2026-03-26T10:00:00Z" }));

      const res = await request(app).get("/api/projects/p-act/activity?limit=10");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(2);

      for (const entry of res.body.data) {
        expect(entry).toHaveProperty("type");
        expect(entry).toHaveProperty("timestamp");
        expect(entry).toHaveProperty("summary");
        expect(entry).toHaveProperty("metadata");
      }

      // pipeline event (10:00) should come before run event (09:00)
      const types = res.body.data.map((e: any) => e.type);
      const pipeIdx = types.indexOf("pipeline_completed");
      const runIdx = types.indexOf("run_completed");
      expect(pipeIdx).toBeLessThan(runIdx);
    });

    it("respects limit parameter", async () => {
      for (let i = 0; i < 5; i++) {
        ctx.runDAO.save(makeRun({ id: `ra-lim-${i}`, projectId: "p-lim", status: "completed", findingCount: 0, endedAt: `2026-03-26T0${i}:00:00Z` }));
      }

      const res = await request(app).get("/api/projects/p-lim/activity?limit=3");
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(3);
    });

    it("returns empty array for empty project", async () => {
      const res = await request(app).get("/api/projects/p-empty/activity");
      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([]);
    });

    it("skips legacy static/deep run entries without BuildTarget ownership", async () => {
      ctx.runDAO.save(makeRun({
        id: "ra-legacy-static",
        projectId: "p-act-agg",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        status: "completed",
        module: "static_analysis",
        findingCount: 2,
        endedAt: "2026-03-26T09:00:00Z",
      }));
      ctx.runDAO.save(makeRun({
        id: "ra-modern-static",
        projectId: "p-act-agg",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        status: "completed",
        module: "static_analysis",
        findingCount: 1,
        endedAt: "2026-03-26T10:00:00Z",
      }));

      const res = await request(app).get("/api/projects/p-act-agg/activity?limit=10");

      expect(res.status).toBe(200);
      const runEntries = res.body.data.filter((entry: any) => entry.type === "run_completed");
      expect(runEntries).toHaveLength(1);
      expect(runEntries[0].metadata.runId).toBe("ra-modern-static");
    });

    it("skips hidden finding/approval activity entries tied to legacy static/deep lineage", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "finding-activity-modern",
        projectId: "p-act-hidden",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-activity-legacy",
        projectId: "p-act-hidden",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));
      ctx.auditLogDAO.save(makeAuditLog({
        id: "audit-finding-modern",
        timestamp: "2026-03-26T11:00:00Z",
        actor: "alice",
        action: "finding.status_change",
        resource: "finding",
        resourceId: "finding-activity-modern",
        detail: { from: "open", to: "fixed" },
      }));
      ctx.auditLogDAO.save(makeAuditLog({
        id: "audit-finding-legacy",
        timestamp: "2026-03-26T11:30:00Z",
        actor: "bob",
        action: "finding.status_change",
        resource: "finding",
        resourceId: "finding-activity-legacy",
        detail: { from: "open", to: "fixed" },
      }));

      ctx.runDAO.save(makeRun({
        id: "run-approval-modern",
        projectId: "p-act-hidden",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-approval-modern", projectId: "p-act-hidden", runId: "run-approval-modern" }));
      ctx.approvalDAO.save(makeApproval({
        id: "approval-activity-modern",
        projectId: "p-act-hidden",
        actionType: "gate.override",
        targetId: "gate-approval-modern",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));

      ctx.runDAO.save(makeRun({
        id: "run-approval-legacy",
        projectId: "p-act-hidden",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-approval-legacy", projectId: "p-act-hidden", runId: "run-approval-legacy" }));
      ctx.approvalDAO.save(makeApproval({
        id: "approval-activity-legacy",
        projectId: "p-act-hidden",
        actionType: "gate.override",
        targetId: "gate-approval-legacy",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }));
      ctx.auditLogDAO.save(makeAuditLog({
        id: "audit-approval-modern",
        timestamp: "2026-03-26T12:00:00Z",
        actor: "admin",
        action: "approval.approved",
        resource: "approval",
        resourceId: "approval-activity-modern",
        detail: { decision: "approved", actionType: "gate.override", targetId: "gate-approval-modern" },
      }));
      ctx.auditLogDAO.save(makeAuditLog({
        id: "audit-approval-legacy",
        timestamp: "2026-03-26T12:30:00Z",
        actor: "admin",
        action: "approval.approved",
        resource: "approval",
        resourceId: "approval-activity-legacy",
        detail: { decision: "approved", actionType: "gate.override", targetId: "gate-approval-legacy" },
      }));

      const res = await request(app).get("/api/projects/p-act-hidden/activity?limit=10");

      expect(res.status).toBe(200);
      const findingEntries = res.body.data.filter((entry: any) => entry.type === "finding_status_changed");
      expect(findingEntries).toHaveLength(1);
      expect(findingEntries[0].metadata.findingId).toBe("finding-activity-modern");

      const approvalEntries = res.body.data.filter((entry: any) => entry.type === "approval_decided");
      expect(approvalEntries).toHaveLength(1);
      expect(approvalEntries[0].metadata.approvalId).toBe("approval-activity-modern");
    });
  });

  describe("Health API", () => {
    it("GET /health returns raw health response without success envelope", async () => {
      const res = await request(app).get("/health");

      expect(res.status).toBe(200);
      expect(res.body.success).toBeUndefined();
      expect(res.body).toMatchObject({
        service: "aegis-core-service",
        status: "ok",
      });
      expect(res.body.adapters).toMatchObject({ total: 0, connected: 0 });
    });
  });

  describe("Project Adapters API", () => {
    it("creates and lists project adapters", async () => {
      const createRes = await request(app)
        .post("/api/projects/p-adapter/adapters")
        .send({ name: "Bench ECU", url: "ws://adapter.local" });

      expect(createRes.status).toBe(201);
      expect(createRes.body.success).toBe(true);
      expect(createRes.body.data).toMatchObject({
        projectId: "p-adapter",
        name: "Bench ECU",
        url: "ws://adapter.local",
        connected: false,
      });

      const listRes = await request(app).get("/api/projects/p-adapter/adapters");
      expect(listRes.status).toBe(200);
      expect(listRes.body.data).toHaveLength(1);
      expect(listRes.body.data[0].id).toBe(createRes.body.data.id);
    });

    it("updates adapter metadata", async () => {
      const createRes = await request(app)
        .post("/api/projects/p-adapter-update/adapters")
        .send({ name: "Bench ECU", url: "ws://adapter.local" });

      const res = await request(app)
        .put(`/api/projects/p-adapter-update/adapters/${createRes.body.data.id}`)
        .send({ name: "Cabin ECU", url: "wss://adapter.example" });

      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({
        id: createRes.body.data.id,
        name: "Cabin ECU",
        url: "wss://adapter.example",
      });
    });

    it("connects and disconnects an adapter", async () => {
      const createRes = await request(app)
        .post("/api/projects/p-adapter-connect/adapters")
        .send({ name: "Bench ECU", url: "ws://adapter.local" });
      const adapterId = createRes.body.data.id as string;

      const connectRes = await request(app).post(`/api/projects/p-adapter-connect/adapters/${adapterId}/connect`);
      expect(connectRes.status).toBe(200);
      expect(connectRes.body.data.connected).toBe(true);

      const disconnectRes = await request(app).post(`/api/projects/p-adapter-connect/adapters/${adapterId}/disconnect`);
      expect(disconnectRes.status).toBe(200);
      expect(disconnectRes.body.data.connected).toBe(false);
    });

    it("deletes an adapter within the project scope", async () => {
      const createRes = await request(app)
        .post("/api/projects/p-adapter-delete/adapters")
        .send({ name: "Bench ECU", url: "ws://adapter.local" });
      const adapterId = createRes.body.data.id as string;

      const deleteRes = await request(app).delete(`/api/projects/p-adapter-delete/adapters/${adapterId}`);
      expect(deleteRes.status).toBe(200);
      expect(deleteRes.body).toEqual({ success: true });

      const listRes = await request(app).get("/api/projects/p-adapter-delete/adapters");
      expect(listRes.body.data).toEqual([]);
    });
  });

  describe("Project Settings API", () => {
    it("returns default project settings", async () => {
      const res = await request(app).get("/api/projects/p-settings/settings");

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty("llmUrl");
      expect(res.body.data.buildProfile).toMatchObject({
        sdkId: "custom",
        compiler: "gcc",
      });
    });

    it("updates project settings and returns merged build profile", async () => {
      const res = await request(app)
        .put("/api/projects/p-settings-update/settings")
        .send({
          llmUrl: "http://localhost:9999",
          buildProfile: {
            sdkId: "none",
            compiler: "clang",
            targetArch: "arm64",
          },
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        llmUrl: "http://localhost:9999",
      });
      expect(res.body.data.buildProfile).toMatchObject({
        sdkId: "none",
        compiler: "clang",
        targetArch: "arm64",
      });
    });
  });

  // ── Build Targets ──

  describe("Build Targets", () => {
    it("POST /api/projects/:pid/targets creates target", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt" }));

      const res = await request(app)
        .post("/api/projects/p-bt/targets")
        .send({ name: "gateway", relativePath: "gateway/", buildSystem: "cmake" });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe("gateway");
      expect(res.body.data.relativePath).toBe("gateway/");
      expect(res.body.data.id).toMatch(/^target-/);
    });

    it("POST /api/projects/:pid/targets accepts a BuildTarget-root-relative scriptHintPath", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt-script" }));
      const targetRoot = path.join("/tmp", "p-bt-script", "gateway");
      fs.mkdirSync(path.join(targetRoot, "scripts"), { recursive: true });
      fs.writeFileSync(path.join(targetRoot, "scripts", "build.sh"), "#!/bin/sh\nmake all\n", "utf-8");

      const res = await request(app)
        .post("/api/projects/p-bt-script/targets")
        .send({
          name: "gateway",
          relativePath: "gateway/",
          buildSystem: "make",
          scriptHintPath: "scripts/build.sh",
        });

      expect(res.status).toBe(201);
      expect(res.body.data.scriptHintPath).toBe("scripts/build.sh");
      expect(ctx.buildTargetDAO.findById(res.body.data.id)?.scriptHintPath).toBe("scripts/build.sh");
    });

    it("GET /api/projects/:pid/targets lists targets", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt2" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t1", projectId: "p-bt2", name: "a" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t2", projectId: "p-bt2", name: "b" }));

      const res = await request(app).get("/api/projects/p-bt2/targets");
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(2);
    });

    it("PUT /api/projects/:pid/targets/:id updates target", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt3" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t3", projectId: "p-bt3", name: "old" }));

      const res = await request(app)
        .put("/api/projects/p-bt3/targets/t3")
        .send({ name: "new-name" });

      expect(res.status).toBe(200);
      expect(res.body.data.name).toBe("new-name");
    });

    it("PUT /api/projects/:pid/targets/:id validates and clears scriptHintPath", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt-script-update" }));
      const targetRoot = path.join("/tmp", "p-bt-script-update", "src");
      fs.mkdirSync(targetRoot, { recursive: true });
      fs.writeFileSync(path.join(targetRoot, "build.sh"), "#!/bin/sh\nmake\n", "utf-8");
      ctx.buildTargetDAO.save(makeBuildTarget({
        id: "t-script-update",
        projectId: "p-bt-script-update",
        relativePath: "src/",
      }));

      const setRes = await request(app)
        .put("/api/projects/p-bt-script-update/targets/t-script-update")
        .send({ scriptHintPath: "build.sh" });
      expect(setRes.status).toBe(200);
      expect(setRes.body.data.scriptHintPath).toBe("build.sh");

      const clearRes = await request(app)
        .put("/api/projects/p-bt-script-update/targets/t-script-update")
        .send({ scriptHintPath: null });
      expect(clearRes.status).toBe(200);
      expect(clearRes.body.data).not.toHaveProperty("scriptHintPath");
    });

    it("PUT rejects relativePath changes that would leave scriptHintPath stale", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt-script-stale" }));
      const oldRoot = path.join("/tmp", "p-bt-script-stale", "old");
      const newRoot = path.join("/tmp", "p-bt-script-stale", "new");
      fs.mkdirSync(oldRoot, { recursive: true });
      fs.mkdirSync(newRoot, { recursive: true });
      fs.writeFileSync(path.join(oldRoot, "build.sh"), "#!/bin/sh\nmake old\n", "utf-8");
      ctx.buildTargetDAO.save(makeBuildTarget({
        id: "t-script-stale",
        projectId: "p-bt-script-stale",
        relativePath: "old/",
        scriptHintPath: "build.sh",
      }));

      const res = await request(app)
        .put("/api/projects/p-bt-script-stale/targets/t-script-stale")
        .send({ relativePath: "new/" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("scriptHintPath");
      expect(ctx.buildTargetDAO.findById("t-script-stale")?.relativePath).toBe("old/");
    });

    it("DELETE /api/projects/:pid/targets/:id deletes target", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt4" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t4", projectId: "p-bt4" }));

      const res = await request(app).delete("/api/projects/p-bt4/targets/t4");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it("POST rejects relativePath with ..", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt5" }));

      const res = await request(app)
        .post("/api/projects/p-bt5/targets")
        .send({ name: "evil", relativePath: "../etc/" });

      expect(res.status).toBe(400);
    });

    it("POST rejects unsafe scriptHintPath values", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt-script-unsafe" }));

      const res = await request(app)
        .post("/api/projects/p-bt-script-unsafe/targets")
        .send({ name: "evil", relativePath: "src/", scriptHintPath: "../build.sh" });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain("scriptHintPath");
    });

    it("returns 404 for wrong project ownership", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt6" }));
      ctx.projectDAO.save(makeProject({ id: "p-bt7" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t6", projectId: "p-bt6" }));

      const res = await request(app).put("/api/projects/p-bt7/targets/t6").send({ name: "x" });
      expect(res.status).toBe(404);
    });

    it("POST /api/projects/:pid/targets/discover returns discovery payload", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt-discover" }));

      const res = await request(app).post("/api/projects/p-bt-discover/targets/discover");

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        discovered: 1,
        created: 1,
        elapsedMs: 123,
      });
      expect(res.body.data.targets).toHaveLength(1);
      expect(res.body.data.targets[0]).toMatchObject({
        projectId: "p-bt-discover",
        name: "auto-discovered",
        relativePath: "auto-discovered/",
        buildSystem: "cmake",
      });
    });

    it("PUT /api/projects/:pid/targets/:id rejects includedPaths updates explicitly", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bt8" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t8", projectId: "p-bt8" }));

      const res = await request(app)
        .put("/api/projects/p-bt8/targets/t8")
        .send({ includedPaths: ["src/"] });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toContain("includedPaths updates are not supported");
      expect(res.body.errorDetail.code).toBe("INVALID_INPUT");
      expect(res.body.errorDetail.retryable).toBe(false);
    });
  });

  // ── SDK API ──

  describe("SDK API", () => {
    it("GET /api/projects/:pid/sdk returns builtIn and registered arrays", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk" }));

      const createRes = await request(app)
        .post("/api/projects/p-sdk/sdk")
        .field("name", "TI SDK")
        .field("description", "Cross toolchain")
        .attach("file", Buffer.from("archive-content"), "ti-sdk-am335x-08.02.00.24.tar.gz");
      expect(createRes.status).toBe(202);

      const res = await request(app).get("/api/projects/p-sdk/sdk");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data.builtIn)).toBe(true);
      expect(Array.isArray(res.body.data.registered)).toBe(true);
      expect(res.body.data.registered).toHaveLength(1);
      expect(res.body.data.registered[0].id).toBe(createRes.body.data.id);
    });

    it("GET /api/projects/:pid/sdk/:id returns RegisteredSdk detail", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk2" }));

      const createRes = await request(app)
        .post("/api/projects/p-sdk2/sdk")
        .field("name", "Yocto SDK")
        .attach("file", Buffer.from("installer"), "yocto-sdk-08.02.00.24.bin");

      const res = await request(app).get(`/api/projects/p-sdk2/sdk/${createRes.body.data.id}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        id: createRes.body.data.id,
        projectId: "p-sdk2",
        name: "Yocto SDK",
        path: `/tmp/p-sdk2/sdk/${createRes.body.data.id}/installed`,
        artifactKind: "bin",
        sdkVersion: "08.02.00.24",
        targetSystem: "am335x-evm",
        status: "uploaded",
        verified: false,
      });
    });

    it("GET /api/projects/:pid/sdk/:id/log returns install log content", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk-log" }));

      const createRes = await request(app)
        .post("/api/projects/p-sdk-log/sdk")
        .field("name", "Loggable SDK")
        .attach("file", Buffer.from("installer"), "ti-sdk.bin");

      const sdkId = createRes.body.data.id as string;
      const res = await request(app).get(`/api/projects/p-sdk-log/sdk/${sdkId}/log?tailLines=200`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        sdkId,
        logPath: expect.stringContaining(`/tmp/logs/${sdkId}.log`),
        content: expect.stringContaining("line 1"),
        truncated: false,
        totalLines: 2,
      });
    });

    it("GET /api/projects/:pid/sdk/:id/log supports pagination and download", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk-log-page" }));

      const createRes = await request(app)
        .post("/api/projects/p-sdk-log-page/sdk")
        .field("name", "Paged Log SDK")
        .attach("file", Buffer.from("installer"), "ti-sdk.bin");

      const sdkId = createRes.body.data.id as string;
      const pageRes = await request(app).get(`/api/projects/p-sdk-log-page/sdk/${sdkId}/log?offset=0&limit=1`);
      expect(pageRes.status).toBe(200);
      expect(pageRes.body.data).toMatchObject({
        sdkId,
        content: "line 1",
        truncated: true,
        totalLines: 2,
        nextOffset: 1,
      });

      const downloadRes = await request(app).get(`/api/projects/p-sdk-log-page/sdk/${sdkId}/log?download=true`);
      expect(downloadRes.status).toBe(200);
      expect(downloadRes.headers["content-disposition"]).toContain(`${sdkId}-install.log`);
      expect(downloadRes.text).toContain("line 1");
    });

    it("GET /api/projects/:pid/sdk/quota and /metrics return SDK operational metadata", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk-ops" }));

      await request(app)
        .post("/api/projects/p-sdk-ops/sdk")
        .field("name", "Ops SDK")
        .attach("file", Buffer.from("archive-content"), "ops-sdk.tar.gz");

      const quotaRes = await request(app).get("/api/projects/p-sdk-ops/sdk/quota");
      expect(quotaRes.status).toBe(200);
      expect(quotaRes.body.data).toMatchObject({
        usedBytes: expect.any(Number),
        maxBytes: expect.any(Number),
        sdkCount: 1,
      });

      const metricsRes = await request(app).get("/api/projects/p-sdk-ops/sdk/metrics");
      expect(metricsRes.status).toBe(200);
      expect(metricsRes.body.data).toMatchObject({
        totalRegistered: 1,
        sdkCount: 1,
        readyCount: 0,
        failedCount: 0,
        averagePhaseDurationMs: {},
      });
    });

    it("POST /api/projects/:pid/sdk/:id/retry exposes server-side retry endpoint", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk-retry" }));

      const createRes = await request(app)
        .post("/api/projects/p-sdk-retry/sdk")
        .field("name", "Retry Route SDK")
        .attach("file", Buffer.from("archive-content"), "retry-sdk.tar.gz");

      const sdkId = createRes.body.data.id as string;
      const retryRes = await request(app)
        .post(`/api/projects/p-sdk-retry/sdk/${sdkId}/retry`)
        .send({ fromPhase: "verifying" });
      expect(retryRes.status).toBe(202);
      expect(retryRes.body).toMatchObject({
        success: true,
        data: {
          id: sdkId,
          status: "ready",
          retryCount: 1,
        },
      });
    });

    it("POST /api/projects/:pid/sdk returns 202 with a full RegisteredSdk payload", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk3" }));

      const res = await request(app)
        .post("/api/projects/p-sdk3/sdk")
        .field("name", "SDK Upload")
        .field("description", "ARM toolchain")
        .attach("file", Buffer.from("archive-content"), "custom-sdk-1.0.0.tar.gz");

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        projectId: "p-sdk3",
        name: "SDK Upload",
        description: "ARM toolchain",
        path: expect.stringContaining("/tmp/p-sdk3/sdk/"),
        artifactKind: "archive",
        sdkVersion: "1.0.0",
        targetSystem: "archive-target",
        status: "uploaded",
        verified: false,
      });
      expect(res.body.data.id).toMatch(/^sdk-/);
      expect(res.body.data.createdAt).toBeTypeOf("string");
      expect(res.body.data.updatedAt).toBeTypeOf("string");
    });

    it("POST /api/projects/:pid/sdk accepts folder uploads and preserves project-scoped metadata", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk4" }));

      const res = await request(app)
        .post("/api/projects/p-sdk4/sdk")
        .field("name", "Folder SDK")
        .attach("file", Buffer.from("one"), "folder/one.txt")
        .attach("file", Buffer.from("two"), "folder/two.txt");

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        projectId: "p-sdk4",
        name: "Folder SDK",
        artifactKind: "folder",
        sdkVersion: "folder-virtual",
        targetSystem: "folder-target",
        status: "uploaded",
        verified: false,
      });
    });

    it("POST /api/projects/:pid/sdk accepts explicit relativePath[] metadata for folder uploads", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk5" }));

      const res = await request(app)
        .post("/api/projects/p-sdk5/sdk")
        .field("name", "Folder SDK Relative")
        .field("relativePath", "dir/one.txt")
        .field("relativePath", "dir/sub/two.txt")
        .attach("file", Buffer.from("one"), "one.txt")
        .attach("file", Buffer.from("two"), "two.txt");

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        projectId: "p-sdk5",
        name: "Folder SDK Relative",
        artifactKind: "folder",
        status: "uploaded",
      });
    });

    it("POST /api/projects/:pid/sdk emits sdk_failed notification when validation fails after multipart acceptance", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk-no-files" }));

      const res = await request(app)
        .post("/api/projects/p-sdk-no-files/sdk")
        .field("name", "Missing Files SDK");

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("SDK upload requires at least one file");

      const notifRes = await request(app).get("/api/projects/p-sdk-no-files/notifications");
      expect(notifRes.status).toBe(200);
      expect(notifRes.body.success).toBe(true);
      expect(notifRes.body.data).toEqual([
        expect.objectContaining({
          projectId: "p-sdk-no-files",
          type: "sdk_failed",
          title: "SDK 업로드 실패",
          body: "SDK upload requires at least one file",
          jobKind: "sdk",
          correlationId: expect.stringMatching(/^sdk-/),
          read: false,
        }),
      ]);
      expect(notifRes.body.data[0].resourceId).toBeUndefined();
    });

    it("POST /api/projects/:pid/sdk emits sdk_failed notification when uploaded payload fails route validation", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk-no-name" }));

      const res = await request(app)
        .post("/api/projects/p-sdk-no-name/sdk")
        .attach("file", Buffer.from("archive-content"), "no-name-sdk.tar.gz");

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("name is required");

      const notifRes = await request(app).get("/api/projects/p-sdk-no-name/notifications");
      expect(notifRes.status).toBe(200);
      expect(notifRes.body.success).toBe(true);
      expect(notifRes.body.data).toEqual([
        expect.objectContaining({
          projectId: "p-sdk-no-name",
          type: "sdk_failed",
          title: "SDK 업로드 실패",
          body: "name is required",
          jobKind: "sdk",
          correlationId: expect.stringMatching(/^sdk-/),
          read: false,
        }),
      ]);
      expect(notifRes.body.data[0].resourceId).toBeUndefined();
    });

    it("DELETE /api/projects/:pid/sdk/:id removes a registered SDK", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-sdk-delete" }));

      const createRes = await request(app)
        .post("/api/projects/p-sdk-delete/sdk")
        .field("name", "Delete SDK")
        .attach("file", Buffer.from("archive-content"), "delete-sdk.tar.gz");
      const sdkId = createRes.body.data.id as string;

      const deleteRes = await request(app).delete(`/api/projects/p-sdk-delete/sdk/${sdkId}`);
      expect(deleteRes.status).toBe(200);
      expect(deleteRes.body).toEqual({ success: true });

      const listRes = await request(app).get("/api/projects/p-sdk-delete/sdk");
      expect(listRes.body.data.registered).toEqual([]);
    });
  });

  describe("SDK Profile API", () => {
    it("GET /api/sdk-profiles returns built-in profile list", async () => {
      const res = await request(app).get("/api/sdk-profiles");

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThan(0);
      expect(res.body.data[0]).toMatchObject({
        id: expect.any(String),
        name: expect.any(String),
        vendor: expect.any(String),
        description: expect.any(String),
        defaults: expect.any(Object),
      });
    });

    it("GET /api/sdk-profiles/:id returns detail or 404 for unknown ids", async () => {
      const listRes = await request(app).get("/api/sdk-profiles");
      const profileId = listRes.body.data[0].id as string;

      const detailRes = await request(app).get(`/api/sdk-profiles/${profileId}`);
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.data.id).toBe(profileId);
      expect(detailRes.body.data.defaults).toMatchObject({
        compiler: expect.any(String),
        targetArch: expect.any(String),
        languageStandard: expect.any(String),
        headerLanguage: expect.any(String),
      });

      const missingRes = await request(app).get("/api/sdk-profiles/nonexistent");
      expect(missingRes.status).toBe(404);
    });
  });

  describe("Source API", () => {
    it("GET /api/projects/:pid/source/files returns data plus composition metadata and targetMapping", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-src" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t-src", projectId: "p-src", relativePath: "src/" }));

      const res = await request(app).get("/api/projects/p-src/source/files?filter=source");

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data).toHaveLength(1);
      expect(res.body).toMatchObject({
        composition: { source: 1, doc: 1 },
        totalFiles: 2,
        totalSize: 192,
      });
      expect(res.body.targetMapping).toMatchObject({
        "src/main.c": { targetId: "t-src", targetName: expect.any(String) },
      });
    });

    it("GET /api/projects/:pid/source/file returns content with file metadata", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-src-file" }));

      const res = await request(app).get("/api/projects/p-src-file/source/file?path=src/main.c");

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        path: "src/main.c",
        content: "contents:src/main.c",
        size: 128,
        language: "c",
        fileType: "source",
        previewable: true,
        lineCount: 3,
      });
    });

    it("POST /api/projects/:pid/source/upload exposes upload-status fallback and completion notification", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-upload" }));

      const createRes = await request(app)
        .post("/api/projects/p-upload/source/upload")
        .attach("file", Buffer.from("int main(void) { return 0; }"), "main.c");

      expect(createRes.status).toBe(202);
      const uploadId = createRes.body.data.uploadId as string;
      expect(uploadId).toMatch(/^upload-/);

      let statusRes = await request(app).get(`/api/projects/p-upload/source/upload-status/${uploadId}`);
      for (let i = 0; i < 10 && statusRes.body?.data?.phase !== "complete"; i++) {
        await new Promise((resolve) => setTimeout(resolve, 0));
        statusRes = await request(app).get(`/api/projects/p-upload/source/upload-status/${uploadId}`);
      }

      expect(statusRes.status).toBe(200);
      expect(statusRes.body.data.phase).toBe("complete");

      const notifRes = await request(app).get("/api/projects/p-upload/notifications");
      expect(notifRes.status).toBe(200);
      expect(notifRes.body.data).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: "upload_complete",
            jobKind: "upload",
            resourceId: uploadId,
            correlationId: uploadId,
          }),
        ]),
      );
    });

    it("POST /api/projects/:pid/source/clone returns clone result payload", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-clone" }));

      const res = await request(app)
        .post("/api/projects/p-clone/source/clone")
        .send({ gitUrl: "https://example.com/repo.git", branch: "main" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        projectPath: "/tmp/p-clone/cloned",
        fileCount: 1,
      });
      expect(Array.isArray(res.body.data.files)).toBe(true);
    });

    it("DELETE /api/projects/:pid/source returns { success: true }", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-source-delete" }));

      const res = await request(app).delete("/api/projects/p-source-delete/source");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
    });
  });

  // ================================================================
  // Pipeline API
  // ================================================================

  describe("Pipeline API", () => {
    it("POST /pipeline/run returns accepted pipeline payload", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-pipe-run" }));

      const res = await request(app)
        .post("/api/projects/p-pipe-run/pipeline/run")
        .send({ targetIds: ["t-a", "t-b"] });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.pipelineId).toMatch(/^pipe-/);
      expect(res.body.data.status).toBe("running");
      expect(ctx.pipelineRunCalls[ctx.pipelineRunCalls.length - 1]).toMatchObject({
        projectId: "p-pipe-run",
        targetIds: ["t-a", "t-b"],
        pipelineId: res.body.data.pipelineId,
      });
    });

    it("POST /pipeline/prepare returns accepted build-preparation payload", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-pipe-prepare" }));

      const res = await request(app)
        .post("/api/projects/p-pipe-prepare/pipeline/prepare")
        .send({ targetIds: ["t-a"] });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.preparationId).toMatch(/^prep-/);
      expect(res.body.data.status).toBe("running");
      expect(ctx.pipelinePrepareCalls[ctx.pipelinePrepareCalls.length - 1]).toMatchObject({
        projectId: "p-pipe-prepare",
        targetIds: ["t-a"],
        preparationId: res.body.data.preparationId,
      });
    });

    it("GET /pipeline/status returns targets with phase mapping", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-pipe" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "tp1", projectId: "p-pipe", status: "discovered" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "tp2", projectId: "p-pipe", status: "ready" }));

      const res = await request(app).get("/api/projects/p-pipe/pipeline/status");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.targets).toHaveLength(2);
      expect(res.body.data.readyCount).toBe(1);

      const discovered = res.body.data.targets.find((t: any) => t.id === "tp1");
      expect(discovered.phase).toBe("setup");

      const ready = res.body.data.targets.find((t: any) => t.id === "tp2");
      expect(ready.phase).toBe("ready");
    });

    it("GET /pipeline/status returns 404 for unknown project", async () => {
      const res = await request(app).get("/api/projects/nonexistent/pipeline/status");
      expect(res.status).toBe(404);
    });

    it("GET /pipeline/status maps resolving/resolve_failed to setup", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-pipe2" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "tp3", projectId: "p-pipe2", status: "resolving" as any }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "tp4", projectId: "p-pipe2", status: "resolve_failed" as any }));

      const res = await request(app).get("/api/projects/p-pipe2/pipeline/status");
      expect(res.status).toBe(200);

      for (const t of res.body.data.targets) {
        expect(t.phase).toBe("setup");
      }
    });

    it("POST /pipeline/run/:targetId returns rerun payload and resets failed targets", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-rerun" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "tp-rerun", projectId: "p-rerun", status: "build_failed" as any }));

      const res = await request(app).post("/api/projects/p-rerun/pipeline/run/tp-rerun");

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({ targetId: "tp-rerun", status: "running" });
      expect(res.body.data.pipelineId).toMatch(/^pipe-/);
      expect(ctx.buildTargetDAO.findById("tp-rerun")?.status).toBe("discovered");
      expect(ctx.pipelineRunCalls[ctx.pipelineRunCalls.length - 1]).toMatchObject({
        projectId: "p-rerun",
        targetIds: ["tp-rerun"],
        pipelineId: res.body.data.pipelineId,
      });
    });

    it("POST /pipeline/prepare/:targetId returns single-target build-preparation payload and resets failed targets", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-prep-rerun" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "tp-prep", projectId: "p-prep-rerun", status: "build_failed" as any }));

      const res = await request(app).post("/api/projects/p-prep-rerun/pipeline/prepare/tp-prep");

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({ targetId: "tp-prep", status: "running" });
      expect(res.body.data.preparationId).toMatch(/^prep-/);
      expect(ctx.buildTargetDAO.findById("tp-prep")?.status).toBe("discovered");
      expect(ctx.pipelinePrepareCalls[ctx.pipelinePrepareCalls.length - 1]).toMatchObject({
        projectId: "p-prep-rerun",
        targetIds: ["tp-prep"],
        preparationId: res.body.data.preparationId,
      });
    });

    it("GET /pipeline/status includes optional artifact fields when present", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-pipe3" }));
      ctx.buildTargetDAO.save(makeBuildTarget({
        id: "tp-opt",
        projectId: "p-pipe3",
        status: "built",
      }));
      ctx.buildTargetDAO.updatePipelineState("tp-opt", {
        status: "built",
        compileCommandsPath: "/tmp/compile_commands.json",
        sastScanId: "scan-123",
        codeGraphNodeCount: 42,
        lastBuiltAt: "2026-04-04T05:00:00.000Z",
      });

      const res = await request(app).get("/api/projects/p-pipe3/pipeline/status");
      expect(res.status).toBe(200);

      expect(res.body.data.targets[0]).toMatchObject({
        id: "tp-opt",
        compileCommandsPath: "/tmp/compile_commands.json",
        sastScanId: "scan-123",
        codeGraphNodeCount: 42,
        lastBuiltAt: "2026-04-04T05:00:00.000Z",
      });
    });
  });

  describe("Analysis API", () => {
    it("POST /api/analysis/run is absent after cutover", async () => {
      const res = await request(app)
        .post("/api/analysis/run")
        .send({ projectId: "p-analysis", buildTargetId: "t-1" });

      expect(res.status).toBe(404);
    });

    it("POST /api/analysis/quick returns 202 accepted payload and dispatches BuildTarget-scoped quick", async () => {
      const res = await request(app)
        .post("/api/analysis/quick")
        .send({ projectId: "p-analysis", buildTargetId: "t-1" });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.analysisId).toMatch(/^analysis-/);
      expect(res.body.data.buildTargetId).toBe("t-1");
      expect(res.body.data.executionId).toBe(res.body.data.analysisId);
      expect(ctx.analysisQuickCalls[ctx.analysisQuickCalls.length - 1]).toMatchObject({
        projectId: "p-analysis",
        targetIds: ["t-1"],
      });
    });

    it("POST /api/analysis/deep returns 202 accepted payload and dispatches execution-bound deep", async () => {
      const res = await request(app)
        .post("/api/analysis/deep")
        .send({ projectId: "p-analysis", buildTargetId: "t-1", executionId: "exec-1" });

      expect(res.status).toBe(202);
      expect(res.body.success).toBe(true);
      expect(res.body.data.analysisId).toMatch(/^analysis-/);
      expect(res.body.data.buildTargetId).toBe("t-1");
      expect(res.body.data.executionId).toBe("exec-1");
      expect(ctx.analysisDeepCalls[ctx.analysisDeepCalls.length - 1]).toMatchObject({
        projectId: "p-analysis",
        buildTargetId: "t-1",
        executionId: "exec-1",
      });
    });

    it("POST /api/analysis/quick and /deep reject legacy project-level analysis semantics", async () => {
      const quickLegacy = await request(app)
        .post("/api/analysis/quick")
        .send({ projectId: "p-analysis", mode: "full", targetIds: ["t-1"] });
      expect(quickLegacy.status).toBe(400);
      expect(quickLegacy.body.error).toContain("mode is no longer supported");

      const quickProjectOnly = await request(app)
        .post("/api/analysis/quick")
        .send({ projectId: "p-analysis" });
      expect(quickProjectOnly.status).toBe(400);
      expect(quickProjectOnly.body.error).toContain("buildTargetId is required");

      const deepLegacy = await request(app)
        .post("/api/analysis/deep")
        .send({ projectId: "p-analysis", buildTargetId: "t-1", quickAnalysisId: "analysis-quick-1" });
      expect(deepLegacy.status).toBe(400);
      expect(deepLegacy.body.error).toContain("quickAnalysisId is no longer supported");

      const deepMissingExecution = await request(app)
        .post("/api/analysis/deep")
        .send({ projectId: "p-analysis", buildTargetId: "t-1" });
      expect(deepMissingExecution.status).toBe(400);
      expect(deepMissingExecution.body.error).toContain("executionId is required");
    });

    it("GET /api/analysis/status returns running analyses", async () => {
      ctx.analysisTracker.start("analysis-running", "p-analysis-status", {
        buildTargetId: "t-analysis",
        executionId: "exec-analysis",
      });

      const res = await request(app).get("/api/analysis/status");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            analysisId: "analysis-running",
            projectId: "p-analysis-status",
            buildTargetId: "t-analysis",
            executionId: "exec-analysis",
            status: "running",
          }),
        ]),
      );
    });

    it("GET /api/analysis/status/:analysisId and abort flow return tracker payloads", async () => {
      ctx.analysisTracker.start("analysis-abort", "p-analysis-abort", {
        buildTargetId: "t-abort",
        executionId: "exec-abort",
      });

      const detailRes = await request(app).get("/api/analysis/status/analysis-abort");
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.data).toMatchObject({
        analysisId: "analysis-abort",
        projectId: "p-analysis-abort",
        buildTargetId: "t-abort",
        executionId: "exec-abort",
        status: "running",
      });

      const abortRes = await request(app).post("/api/analysis/abort/analysis-abort");
      expect(abortRes.status).toBe(200);
      expect(abortRes.body.data).toEqual({ analysisId: "analysis-abort", status: "aborted" });
    });

    it("GET /api/analysis/results, detail, and delete follow the documented contract", async () => {
      ctx.analysisResultDAO.save(makeAnalysisResult({
        id: "analysis-result-1",
        projectId: "p-analysis-results",
        module: "static_analysis",
        summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      }));

      const listRes = await request(app).get("/api/analysis/results?projectId=p-analysis-results");
      expect(listRes.status).toBe(200);
      expect(listRes.body.data).toHaveLength(1);

      const detailRes = await request(app).get("/api/analysis/results/analysis-result-1");
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.data.id).toBe("analysis-result-1");

      const deleteRes = await request(app).delete("/api/analysis/results/analysis-result-1");
      expect(deleteRes.status).toBe(200);
      expect(deleteRes.body).toEqual({ success: true });
    });

    it("preserves S3 claim and evidence diagnostics on analysis results", async () => {
      ctx.analysisResultDAO.save(makeAnalysisResult({
        id: "analysis-diagnostics-1",
        projectId: "p-analysis-diagnostics",
        module: "deep_analysis",
        analysisOutcome: "no_accepted_claims",
        qualityOutcome: "accepted_with_caveats",
        claimDiagnostics: {
          lifecycleCounts: { under_evidenced: 1 },
          nonAcceptedClaims: [
            {
              claimId: "claim-0",
              status: "under_evidenced",
              outcomeContribution: "no_accepted_claims",
            },
          ],
        },
        evidenceDiagnostics: {
          failedAcquisitions: [{ evidenceRef: "eref-1", reason: "not observed" }],
        },
      }));

      const detailRes = await request(app).get("/api/analysis/results/analysis-diagnostics-1");
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.data.claimDiagnostics.lifecycleCounts.under_evidenced).toBe(1);
      expect(detailRes.body.data.claimDiagnostics.nonAcceptedClaims[0].claimId).toBe("claim-0");
      expect(detailRes.body.data.evidenceDiagnostics.failedAcquisitions[0].reason).toBe("not observed");
    });

    it("GET /api/analysis/results hides legacy static/deep results without full BuildTarget execution lineage", async () => {
      ctx.analysisResultDAO.save(makeAnalysisResult({
        id: "analysis-modern",
        projectId: "p-analysis-results-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.analysisResultDAO.save(makeAnalysisResult({
        id: "analysis-legacy",
        projectId: "p-analysis-results-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
      }));

      const listRes = await request(app).get("/api/analysis/results?projectId=p-analysis-results-agg");
      expect(listRes.status).toBe(200);
      expect(listRes.body.data.map((result: any) => result.id)).toEqual(["analysis-modern"]);

      const detailRes = await request(app).get("/api/analysis/results/analysis-legacy");
      expect(detailRes.status).toBe(404);
    });

    it("GET /api/analysis/summary returns aggregated dashboard shape", async () => {
      ctx.runDAO.save(makeRun({ id: "run-static", projectId: "p-analysis-summary", module: "static_analysis", status: "completed" }));
      ctx.runDAO.save(makeRun({ id: "run-deep", projectId: "p-analysis-summary", module: "deep_analysis", status: "completed" }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-static",
        runId: "run-static",
        projectId: "p-analysis-summary",
        module: "static_analysis",
        severity: "high",
        status: "open",
        sourceType: "rule-engine",
        ruleId: "RULE-1",
        location: "src/main.c:10",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-deep",
        runId: "run-deep",
        projectId: "p-analysis-summary",
        module: "deep_analysis",
        severity: "medium",
        status: "needs_review",
        sourceType: "agent",
        location: "src/secondary.c:20",
      }));

      const res = await request(app).get("/api/analysis/summary?projectId=p-analysis-summary&period=30d");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.bySeverity).toMatchObject({ high: 1, medium: 1 });
      expect(res.body.data.unresolvedCount).toMatchObject({ open: 1, needsReview: 1 });
      expect(Array.isArray(res.body.data.topFiles)).toBe(true);
      expect(Array.isArray(res.body.data.trend)).toBe(true);
    });

    it("GET /api/analysis/summary excludes legacy static/deep findings, runs, and gate rows without full lineage", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-summary-modern",
        projectId: "p-analysis-summary-agg",
        module: "static_analysis",
        status: "completed",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        findingCount: 1,
        createdAt: "2026-04-20T00:00:00Z",
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "gate-summary-modern",
        projectId: "p-analysis-summary-agg",
        runId: "run-summary-modern",
        status: "pass",
        createdAt: "2026-04-20T00:00:00Z",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-summary-modern",
        runId: "run-summary-modern",
        projectId: "p-analysis-summary-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        severity: "high",
        status: "open",
        sourceType: "rule-engine",
        ruleId: "RULE-MODERN",
        location: "src/modern.c:10",
        createdAt: "2026-04-20T00:00:00Z",
      }));

      ctx.runDAO.save(makeRun({
        id: "run-summary-legacy",
        projectId: "p-analysis-summary-agg",
        module: "static_analysis",
        status: "completed",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        findingCount: 3,
        createdAt: "2026-04-20T00:00:00Z",
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "gate-summary-legacy",
        projectId: "p-analysis-summary-agg",
        runId: "run-summary-legacy",
        status: "fail",
        createdAt: "2026-04-20T00:00:00Z",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "finding-summary-legacy",
        runId: "run-summary-legacy",
        projectId: "p-analysis-summary-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        severity: "critical",
        status: "open",
        sourceType: "rule-engine",
        ruleId: "RULE-LEGACY",
        location: "src/legacy.c:20",
        createdAt: "2026-03-25T00:00:00Z",
      }));

      const res = await request(app).get("/api/analysis/summary?projectId=p-analysis-summary-agg&period=30d");
      expect(res.status).toBe(200);
      expect(res.body.data.bySeverity).toMatchObject({ high: 1 });
      expect(res.body.data.bySeverity.critical ?? 0).toBe(0);
      expect(res.body.data.topRules).toEqual([{ ruleId: "RULE-MODERN", hitCount: 1 }]);
      expect(res.body.data.gateStats).toMatchObject({ total: 1, passed: 1, failed: 0 });
      expect(res.body.data.trend).toEqual([
        expect.objectContaining({ date: "2026-04-20", runCount: 1, findingCount: 1, gatePassCount: 1 }),
      ]);
    });

    it("POST /api/analysis/poc returns generated PoC payload", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "finding-poc",
        projectId: "p-analysis-poc",
        title: "Buffer overflow",
        description: "Potential overflow in parser",
        detail: "PoC requested",
        location: "src/main.c:42",
      }));

      const res = await request(app)
        .post("/api/analysis/poc")
        .send({ projectId: "p-analysis-poc", findingId: "finding-poc" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        findingId: "finding-poc",
        poc: {
          statement: "demo poc",
          detail: "demo detail",
        },
        pocOutcome: "poc_accepted",
        qualityOutcome: "accepted",
        cleanPass: true,
      });
    });

    it("POST /api/analysis/poc forwards non-clean S3 outcome fields as envelope success", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "finding-poc-non-clean",
        projectId: "p-analysis-poc",
        title: "Command injection",
        description: "Potential command injection",
        detail: "PoC requested",
        location: "src/main.c:42",
      }));
      const nonAcceptedClaims = [
        {
          claimId: "claim-0",
          status: "under_evidenced",
          family: "command_injection",
          primaryLocation: "src/main.c:42",
          rejectionCode: "evidence_missing",
          rejectionReason: "missing required sink evidence",
          statement: "user-controlled input reaches system",
          detail: "repair could not ground the command sink",
          retryCount: 2,
          severity: "high",
          requiredEvidence: ["local_or_derived_support", "sink_or_dangerous_api"],
          presentEvidence: ["local_or_derived_support"],
          missingEvidence: ["sink_or_dangerous_api"],
          evidenceTrail: [
            { evidenceRef: "eref-1", role: "local_or_derived_support", status: "present" },
          ],
          revisionHistory: [
            {
              fromStatus: "candidate",
              toStatus: "under_evidenced",
              reason: "missing:sink_or_dangerous_api",
              timestampMs: 1710000000000,
            },
          ],
          invalidRefs: ["eref-hallucinated"],
          supportingEvidenceRefs: ["eref-1"],
          outcomeContribution: "no_accepted_claims",
        },
        {
          claimId: "claim-1",
          status: "rejected",
          rejectionCode: "rejected_unsupported",
          outcomeContribution: "rejected_unsupported",
        },
      ];
      ctx.agentTaskResponses.push({
        status: "completed",
        result: {
          claims: [],
          pocOutcome: "poc_inconclusive",
          qualityOutcome: "repair_exhausted",
          cleanPass: false,
          claimDiagnostics: {
            lifecycleCounts: { under_evidenced: 1, rejected: 1 },
            nonAcceptedClaims,
          },
        },
        audit: {
          latencyMs: 17,
          tokenUsage: { prompt: 101, completion: 12 },
        },
      });

      const res = await request(app)
        .post("/api/analysis/poc")
        .send({ projectId: "p-analysis-poc", findingId: "finding-poc-non-clean" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        findingId: "finding-poc-non-clean",
        poc: {
          statement: "",
          detail: "",
        },
        audit: {
          latencyMs: 17,
          tokenUsage: { prompt: 101, completion: 12 },
        },
        pocOutcome: "poc_inconclusive",
        qualityOutcome: "repair_exhausted",
        cleanPass: false,
        claimDiagnostics: {
          lifecycleCounts: { under_evidenced: 1, rejected: 1 },
        },
      });
      expect(res.body.data.claimDiagnostics.nonAcceptedClaims).toEqual(nonAcceptedClaims);
    });

    it("POST /api/analysis/poc omits malformed claim diagnostics instead of exposing untyped records", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "finding-poc-invalid-diagnostics",
        projectId: "p-analysis-poc",
        title: "Invalid diagnostics",
        description: "S3 returned malformed optional diagnostics",
      }));
      ctx.agentTaskResponses.push({
        status: "completed",
        result: {
          claims: [],
          pocOutcome: "poc_inconclusive",
          qualityOutcome: "repair_exhausted",
          cleanPass: false,
          claimDiagnostics: {
            lifecycleCounts: { rejected: 1 },
            nonAcceptedClaims: [{ claimId: "claim-without-status" }],
          },
        },
        audit: { latencyMs: 4 },
      });

      const res = await request(app)
        .post("/api/analysis/poc")
        .send({ projectId: "p-analysis-poc", findingId: "finding-poc-invalid-diagnostics" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.claimDiagnostics).toBeUndefined();
    });

    it("POST /api/analysis/poc conservatively derives legacy outcome fields", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "finding-poc-legacy-empty",
        projectId: "p-analysis-poc",
        title: "Legacy empty PoC",
        description: "Legacy response has no accepted claim",
      }));
      ctx.agentTaskResponses.push({
        status: "completed",
        result: {
          claims: [],
        },
        audit: { latencyMs: 3 },
      });

      const res = await request(app)
        .post("/api/analysis/poc")
        .send({ projectId: "p-analysis-poc", findingId: "finding-poc-legacy-empty" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        findingId: "finding-poc-legacy-empty",
        pocOutcome: "poc_inconclusive",
        qualityOutcome: "inconclusive",
        cleanPass: false,
      });
    });
  });

  describe("Dynamic Analysis API", () => {
    it("creates sessions, lists them, and returns predefined scenarios", async () => {
      const createRes = await request(app)
        .post("/api/dynamic-analysis/sessions")
        .send({ projectId: "p-dyn", adapterId: "adapter-1" });

      expect(createRes.status).toBe(201);
      expect(createRes.body.data).toMatchObject({
        projectId: "p-dyn",
        status: "connected",
      });

      const listRes = await request(app).get("/api/dynamic-analysis/sessions?projectId=p-dyn");
      expect(listRes.status).toBe(200);
      expect(listRes.body.data).toHaveLength(1);

      const scenariosRes = await request(app).get("/api/dynamic-analysis/scenarios");
      expect(scenariosRes.status).toBe(200);
      expect(Array.isArray(scenariosRes.body.data)).toBe(true);
      expect(scenariosRes.body.data.length).toBeGreaterThan(0);
    });

    it("starts a session, injects traffic, and exposes injection history", async () => {
      const createRes = await request(app)
        .post("/api/dynamic-analysis/sessions")
        .send({ projectId: "p-dyn-flow", adapterId: "adapter-2" });
      const sessionId = createRes.body.data.id as string;

      const startRes = await request(app).post(`/api/dynamic-analysis/sessions/${sessionId}/start`);
      expect(startRes.status).toBe(200);
      expect(startRes.body.data.status).toBe("monitoring");

      const injectRes = await request(app)
        .post(`/api/dynamic-analysis/sessions/${sessionId}/inject`)
        .send({ canId: "0x7E0", dlc: 8, data: "02 10 03 00 00 00 00 00", label: "single-shot" });
      expect(injectRes.status).toBe(200);
      expect(injectRes.body.data).toMatchObject({
        request: { canId: "0x7E0", dlc: 8 },
        classification: "normal",
      });

      const scenarioRes = await request(app)
        .post(`/api/dynamic-analysis/sessions/${sessionId}/inject-scenario`)
        .send({ scenarioId: "diagnostic-abuse" });
      expect(scenarioRes.status).toBe(200);
      expect(Array.isArray(scenarioRes.body.data)).toBe(true);

      const historyRes = await request(app).get(`/api/dynamic-analysis/sessions/${sessionId}/injections`);
      expect(historyRes.status).toBe(200);
      expect(historyRes.body.data.length).toBeGreaterThanOrEqual(2);
    });

    it("GET /api/dynamic-analysis/sessions/:id returns composite session detail payload (current drift surface)", async () => {
      const createRes = await request(app)
        .post("/api/dynamic-analysis/sessions")
        .send({ projectId: "p-dyn-detail", adapterId: "adapter-3" });
      const sessionId = createRes.body.data.id as string;

      const res = await request(app).get(`/api/dynamic-analysis/sessions/${sessionId}`);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        session: expect.objectContaining({
          id: sessionId,
          projectId: "p-dyn-detail",
        }),
        alerts: [],
        recentMessages: [],
      });
    });

    it("DELETE /api/dynamic-analysis/sessions/:id stops the session", async () => {
      const createRes = await request(app)
        .post("/api/dynamic-analysis/sessions")
        .send({ projectId: "p-dyn-stop", adapterId: "adapter-4" });
      const sessionId = createRes.body.data.id as string;

      const res = await request(app).delete(`/api/dynamic-analysis/sessions/${sessionId}`);
      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({
        id: sessionId,
        status: "stopped",
      });
    });
  });

  describe("Dynamic Test API", () => {
    it("runs a dynamic test and returns collection/detail/delete contracts", async () => {
      const runRes = await request(app)
        .post("/api/dynamic-test/run")
        .send({
          projectId: "p-dtest",
          adapterId: "adapter-1",
          config: {
            testType: "fuzzing",
            strategy: "random",
            targetEcu: "ECM",
            protocol: "UDS",
            targetId: "0x7E0",
            count: 5,
          },
        });

      expect(runRes.status).toBe(200);
      expect(runRes.body.success).toBe(true);
      expect(runRes.body.data).toMatchObject({
        projectId: "p-dtest",
        status: "completed",
        totalRuns: 5,
      });

      const testId = runRes.body.data.id as string;
      const listRes = await request(app).get("/api/dynamic-test/results?projectId=p-dtest");
      expect(listRes.status).toBe(200);
      expect(listRes.body.data).toHaveLength(1);

      const detailRes = await request(app).get(`/api/dynamic-test/results/${testId}`);
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.data.id).toBe(testId);

      const deleteRes = await request(app).delete(`/api/dynamic-test/results/${testId}`);
      expect(deleteRes.status).toBe(200);
      expect(deleteRes.body).toEqual({ success: true });
    });
  });

  // ── Gate Profiles ──

  describe("Gate Profile API", () => {
    it("GET /api/gate-profiles returns 3 profiles", async () => {
      const res = await request(app).get("/api/gate-profiles");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(3);
      expect(res.body.data.map((p: any) => p.id).sort()).toEqual(["default", "relaxed", "strict"]);
    });

    it("GET /api/gate-profiles/:id returns single profile", async () => {
      const res = await request(app).get("/api/gate-profiles/strict");
      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe("strict");
      expect(res.body.data.rules).toBeDefined();
    });

    it("GET /api/gate-profiles/:id returns 404 for unknown", async () => {
      const res = await request(app).get("/api/gate-profiles/nonexistent");
      expect(res.status).toBe(404);
    });
  });

  // ── Notifications ──

  describe("Notification API", () => {
    it("GET /api/projects/:pid/notifications returns list", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-notif" }));
      ctx.notificationService.emit({
        projectId: "p-notif",
        type: "analysis_complete",
        title: "Test",
        jobKind: "analysis",
        resourceId: "run-1",
        correlationId: "analysis-1",
      });

      const res = await request(app).get("/api/projects/p-notif/notifications");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0]).toMatchObject({
        type: "analysis_complete",
        jobKind: "analysis",
        resourceId: "run-1",
        correlationId: "analysis-1",
      });
    });

    it("GET /api/projects/:pid/notifications/count returns unread count", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-notif-c" }));
      ctx.notificationService.emit({ projectId: "p-notif-c", type: "gate_failed", title: "Fail" });
      ctx.notificationService.emit({ projectId: "p-notif-c", type: "critical_finding", title: "Crit" });

      const res = await request(app).get("/api/projects/p-notif-c/notifications/count");
      expect(res.status).toBe(200);
      expect(res.body.data.unread).toBe(2);
    });

    it("PATCH /api/projects/:pid/notifications/read-all marks all read", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-notif-r" }));
      ctx.notificationService.emit({ projectId: "p-notif-r", type: "analysis_complete", title: "A" });
      ctx.notificationService.emit({ projectId: "p-notif-r", type: "gate_failed", title: "B" });

      const res = await request(app).patch("/api/projects/p-notif-r/notifications/read-all");
      expect(res.status).toBe(200);

      const countRes = await request(app).get("/api/projects/p-notif-r/notifications/count");
      expect(countRes.body.data.unread).toBe(0);
    });

    it("PATCH /api/notifications/:id/read marks single read", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-notif-s" }));
      const notif = ctx.notificationService.emit({ projectId: "p-notif-s", type: "analysis_complete", title: "X" });

      const res = await request(app).patch(`/api/notifications/${notif.id}/read`);
      expect(res.status).toBe(200);
    });
  });

  // ── Auth ──

  describe("Auth API", () => {
    it("POST /api/auth/login with valid credentials", async () => {
      ctx.userService.createUser("testuser", "pass1234", "Test User");
      const res = await request(app).post("/api/auth/login").send({ username: "testuser", password: "pass1234" });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.token).toBeDefined();
      expect(res.body.data.expiresAt).toBeDefined();
      expect(res.body.data.user.username).toBe("testuser");
    });

    it("POST /api/auth/login honors rememberMe session policy", async () => {
      ctx.userService.createUser("remember", "pass1234", "Remember User");
      const normal = await request(app).post("/api/auth/login").send({ username: "remember", password: "pass1234" });
      const remembered = await request(app).post("/api/auth/login").send({ username: "remember", password: "pass1234", rememberMe: true });

      expect(normal.status).toBe(200);
      expect(remembered.status).toBe(200);
      expect(new Date(remembered.body.data.expiresAt).getTime()).toBeGreaterThan(new Date(normal.body.data.expiresAt).getTime());
    });

    it("POST /api/auth/login with invalid credentials", async () => {
      ctx.userService.createUser("testuser2", "pass1234", "Test User 2");
      const res = await request(app).post("/api/auth/login").send({ username: "testuser2", password: "wrong" });
      expect(res.status).toBe(400);
    });

    it("POST /api/auth/login returns 429 after repeated failed attempts", async () => {
      ctx.userService.createUser("throttle-user", "pass1234", "Throttle User");
      for (let i = 0; i < 10; i += 1) {
        const res = await request(app).post("/api/auth/login").send({ username: "throttle-user", password: "wrong" });
        expect(res.status).toBe(400);
      }
      const limited = await request(app).post("/api/auth/login").send({ username: "throttle-user", password: "wrong" });
      expect(limited.status).toBe(429);
      expect(limited.body.errorDetail.code).toBe("RATE_LIMITED");
    });

    it("GET /api/auth/users requires admin token", async () => {
      ctx.organizationDAO.save({
        id: "org-auth",
        code: "AUTH-ORG",
        name: "Auth Org",
        region: "kr-seoul-1",
        defaultRole: "viewer",
        adminDisplayName: "Org Admin",
        adminEmail: "admin@auth.org",
      });
      ctx.userService.createUser("user1", "pass1234", "User 1", "analyst", {
        email: "user1@auth.org",
        organizationId: "org-auth",
      });
      ctx.userService.createUser("orgadmin", "pass1234", "Org Admin", "admin", {
        email: "admin@auth.org",
        organizationId: "org-auth",
      });
      const login = await request(app).post("/api/auth/login").send({ username: "orgadmin", password: "pass1234" });
      const res = await request(app)
        .get("/api/auth/users")
        .set("Authorization", `Bearer ${login.body.data.token}`);

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });

    it("GET /api/auth/orgs/:code/verify returns org preview", async () => {
      ctx.organizationDAO.save({
        id: "org-verify",
        code: "VERIFY-ORG",
        name: "Verify Org",
        region: "kr-seoul-1",
        defaultRole: "viewer",
        adminDisplayName: "Verifier",
        adminEmail: "verify@org.kr",
      });

      const res = await request(app).get("/api/auth/orgs/VERIFY-ORG/verify");
      expect(res.status).toBe(200);
      expect(res.body.data.name).toBe("Verify Org");
      expect(res.body.data.admin.email).toBe("verify@org.kr");
    });

    it("POST /api/auth/register returns lookup token and lookup API resolves status", async () => {
      ctx.organizationDAO.save({
        id: "org-register",
        code: "REGISTER-ORG",
        name: "Register Org",
        region: "kr-seoul-1",
        defaultRole: "viewer",
        adminDisplayName: "Reg Admin",
        adminEmail: "reg@org.kr",
      });

      const registerRes = await request(app).post("/api/auth/register").send({
        fullName: "Bob Member",
        email: "bob@org.kr",
        password: "Passw0rd!",
        orgCode: "REGISTER-ORG",
        termsAcceptedAt: new Date().toISOString(),
        auditAcceptedAt: new Date().toISOString(),
      });

      expect(registerRes.status).toBe(202);
      expect(registerRes.body.data.lookupToken).toBeDefined();

      const lookupRes = await request(app).get(`/api/auth/registrations/lookup/${registerRes.body.data.lookupToken}`);
      expect(lookupRes.status).toBe(200);
      expect(lookupRes.body.data.status).toBe("pending_admin_review");
      expect(lookupRes.body.data.email).toBe("bob@org.kr");
      expect(lookupRes.body.data.fullName).toBe("Bob Member");
      expect(lookupRes.body.data.organizationId).toBe("org-register");
      expect(lookupRes.body.data.organizationCode).toBe("REGISTER-ORG");
      expect(lookupRes.body.data.organizationName).toBe("Register Org");
      expect(lookupRes.body.data.createdAt).toBeDefined();
      expect(lookupRes.body.data.lookupExpiresAt).toBeDefined();

      const rawIdRes = await request(app).get(`/api/auth/registrations/lookup/${registerRes.body.data.registrationId}`);
      expect(rawIdRes.status).toBe(404);
    });

    it("admin can approve same-org registration and user can login immediately", async () => {
      ctx.organizationDAO.save({
        id: "org-approve",
        code: "APPROVE-ORG",
        name: "Approve Org",
        region: "kr-seoul-1",
        defaultRole: "viewer",
        adminDisplayName: "Approve Admin",
        adminEmail: "approve@org.kr",
      });
      ctx.userService.createUser("approve-admin", "pass1234", "Approve Admin", "admin", {
        email: "approve@org.kr",
        organizationId: "org-approve",
      });

      const registerRes = await request(app).post("/api/auth/register").send({
        fullName: "Alice Member",
        email: "alice@approve.org",
        password: "Passw0rd!",
        orgCode: "APPROVE-ORG",
        termsAcceptedAt: new Date().toISOString(),
        auditAcceptedAt: new Date().toISOString(),
      });
      const adminLogin = await request(app).post("/api/auth/login").send({ username: "approve-admin", password: "pass1234" });
      const approveRes = await request(app)
        .post(`/api/auth/registration-requests/${registerRes.body.data.registrationId}/approve`)
        .set("Authorization", `Bearer ${adminLogin.body.data.token}`)
        .send({ role: "analyst" });

      expect(approveRes.status).toBe(200);
      expect(approveRes.body.data.status).toBe("approved");
      expect(approveRes.body.data.fullName).toBe("Alice Member");
      expect(approveRes.body.data.organizationId).toBe("org-approve");
      expect(approveRes.body.data.organizationCode).toBe("APPROVE-ORG");
      expect(approveRes.body.data.organizationName).toBe("Approve Org");
      expect(approveRes.body.data.assignedRole).toBe("analyst");
      expect(approveRes.body.data.approvedAt).toBeDefined();
      expect(approveRes.body.data.createdAt).toBeDefined();
      expect(approveRes.body.data.lookupExpiresAt).toBeDefined();

      const memberLogin = await request(app).post("/api/auth/login").send({ username: "alice@approve.org", password: "Passw0rd!" });
      expect(memberLogin.status).toBe(200);
      expect(memberLogin.body.data.user.role).toBe("analyst");
    });

    it("admin reject returns full registration request shape", async () => {
      ctx.organizationDAO.save({
        id: "org-reject",
        code: "REJECT-ORG",
        name: "Reject Org",
        region: "kr-seoul-1",
        defaultRole: "viewer",
        adminDisplayName: "Reject Admin",
        adminEmail: "reject@org.kr",
      });
      ctx.userService.createUser("reject-admin", "pass1234", "Reject Admin", "admin", {
        email: "reject@org.kr",
        organizationId: "org-reject",
      });

      const registerRes = await request(app).post("/api/auth/register").send({
        fullName: "Reject Member",
        email: "member@reject.org",
        password: "Passw0rd!",
        orgCode: "REJECT-ORG",
        termsAcceptedAt: new Date().toISOString(),
        auditAcceptedAt: new Date().toISOString(),
      });
      const adminLogin = await request(app).post("/api/auth/login").send({ username: "reject-admin", password: "pass1234" });
      const rejectRes = await request(app)
        .post(`/api/auth/registration-requests/${registerRes.body.data.registrationId}/reject`)
        .set("Authorization", `Bearer ${adminLogin.body.data.token}`)
        .send({ reason: "Not in scope" });

      expect(rejectRes.status).toBe(200);
      expect(rejectRes.body.data).toMatchObject({
        status: "rejected",
        fullName: "Reject Member",
        email: "member@reject.org",
        organizationId: "org-reject",
        organizationCode: "REJECT-ORG",
        organizationName: "Reject Org",
        decisionReason: "Not in scope",
      });
      expect(rejectRes.body.data.rejectedAt).toBeDefined();
      expect(rejectRes.body.data.createdAt).toBeDefined();
      expect(rejectRes.body.data.lookupExpiresAt).toBeDefined();
    });

    it("password reset request is non-enumerating and confirm resets password", async () => {
      ctx.userService.createUser("reset-user", "pass1234", "Reset User", "analyst", { email: "reset@org.kr" });

      const known = await request(app).post("/api/auth/password-reset/request").send({ email: "reset@org.kr" });
      const unknown = await request(app).post("/api/auth/password-reset/request").send({ email: "nobody@org.kr" });
      expect(known.status).toBe(202);
      expect(unknown.status).toBe(202);
      expect(known.body).toEqual(unknown.body);

      const issued = ctx.userService.requestPasswordReset("reset@org.kr", "127.0.0.1");
      const confirm = await request(app).post("/api/auth/password-reset/confirm").send({
        token: issued.token,
        newPassword: "NewPassw0rd!",
      });
      expect(confirm.status).toBe(200);

      const oldLogin = await request(app).post("/api/auth/login").send({ username: "reset-user", password: "pass1234" });
      const newLogin = await request(app).post("/api/auth/login").send({ username: "reset-user", password: "NewPassw0rd!" });
      expect(oldLogin.status).toBe(400);
      expect(newLogin.status).toBe(200);
    });

    it("GET /api/auth/dev/password-reset/latest exposes the latest dev reset token for mock bridging", async () => {
      ctx.userService.createUser("dev-reset-user", "pass1234", "Dev Reset User", "analyst", { email: "dev-reset@org.kr" });

      const requestRes = await request(app).post("/api/auth/password-reset/request").send({ email: "dev-reset@org.kr" });
      expect(requestRes.status).toBe(202);

      const latest = await request(app).get("/api/auth/dev/password-reset/latest").query({ email: "dev-reset@org.kr" });
      expect(latest.status).toBe(200);
      expect(latest.body.data.available).toBe(true);
      expect(latest.body.data.delivery.email).toBe("dev-reset@org.kr");
      expect(latest.body.data.delivery.token).toBeTruthy();

      const absent = await request(app).get("/api/auth/dev/password-reset/latest").query({ email: "missing@org.kr" });
      expect(absent.status).toBe(200);
      expect(absent.body.data).toEqual({ available: false });
    });

    it("GET /api/auth/me without token returns 401 or empty", async () => {
      const res = await request(app).get("/api/auth/me");
      // Soft auth: no token → no user → 401
      expect([200, 401]).toContain(res.status);
    });

    it("POST /api/auth/logout returns { success: true }", async () => {
      const res = await request(app).post("/api/auth/logout");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
    });
  });

  // ── Finding Groups ──

  describe("Finding Groups API", () => {
    it("GET /findings/groups?groupBy=ruleId", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-fg" }));
      ctx.runDAO.save(makeRun({ id: "r-fg", projectId: "p-fg" }));
      ctx.findingDAO.save(makeFinding({ id: "f-fg1", runId: "r-fg", projectId: "p-fg", ruleId: "rule-X" }));
      ctx.findingDAO.save(makeFinding({ id: "f-fg2", runId: "r-fg", projectId: "p-fg", ruleId: "rule-X" }));

      const res = await request(app).get("/api/projects/p-fg/findings/groups?groupBy=ruleId");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });

    it("GET /findings/groups?groupBy=location", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-fg2" }));
      ctx.runDAO.save(makeRun({ id: "r-fg2", projectId: "p-fg2" }));
      ctx.findingDAO.save(makeFinding({ id: "f-fg3", runId: "r-fg2", projectId: "p-fg2", location: "src/a.c:1" }));

      const res = await request(app).get("/api/projects/p-fg2/findings/groups?groupBy=location");
      expect(res.status).toBe(200);
    });
  });

  describe("Finding Summary API", () => {
    it("GET /api/projects/:pid/findings/summary returns aggregate counts", async () => {
      ctx.findingDAO.save(makeFinding({ id: "fsum-1", projectId: "p-fsum", severity: "critical", status: "open" }));
      ctx.findingDAO.save(makeFinding({ id: "fsum-2", projectId: "p-fsum", severity: "high", status: "fixed" }));

      const res = await request(app).get("/api/projects/p-fsum/findings/summary");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        total: 2,
        byStatus: {
          open: 1,
          fixed: 1,
        },
        bySeverity: {
          critical: 1,
          high: 1,
        },
      });
    });

    it("GET /api/projects/:pid/findings/summary hides legacy static/deep findings without full lineage", async () => {
      ctx.findingDAO.save(makeFinding({
        id: "fsum-modern",
        projectId: "p-fsum-agg",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
        severity: "high",
        status: "open",
      }));
      ctx.findingDAO.save(makeFinding({
        id: "fsum-legacy",
        projectId: "p-fsum-agg",
        module: "static_analysis",
        buildTargetId: undefined,
        analysisExecutionId: undefined,
        severity: "critical",
        status: "open",
      }));

      const res = await request(app).get("/api/projects/p-fsum-agg/findings/summary");
      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({
        total: 1,
        bySeverity: {
          high: 1,
        },
      });
      expect(res.body.data.bySeverity.critical ?? 0).toBe(0);
    });
  });

  describe("Gate detail APIs", () => {
    it("GET /api/projects/:pid/gates/runs/:runId returns the gate result for a run", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-gate-detail",
        projectId: "p-gate-run",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-run-detail", projectId: "p-gate-run", runId: "run-gate-detail", status: "fail" }));

      const res = await request(app).get("/api/projects/p-gate-run/gates/runs/run-gate-detail");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.id).toBe("gate-run-detail");
    });

    it("POST /api/gates/:id/override creates an approval request", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-gate-override",
        projectId: "p-gate-override",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({ id: "gate-override", projectId: "p-gate-override", runId: "run-gate-override", status: "fail" }));

      const res = await request(app)
        .post("/api/gates/gate-override/override")
        .send({ reason: "accepted operational risk", actor: "admin" });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        actionType: "gate.override",
        targetId: "gate-override",
        projectId: "p-gate-override",
        status: "pending",
        impactSummary: expect.objectContaining({ failedRules: expect.any(Number), ignoredFindings: expect.any(Number) }),
        targetSnapshot: expect.objectContaining({ runId: "run-gate-override", action: "gate.override" }),
      });
    });
  });

  describe("Approval detail API", () => {
    it("GET /api/approvals/:id returns approval detail", async () => {
      ctx.runDAO.save(makeRun({
        id: "run-approval-detail",
        projectId: "p-approval-detail",
        module: "static_analysis",
        buildTargetId: "t-modern",
        analysisExecutionId: "exec-modern",
      }));
      ctx.gateResultDAO.save(makeGateResult({
        id: "gate-1",
        projectId: "p-approval-detail",
        runId: "run-approval-detail",
      }));
      ctx.approvalDAO.save(makeApproval({ id: "approval-detail", projectId: "p-approval-detail", targetId: "gate-1" }));

      const res = await request(app).get("/api/approvals/approval-detail");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        id: "approval-detail",
        projectId: "p-approval-detail",
        targetId: "gate-1",
      });
    });
  });

  // ── Build Log ──

  describe("Build Log API", () => {
    it("GET /targets/:id/build-log returns log", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bl" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t-bl", projectId: "p-bl", buildLog: "make: ok" } as any));

      const res = await request(app).get("/api/projects/p-bl/targets/t-bl/build-log");
      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty("buildLog");
    });

    it("GET /targets/:id/build-log returns 404 for unknown target", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-bl2" }));
      const res = await request(app).get("/api/projects/p-bl2/targets/nonexistent/build-log");
      expect(res.status).toBe(404);
    });
  });

  describe("Target Library API", () => {
    it("GET and PATCH /api/projects/:pid/targets/:tid/libraries follow the documented contract", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-lib" }));
      ctx.buildTargetDAO.save(makeBuildTarget({ id: "t-lib", projectId: "p-lib" }));
      ctx.targetLibraryDAO.upsertFromScan("t-lib", "p-lib", [
        { name: "openssl", version: "3.0.0", path: "third_party/openssl", modifiedFiles: ["src/main.c"] },
        { name: "zlib", version: "1.2.13", path: "third_party/zlib", modifiedFiles: [] },
      ]);

      const listRes = await request(app).get("/api/projects/p-lib/targets/t-lib/libraries");
      expect(listRes.status).toBe(200);
      expect(listRes.body.success).toBe(true);
      expect(listRes.body.data).toHaveLength(2);

      const firstId = listRes.body.data[0].id as string;
      const patchRes = await request(app)
        .patch("/api/projects/p-lib/targets/t-lib/libraries")
        .send({ libraries: [{ id: firstId, included: true }] });

      expect(patchRes.status).toBe(200);
      expect(patchRes.body.data).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ id: firstId, included: true }),
        ]),
      );
    });
  });

  // ── Custom Report ──

  describe("Custom Report API", () => {
    it("POST /report/custom returns filtered report", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-cr" }));

      const res = await request(app)
        .post("/api/projects/p-cr/report/custom")
        .send({ customization: { reportTitle: "Custom" } });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe("Module Report APIs", () => {
    it("GET /api/projects/:pid/report/dynamic returns dynamic-analysis module report", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-report-dynamic", name: "Dynamic Report" }));
      ctx.runDAO.save(makeRun({ id: "run-report-dynamic", projectId: "p-report-dynamic", module: "dynamic_analysis" }));
      ctx.findingDAO.save(makeFinding({ id: "finding-report-dynamic", runId: "run-report-dynamic", projectId: "p-report-dynamic", module: "dynamic_analysis" }));

      const res = await request(app).get("/api/projects/p-report-dynamic/report/dynamic");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.meta.module).toBe("dynamic_analysis");
    });

    it("GET /api/projects/:pid/report/test returns dynamic-testing module report", async () => {
      ctx.projectDAO.save(makeProject({ id: "p-report-test", name: "Test Report" }));
      ctx.runDAO.save(makeRun({ id: "run-report-test", projectId: "p-report-test", module: "dynamic_testing" }));
      ctx.findingDAO.save(makeFinding({ id: "finding-report-test", runId: "run-report-test", projectId: "p-report-test", module: "dynamic_testing" }));

      const res = await request(app).get("/api/projects/p-report-test/report/test");
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.meta.module).toBe("dynamic_testing");
    });
  });
});
