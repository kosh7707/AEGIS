/**
 * Centralized mock data for Playwright E2E tests.
 * All data matches @aegis/shared types and uses Korean labels.
 */

// ── Projects ──

export const PROJECTS = [
  {
    id: "p-1",
    name: "차량 게이트웨이 ECU",
    description: "차량용 게이트웨이 ECU 보안 분석 프로젝트",
    createdAt: "2026-03-01T09:00:00Z",
    updatedAt: "2026-03-27T14:30:00Z",
    lastAnalysisAt: "2026-03-25T10:02:30Z",
    severitySummary: { critical: 1, high: 2, medium: 1, low: 1 },
    gateStatus: "fail" as const,
    unresolvedDelta: 2,
    pendingApprovals: 2,
    owner: "김",
    ownerName: "Kim",
    lang: "c" as const,
    metaLabel: "ECU · AUTOSAR Classic",
  },
  {
    id: "p-2",
    name: "바디 컨트롤 모듈",
    description: "BCM 펌웨어 보안 검증",
    createdAt: "2026-03-10T09:00:00Z",
    updatedAt: "2026-03-25T11:00:00Z",
    lastAnalysisAt: "2026-03-25T11:00:00Z",
    severitySummary: { critical: 0, high: 1, medium: 2, low: 0 },
    gateStatus: "running" as const,
    unresolvedDelta: -1,
    pendingApprovals: 1,
    owner: "박",
    ownerName: "Park",
    lang: "cpp" as const,
    metaLabel: "BMS · CAN-FD",
  },
];

// ── Files ──

export const FILES = [
  { id: "f-1", name: "main.c", size: 15420, language: "c", projectId: "p-1", path: "src/main.c", createdAt: "2026-03-15T10:00:00Z" },
  { id: "f-2", name: "gateway.c", size: 28300, language: "c", projectId: "p-1", path: "src/gateway.c", createdAt: "2026-03-15T10:00:00Z" },
  { id: "f-3", name: "can_handler.h", size: 4200, language: "c", projectId: "p-1", path: "include/can_handler.h", createdAt: "2026-03-15T10:00:00Z" },
  { id: "f-4", name: "auth.c", size: 9800, language: "c", projectId: "p-1", path: "src/auth.c", createdAt: "2026-03-15T10:00:00Z" },
  { id: "f-5", name: "crypto_utils.c", size: 12500, language: "c", projectId: "p-1", path: "src/crypto_utils.c", createdAt: "2026-03-15T10:00:00Z" },
];

// ── Findings ──

export const FINDINGS = [
  {
    id: "find-1", runId: "run-1", projectId: "p-1", module: "static_analysis",
    status: "open", severity: "critical", confidence: "high", sourceType: "agent",
    title: "버퍼 오버플로우 - CAN 메시지 처리",
    description: "CAN 메시지 파싱 시 입력 길이를 검증하지 않아 스택 버퍼 오버플로우 발생 가능",
    location: "src/can_handler.c:142", suggestion: "입력 길이 검증 추가",
    fingerprint: "a1b2c3d4e5f60001",
    cweId: "CWE-120", cveIds: ["CVE-2026-0001"], confidenceScore: 0.92,
    detail: "CAN 프레임 수신 시 DLC 필드를 검증하지 않고 memcpy를 수행합니다. 공격자가 조작된 CAN 프레임(DLC > 8)을 전송하면 스택 버퍼가 오버플로우되어 제어 흐름을 탈취할 수 있습니다.",
    createdAt: "2026-03-25T10:00:00Z", updatedAt: "2026-03-25T10:00:00Z",
  },
  {
    id: "find-2", runId: "run-1", projectId: "p-1", module: "static_analysis",
    status: "needs_review", severity: "high", confidence: "medium", sourceType: "sast-tool",
    title: "하드코딩된 인증키",
    description: "소스 코드에 인증키가 하드코딩되어 있습니다",
    location: "src/auth.c:55", ruleId: "CWE-798", suggestion: "환경 변수 또는 키 저장소 사용",
    fingerprint: "a1b2c3d4e5f60002",
    cweId: "CWE-798", confidenceScore: 0.78,
    createdAt: "2026-03-25T10:01:00Z", updatedAt: "2026-03-25T10:01:00Z",
  },
  {
    id: "find-3", runId: "run-1", projectId: "p-1", module: "static_analysis",
    status: "open", severity: "medium", confidence: "high", sourceType: "rule-engine",
    title: "안전하지 않은 메모리 할당",
    description: "malloc 반환값 검증 없이 사용",
    location: "src/gateway.c:88", ruleId: "CWE-252",
    fingerprint: "a1b2c3d4e5f60003",
    cweId: "CWE-252", confidenceScore: 0.95,
    createdAt: "2026-03-25T10:02:00Z", updatedAt: "2026-03-25T10:02:00Z",
  },
  {
    id: "find-4", runId: "run-1", projectId: "p-1", module: "deep_analysis",
    status: "sandbox", severity: "high", confidence: "low", sourceType: "llm-assist",
    title: "경쟁 조건 가능성 - 타이머 핸들러",
    description: "인터럽트 핸들러에서 공유 변수를 비원자적으로 접근",
    location: "src/main.c:203",
    fingerprint: "a1b2c3d4e5f60004",
    confidenceScore: 0.45,
    createdAt: "2026-03-26T09:00:00Z", updatedAt: "2026-03-26T09:00:00Z",
  },
  {
    id: "find-5", runId: "run-2", projectId: "p-1", module: "static_analysis",
    status: "fixed", severity: "low", confidence: "high", sourceType: "sast-tool",
    title: "미사용 변수",
    description: "선언된 변수가 사용되지 않습니다",
    location: "src/crypto_utils.c:22", ruleId: "CWE-561",
    fingerprint: "a1b2c3d4e5f60005",
    cweId: "CWE-561", confidenceScore: 0.99,
    createdAt: "2026-03-24T08:00:00Z", updatedAt: "2026-03-26T12:00:00Z",
  },
];

// ── Runs ──

export const RUNS = [
  {
    id: "run-1", projectId: "p-1", module: "static_analysis",
    status: "completed", analysisResultId: "ar-1", findingCount: 4,
    startedAt: "2026-03-25T09:55:00Z", endedAt: "2026-03-25T10:02:30Z",
    createdAt: "2026-03-25T09:55:00Z",
  },
  {
    id: "run-2", projectId: "p-1", module: "static_analysis",
    status: "completed", analysisResultId: "ar-2", findingCount: 1,
    startedAt: "2026-03-24T07:55:00Z", endedAt: "2026-03-24T08:01:00Z",
    createdAt: "2026-03-24T07:55:00Z",
  },
];

// ── Build Targets ──

export const TARGETS = [
  {
    id: "t-1", projectId: "p-1", name: "gateway-main",
    relativePath: "gateway/", includedPaths: ["src/", "include/"],
    buildProfile: { sdkId: "none", compiler: "arm-none-eabi-gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" as const },
    status: "ready", createdAt: "2026-03-20T10:00:00Z", updatedAt: "2026-03-25T10:00:00Z",
  },
  {
    id: "t-2", projectId: "p-1", name: "crypto-lib",
    relativePath: "crypto/", includedPaths: ["src/crypto_utils.c"],
    buildProfile: { sdkId: "none", compiler: "arm-none-eabi-gcc", targetArch: "arm", languageStandard: "c11", headerLanguage: "c" as const },
    status: "building", createdAt: "2026-03-20T10:00:00Z", updatedAt: "2026-03-27T09:00:00Z",
  },
];

// ── Quality Gates ──

export const GATES = [
  {
    id: "gate-1", runId: "run-1", projectId: "p-1", status: "fail",
    rules: [
      { ruleId: "no-critical", result: "failed", message: "Critical 취약점 1건 존재", linkedFindingIds: ["find-1"] },
      { ruleId: "high-threshold", result: "warning", message: "High 취약점 2건 (임계값: 3)", linkedFindingIds: ["find-2", "find-4"] },
      { ruleId: "evidence-coverage", result: "passed", message: "증적 커버리지 85%", linkedFindingIds: [] },
      { ruleId: "sandbox-unreviewed", result: "failed", message: "미검토 Sandbox Finding 1건", linkedFindingIds: ["find-4"] },
    ],
    evaluatedAt: "2026-03-25T10:03:00Z", createdAt: "2026-03-25T10:03:00Z",
  },
];

// ── Helpers ──

/** Generate an ISO date string `days` into the future. Avoids hardcoded date time-bombs in mock data. */
export const futureDate = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

// ── Approvals ──

export const APPROVALS = [
  {
    id: "appr-1", actionType: "gate.override", requestedBy: "analyst",
    targetId: "gate-1", projectId: "p-1",
    reason: "긴급 릴리스 대응 — Critical 취약점은 핫픽스 예정",
    status: "pending", expiresAt: futureDate(365),
    createdAt: "2026-03-25T11:00:00Z",
  },
  {
    id: "appr-2", actionType: "finding.accepted_risk", requestedBy: "analyst",
    targetId: "find-2", projectId: "p-1",
    reason: "테스트 환경 전용 키 — 프로덕션에서는 별도 키 관리 시스템 사용",
    status: "approved",
    decision: { decidedBy: "lead", decidedAt: "2026-03-26T09:00:00Z", comment: "확인 완료" },
    expiresAt: futureDate(365),
    createdAt: "2026-03-25T12:00:00Z",
  },
];

// ── Activities ──

export const ACTIVITIES = [
  {
    type: "run_completed",
    timestamp: "2026-03-25T10:02:30Z",
    summary: "정적 분석 완료",
    metadata: {
      projectId: "p-1",
      projectName: "motor-control-unit",
      variant: "analysis_completed",
      critical: 14,
      high: 23,
      runId: "run-1",
    },
  },
  {
    type: "pipeline_completed",
    timestamp: "2026-03-25T09:59:30Z",
    summary: "Quality Gate BLOCKED",
    metadata: {
      projectId: "p-1",
      projectName: "motor-control-unit",
      variant: "gate_blocked",
      blockedRules: 3,
      totalRules: 7,
    },
  },
  {
    type: "run_completed",
    timestamp: "2026-03-27T09:00:00Z",
    summary: "정적 분석 시작",
    metadata: {
      projectId: "p-2",
      projectName: "bms-gateway-fw",
      variant: "analysis_started",
      tone: "primary",
      icon: "play",
      agent: "taint-flow",
    },
  },
  {
    type: "approval_decided",
    timestamp: "2026-03-26T09:00:00Z",
    summary: "하드코딩 키 위험 수용 승인",
    metadata: {
      projectId: "p-3",
      projectName: "adas-perception-rt",
      variant: "accepted_risk",
      actor: "박지은",
      findingId: "F-4021",
      approvalId: "appr-2",
    },
  },
  {
    type: "source_uploaded",
    timestamp: "2026-03-26T08:46:00Z",
    summary: "빌드 타깃 QNX 7.1 추가",
    metadata: {
      projectId: "p-4",
      projectName: "infotainment-ivi",
      variant: "build_target_added",
      targetName: "QNX 7.1",
    },
  },
  {
    type: "run_completed",
    timestamp: "2026-03-26T08:00:00Z",
    summary: "동적 테스트 통과",
    metadata: {
      projectId: "p-5",
      projectName: "ota-update-service",
      variant: "dynamic_test_passed",
      passed: 120,
      total: 120,
    },
  },
  {
    type: "approval_decided",
    timestamp: "2026-03-26T07:00:00Z",
    summary: "승인 요청 제출",
    metadata: {
      projectId: "p-6",
      projectName: "v2x-stack-dsrc",
      variant: "approval_requested",
      actor: "이준호",
      approvalId: "A-209",
    },
  },
  {
    type: "finding_status_changed",
    timestamp: "2026-03-26T06:00:00Z",
    summary: "재검증 필요",
    metadata: {
      projectId: "p-9",
      projectName: "hypervisor-arm",
      variant: "needs_revalidation",
      findingId: "F-3880",
      findingStatus: "needs-revalidation",
    },
  },
  {
    type: "run_completed",
    timestamp: "2026-03-25T22:00:00Z",
    summary: "정적 분석 완료 · 신규 없음",
    metadata: {
      projectId: "p-7",
      projectName: "telematics-edge",
      variant: "analysis_completed",
      critical: 0,
      high: 0,
    },
  },
];

// ── Overview ──

/** Pattern A: fetchProjectOverview returns apiFetch result directly (no .data extraction) */
export function projectOverview(projectId: string) {
  return {
    project: PROJECTS.find((p) => p.id === projectId) ?? PROJECTS[0],
    fileCount: FILES.length,
    summary: {
      totalVulnerabilities: FINDINGS.length,
      bySeverity: { total: 5, critical: 1, high: 2, medium: 1, low: 1, info: 0 },
      byModule: { static: 4, dynamic: 0, test: 0 },
    },
    targetSummary: { total: 2, ready: 1, failed: 0, running: 1, discovered: 0 },
    recentAnalyses: ANALYSIS_RESULTS,
    trend: { newFindings: 2, resolvedFindings: 1, unresolvedTotal: 4 },
  };
}

// ── Dashboard Summary ──

export const DASHBOARD_SUMMARY = {
  success: true,
  data: {
    bySeverity: { critical: 1, high: 2, medium: 1, low: 1, info: 0 },
    byStatus: { open: 2, needs_review: 1, sandbox: 1, fixed: 1 },
    bySource: { agent: 1, "sast-tool": 2, "rule-engine": 1, "llm-assist": 1 },
    topFiles: [
      { filePath: "src/can_handler.c", findingCount: 1, topSeverity: "critical" },
      { filePath: "src/auth.c", findingCount: 1, topSeverity: "high" },
    ],
    topRules: [
      { ruleId: "CWE-798", hitCount: 1 },
      { ruleId: "CWE-252", hitCount: 1 },
    ],
    trend: [
      { date: "2026-03-24", runCount: 1, findingCount: 1, gatePassCount: 1 },
      { date: "2026-03-25", runCount: 1, findingCount: 4, gatePassCount: 0 },
    ],
    gateStats: { total: 1, passed: 0, failed: 1, rate: 0 },
    unresolvedCount: { open: 2, needsReview: 1, needsRevalidation: 0, sandbox: 1 },
  },
};

// ── Source File Entries (SourceFileEntry shape for FilesPage) ──

export const SOURCE_FILE_ENTRIES = [
  { relativePath: "src/main.c", size: 15420, language: "c", fileType: "source" as const, previewable: true },
  { relativePath: "src/gateway.c", size: 28300, language: "c", fileType: "source" as const, previewable: true },
  { relativePath: "include/can_handler.h", size: 4200, language: "c", fileType: "source" as const, previewable: true },
  { relativePath: "src/auth.c", size: 9800, language: "c", fileType: "source" as const, previewable: true },
  { relativePath: "src/crypto_utils.c", size: 12500, language: "c", fileType: "source" as const, previewable: true },
];

/** Pattern A: fetchSourceFilesWithComposition returns apiFetch result directly */
export const SOURCE_FILES_RESPONSE = {
  success: true,
  data: SOURCE_FILE_ENTRIES,
  composition: { c: { count: 5, bytes: 70220 } },
  totalFiles: 5,
  totalSize: 70220,
  targetMapping: {
    "src/main.c": { targetId: "t-1", targetName: "gateway-main" },
    "src/gateway.c": { targetId: "t-1", targetName: "gateway-main" },
    "include/can_handler.h": { targetId: "t-1", targetName: "gateway-main" },
    "src/crypto_utils.c": { targetId: "t-2", targetName: "crypto-lib" },
  },
};

// ── Vulnerabilities (for VulnerabilitiesPage via AnalysisResult) ──

export const VULNERABILITIES = [
  { id: "vuln-1", severity: "critical" as const, title: "버퍼 오버플로우 - CAN 메시지 처리",
    description: "CAN 메시지 파싱 시 입력 길이를 검증하지 않아 스택 버퍼 오버플로우 발생 가능",
    location: "src/can_handler.c:142", source: "rule" as const, ruleId: "CWE-120" },
  { id: "vuln-2", severity: "high" as const, title: "하드코딩된 인증키",
    description: "소스 코드에 인증키가 하드코딩되어 있습니다",
    location: "src/auth.c:55", source: "rule" as const, ruleId: "CWE-798" },
  { id: "vuln-3", severity: "medium" as const, title: "안전하지 않은 메모리 할당",
    description: "malloc 반환값 검증 없이 사용",
    location: "src/gateway.c:88", source: "rule" as const, ruleId: "CWE-252" },
  { id: "vuln-4", severity: "low" as const, title: "미사용 변수",
    description: "선언된 변수가 사용되지 않습니다",
    location: "src/crypto_utils.c:22", source: "rule" as const, ruleId: "CWE-561" },
];

export const ANALYSIS_RESULTS = [{
  id: "ar-1", projectId: "p-1", module: "static_analysis" as const, status: "completed" as const,
  vulnerabilities: VULNERABILITIES,
  summary: { total: 4, critical: 1, high: 1, medium: 1, low: 1, info: 0 },
  createdAt: "2026-03-25T10:00:00Z",
}];

// ── Report ──

export const PROJECT_REPORT = {
  success: true,
  data: {
    generatedAt: "2026-03-27T15:00:00Z",
    projectId: "p-1",
    projectName: "차량 게이트웨이 ECU",
    modules: {
      static: {
        meta: { generatedAt: "2026-03-27T15:00:00Z", projectId: "p-1", projectName: "차량 게이트웨이 ECU", module: "static_analysis" },
        summary: {
          totalFindings: 4, bySeverity: { critical: 1, high: 1, medium: 1, low: 1 },
          byStatus: { open: 2, needs_review: 1, fixed: 1 }, bySource: { agent: 1, "sast-tool": 2, "rule-engine": 1 },
        },
        runs: [{ run: RUNS[0] }],
        findings: FINDINGS.filter((f) => f.module === "static_analysis").map((f) => ({ finding: f, evidenceRefs: [] })),
        gateResults: GATES,
      },
    },
    totalSummary: {
      totalFindings: 5, bySeverity: { critical: 1, high: 2, medium: 1, low: 1 },
      byStatus: { open: 2, needs_review: 1, sandbox: 1, fixed: 1 }, bySource: { agent: 1, "sast-tool": 2, "rule-engine": 1, "llm-assist": 1 },
    },
    approvals: APPROVALS,
    auditTrail: [],
  },
};

// ── Health ──

export const HEALTH_OK = {
  service: "aegis-backend",
  status: "ok",
  version: "0.7.0",
  detail: { version: "0.7.0", uptime: 3661 },
};

// ── Analysis Status (active analyses) ──

export const ANALYSIS_STATUS_EMPTY = { success: true, data: [] };

// ── Approvals Count ──

export const APPROVAL_COUNT = { success: true, data: { pending: 1, total: 2 } };

// ── Gate Profiles ──

export const GATE_PROFILES = [
  {
    id: "gp-default", name: "기본", description: "표준 게이트 프로파일",
    rules: [
      { ruleId: "no-critical", enabled: true },
      { ruleId: "high-threshold", enabled: true, params: { threshold: 5 } },
      { ruleId: "evidence-coverage", enabled: true, params: { minPercent: 80 } },
      { ruleId: "sandbox-unreviewed", enabled: true },
    ],
  },
  {
    id: "gp-strict", name: "엄격", description: "릴리스 전 엄격 검사",
    rules: [
      { ruleId: "no-critical", enabled: true },
      { ruleId: "high-threshold", enabled: true, params: { threshold: 0 } },
      { ruleId: "evidence-coverage", enabled: true, params: { minPercent: 95 } },
      { ruleId: "sandbox-unreviewed", enabled: true },
    ],
  },
  {
    id: "gp-relaxed", name: "완화", description: "초기 개발 단계용",
    rules: [
      { ruleId: "no-critical", enabled: true },
      { ruleId: "high-threshold", enabled: false },
      { ruleId: "evidence-coverage", enabled: false },
      { ruleId: "sandbox-unreviewed", enabled: false },
    ],
  },
];

// ── Build Log ──

export const BUILD_LOG = `[2026-03-25T09:56:00Z] === Build Start: gateway-main ===
[2026-03-25T09:56:01Z] arm-none-eabi-gcc -c -std=c11 -Wall -Wextra src/main.c -o obj/main.o
[2026-03-25T09:56:02Z] arm-none-eabi-gcc -c -std=c11 -Wall -Wextra src/gateway.c -o obj/gateway.o
[2026-03-25T09:56:03Z] arm-none-eabi-gcc -c -std=c11 -Wall -Wextra src/can_handler.c -o obj/can_handler.o
[2026-03-25T09:56:04Z] arm-none-eabi-ld obj/main.o obj/gateway.o obj/can_handler.o -o gateway.elf
[2026-03-25T09:56:05Z] === Build Complete: 0 errors, 0 warnings ===`;

// ── Finding Groups ──

export const FINDING_GROUPS = {
  groups: [
    { key: "CWE-120", count: 1, topSeverity: "critical", findingIds: ["find-1"] },
    { key: "CWE-798", count: 1, topSeverity: "high", findingIds: ["find-2"] },
    { key: "CWE-252", count: 1, topSeverity: "medium", findingIds: ["find-3"] },
    { key: "CWE-561", count: 1, topSeverity: "low", findingIds: ["find-5"] },
  ],
};

// ── Notifications ──

export const NOTIFICATIONS = [
  {
    id: "notif-1", projectId: "p-1", type: "critical_finding" as const,
    title: "Critical 취약점 발견", body: "버퍼 오버플로우 - CAN 메시지 처리",
    severity: "critical" as const, resourceId: "find-1", read: false,
    createdAt: "2026-03-25T10:03:00Z",
  },
  {
    id: "notif-2", projectId: "p-1", type: "analysis_complete" as const,
    title: "정적 분석 완료", body: "Finding 4건 발견",
    resourceId: "run-1", read: false,
    createdAt: "2026-03-25T10:02:30Z",
  },
  {
    id: "notif-3", projectId: "p-1", type: "gate_failed" as const,
    title: "Quality Gate 실패", body: "Critical 취약점 존재로 Gate 실패",
    severity: "high" as const, resourceId: "gate-1", read: true,
    createdAt: "2026-03-25T10:03:00Z",
  },
  {
    id: "notif-4", projectId: "p-1", type: "approval_pending" as const,
    title: "승인 요청 대기", body: "Quality Gate 오버라이드 승인 요청",
    resourceId: "appr-1", read: false,
    createdAt: "2026-03-25T11:00:00Z",
  },
];

export const NOTIFICATION_COUNT = { success: true, data: { unread: 3 } };

// ── Auth ──

export const AUTH_USER = {
  id: "user-1", username: "analyst", displayName: "김분석",
  role: "analyst" as const,
  createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-03-01T00:00:00Z",
};

export const LOGIN_RESPONSE = {
  success: true,
  data: {
    token: "mock-jwt-token-abc123",
    expiresAt: "2026-04-21T00:00:00Z",
    user: AUTH_USER,
  },
};

export const AUTH_ME_RESPONSE = {
  success: true,
  data: AUTH_USER,
};

export const ORG_VERIFY_PREVIEW = {
  orgId: "org-acme-kr-sec",
  code: "ACME-KR-SEC",
  name: "ACME Corp · Security Team",
  admin: { displayName: "ACME Security Admin", email: "admin@acme.kr" },
  region: "kr-seoul-1",
  defaultRole: "analyst" as const,
  emailDomainHint: "acme.kr",
};

export const REGISTRATION_CREATED = {
  registrationId: "mock-reg-0001",
  lookupToken: "mock-lookup-0001",
  lookupExpiresAt: "2026-04-27T00:00:00Z",
  status: "pending_admin_review" as const,
  createdAt: "2026-04-20T08:00:00Z",
};

export const REGISTRATION_LOOKUP = {
  id: "mock-reg-0001",
  organizationId: "org-acme-kr-sec",
  organizationCode: "ACME-KR-SEC",
  organizationName: "ACME Corp · Security Team",
  fullName: "홍길동",
  email: "qa-member@acme.kr",
  status: "pending_admin_review" as const,
  lookupExpiresAt: "2026-04-27T00:00:00Z",
  createdAt: "2026-04-20T08:00:00Z",
};

// ── Custom Report ──

export const CUSTOM_REPORT_RESPONSE = {
  reportId: "report-custom-1",
};

// ── Evidence Refs (for Finding detail mock enrichment) ──

export const EVIDENCE_REFS = [
  {
    id: "evr-1", findingId: "find-1", artifactId: "ar-1",
    artifactType: "sast-finding" as const,
    locatorType: "line-range" as const,
    locator: { file: "src/can_handler.c", startLine: 140, endLine: 145 },
    createdAt: "2026-03-25T10:02:00Z",
  },
  {
    id: "evr-2", findingId: "find-1", artifactId: "ar-1",
    artifactType: "agent-assessment" as const,
    locatorType: "line-range" as const,
    locator: { file: "src/can_handler.c", startLine: 138, endLine: 150 },
    createdAt: "2026-03-25T10:02:00Z",
  },
  {
    id: "evr-3", findingId: "find-2", artifactId: "ar-1",
    artifactType: "sast-finding" as const,
    locatorType: "line-range" as const,
    locator: { file: "src/auth.c", startLine: 53, endLine: 57 },
    createdAt: "2026-03-25T10:02:00Z",
  },
];

// ── Audit Log Entries ──

export const AUDIT_LOG_ENTRIES = [
  {
    id: "audit-1", timestamp: "2026-03-25T10:02:30Z", actor: "system",
    action: "finding.created", resource: "finding", resourceId: "find-1",
    detail: { status: "open", severity: "critical" },
  },
  {
    id: "audit-2", timestamp: "2026-03-26T12:00:00Z", actor: "analyst",
    action: "finding.status_change", resource: "finding", resourceId: "find-5",
    detail: { from: "open", to: "fixed", reason: "수정 완료" },
  },
];

// ── File Content (for file preview mock - MOCK-33) ──

export const FILE_CONTENT_RESPONSE = {
  success: true,
  data: {
    content: `#include <string.h>
#include <stdlib.h>
#include "can_handler.h"

#define CAN_BUF_SIZE 8

static uint8_t can_rx_buf[CAN_BUF_SIZE];

void can_process_message(const can_frame_t *frame) {
    // WARNING: No length validation before memcpy
    memcpy(can_rx_buf, frame->data, frame->dlc);

    if (can_rx_buf[0] == CMD_DIAGNOSTIC) {
        handle_diagnostic(can_rx_buf, frame->dlc);
    }
}`,
    language: "c",
    path: "src/can_handler.c",
    size: 4200,
    lineCount: 16,
  },
};
