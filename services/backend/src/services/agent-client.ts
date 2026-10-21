/**
 * S3 Analysis Agent HTTP 클라이언트
 *
 * API 계약: docs/contracts/analysis-agent.md
 * POST /v1/tasks — deep-analyze (프로젝트 보안 심층 분석)
 * GET  /v1/health — 서비스 상태
 */
import { createLogger } from "../lib/logger";
import {
  AgentUnavailableError,
  AgentTimeoutError,
} from "../lib/errors";
import { buildHealthCheckUrl } from "../lib/downstream-health";
import type {
  AgentAnalysisOutcome,
  AgentPocOutcome,
  AgentQualityOutcome,
  AgentClaimDiagnosticsSummary,
  AgentEvidenceDiagnosticsSummary,
  AgentRecoveryTraceEntry,
  BuildProfile,
  S3GenerationOverrides,
  SastFinding,
} from "@aegis/shared";

const logger = createLogger("agent-client");

// ── 요청 타입 ──

export interface AgentEvidenceRef {
  refId: string;
  artifactId: string;
  artifactType: string;
  locatorType: string;
  locator: Record<string, unknown>;
  hash?: string;
}

export interface AgentTaskRequest {
  taskType: "deep-analyze" | "generate-poc";
  taskId: string;
  context: {
    trusted: {
      objective: string;
      files?: Array<{ path: string; content: string }>;
      projectId?: string;
      projectPath?: string;
      /** 프로젝트 내 빌드 타겟 상대 경로 (e.g. "gateway/") */
      targetPath?: string;
      buildCommand?: string;
      buildEnvironment?: Record<string, string>;
      buildProfile?: Partial<BuildProfile>;
      provenance?: Record<string, unknown>;
      sastFindings?: SastFinding[];
      /** Phase 1 캐싱: 코드그래프 요약 (S4 /v1/scan 응답에서 추출) */
      codeGraphSummary?: unknown;
      /** Phase 1 캐싱: SCA 라이브러리 목록 (S4 /v1/scan 응답에서 추출) */
      scaLibraries?: unknown;
      /** explicit-step flow alias: build-prep 결과물 */
      buildPreparation?: Record<string, unknown>;
      /** explicit-step flow alias: Quick 결과 컨텍스트 */
      quickContext?: Record<string, unknown>;
      /** explicit-step flow alias: GraphRAG/graph ingest 컨텍스트 */
      graphContext?: Record<string, unknown>;
      /** 서드파티 라이브러리 경로 — S3가 S4에 전달하여 heavy analyzer 제외 */
      thirdPartyPaths?: string[];
      /** S4 도구 서브셋 선택 (미지정 시 전체). e.g. ["flawfinder", "cppcheck"] */
      sastTools?: string[] | null;
      /** PoC 생성 시 대상 클레임 */
      claim?: {
        statement: string;
        detail?: string;
        location?: string;
      };
    };
  };
  evidenceRefs: AgentEvidenceRef[];
  constraints?: S3GenerationOverrides & {
    timeoutMs?: number;
  };
  metadata?: {
    runId?: string;
    requestedBy?: string;
  };
}

// ── 응답 타입 ──

export interface AgentClaim {
  statement: string;
  /** 상세 분석 — 공격 경로, 영향 범위, 코드 흐름, 악용 시나리오 */
  detail?: string | null;
  supportingEvidenceRefs: string[];
  location?: string | null;
}

export interface AgentAssessmentResult {
  summary: string;
  claims: AgentClaim[];
  caveats: string[];
  usedEvidenceRefs: string[];
  suggestedSeverity?: string | null;
  confidence: number;
  confidenceBreakdown: {
    grounding: number;
    deterministicSupport: number;
    ragCoverage: number;
    schemaCompliance: number;
  };
  needsHumanReview: boolean;
  recommendedNextSteps: string[];
  policyFlags: string[];
  /** completed is an honest envelope; this field decides accepted/no-accepted/inconclusive analysis outcome. */
  analysisOutcome?: AgentAnalysisOutcome;
  /** Result-level quality classifier; clean deep pass requires `accepted`. */
  qualityOutcome?: AgentQualityOutcome;
  /** PoC classifier for generate-poc; deep-analyze defaults to `poc_not_requested`. */
  pocOutcome?: AgentPocOutcome;
  /** Strict clean evaluation pass flag. For generate-poc, true only for clean accepted PoC. */
  cleanPass?: boolean;
  /** Bounded public recovery/deficiency summaries. */
  recoveryTrace?: AgentRecoveryTraceEntry[];
  /**
   * S3 WP-1 shape: diagnostics object for non-accepted claim lifecycle candidates.
   * `claims[]` remains accepted-final-only.
   */
  claimDiagnostics?: AgentClaimDiagnosticsSummary;
  /** Evidence acquisition diagnostics; diagnostic-only refs must not be treated as supporting claim refs. */
  evidenceDiagnostics?: AgentEvidenceDiagnosticsSummary;
}

export interface AgentAudit {
  inputHash: string;
  latencyMs: number;
  tokenUsage: { prompt: number; completion: number };
  retryCount: number;
  ragHits?: number;
  createdAt: string;
  agentAudit?: {
    turn_count: number;
    tool_call_count: number;
    termination_reason: string;
    trace: unknown[];
  };
}

export interface AgentResponseSuccess {
  taskId: string;
  taskType: string;
  status: "completed";
  modelProfile: string;
  promptVersion: string;
  schemaVersion: string;
  validation: { valid: boolean; errors: string[] };
  result: AgentAssessmentResult;
  audit: AgentAudit;
}

export interface AgentResponseFailure {
  taskId: string;
  taskType: string;
  status:
    | "timeout"
    | "validation_failed"
    | "model_error"
    | "budget_exceeded"
    | "unsafe_output"
    | "empty_result";
  failureCode: string;
  failureDetail: string;
  retryable?: boolean;
  audit?: AgentAudit;
}

export type AgentResponse = AgentResponseSuccess | AgentResponseFailure;

// ── 클라이언트 ──

export class AgentClient {
  private static readonly MAX_RETRIES = 2;
  private static readonly RETRY_BASE_MS = 3000;

  constructor(private baseUrl: string) {}

  async submitTask(
    request: AgentTaskRequest,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<AgentResponse> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (requestId) headers["X-Request-Id"] = requestId;

    const data = await this.doFetch(
      `${this.baseUrl}/v1/tasks`,
      headers,
      request,
      requestId,
      signal,
    );

    if (data.status === "completed") {
      const success = data as AgentResponseSuccess;
      logger.info(
        {
          taskId: success.taskId,
          claimCount: success.result.claims.length,
          analysisOutcome: success.result.analysisOutcome,
          qualityOutcome: success.result.qualityOutcome,
          pocOutcome: success.result.pocOutcome,
          confidence: success.result.confidence,
          latencyMs: success.audit.latencyMs,
          requestId,
        },
        "Agent deep-analyze completed",
      );
    } else {
      const fail = data as AgentResponseFailure;
      logger.warn(
        {
          taskId: fail.taskId,
          status: fail.status,
          failureCode: fail.failureCode,
          retryable: fail.retryable,
          requestId,
        },
        "Agent deep-analyze failed: %s",
        fail.failureDetail,
      );
    }

    return data;
  }

  isSuccess(response: AgentResponse): response is AgentResponseSuccess {
    return response.status === "completed";
  }

  async checkHealth(requestId?: string): Promise<Record<string, unknown> | null> {
    try {
      const res = await fetch(buildHealthCheckUrl(this.baseUrl, requestId));
      return (await res.json()) as Record<string, unknown>;
    } catch (err) {
      logger.warn({ err }, "Agent health check failed");
      return null;
    }
  }

  private async doFetch(
    url: string,
    headers: Record<string, string>,
    body: unknown,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<AgentResponse> {
    const bodyStr = JSON.stringify(body);

    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await fetch(url, {
          method: "POST",
          headers,
          body: bodyStr,
          signal,
        });
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") throw err;
        const message = err instanceof Error ? err.message : "Network error";
        if (message.includes("timeout") || message.includes("ETIMEDOUT")) {
          throw new AgentTimeoutError(`Agent timeout: ${message}`, err);
        }
        throw new AgentUnavailableError(
          `Agent unreachable: ${message}`,
          err,
        );
      }

      const structuredFailure = await this.tryParseFailureResponse(res);
      if (structuredFailure) {
        return structuredFailure;
      }

      if (res.status === 503 && attempt < AgentClient.MAX_RETRIES) {
        const delay = AgentClient.RETRY_BASE_MS * 2 ** attempt;
        logger.warn(
          { attempt: attempt + 1, delayMs: delay, requestId },
          "Agent overloaded (503), retrying",
        );
        await this.sleep(delay, signal);
        continue;
      }

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new AgentUnavailableError(
          `Agent returned HTTP ${res.status}: ${text.slice(0, 200)}`,
        );
      }

      try {
        return (await res.json()) as AgentResponse;
      } catch (err) {
        throw new AgentUnavailableError(
          "Failed to parse Agent response as JSON",
          err,
        );
      }
    }
  }

  private async tryParseFailureResponse(res: Response): Promise<AgentResponseFailure | null> {
    if (res.ok) return null;
    try {
      const clone = typeof res.clone === "function" ? res.clone() : res;
      const parsed = (await clone.json()) as Record<string, unknown>;
      if (
        typeof parsed.status === "string"
        && parsed.status !== "completed"
        && typeof parsed.failureCode === "string"
        && typeof parsed.failureDetail === "string"
      ) {
        return parsed as unknown as AgentResponseFailure;
      }
    } catch {
      // Non-JSON transport failure: keep legacy retry / unavailable behavior.
    }
    return null;
  }

  private sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason);
        return;
      }
      const timer = setTimeout(resolve, ms);
      signal?.addEventListener(
        "abort",
        () => { clearTimeout(timer); reject(signal.reason); },
        { once: true },
      );
    });
  }
}
