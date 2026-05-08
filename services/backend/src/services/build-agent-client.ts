/**
 * S3 Build Agent HTTP 클라이언트
 *
 * API 계약: docs/api/build-agent-api.md
 * POST /v1/tasks — build-resolve (빌드 명령어/프로필 자동 탐색)
 * GET  /v1/health — 서비스 상태
 */
import { createLogger } from "../lib/logger";
import {
  BuildAgentUnavailableError,
  BuildAgentTimeoutError,
} from "../lib/errors";
import { buildHealthCheckUrl } from "../lib/downstream-health";
import type { S3GenerationOverrides } from "@aegis/shared";

const logger = createLogger("build-agent-client");

// ── 요청 타입 ──

export interface BuildResolveTarget {
  name: string;
  path: string;
  buildSystem: string;
  buildFiles: string[];
}

export interface BuildResolveBuildContext {
  mode: "native" | "sdk";
  sdkId?: string;
  /** Absolute server-visible path to the materialized uploaded SDK root. */
  sdkRootPath?: string;
  /** Preferred path relative to sdkRootPath; transitional absolute values are S3-scoped inside sdkRootPath. */
  setupScript?: string;
  /** Preferred path relative to sdkRootPath; transitional absolute values are S3-scoped inside sdkRootPath. */
  sysroot?: string;
  /** Compiler-prefix/toolchain hint without a trailing dash, e.g. arm-none-linux-gnueabihf. */
  toolchainTriplet?: string;
  scriptHintPath?: string;
  environment?: Record<string, string>;
}

export interface BuildResolveRequest {
  taskType: "build-resolve" | "sdk-analyze";
  taskId: string;
  contractVersion?: "build-resolve-v1";
  strictMode?: boolean;
  context: {
    trusted: {
      projectPath: string;
      buildTargetPath?: string;
      buildTargetName?: string;
      build?: BuildResolveBuildContext;
      targetPath?: string;
      targetName?: string;
      targets?: BuildResolveTarget[];
    };
  };
  constraints?: S3GenerationOverrides & {
    timeoutMs?: number;
  };
  metadata?: {
    runId?: string;
    requestedBy?: string;
  };
}

// ── 응답 타입 ──

export interface BuildResultPayload {
  success: boolean;
  buildCommand: string;
  /** 에이전트가 작성한 빌드 스크립트 경로 (항상 build-aegis/aegis-build.sh) */
  buildScript: string;
  /** 빌드 출력 디렉토리 (build-aegis) */
  buildDir: string;
  /** 실패 시 에러 로그 */
  errorLog?: string | null;
}

export interface BuildPreparationPayload {
  declaredMode?: string;
  sdkId?: string;
  buildCommand?: string;
  buildScript?: string;
  buildDir?: string;
  buildEnvironment?: Record<string, string>;
  provenance?: Record<string, unknown>;
  expectedArtifacts?: Array<Record<string, unknown>>;
  producedArtifacts?: Array<Record<string, unknown>>;
}

export interface BuildOutcomePayload {
  outcome?: "built" | "compile_failed" | "missing_materials" | "sdk_mismatch" | "artifact_mismatch" | "inconclusive" | string;
  cleanPass?: boolean;
  [key: string]: unknown;
}

export interface BuildDiagnosticsPayload {
  failureCode?: string;
  expectedArtifacts?: unknown[];
  producedArtifacts?: unknown[];
  missingArtifacts?: unknown[];
  [key: string]: unknown;
}

export interface BuildResolveResult {
  summary: string;
  claims: Array<{
    statement: string;
    supportingEvidenceRefs: string[];
    location?: string;
  }>;
  caveats: string[];
  usedEvidenceRefs: string[];
  confidence: number;
  confidenceBreakdown: {
    grounding: number;
    deterministicSupport: number;
    ragCoverage: number;
    schemaCompliance: number;
  };
  needsHumanReview: boolean;
  buildResult: BuildResultPayload;
  /** explicit-step flow용 follow-up bundle (legacy buildResult와 병행 유지) */
  buildPreparation?: BuildPreparationPayload;
  /** build-v1.1 domain outcome; status=completed is an envelope, not necessarily a clean build. */
  buildOutcome?: BuildOutcomePayload;
  /** Convenience mirror of buildOutcome.cleanPass. */
  cleanPass?: boolean;
  /** build-v1.1 domain diagnostics for completed-but-non-clean results. */
  buildDiagnostics?: BuildDiagnosticsPayload;
  /** sdk-analyze result payload (present for sdk-analyze tasks). */
  sdkProfile?: Record<string, unknown>;
}

export interface BuildAgentAudit {
  inputHash: string;
  latencyMs: number;
  tokenUsage: { prompt: number; completion: number };
  retryCount: number;
  createdAt: string;
  agentAudit?: {
    turn_count: number;
    tool_call_count: number;
    termination_reason: string;
    trace: unknown[];
  };
}

export interface BuildAgentResponseSuccess {
  taskId: string;
  taskType: string;
  status: "completed";
  modelProfile: string;
  promptVersion: string;
  schemaVersion: string;
  validation: { valid: boolean; errors: string[] };
  result: BuildResolveResult;
  audit: BuildAgentAudit;
}

export interface BuildAgentResponseFailure {
  taskId: string;
  taskType: string;
  status:
    | "timeout"
    | "validation_failed"
    | "model_error"
    | "budget_exceeded"
    | "empty_result"
    | "build_failed";
  failureCode: string;
  failureDetail: string;
  retryable?: boolean;
  audit?: BuildAgentAudit;
}

export type BuildAgentResponse =
  | BuildAgentResponseSuccess
  | BuildAgentResponseFailure;

// ── 클라이언트 ──

export class BuildAgentClient {
  private static readonly MAX_RETRIES = 2;
  private static readonly RETRY_BASE_MS = 3000;

  constructor(private baseUrl: string) {}

  async submitTask(
    request: BuildResolveRequest,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<BuildAgentResponse> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (requestId) headers["X-Request-Id"] = requestId;

    const res = await this.doFetch(
      `${this.baseUrl}/v1/tasks`,
      headers,
      request,
      requestId,
      signal,
    );

    let data: BuildAgentResponse;
    try {
      data = (await res.json()) as BuildAgentResponse;
    } catch (err) {
      throw new BuildAgentUnavailableError(
        "Failed to parse Build Agent response as JSON",
        err,
      );
    }

    if (data.status === "completed") {
      const success = data as BuildAgentResponseSuccess;
      logger.info(
        {
          taskId: success.taskId,
          buildCommand: success.result.buildResult.buildCommand,
          confidence: success.result.confidence,
          latencyMs: success.audit.latencyMs,
          requestId,
        },
        "Build Agent resolve completed",
      );
    } else {
      const fail = data as BuildAgentResponseFailure;
      logger.warn(
        {
          taskId: fail.taskId,
          status: fail.status,
          failureCode: fail.failureCode,
          retryable: fail.retryable,
          requestId,
        },
        "Build Agent resolve failed: %s",
        fail.failureDetail,
      );
    }

    return data;
  }

  isSuccess(
    response: BuildAgentResponse,
  ): response is BuildAgentResponseSuccess {
    return response.status === "completed";
  }

  isCleanSuccess(
    response: BuildAgentResponse,
  ): response is BuildAgentResponseSuccess {
    return response.status === "completed" && response.result.cleanPass !== false;
  }

  async checkHealth(requestId?: string): Promise<Record<string, unknown> | null> {
    try {
      const res = await fetch(buildHealthCheckUrl(this.baseUrl, requestId));
      return (await res.json()) as Record<string, unknown>;
    } catch (err) {
      logger.warn({ err }, "Build Agent health check failed");
      return null;
    }
  }

  private async doFetch(
    url: string,
    headers: Record<string, string>,
    body: unknown,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<Response> {
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
          throw new BuildAgentTimeoutError(
            `Build Agent timeout: ${message}`,
            err,
          );
        }
        throw new BuildAgentUnavailableError(
          `Build Agent unreachable: ${message}`,
          err,
        );
      }

      if (res.status === 503 && attempt < BuildAgentClient.MAX_RETRIES) {
        const delay = BuildAgentClient.RETRY_BASE_MS * 2 ** attempt;
        logger.warn(
          { attempt: attempt + 1, delayMs: delay, requestId },
          "Build Agent overloaded (503), retrying",
        );
        await this.sleep(delay, signal);
        continue;
      }

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new BuildAgentUnavailableError(
          `Build Agent returned HTTP ${res.status}: ${text.slice(0, 200)}`,
        );
      }

      return res;
    }
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
        () => {
          clearTimeout(timer);
          reject(signal.reason);
        },
        { once: true },
      );
    });
  }
}
