/**
 * S7 LLM Gateway v1 Task API 클라이언트
 *
 * 동시성 제어(concurrency queue) 내장. 모든 LLM 호출은 이 클라이언트를 통해 수행.
 * API 계약: docs/contracts/llm-gateway.md
 */
import { createLogger } from "../lib/logger";
import {
  LlmUnavailableError,
  LlmHttpError,
  LlmParseError,
  LlmTimeoutError,
} from "../lib/errors";
import { buildHealthCheckUrl } from "../lib/downstream-health";
import {
  DEFAULT_S7_TASK_GENERATION_CONSTRAINTS,
  type PartialS7TaskGenerationConstraints,
  type S7TaskGenerationConstraints,
} from "@aegis/shared";

const logger = createLogger("llm-task-client");

// ── v1 요청 타입 ──

export type TaskType =
  | "static-explain"
  | "static-cluster"
  | "dynamic-annotate"
  | "test-plan-propose"
  | "report-draft";

export interface TaskEvidenceRef {
  refId: string;
  artifactId: string;
  artifactType: string;
  locatorType: string;
  locator: Record<string, unknown>;
  hash?: string;
  label?: string;
}

export interface TaskRequest {
  taskType: TaskType;
  taskId: string;
  context: {
    trusted: Record<string, unknown>;
    semiTrusted?: Record<string, unknown>;
    untrusted?: Record<string, unknown>;
  };
  evidenceRefs: TaskEvidenceRef[];
  constraints?: PartialS7TaskGenerationConstraints & {
    timeoutMs?: number;
    outputSchema?: string;
  };
  metadata?: {
    runId?: string;
    requestedBy?: string;
  };
}

// ── v1 응답 타입 ──

export interface TaskClaim {
  statement: string;
  supportingEvidenceRefs: string[];
  location?: string | null;
}

export interface TaskResult {
  summary: string;
  claims: TaskClaim[];
  caveats: string[];
  usedEvidenceRefs: string[];
  suggestedSeverity?: string;
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
  plan?: Record<string, unknown>;
}

export interface TaskAudit {
  inputHash: string;
  latencyMs: number;
  tokenUsage: Record<string, number>;
  retryCount: number;
  ragHits?: number;
  createdAt: string;
}

export interface TaskResponseSuccess {
  taskId: string;
  taskType: string;
  status: "completed";
  modelProfile: string;
  promptVersion: string;
  schemaVersion: string;
  validation: { valid: boolean; errors: string[] };
  result: TaskResult;
  audit: TaskAudit;
}

export interface TaskResponseFailure {
  taskId: string;
  taskType: string;
  status:
    | "validation_failed"
    | "timeout"
    | "model_error"
    | "budget_exceeded"
    | "unsafe_output"
    | "empty_result";
  failureCode: string;
  failureDetail: string;
  retryable?: boolean;
  audit: TaskAudit;
}

export type TaskResponse = TaskResponseSuccess | TaskResponseFailure;

// ── 클라이언트 ──

export class LlmTaskClient {
  private static readonly MAX_RETRIES = 3;
  private static readonly RETRY_BASE_MS = 1000;

  private queue: Array<{ run: () => void }> = [];
  private running = 0;

  constructor(private baseUrl: string, private concurrency = 1) {}

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const run = () => {
        this.running++;
        fn().then(resolve, reject).finally(() => {
          this.running--;
          const next = this.queue.shift();
          if (next) next.run();
        });
      };
      if (this.running < this.concurrency) {
        run();
      } else {
        this.queue.push({ run });
        logger.info(
          { queueSize: this.queue.length },
          "LLM request queued (concurrency=%d)",
          this.concurrency,
        );
      }
    });
  }

  async submitTask(
    request: TaskRequest,
    requestId?: string,
    options?: { signal?: AbortSignal; baseUrl?: string },
  ): Promise<TaskResponse> {
    return this.enqueue(() => this.doSubmitTask(request, requestId, options));
  }

  private async doSubmitTask(
    request: TaskRequest,
    requestId?: string,
    options?: { signal?: AbortSignal; baseUrl?: string },
  ): Promise<TaskResponse> {
    const url = options?.baseUrl ?? this.baseUrl;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (requestId) headers["X-Request-Id"] = requestId;

    const res = await this.doFetch(url, headers, this.withGenerationConstraints(request), requestId, options?.signal);

    let data: TaskResponse;
    try {
      data = (await res.json()) as TaskResponse;
    } catch (err) {
      throw new LlmParseError(
        "Failed to parse v1 Task API response as JSON",
        err,
      );
    }

    if (data.status !== "completed") {
      const fail = data as TaskResponseFailure;
      logger.warn(
        {
          taskId: fail.taskId,
          status: fail.status,
          failureCode: fail.failureCode,
          latencyMs: fail.audit?.latencyMs,
          requestId,
        },
        "v1 Task failed: %s",
        fail.failureDetail,
      );
    } else {
      logger.info(
        {
          taskId: data.taskId,
          taskType: data.taskType,
          confidence: data.result.confidence,
          latencyMs: data.audit.latencyMs,
          requestId,
        },
        "v1 Task completed",
      );
    }

    return data;
  }

  // ── HTTP fetch + 503 재시도 ──

  private async doFetch(
    url: string,
    headers: Record<string, string>,
    request: TaskRequest,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<Response> {
    const body = JSON.stringify(request);

    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await fetch(`${url}/v1/tasks`, {
          method: "POST",
          headers,
          body,
          signal,
        });
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") throw err;
        const message = err instanceof Error ? err.message : "Network error";
        if (message.includes("timeout") || message.includes("ETIMEDOUT")) {
          throw new LlmTimeoutError(`v1 Task API timeout: ${message}`, err);
        }
        throw new LlmUnavailableError(
          `v1 Task API unreachable: ${message}`,
          err,
        );
      }

      // S3가 vLLM 과부하 시 503 + retryable 응답
      if (res.status === 503 && attempt < LlmTaskClient.MAX_RETRIES) {
        const text = await res.text().catch(() => "");
        if (this.isRetryableBody(text)) {
          const delay = LlmTaskClient.RETRY_BASE_MS * 2 ** attempt;
          logger.warn(
            { attempt: attempt + 1, maxRetries: LlmTaskClient.MAX_RETRIES, delayMs: delay, requestId },
            "S3 overloaded (503), retrying",
          );
          await this.sleep(delay, signal);
          continue;
        }
      }

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new LlmHttpError(
          `v1 Task API returned HTTP ${res.status}: ${text.slice(0, 200)}`,
        );
      }

      return res;
    }
  }

  private withGenerationConstraints(request: TaskRequest): TaskRequest {
    const constraints: S7TaskGenerationConstraints & {
      timeoutMs?: number;
      outputSchema?: string;
    } = {
      ...DEFAULT_S7_TASK_GENERATION_CONSTRAINTS,
      ...request.constraints,
    };

    return {
      ...request,
      constraints,
    };
  }

  private isRetryableBody(body: string): boolean {
    try {
      const json = JSON.parse(body);
      return json?.errorDetail?.retryable === true;
    } catch {
      return false;
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
        () => { clearTimeout(timer); reject(signal.reason); },
        { once: true },
      );
    });
  }

  isSuccess(response: TaskResponse): response is TaskResponseSuccess {
    return response.status === "completed";
  }

  async checkHealth(requestId?: string, baseUrl?: string): Promise<Record<string, unknown> | null> {
    const url = baseUrl ?? this.baseUrl;
    try {
      const res = await fetch(buildHealthCheckUrl(url, requestId));
      return (await res.json()) as Record<string, unknown>;
    } catch (err) {
      logger.warn({ err }, "v1 health check failed");
      return null;
    }
  }
}
