/**
 * S5 Knowledge Base HTTP 클라이언트
 *
 * API 계약: docs/api/knowledge-base-api.md
 * POST /v1/code-graph/{projectId}/ingest — 코드그래프 적재
 * GET  /v1/code-graph/{projectId}/stats  — 적재 통계
 * DELETE /v1/code-graph/{projectId}      — 코드그래프 삭제
 * GET  /v1/health                        — 서비스 상태
 */
import { createLogger } from "../lib/logger";
import { KbUnavailableError, KbHttpError } from "../lib/errors";
import { buildHealthCheckUrl } from "../lib/downstream-health";
import type { SastCodeGraph } from "./sast-client";

const logger = createLogger("kb-client");
const DEFAULT_CODE_GRAPH_INGEST_TIMEOUT_MS = "15000";

export interface CodeGraphIngestResponse {
  success?: boolean;
  project_id: string;
  nodeCount?: number;
  edgeCount?: number;
  vectorCount?: number;
  files?: string[];
  latency_ms?: number;
  nodes_created?: number;
  edges_created?: number;
  elapsed_ms?: number;
  status?: "ready" | "partial" | "empty";
  readiness?: {
    neo4jGraph?: boolean;
    vectorIndex?: boolean;
    graphRag?: boolean;
  };
  replaceMode?: "replace_project_graph";
  operation?: {
    repeatable?: boolean;
    replacedExistingGraph?: boolean;
  };
  warnings?: string[];
  error?: string;
}

export interface CodeGraphStatsResponse {
  project_id?: string;
  nodeCount?: number;
  edgeCount?: number;
  files?: string[];
  function_count?: number;
  call_edge_count?: number;
}

interface KbErrorPayload {
  error?: string;
  errorDetail?: {
    code?: string;
    message?: string;
    requestId?: string;
    retryable?: boolean;
  };
}

export class KbClient {
  private static readonly MAX_RETRIES = 2;
  private static readonly RETRY_BASE_MS = 2000;

  constructor(private baseUrl: string) {}

  async ingestCodeGraph(
    projectId: string,
    codeGraph: SastCodeGraph,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<CodeGraphIngestResponse> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (requestId) headers["X-Request-Id"] = requestId;
    headers["X-Timeout-Ms"] = DEFAULT_CODE_GRAPH_INGEST_TIMEOUT_MS;

    const callsByFunction = new Map<string, Set<string>>();
    for (const fn of codeGraph.functions) {
      callsByFunction.set(fn.name, new Set(fn.calls ?? []));
    }
    for (const edge of codeGraph.callEdges ?? []) {
      const calls = callsByFunction.get(edge.caller) ?? new Set<string>();
      calls.add(edge.callee);
      callsByFunction.set(edge.caller, calls);
    }

    const res = await this.doFetch(
      `${this.baseUrl}/v1/code-graph/${encodeURIComponent(projectId)}/ingest`,
      headers,
      {
        functions: codeGraph.functions.map((fn) => ({
          ...fn,
          calls: [...(callsByFunction.get(fn.name) ?? new Set<string>())],
        })),
      },
      requestId,
      signal,
    );

    try {
      return (await res.json()) as CodeGraphIngestResponse;
    } catch (err) {
      throw new KbHttpError(`Failed to parse KB ingest response: ${err}`, err);
    }
  }

  isGraphReady(result: CodeGraphIngestResponse): boolean {
    if (result.status !== undefined || result.readiness !== undefined) {
      return result.status === "ready" && result.readiness?.graphRag === true;
    }

    return this.getIngestNodeCount(result) > 0;
  }

  getIngestNodeCount(result: CodeGraphIngestResponse): number {
    return result.nodeCount ?? result.nodes_created ?? 0;
  }

  getIngestEdgeCount(result: CodeGraphIngestResponse): number {
    return result.edgeCount ?? result.edges_created ?? 0;
  }

  getStatsFunctionCount(result: CodeGraphStatsResponse): number {
    return result.nodeCount ?? result.function_count ?? 0;
  }

  getStatsCallEdgeCount(result: CodeGraphStatsResponse): number {
    return result.edgeCount ?? result.call_edge_count ?? 0;
  }

  async getCodeGraphStats(
    projectId: string,
    requestId?: string,
  ): Promise<CodeGraphStatsResponse | null> {
    try {
      const headers: Record<string, string> = {};
      if (requestId) headers["X-Request-Id"] = requestId;

      const res = await fetch(
        `${this.baseUrl}/v1/code-graph/${encodeURIComponent(projectId)}/stats`,
        { headers },
      );
      if (!res.ok) return null;
      return (await res.json()) as CodeGraphStatsResponse;
    } catch {
      return null;
    }
  }

  async deleteCodeGraph(
    projectId: string,
    requestId?: string,
  ): Promise<boolean> {
    try {
      const headers: Record<string, string> = {};
      if (requestId) headers["X-Request-Id"] = requestId;

      const res = await fetch(
        `${this.baseUrl}/v1/code-graph/${encodeURIComponent(projectId)}`,
        { method: "DELETE", headers },
      );
      return res.ok;
    } catch {
      return false;
    }
  }

  /** Liveness — S5가 살아있는지 확인 */
  async checkHealth(requestId?: string): Promise<Record<string, unknown> | null> {
    try {
      const res = await fetch(buildHealthCheckUrl(this.baseUrl, requestId));
      return (await res.json()) as Record<string, unknown>;
    } catch {
      logger.warn("KB health check failed");
      return null;
    }
  }

  /** Readiness — S5가 완전 초기화(Neo4j, Qdrant 등) 되었는지 확인 */
  async checkReady(): Promise<Record<string, unknown> | null> {
    try {
      const res = await fetch(`${this.baseUrl}/v1/ready`);
      if (!res.ok) return null;
      return (await res.json()) as Record<string, unknown>;
    } catch {
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
        res = await fetch(url, { method: "POST", headers, body: bodyStr, signal });
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") throw err;
        throw new KbUnavailableError(`KB unreachable: ${err instanceof Error ? err.message : "Network error"}`, err);
      }

      if (res.status === 503 && attempt < KbClient.MAX_RETRIES) {
        const errorPayload = await this.parseErrorPayload(res.clone());
        const delay = KbClient.RETRY_BASE_MS * 2 ** attempt;
        logger.warn(
          {
            attempt: attempt + 1,
            delayMs: delay,
            requestId,
            errorCode: errorPayload.errorDetail?.code,
          },
          "KB returned 503, retrying",
        );
        await this.sleep(delay, signal);
        continue;
      }

      if (!res.ok) {
        const errorPayload = await this.parseErrorPayload(res);
        const errorCode = errorPayload.errorDetail?.code;
        const errorMessage = errorPayload.errorDetail?.message
          ?? errorPayload.error
          ?? `HTTP ${res.status}`;
        throw new KbHttpError(
          `KB returned HTTP ${res.status}${errorCode ? ` (${errorCode})` : ""}: ${errorMessage}`.slice(0, 240),
          undefined,
          {
            status: res.status,
            errorCode,
            retryable: errorPayload.errorDetail?.retryable ?? false,
            requestId: errorPayload.errorDetail?.requestId,
          },
        );
      }

      return res;
    }
  }

  private async parseErrorPayload(res: Response): Promise<KbErrorPayload> {
    try {
      return (await res.json()) as KbErrorPayload;
    } catch {
      const text = await res.text().catch(() => "");
      return { error: text.slice(0, 200) };
    }
  }

  private sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (signal?.aborted) { reject(signal.reason); return; }
      const timer = setTimeout(resolve, ms);
      signal?.addEventListener("abort", () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
    });
  }
}
