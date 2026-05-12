/**
 * S4 SAST Runner HTTP 클라이언트
 *
 * API 계약: docs/api/sast-runner-api.md
 * POST /v1/scan — 6개 SAST 도구 병렬 실행
 * GET  /v1/health — 서비스 상태
 */
import crypto from "crypto";
import { createLogger } from "../lib/logger";
import {
  InvalidInputError,
  SastUnavailableError,
  SastTimeoutError,
} from "../lib/errors";
import { buildHealthCheckUrl, normalizeControlSummary } from "../lib/downstream-health";
import type { BuildProfile, SastFinding } from "@aegis/shared";

const logger = createLogger("sast-client");
const DEFAULT_S4_OWNERSHIP_POLL_MS = 1000;

// ── 요청 타입 ──

export interface SastScanRequest {
  scanId: string;
  projectId: string;
  files?: Array<{ path: string; content: string }>;
  projectPath?: string;
  compileCommands?: string;
  buildProfile?: SastAnalysisBuildProfile;
  rulesets?: string[];
  /** 포함된 서드파티 라이브러리 경로 (S4가 cross-boundary 필터링에 사용) */
  thirdPartyPaths?: string[];
  options?: {
    timeoutSeconds?: number;
    /** 실행할 도구 서브셋 (미지정 시 전체). 허용: semgrep, cppcheck, flawfinder, clang-tidy, scan-build, gcc-fanalyzer */
    tools?: string[];
  };
}

export interface SastSdkDescriptor {
  sdkRootPath: string;
  sysroot?: string;
  setupScript?: string;
  toolchainTriplet?: string;
  compilerPath?: string;
  compilerVersion?: string;
  targetArch?: string;
  languageStandard?: string;
  includePaths?: string[];
  defines?: Record<string, string>;
  environment?: Record<string, string>;
}

export type SastAnalysisBuildProfile = Omit<Partial<BuildProfile>, "sdkId"> & {
  sdkId?: string;
  sdkResolutionMode?: "none" | "non-registered";
  sdkDescriptor?: SastSdkDescriptor;
};

function normalizeScanRequestForS4(request: SastScanRequest): SastScanRequest {
  const buildProfile = request.buildProfile;
  if (!buildProfile) {
    return request;
  }
  const sdkId = buildProfile?.sdkId;
  if (sdkId?.startsWith("sdk-")) {
    throw new InvalidInputError(
      "S4 scan buildProfile must use sdkResolutionMode non-registered with sdkDescriptor for uploaded SDKs",
    );
  }
  if (sdkId !== "custom" && sdkId !== "none") {
    return request;
  }

  const { sdkId: _sdkId, ...nativeBuildProfile } = buildProfile;
  return {
    ...request,
    buildProfile: {
      ...nativeBuildProfile,
      ...(sdkId === "none" ? { sdkResolutionMode: "none" as const } : {}),
    } as SastAnalysisBuildProfile,
  };
}

// ── 응답 타입 ──

export interface SastToolResult {
  findingsCount: number;
  elapsedMs: number;
  status: "ok" | "partial" | "skipped" | "failed";
  skipReason?: string;
  error?: string;
}

export interface SastScanErrorDetail {
  code?: string;
  message?: string;
  requestId?: string;
  retryable?: boolean;
}

export interface SastCodeGraph {
  functions: Array<{ name: string; file: string; line: number; complexity?: number; calls?: string[] }>;
  callEdges?: Array<{ caller: string; callee: string; file: string; line: number }>;
  complexity?: Record<string, number>;
}

export interface SastScaLibrary {
  name: string;
  version?: string;
  path: string;
  repoUrl?: string;
}

export interface SastScanResponse {
  success: boolean;
  scanId: string;
  status: "completed" | "failed";
  findings: SastFinding[];
  stats: {
    filesScanned: number;
    rulesRun: number;
    findingsTotal: number;
    elapsedMs: number;
  };
  execution: {
    toolsRun: string[];
    toolResults: Record<string, SastToolResult>;
    sdk?: {
      resolved: boolean;
      sdkId: string;
      includePathsAdded: number;
    };
    filtering?: {
      beforeFilter: number;
      afterFilter: number;
      sdkNoiseRemoved: number;
      /** 서드파티 경로 제거 수 (thirdPartyPaths 전달 시) */
      thirdPartyRemoved?: number;
      /** cross-boundary로 유지된 finding 수 */
      crossBoundaryKept?: number;
      /** scope-early로 도구 실행 전 제외된 파일 수 */
      filesScopedOut?: number;
    };
  };
  /** 코드 구조 그래프 (projectPath 모드에서만 반환) */
  codeGraph?: SastCodeGraph | null;
  /** SCA 분석 결과 — 라이브러리 목록 (CVE는 S5에서 별도 조회) */
  sca?: { libraries: SastScaLibrary[] } | null;
  error?: string;
  errorDetail?: SastScanErrorDetail;
}

/** 빌드 타겟 탐색 응답 */
/** S4 POST /v1/build 응답 */
export interface BuildResponse {
  success: boolean;
  compileCommandsPath?: string;
  entries?: number;
  userEntries?: number;
  elapsedMs?: number;
  exitCode?: number;
  error?: string;
  buildLog?: string;
  failureCategory?: string;
  environmentKeys?: string[];
  readinessStatus?: string;
  compileCommandsReady?: boolean;
  quickEligible?: boolean;
}

export interface DiscoverTargetsResponse {
  targets: Array<{
    name: string;
    relativePath: string;
    buildSystem: string;
    buildFile: string;
  }>;
  elapsedMs: number;
}

type S4OwnedEndpoint = "scan" | "build";

interface S4OwnershipEnvelope {
  requestId?: string;
  endpoint?: S4OwnedEndpoint | string;
  state?: "queued" | "running" | "completed" | "failed" | "cancelled" | "expired" | string;
  resultReady?: boolean;
  requestSummary?: Record<string, unknown>;
  result?: unknown;
  failureDetail?: unknown;
  error?: string;
}

type S4BuildRawResponse = {
  success: boolean;
  buildEvidence?: {
    compileCommandsPath?: string;
    entries?: number;
    userEntries?: number;
    exitCode?: number;
    elapsedMs?: number;
    buildOutput?: string;
    environmentKeys?: string[];
  };
  failureDetail?: {
    category?: string;
    summary?: string;
    matchedExcerpt?: string;
  };
  compileCommandsPath?: string;
  entries?: number;
  elapsedMs?: number;
  error?: string;
  buildLog?: string;
  readiness?: {
    status?: string;
    compileCommandsReady?: boolean;
    quickEligible?: boolean;
  };
};

// ── 클라이언트 ──

export class SastClient {
  private static readonly MAX_RETRIES = 2;
  private static readonly RETRY_BASE_MS = 2000;

  constructor(private baseUrl: string) {}

  async scan(
    request: SastScanRequest,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<SastScanResponse> {
    const normalizedRequest = normalizeScanRequestForS4(request);
    const ownedRequestId = this.deriveOwnedRequestId("scan", normalizedRequest, requestId);
    const headers: Record<string, string> = this.buildOwnedHeaders(ownedRequestId);

    const data = await this.withOwnedCancellation(
      ownedRequestId,
      signal,
      () => this.doOwnedScanFetch(
        "scan",
        this.endpointUrl("/v1/scan"),
        headers,
        normalizedRequest,
        ownedRequestId,
        signal,
      ),
    );

    if (data.status === "completed") {
      logger.info(
        {
          scanId: data.scanId,
          findingsTotal: data.stats.findingsTotal,
          elapsedMs: data.stats.elapsedMs,
          toolsRun: data.execution.toolsRun,
          requestId,
        },
        "SAST scan completed",
      );
    } else {
      logger.warn(
        { scanId: data.scanId, error: data.error, errorCode: data.errorDetail?.code, requestId },
        "SAST scan failed",
      );
    }

    return data;
  }

  async build(
    request: {
      projectPath: string;
      buildCommand: string;
      buildEnvironment?: Record<string, string>;
      provenance?: {
        buildSnapshotId?: string;
        buildUnitId?: string;
        snapshotSchemaVersion?: string;
      };
      wrapWithBear?: boolean;
    },
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<BuildResponse> {
    const ownedRequestId = this.deriveOwnedRequestId("build", request, requestId);
    const headers: Record<string, string> = this.buildOwnedHeaders(ownedRequestId);

    const data = await this.withOwnedCancellation(
      ownedRequestId,
      signal,
      () => this.doOwnedJsonFetch<S4BuildRawResponse>(
        "build",
        this.endpointUrl("/v1/build"),
        headers,
        request,
        ownedRequestId,
        signal,
      ),
    );

    return this.toBuildResponse(data);
  }

  isBuildReadyForQuick(build: BuildResponse): boolean {
    if (build.readinessStatus !== undefined || build.compileCommandsReady !== undefined || build.quickEligible !== undefined) {
      return build.success === true
        && build.readinessStatus === "ready"
        && build.compileCommandsReady === true
        && build.quickEligible === true
        && !!build.compileCommandsPath
        && (build.userEntries ?? build.entries ?? 0) > 0
        && (build.exitCode ?? 0) === 0;
    }

    return build.success === true
      && !!build.compileCommandsPath
      && (build.entries ?? 0) > 0;
  }

  async discoverTargets(
    projectPath: string,
    requestId?: string,
  ): Promise<DiscoverTargetsResponse> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (requestId) headers["X-Request-Id"] = requestId;

    const res = await this.doFetch(
      `${this.baseUrl}/v1/discover-targets`,
      headers,
      { projectPath },
      requestId,
    );

    try {
      return (await res.json()) as DiscoverTargetsResponse;
    } catch (err) {
      throw new SastUnavailableError("Failed to parse discover-targets response", err);
    }
  }

  async identifyLibraries(
    projectPath: string,
    requestId?: string,
    signal?: AbortSignal,
  ): Promise<Array<{ name: string; version?: string; path: string; modifiedFiles?: string[] }>> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (requestId) headers["X-Request-Id"] = requestId;

    try {
      const res = await this.doFetch(
        `${this.baseUrl}/v1/libraries`,
        headers,
        { projectPath },
        requestId,
        signal,
      );
      const data = (await res.json()) as { libraries: Array<{ name: string; version?: string; path: string; modifiedFiles?: string[] }> };
      return data.libraries ?? [];
    } catch (err) {
      logger.warn({ err, projectPath, requestId }, "Library identification failed — continuing without");
      return [];
    }
  }

  async checkHealth(requestId?: string): Promise<Record<string, unknown> | null> {
    try {
      const res = await fetch(buildHealthCheckUrl(this.baseUrl, requestId));
      return (await res.json()) as Record<string, unknown>;
    } catch (err) {
      logger.warn({ err }, "SAST Runner health check failed");
      return null;
    }
  }

  private buildOwnedHeaders(requestId: string): Record<string, string> {
    return {
      "Content-Type": "application/json",
      "Prefer": "respond-async",
      "X-Request-Id": requestId,
    };
  }

  private deriveOwnedRequestId(endpoint: S4OwnedEndpoint, body: unknown, parentRequestId?: string): string {
    const stableBody = JSON.stringify(body);
    const digest = crypto.createHash("sha256").update(`${endpoint}:${stableBody}`).digest("hex").slice(0, 16);
    const prefix = parentRequestId?.trim() || `req-s2-${crypto.randomUUID().slice(0, 8)}`;
    return `${prefix}:s4:${endpoint}:${digest}`;
  }

  private endpointUrl(pathname: string): string {
    const base = this.baseUrl.replace(/\/+$/, "");
    return `${base}${pathname}`;
  }

  private async withOwnedCancellation<T>(
    requestId: string,
    signal: AbortSignal | undefined,
    operation: () => Promise<T>,
  ): Promise<T> {
    try {
      return await operation();
    } catch (err) {
      if (signal?.aborted) {
        await this.cancelOwnedRequest(requestId, err);
        throw signal.reason ?? err;
      }
      throw err;
    }
  }

  private async cancelOwnedRequest(requestId: string, cause?: unknown): Promise<void> {
    try {
      const res = await fetch(
        this.endpointUrl(`/v1/requests/${encodeURIComponent(requestId)}`),
        {
          method: "DELETE",
          headers: { "X-Request-Id": requestId },
        },
      );

      if (res.status === 200 || res.status === 202) {
        logger.info({ requestId }, "SAST Runner owned request cancelled after local abort");
        return;
      }

      if (res.status === 404 || res.status === 410) {
        logger.warn(
          { requestId, status: res.status, cause },
          "SAST Runner owned request cancel skipped because ownership is no longer retained",
        );
        return;
      }

      const text = await res.text().catch(() => "");
      logger.warn(
        { requestId, status: res.status, response: text.slice(0, 200), cause },
        "SAST Runner owned request cancel returned non-success status",
      );
    } catch (cancelErr) {
      logger.warn({ requestId, err: cancelErr, cause }, "SAST Runner owned request cancel failed");
    }
  }

  private async doOwnedScanFetch(
    endpoint: S4OwnedEndpoint,
    url: string,
    headers: Record<string, string>,
    body: unknown,
    ownedRequestId: string,
    signal?: AbortSignal,
  ): Promise<SastScanResponse> {
    const bodyStr = JSON.stringify(body);

    for (let attempt = 0; ; attempt++) {
      const res = await this.postOwned(url, headers, bodyStr, ownedRequestId, signal);

      if (res.status === 202) {
        return await this.pollOwnedResult<SastScanResponse>(endpoint, ownedRequestId, signal);
      }

      if (res.status === 503) {
        const text = await res.text().catch(() => "");
        const failure = this.tryParseScanFailure(text);
        if (failure) {
          return failure;
        }
        if (attempt < SastClient.MAX_RETRIES) {
          const delay = SastClient.RETRY_BASE_MS * 2 ** attempt;
          logger.warn(
            { attempt: attempt + 1, delayMs: delay, requestId: ownedRequestId },
            "SAST Runner overloaded (503), retrying",
          );
          await this.sleep(delay, signal);
          continue;
        }
        throw new SastUnavailableError(
          `SAST Runner returned HTTP 503: ${text.slice(0, 200)}`,
        );
      }

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new SastUnavailableError(
          `SAST Runner returned HTTP ${res.status}: ${text.slice(0, 200)}`,
        );
      }

      try {
        return (await res.json()) as SastScanResponse;
      } catch (err) {
        throw new SastUnavailableError(
          "Failed to parse SAST Runner response as JSON",
          err,
        );
      }
    }
  }

  private async doOwnedJsonFetch<T>(
    endpoint: S4OwnedEndpoint,
    url: string,
    headers: Record<string, string>,
    body: unknown,
    ownedRequestId: string,
    signal?: AbortSignal,
  ): Promise<T> {
    const bodyStr = JSON.stringify(body);
    const res = await this.postOwned(url, headers, bodyStr, ownedRequestId, signal);

    if (res.status === 202) {
      return await this.pollOwnedResult<T>(endpoint, ownedRequestId, signal);
    }

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new SastUnavailableError(
        `SAST Runner returned HTTP ${res.status}: ${text.slice(0, 200)}`,
      );
    }

    try {
      return (await res.json()) as T;
    } catch (err) {
      throw new SastUnavailableError("Failed to parse SAST Runner response as JSON", err);
    }
  }

  private async postOwned(
    url: string,
    headers: Record<string, string>,
    body: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<Response> {
    try {
      return await fetch(url, {
        method: "POST",
        headers,
        body,
        signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") throw err;
      const message = err instanceof Error ? err.message : "Network error";
      if (message.includes("timeout") || message.includes("ETIMEDOUT")) {
        const control = await this.checkHealth(requestId);
        const summary = control ? normalizeControlSummary(control) : undefined;
        const isSameOwnedRequest = summary?.requestId === null || summary?.requestId === requestId;
        if (control && summary && isSameOwnedRequest) {
          if (summary.pollDecision === "continue_waiting" || summary.state === "completed") {
            logger.warn(
              { requestId, state: summary.state, localAckState: summary.localAckState },
              "SAST Runner transport timeout recovered through owned request health",
            );
            return new Response(JSON.stringify(control), {
              status: 202,
              headers: { "Content-Type": "application/json" },
            });
          }
          if (summary.pollDecision === "chain_abort") {
            throw new SastUnavailableError(
              `SAST Runner owned request ${requestId} requested chain abort after transport timeout: ${summary.decisionReasons.join(",")}`,
              err,
            );
          }
        }
        throw new SastTimeoutError(`SAST Runner timeout: ${message}`, err);
      }
      throw new SastUnavailableError(`SAST Runner unreachable: ${message}`, err);
    }
  }

  private async pollOwnedResult<T>(
    endpoint: S4OwnedEndpoint,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<T> {
    while (true) {
      if (signal?.aborted) {
        throw signal.reason ?? new Error("SAST owned request wait aborted");
      }

      const res = await fetch(
        this.endpointUrl(`/v1/requests/${encodeURIComponent(requestId)}/result`),
        { headers: { "X-Request-Id": requestId }, signal },
      );

      if (res.status === 202) {
        const envelope = await this.parseOwnershipEnvelope(res, requestId);
        this.assertContinueOwnership(endpoint, requestId, envelope);
        await this.sleep(this.ownershipPollMs(), signal);
        continue;
      }

      if (res.status === 404 || res.status === 409 || res.status === 410) {
        const text = await res.text().catch(() => "");
        throw new SastUnavailableError(
          `SAST Runner ownership loss for ${requestId}: HTTP ${res.status}${text ? ` ${text.slice(0, 160)}` : ""}`,
        );
      }

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new SastUnavailableError(
          `SAST Runner result retrieval failed for ${requestId}: HTTP ${res.status}${text ? ` ${text.slice(0, 160)}` : ""}`,
        );
      }

      const envelope = await this.parseOwnershipEnvelope(res, requestId);
      this.assertTerminalOwnership(endpoint, requestId, envelope);
      if (envelope.result === undefined) {
        throw new SastUnavailableError(`SAST Runner terminal result missing for ${requestId}`);
      }
      return envelope.result as T;
    }
  }

  private async parseOwnershipEnvelope(res: Response, requestId: string): Promise<S4OwnershipEnvelope> {
    try {
      return (await res.json()) as S4OwnershipEnvelope;
    } catch (err) {
      throw new SastUnavailableError(`Failed to parse SAST ownership envelope for ${requestId}`, err);
    }
  }

  private assertContinueOwnership(endpoint: S4OwnedEndpoint, requestId: string, envelope: S4OwnershipEnvelope): void {
    this.assertMatchingEndpoint(endpoint, requestId, envelope);
    const control = normalizeControlSummary(envelope as unknown as Record<string, unknown>);
    if (control?.pollDecision === "chain_abort") {
      throw new SastUnavailableError(
        `SAST Runner owned request ${requestId} requested chain abort: ${control.decisionReasons.join(",")}`,
      );
    }
    if (control?.pollDecision === "continue_waiting") {
      logger.debug(
        {
          requestId,
          endpoint,
          state: control.state,
          localAckState: control.localAckState,
          degraded: control.degraded,
        },
        "SAST Runner owned request still alive",
      );
      return;
    }

    if (envelope.state === "queued" || envelope.state === "running") {
      return;
    }

    throw new SastUnavailableError(
      `SAST Runner owned request ${requestId} not alive during wait: state=${envelope.state ?? "unknown"}`,
    );
  }

  private assertTerminalOwnership(endpoint: S4OwnedEndpoint, requestId: string, envelope: S4OwnershipEnvelope): void {
    this.assertMatchingEndpoint(endpoint, requestId, envelope);
    const control = normalizeControlSummary(envelope as unknown as Record<string, unknown>);
    if (control?.pollDecision === "chain_abort" && envelope.result === undefined) {
      throw new SastUnavailableError(
        `SAST Runner owned request ${requestId} terminal abort without retrievable result: ${control.decisionReasons.join(",")}`,
      );
    }
    if (envelope.state === "queued" || envelope.state === "running") {
      throw new SastUnavailableError(`SAST Runner owned request ${requestId} returned non-terminal result status`);
    }
  }

  private assertMatchingEndpoint(endpoint: S4OwnedEndpoint, requestId: string, envelope: S4OwnershipEnvelope): void {
    if (envelope.requestId && envelope.requestId !== requestId) {
      throw new SastUnavailableError(`SAST Runner ownership id mismatch: expected ${requestId}, got ${envelope.requestId}`);
    }
    if (envelope.endpoint && envelope.endpoint !== endpoint) {
      throw new SastUnavailableError(`SAST Runner ownership endpoint mismatch for ${requestId}: expected ${endpoint}, got ${envelope.endpoint}`);
    }
  }

  private ownershipPollMs(): number {
    const configured = Number(process.env.AEGIS_S4_OWNERSHIP_POLL_MS);
    return Number.isFinite(configured) && configured > 0
      ? configured
      : DEFAULT_S4_OWNERSHIP_POLL_MS;
  }

  private toBuildResponse(data: S4BuildRawResponse): BuildResponse {
    const evidence = data.buildEvidence;
    const readiness = data.readiness;
    return {
      success: data.success,
      compileCommandsPath: evidence?.compileCommandsPath ?? data.compileCommandsPath,
      entries: evidence?.userEntries ?? evidence?.entries ?? data.entries,
      userEntries: evidence?.userEntries,
      elapsedMs: evidence?.elapsedMs ?? data.elapsedMs,
      exitCode: evidence?.exitCode,
      buildLog: evidence?.buildOutput ?? data.buildLog,
      error: data.error ?? data.failureDetail?.summary ?? data.failureDetail?.matchedExcerpt,
      failureCategory: data.failureDetail?.category,
      environmentKeys: evidence?.environmentKeys,
      readinessStatus: readiness?.status,
      compileCommandsReady: readiness?.compileCommandsReady,
      quickEligible: readiness?.quickEligible,
    };
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
          throw new SastTimeoutError(`SAST Runner timeout: ${message}`, err);
        }
        throw new SastUnavailableError(
          `SAST Runner unreachable: ${message}`,
          err,
        );
      }

      if (res.status === 503 && attempt < SastClient.MAX_RETRIES) {
        const delay = SastClient.RETRY_BASE_MS * 2 ** attempt;
        logger.warn(
          { attempt: attempt + 1, delayMs: delay, requestId },
          "SAST Runner overloaded (503), retrying",
        );
        await this.sleep(delay, signal);
        continue;
      }

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new SastUnavailableError(
          `SAST Runner returned HTTP ${res.status}: ${text.slice(0, 200)}`,
        );
      }

      return res;
    }
  }

  private tryParseScanFailure(text: string): SastScanResponse | null {
    if (!text) return null;
    try {
      const parsed = JSON.parse(text) as Partial<SastScanResponse>;
      if (parsed.success === false && parsed.status === "failed") {
        return {
          success: false,
          scanId: parsed.scanId ?? "",
          status: "failed",
          findings: Array.isArray(parsed.findings) ? parsed.findings : [],
          stats: parsed.stats ?? {
            filesScanned: 0,
            rulesRun: 0,
            findingsTotal: 0,
            elapsedMs: 0,
          },
          execution: parsed.execution ?? {
            toolsRun: [],
            toolResults: {},
          },
          codeGraph: parsed.codeGraph ?? null,
          sca: parsed.sca ?? null,
          error: parsed.error,
          errorDetail: parsed.errorDetail,
        };
      }
      return null;
    } catch {
      return null;
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
}
