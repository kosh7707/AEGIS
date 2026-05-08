import "./SdkManagementSection.css";
import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Archive,
  Binary,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  FileText,
  FolderOpen,
  Loader,
  Plus,
  RefreshCcw,
  Trash2,
  Upload,
  X,
  XCircle,
} from "lucide-react";
import type {
  RegisteredSdk,
  SdkAnalyzedProfile,
  SdkErrorCode,
  SdkLogResponse,
  SdkPhaseDetail,
  SdkPhaseHistoryEntry,
  SdkQuota,
  SdkRegistryStatus,
} from "@/common/api/sdk";
import { fetchSdkLog, getSdkLogDownloadUrl } from "@/common/api/sdk";
import type {
  SdkErrorEventDetails,
  SdkProgressDetails,
} from "@/common/hooks/useSdkProgress";
import { logError } from "@/common/api/core";
import { SdkUploadForm } from "../SdkUploadForm/SdkUploadForm";
import { SdkMetricsPanel } from "../SdkMetricsPanel/SdkMetricsPanel";
import { SdkProfilesPanel } from "../SdkProfilesPanel/SdkProfilesPanel";

const STATUS_CONFIG: Record<SdkRegistryStatus, { label: string; icon: "spin" | "check" | "fail"; tone: "pending" | "ready" | "failed" }> = {
  uploading: { label: "업로드 중", icon: "spin", tone: "pending" },
  uploaded: { label: "업로드 완료", icon: "spin", tone: "pending" },
  extracting: { label: "압축 해제 중", icon: "spin", tone: "pending" },
  extracted: { label: "압축 해제 완료", icon: "spin", tone: "pending" },
  installing: { label: "설치 중", icon: "spin", tone: "pending" },
  installed: { label: "설치 완료", icon: "spin", tone: "pending" },
  analyzing: { label: "AI 분석 중", icon: "spin", tone: "pending" },
  verifying: { label: "검증 중", icon: "spin", tone: "pending" },
  ready: { label: "사용 가능", icon: "check", tone: "ready" },
  upload_failed: { label: "업로드 실패", icon: "fail", tone: "failed" },
  extract_failed: { label: "압축해제 실패", icon: "fail", tone: "failed" },
  install_failed: { label: "설치 실패", icon: "fail", tone: "failed" },
  verify_failed: { label: "검증 실패", icon: "fail", tone: "failed" },
};

interface PhaseGroup {
  label: string;
  phases: SdkRegistryStatus[];
  failPhases: SdkRegistryStatus[];
}

const PHASE_GROUPS: PhaseGroup[] = [
  { label: "업로드", phases: ["uploading", "uploaded"], failPhases: ["upload_failed"] },
  { label: "설치/압축해제", phases: ["extracting", "extracted", "installing", "installed"], failPhases: ["extract_failed", "install_failed"] },
  { label: "AI 분석", phases: ["analyzing"], failPhases: [] },
  { label: "검증", phases: ["verifying"], failPhases: ["verify_failed"] },
  { label: "완료", phases: ["ready"], failPhases: [] },
];

interface SdkManagementSectionProps {
  projectId: string;
  registered: RegisteredSdk[];
  sdkProgressById: Record<string, SdkProgressDetails>;
  sdkErrorDetailsById: Record<string, SdkErrorEventDetails>;
  sdkQuota: SdkQuota | null;
  retryingSdkIds: Set<string>;
  showForm: boolean;
  onToggleForm: () => void;
  onRegistered: (sdk: RegisteredSdk) => void;
  onCancelForm: () => void;
  onRequestDelete: (sdk: RegisteredSdk) => void;
  onRetry: (sdk: RegisteredSdk) => void;
}

function formatBytes(bytes?: number): string | null {
  if (bytes == null) return null;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function formatElapsedSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0초";
  const total = Math.floor(seconds);
  if (total < 60) return `${total}초`;
  const m = Math.floor(total / 60);
  const s = total % 60;
  return s > 0 ? `${m}분 ${s}초` : `${m}분`;
}

function formatDurationMs(ms?: number): string | null {
  if (ms == null) return null;
  if (ms <= 0) return "0초";
  if (ms < 1000) return `${ms}ms`;
  return formatElapsedSeconds(ms / 1000);
}

function formatTimestampKo(ms?: number): string | null {
  if (ms == null || !Number.isFinite(ms)) return null;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}

function liveSignalsPaused(): boolean {
  if (typeof document === "undefined") return false;
  if (document.body?.classList?.contains("no-live")) return true;
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    try {
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return true;
    } catch {
      /* matchMedia unavailable; ignore */
    }
  }
  return false;
}

function formatPhaseDetail(detail: SdkPhaseDetail | undefined, fallbackMessage?: string): string | null {
  if (!detail) return fallbackMessage ?? null;
  const path = detail.params?.path;
  if (detail.kind === "analyzing-file" && typeof path === "string") {
    return `분석 중: ${path}`;
  }
  if (detail.kind === "extracting-entry" && typeof path === "string") {
    return `압축 해제: ${path}`;
  }
  return fallbackMessage ?? null;
}

/** SDK error code → page-local review tone (NOT severity ramp). */
function reviewToneForCode(code?: SdkErrorCode): "caution" | "critical" | "fallback" {
  if (!code) return "fallback";
  if (code.startsWith("EXTRACT_") || code.startsWith("VERIFY_")) return "caution";
  if (code.startsWith("INSTALL_") || code.startsWith("UPLOAD_")) return "critical";
  if (code.startsWith("RETRY_") || code === "ANALYZE_UNAVAILABLE") return "caution";
  return "fallback";
}

function SdkStatusBadge({ status }: { status: SdkRegistryStatus }) {
  const config = STATUS_CONFIG[status];
  const icon =
    config.icon === "spin" ? <Loader size={12} className="animate-spin" /> :
    config.icon === "check" ? <CheckCircle size={12} /> :
    <XCircle size={12} />;
  return (
    <span className={`sdk-status-badge sdk-status-badge--${config.tone}`}>
      {icon}
      {config.label}
    </span>
  );
}

interface SdkStepperProps {
  status: SdkRegistryStatus;
  phaseHistory?: SdkPhaseHistoryEntry[];
}

function SdkStepper({ status, phaseHistory }: SdkStepperProps) {
  let activeGroupIndex = -1;
  let failedGroupIndex = -1;
  PHASE_GROUPS.forEach((group, index) => {
    if (group.phases.includes(status)) activeGroupIndex = index;
    if (group.failPhases.includes(status)) failedGroupIndex = index;
  });

  const groupDurationMs = (group: PhaseGroup): number | undefined => {
    if (!phaseHistory || phaseHistory.length === 0) return undefined;
    let total = 0;
    let any = false;
    for (const entry of phaseHistory) {
      if (group.phases.includes(entry.phase as SdkRegistryStatus) && entry.durationMs != null) {
        total += entry.durationMs;
        any = true;
      }
    }
    return any ? total : undefined;
  };

  return (
    <div className="sdk-stepper">
      {PHASE_GROUPS.map((group, index) => {
        const failed = failedGroupIndex === index;
        const done = failedGroupIndex >= 0
          ? index < failedGroupIndex
          : activeGroupIndex >= 0
            ? index < activeGroupIndex
            : false;
        const active = !failed && activeGroupIndex === index;
        const stepClassName = [
          "sdk-stepper__step",
          failed ? "sdk-stepper__step--failed" : "",
          done ? "sdk-stepper__step--done" : "",
          active ? "sdk-stepper__step--active" : "",
        ].filter(Boolean).join(" ");
        const lineClassName = done ? "sdk-stepper__line sdk-stepper__line--done" : "sdk-stepper__line";
        const duration = done ? groupDurationMs(group) : undefined;
        const durationLabel = duration != null ? formatDurationMs(duration) : null;
        return (
          <React.Fragment key={group.label}>
            {index > 0 ? <span className={lineClassName} /> : null}
            <span className={stepClassName}>
              <span className="sdk-stepper__dot" />
              {group.label}
              {durationLabel ? (
                <span className="sdk-stepper__duration">{durationLabel}</span>
              ) : null}
            </span>
          </React.Fragment>
        );
      })}
    </div>
  );
}

function ProfileDetail({ profile }: { profile: SdkAnalyzedProfile }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="sdk-profile-detail">
      <button
        type="button"
        className="btn btn-ghost btn-sm sdk-profile-detail__toggle"
        onClick={() => setOpen((prev) => !prev)}
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        분석된 프로파일
      </button>
      {open ? (
        <div className="sdk-profile-detail__body">
          {profile.compiler ? <div><strong>컴파일러:</strong> {profile.compiler}</div> : null}
          {profile.gccVersion ? <div><strong>GCC 버전:</strong> {profile.gccVersion}</div> : null}
          {profile.targetArch ? <div><strong>아키텍처:</strong> {profile.targetArch}</div> : null}
          {profile.languageStandard ? <div><strong>언어 표준:</strong> {profile.languageStandard}</div> : null}
          {profile.sysroot ? <div><strong>Sysroot:</strong> <code>{profile.sysroot}</code></div> : null}
          {profile.environmentSetup ? <div><strong>환경 스크립트:</strong> <code>{profile.environmentSetup}</code></div> : null}
          {profile.includePaths?.length ? (
            <div>
              <strong>Include paths:</strong>{" "}
              {profile.includePaths.map((path) => <code key={path}>{path}</code>)}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function artifactLabel(kind?: RegisteredSdk["artifactKind"]) {
  if (kind === "archive") return { icon: <Archive size={12} />, label: "아카이브" };
  if (kind === "bin") return { icon: <Binary size={12} />, label: "바이너리" };
  return { icon: <FolderOpen size={12} />, label: "폴더" };
}

interface PhaseElapsedProps {
  phaseStartedAt?: number;
}

/** Live phase elapsed counter (1s tick). Pauses on body.no-live or prefers-reduced-motion. */
function PhaseElapsed({ phaseStartedAt }: PhaseElapsedProps) {
  const [now, setNow] = useState<number>(() => Date.now());
  const [paused, setPaused] = useState<boolean>(() => liveSignalsPaused());

  useEffect(() => {
    if (typeof window === "undefined") return;
    let mql: MediaQueryList | null = null;
    let handleMql: ((e: MediaQueryListEvent) => void) | null = null;
    try {
      mql = window.matchMedia("(prefers-reduced-motion: reduce)");
      handleMql = () => setPaused(liveSignalsPaused());
      if (typeof mql.addEventListener === "function") {
        mql.addEventListener("change", handleMql);
      }
    } catch {
      mql = null;
    }
    let observer: MutationObserver | null = null;
    if (typeof document !== "undefined" && typeof MutationObserver !== "undefined") {
      observer = new MutationObserver(() => setPaused(liveSignalsPaused()));
      observer.observe(document.body, { attributes: true, attributeFilter: ["class"] });
    }
    return () => {
      if (mql && handleMql && typeof mql.removeEventListener === "function") {
        mql.removeEventListener("change", handleMql);
      }
      if (observer) observer.disconnect();
    };
  }, []);

  useEffect(() => {
    if (paused || phaseStartedAt == null) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [paused, phaseStartedAt]);

  if (phaseStartedAt == null) return null;
  const seconds = Math.max(0, ((paused ? now : Date.now()) - phaseStartedAt) / 1000);
  return (
    <span className="sdk-card__elapsed">
      <span className="sdk-card__meta-key">ELAPSED</span>
      <span>{formatElapsedSeconds(seconds)}</span>
    </span>
  );
}

interface SdkLogPanelProps {
  projectId: string;
  sdk: RegisteredSdk;
  onClose: () => void;
}

function SdkLogPanel({ projectId, sdk, onClose }: SdkLogPanelProps) {
  const [content, setContent] = useState<string>("");
  const [totalLines, setTotalLines] = useState<number | undefined>(undefined);
  const [nextOffset, setNextOffset] = useState<number | undefined>(undefined);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const requestedRef = useRef<boolean>(false);

  const loadInitial = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res: SdkLogResponse = await fetchSdkLog(projectId, sdk.id, { tailLines: 200 });
      setContent(res.content);
      setTotalLines(res.totalLines);
      setNextOffset(res.nextOffset);
    } catch (e) {
      logError("Fetch SDK log", e);
      setError("로그를 불러오지 못했습니다.");
    } finally {
      setLoading(false);
    }
  }, [projectId, sdk.id]);

  const loadMore = useCallback(async () => {
    if (nextOffset == null) return;
    setLoading(true);
    setError(null);
    try {
      const res: SdkLogResponse = await fetchSdkLog(projectId, sdk.id, { offset: nextOffset, limit: 500 });
      setContent((prev) => (prev ? `${prev}\n${res.content}` : res.content));
      setTotalLines(res.totalLines);
      setNextOffset(res.nextOffset);
    } catch (e) {
      logError("Fetch SDK log more", e);
      setError("로그를 더 불러오지 못했습니다.");
    } finally {
      setLoading(false);
    }
  }, [projectId, sdk.id, nextOffset]);

  useEffect(() => {
    if (requestedRef.current) return;
    requestedRef.current = true;
    void loadInitial();
  }, [loadInitial]);

  return (
    <div className="sdk-log-panel" role="region" aria-label={`${sdk.name} 설치 로그`}>
      <div className="sdk-log-panel__head">
        <div className="sdk-log-panel__title">
          <FileText size={12} aria-hidden="true" />
          <span className="sdk-card__meta-key">INSTALL LOG</span>
          {totalLines != null ? (
            <span className="sdk-log-panel__total">총 {totalLines}줄</span>
          ) : null}
        </div>
        <div className="sdk-log-panel__actions">
          <a
            className="btn btn-ghost btn-sm"
            href={getSdkLogDownloadUrl(projectId, sdk.id)}
            download
            target="_blank"
            rel="noopener"
          >
            <Download size={12} /> 로그 다운로드
          </a>
          <button
            type="button"
            className="btn btn-ghost btn-icon-sm"
            onClick={onClose}
            aria-label="로그 패널 닫기"
          >
            <X size={14} />
          </button>
        </div>
      </div>
      {error ? (
        <div className="sdk-log-panel__error">{error}</div>
      ) : null}
      <pre className="sdk-log-panel__pre" aria-live="polite">{content || (loading ? "로그를 불러오는 중..." : "로그가 비어 있습니다.")}</pre>
      {nextOffset != null ? (
        <div className="sdk-log-panel__more">
          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={() => void loadMore()}
            disabled={loading}
          >
            {loading ? "불러오는 중..." : "더 보기"}
          </button>
        </div>
      ) : null}
    </div>
  );
}

interface ReadyMetaRowProps {
  sdk: RegisteredSdk;
}

function ReadyMetaRow({ sdk }: ReadyMetaRowProps) {
  const profile = sdk.profile;
  const items: Array<{ key: string; value: string; mono?: boolean }> = [];
  if (sdk.sdkVersion ?? profile?.sdkVersion) {
    items.push({ key: "VER", value: (sdk.sdkVersion ?? profile?.sdkVersion) as string, mono: true });
  }
  if (sdk.targetSystem ?? profile?.targetSystem) {
    items.push({ key: "TARGET", value: (sdk.targetSystem ?? profile?.targetSystem) as string, mono: true });
  }
  if (profile?.compiler) items.push({ key: "CC", value: profile.compiler, mono: true });
  if (profile?.gccVersion) items.push({ key: "GCC", value: profile.gccVersion, mono: true });
  if (profile?.targetArch) items.push({ key: "ARCH", value: profile.targetArch, mono: true });
  if (profile?.languageStandard) items.push({ key: "STD", value: profile.languageStandard, mono: true });
  if (profile?.sysroot) items.push({ key: "SYSROOT", value: profile.sysroot, mono: true });
  if (sdk.artifactKind ?? profile?.artifactKind) {
    items.push({ key: "KIND", value: (sdk.artifactKind ?? profile?.artifactKind) as string, mono: true });
  }
  if (items.length === 0) return null;
  return (
    <div className="sdk-row__meta">
      {items.map((item) => (
        <span key={item.key}>
          <b>{item.key}</b> {item.mono ? <code>{item.value}</code> : item.value}
        </span>
      ))}
    </div>
  );
}

export const SdkManagementSection: React.FC<SdkManagementSectionProps> = ({
  projectId,
  registered,
  sdkProgressById,
  sdkErrorDetailsById,
  sdkQuota,
  retryingSdkIds,
  showForm,
  onToggleForm,
  onRegistered,
  onCancelForm,
  onRequestDelete,
  onRetry,
}) => {
  const [logOpenSdkId, setLogOpenSdkId] = useState<string | null>(null);
  const [techOpenSdkId, setTechOpenSdkId] = useState<string | null>(null);

  const quotaExceeded = sdkQuota != null && sdkQuota.usedBytes >= sdkQuota.maxBytes;
  const addDisabled = quotaExceeded;
  const addDisabledReason = quotaExceeded
    ? "프로젝트 SDK 저장 용량을 초과했습니다. 기존 SDK를 삭제한 뒤 다시 시도하세요."
    : null;

  return (
    <section className="ps-section" data-pane="sdk" role="tabpanel" aria-label="SDK 관리">
      <div className="ps-section-head">
        <div>
          <h2 className="ps-section-head__title">SDK 관리</h2>
          <p className="ps-section-head__desc">
            크로스 컴파일 SDK를 등록하면 BuildTarget 분석 시 해당 툴체인이 자동으로 사용됩니다.
            업로드 후 AI가 컴파일러·아키텍처 프로파일을 자동 추출하고, 검증을 거쳐{" "}
            <code className="ps-chip-code">ready</code> 상태가 되어야 분석에 사용됩니다.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary btn-sm"
          onClick={onToggleForm}
          disabled={addDisabled}
          title={addDisabled && addDisabledReason ? addDisabledReason : undefined}
        >
          <Plus size={14} />
          SDK 추가
        </button>
      </div>

      <SdkMetricsPanel projectId={projectId} />

      <SdkProfilesPanel />

      {showForm ? (
        <div className="panel ps-sdk__upload-card">
          <div className="panel-head">
            <h3>
              <Upload size={14} aria-hidden="true" />
              새 SDK 등록
            </h3>
            <button
              type="button"
              className="btn btn-ghost btn-icon-sm"
              onClick={onCancelForm}
              aria-label="업로드 폼 닫기"
            >
              <X size={14} />
            </button>
          </div>
          <div className="panel-body ps-sdk__form-slot">
            <SdkUploadForm projectId={projectId} onRegistered={onRegistered} onCancel={onCancelForm} />
          </div>
        </div>
      ) : null}

      <div className="panel">
        <div className="panel-head">
          <h3>
            등록된 SDK
            <span className="count">{registered.length}</span>
          </h3>
          {sdkQuota ? (
            <span
              className={`sdk-quota${quotaExceeded ? " sdk-quota--exceeded" : ""}`}
              title="프로젝트 SDK 저장 사용량"
            >
              <span className="sdk-card__meta-key">QUOTA</span>
              <code>
                {formatBytes(sdkQuota.usedBytes) ?? "0 B"} / {formatBytes(sdkQuota.maxBytes) ?? "—"}
              </code>
            </span>
          ) : null}
        </div>

        {registered.length === 0 ? (
          <div className="panel-body ps-sdk__empty">
            <p className="ps-reserved__title">등록된 SDK가 없습니다</p>
            <p className="ps-reserved__desc">
              상단 <code className="ps-chip-code">SDK 추가</code> 버튼으로 크로스 컴파일 SDK를 등록하세요.
            </p>
          </div>
        ) : (
          <div className="ps-sdk-list">
            {registered.map((sdk) => {
              const isFailed = sdk.status.endsWith("_failed");
              const isReady = sdk.status === "ready";
              const isActive = !isFailed && !isReady;
              const kind = sdk.artifactKind ? artifactLabel(sdk.artifactKind) : null;
              const details = sdkProgressById[sdk.id];
              const errorDetails = sdkErrorDetailsById[sdk.id];
              const byteSummary = details?.uploadedBytes != null && details?.totalBytes != null
                ? `${formatBytes(details.uploadedBytes)} / ${formatBytes(details.totalBytes)}`
                : null;
              const uploadPercent = details?.percent != null
                ? Math.max(0, Math.min(100, details.percent))
                : null;
              const phaseStartedAt = details?.phaseStartedAt ?? sdk.currentPhaseStartedAt;
              const phaseDetailCopy = formatPhaseDetail(details?.phaseDetail);
              const isRetrying = retryingSdkIds.has(sdk.id);
              const retryExpired = sdk.retryExpiresAt != null && sdk.retryExpiresAt < Date.now();
              const retryable = isFailed && (sdk.retryable ?? errorDetails?.retryable ?? false) && !retryExpired;
              const retryDisabledReason = !isFailed
                ? null
                : retryExpired
                  ? "재시도 가능 기간이 만료되었습니다."
                  : !(sdk.retryable ?? errorDetails?.retryable ?? false)
                    ? "이 실패는 재시도할 수 없습니다. 새 SDK를 업로드하세요."
                    : null;

              if (isReady) {
                return (
                  <div key={sdk.id} className="sdk-row sdk-row--ready">
                    <span className="sdk-row__rail" aria-hidden="true" />
                    <div className="sdk-row__name">
                      <span className="sdk-row__title">{sdk.name}</span>
                      {kind ? (
                        <span className="sdk-row__kind">
                          {kind.icon}
                          {kind.label}
                        </span>
                      ) : null}
                      <SdkStatusBadge status={sdk.status} />
                    </div>
                    <ReadyMetaRow sdk={sdk} />
                    <button
                      type="button"
                      className="btn btn-ghost btn-icon-sm sdk-row__delete"
                      title="삭제"
                      aria-label={`${sdk.name} 삭제`}
                      onClick={() => onRequestDelete(sdk)}
                    >
                      <Trash2 size={14} />
                    </button>
                    {sdk.profile ? (
                      <div className="sdk-row__profile">
                        <ProfileDetail profile={sdk.profile} />
                      </div>
                    ) : null}
                  </div>
                );
              }

              const expandedClass = [
                "sdk-expanded",
                isActive ? "sdk-expanded--active" : "",
                isFailed ? "sdk-expanded--failed" : "",
              ].filter(Boolean).join(" ");

              const userMessage = errorDetails?.userMessage ?? sdk.verifyError;
              const tone = reviewToneForCode(errorDetails?.code);
              const errToneClass =
                tone === "critical" ? "sdk-err-block--critical" :
                tone === "caution" ? "sdk-err-block--caution" :
                "sdk-err-block--fallback";
              const techOpen = techOpenSdkId === sdk.id;
              const logOpen = logOpenSdkId === sdk.id;

              return (
                <div key={sdk.id} className={expandedClass}>
                  <span className="sdk-expanded__rail" aria-hidden="true" />
                  <div className="sdk-expanded__body">
                    <div className="sdk-expanded__top">
                      <div className="sdk-expanded__title">
                        <span className="sdk-row__title">{sdk.name}</span>
                        {kind ? (
                          <span className="sdk-row__kind">
                            {kind.icon}
                            {kind.label}
                          </span>
                        ) : null}
                        <SdkStatusBadge status={sdk.status} />
                      </div>
                      <div className="sdk-expanded__actions">
                        {isFailed && retryable ? (
                          <button
                            type="button"
                            className="btn btn-outline btn-sm"
                            onClick={() => onRetry(sdk)}
                            disabled={isRetrying}
                          >
                            <RefreshCcw size={12} />
                            {isRetrying ? "재시도 중..." : "재시도"}
                          </button>
                        ) : isFailed ? (
                          <button
                            type="button"
                            className="btn btn-outline btn-sm"
                            disabled
                            title={retryDisabledReason ?? undefined}
                          >
                            <RefreshCcw size={12} />
                            재시도
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="btn btn-ghost btn-icon-sm"
                          title="삭제"
                          aria-label={`${sdk.name} 삭제`}
                          onClick={() => onRequestDelete(sdk)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>

                    {sdk.description ? (
                      <p className="sdk-card__desc">{sdk.description}</p>
                    ) : null}

                    {(sdk.sdkVersion || sdk.targetSystem) ? (
                      <div className="sdk-card__meta">
                        {sdk.sdkVersion ? (
                          <span>
                            <span className="sdk-card__meta-key">VER</span>
                            <code>{sdk.sdkVersion}</code>
                          </span>
                        ) : null}
                        {sdk.targetSystem ? (
                          <span>
                            <span className="sdk-card__meta-key">TARGET</span>
                            <code>{sdk.targetSystem}</code>
                          </span>
                        ) : null}
                      </div>
                    ) : null}

                    {isActive ? (
                      <SdkStepper status={sdk.status} phaseHistory={sdk.phaseHistory} />
                    ) : null}

                    {isActive ? (
                      <div className="sdk-card__live-meta">
                        {phaseStartedAt != null ? (
                          <PhaseElapsed phaseStartedAt={phaseStartedAt} />
                        ) : null}
                        {details?.etaSeconds != null ? (
                          <span className="sdk-card__eta">
                            <span className="sdk-card__meta-key">ETA</span>
                            <span>~{Math.max(0, Math.round(details.etaSeconds))}초</span>
                          </span>
                        ) : null}
                        {phaseDetailCopy ? (
                          <span className="sdk-card__phase-detail">{phaseDetailCopy}</span>
                        ) : null}
                      </div>
                    ) : null}

                    {sdk.status === "uploading" ? (
                      <div className="sdk-card__progress">
                        <div className="sdk-card__progress-head">
                          <span className="sdk-card__progress-label">업로드 진행률</span>
                          {uploadPercent != null ? (
                            <span className="sdk-card__progress-value">{uploadPercent}%</span>
                          ) : null}
                        </div>
                        {details?.fileName ? (
                          <div className="sdk-card__progress-file">{details.fileName}</div>
                        ) : null}
                        {byteSummary ? (
                          <div className="sdk-card__progress-bytes">
                            <span>{byteSummary}</span>
                            {uploadPercent != null ? (
                              <span className="sdk-card__progress-bytes-pct"> ({uploadPercent}%)</span>
                            ) : null}
                          </div>
                        ) : null}
                        {uploadPercent != null ? (
                          <div className="sdk-card__progress-track" aria-label="SDK upload progress">
                            <div
                              className="sdk-card__progress-fill"
                              style={{ width: `${uploadPercent}%` }}
                            />
                          </div>
                        ) : null}
                      </div>
                    ) : null}

                    {isFailed && (userMessage || errorDetails || sdk.installLogPath) ? (
                      <div className={`sdk-err-block ${errToneClass}`}>
                        {userMessage ? (
                          <div className="sdk-err-block__msg">{userMessage}</div>
                        ) : null}
                        {(errorDetails?.failedAt != null || errorDetails?.correlationId) ? (
                          <div className="sdk-err-block__attrs">
                            {errorDetails?.failedAt != null ? (
                              <span>
                                <span className="sdk-card__meta-key">FAILED AT</span>
                                <code>{formatTimestampKo(errorDetails.failedAt) ?? "—"}</code>
                              </span>
                            ) : null}
                            {errorDetails?.correlationId ? (
                              <span>
                                <span className="sdk-card__meta-key">문의 ID</span>
                                <code>{errorDetails.correlationId}</code>
                              </span>
                            ) : null}
                            {errorDetails?.code ? (
                              <span>
                                <span className="sdk-card__meta-key">CODE</span>
                                <code>{errorDetails.code}</code>
                              </span>
                            ) : null}
                          </div>
                        ) : null}
                        {errorDetails?.technicalDetail ? (
                          <div className="sdk-err-block__tech">
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm sdk-err-block__tech-toggle"
                              onClick={() =>
                                setTechOpenSdkId((prev) => (prev === sdk.id ? null : sdk.id))
                              }
                              aria-expanded={techOpen}
                            >
                              {techOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                              <span className="sdk-card__meta-key">기술 상세</span>
                            </button>
                            {techOpen ? (
                              <pre className="sdk-err-block__tech-body">{errorDetails.technicalDetail}</pre>
                            ) : null}
                          </div>
                        ) : null}
                        <div className="sdk-err-block__cta">
                          {(sdk.installLogPath || errorDetails) ? (
                            <button
                              type="button"
                              className="btn btn-outline btn-sm"
                              onClick={() =>
                                setLogOpenSdkId((prev) => (prev === sdk.id ? null : sdk.id))
                              }
                              aria-expanded={logOpen}
                            >
                              <FileText size={12} />
                              {logOpen ? "로그 닫기" : "로그 보기"}
                            </button>
                          ) : null}
                          {errorDetails?.troubleshootingUrl ? (
                            <a
                              className="btn btn-outline btn-sm"
                              href={errorDetails.troubleshootingUrl}
                              target="_blank"
                              rel="noopener"
                            >
                              <ExternalLink size={12} />
                              문제 해결 가이드
                            </a>
                          ) : null}
                        </div>
                      </div>
                    ) : null}

                    {logOpen ? (
                      <SdkLogPanel
                        projectId={projectId}
                        sdk={sdk}
                        onClose={() => setLogOpenSdkId(null)}
                      />
                    ) : null}

                    {sdk.profile ? <ProfileDetail profile={sdk.profile} /> : null}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
};
