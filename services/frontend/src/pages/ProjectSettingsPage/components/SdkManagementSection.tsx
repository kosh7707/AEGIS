import React, { useState } from "react";
import { Archive, Binary, CheckCircle, ChevronDown, ChevronRight, FolderOpen, Loader, Plus, Settings, Trash2, XCircle } from "lucide-react";
import type { RegisteredSdk, SdkAnalyzedProfile, SdkRegistryStatus } from "../../../api/sdk";
import type { SdkProgressDetails } from "../../../hooks/useSdkProgress";
import { EmptyState } from "../../../shared/ui";
import { SdkUploadForm } from "./SdkUploadForm";

const STATUS_CONFIG: Record<SdkRegistryStatus, { label: string; icon: "spin" | "check" | "fail"; tone: string }> = {
  uploading: { label: "업로드 중", icon: "spin", tone: "sdk-status-badge--pending" },
  uploaded: { label: "업로드 완료", icon: "spin", tone: "sdk-status-badge--pending" },
  extracting: { label: "압축 해제 중", icon: "spin", tone: "sdk-status-badge--pending" },
  extracted: { label: "압축 해제 완료", icon: "spin", tone: "sdk-status-badge--pending" },
  installing: { label: "설치 중", icon: "spin", tone: "sdk-status-badge--pending" },
  installed: { label: "설치 완료", icon: "spin", tone: "sdk-status-badge--pending" },
  analyzing: { label: "AI 분석 중", icon: "spin", tone: "sdk-status-badge--pending" },
  verifying: { label: "검증 중", icon: "spin", tone: "sdk-status-badge--pending" },
  ready: { label: "사용 가능", icon: "check", tone: "sdk-status-badge--ready" },
  upload_failed: { label: "업로드 실패", icon: "fail", tone: "sdk-status-badge--failed" },
  extract_failed: { label: "압축해제 실패", icon: "fail", tone: "sdk-status-badge--failed" },
  install_failed: { label: "설치 실패", icon: "fail", tone: "sdk-status-badge--failed" },
  verify_failed: { label: "검증 실패", icon: "fail", tone: "sdk-status-badge--failed" },
};

const PHASE_GROUPS: { label: string; phases: SdkRegistryStatus[]; failPhases: SdkRegistryStatus[] }[] = [
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
  sdkLogsById: Record<string, { content: string; truncated: boolean; loading: boolean; logPath?: string }>;
  showForm: boolean;
  onToggleForm: () => void;
  onRegistered: (sdk: RegisteredSdk) => void;
  onCancelForm: () => void;
  onRequestDelete: (sdk: RegisteredSdk) => void;
}

function formatBytes(bytes?: number): string | null {
  if (bytes == null) return null;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function SdkStatusBadge({ status }: { status: SdkRegistryStatus }) {
  const config = STATUS_CONFIG[status];
  const icon = config.icon === "spin"
    ? <Loader size={12} className="animate-spin" />
    : config.icon === "check"
      ? <CheckCircle size={12} />
      : <XCircle size={12} />;

  return <span className={`sdk-status-badge ${config.tone}`}>{icon} {config.label}</span>;
}

function SdkStepper({ status }: { status: SdkRegistryStatus }) {
  let activeGroupIndex = -1;
  let failedGroupIndex = -1;

  PHASE_GROUPS.forEach((group, index) => {
    if (group.phases.includes(status)) activeGroupIndex = index;
    if (group.failPhases.includes(status)) failedGroupIndex = index;
  });

  return (
    <div className="sdk-stepper">
      {PHASE_GROUPS.map((group, index) => {
        const failed = failedGroupIndex === index;
        const done = failedGroupIndex >= 0 ? index < failedGroupIndex : activeGroupIndex >= 0 ? index < activeGroupIndex : false;
        const active = !failed && activeGroupIndex === index;
        const stepClassName = [
          "sdk-stepper__step",
          failed ? "sdk-stepper__step--failed" : "",
          done ? "sdk-stepper__step--done" : "",
          active ? "sdk-stepper__step--active" : "",
        ].filter(Boolean).join(" ");
        const lineClassName = done ? "sdk-stepper__line sdk-stepper__line--done" : "sdk-stepper__line";

        return (
          <React.Fragment key={group.label}>
            {index > 0 && <span className={lineClassName} />}
            <span className={stepClassName}>{group.label}</span>
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
      <button className="sdk-profile-detail__toggle" onClick={() => setOpen((prev) => !prev)}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        분석된 프로파일
      </button>
      {open && (
        <div className="sdk-profile-detail__body">
          {profile.compiler && <div><strong>컴파일러:</strong> {profile.compiler}</div>}
          {profile.gccVersion && <div><strong>GCC 버전:</strong> {profile.gccVersion}</div>}
          {profile.targetArch && <div><strong>아키텍처:</strong> {profile.targetArch}</div>}
          {profile.languageStandard && <div><strong>언어 표준:</strong> {profile.languageStandard}</div>}
          {profile.sysroot && <div><strong>Sysroot:</strong> <code>{profile.sysroot}</code></div>}
          {profile.environmentSetup && <div><strong>환경 스크립트:</strong> <code>{profile.environmentSetup}</code></div>}
          {profile.includePaths && profile.includePaths.length > 0 && (
            <div>
              <strong>Include paths:</strong> {profile.includePaths.map((path) => <code key={path}>{path}</code>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function artifactLabel(kind?: RegisteredSdk["artifactKind"]) {
  if (kind === "archive") return { icon: <Archive size={12} />, label: "아카이브" };
  if (kind === "bin") return { icon: <Binary size={12} />, label: "바이너리" };
  return { icon: <FolderOpen size={12} />, label: "폴더" };
}

export const SdkManagementSection: React.FC<SdkManagementSectionProps> = ({
  projectId,
  registered,
  sdkProgressById,
  sdkLogsById,
  showForm,
  onToggleForm,
  onRegistered,
  onCancelForm,
  onRequestDelete,
}) => (
  <div className="card project-settings-card">
    <div className="project-settings-panel__header">
      <div className="project-settings-panel__icon"><Settings size={18} /></div>
      <div>
        <div className="project-settings-panel__title">SDK 관리</div>
        <div className="project-settings-panel__desc">크로스 컴파일 SDK를 등록하여 서브프로젝트 분석에 사용합니다.</div>
      </div>
    </div>

    <div className="sdk-actions">
      <button className="btn btn-sm" onClick={onToggleForm}>
        <Plus size={14} /> SDK 추가
      </button>
    </div>

    {showForm && (
      <SdkUploadForm projectId={projectId} onRegistered={onRegistered} onCancel={onCancelForm} />
    )}

    {registered.length === 0 ? (
      <EmptyState
        icon={<Settings size={28} />}
        title="등록된 SDK가 없습니다"
        description="SDK 추가 버튼으로 크로스 컴파일 SDK를 등록하세요."
      />
    ) : (
      <div className="sdk-list">
        {registered.map((sdk) => {
          const cardClassName = [
            "card",
            "sdk-card",
            "sdk-card--registered",
            sdk.status.endsWith("_failed") ? "sdk-card--failed" : "",
            sdk.status === "ready" ? "sdk-card--ready" : "",
          ].filter(Boolean).join(" ");
          const kind = sdk.artifactKind ? artifactLabel(sdk.artifactKind) : null;
          const details = sdkProgressById[sdk.id];
          const byteSummary = details?.uploadedBytes != null && details?.totalBytes != null
            ? `${formatBytes(details.uploadedBytes)} / ${formatBytes(details.totalBytes)}`
            : null;
          const uploadPercent = details?.percent != null ? Math.max(0, Math.min(100, details.percent)) : null;
          const sdkLog = sdkLogsById[sdk.id];
          const showLog = Boolean(sdkLog?.content) || Boolean(sdkLog?.loading);

          return (
            <div key={sdk.id} className={cardClassName}>
              <div className="sdk-card__header">
                <span className="sdk-card__name">{sdk.name}</span>
                {kind && (
                  <span className="sdk-card__kind">
                    {kind.icon}
                    {kind.label}
                  </span>
                )}
                <SdkStatusBadge status={sdk.status} />
                <button className="btn-icon btn-danger" title="삭제" onClick={() => onRequestDelete(sdk)}>
                  <Trash2 size={14} />
                </button>
              </div>

              {sdk.description && <p className="sdk-card__desc">{sdk.description}</p>}

              {(sdk.sdkVersion || sdk.targetSystem) && (
                <div className="sdk-card__meta">
                  {sdk.sdkVersion && <span>버전: <code>{sdk.sdkVersion}</code></span>}
                  {sdk.targetSystem && <span>타겟: <code>{sdk.targetSystem}</code></span>}
                </div>
              )}

              {sdk.path && <div className="sdk-card__path"><code>{sdk.path}</code></div>}
              {sdk.status === "uploading" && (
                <div className="sdk-card__progress">
                  <div className="sdk-card__progress-head">
                    <span className="sdk-card__progress-label">업로드 진행률</span>
                    {uploadPercent != null && (
                      <span className="sdk-card__progress-value">{uploadPercent}%</span>
                    )}
                  </div>
                  {details?.fileName && (
                    <div className="sdk-card__progress-file">{details.fileName}</div>
                  )}
                  {byteSummary && (
                    <div className="sdk-card__progress-bytes">{byteSummary}</div>
                  )}
                  {uploadPercent != null && (
                    <div className="sdk-card__progress-track" aria-label="SDK upload progress">
                      <div className="sdk-card__progress-fill" style={{ width: `${uploadPercent}%` }} />
                    </div>
                  )}
                </div>
              )}
              {sdk.status !== "ready" && !sdk.status.endsWith("_failed") && <SdkStepper status={sdk.status} />}
              {sdk.verifyError && <div className="sdk-card__error">{sdk.verifyError}</div>}
              {sdk.status.endsWith("_failed") && sdk.installLogPath && (
                <div className="sdk-card__logpath"><strong>로그 경로:</strong> <code>{sdk.installLogPath}</code></div>
              )}
              {showLog && (
                <div className="sdk-card__install-log">
                  <div className="sdk-card__install-log-head">
                    <span className="sdk-card__install-log-title">Install log</span>
                    {sdkLog?.truncated && <span className="sdk-card__install-log-meta">최근 로그 tail 표시</span>}
                    {sdkLog?.loading && <span className="sdk-card__install-log-meta">복구 중…</span>}
                  </div>
                  <pre className="sdk-card__install-log-body">{sdkLog?.content || ""}</pre>
                </div>
              )}
              {sdk.profile && <ProfileDetail profile={sdk.profile} />}
            </div>
          );
        })}
      </div>
    )}
  </div>
);
