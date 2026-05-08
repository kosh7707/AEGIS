import React, { useCallback, useEffect, useMemo } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { ShieldQuestion, Settings2, Play, BookOpen, GitCommitHorizontal } from "lucide-react";
import { useToast } from "@/common/contexts/ToastContext";
import { PageHeader, Spinner } from "@/common/ui/primitives";
import { QualityGateCard } from "./components/QualityGateCard/QualityGateCard";
import { QualityGateHeroVerdict } from "./components/QualityGateHeroVerdict/QualityGateHeroVerdict";
import { QualityGateOverrideModal } from "./components/QualityGateOverrideModal/QualityGateOverrideModal";
import { QualityGateRunSection } from "./components/QualityGateRunSection/QualityGateRunSection";
import { QualityGateSidebar } from "./components/QualityGateSidebar/QualityGateSidebar";
import { useQualityGatePageController } from "./useQualityGatePageController";
import "./QualityGatePage.css";

export const QualityGatePage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const [searchParams] = useSearchParams();
  const runId = searchParams.get("runId") ?? undefined;
  const toast = useToast();
  const {
    gates,
    latestGate,
    loading,
    overrideTarget,
    setOverrideTarget,
    overrideReason,
    setOverrideReason,
    overriding,
    resetOverrideDraft,
    handleOverride,
    gateProfilesById,
  } = useQualityGatePageController(projectId, toast);

  useEffect(() => {
    document.title = "AEGIS — 품질 게이트";
  }, []);

  const overrideGate = useMemo(
    () => gates.find((gate) => gate.id === overrideTarget) ?? null,
    [gates, overrideTarget],
  );

  const handleRequestOverride = useCallback(
    (gateId: string) => setOverrideTarget(gateId),
    [setOverrideTarget],
  );

  if (loading) {
    return (
      <div className="page-loading-shell">
        <Spinner size={36} label="품질 게이트 로딩 중..." />
      </div>
    );
  }

  if (gates.length === 0) {
    return (
      <div className="page-shell quality-gate-page" data-mode="no-gate-evaluated">
        <PageHeader
          surface="plain"
          title="품질 게이트"
          subtitle="실패한 규칙, 경고 항목, 오버라이드 이력을 운영 순서대로 검토합니다."
        />

        <section
          className="empty-state quality-gate-empty is-pending"
          aria-label="아직 평가 이력이 없습니다"
        >
          <div className="empty-state__icon" aria-hidden="true">
            <ShieldQuestion />
          </div>
          <div className="empty-state__copy">
            <h2 className="empty-state__title">아직 평가 이력이 없습니다</h2>
            <p className="empty-state__desc">
              분석을 실행하면 활성 정책 프로필의 규칙이 평가되고 결과가 여기에 표시됩니다.
              머지 차단 여부는 게이트 결과에 따라 자동 결정됩니다.
            </p>
          </div>
          <div className="empty-state__actions">
            <button type="button" className="btn btn-primary btn-sm" disabled>
              <Play aria-hidden="true" />
              첫 평가 실행
            </button>
            <button type="button" className="btn btn-outline btn-sm" disabled>
              <BookOpen aria-hidden="true" />
              게이트 가이드
            </button>
          </div>
          <div className="empty-state__hint">
            <Settings2 aria-hidden="true" />
            <span>활성 정책 프로필이 도착하면 여기에 표시됩니다.</span>
          </div>
          <div className="empty-state__hint quality-gate-empty__commit-hint">
            <GitCommitHorizontal aria-hidden="true" />
            <span>분석 대상 commit/branch 정보는 첫 평가 후 채워집니다.</span>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="page-shell quality-gate-page">
      <PageHeader
        surface="plain"
        title="품질 게이트"
        subtitle="실패한 규칙, 경고 항목, 오버라이드 이력을 운영 순서대로 검토합니다."
      />

      {latestGate ? <QualityGateHeroVerdict gate={latestGate} /> : null}

      {projectId && runId ? (
        <QualityGateRunSection
          projectId={projectId}
          runId={runId}
          gateProfilesById={gateProfilesById}
          onRequestOverride={handleRequestOverride}
        />
      ) : null}

      <div className="quality-gate-layout">
        <div className="quality-gate-main">
          {gates.map((gate) => (
            <QualityGateCard
              key={gate.id}
              gate={gate}
              profile={gate.profileId ? gateProfilesById[gate.profileId] : undefined}
              onRequestOverride={handleRequestOverride}
            />
          ))}
        </div>
        <QualityGateSidebar gates={gates} />
      </div>

      <QualityGateOverrideModal
        open={overrideTarget !== null}
        gate={overrideGate}
        reason={overrideReason}
        onChangeReason={setOverrideReason}
        submitting={overriding}
        onClose={resetOverrideDraft}
        onSubmit={handleOverride}
      />
    </div>
  );
};
