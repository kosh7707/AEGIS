import React, { useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { BackButton, PageHeader } from "@/common/ui/primitives";
import { useProjects } from "@/common/contexts/ProjectContext";
import { SettingsApiAccessSection } from "./components/SettingsApiAccessSection/SettingsApiAccessSection";
import { SettingsBackendSection } from "./components/SettingsBackendSection/SettingsBackendSection";
import { SettingsLlmGatewaySection } from "./components/SettingsLlmGatewaySection/SettingsLlmGatewaySection";
import { SettingsPlatformSection } from "./components/SettingsPlatformSection/SettingsPlatformSection";
import { SettingsThemeSection } from "./components/SettingsThemeSection/SettingsThemeSection";
import { useSettingsPageController } from "./useSettingsPageController";
import "./SettingsPage.css";

const PROJECT_ROUTE_RE = /^\/projects\/([^/]+)(?:\/|$)/;

type BackTarget = {
  label: string;
  resolve: () => void;
};

function useBackTarget(): BackTarget {
  const navigate = useNavigate();
  const location = useLocation();
  const { getProject } = useProjects();

  return useMemo(() => {
    const state = location.state as { from?: string } | null;
    const from = state?.from;

    if (from) {
      const match = PROJECT_ROUTE_RE.exec(from);
      const label = match ? (getProject(match[1])?.name ?? "뒤로") : "뒤로";
      return { label, resolve: () => navigate(from) };
    }

    return { label: "뒤로", resolve: () => navigate(-1) };
  }, [location.state, navigate, getProject]);
}

export const SettingsPage: React.FC = () => {
  const {
    url,
    saved,
    testStatus,
    testDetail,
    theme,
    dirty,
    llmGateway,
    handleUrlChange,
    handleThemeChange,
    handleSave,
    handleReset,
    handleCancel,
    handleTest,
  } = useSettingsPageController();

  const backTarget = useBackTarget();

  return (
    <div className="page-shell settings-page">
      <PageHeader
        surface="plain"
        title="시스템 설정"
        action={<BackButton onClick={backTarget.resolve} label={backTarget.label} />}
      />

      <section className="settings-section settings-section--1">
        <header className="settings-section__head">
          <span className="settings-section__label">Backend</span>
          <span className="settings-section__meta">api.v1</span>
        </header>
        <SettingsBackendSection
          url={url}
          testStatus={testStatus}
          testDetail={testDetail}
          onUrlChange={handleUrlChange}
          onTest={handleTest}
          onReset={handleReset}
        />
      </section>

      <section className="settings-section settings-section--2">
        <header className="settings-section__head">
          <span className="settings-section__label">Appearance</span>
          <span className="settings-section__meta">local preference</span>
        </header>
        <SettingsThemeSection theme={theme} onThemeChange={handleThemeChange} />
      </section>

      <section className="settings-section settings-section--3">
        <header className="settings-section__head">
          <span className="settings-section__label">Endpoint</span>
          <span className="settings-section__meta">derived</span>
        </header>
        <SettingsApiAccessSection url={url} testStatus={testStatus} />
      </section>

      <section className="settings-section settings-section--4">
        <header className="settings-section__head">
          <span className="settings-section__label">Services</span>
          <span className="settings-section__meta">live readiness</span>
        </header>
        <SettingsLlmGatewaySection llmGateway={llmGateway} />
      </section>

      <section className="settings-section settings-section--5">
        <header className="settings-section__head">
          <span className="settings-section__label">Platform</span>
          <span className="settings-section__meta">runtime</span>
        </header>
        <SettingsPlatformSection />
      </section>

      {dirty ? (
        <div className="settings-savebar" role="group" aria-label="변경사항 제어">
          <div className="settings-savebar__signal">
            <span className="settings-savebar__dot" aria-hidden="true" />
            <span className="settings-savebar__label">저장되지 않은 변경</span>
          </div>
          <div className="settings-savebar__actions">
            <button type="button" className="btn btn-ghost btn-sm" onClick={handleCancel}>
              취소
            </button>
            <button type="button" className="btn btn-primary btn-sm" onClick={handleSave}>
              {saved ? "저장됨" : "저장"}
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
};
