import "./SdkProfilesPanel.css";
import React, { useEffect, useState } from "react";
import { Library } from "lucide-react";
import { fetchSdkProfiles, type SdkProfile } from "@/common/api/sdk";
import { logError } from "@/common/api/core";

/** SDK profiles registry list — canonical profiles available across the
 *  org (not project-scoped). Read-only; serves as a reference catalog
 *  while the upload form remains the actual SDK registration entry. */
export const SdkProfilesPanel: React.FC = () => {
  const [profiles, setProfiles] = useState<SdkProfile[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const data = await fetchSdkProfiles();
        if (!cancelled) {
          setProfiles(data);
          setLoaded(true);
        }
      } catch (error) {
        logError("Fetch SDK profiles", error);
        if (!cancelled) {
          setProfiles([]);
          setLoaded(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!loaded) return null;

  return (
    <div className="panel sdk-profiles-panel">
      <div className="panel-head">
        <h3>
          <Library size={14} aria-hidden="true" />
          SDK 프로파일
          <span className="count">{profiles.length}</span>
        </h3>
        <span className="panel-hint" aria-hidden="true">
          등록 가능한 표준 SDK 프로파일 카탈로그
        </span>
      </div>

      {profiles.length === 0 ? (
        <div className="panel-body sdk-profiles-panel__empty">
          <p className="sdk-profiles-panel__empty-title">표시할 프로파일이 없습니다</p>
          <p className="sdk-profiles-panel__empty-desc">
            카탈로그가 비어 있거나 아직 동기화되지 않았습니다.
          </p>
        </div>
      ) : (
        <ul className="panel-body sdk-profiles-panel__list" role="list">
          {profiles.map((profile) => (
            <li key={profile.id} className="sdk-profiles-panel__item">
              <div className="sdk-profiles-panel__item-main">
                <span className="sdk-profiles-panel__name">{profile.name}</span>
                {/* vendor is required string; empty string renders as empty meta cell (acceptable) */}
                <span className="sdk-profiles-panel__vendor">{profile.vendor}</span>
              </div>
              {profile.description ? (
                <p className="sdk-profiles-panel__description">{profile.description}</p>
              ) : null}
              <div className="sdk-profiles-panel__meta">
                <code className="sdk-profiles-panel__id">{profile.id}</code>
                <span className="sdk-profiles-panel__defaults">
                  <span className="sdk-profiles-panel__chip">
                    <span className="sdk-profiles-panel__chip-label">COMPILER</span>
                    <span className="sdk-profiles-panel__chip-value">{profile.defaults.compiler}</span>
                  </span>
                  <span className="sdk-profiles-panel__chip">
                    <span className="sdk-profiles-panel__chip-label">ARCH</span>
                    <span className="sdk-profiles-panel__chip-value">{profile.defaults.targetArch}</span>
                  </span>
                  <span className="sdk-profiles-panel__chip">
                    <span className="sdk-profiles-panel__chip-label">STD</span>
                    <span className="sdk-profiles-panel__chip-value">{profile.defaults.languageStandard}</span>
                  </span>
                  <span className="sdk-profiles-panel__chip">
                    <span className="sdk-profiles-panel__chip-label">HEADER</span>
                    <span className="sdk-profiles-panel__chip-value">{profile.defaults.headerLanguage}</span>
                  </span>
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
