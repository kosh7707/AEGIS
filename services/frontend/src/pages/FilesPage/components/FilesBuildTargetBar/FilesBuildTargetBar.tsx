import "./FilesBuildTargetBar.css";
import React from "react";
import { Trash2, Wrench } from "lucide-react";
import type { useBuildTargets } from "@/common/hooks/useBuildTargets";
import { FilesBuildTargetFilterChips } from "./FilesBuildTargetFilterChips/FilesBuildTargetFilterChips";

interface FilesBuildTargetBarProps {
  targets: ReturnType<typeof useBuildTargets>["targets"];
  activeTargetFilters: Set<string>;
  onToggleFilter: (targetId: string) => void;
  onClearFilters: () => void;
  onRequestDeleteSource: () => void;
  deletingSource: boolean;
  onPrepareTarget?: (targetId: string) => void;
  isPreparing?: boolean;
  preparingTargetId?: string | null;
}

// E1 — per-target "빌드 검증" mounts here next to the existing filter chips.
// Mount inside the bar (not the workspace) because target identity already lives
// here; signal stays adjacent to its referent.
// E2 — Extend (not Boring/Novel): the trigger button itself becomes the progress
// surface via "빌드 검증 중..." caps-mono label while isPreparing && preparingTargetId
// matches the target. No new component file.
export const FilesBuildTargetBar: React.FC<FilesBuildTargetBarProps> = ({
  targets,
  activeTargetFilters,
  onToggleFilter,
  onClearFilters,
  onRequestDeleteSource,
  deletingSource,
  onPrepareTarget,
  isPreparing,
  preparingTargetId,
}) => (
  <div className="files-build-target-bar">
    <FilesBuildTargetFilterChips
      targets={targets}
      activeTargetFilters={activeTargetFilters}
      onToggleFilter={onToggleFilter}
      onClearFilters={onClearFilters}
    />
    {onPrepareTarget && targets.length > 0 ? (
      <div
        className="files-build-target-bar__prepare-row"
        role="group"
        aria-label="빌드 타겟 검증"
      >
        {isPreparing && !preparingTargetId ? (
          <span className="files-target-prepare__cross-surface-banner">
            다른 화면에서 빌드 검증이 진행 중입니다.
          </span>
        ) : null}
        {targets.map((target) => {
          const active = Boolean(isPreparing) && preparingTargetId === target.id;
          return (
            <button
              key={target.id}
              type="button"
              className="btn btn-outline btn-sm files-target-prepare"
              onClick={() => onPrepareTarget(target.id)}
              disabled={Boolean(isPreparing)}
              title={`${target.name} 빌드 검증`}
              aria-label={`${target.name} 빌드 검증`}
            >
              <Wrench size={14} aria-hidden="true" />
              <span className="files-target-prepare__label">
                {active ? "빌드 검증 중..." : "빌드 검증"}
              </span>
              <span className="files-target-prepare__target">{target.name}</span>
            </button>
          );
        })}
      </div>
    ) : null}
    <button
      type="button"
      className="btn btn-outline btn-sm files-source-bulk-delete"
      onClick={onRequestDeleteSource}
      disabled={deletingSource}
    >
      <Trash2 size={14} aria-hidden="true" />
      <span className="files-source-bulk-delete__label">소스 일괄 삭제</span>
    </button>
  </div>
);
