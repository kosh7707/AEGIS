import "./StaticAnalysisUploadScreen.css";
import React from "react";
import { BackButton, PageHeader } from "@/common/ui/primitives";
import type { AnalysisMode } from "@/common/hooks/useAnalysisWebSocket";
import { SourceUploadView } from "../SourceUploadView/SourceUploadView";

type StaticAnalysisUploadScreenProps = {
  projectId: string;
  onBack: () => void;
  onAnalysisStart: (mode: AnalysisMode) => void;
  onBrowseTree: () => void;
  onDiscoverTargets: () => void;
  onPrepare?: () => void;
  isPreparing?: boolean;
};

export function StaticAnalysisUploadScreen({
  projectId,
  onBack,
  onAnalysisStart,
  onBrowseTree,
  onDiscoverTargets,
  onPrepare,
  isPreparing,
}: StaticAnalysisUploadScreenProps) {
  return (
    <div className="page-shell static-analysis-upload-screen">
      <BackButton onClick={onBack} label="대시보드로" />
      <PageHeader title="소스코드 업로드" />
      <SourceUploadView
        projectId={projectId}
        onAnalysisStart={onAnalysisStart}
        onBrowseTree={onBrowseTree}
        onDiscoverTargets={onDiscoverTargets}
        onPrepare={onPrepare}
        isPreparing={isPreparing}
      />
    </div>
  );
}
