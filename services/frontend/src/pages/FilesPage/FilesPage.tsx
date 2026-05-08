import React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useToast } from "@/common/contexts/ToastContext";
import { useUploadProgress } from "@/common/hooks/useUploadProgress";
import { useBuildTargets } from "@/common/hooks/useBuildTargets";
import { ConfirmDialog } from "@/common/ui/primitives";
import { FilesEmptyState } from "./components/FilesPageChrome/FilesEmptyState/FilesEmptyState";
import { BuildTargetCreateDialog } from "./components/BuildTargetCreateDialog/BuildTargetCreateDialog";
import { FilesPageHeader } from "./components/FilesPageHeader/FilesPageHeader";
import { FilesPageShell } from "./components/FilesPageChrome/FilesPageShell/FilesPageShell";
import { FilesPageLoadingState } from "./components/FilesPageChrome/FilesPageLoadingState/FilesPageLoadingState";
import { FilesUploadBanner } from "./components/FilesPageChrome/FilesUploadBanner/FilesUploadBanner";
import { FilesDropOverlay } from "./components/FilesPageChrome/FilesDropOverlay/FilesDropOverlay";
import { FilesBuildTargetBar } from "./components/FilesBuildTargetBar/FilesBuildTargetBar";
import { FilesSourceWorkspace } from "./components/FilesSourceWorkspace/FilesSourceWorkspace";
import { useFilesPageController } from "./useFilesPageController";
import "./FilesPage.css";

export const FilesPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const upload = useUploadProgress();
  const bt = useBuildTargets(projectId);
  const state = useFilesPageController(projectId, navigate, toast, upload, bt);

  if (state.loading) return <FilesPageLoadingState />;
  if (!projectId) return null;

  const handleOpenInDetail = (path: string) => {
    navigate(`/projects/${projectId}/files/${encodeURIComponent(path)}`);
  };

  const showEmpty = state.sourceFiles.length === 0 && !state.upload.isActive;

  return (
    <FilesPageShell
      onDragOver={(event) => { event.preventDefault(); state.setDragOver(true); }}
      onDragLeave={(event) => { event.preventDefault(); state.setDragOver(false); }}
      onDrop={state.handleDrop}
    >
      <FilesPageHeader
        onOpenUpload={() => state.fileInputRef.current?.click()}
        fileInputRef={state.fileInputRef}
        onFileInputChange={(event) => event.target.files && state.handleUpload(event.target.files)}
        onOpenCreateDialog={() => state.setShowBuildTargetDialog(true)}
      />

      {state.upload.isActive && <FilesUploadBanner message={state.upload.message} />}

      {showEmpty ? (
        <FilesEmptyState />
      ) : (
        <>
        <FilesBuildTargetBar
          targets={state.buildTargets.targets}
          activeTargetFilters={state.activeTargetFilters}
          onToggleFilter={state.toggleTargetFilter}
          onClearFilters={state.clearTargetFilters}
          onRequestDeleteSource={() => state.setShowDeleteSource(true)}
          deletingSource={state.deletingSource}
          onPrepareTarget={state.handlePrepareTarget}
          isPreparing={state.isPreparingPipeline}
          preparingTargetId={state.preparingTargetId}
        />
        <FilesSourceWorkspace
          search={state.search}
          onSearchChange={state.setSearch}
          onExpandAll={state.onExpandAll}
          onCollapseAll={state.onCollapseAll}
          displayTree={state.displayTree}
          selectedPath={state.selectedPath}
          handleFileClick={state.handleFileClick}
          previewLoading={state.previewLoading}
          previewLang={state.previewLang}
          previewContent={state.previewContent}
          previewFileClass={state.previewFileClass}
          previewSize={state.previewSize}
          highlightLines={state.highlightLines}
          selectedFileFindings={state.selectedFileFindings}
          onSelectFinding={state.handleSelectFinding}
          openPaths={state.effectiveOpenPaths}
          onToggleFolder={state.onToggleFolder}
          layoutRef={state.workspaceLayout.layoutRef}
          treePanelWidth={state.workspaceLayout.treePanelWidth}
          isResizing={state.workspaceLayout.isResizing}
          onStartResize={state.workspaceLayout.startResizing}
          onNudgeResize={state.workspaceLayout.nudgeResize}
          sourceFiles={state.sourceFiles}
          targetMapping={state.targetMapping}
          targets={state.buildTargets.targets}
          findings={state.findings}
          findingsByFile={state.findingsByFile}
          composition={state.composition}
          previewDrawerOpen={state.previewDrawerOpen}
          onPreviewFile={state.openPreviewDrawer}
          onClosePreview={state.closePreview}
          onOpenInDetail={handleOpenInDetail}
          onInsightHotspotClick={state.openPreviewDrawer}
        />
        </>
      )}

      {state.dragOver && <FilesDropOverlay />}

      <BuildTargetCreateDialog
        open={state.showBuildTargetDialog}
        projectId={projectId}
        sourceFiles={state.sourceFiles}
        onCreated={state.onBuildTargetCreated}
        onCancel={() => state.setShowBuildTargetDialog(false)}
      />

      <ConfirmDialog
        open={state.showDeleteSource}
        title="소스 일괄 삭제"
        message="프로젝트의 모든 소스 파일을 삭제합니다. 이 작업은 되돌릴 수 없습니다. 정말 삭제하시겠습니까?"
        confirmLabel={state.deletingSource ? "삭제 중..." : "삭제"}
        danger
        onConfirm={() => void state.handleConfirmDeleteSource()}
        onCancel={() => state.setShowDeleteSource(false)}
      />
    </FilesPageShell>
  );
};
