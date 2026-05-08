import "./SourceUploadView.css";
import React, { useState, useEffect, useMemo, useCallback } from "react";
import { Crosshair, Folder, FolderArchive, GitBranch, Play, Search, Upload, Wrench } from "lucide-react";
import { cn } from "@/common/utils/cn";
import type { SourceFileEntry } from "@/common/api/client";
import { cloneSource, fetchSourceFiles, logError, uploadSource } from "@/common/api/client";
import { LANG_GROUPS } from "@/common/constants/languages";
import { useToast } from "@/common/contexts/ToastContext";
import { useUploadProgress } from "@/common/hooks/useUploadProgress";
import { ConnectionStatusBanner, Spinner } from "@/common/ui/primitives";
import type { AnalysisMode } from "@/common/hooks/useAnalysisWebSocket";
import { formatFileSize } from "@/common/utils/format";
import { buildTree, countFiles } from "@/common/utils/tree";

type UploadTab = "zip" | "git";

interface Props {
  projectId: string;
  onAnalysisStart: (mode: AnalysisMode) => void;
  onBrowseTree?: () => void;
  onDiscoverTargets?: () => void;
  onPrepare?: () => void;
  isPreparing?: boolean;
}

export const SourceUploadView: React.FC<Props> = ({ projectId, onAnalysisStart, onBrowseTree, onDiscoverTargets, onPrepare, isPreparing }) => {
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>("quick");
  const toast = useToast();
  const upload = useUploadProgress();
  const [tab, setTab] = useState<UploadTab>("zip");
  const [uploading, setUploading] = useState(false);
  const [sourceFiles, setSourceFiles] = useState<SourceFileEntry[] | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [gitUrl, setGitUrl] = useState("");
  const [gitBranch, setGitBranch] = useState("");

  const loadSourceFiles = useCallback(async () => {
    try {
      const files = await fetchSourceFiles(projectId);
      if (files.length > 0) setSourceFiles(files);
    } catch {
      // No source yet — normal
    }
  }, [projectId]);

  React.useEffect(() => {
    loadSourceFiles();
  }, [loadSourceFiles]);

  useEffect(() => {
    if (upload.phase === "complete") {
      loadSourceFiles();
      upload.reset();
      setUploading(false);
    } else if (upload.phase === "failed") {
      toast.error(upload.error ?? "소스코드 업로드에 실패했습니다.");
      upload.reset();
      setUploading(false);
    }
  }, [upload.phase]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleZipUpload = useCallback(
    async (file: File) => {
      const ext = file.name.toLowerCase();
      if (
        !ext.endsWith(".zip") &&
        !ext.endsWith(".tar.gz") &&
        !ext.endsWith(".tgz") &&
        !ext.endsWith(".tar.bz2") &&
        !ext.endsWith(".tar")
      ) {
        toast.error("ZIP, tar.gz, tgz, tar.bz2, tar 파일만 업로드할 수 있습니다.");
        return;
      }
      setUploading(true);
      upload.setUploading();
      try {
        const { uploadId } = await uploadSource(projectId, file);
        upload.startTracking(uploadId);
      } catch (error) {
        logError("Upload source", error);
        toast.error("소스코드 업로드에 실패했습니다.");
        setUploading(false);
        upload.reset();
      }
    },
    [projectId, toast, upload],
  );

  const handleDrop = useCallback(
    async (event: React.DragEvent) => {
      event.preventDefault();
      setDragOver(false);
      const file = event.dataTransfer.files[0];
      if (!file) return;
      await handleZipUpload(file);
    },
    [handleZipUpload],
  );

  const handleFileSelect = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;
      await handleZipUpload(file);
      event.target.value = "";
    },
    [handleZipUpload],
  );

  const handleGitClone = useCallback(async () => {
    if (!gitUrl.trim()) {
      toast.error("Git URL을 입력해주세요.");
      return;
    }
    setUploading(true);
    try {
      const result = await cloneSource(projectId, gitUrl.trim(), gitBranch.trim() || undefined);
      setSourceFiles(result.files);
      toast.success(`${result.fileCount}개 파일 클론 완료`);
    } catch (error) {
      logError("Clone source", error);
      toast.error("소스코드 클론에 실패했습니다.");
    } finally {
      setUploading(false);
    }
  }, [projectId, gitUrl, gitBranch, toast]);

  const handleReupload = () => {
    setSourceFiles(null);
  };

  const topDirs = useMemo(() => {
    if (!sourceFiles || sourceFiles.length === 0) return [];
    const tree = buildTree(sourceFiles, (file) => file.relativePath);
    return tree.children
      .filter((child) => !child.data)
      .map((child) => ({ name: child.name, count: countFiles(child) }))
      .sort((a, b) => b.count - a.count);
  }, [sourceFiles]);

  const langStats = useMemo(() => {
    if (!sourceFiles || sourceFiles.length === 0) return [];
    const grouped: Record<string, { count: number; color: string }> = {};
    for (const file of sourceFiles) {
      const lang = file.language || "기타";
      const info = LANG_GROUPS[lang];
      const group = info?.group ?? "기타";
      const color = info?.color ?? "var(--foreground-subtle)";
      if (!grouped[group]) grouped[group] = { count: 0, color };
      grouped[group].count += 1;
    }
    return Object.entries(grouped)
      .map(([group, { count, color }]) => ({ group, count, color }))
      .sort((a, b) => b.count - a.count);
  }, [sourceFiles]);

  const totalSize = useMemo(() => (sourceFiles ?? []).reduce((sum, file) => sum + (file.size || 0), 0), [sourceFiles]);

  return (
    <div className="source-upload-shell">
      <ConnectionStatusBanner connectionState={upload.connectionState} />
      {sourceFiles && sourceFiles.length > 0 ? (
        <>
          <div className="panel source-upload-summary-card">
            <div className="panel-head source-upload-summary-head">
              <h3 className="panel-title source-upload-summary-title">
                <FolderArchive size={16} />
                소스코드 ({sourceFiles.length}개 파일 · {formatFileSize(totalSize)})
              </h3>
            </div>
            {langStats.length > 0 ? (
              <div className="source-upload-summary-bar">
                {langStats.map((item) => (
                  <div
                    key={item.group}
                    className="source-upload-summary-segment"
                    style={{
                      width: `${(item.count / sourceFiles.length) * 100}%`,
                      background: item.color,
                    }}
                    title={`${item.group}: ${item.count}`}
                  />
                ))}
              </div>
            ) : null}
            {topDirs.length > 0 ? (
              <div className="panel-body source-upload-dir-list">
                {topDirs.map((directory) => (
                  <div key={directory.name} className="source-upload-dir-item">
                    <Folder size={14} className="source-upload-dir-icon" />
                    <span className="source-upload-dir-name">{directory.name}/</span>
                    <span className="source-upload-dir-count">{directory.count}개 파일</span>
                  </div>
                ))}
              </div>
            ) : null}
          </div>

          <div className="source-upload-actions">
            {onBrowseTree ? (
              <button type="button" className="btn btn-outline btn-sm" onClick={onBrowseTree}>
                <Search size={14} />
                소스코드 탐색
              </button>
            ) : null}
            {onDiscoverTargets ? (
              <button type="button" className="btn btn-outline btn-sm" onClick={onDiscoverTargets}>
                <Crosshair size={14} />
                타겟 탐색
              </button>
            ) : null}
            <button type="button" className="btn btn-outline btn-sm" onClick={handleReupload}>
              <Upload size={14} />
              재업로드
            </button>
            {onPrepare ? (
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={onPrepare}
                disabled={isPreparing}
              >
                <Wrench size={14} />
                {isPreparing ? "빌드 검증 중..." : "빌드 검증"}
              </button>
            ) : null}
            <div
              className="seg source-upload-mode-seg"
              role="radiogroup"
              aria-label="분석 모드"
              onKeyDown={(event) => {
                if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
                  event.preventDefault();
                  setAnalysisMode((prev) => (prev === "quick" ? "deep" : "quick"));
                } else if (event.key === "Home") {
                  event.preventDefault();
                  setAnalysisMode("quick");
                } else if (event.key === "End") {
                  event.preventDefault();
                  setAnalysisMode("deep");
                }
              }}
            >
              <button
                type="button"
                role="radio"
                aria-checked={analysisMode === "quick"}
                className={cn("source-upload-mode-seg__btn", analysisMode === "quick" && "active")}
                onClick={() => setAnalysisMode("quick")}
              >
                QUICK
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={analysisMode === "deep"}
                className={cn("source-upload-mode-seg__btn", analysisMode === "deep" && "active")}
                onClick={() => setAnalysisMode("deep")}
              >
                DEEP
              </button>
            </div>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => onAnalysisStart(analysisMode)}
            >
              <Play size={14} />
              분석 실행
            </button>
          </div>
        </>
      ) : (
        <>
          <div className="seg source-upload-tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={tab === "zip"}
              className={cn("source-upload-tab", tab === "zip" && "btn btn-primary")}
              onClick={() => setTab("zip")}
            >
              <FolderArchive size={14} />
              ZIP / tar.gz 업로드
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tab === "git"}
              className={cn("source-upload-tab", tab === "git" && "btn btn-primary")}
              onClick={() => setTab("git")}
            >
              <GitBranch size={14} />
              Git 클론
            </button>
          </div>

          {uploading ? (
            <div className="panel source-upload-progress-card">
              <div className="panel-body source-upload-progress-body">
                <Spinner
                  size={32}
                  label={upload.isActive ? upload.message : tab === "zip" ? "업로드 중..." : "클론 중..."}
                />
              </div>
            </div>
          ) : tab === "zip" ? (
            <div className={"panel" + " " + cn("source-upload-dropzone", dragOver && "is-dragover")}
              onDrop={handleDrop}
              onDragOver={(event) => {
                event.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onClick={() => document.getElementById("source-file-input")?.click()}
            >
              <div className="panel-body source-upload-dropzone-body">
                <div className="source-upload-dropzone-icon">
                  <Upload size={36} />
                </div>
                <p className="source-upload-dropzone-title">프로젝트 소스코드를 드래그하거나 클릭하여 업로드</p>
                <small className="source-upload-dropzone-copy">
                  지원 형식: .zip, .tar.gz, .tgz, .tar.bz2, .tar
                </small>
              </div>
              <input
                id="source-file-input"
                type="file"
                accept=".zip,.tar.gz,.tgz,.tar.bz2,.tar"
                className="source-upload-hidden-input"
                onChange={handleFileSelect}
              />
            </div>
          ) : (
            <div className="panel source-upload-git-card">
              <div className="panel-body source-upload-git-body">
                <label className="form-label source-upload-field">
                  <span className="source-upload-field-label">Git URL *</span>
                  <input className="form-input source-upload-input-mono"
                    value={gitUrl}
                    onChange={(event) => setGitUrl(event.target.value)}
                    placeholder="https://github.com/org/repo.git"
                    spellCheck={false}
                  />
                </label>
                <label className="form-label source-upload-field">
                  <span className="source-upload-field-label">Branch</span>
                  <input className="form-input"
                    value={gitBranch}
                    onChange={(event) => setGitBranch(event.target.value)}
                    placeholder="main (기본)"
                  />
                </label>
                <div className="source-upload-git-actions">
                  <button type="button" onClick={handleGitClone}>
                    <GitBranch size={14} />
                    클론
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
