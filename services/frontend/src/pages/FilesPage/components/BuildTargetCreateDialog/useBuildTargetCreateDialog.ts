import { useCallback, useEffect, useMemo, useState } from "react";
import type { BuildProfile } from "@aegis/shared";
import { ApiError } from "@/common/api/core";
import type { SourceFileEntry } from "@/common/api/client";
import { logError } from "@/common/api/client";
import { fetchProjectSdks } from "@/common/api/sdk";
import type { RegisteredSdk } from "@/common/api/sdk";
import { useToast } from "@/common/contexts/ToastContext";
import { useBuildTargets } from "@/common/hooks/useBuildTargets";

export const DEFAULT_PROFILE: BuildProfile = {
  sdkId: "none",
  compiler: "gcc",
  targetArch: "x86_64",
  languageStandard: "c17",
  headerLanguage: "auto",
};

export const INCLUDED_PATHS_EDIT_UNSUPPORTED_TEXT = "현재 백엔드 계약상 includedPaths는 수정 API에서 갱신되지 않습니다. 파일 구성 변경이 필요하면 BuildTarget을 새로 만들고 기존 항목을 삭제하세요.";

export const SCRIPT_HINT_INVALID_INPUT_TEXT = "선택한 파일은 빌드 스크립트 힌트로 사용할 수 없습니다. (BuildTarget 루트 외부 / 비-텍스트 / 20KB 초과 / traversal 등)";

function deriveScriptHintRoot(name: string, initialRelativePath?: string): string {
  if (initialRelativePath && initialRelativePath.length > 0) {
    return initialRelativePath.endsWith("/") ? initialRelativePath : `${initialRelativePath}/`;
  }
  const trimmed = name.trim();
  return trimmed ? `${trimmed}/` : "";
}

function toApiScriptHintPath(uploadedPath: string | null, root: string): string | null {
  if (!uploadedPath) return null;
  if (!root) return uploadedPath;
  return uploadedPath.startsWith(root) ? uploadedPath.slice(root.length) : uploadedPath;
}

export function useBuildTargetCreateDialog({
  open,
  projectId,
  sourceFiles,
  initialName = "",
  initialProfile = DEFAULT_PROFILE,
  initialIncludedPaths = [],
  initialRelativePath,
  initialScriptHintPath = null,
  onCreated,
  onSubmit,
}: {
  open: boolean;
  projectId: string;
  sourceFiles: SourceFileEntry[];
  initialName?: string;
  initialProfile?: BuildProfile;
  initialIncludedPaths?: string[];
  initialRelativePath?: string;
  initialScriptHintPath?: string | null;
  onCreated?: () => void;
  onSubmit?: (payload: {
    name: string;
    profile: BuildProfile;
    includedPaths: string[];
    scriptHintPath: string | null;
  }) => Promise<void>;
}) {
  const toast = useToast();
  const buildTargets = useBuildTargets(projectId);
  const [name, setName] = useState("");
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [profile, setProfile] = useState<BuildProfile>(DEFAULT_PROFILE);
  const [creating, setCreating] = useState(false);
  const [registeredSdks, setRegisteredSdks] = useState<RegisteredSdk[]>([]);
  const [scriptHintPath, setScriptHintPath] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setName(initialName);
    setProfile(initialProfile);
    const selected = sourceFiles
      .filter((sourceFile) => initialIncludedPaths.some((path) => sourceFile.relativePath === path || sourceFile.relativePath.startsWith(path)))
      .map((sourceFile) => sourceFile.relativePath);
    setChecked(new Set(selected));
    if (initialScriptHintPath) {
      const root = deriveScriptHintRoot(initialName, initialRelativePath);
      const normalized = initialScriptHintPath.startsWith("/") ? initialScriptHintPath.slice(1) : initialScriptHintPath;
      setScriptHintPath(`${root}${normalized}`);
    } else {
      setScriptHintPath(null);
    }
    fetchProjectSdks(projectId)
      .then((data) => setRegisteredSdks(data.registered))
      .catch(() => setRegisteredSdks([]));
  }, [initialIncludedPaths, initialName, initialProfile, initialRelativePath, initialScriptHintPath, open, projectId, sourceFiles]);

  const handleToggle = useCallback((paths: string[], add: boolean) => {
    setChecked((prev) => {
      const next = new Set(prev);
      for (const path of paths) {
        if (add) next.add(path);
        else next.delete(path);
      }
      return next;
    });
  }, []);

  const selectedFiles = useMemo(
    () => sourceFiles.filter((sourceFile) => checked.has(sourceFile.relativePath)),
    [checked, sourceFiles],
  );
  const selectedCount = selectedFiles.length;
  const selectedSize = selectedFiles.reduce((sum, sourceFile) => sum + (sourceFile.size || 0), 0);
  const includedPaths = useMemo(() => [...checked], [checked]);

  const addBuildTarget = buildTargets.add;
  const handleCreate = useCallback(async () => {
    if (!name.trim()) { toast.error("BuildTarget 이름을 입력해주세요."); return; }
    if (selectedCount === 0) { toast.error("파일을 1개 이상 선택해주세요."); return; }
    setCreating(true);
    const root = deriveScriptHintRoot(name, initialRelativePath);
    const apiHint = toApiScriptHintPath(scriptHintPath, root);
    try {
      if (onSubmit) {
        await onSubmit({ name: name.trim(), profile, includedPaths, scriptHintPath: apiHint });
      } else {
        await addBuildTarget(name.trim(), `${name.trim()}/`, profile, undefined, includedPaths, apiHint ?? undefined);
        onCreated?.();
      }
      toast.success(`BuildTarget "${name.trim()}" ${onSubmit ? "수정" : "생성"} 완료 (${selectedCount}개 파일)`);
    } catch (error) {
      logError(onSubmit ? "Update BuildTarget" : "Create BuildTarget", error);
      if (error instanceof ApiError && error.code === "INVALID_INPUT") {
        if (error.detailMessage) {
          toast.error(error.detailMessage);
        } else if (scriptHintPath) {
          toast.error(SCRIPT_HINT_INVALID_INPUT_TEXT);
        } else {
          toast.error(`BuildTarget ${onSubmit ? "수정" : "생성"}에 실패했습니다.`);
        }
      } else {
        toast.error(`BuildTarget ${onSubmit ? "수정" : "생성"}에 실패했습니다.`);
      }
    } finally {
      setCreating(false);
    }
  }, [addBuildTarget, includedPaths, initialRelativePath, name, onCreated, onSubmit, profile, scriptHintPath, selectedCount, toast]);

  return {
    name,
    setName,
    checked,
    profile,
    setProfile,
    creating,
    registeredSdks,
    selectedCount,
    selectedSize,
    handleToggle,
    handleCreate,
    scriptHintPath,
    setScriptHintPath,
  };
}
