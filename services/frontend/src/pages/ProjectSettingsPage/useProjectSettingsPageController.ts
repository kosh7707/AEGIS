import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import type { Project } from "@aegis/shared";
import type { RegisteredSdk, SdkRegistryStatus, SdkQuota } from "@/common/api/sdk";
import { deleteProject, fetchProject, updateProject, updateProjectSettings } from "@/common/api/projects";
import {
  deleteSdk,
  fetchProjectSdks,
  fetchSdkQuota,
  retrySdk,
} from "@/common/api/sdk";
import { ApiError, logError } from "@/common/api/core";
import {
  useSdkProgress,
  type SdkProgressDetails,
  type SdkErrorEventDetails,
} from "@/common/hooks/useSdkProgress";
import type { SettingsSection } from "../components/ProjectSettingsTabStrip";

type ToastApi = {
  error: (message: string) => void;
  success: (message: string) => void;
};

const VALID_SECTIONS: SettingsSection[] = ["general", "sdk", "build-targets", "notifications", "adapters", "danger"];

function parseSection(value: string | null): SettingsSection {
  if (value && (VALID_SECTIONS as string[]).includes(value)) return value as SettingsSection;
  return "general";
}

export function useProjectSettingsPageController(projectId: string | undefined, toast: ToastApi) {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeSection = parseSection(searchParams.get("section"));
  const setActiveSection = useCallback((next: SettingsSection) => {
    setSearchParams((prev) => {
      const copy = new URLSearchParams(prev);
      if (next === "general") copy.delete("section");
      else copy.set("section", next);
      return copy;
    }, { replace: true });
  }, [setSearchParams]);
  const [registered, setRegistered] = useState<RegisteredSdk[]>([]);
  const [sdkProgressById, setSdkProgressById] = useState<Record<string, SdkProgressDetails>>({});
  const [sdkErrorDetailsById, setSdkErrorDetailsById] = useState<Record<string, SdkErrorEventDetails>>({});
  const [sdkQuota, setSdkQuota] = useState<SdkQuota | null>(null);
  const [retryingSdkIds, setRetryingSdkIds] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<RegisteredSdk | null>(null);

  const [project, setProject] = useState<Project | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [storedName, setStoredName] = useState("");
  const [storedDescription, setStoredDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [showDeleteProject, setShowDeleteProject] = useState(false);
  const [deletingProject, setDeletingProject] = useState(false);

  const refreshQuota = useCallback(() => {
    if (!projectId) return;
    void fetchSdkQuota(projectId)
      .then((q) => setSdkQuota(q))
      .catch((error) => logError("Fetch SDK quota", error));
  }, [projectId]);

  const { connectionState: sdkConnectionState } = useSdkProgress({
    projectId,
    onProgress: useCallback((sdkId: string, phase: SdkRegistryStatus, details?: SdkProgressDetails) => {
      setRegistered((prev) => prev.map((sdk) => (
        sdk.id === sdkId
          ? {
              ...sdk,
              status: phase,
              currentPhaseStartedAt: details?.phaseStartedAt ?? sdk.currentPhaseStartedAt,
            }
          : sdk
      )));
      setSdkProgressById((prev) => (
        details && Object.keys(details).length > 0
          ? { ...prev, [sdkId]: details }
          : prev
      ));
      // clear previous error context when transitioning out of failed state
      setSdkErrorDetailsById((prev) => {
        if (!(sdkId in prev)) return prev;
        const next = { ...prev };
        delete next[sdkId];
        return next;
      });
    }, []),
    onComplete: useCallback((sdkId: string, profile: RegisteredSdk["profile"]) => {
      if (!projectId) return;
      setSdkProgressById((prev) => {
        const next = { ...prev };
        delete next[sdkId];
        return next;
      });
      setSdkErrorDetailsById((prev) => {
        if (!(sdkId in prev)) return prev;
        const next = { ...prev };
        delete next[sdkId];
        return next;
      });
      void fetchProjectSdks(projectId)
        .then((data) => {
          const freshSdk = data.registered.find((sdk) => sdk.id === sdkId);
          setRegistered((prev) => prev.map((sdk) => (
            sdk.id === sdkId
              ? freshSdk ?? { ...sdk, status: "ready", profile }
              : sdk
          )));
        })
        .catch((error) => {
          logError("Refresh SDK after complete", error);
          setRegistered((prev) => prev.map((sdk) => (
            sdk.id === sdkId ? { ...sdk, status: "ready", profile } : sdk
          )));
        });
      refreshQuota();
    }, [projectId, refreshQuota]),
    onError: useCallback((
      sdkId: string,
      error: string,
      phase?: string,
      logPath?: string,
      details?: SdkErrorEventDetails,
    ) => {
      const errorStatus = (phase || "verify_failed") as SdkRegistryStatus;
      setRegistered((prev) => prev.map((sdk) => (
        sdk.id === sdkId
          ? {
              ...sdk,
              status: errorStatus,
              verifyError: error,
              installLogPath: logPath ?? sdk.installLogPath,
              retryable: details?.retryable ?? sdk.retryable,
            }
          : sdk
      )));
      setSdkProgressById((prev) => {
        const next = { ...prev };
        delete next[sdkId];
        return next;
      });
      if (details && Object.keys(details).length > 0) {
        setSdkErrorDetailsById((prev) => ({ ...prev, [sdkId]: details }));
      }
    }, []),
  });

  useEffect(() => {
    document.title = "AEGIS — Project Settings";
  }, []);

  const load = useCallback(async () => {
    if (!projectId) {
      setRegistered([]);
      setProject(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const [sdks, fetched, quota] = await Promise.allSettled([
        fetchProjectSdks(projectId),
        fetchProject(projectId),
        fetchSdkQuota(projectId),
      ]);
      if (sdks.status === "fulfilled") {
        setRegistered(sdks.value.registered);
      } else {
        logError("Load SDKs", sdks.reason);
        toast.error("SDK 목록을 불러올 수 없습니다.");
      }
      if (fetched.status === "fulfilled") {
        setProject(fetched.value);
        const nextName = fetched.value.name ?? "";
        const nextDesc = fetched.value.description ?? "";
        setName(nextName);
        setDescription(nextDesc);
        setStoredName(nextName);
        setStoredDescription(nextDesc);
      } else {
        logError("Load project metadata", fetched.reason);
      }
      if (quota.status === "fulfilled") {
        setSdkQuota(quota.value);
      } else {
        // Quota fetch may fail in offline/mock; non-fatal
        logError("Load SDK quota", quota.reason);
      }
    } finally {
      setLoading(false);
    }
  }, [projectId, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleRegistered = useCallback((sdk: RegisteredSdk) => {
    setRegistered((prev) => [...prev, sdk]);
    setShowForm(false);
    refreshQuota();
  }, [refreshQuota]);

  const handleDelete = useCallback(async (sdk: RegisteredSdk) => {
    if (!projectId) return;
    try {
      await deleteSdk(projectId, sdk.id);
      setRegistered((prev) => prev.filter((entry) => entry.id !== sdk.id));
      setSdkErrorDetailsById((prev) => {
        if (!(sdk.id in prev)) return prev;
        const next = { ...prev };
        delete next[sdk.id];
        return next;
      });
      toast.success(`SDK "${sdk.name}" 삭제 완료`);
      refreshQuota();
    } catch (error) {
      logError("Delete SDK", error);
      toast.error("SDK 삭제에 실패했습니다.");
    }
    setDeleteTarget(null);
  }, [projectId, toast, refreshQuota]);

  const handleRetry = useCallback(async (sdk: RegisteredSdk) => {
    if (!projectId) return;
    setRetryingSdkIds((prev) => {
      const next = new Set(prev);
      next.add(sdk.id);
      return next;
    });
    try {
      const updated = await retrySdk(projectId, sdk.id);
      setRegistered((prev) => prev.map((entry) => (entry.id === sdk.id ? updated : entry)));
      setSdkErrorDetailsById((prev) => {
        if (!(sdk.id in prev)) return prev;
        const next = { ...prev };
        delete next[sdk.id];
        return next;
      });
      toast.success(`"${sdk.name}" 재시도를 시작했습니다.`);
    } catch (error) {
      logError("Retry SDK", error);
      toast.error("SDK 재시도에 실패했습니다.");
    } finally {
      setRetryingSdkIds((prev) => {
        if (!prev.has(sdk.id)) return prev;
        const next = new Set(prev);
        next.delete(sdk.id);
        return next;
      });
    }
  }, [projectId, toast]);

  const dirty = useMemo(
    () => name !== storedName || description !== storedDescription,
    [name, storedName, description, storedDescription],
  );

  const handleNameChange = setName;
  const handleDescriptionChange = setDescription;

  const handleCancel = useCallback(() => {
    setName(storedName);
    setDescription(storedDescription);
  }, [storedName, storedDescription]);

  const handleSave = useCallback(async () => {
    if (!projectId || !dirty || saving) return;
    const trimmedName = name.trim();
    const trimmedDescription = description.trim();

    // C11 — pre-validate empty name client-side; PUT /api/projects/:id 400s on empty trim.
    if (trimmedName.length === 0) {
      toast.error("프로젝트 이름을 입력해 주세요.");
      return;
    }

    setSaving(true);
    const nameChanged = trimmedName !== storedName;
    const descriptionChanged = trimmedDescription !== storedDescription;
    let nameUpdated = false;
    try {
      // Canonical rename endpoint — PUT /api/projects/:id (name-only).
      if (nameChanged) {
        await updateProject(projectId, { name: trimmedName });
        setStoredName(trimmedName);
        setName(trimmedName);
        nameUpdated = true;
      }
      // Description (and other settings) — PUT /api/projects/:pid/settings.
      if (descriptionChanged) {
        await updateProjectSettings(projectId, { description: trimmedDescription });
        setStoredDescription(trimmedDescription);
        setDescription(trimmedDescription);
      }
      if (nameChanged && !descriptionChanged) {
        toast.success("프로젝트 이름이 변경되었습니다.");
      } else {
        toast.success("프로젝트 정보를 저장했습니다.");
      }
    } catch (error) {
      logError("Save project settings", error);
      if (nameUpdated) {
        // Name persisted on server but description update failed — surface unambiguous message.
        toast.error("이름은 저장됐지만 설명을 저장하지 못했습니다. 다시 시도해주세요.");
      } else {
        // Name update failed (or nothing was updated yet).
        const detail = error instanceof ApiError ? (error.detailMessage ?? error.message) : null;
        toast.error(detail ?? "프로젝트 정보를 저장하지 못했습니다.");
      }
    } finally {
      setSaving(false);
    }
  }, [projectId, dirty, saving, name, description, storedName, storedDescription, toast]);

  const handleConfirmDeleteProject = useCallback(async () => {
    if (!projectId) return;
    setDeletingProject(true);
    try {
      await deleteProject(projectId);
      toast.success("프로젝트를 삭제했습니다.");
      setShowDeleteProject(false);
      navigate("/");
    } catch (error) {
      logError("Delete project", error);
      toast.error("프로젝트 삭제에 실패했습니다.");
    } finally {
      setDeletingProject(false);
    }
  }, [projectId, toast, navigate]);

  return {
    activeSection,
    setActiveSection,
    registered,
    sdkProgressById,
    sdkErrorDetailsById,
    sdkQuota,
    retryingSdkIds,
    loading,
    showForm,
    setShowForm,
    deleteTarget,
    setDeleteTarget,
    sdkConnectionState,
    handleRegistered,
    handleDelete,
    handleRetry,

    project,
    name,
    description,
    dirty,
    saving,
    handleNameChange,
    handleDescriptionChange,
    handleCancel,
    handleSave,

    showDeleteProject,
    setShowDeleteProject,
    deletingProject,
    handleConfirmDeleteProject,
  };
}
