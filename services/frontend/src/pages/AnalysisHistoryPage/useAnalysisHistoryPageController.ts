import { useCallback, useEffect, useMemo, useState } from "react";
import type { Run } from "@aegis/shared";
import { fetchProjectRuns, logError } from "@/common/api/client";
import { deleteAnalysisResult } from "@/common/api/analysis";

export type AnalysisHistoryFilter = "all" | "static_analysis" | "deep_analysis";

type ToastApi = {
  error: (message: string) => void;
  success: (message: string) => void;
};

export const ANALYSIS_HISTORY_FILTER_OPTIONS: Array<{ value: AnalysisHistoryFilter; label: string }> = [
  { value: "all", label: "전체" },
  { value: "static_analysis", label: "정적 분석" },
  { value: "deep_analysis", label: "심층 분석" },
];

export function useAnalysisHistoryPageController(projectId: string | undefined, toast: ToastApi) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<AnalysisHistoryFilter>("all");
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const loadRuns = useCallback(async () => {
    if (!projectId) {
      setRuns([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data = await fetchProjectRuns(projectId);
      const sorted = [...data].sort(
        (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
      setRuns(sorted);
    } catch (error) {
      logError("Fetch analysis history", error);
      toast.error("분석 이력을 불러올 수 없습니다.");
      setRuns([]);
    } finally {
      setLoading(false);
    }
  }, [projectId, toast]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      await loadRuns();
      if (cancelled) return;
    })();
    return () => {
      cancelled = true;
    };
  }, [loadRuns]);

  const requestDelete = useCallback((analysisResultId: string) => {
    setConfirmDeleteId(analysisResultId);
  }, []);

  const cancelDelete = useCallback(() => {
    setConfirmDeleteId(null);
  }, []);

  const confirmDelete = useCallback(async () => {
    const id = confirmDeleteId;
    if (!id) return;
    setDeleting(true);
    try {
      await deleteAnalysisResult(id);
      toast.success("분석 결과를 삭제했습니다.");
      await loadRuns();
    } catch (error) {
      logError("Delete analysis result", error);
      toast.error("분석 결과 삭제에 실패했습니다.");
    } finally {
      setDeleting(false);
      setConfirmDeleteId(null);
    }
  }, [confirmDeleteId, loadRuns, toast]);

  const filteredRuns = useMemo(
    () => (filter === "all" ? runs : runs.filter((run) => run.module === filter)),
    [filter, runs],
  );

  const completedCount = useMemo(
    () => runs.filter((run) => run.status === "completed").length,
    [runs],
  );
  const failedCount = useMemo(
    () => runs.filter((run) => run.status === "failed").length,
    [runs],
  );

  return {
    loading,
    runs,
    filter,
    setFilter,
    filteredRuns,
    completedCount,
    failedCount,
    confirmDeleteId,
    deleting,
    requestDelete,
    cancelDelete,
    confirmDelete,
  };
}
