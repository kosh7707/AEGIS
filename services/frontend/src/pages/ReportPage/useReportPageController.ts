import { useCallback, useEffect, useMemo, useState } from "react";
import type { AnalysisResult, ModuleReport, ProjectReport } from "@aegis/shared";
import type { ReportFilters } from "@/common/api/client";
import {
  ApiError,
  fetchDynamicModuleReport,
  fetchProjectReport,
  fetchStaticModuleReport,
  fetchTestModuleReport,
  logError,
} from "@/common/api/client";
import { fetchAnalysisResults } from "@/common/api/analysis";
import { getReportModuleEntries, type ModuleTab } from "./reportPresentation";

type ToastAction = { label: string; onClick: () => void } | undefined;

type ToastApi = {
  error: (message: string, action?: ToastAction) => void;
};

type LazyModuleTab = "static" | "dynamic" | "test";

const LAZY_MODULE_FETCHERS: Record<
  LazyModuleTab,
  (projectId: string, filters?: ReportFilters) => Promise<ModuleReport>
> = {
  static: fetchStaticModuleReport,
  dynamic: fetchDynamicModuleReport,
  test: fetchTestModuleReport,
};

function isLazyModuleTab(tab: ModuleTab): tab is LazyModuleTab {
  return tab === "static" || tab === "dynamic" || tab === "test";
}

export function useReportPageController(projectId: string | undefined, toast: ToastApi) {
  const [report, setReport] = useState<ProjectReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [activeTab, setActiveTab] = useState<ModuleTab>("all");
  const [showFilters, setShowFilters] = useState(false);
  const [showCustomReport, setShowCustomReport] = useState(false);
  const [filters, setFilters] = useState<ReportFilters>({});
  const [pendingFilters, setPendingFilters] = useState<ReportFilters>({});

  // Per-module lazy state — applied filter + cached ModuleReport per module tab.
  const [moduleFilters, setModuleFilters] = useState<Record<LazyModuleTab, ReportFilters>>({
    static: {},
    dynamic: {},
    test: {},
  });
  const [moduleReports, setModuleReports] = useState<Record<LazyModuleTab, ModuleReport | null>>({
    static: null,
    dynamic: null,
    test: null,
  });
  const [moduleLoading, setModuleLoading] = useState<Record<LazyModuleTab, boolean>>({
    static: false,
    dynamic: false,
    test: false,
  });

  useEffect(() => {
    document.title = "AEGIS — 보고서";
  }, []);

  const loadReport = useCallback(() => {
    if (!projectId) {
      setReport(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setLoadError(false);

    fetchProjectReport(projectId, filters)
      .then(setReport)
      .catch((error) => {
        logError("Load report", error);
        setLoadError(true);
        const retry = error instanceof ApiError && error.retryable ? { label: "다시 시도", onClick: loadReport } : undefined;
        toast.error(error instanceof Error ? error.message : "보고서를 불러올 수 없습니다.", retry);
      })
      .finally(() => setLoading(false));
  }, [filters, projectId, toast]);

  useEffect(() => {
    loadReport();
  }, [loadReport]);

  // Lazy module-report fetcher used when the user opens a static/dynamic/test tab
  // or changes that tab's filters. Mirrors the aggregate fetcher's error handling.
  const loadModuleReport = useCallback(
    (tab: LazyModuleTab) => {
      if (!projectId) return;
      const fetcher = LAZY_MODULE_FETCHERS[tab];
      const moduleFilter = moduleFilters[tab];

      setModuleLoading((prev) => ({ ...prev, [tab]: true }));
      fetcher(projectId, moduleFilter)
        .then((data) => {
          setModuleReports((prev) => ({ ...prev, [tab]: data }));
        })
        .catch((error) => {
          logError(`Load module report (${tab})`, error);
          setModuleReports((prev) => ({ ...prev, [tab]: null }));
          const retry =
            error instanceof ApiError && error.retryable
              ? { label: "다시 시도", onClick: () => loadModuleReport(tab) }
              : undefined;
          toast.error(
            error instanceof Error ? error.message : "모듈 보고서를 불러올 수 없습니다.",
            retry,
          );
        })
        .finally(() => {
          setModuleLoading((prev) => ({ ...prev, [tab]: false }));
        });
    },
    [moduleFilters, projectId, toast],
  );

  // Trigger lazy fetch on tab activation / filter change for that tab.
  useEffect(() => {
    if (!projectId || !isLazyModuleTab(activeTab)) return;
    loadModuleReport(activeTab);
  }, [activeTab, moduleFilters, projectId, loadModuleReport]);

  const [deepResult, setDeepResult] = useState<AnalysisResult | null>(null);
  useEffect(() => {
    if (!report) {
      setDeepResult(null);
      return;
    }
    const deepRuns = report.modules.deep?.runs ?? [];
    const latestRun = deepRuns
      .map((entry) => entry.run)
      .filter((run) => run.status === "completed" && run.analysisResultId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];
    if (!latestRun?.analysisResultId) {
      setDeepResult(null);
      return;
    }
    let cancelled = false;
    fetchAnalysisResults(latestRun.analysisResultId)
      .then((result) => {
        if (!cancelled) setDeepResult(result);
      })
      .catch((error) => {
        logError("Load deep analysis result for report", error);
        if (!cancelled) setDeepResult(null);
      });
    return () => {
      cancelled = true;
    };
  }, [report]);

  const handleApplyFilters = useCallback(() => {
    if (isLazyModuleTab(activeTab)) {
      setModuleFilters((prev) => ({ ...prev, [activeTab]: pendingFilters }));
    } else {
      setFilters(pendingFilters);
    }
    setShowFilters(false);
  }, [activeTab, pendingFilters]);

  const handleClearFilters = useCallback(() => {
    setPendingFilters({});
    if (isLazyModuleTab(activeTab)) {
      setModuleFilters((prev) => ({ ...prev, [activeTab]: {} }));
    } else {
      setFilters({});
    }
    setShowFilters(false);
  }, [activeTab]);

  // Sync pendingFilters to the currently-active tab's applied filter so the
  // filters panel reflects what the user is editing for the active scope.
  useEffect(() => {
    if (isLazyModuleTab(activeTab)) {
      setPendingFilters(moduleFilters[activeTab]);
    } else {
      setPendingFilters(filters);
    }
  }, [activeTab, filters, moduleFilters]);

  const hasActiveFilters = useMemo(() => {
    const current = isLazyModuleTab(activeTab) ? moduleFilters[activeTab] : filters;
    return Object.values(current).some(Boolean);
  }, [activeTab, filters, moduleFilters]);

  const moduleEntries = useMemo(() => {
    if (!report) return [];
    if (isLazyModuleTab(activeTab)) {
      const lazy = moduleReports[activeTab];
      return lazy ? [{ key: activeTab, mod: lazy }] : [];
    }
    return getReportModuleEntries(report, activeTab);
  }, [activeTab, moduleReports, report]);

  const allFindings = useMemo(() => moduleEntries.flatMap((entry) => entry.mod!.findings), [moduleEntries]);
  const allRuns = useMemo(() => moduleEntries.flatMap((entry) => entry.mod!.runs), [moduleEntries]);
  const summary = useMemo(
    () => (report ? (activeTab === "all" ? report.totalSummary : moduleEntries[0]?.mod?.summary ?? report.totalSummary) : null),
    [activeTab, moduleEntries, report],
  );
  const sevCounts = useMemo(() => {
    if (!summary) {
      return { critical: 0, high: 0, medium: 0, low: 0 };
    }

    return {
      critical: summary.bySeverity.critical ?? 0,
      high: summary.bySeverity.high ?? 0,
      medium: summary.bySeverity.medium ?? 0,
      low: summary.bySeverity.low ?? 0,
    };
  }, [summary]);
  const sevMax = useMemo(() => Math.max(1, ...Object.values(sevCounts)), [sevCounts]);

  const moduleTabLoading = isLazyModuleTab(activeTab) ? moduleLoading[activeTab] : false;
  const moduleTabEmpty =
    isLazyModuleTab(activeTab) &&
    !moduleTabLoading &&
    moduleReports[activeTab] != null &&
    moduleReports[activeTab]!.findings.length === 0 &&
    moduleReports[activeTab]!.runs.length === 0;

  return {
    report,
    loading,
    loadError,
    activeTab,
    setActiveTab,
    showFilters,
    setShowFilters,
    showCustomReport,
    setShowCustomReport,
    filters,
    pendingFilters,
    setPendingFilters,
    hasActiveFilters,
    loadReport,
    handleApplyFilters,
    handleClearFilters,
    moduleEntries,
    allFindings,
    allRuns,
    summary,
    sevCounts,
    sevMax,
    deepResult,
    moduleTabLoading,
    moduleTabEmpty,
  };
}
