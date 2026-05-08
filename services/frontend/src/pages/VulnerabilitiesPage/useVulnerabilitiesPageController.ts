import { useCallback, useEffect, useMemo, useState } from "react";
import type { Finding, FindingSourceType, FindingStatus, Severity } from "@aegis/shared";
import type { FindingGroup, FindingsSummary } from "@/common/api/analysis";
import {
  bulkUpdateFindingStatus,
  fetchFindingGroups,
  fetchFindingsSummary,
  fetchProjectFindings,
} from "@/common/api/analysis";
import { logError } from "@/common/api/core";
import { useKeyboardShortcuts } from "@/common/hooks/useKeyboardShortcuts";
import { SEVERITY_ORDER } from "@/common/utils/severity";

type ToastApi = {
  error: (message: string) => void;
  success: (message: string) => void;
};

export function useVulnerabilitiesPageController(
  projectId: string | undefined,
  activeSeverities: ReadonlySet<Severity>,
  toast: ToastApi,
) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [sourceTypeFilter, setSourceTypeFilter] = useState<FindingSourceType | "all">("all");
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<"severity" | "createdAt" | "location">("severity");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState<FindingStatus | "">("");
  const [bulkReason, setBulkReason] = useState("");
  const [bulkProcessing, setBulkProcessing] = useState(false);
  const [highlightIndex, setHighlightIndex] = useState(-1);
  const [showShortcutHelp, setShowShortcutHelp] = useState(false);
  const [groupBy, setGroupByState] = useState<"none" | "ruleId" | "location">("none");
  const [groups, setGroups] = useState<FindingGroup[]>([]);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [groupsLoading, setGroupsLoading] = useState(false);
  const [summary, setSummary] = useState<FindingsSummary | null>(null);

  useEffect(() => {
    document.title = "AEGIS — Vulnerabilities";
  }, []);

  useEffect(() => {
    if (!projectId) {
      setSummary(null);
      return;
    }
    let cancelled = false;
    fetchFindingsSummary(projectId)
      .then((data) => {
        if (cancelled) return;
        setSummary(data);
      })
      .catch((error) => {
        if (cancelled) return;
        logError("Findings summary", error);
        setSummary(null);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  const loadFindings = useCallback(async () => {
    if (!projectId) {
      setFindings([]);
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const data = await fetchProjectFindings(projectId);
      setFindings(data);
    } catch (error) {
      logError("Load findings", error);
      toast.error("Finding 목록을 불러올 수 없습니다.");
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }, [projectId, toast]);

  useEffect(() => {
    void loadFindings();
  }, [loadFindings]);

  useEffect(() => {
    if (groupBy === "none" || !projectId) {
      setGroups([]);
      return;
    }

    setGroupsLoading(true);
    fetchFindingGroups(projectId, groupBy)
      .then((response) => setGroups(response.groups))
      .catch((error) => {
        logError("FindingGroups", error);
        setGroups([]);
      })
      .finally(() => setGroupsLoading(false));
  }, [groupBy, projectId]);

  const counts = useMemo(() => {
    const next = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) {
      if (finding.severity !== "info") next.total++;
      next[finding.severity as keyof typeof next]++;
    }
    return next;
  }, [findings]);

  const filtered = useMemo(() => {
    let result = findings;
    if (activeSeverities.size < SEVERITY_ORDER.length) {
      result = result.filter((finding) => activeSeverities.has(finding.severity));
    }
    if (sourceTypeFilter !== "all") result = result.filter((finding) => finding.sourceType === sourceTypeFilter);
    if (statusFilter !== "all") result = result.filter((finding) => finding.status === statusFilter);
    if (searchQuery.trim()) {
      const query = searchQuery.trim().toLowerCase();
      result = result.filter(
        (finding) =>
          finding.title.toLowerCase().includes(query) ||
          (finding.location ?? "").toLowerCase().includes(query) ||
          (finding.ruleId ?? "").toLowerCase().includes(query),
      );
    }

    return [...result].sort((a, b) => {
      let comparison = 0;
      if (sortBy === "severity") {
        comparison = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      } else if (sortBy === "createdAt") {
        comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      } else if (sortBy === "location") {
        comparison = (a.location ?? "").localeCompare(b.location ?? "");
      }
      return sortOrder === "asc" ? comparison : -comparison;
    });
  }, [activeSeverities, findings, searchQuery, sortBy, sortOrder, sourceTypeFilter, statusFilter]);

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleBulkAction = useCallback(async () => {
    if (!bulkStatus || selectedIds.size === 0 || !bulkReason.trim()) return;
    setBulkProcessing(true);
    try {
      const result = await bulkUpdateFindingStatus(Array.from(selectedIds), bulkStatus as FindingStatus, bulkReason.trim());
      toast.success(`${result.updated}건 상태 변경 완료${result.failed > 0 ? ` (${result.failed}건 실패)` : ""}`);
      setSelectedIds(new Set());
      setBulkStatus("");
      setBulkReason("");
      await loadFindings();
    } catch (error) {
      logError("Bulk status", error);
      toast.error("벌크 상태 변경에 실패했습니다.");
    } finally {
      setBulkProcessing(false);
    }
  }, [bulkReason, bulkStatus, loadFindings, selectedIds, toast]);

  useKeyboardShortcuts({
    j: () => setHighlightIndex((index) => Math.min(index + 1, filtered.length - 1)),
    k: () => setHighlightIndex((index) => Math.max(index - 1, 0)),
    o: () => {
      if (highlightIndex >= 0 && filtered[highlightIndex]) setSelectedFindingId(filtered[highlightIndex].id);
    },
    Enter: () => {
      if (highlightIndex >= 0 && filtered[highlightIndex]) setSelectedFindingId(filtered[highlightIndex].id);
    },
    Escape: () => {
      setHighlightIndex(-1);
      setSelectedIds(new Set());
      setShowShortcutHelp(false);
    },
    "?": () => setShowShortcutHelp((value) => !value),
  }, !selectedFindingId);

  const hasActiveFilters =
    activeSeverities.size < SEVERITY_ORDER.length ||
    sourceTypeFilter !== "all" ||
    statusFilter !== "all" ||
    searchQuery.trim() !== "";

  const setGroupBy = useCallback((value: "none" | "ruleId" | "location") => {
    setGroupByState(value);
    setExpandedGroups(new Set());
  }, []);

  const toggleGroup = useCallback((key: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  return {
    findings,
    loading,
    selectedFindingId,
    setSelectedFindingId,
    sourceTypeFilter,
    setSourceTypeFilter,
    statusFilter,
    setStatusFilter,
    searchQuery,
    setSearchQuery,
    sortBy,
    setSortBy,
    sortOrder,
    setSortOrder,
    selectedIds,
    bulkStatus,
    setBulkStatus,
    bulkReason,
    setBulkReason,
    bulkProcessing,
    highlightIndex,
    showShortcutHelp,
    setShowShortcutHelp,
    groupBy,
    setGroupBy,
    groups,
    expandedGroups,
    groupsLoading,
    counts,
    filtered,
    hasActiveFilters,
    loadFindings,
    toggleSelect,
    handleBulkAction,
    clearSelection: () => setSelectedIds(new Set()),
    toggleGroup,
    summary,
  };
}
