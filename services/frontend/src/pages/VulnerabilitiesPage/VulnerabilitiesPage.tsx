import React, { useCallback, useMemo } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import type { Severity } from "@aegis/shared";
import { useToast } from "@/common/contexts/ToastContext";
import { FindingDetailView } from "@/common/ui/findings/FindingDetailView";
import { Spinner } from "@/common/ui/primitives";
import { SEVERITY_ORDER } from "@/common/utils/severity";
import { FindingsSummaryPanel } from "./components/FindingsSummaryPanel/FindingsSummaryPanel";
import { VulnerabilitiesHeader } from "./components/VulnerabilitiesHeader/VulnerabilitiesHeader";
import { VulnerabilityGroups } from "./components/VulnerabilityGroups/VulnerabilityGroups";
import { VulnerabilityKeyboardHint } from "./components/VulnerabilityKeyboardHint/VulnerabilityKeyboardHint";
import { VulnerabilityList } from "./components/VulnerabilityList/VulnerabilityList";
import { VulnerabilitiesToolbar } from "./components/VulnerabilitiesToolbar/VulnerabilitiesToolbar";
import { useVulnerabilitiesPageController } from "./useVulnerabilitiesPageController";
import "./VulnerabilitiesPage.css";

const ALL_SEVERITIES: ReadonlySet<Severity> = new Set(SEVERITY_ORDER);

function parseSeverityParam(raw: string | null): Set<Severity> {
  if (!raw) return new Set(SEVERITY_ORDER);
  const tokens = raw.split(",").map((t) => t.trim()).filter(Boolean);
  const parsed = new Set<Severity>();
  for (const token of tokens) {
    if ((SEVERITY_ORDER as readonly string[]).includes(token)) {
      parsed.add(token as Severity);
    }
  }
  if (parsed.size === 0) return new Set(SEVERITY_ORDER);
  return parsed;
}

function serializeSeverities(set: ReadonlySet<Severity>): string | null {
  if (set.size === 0 || set.size === SEVERITY_ORDER.length) return null;
  return SEVERITY_ORDER.filter((s) => set.has(s)).join(",");
}

export const VulnerabilitiesPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const toast = useToast();

  const severityParam = searchParams.get("severity");
  const activeSeverities = useMemo(() => parseSeverityParam(severityParam), [severityParam]);

  const commitSeverities = useCallback(
    (next: ReadonlySet<Severity>) => {
      const serialized = serializeSeverities(next);
      setSearchParams(serialized ? { severity: serialized } : {});
    },
    [setSearchParams],
  );

  const toggleSeverity = useCallback(
    (severity: Severity) => {
      if (activeSeverities.size === ALL_SEVERITIES.size) {
        commitSeverities(new Set([severity]));
        return;
      }
      const next = new Set(activeSeverities);
      if (next.has(severity)) {
        next.delete(severity);
        if (next.size === 0) {
          commitSeverities(ALL_SEVERITIES);
          return;
        }
      } else {
        next.add(severity);
      }
      commitSeverities(next);
    },
    [activeSeverities, commitSeverities],
  );

  const resetSeverities = useCallback(() => {
    commitSeverities(ALL_SEVERITIES);
  }, [commitSeverities]);

  const state = useVulnerabilitiesPageController(projectId, activeSeverities, toast);

  if (state.selectedFindingId) {
    return (
      <FindingDetailView
        findingId={state.selectedFindingId}
        projectId={projectId ?? ""}
        onBack={() => {
          state.setSelectedFindingId(null);
          state.loadFindings();
        }}
      />
    );
  }

  if (state.loading) {
    return (
      <div className="page-loading-shell">
        <Spinner size={36} label="탐지 항목 로딩 중..." />
      </div>
    );
  }

  const showGrouped = state.groupBy !== "none" && state.groups.length > 0;
  const showEmpty = !showGrouped && state.filtered.length === 0;
  const severityNarrowed = activeSeverities.size < ALL_SEVERITIES.size;
  const emptyTitle = severityNarrowed
    ? "선택한 심각도 수준의 탐지 항목이 없습니다"
    : "조건에 맞는 탐지 항목이 없습니다";
  const emptyNote = state.hasActiveFilters
    ? "필터를 해제하면 더 많은 항목이 보일 수 있습니다."
    : "분석이 완료되면 이곳에 기록됩니다.";

  return (
    <div className="page-shell vuln-page">
      <VulnerabilitiesHeader
        totalActiveFindings={state.counts.total}
        counts={state.counts}
      />

      <FindingsSummaryPanel summary={state.summary} />

      <VulnerabilitiesToolbar
        counts={state.counts}
        activeSeverities={activeSeverities}
        allSeveritiesSize={ALL_SEVERITIES.size}
        sourceTypeFilter={state.sourceTypeFilter}
        statusFilter={state.statusFilter}
        searchQuery={state.searchQuery}
        sortBy={state.sortBy}
        sortOrder={state.sortOrder}
        groupBy={state.groupBy}
        hasActiveFilters={state.hasActiveFilters}
        filteredCount={state.filtered.length}
        totalCount={state.findings.length}
        showShortcutHelp={state.showShortcutHelp}
        selectedCount={state.selectedIds.size}
        bulkStatus={state.bulkStatus}
        bulkReason={state.bulkReason}
        bulkProcessing={state.bulkProcessing}
        toggleSeverity={toggleSeverity}
        resetSeverities={resetSeverities}
        setSourceTypeFilter={state.setSourceTypeFilter}
        setStatusFilter={state.setStatusFilter}
        setSearchQuery={state.setSearchQuery}
        setSortBy={state.setSortBy}
        setSortOrder={state.setSortOrder}
        setGroupBy={state.setGroupBy}
        setShowShortcutHelp={state.setShowShortcutHelp}
        setBulkStatus={state.setBulkStatus}
        setBulkReason={state.setBulkReason}
        clearSelection={state.clearSelection}
        onBulkAction={state.handleBulkAction}
      />

      {showGrouped ? (
        <VulnerabilityGroups
          groups={state.groups}
          findings={state.findings}
          groupsLoading={state.groupsLoading}
          expandedGroups={state.expandedGroups}
          onToggleGroup={state.toggleGroup}
          onOpenFinding={state.setSelectedFindingId}
        />
      ) : showEmpty ? (
        <div className="vuln-empty" role="status">
          <span className="vuln-empty__stamp" aria-hidden="true">NO ENTRIES</span>
          <p className="vuln-empty__title">{emptyTitle}</p>
          <p className="vuln-empty__note">{emptyNote}</p>
        </div>
      ) : (
        <VulnerabilityList
          findings={state.filtered}
          selectedIds={state.selectedIds}
          highlightIndex={state.highlightIndex}
          onOpenFinding={state.setSelectedFindingId}
          onToggleSelect={state.toggleSelect}
        />
      )}

      <VulnerabilityKeyboardHint />
    </div>
  );
};
