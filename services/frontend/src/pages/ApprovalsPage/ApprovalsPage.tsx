import React, { useCallback, useEffect, useMemo } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import type { ApprovalRequest } from "@/common/api/approval";
import { PageHeader, Spinner } from "@/common/ui/primitives";
import { useToast } from "@/common/contexts/ToastContext";
import { ApprovalListRail } from "./components/ApprovalListRail/ApprovalListRail";
import { ApprovalDocument } from "./components/ApprovalDocument/ApprovalDocument";
import {
  useApprovalsPageController,
  type ApprovalFilterStatus,
} from "./useApprovalsPageController";
import { formatRelative } from "./approvalFormat";
import "./ApprovalsPage.css";

const FILTER_TABS: { id: ApprovalFilterStatus; label: string }[] = [
  { id: "pending", label: "대기" },
  { id: "approved", label: "승인됨" },
  { id: "rejected", label: "거부" },
  { id: "expired", label: "만료" },
];

export const ApprovalsPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const {
    loading,
    approvals,
    filter,
    setFilter,
    filteredApprovals,
    statusCounts,
    pendingCount,
    decidingId,
    submitDecision,
    selectedId,
    setSelectedId,
    sevenDayStats,
    imminentCount,
    oldestPendingAge,
    detailById,
  } = useApprovalsPageController(projectId, toast);

  useEffect(() => {
    document.title = "AEGIS — 승인 큐";
  }, []);

  // URL ↔ selected sync (?selected=APR-XXXX)
  useEffect(() => {
    const urlSelected = searchParams.get("selected");
    if (urlSelected && urlSelected !== selectedId) {
      setSelectedId(urlSelected);
    } else if (!urlSelected && selectedId) {
      setSelectedId(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (selectedId) {
      next.set("selected", selectedId);
    } else {
      next.delete("selected");
    }
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  const handleTargetOpen = useCallback(
    (approval: ApprovalRequest) => {
      if (!projectId) return;
      navigate(
        approval.actionType === "gate.override"
          ? `/projects/${projectId}/quality-gate`
          : `/projects/${projectId}/vulnerabilities`,
      );
    },
    [navigate, projectId],
  );

  const selectedApproval = useMemo(() => {
    const fromList = filteredApprovals.find((a) => a.id === selectedId) ?? filteredApprovals[0] ?? null;
    if (!fromList) return null;
    // Prefer canonical detail when available (C9 — fresh single-record fetch).
    return detailById[fromList.id] ?? fromList;
  }, [filteredApprovals, selectedId, detailById]);

  const oldestSubmittedIso = useMemo(() => {
    if (oldestPendingAge === null) return null;
    let ageMs = oldestPendingAge;
    let iso: string | null = null;
    for (const a of approvals) {
      if (a.status !== "pending") continue;
      const t = new Date(a.createdAt).getTime();
      if (Number.isNaN(t)) continue;
      const age = Date.now() - t;
      if (age >= ageMs - 1) {
        ageMs = age;
        iso = a.createdAt;
      }
    }
    return iso;
  }, [approvals, oldestPendingAge]);

  if (loading) {
    return (
      <div className="page-loading-shell">
        <Spinner size={36} label="승인 요청 로딩 중..." />
      </div>
    );
  }

  const hasProject = Boolean(projectId);

  const subtitleNode =
    pendingCount > 0 ? (
      <span className="approvals-page__sub" aria-label="승인 큐 현재 상태">
        대기 <span className="num">{pendingCount}</span>건
        {imminentCount > 0 ? (
          <>
            <span className="sep" aria-hidden="true"> · </span>
            <span className="warn">
              24시간 내 만료 <span className="num">{imminentCount}</span>건
            </span>
          </>
        ) : null}
        {oldestSubmittedIso ? (
          <>
            <span className="sep" aria-hidden="true"> · </span>
            가장 오래된 항목{" "}
            <span className="num">{formatRelative(oldestSubmittedIso)}</span> 제출
          </>
        ) : null}
      </span>
    ) : undefined;

  return (
    <div className="page-shell approvals-page">
      <PageHeader surface="plain" title="승인 큐" subtitle={subtitleNode} />

      <div className="approvals-page__frame">
        <div
          className="approvals-page__filters"
          role="tablist"
          aria-label="승인 요청 상태 필터"
        >
          {FILTER_TABS.map((tab) => {
            const count = statusCounts[tab.id];
            const isActive = filter === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                data-count={count}
                className="approvals-page__tab"
                onClick={() => setFilter(tab.id)}
              >
                {tab.label}
                <span className="c">{count}</span>
              </button>
            );
          })}
        </div>

        <div className="approvals-page__work">
          <ApprovalListRail
            approvals={filteredApprovals}
            filter={filter}
            selectedId={selectedApproval?.id ?? null}
            hasProject={hasProject}
            sevenDayStats={sevenDayStats}
            onSelect={setSelectedId}
          />
          <ApprovalDocument
            approval={selectedApproval}
            decidingId={decidingId}
            onOpenTarget={handleTargetOpen}
            onDecide={submitDecision}
          />
        </div>
      </div>
    </div>
  );
};
