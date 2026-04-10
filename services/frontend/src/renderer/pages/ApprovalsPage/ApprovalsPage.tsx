import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AlertCircle, CheckCircle, ClipboardCheck, Clock, ExternalLink, Timer, XCircle } from "lucide-react";
import type { ApprovalRequest } from "../../api/approval";
import { decideApproval, fetchProjectApprovals } from "../../api/approval";
import { logError } from "../../api/core";
import { EmptyState, Spinner } from "../../components/ui";
import { useToast } from "../../contexts/ToastContext";
import { formatDateTime } from "../../utils/format";
import "./ApprovalsPage.css";

type FilterStatus = "all" | "pending" | "approved" | "rejected" | "expired";
type DecisionAction = "approved" | "rejected";

type ApprovalStatusConfig = {
  icon: React.ReactNode;
  label: string;
  className: string;
};

const STATUS_CONFIG: Record<Exclude<FilterStatus, "all">, ApprovalStatusConfig> = {
  pending: { icon: <Clock size={14} />, label: "대기", className: "approval-status--pending" },
  approved: { icon: <CheckCircle size={14} />, label: "승인됨", className: "approval-status--approved" },
  rejected: { icon: <XCircle size={14} />, label: "거부", className: "approval-status--rejected" },
  expired: { icon: <Timer size={14} />, label: "만료", className: "approval-status--expired" },
};

const FILTERS: FilterStatus[] = ["all", "pending", "approved", "rejected", "expired"];

const ACTION_LABELS: Record<string, string> = {
  "gate.override": "Quality Gate 오버라이드",
  "finding.accepted_risk": "Finding 위험 수용",
};

export const ApprovalsPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<FilterStatus>("all");
  const [decidingId, setDecidingId] = useState<string | null>(null);
  const [decidingAction, setDecidingAction] = useState<DecisionAction | null>(null);
  const [comment, setComment] = useState("");
  const [processing, setProcessing] = useState(false);

  useEffect(() => {
    document.title = "AEGIS — Approvals";
  }, []);

  const load = useCallback(async () => {
    if (!projectId) return;

    setLoading(true);

    try {
      const data = await fetchProjectApprovals(projectId);
      setApprovals(data.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()));
    } catch (error) {
      logError("Load approvals", error);
      toast.error("승인 요청 목록을 불러올 수 없습니다.");
    } finally {
      setLoading(false);
    }
  }, [projectId, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const closeDecisionDialog = useCallback(() => {
    setDecidingId(null);
    setDecidingAction(null);
    setComment("");
  }, []);

  const openDecisionDialog = useCallback((approvalId: string, action: DecisionAction) => {
    setDecidingId(approvalId);
    setDecidingAction(action);
  }, []);

  const handleDecision = useCallback(async () => {
    if (!decidingId || !decidingAction) return;

    setProcessing(true);

    try {
      await decideApproval(decidingId, decidingAction, undefined, comment.trim() || undefined);
      toast.success(decidingAction === "approved" ? "승인 완료" : "거부 완료");
      closeDecisionDialog();
      await load();
    } catch (error) {
      logError("Decide approval", error);
      toast.error("처리에 실패했습니다.");
    } finally {
      setProcessing(false);
    }
  }, [closeDecisionDialog, comment, decidingAction, decidingId, load, toast]);

  const filteredApprovals = useMemo(
    () => (filter === "all" ? approvals : approvals.filter((approval) => approval.status === filter)),
    [approvals, filter],
  );
  const pendingCount = useMemo(
    () => approvals.filter((approval) => approval.status === "pending").length,
    [approvals],
  );

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

  if (loading) {
    return (
      <div className="page-enter centered-loader">
        <Spinner size={36} label="승인 요청 로딩 중..." />
      </div>
    );
  }

  return (
    <div className="page-enter">
      <div className="approval-page-header">
        <div>
          <h1 className="approval-page-header__title">Approvals</h1>
          {pendingCount > 0 && (
            <p className="approval-page-header__subtitle">{pendingCount}건의 승인 요청이 대기 중입니다</p>
          )}
        </div>
      </div>

      <div className="approval-filters" role="tablist" aria-label="Approval status filters">
        {FILTERS.map((status) => (
          <button
            key={status}
            type="button"
            className={`approval-filter__btn${filter === status ? " active" : ""}`}
            onClick={() => setFilter(status)}
          >
            {status === "all" ? "전체" : STATUS_CONFIG[status].label}
          </button>
        ))}
      </div>

      {filteredApprovals.length === 0 ? (
        <EmptyState
          icon={<ClipboardCheck size={28} />}
          title={filter === "all" ? "승인 요청이 없습니다" : `${STATUS_CONFIG[filter]?.label ?? filter} 상태의 요청이 없습니다`}
        />
      ) : (
        <div className="approval-list">
          {filteredApprovals.map((approval) => {
            const statusConfig = STATUS_CONFIG[approval.status] ?? STATUS_CONFIG.pending;
            const isExpired = new Date(approval.expiresAt) < new Date();
            const isPending = approval.status === "pending";
            const isImminent = new Date(approval.expiresAt).getTime() - Date.now() < 24 * 60 * 60 * 1000;

            return (
              <div key={approval.id} className={`approval-card card approval-card--${approval.status}`}>
                <div className="approval-card__header">
                  <div>
                    <h3 className="approval-card__action">{ACTION_LABELS[approval.actionType] ?? approval.actionType}</h3>
                    <div className="approval-card__meta">
                      <span>요청자: {approval.requestedBy}</span>
                      <span>{formatDateTime(approval.createdAt)}</span>
                      {!isExpired && isPending && (
                        <span className={`approval-card__expires${isImminent ? " approval-card__expires--imminent" : ""}`}>
                          만료: {formatDateTime(approval.expiresAt)}
                        </span>
                      )}
                    </div>
                  </div>
                  <span className={`approval-card__status-badge approval-card__status-badge--${approval.status} ${statusConfig.className}`}>
                    {statusConfig.icon} {statusConfig.label}
                  </span>
                </div>

                <div className="approval-card__body">
                  <div className="approval-card__reason">
                    <AlertCircle size={12} />
                    <span>{approval.reason}</span>
                  </div>
                  <button type="button" className="approval-card__target" onClick={() => handleTargetOpen(approval)}>
                    <ExternalLink size={11} />
                    {approval.actionType === "gate.override" ? "Gate 보기" : "Finding 보기"}
                  </button>
                </div>

                {approval.decision && (
                  <div className="approval-card__decision">
                    <span>결정: {approval.decision.decidedBy} ({formatDateTime(approval.decision.decidedAt)})</span>
                    {approval.decision.comment && <span className="approval-card__comment">"{approval.decision.comment}"</span>}
                  </div>
                )}

                {isPending && !isExpired && (
                  <div className="approval-card__actions">
                    <button
                      type="button"
                      className="btn btn-sm approval-btn--approve"
                      onClick={() => openDecisionDialog(approval.id, "approved")}
                    >
                      승인
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm approval-btn--reject"
                      onClick={() => openDecisionDialog(approval.id, "rejected")}
                    >
                      거부
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {decidingId && decidingAction && (
        <div className="confirm-overlay" role="presentation" onClick={closeDecisionDialog}>
          <div className="confirm-dialog card" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <h3 className="confirm-dialog__title">{decidingAction === "approved" ? "승인 확인" : "거부 확인"}</h3>
            <textarea
              className="input approval-dialog__comment-input"
              rows={3}
              placeholder="코멘트 (선택)"
              value={comment}
              onChange={(event) => setComment(event.target.value)}
            />
            <div className="confirm-dialog__actions">
              <button type="button" className="btn btn-secondary btn-sm" onClick={closeDecisionDialog}>
                취소
              </button>
              <button
                type="button"
                className={`btn btn-sm${decidingAction === "rejected" ? " confirm-dialog__btn--cds-support-error" : ""}`}
                onClick={handleDecision}
                disabled={processing}
              >
                {processing ? "처리 중..." : decidingAction === "approved" ? "승인" : "거부"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
