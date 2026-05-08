import "./AdminRegistrationsRow.css";
import React from "react";
import type { RegistrationRequest, UserRole } from "@aegis/shared";
import { useAdminRegistrationsRow } from "./useAdminRegistrationsRow";
import { AdminRegistrationsRowSummary } from "./AdminRegistrationsRowSummary/AdminRegistrationsRowSummary";
import { AdminRegistrationsRowMeta } from "./AdminRegistrationsRowMeta/AdminRegistrationsRowMeta";
import { AdminRegistrationsRowReason } from "./AdminRegistrationsRowReason/AdminRegistrationsRowReason";
import { AdminRegistrationsRowApproveActions } from "./AdminRegistrationsRowApproveActions/AdminRegistrationsRowApproveActions";
import { AdminRegistrationsRowRejectForm } from "./AdminRegistrationsRowRejectForm/AdminRegistrationsRowRejectForm";

interface AdminRegistrationsRowProps {
  request: RegistrationRequest;
  busy?: "approve" | "reject";
  onApprove: (id: string, role: UserRole) => void;
  onReject: (id: string, reason: string) => Promise<boolean>;
  onOpenDetail: (id: string) => void;
}

export const AdminRegistrationsRow: React.FC<AdminRegistrationsRowProps> = ({ request, busy, onApprove, onReject, onOpenDetail }) => {
  const {
    role,
    setRole,
    rejectMode,
    enterRejectMode,
    cancelReject,
    reason,
    setReason,
    approve,
    confirmReject,
  } = useAdminRegistrationsRow(request.id, onApprove, onReject);

  const isPending = request.status === "pending_admin_review";
  const organization = request.organizationName || request.organizationCode || request.organizationId;

  return (
    <div className={`admin-reg-row${isPending ? " admin-reg-row--pending" : ""}`}>
      <div className="admin-reg-row__body">
        <AdminRegistrationsRowSummary
          fullName={request.fullName}
          status={request.status}
          assignedRole={request.assignedRole}
        />
        <div className="admin-reg-row__email">{request.email}</div>
        <AdminRegistrationsRowMeta
          organization={organization}
          createdAt={request.createdAt}
          approvedAt={request.approvedAt}
          rejectedAt={request.rejectedAt}
        />
        {request.decisionReason ? <AdminRegistrationsRowReason reason={request.decisionReason} /> : null}
        {/* 상세 button is status-agnostic by design — even decided rows preserve audit value
            (admins frequently revisit approved/rejected requests for context). */}
        <div className="admin-reg-row__inline-actions">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => onOpenDetail(request.id)}
            aria-label={`${request.fullName} 가입 요청 상세 보기`}
          >
            상세
          </button>
        </div>
      </div>

      {isPending ? (
        rejectMode ? (
          <AdminRegistrationsRowRejectForm
            reason={reason}
            onReasonChange={setReason}
            onCancel={cancelReject}
            onConfirm={() => void confirmReject()}
            busy={busy}
          />
        ) : (
          <AdminRegistrationsRowApproveActions
            fullName={request.fullName}
            role={role}
            onRoleChange={setRole}
            onApprove={approve}
            onEnterRejectMode={enterRejectMode}
            busy={busy}
          />
        )
      ) : null}
    </div>
  );
};
