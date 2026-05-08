import "./AdminRegistrationsDetailDialog.css";
import React from "react";
import type { RegistrationRequest } from "@aegis/shared";
import { Modal, Spinner } from "@/common/ui/primitives";
import { AdminRegistrationsStatusBadge } from "../AdminRegistrationsStatusBadge/AdminRegistrationsStatusBadge";

interface AdminRegistrationsDetailDialogProps {
  open: boolean;
  loading: boolean;
  error: string | null;
  request: RegistrationRequest | null;
  onClose: () => void;
}

function formatDateTime(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("ko-KR", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export const AdminRegistrationsDetailDialog: React.FC<AdminRegistrationsDetailDialogProps> = ({
  open,
  loading,
  error,
  request,
  onClose,
}) => {
  if (!open) return null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      labelledBy="admin-reg-detail-title"
      describedBy="admin-reg-detail-desc"
      className="admin-reg-detail"
    >
      <header className="admin-reg-detail__head">
        <div className="admin-reg-detail__eyebrow">REGISTRATION REQUEST</div>
        <h2 id="admin-reg-detail-title" className="admin-reg-detail__title">
          {request?.fullName ?? "가입 요청 상세"}
        </h2>
        <p id="admin-reg-detail-desc" className="admin-reg-detail__desc">
          관리자 검토용 단일 레코드 — 목록과 별개로 백엔드의 최신 상태를 다시 가져옵니다.
        </p>
      </header>

      <div className="admin-reg-detail__body">
        {loading ? (
          <div className="admin-reg-detail__loading">
            <Spinner size={20} label="상세 로딩 중..." />
          </div>
        ) : error ? (
          <div className="admin-reg-detail__error" role="alert">{error}</div>
        ) : request ? (
          <dl className="admin-reg-detail__grid">
            <div className="admin-reg-detail__row">
              <dt>상태</dt>
              <dd><AdminRegistrationsStatusBadge status={request.status} /></dd>
            </div>
            <div className="admin-reg-detail__row">
              <dt>이메일</dt>
              <dd className="mono">{request.email}</dd>
            </div>
            <div className="admin-reg-detail__row">
              <dt>조직</dt>
              <dd>
                {request.organizationName ?? request.organizationCode ?? request.organizationId}
                {request.organizationCode ? (
                  <span className="admin-reg-detail__sub mono"> · {request.organizationCode}</span>
                ) : null}
              </dd>
            </div>
            <div className="admin-reg-detail__row">
              <dt>요청 ID</dt>
              <dd className="mono">{request.id}</dd>
            </div>
            <div className="admin-reg-detail__row">
              <dt>요청 시각</dt>
              <dd>{formatDateTime(request.createdAt)}</dd>
            </div>
            {request.approvedAt ? (
              <div className="admin-reg-detail__row">
                <dt>승인 시각</dt>
                <dd>{formatDateTime(request.approvedAt)}</dd>
              </div>
            ) : null}
            {request.rejectedAt ? (
              <div className="admin-reg-detail__row">
                <dt>반려 시각</dt>
                <dd>{formatDateTime(request.rejectedAt)}</dd>
              </div>
            ) : null}
            {request.assignedRole ? (
              <div className="admin-reg-detail__row">
                <dt>할당 역할</dt>
                <dd className="mono">{request.assignedRole}</dd>
              </div>
            ) : null}
            <div className="admin-reg-detail__row">
              <dt>조회 토큰 만료</dt>
              <dd>{formatDateTime(request.lookupExpiresAt)}</dd>
            </div>
            {request.decisionReason ? (
              <div className="admin-reg-detail__row admin-reg-detail__row--full">
                <dt>반려 사유</dt>
                <dd className="admin-reg-detail__reason">{request.decisionReason}</dd>
              </div>
            ) : null}
          </dl>
        ) : null}
      </div>

      <footer className="admin-reg-detail__foot">
        <button type="button" className="btn btn-outline btn-sm" onClick={onClose}>
          닫기
        </button>
      </footer>
    </Modal>
  );
};
