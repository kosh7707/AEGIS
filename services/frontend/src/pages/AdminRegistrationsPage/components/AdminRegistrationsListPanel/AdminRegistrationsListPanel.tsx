import "./AdminRegistrationsListPanel.css";
import React from "react";
import type { RegistrationRequest, UserRole } from "@aegis/shared";
import type { RegistrationStatusFilter } from "../../useAdminRegistrationsPageController";
import { AdminRegistrationsListPanelHeader } from "../AdminRegistrationsListPanelHeader/AdminRegistrationsListPanelHeader";
import { AdminRegistrationsLoadingState } from "../AdminRegistrationsLoadingState/AdminRegistrationsLoadingState";
import { AdminRegistrationsEmptyState } from "../AdminRegistrationsEmptyState/AdminRegistrationsEmptyState";
import { AdminRegistrationsList } from "../AdminRegistrationsList/AdminRegistrationsList";

interface AdminRegistrationsListPanelProps {
  loading: boolean;
  requests: RegistrationRequest[];
  busy: Record<string, "approve" | "reject" | undefined>;
  filter: RegistrationStatusFilter;
  onFilterChange: (value: RegistrationStatusFilter) => void;
  onApprove: (id: string, role: UserRole) => void;
  onReject: (id: string, reason: string) => Promise<boolean>;
  onOpenDetail: (id: string) => void;
}

export const AdminRegistrationsListPanel: React.FC<AdminRegistrationsListPanelProps> = ({
  loading,
  requests,
  busy,
  filter,
  onFilterChange,
  onApprove,
  onReject,
  onOpenDetail,
}) => (
  <section className="panel" aria-label="가입 요청 목록">
    <AdminRegistrationsListPanelHeader count={requests.length} filter={filter} onFilterChange={onFilterChange} />
    {loading ? (
      <AdminRegistrationsLoadingState />
    ) : requests.length === 0 ? (
      <AdminRegistrationsEmptyState pendingFilter={filter === "pending"} />
    ) : (
      <AdminRegistrationsList
        requests={requests}
        busy={busy}
        onApprove={onApprove}
        onReject={onReject}
        onOpenDetail={onOpenDetail}
      />
    )}
  </section>
);
