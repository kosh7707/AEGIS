import "./AdminRegistrationsList.css";
import React from "react";
import type { RegistrationRequest, UserRole } from "@aegis/shared";
import { AdminRegistrationsRow } from "../AdminRegistrationsRow/AdminRegistrationsRow";

interface AdminRegistrationsListProps {
  requests: RegistrationRequest[];
  busy: Record<string, "approve" | "reject" | undefined>;
  onApprove: (id: string, role: UserRole) => void;
  onReject: (id: string, reason: string) => Promise<boolean>;
  onOpenDetail: (id: string) => void;
}

export const AdminRegistrationsList: React.FC<AdminRegistrationsListProps> = ({ requests, busy, onApprove, onReject, onOpenDetail }) => (
  <div className="admin-reg-list">
    {requests.map((request) => (
      <AdminRegistrationsRow
        key={request.id}
        request={request}
        busy={busy[request.id]}
        onApprove={onApprove}
        onReject={onReject}
        onOpenDetail={onOpenDetail}
      />
    ))}
  </div>
);
