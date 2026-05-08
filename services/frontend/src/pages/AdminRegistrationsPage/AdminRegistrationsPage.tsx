import "./AdminRegistrationsPage.css";
import React from "react";
import { PageHeader } from "@/common/ui/primitives";
import { useAdminRegistrationsPageController } from "./useAdminRegistrationsPageController";
import { AdminRegistrationsRefreshButton } from "./components/AdminRegistrationsRefreshButton/AdminRegistrationsRefreshButton";
import { AdminRegistrationsKpiBar } from "./components/AdminRegistrationsKpiBar/AdminRegistrationsKpiBar";
import { AdminRegistrationsErrorNotice } from "./components/AdminRegistrationsErrorNotice/AdminRegistrationsErrorNotice";
import { AdminRegistrationsListPanel } from "./components/AdminRegistrationsListPanel/AdminRegistrationsListPanel";
import { AdminRegistrationsDetailDialog } from "./components/AdminRegistrationsDetailDialog/AdminRegistrationsDetailDialog";

export const AdminRegistrationsPage: React.FC = () => {
  const {
    counts,
    loading,
    loadError,
    actionError,
    busy,
    refresh,
    approve,
    reject,
    clearActionError,
    filter,
    setFilter,
    displayRequests,
    detailRequest,
    detailLoading,
    detailError,
    openDetail,
    closeDetail,
  } = useAdminRegistrationsPageController();

  const [detailOpen, setDetailOpen] = React.useState(false);
  const handleOpenDetail = React.useCallback((id: string) => {
    setDetailOpen(true);
    void openDetail(id);
  }, [openDetail]);
  const handleCloseDetail = React.useCallback(() => {
    setDetailOpen(false);
    closeDetail();
  }, [closeDetail]);

  return (
    <div className="page-shell admin-reg-page">
      <PageHeader
        surface="plain"
        title="가입 요청 관리"
        action={<AdminRegistrationsRefreshButton loading={loading} onClick={() => void refresh()} />}
      />

      <AdminRegistrationsKpiBar
        pending={counts.pending}
        approved={counts.approved}
        rejected={counts.rejected}
        pendingActive={filter === "pending"}
      />

      {loadError ? <AdminRegistrationsErrorNotice message={loadError} /> : null}
      {actionError ? <AdminRegistrationsErrorNotice message={actionError} onClose={clearActionError} /> : null}

      <AdminRegistrationsListPanel
        loading={loading}
        requests={displayRequests}
        busy={busy}
        filter={filter}
        onFilterChange={setFilter}
        onApprove={approve}
        onReject={reject}
        onOpenDetail={handleOpenDetail}
      />

      <AdminRegistrationsDetailDialog
        open={detailOpen}
        loading={detailLoading}
        error={detailError}
        request={detailRequest}
        onClose={handleCloseDetail}
      />
    </div>
  );
};
