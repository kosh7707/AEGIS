import { useCallback, useEffect, useMemo, useState } from "react";
import type { RegistrationRequest, UserRole } from "@aegis/shared";
import {
  approveRegistrationRequest,
  fetchRegistrationRequest,
  listRegistrationRequests,
  rejectRegistrationRequest,
} from "@/common/api/auth";

export type RegistrationStatusFilter = "pending" | "approved" | "rejected" | "all";

type BusyMap = Record<string, "approve" | "reject" | undefined>;

export function useAdminRegistrationsPageController() {
  const [requests, setRequests] = useState<RegistrationRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<BusyMap>({});
  const [actionError, setActionError] = useState<string | null>(null);
  const [filter, setFilter] = useState<RegistrationStatusFilter>("pending");
  const [detailRequest, setDetailRequest] = useState<RegistrationRequest | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const data = await listRegistrationRequests();
      setRequests(data);
    } catch (failure: unknown) {
      const message = failure instanceof Error ? failure.message : "가입 요청 목록을 불러오지 못했습니다.";
      setLoadError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    document.title = "AEGIS — 관리자 · 가입 요청";
    void refresh();
  }, [refresh]);

  const approve = useCallback(async (id: string, role: UserRole) => {
    setActionError(null);
    setBusy((prev) => ({ ...prev, [id]: "approve" }));
    try {
      const updated = await approveRegistrationRequest(id, role);
      setRequests((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
    } catch (failure: unknown) {
      const message = failure instanceof Error ? failure.message : "승인 처리에 실패했습니다.";
      setActionError(message);
    } finally {
      setBusy((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }
  }, []);

  const reject = useCallback(async (id: string, reason: string) => {
    const trimmed = reason.trim();
    if (!trimmed) {
      setActionError("반려 사유를 입력해 주세요.");
      return false;
    }
    setActionError(null);
    setBusy((prev) => ({ ...prev, [id]: "reject" }));
    try {
      const updated = await rejectRegistrationRequest(id, trimmed);
      setRequests((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      return true;
    } catch (failure: unknown) {
      const message = failure instanceof Error ? failure.message : "반려 처리에 실패했습니다.";
      setActionError(message);
      return false;
    } finally {
      setBusy((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }
  }, []);

  const openDetail = useCallback(async (id: string) => {
    setDetailError(null);
    setDetailLoading(true);
    setDetailRequest(null);
    try {
      const fresh = await fetchRegistrationRequest(id);
      setDetailRequest(fresh);
    } catch (failure: unknown) {
      const message = failure instanceof Error ? failure.message : "가입 요청 상세를 불러오지 못했습니다.";
      setDetailError(message);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeDetail = useCallback(() => {
    setDetailRequest(null);
    setDetailError(null);
    setDetailLoading(false);
  }, []);

  const counts = useMemo(() => ({
    pending: requests.filter((r) => r.status === "pending_admin_review").length,
    approved: requests.filter((r) => r.status === "approved").length,
    rejected: requests.filter((r) => r.status === "rejected").length,
  }), [requests]);

  const displayRequests = useMemo(() => {
    switch (filter) {
      case "pending":  return requests.filter((r) => r.status === "pending_admin_review");
      case "approved": return requests.filter((r) => r.status === "approved");
      case "rejected": return requests.filter((r) => r.status === "rejected");
      case "all":
      default:         return requests;
    }
  }, [requests, filter]);

  return {
    requests,
    counts,
    loading,
    loadError,
    actionError,
    busy,
    refresh,
    approve,
    reject,
    clearActionError: () => setActionError(null),
    filter,
    setFilter,
    displayRequests,
    detailRequest,
    detailLoading,
    detailError,
    openDetail,
    closeDetail,
  };
}
