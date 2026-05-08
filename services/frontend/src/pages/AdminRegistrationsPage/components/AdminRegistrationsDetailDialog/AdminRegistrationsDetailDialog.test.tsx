import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import type { RegistrationRequest } from "@aegis/shared";
import { AdminRegistrationsDetailDialog } from "./AdminRegistrationsDetailDialog";

const sampleRequest: RegistrationRequest = {
  id: "reg-1",
  organizationId: "org-1",
  organizationCode: "ACME-KR-SEC",
  organizationName: "ACME Security",
  fullName: "홍길동",
  email: "g.hong@acme.kr",
  status: "approved",
  assignedRole: "analyst",
  lookupExpiresAt: "2026-06-01T00:00:00Z",
  createdAt: "2026-05-01T00:00:00Z",
  approvedAt: "2026-05-02T00:00:00Z",
};

describe("AdminRegistrationsDetailDialog", () => {
  it("returns null when closed", () => {
    const { container } = render(
      <AdminRegistrationsDetailDialog
        open={false}
        loading={false}
        error={null}
        request={null}
        onClose={vi.fn()}
      />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("shows the spinner label while loading", () => {
    render(
      <AdminRegistrationsDetailDialog
        open={true}
        loading={true}
        error={null}
        request={null}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByText("상세 로딩 중...")).toBeInTheDocument();
  });

  it("renders the error notice when error is set", () => {
    render(
      <AdminRegistrationsDetailDialog
        open={true}
        loading={false}
        error="가입 요청을 찾을 수 없습니다."
        request={null}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("가입 요청을 찾을 수 없습니다.");
  });

  it("renders all canonical fields when a request is supplied", () => {
    render(
      <AdminRegistrationsDetailDialog
        open={true}
        loading={false}
        error={null}
        request={sampleRequest}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByText("홍길동")).toBeInTheDocument();
    expect(screen.getByText("g.hong@acme.kr")).toBeInTheDocument();
    expect(screen.getByText("ACME Security")).toBeInTheDocument();
    expect(screen.getByText("reg-1")).toBeInTheDocument();
    expect(screen.getByText("analyst")).toBeInTheDocument();
  });

  it("invokes onClose when the close button is pressed", () => {
    const onClose = vi.fn();
    render(
      <AdminRegistrationsDetailDialog
        open={true}
        loading={false}
        error={null}
        request={sampleRequest}
        onClose={onClose}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "닫기" }));
    expect(onClose).toHaveBeenCalled();
  });
});
