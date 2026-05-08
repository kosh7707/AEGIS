import React from "react";
import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { FilesBuildTargetBar } from "./FilesBuildTargetBar";

const baseTargets = [
  { id: "t-1", name: "Firmware", status: "discovered" as const },
  { id: "t-2", name: "Bootloader", status: "discovered" as const },
];

function renderBar(overrides: Partial<React.ComponentProps<typeof FilesBuildTargetBar>> = {}) {
  return render(
    <FilesBuildTargetBar
      // useBuildTargets target shape is wider; tests only need id/name
      targets={baseTargets as unknown as React.ComponentProps<typeof FilesBuildTargetBar>["targets"]}
      activeTargetFilters={new Set()}
      onToggleFilter={vi.fn()}
      onClearFilters={vi.fn()}
      onRequestDeleteSource={vi.fn()}
      deletingSource={false}
      {...overrides}
    />,
  );
}

describe("FilesBuildTargetBar — per-target Prepare (E1)", () => {
  it("does not render Prepare row when onPrepareTarget is omitted", () => {
    renderBar();
    expect(screen.queryByRole("group", { name: "빌드 타겟 검증" })).not.toBeInTheDocument();
  });

  it("renders one Prepare button per target when onPrepareTarget is provided", () => {
    renderBar({ onPrepareTarget: vi.fn() });
    expect(screen.getByRole("group", { name: "빌드 타겟 검증" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Firmware 빌드 검증" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Bootloader 빌드 검증" })).toBeInTheDocument();
  });

  it("invokes onPrepareTarget with the target id when clicked", () => {
    const onPrepareTarget = vi.fn();
    renderBar({ onPrepareTarget });
    fireEvent.click(screen.getByRole("button", { name: "Firmware 빌드 검증" }));
    expect(onPrepareTarget).toHaveBeenCalledWith("t-1");
  });
});

describe("FilesBuildTargetBar — Prepare progress (E2)", () => {
  it('shows "빌드 검증 중..." on the active target while isPreparing', () => {
    renderBar({
      onPrepareTarget: vi.fn(),
      isPreparing: true,
      preparingTargetId: "t-1",
    });
    const activeBtn = screen.getByRole("button", { name: "Firmware 빌드 검증" });
    expect(activeBtn).toHaveTextContent("빌드 검증 중...");
    const otherBtn = screen.getByRole("button", { name: "Bootloader 빌드 검증" });
    expect(otherBtn).toHaveTextContent("빌드 검증");
    expect(otherBtn).not.toHaveTextContent("빌드 검증 중...");
  });

  it("disables every Prepare button while isPreparing to prevent double-dispatch", () => {
    renderBar({
      onPrepareTarget: vi.fn(),
      isPreparing: true,
      preparingTargetId: "t-1",
    });
    expect(screen.getByRole("button", { name: "Firmware 빌드 검증" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Bootloader 빌드 검증" })).toBeDisabled();
  });
});

describe("FilesBuildTargetBar — cross-surface preparation banner", () => {
  it("shows banner when isPreparing=true and preparingTargetId=null (preparation from another surface)", () => {
    renderBar({
      onPrepareTarget: vi.fn(),
      isPreparing: true,
      preparingTargetId: null,
    });
    expect(screen.getByText("다른 화면에서 빌드 검증이 진행 중입니다.")).toBeInTheDocument();
  });

  it("hides banner and shows active button label when isPreparing=true and preparingTargetId is set", () => {
    renderBar({
      onPrepareTarget: vi.fn(),
      isPreparing: true,
      preparingTargetId: "t-1",
    });
    expect(screen.queryByText("다른 화면에서 빌드 검증이 진행 중입니다.")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Firmware 빌드 검증" })).toHaveTextContent("빌드 검증 중...");
  });
});
