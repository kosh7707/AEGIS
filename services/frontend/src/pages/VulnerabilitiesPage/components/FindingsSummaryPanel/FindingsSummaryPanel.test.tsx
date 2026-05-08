import React from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingsSummaryPanel } from "./FindingsSummaryPanel";

describe("FindingsSummaryPanel", () => {
  it("renders 정보 없음 placeholder when summary is null", () => {
    render(<FindingsSummaryPanel summary={null} />);
    expect(screen.getByText("정보 없음")).toBeInTheDocument();
  });

  it("renders 정보 없음 placeholder when summary lacks the typed `total` field (early-load empty payload)", () => {
    // Some intermediate fetches may resolve before the canonical envelope is
    // fully populated. Panel guards `summary.total` as the contract anchor.
    render(<FindingsSummaryPanel summary={{} as never} />);
    expect(screen.getByText("정보 없음")).toBeInTheDocument();
  });

  it("renders TOTAL when summary.total is a number", () => {
    render(
      <FindingsSummaryPanel
        summary={{ total: 42, bySeverity: {}, byStatus: {} }}
      />,
    );
    expect(screen.getByText("TOTAL")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("renders severity buckets only for keys actually present in bySeverity", () => {
    render(
      <FindingsSummaryPanel
        summary={{
          total: 8,
          bySeverity: { critical: 3, high: 5 },
          byStatus: {},
        }}
      />,
    );
    expect(screen.getByText("치명")).toBeInTheDocument();
    expect(screen.getByText("높음")).toBeInTheDocument();
    expect(screen.queryByText("보통")).not.toBeInTheDocument();
    expect(screen.queryByText("낮음")).not.toBeInTheDocument();
  });

  it("does not invent severity buckets when bySeverity is empty", () => {
    render(<FindingsSummaryPanel summary={{ total: 5, bySeverity: {}, byStatus: {} }} />);
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.queryByText("치명")).not.toBeInTheDocument();
  });

  it("renders byStatus pills with review-tone vocabulary", () => {
    render(
      <FindingsSummaryPanel
        summary={{
          total: 12,
          bySeverity: {},
          byStatus: { open: 5, fixed: 4, needs_review: 3 },
        }}
      />,
    );
    expect(screen.getByText("OPEN")).toBeInTheDocument();
    expect(screen.getByText("FIXED")).toBeInTheDocument();
    expect(screen.getByText("REVIEW")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("renders byStatus pills even when count is zero — zero is a meaningful aggregate", () => {
    render(
      <FindingsSummaryPanel
        summary={{
          total: 1,
          bySeverity: {},
          byStatus: { open: 1, fixed: 0 },
        }}
      />,
    );
    expect(screen.getByText("OPEN")).toBeInTheDocument();
    expect(screen.getByText("FIXED")).toBeInTheDocument();
  });

  it("renders TOTAL as '0' (not '정보 없음') when total is zero", () => {
    render(
      <FindingsSummaryPanel
        summary={{ total: 0, bySeverity: {}, byStatus: {} }}
      />,
    );
    expect(screen.getByText("TOTAL")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.queryByText("정보 없음")).not.toBeInTheDocument();
  });

  it("applies tone class — fixed → success, open → danger, needs_review → warning", () => {
    const { container } = render(
      <FindingsSummaryPanel
        summary={{
          total: 9,
          bySeverity: {},
          byStatus: { open: 3, fixed: 4, needs_review: 2 },
        }}
      />,
    );
    expect(
      container.querySelector(".findings-summary-panel__status-pill--success"),
    ).toBeInTheDocument();
    expect(
      container.querySelector(".findings-summary-panel__status-pill--danger"),
    ).toBeInTheDocument();
    expect(
      container.querySelector(".findings-summary-panel__status-pill--warning"),
    ).toBeInTheDocument();
  });
});
