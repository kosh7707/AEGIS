import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { SdkMetricsPanel } from "./SdkMetricsPanel";

const mockFetchSdkMetrics = vi.fn();

vi.mock("@/common/api/sdk", () => ({
  fetchSdkMetrics: (...args: unknown[]) => mockFetchSdkMetrics(...args),
}));
vi.mock("@/common/api/core", () => ({ logError: vi.fn() }));

const metricsFixture = (overrides: Partial<{
  totalRegistered: number;
  sdkCount: number;
  readyCount: number;
  failedCount: number;
  averagePhaseDurationMs: Record<string, number>;
}> = {}) => ({
  totalRegistered: overrides.totalRegistered ?? 0,
  sdkCount: overrides.sdkCount ?? overrides.totalRegistered ?? 0,
  readyCount: overrides.readyCount ?? 0,
  failedCount: overrides.failedCount ?? 0,
  averagePhaseDurationMs: overrides.averagePhaseDurationMs ?? {},
});

describe("SdkMetricsPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls fetchSdkMetrics with projectId on mount", async () => {
    mockFetchSdkMetrics.mockResolvedValue(metricsFixture());
    render(<SdkMetricsPanel projectId="p-1" />);
    await waitFor(() => expect(mockFetchSdkMetrics).toHaveBeenCalledWith("p-1"));
  });

  it("renders TOTAL REGISTERED, READY, FAILED canonical KPI cells", async () => {
    mockFetchSdkMetrics.mockResolvedValue(
      metricsFixture({ totalRegistered: 5, readyCount: 3, failedCount: 2 }),
    );
    render(<SdkMetricsPanel projectId="p-1" />);
    await waitFor(() => expect(screen.getByText("TOTAL REGISTERED")).toBeInTheDocument());
    expect(screen.getByText("READY")).toBeInTheDocument();
    expect(screen.getByText("FAILED")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("falls back to sdkCount when totalRegistered is missing", async () => {
    // Backend may temporarily emit only the compat alias.
    mockFetchSdkMetrics.mockResolvedValue({
      ...metricsFixture({ sdkCount: 7 }),
      totalRegistered: undefined as unknown as number,
    });
    render(<SdkMetricsPanel projectId="p-1" />);
    await waitFor(() => expect(screen.getByText("7")).toBeInTheDocument());
  });

  it("renders average phase duration cells when present", async () => {
    mockFetchSdkMetrics.mockResolvedValue(
      metricsFixture({
        totalRegistered: 4,
        readyCount: 4,
        averagePhaseDurationMs: { analyzing: 1234, verifying: 567 },
      }),
    );
    render(<SdkMetricsPanel projectId="p-1" />);
    await waitFor(() => expect(screen.getByText("ANALYZE")).toBeInTheDocument());
    expect(screen.getByText("VERIFY")).toBeInTheDocument();
    expect(screen.getByText("1,234 ms")).toBeInTheDocument();
    expect(screen.getByText("567 ms")).toBeInTheDocument();
  });

  it("renders 정보 없음 placeholder when fetch rejects", async () => {
    mockFetchSdkMetrics.mockRejectedValue(new Error("server error"));
    render(<SdkMetricsPanel projectId="p-1" />);
    await waitFor(() => expect(screen.getByText("정보 없음")).toBeInTheDocument());
  });

  it("renders zero counters as '0' (not '—') when payload is fully canonical", async () => {
    mockFetchSdkMetrics.mockResolvedValue(metricsFixture());
    render(<SdkMetricsPanel projectId="p-1" />);
    await waitFor(() => expect(screen.getByText("TOTAL REGISTERED")).toBeInTheDocument());
    // All three KPI cells render '0'.
    expect(screen.getAllByText("0")).toHaveLength(3);
  });
});
