import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useAnalysisHistoryPageController } from "./useAnalysisHistoryPageController";

const mockFetchProjectRuns = vi.fn();
const mockDeleteAnalysisResult = vi.fn();
const mockLogError = vi.fn();

vi.mock("@/common/api/client", () => ({
  fetchProjectRuns: (...args: unknown[]) => mockFetchProjectRuns(...args),
  logError: (...args: unknown[]) => mockLogError(...args),
}));

vi.mock("@/common/api/analysis", () => ({
  deleteAnalysisResult: (...args: unknown[]) => mockDeleteAnalysisResult(...args),
}));

const toast = { error: vi.fn(), success: vi.fn() };

describe("useAnalysisHistoryPageController", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchProjectRuns.mockResolvedValue([]);
  });

  it("requestDelete sets confirmDeleteId to that id", async () => {
    const { result } = renderHook(() =>
      useAnalysisHistoryPageController("proj-1", toast),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      result.current.requestDelete("result-abc");
    });

    expect(result.current.confirmDeleteId).toBe("result-abc");
  });

  it("cancelDelete clears confirmDeleteId to null", async () => {
    const { result } = renderHook(() =>
      useAnalysisHistoryPageController("proj-1", toast),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      result.current.requestDelete("result-abc");
    });
    act(() => {
      result.current.cancelDelete();
    });

    expect(result.current.confirmDeleteId).toBeNull();
  });

  it("confirmDelete with null id is a no-op (no API call)", async () => {
    const { result } = renderHook(() =>
      useAnalysisHistoryPageController("proj-1", toast),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.confirmDelete();
    });

    expect(mockDeleteAnalysisResult).not.toHaveBeenCalled();
  });

  it("deleting flips true during await then false in finally", async () => {
    let resolveDelete!: () => void;
    mockDeleteAnalysisResult.mockReturnValue(
      new Promise<void>((resolve) => {
        resolveDelete = resolve;
      }),
    );

    const { result } = renderHook(() =>
      useAnalysisHistoryPageController("proj-1", toast),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      result.current.requestDelete("result-xyz");
    });

    let confirmPromise!: Promise<void>;
    act(() => {
      confirmPromise = result.current.confirmDelete();
    });

    await waitFor(() => expect(result.current.deleting).toBe(true));

    await act(async () => {
      resolveDelete();
      await confirmPromise;
    });

    expect(result.current.deleting).toBe(false);
  });

  it("confirmDelete clears confirmDeleteId in finally even on API error", async () => {
    mockDeleteAnalysisResult.mockRejectedValue(new Error("server error"));

    const { result } = renderHook(() =>
      useAnalysisHistoryPageController("proj-1", toast),
    );
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      result.current.requestDelete("result-err");
    });

    await act(async () => {
      await result.current.confirmDelete();
    });

    expect(result.current.confirmDeleteId).toBeNull();
    expect(result.current.deleting).toBe(false);
  });
});
