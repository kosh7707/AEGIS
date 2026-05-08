import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
  ApiError: class ApiError extends Error {
    constructor(message: string) { super(message); }
  },
  getBaseUrl: vi.fn(() => "http://localhost:3000"),
}));

import { apiFetch } from "./core";
import {
  fetchSourceFiles,
  fetchSourceFilesWithComposition,
  fetchUploadStatus,
  deleteSource,
} from "./source";
import type { UploadStatusSnapshot } from "./source";

const mockApiFetch = vi.mocked(apiFetch);

beforeEach(() => {
  vi.clearAllMocks();
});

// ── fetchSourceFiles ──

describe("fetchSourceFiles", () => {
  it("calls /source/files without query param when filter omitted", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: [] });

    await fetchSourceFiles("p-1");

    const [url] = mockApiFetch.mock.calls[0] as [string, ...unknown[]];
    expect(url).toBe("/api/projects/p-1/source/files");
  });

  it("forwards ?filter=source query string when filter is 'source'", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: [] });

    await fetchSourceFiles("p-1", "source");

    const [url] = mockApiFetch.mock.calls[0] as [string, ...unknown[]];
    expect(url).toBe("/api/projects/p-1/source/files?filter=source");
  });
});

// ── fetchSourceFilesWithComposition ──

describe("fetchSourceFilesWithComposition", () => {
  it("calls /source/files without query param when filter omitted", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: [] });

    await fetchSourceFilesWithComposition("p-1");

    const [url] = mockApiFetch.mock.calls[0] as [string, ...unknown[]];
    expect(url).toBe("/api/projects/p-1/source/files");
  });

  it("forwards ?filter=source query string when filter is 'source'", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: [] });

    await fetchSourceFilesWithComposition("p-1", "source");

    const [url] = mockApiFetch.mock.calls[0] as [string, ...unknown[]];
    expect(url).toBe("/api/projects/p-1/source/files?filter=source");
  });
});

// ── UploadStatusSnapshot shape ──

describe("fetchUploadStatus", () => {
  it("returns snapshot with message, error, projectPath fields", async () => {
    const snapshot: UploadStatusSnapshot = {
      phase: "indexing",
      message: "인덱싱 중...",
      fileCount: 42,
      projectPath: "/uploads/p-1/src",
      error: undefined,
    };
    mockApiFetch.mockResolvedValue({ success: true, data: snapshot });

    const result = await fetchUploadStatus("p-1", "upload-abc");

    const [url] = mockApiFetch.mock.calls[0] as [string, ...unknown[]];
    expect(url).toBe("/api/projects/p-1/source/upload-status/upload-abc");
    expect(result.phase).toBe("indexing");
    expect(result.message).toBe("인덱싱 중...");
    expect(result.fileCount).toBe(42);
    expect(result.projectPath).toBe("/uploads/p-1/src");
    expect(result.error).toBeUndefined();
  });

  it("returns snapshot with error field when backend reports failure", async () => {
    const snapshot: UploadStatusSnapshot = {
      phase: "failed",
      error: "Unsupported archive format",
    };
    mockApiFetch.mockResolvedValue({ success: true, data: snapshot });

    const result = await fetchUploadStatus("p-1", "upload-err");

    expect(result.error).toBe("Unsupported archive format");
    expect(result.message).toBeUndefined();
    expect(result.projectPath).toBeUndefined();
  });
});

// ── deleteSource ──

describe("deleteSource", () => {
  it("sends DELETE to /api/projects/:pid/source", async () => {
    mockApiFetch.mockResolvedValue(undefined);

    await deleteSource("p-1");

    const [url, opts] = mockApiFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/projects/p-1/source");
    expect(opts.method).toBe("DELETE");
  });

  it("returns void on success", async () => {
    mockApiFetch.mockResolvedValue(undefined);

    const result = await deleteSource("p-1");

    expect(result).toBeUndefined();
  });
});
