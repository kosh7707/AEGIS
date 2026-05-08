import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchSdkProfiles,
  fetchSdkProfile,
  fetchSdkMetrics,
} from "./sdk";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
  getBaseUrl: vi.fn(() => "http://localhost:3000"),
  getWsBaseUrl: vi.fn(() => "ws://localhost:3000"),
}));

import { apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("fetchSdkProfiles", () => {
  it("GETs /api/sdk-profiles and returns typed SdkProfile[]", async () => {
    const profiles = [
      {
        id: "p1",
        name: "TI SDK",
        vendor: "TI",
        description: "TI catalog profile",
        defaults: {
          compiler: "gcc",
          targetArch: "arm",
          languageStandard: "c11",
          headerLanguage: "c" as const,
        },
      },
    ];
    mockApiFetch.mockResolvedValue({ success: true, data: profiles });

    const result = await fetchSdkProfiles();

    expect(mockApiFetch).toHaveBeenCalledWith("/api/sdk-profiles");
    expect(result).toEqual(profiles);
    // Typed surface — direct property access without narrowing.
    expect(result[0].id).toBe("p1");
    expect(result[0].defaults.compiler).toBe("gcc");
  });
});

describe("fetchSdkProfile", () => {
  it("GETs /api/sdk-profiles/:id and returns single typed SdkProfile", async () => {
    const profile = {
      id: "p1",
      name: "TI SDK",
      vendor: "TI",
      description: "",
      defaults: {
        compiler: "gcc",
        targetArch: "arm",
        languageStandard: "c11",
        headerLanguage: "c" as const,
      },
    };
    mockApiFetch.mockResolvedValue({ success: true, data: profile });

    const result = await fetchSdkProfile("p1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/sdk-profiles/p1");
    expect(result).toEqual(profile);
    expect(result.name).toBe("TI SDK");
  });

  it("throws when envelope omits data", async () => {
    mockApiFetch.mockResolvedValue({ success: false, error: "not found" });

    await expect(fetchSdkProfile("missing")).rejects.toThrow("not found");
  });
});

describe("fetchSdkMetrics", () => {
  it("GETs /api/projects/:pid/sdk/metrics and returns typed SdkMetrics", async () => {
    const metrics = {
      totalRegistered: 3,
      sdkCount: 3,
      readyCount: 2,
      failedCount: 1,
      averagePhaseDurationMs: { analyzing: 120, verifying: 80 },
    };
    mockApiFetch.mockResolvedValue({ success: true, data: metrics });

    const result = await fetchSdkMetrics("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/sdk/metrics");
    expect(result).toEqual(metrics);
    expect(result.totalRegistered).toBe(3);
    expect(result.averagePhaseDurationMs.analyzing).toBe(120);
  });

  it("returns metrics with zero counters and empty phase map", async () => {
    const metrics = {
      totalRegistered: 0,
      sdkCount: 0,
      readyCount: 0,
      failedCount: 0,
      averagePhaseDurationMs: {},
    };
    mockApiFetch.mockResolvedValue({ success: true, data: metrics });

    const result = await fetchSdkMetrics("proj-2");

    expect(result.totalRegistered).toBe(0);
    expect(result.averagePhaseDurationMs).toEqual({});
  });
});
