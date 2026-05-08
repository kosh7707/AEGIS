import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchProjectGates,
  fetchGateProfile,
  fetchGateRunResults,
  overrideGate,
} from "./gate";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
});

describe("fetchProjectGates", () => {
  it("GETs /api/projects/:pid/gates and returns gate results", async () => {
    const gates = [{ id: "g1", status: "passed" }];
    mockApiFetch.mockResolvedValue({ success: true, data: gates });

    const result = await fetchProjectGates("proj-1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/gates");
    expect(result).toEqual(gates);
  });
});

describe("fetchGateProfile", () => {
  it("GETs /api/gate-profiles/:id and returns profile", async () => {
    const profile = { id: "gp1", name: "Default Gate" };
    mockApiFetch.mockResolvedValue({ success: true, data: profile });

    const result = await fetchGateProfile("gp1");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/gate-profiles/gp1");
    expect(result).toEqual(profile);
  });
});

describe("fetchGateRunResults", () => {
  it("GETs /api/projects/:pid/gates/runs/:runId and returns gate results", async () => {
    const gates = [{ id: "g2", status: "failed", runId: "run-42" }];
    mockApiFetch.mockResolvedValue({ success: true, data: gates });

    const result = await fetchGateRunResults("proj-1", "run-42");

    expect(mockApiFetch).toHaveBeenCalledWith("/api/projects/proj-1/gates/runs/run-42");
    expect(result).toEqual(gates);
  });

  it("returns empty array when run has no gate results", async () => {
    mockApiFetch.mockResolvedValue({ success: true, data: [] });

    const result = await fetchGateRunResults("proj-2", "run-99");

    expect(result).toEqual([]);
  });
});

describe("overrideGate", () => {
  it("POSTs to /api/gates/:id/override with reason and actor", async () => {
    mockApiFetch.mockResolvedValue({ success: true });

    await overrideGate("g1", "emergency override", "user-1");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/gates/g1/override",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ reason: "emergency override", actor: "user-1" }),
      }),
    );
  });
});
