import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { SdkProfilesPanel } from "./SdkProfilesPanel";

const mockFetchSdkProfiles = vi.fn();

vi.mock("@/common/api/sdk", () => ({
  fetchSdkProfiles: (...args: unknown[]) => mockFetchSdkProfiles(...args),
}));
vi.mock("@/common/api/core", () => ({ logError: vi.fn() }));

const profileFixture = (overrides: Partial<{ id: string; name: string; vendor: string; description: string }> = {}) => ({
  id: overrides.id ?? "sdk-a",
  name: overrides.name ?? "ARM Cortex-M4",
  vendor: overrides.vendor ?? "ARM",
  description: overrides.description ?? "Cortex-M4 reference SDK",
  defaults: {
    compiler: "arm-none-eabi-gcc",
    targetArch: "armv7e-m",
    languageStandard: "c11",
    headerLanguage: "c" as const,
  },
});

describe("SdkProfilesPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders profile names when profiles are present", async () => {
    mockFetchSdkProfiles.mockResolvedValue([
      profileFixture({ id: "sdk-a", name: "ARM Cortex-M4" }),
      profileFixture({ id: "sdk-b", name: "RISC-V RV32", vendor: "SiFive" }),
    ]);
    render(<SdkProfilesPanel />);
    await waitFor(() => expect(screen.getByText("ARM Cortex-M4")).toBeInTheDocument());
    expect(screen.getByText("RISC-V RV32")).toBeInTheDocument();
  });

  it("renders vendor, description, id, and defaults chips", async () => {
    mockFetchSdkProfiles.mockResolvedValue([profileFixture()]);
    render(<SdkProfilesPanel />);
    await waitFor(() => expect(screen.getByText("ARM Cortex-M4")).toBeInTheDocument());
    expect(screen.getByText("ARM")).toBeInTheDocument();
    expect(screen.getByText("Cortex-M4 reference SDK")).toBeInTheDocument();
    expect(screen.getByText("sdk-a")).toBeInTheDocument();
    expect(screen.getByText("arm-none-eabi-gcc")).toBeInTheDocument();
    expect(screen.getByText("armv7e-m")).toBeInTheDocument();
    expect(screen.getByText("c11")).toBeInTheDocument();
    // Caps-mono labels
    expect(screen.getByText("COMPILER")).toBeInTheDocument();
    expect(screen.getByText("ARCH")).toBeInTheDocument();
    expect(screen.getByText("STD")).toBeInTheDocument();
    expect(screen.getByText("HEADER")).toBeInTheDocument();
  });

  it("renders empty state when profiles list is empty", async () => {
    mockFetchSdkProfiles.mockResolvedValue([]);
    render(<SdkProfilesPanel />);
    await waitFor(() =>
      expect(screen.getByText("표시할 프로파일이 없습니다")).toBeInTheDocument(),
    );
  });

  it("renders empty state when fetch rejects", async () => {
    mockFetchSdkProfiles.mockRejectedValue(new Error("network error"));
    render(<SdkProfilesPanel />);
    await waitFor(() =>
      expect(screen.getByText("표시할 프로파일이 없습니다")).toBeInTheDocument(),
    );
  });

  it("calls fetchSdkProfiles on mount", async () => {
    mockFetchSdkProfiles.mockResolvedValue([]);
    render(<SdkProfilesPanel />);
    await waitFor(() => expect(mockFetchSdkProfiles).toHaveBeenCalledTimes(1));
  });

  it("shows count badge matching number of profiles", async () => {
    mockFetchSdkProfiles.mockResolvedValue([
      profileFixture({ id: "p1", name: "Profile One" }),
      profileFixture({ id: "p2", name: "Profile Two" }),
      profileFixture({ id: "p3", name: "Profile Three" }),
    ]);
    render(<SdkProfilesPanel />);
    await waitFor(() => expect(screen.getByText("3")).toBeInTheDocument());
  });

  it("omits description block when description is empty", async () => {
    mockFetchSdkProfiles.mockResolvedValue([profileFixture({ description: "" })]);
    render(<SdkProfilesPanel />);
    await waitFor(() => expect(screen.getByText("ARM Cortex-M4")).toBeInTheDocument());
    expect(screen.queryByText("Cortex-M4 reference SDK")).not.toBeInTheDocument();
  });
});
