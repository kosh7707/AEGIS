import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchRegistrationRequest } from "./auth";

vi.mock("./core", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "./core";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

describe("fetchRegistrationRequest", () => {
  it("GETs /api/auth/registration-requests/:id and returns RegistrationRequest", async () => {
    const request = {
      id: "reg-001",
      organizationId: "org-1",
      organizationCode: "ACME-KR",
      organizationName: "ACME Corp",
      fullName: "홍길동",
      email: "test@acme.kr",
      status: "pending_admin_review",
      lookupExpiresAt: "2026-06-01T00:00:00.000Z",
      createdAt: "2026-05-01T00:00:00.000Z",
    };
    mockApiFetch.mockResolvedValue({ success: true, data: request });

    const result = await fetchRegistrationRequest("reg-001");

    expect(mockApiFetch).toHaveBeenCalledWith(
      "/api/auth/registration-requests/reg-001",
      expect.objectContaining({ method: "GET" }),
    );
    expect(result).toEqual(request);
  });

  it("encodes the id in the URL path", async () => {
    const request = {
      id: "reg/special",
      organizationId: "org-1",
      organizationCode: "ACME",
      organizationName: "ACME",
      fullName: "test",
      email: "t@t.com",
      status: "pending_admin_review",
      lookupExpiresAt: "2026-06-01T00:00:00.000Z",
      createdAt: "2026-05-01T00:00:00.000Z",
    };
    mockApiFetch.mockResolvedValue({ success: true, data: request });

    await fetchRegistrationRequest("reg/special");

    expect(mockApiFetch).toHaveBeenCalledWith(
      expect.stringContaining("reg%2Fspecial"),
      expect.any(Object),
    );
  });

  it("throws when data is missing in response", async () => {
    mockApiFetch.mockResolvedValue({ success: false, data: undefined });

    await expect(fetchRegistrationRequest("reg-missing")).rejects.toThrow(
      "가입 요청을 찾을 수 없습니다.",
    );
  });
});
