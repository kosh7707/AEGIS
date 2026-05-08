import type {
  User,
  UserRole,
  LoginResponse,
  OrganizationVerifyPreview,
  OrganizationVerifyResponse,
  RegisterRequest,
  RegisterResponse,
  RegistrationLookupResponse,
  RegistrationRequest,
  RegistrationRequestListResponse,
} from "@aegis/shared";
import { apiFetch } from "./core";

const TOKEN_KEY = "aegis:authToken";
const MOCK_USER_KEY = "aegis:mockUser";
const SESSION_EXPIRES_KEY = "aegis:sessionExpiresAt";

export type LoginResult = { token: string; expiresAt: string; user: User };

export function getAuthToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setAuthToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

function readMockUser(): User | null {
  const raw = localStorage.getItem(MOCK_USER_KEY);
  if (!raw) return null;

  try {
    return JSON.parse(raw) as User;
  } catch {
    localStorage.removeItem(MOCK_USER_KEY);
    return null;
  }
}

function writeMockUser(user: User): void {
  localStorage.setItem(MOCK_USER_KEY, JSON.stringify(user));
}

function clearMockUser(): void {
  localStorage.removeItem(MOCK_USER_KEY);
}

function buildMockUser(username: string): User {
  const now = new Date().toISOString();
  const normalized = username.trim() || "operator";
  const displayName = normalized.includes("@") ? normalized.split("@")[0] : normalized;
  return {
    id: `mock-${displayName.toLowerCase().replace(/[^a-z0-9]+/gi, "-")}`,
    username: normalized,
    displayName,
    role: "admin",
    createdAt: now,
    updatedAt: now,
  };
}

function isMockAuthEnabled(): boolean {
  return import.meta.env.VITE_MOCK === "true";
}

function createMockToken(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `mock-token:${crypto.randomUUID()}`;
  }
  return `mock-token:${Date.now().toString(36)}`;
}

function computeMockExpiresAt(rememberMe: boolean): string {
  const ttlMs = rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
  return new Date(Date.now() + ttlMs).toISOString();
}

function writeSessionExpiresAt(expiresAt: string): void {
  localStorage.setItem(SESSION_EXPIRES_KEY, expiresAt);
}

function clearSessionExpiresAt(): void {
  localStorage.removeItem(SESSION_EXPIRES_KEY);
}

export function getSessionExpiresAt(): string | null {
  return localStorage.getItem(SESSION_EXPIRES_KEY);
}

export async function login(
  username: string,
  password: string,
  rememberMe: boolean = false,
): Promise<LoginResult> {
  if (isMockAuthEnabled()) {
    const user = buildMockUser(username);
    const token = createMockToken();
    const expiresAt = computeMockExpiresAt(rememberMe);
    setAuthToken(token);
    writeMockUser(user);
    writeSessionExpiresAt(expiresAt);
    return { token, expiresAt, user };
  }

  const res = await apiFetch<LoginResponse>("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, rememberMe }),
  });
  const data = res.data!;
  setAuthToken(data.token);
  writeSessionExpiresAt(data.expiresAt);
  return data;
}

export async function logout(): Promise<void> {
  if (isMockAuthEnabled()) {
    clearAuthToken();
    clearMockUser();
    clearSessionExpiresAt();
    return;
  }

  try {
    await apiFetch("/api/auth/logout", { method: "POST" });
  } finally {
    clearAuthToken();
    clearSessionExpiresAt();
  }
}

export async function fetchCurrentUser(): Promise<User> {
  if (isMockAuthEnabled()) {
    const user = readMockUser();
    if (!user) {
      clearAuthToken();
      throw new Error("로그인된 사용자가 없습니다.");
    }
    return user;
  }

  const res = await apiFetch<{ success: boolean; data: User }>("/api/auth/me");
  return res.data;
}

export async function fetchUsers(): Promise<User[]> {
  if (isMockAuthEnabled()) {
    const user = readMockUser();
    return user ? [user] : [];
  }

  const res = await apiFetch<{ success: boolean; data: User[] }>("/api/auth/users");
  return res.data;
}

export async function requestPasswordReset(email: string): Promise<void> {
  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 400));
    return;
  }

  await apiFetch("/api/auth/password-reset/request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
}

export async function confirmPasswordReset(token: string, newPassword: string): Promise<void> {
  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 400));
    return;
  }

  await apiFetch<{ success: boolean }>("/api/auth/password-reset/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, newPassword }),
  });
}

export async function verifyOrgCode(code: string): Promise<OrganizationVerifyPreview> {
  const trimmed = code.trim();
  if (!trimmed) {
    throw new Error("조직 코드를 입력해 주세요.");
  }

  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 350));
    return {
      orgId: `mock-org-${trimmed.toLowerCase().replace(/[^a-z0-9]+/gi, "-")}`,
      code: trimmed,
      name: "ACME Corp · Security Team",
      admin: { displayName: "ACME Security Admin", email: "admin@acme.kr" },
      region: "kr-seoul-1",
      defaultRole: "analyst",
      emailDomainHint: "acme.kr",
    };
  }

  const res = await apiFetch<OrganizationVerifyResponse>(
    `/api/auth/orgs/${encodeURIComponent(trimmed)}/verify`,
    { method: "GET" },
  );
  if (!res.data) {
    throw new Error(res.error ?? "조직 코드를 확인할 수 없습니다.");
  }
  return res.data;
}

export async function register(body: RegisterRequest): Promise<NonNullable<RegisterResponse["data"]>> {
  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 400));
    const now = new Date();
    const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    return {
      registrationId: `mock-reg-${now.getTime().toString(36)}`,
      lookupToken: `mock-lookup-${now.getTime().toString(36)}`,
      lookupExpiresAt: expires.toISOString(),
      status: "pending_admin_review",
      createdAt: now.toISOString(),
    };
  }

  const res = await apiFetch<RegisterResponse>("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.data) {
    throw new Error(res.error ?? "가입 요청을 제출할 수 없습니다.");
  }
  return res.data;
}

export async function lookupRegistration(lookupToken: string): Promise<RegistrationRequest> {
  const trimmed = lookupToken.trim();
  if (!trimmed) {
    throw new Error("조회 토큰이 없습니다.");
  }

  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 300));
    const now = new Date();
    return {
      id: `mock-reg-${trimmed}`,
      organizationId: "mock-org-demo",
      organizationCode: "AEGIS-DEMO",
      organizationName: "AEGIS Demo Org",
      fullName: "(미정)",
      email: "(미정)",
      status: "pending_admin_review",
      lookupExpiresAt: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      createdAt: now.toISOString(),
    };
  }

  const res = await apiFetch<RegistrationLookupResponse>(
    `/api/auth/registrations/lookup/${encodeURIComponent(trimmed)}`,
    { method: "GET" },
  );
  if (!res.data) {
    throw new Error(res.error ?? "가입 요청을 찾을 수 없습니다.");
  }
  return res.data;
}

export async function fetchRegistrationRequest(id: string): Promise<RegistrationRequest> {
  const res = await apiFetch<{ success: boolean; data: RegistrationRequest }>(
    `/api/auth/registration-requests/${encodeURIComponent(id)}`,
    { method: "GET" },
  );
  if (!res.data) {
    throw new Error("가입 요청을 찾을 수 없습니다.");
  }
  return res.data;
}

export async function listRegistrationRequests(): Promise<RegistrationRequest[]> {
  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 200));
    const now = new Date().toISOString();
    return [
      {
        id: "mock-reg-0001",
        organizationId: "org-acme-kr-sec",
        organizationCode: "ACME-KR-SEC",
        organizationName: "ACME Corp · Security Team",
        fullName: "홍길동",
        email: "qa-member@acme.kr",
        status: "pending_admin_review",
        lookupExpiresAt: now,
        createdAt: now,
      },
    ];
  }

  const res = await apiFetch<RegistrationRequestListResponse>(
    "/api/auth/registration-requests",
    { method: "GET" },
  );
  return res.data ?? [];
}

export async function approveRegistrationRequest(
  id: string,
  role: UserRole,
): Promise<RegistrationRequest> {
  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 300));
    return {
      id,
      organizationId: "org-acme-kr-sec",
      organizationCode: "ACME-KR-SEC",
      organizationName: "ACME Corp · Security Team",
      fullName: "(mock)",
      email: "qa-member@acme.kr",
      status: "approved",
      assignedRole: role,
      lookupExpiresAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      approvedAt: new Date().toISOString(),
    };
  }

  const res = await apiFetch<{ success: boolean; data?: RegistrationRequest; error?: string }>(
    `/api/auth/registration-requests/${encodeURIComponent(id)}/approve`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    },
  );
  if (!res.data) {
    throw new Error(res.error ?? "가입 요청을 승인하지 못했습니다.");
  }
  return res.data;
}

export async function rejectRegistrationRequest(
  id: string,
  reason: string,
): Promise<RegistrationRequest> {
  if (isMockAuthEnabled()) {
    await new Promise((resolve) => window.setTimeout(resolve, 300));
    return {
      id,
      organizationId: "org-acme-kr-sec",
      organizationCode: "ACME-KR-SEC",
      organizationName: "ACME Corp · Security Team",
      fullName: "(mock)",
      email: "qa-member@acme.kr",
      status: "rejected",
      decisionReason: reason,
      lookupExpiresAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      rejectedAt: new Date().toISOString(),
    };
  }

  const res = await apiFetch<{ success: boolean; data?: RegistrationRequest; error?: string }>(
    `/api/auth/registration-requests/${encodeURIComponent(id)}/reject`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    },
  );
  if (!res.data) {
    throw new Error(res.error ?? "가입 요청을 반려하지 못했습니다.");
  }
  return res.data;
}
