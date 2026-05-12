import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ConnectionStatusBanner, describeLlmBlockedReason } from "./ConnectionStatusBanner";

describe("ConnectionStatusBanner", () => {
  it("renders nothing when connected", () => {
    const { container } = render(<ConnectionStatusBanner connectionState="connected" />);
    expect(container.innerHTML).toBe("");
  });

  it("renders nothing when disconnected (initial state)", () => {
    const { container } = render(<ConnectionStatusBanner connectionState="disconnected" />);
    expect(container.innerHTML).toBe("");
  });

  it("renders reconnecting banner with retry count", () => {
    render(<ConnectionStatusBanner connectionState="reconnecting" retryCount={3} />);
    expect(screen.getByRole("status")).toBeTruthy();
    expect(screen.getByText(/재연결 중/)).toBeTruthy();
    expect(screen.getByText(/시도 3/)).toBeTruthy();
  });

  it("renders reconnecting banner without retry count", () => {
    render(<ConnectionStatusBanner connectionState="reconnecting" />);
    expect(screen.getByText(/재연결 중/)).toBeTruthy();
    expect(screen.queryByText(/시도/)).toBeNull();
  });

  it("renders failed banner with refresh button", () => {
    render(<ConnectionStatusBanner connectionState="failed" />);
    expect(screen.getByText(/연결 실패/)).toBeTruthy();
    expect(screen.getByRole("button", { name: /새로고침/ })).toBeTruthy();
  });

  describe("LLM readiness ramp (S2 /health llmGateway.detail forwarding)", () => {
    it("renders caution-review banner when degraded=true && llmReady=false with blockedReason copy", () => {
      const { container } = render(
        <ConnectionStatusBanner
          connectionState="connected"
          llmGatewayDetail={{
            degraded: true,
            llmReady: false,
            blockedReason: "backend_unreachable",
          }}
        />,
      );
      const banner = screen.getByRole("status");
      expect(banner.className).toContain("is-llm-degraded");
      expect(banner.className).not.toContain("is-failed");
      expect(screen.getByText("LLM 일부 준비 안 됨")).toBeTruthy();
      expect(screen.getByText("LLM 백엔드 연결 불가")).toBeTruthy();
      // No refresh button on review-tone banner
      expect(container.querySelector("button")).toBeNull();
    });

    it("renders caution banner when degraded=true with circuit_open mapped to Korean copy", () => {
      render(
        <ConnectionStatusBanner
          connectionState="connected"
          llmGatewayDetail={{
            degraded: true,
            llmReady: true,
            blockedReason: "circuit_open",
          }}
        />,
      );
      expect(screen.getByText("LLM 회로 차단")).toBeTruthy();
    });

    it("renders caution banner when llmReady=false alone (degraded omitted) with circuit_half_open copy", () => {
      render(
        <ConnectionStatusBanner
          connectionState="connected"
          llmGatewayDetail={{
            llmReady: false,
            blockedReason: "circuit_half_open",
          }}
        />,
      );
      expect(screen.getByText("LLM 복구 탐침 중")).toBeTruthy();
    });

    it("falls back to generic copy when blockedReason is null", () => {
      render(
        <ConnectionStatusBanner
          connectionState="connected"
          llmGatewayDetail={{
            degraded: true,
            llmReady: false,
            blockedReason: null,
          }}
        />,
      );
      expect(screen.getByText("일부 기능이 제한될 수 있습니다")).toBeTruthy();
    });

    it("renders nothing when degraded=false && llmReady=true", () => {
      const { container } = render(
        <ConnectionStatusBanner
          connectionState="connected"
          llmGatewayDetail={{
            degraded: false,
            llmReady: true,
            blockedReason: null,
          }}
        />,
      );
      expect(container.innerHTML).toBe("");
    });

    it("preserves existing critical-review failed banner regardless of LLM detail", () => {
      render(
        <ConnectionStatusBanner
          connectionState="failed"
          llmGatewayDetail={{
            degraded: true,
            llmReady: false,
            blockedReason: "backend_unreachable",
          }}
        />,
      );
      const banner = screen.getByRole("status");
      expect(banner.className).toContain("is-failed");
      expect(banner.className).not.toContain("is-llm-degraded");
      expect(screen.getByText(/연결 실패/)).toBeTruthy();
      expect(screen.getByRole("button", { name: /새로고침/ })).toBeTruthy();
      // LLM caution copy must NOT appear when connection is failed
      expect(screen.queryByText("LLM 일부 준비 안 됨")).toBeNull();
    });

    it("preserves reconnecting banner regardless of LLM detail", () => {
      render(
        <ConnectionStatusBanner
          connectionState="reconnecting"
          retryCount={2}
          llmGatewayDetail={{ degraded: true, llmReady: false, blockedReason: "circuit_open" }}
        />,
      );
      const banner = screen.getByRole("status");
      expect(banner.className).toContain("is-reconnecting");
      expect(banner.className).not.toContain("is-llm-degraded");
      expect(screen.getByText(/재연결 중/)).toBeTruthy();
      expect(screen.queryByText("LLM 회로 차단")).toBeNull();
    });
  });

  describe("describeLlmBlockedReason", () => {
    it("maps known codes to Korean copy", () => {
      expect(describeLlmBlockedReason("backend_unreachable")).toBe("LLM 백엔드 연결 불가");
      expect(describeLlmBlockedReason("circuit_open")).toBe("LLM 회로 차단");
      expect(describeLlmBlockedReason("circuit_half_open")).toBe("LLM 복구 탐침 중");
    });

    it("returns null for null / undefined / unknown codes", () => {
      expect(describeLlmBlockedReason(null)).toBeNull();
      expect(describeLlmBlockedReason(undefined)).toBeNull();
      expect(describeLlmBlockedReason("")).toBeNull();
      expect(describeLlmBlockedReason("something_else")).toBeNull();
    });
  });
});
