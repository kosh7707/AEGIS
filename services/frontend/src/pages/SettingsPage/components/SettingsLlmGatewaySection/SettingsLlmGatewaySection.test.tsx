import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SettingsLlmGatewaySection } from "./SettingsLlmGatewaySection";

describe("SettingsLlmGatewaySection", () => {
  it("renders Idle dot when no health data yet", () => {
    const { container } = render(<SettingsLlmGatewaySection />);
    expect(screen.getByText("LLM Gateway")).toBeTruthy();
    expect(screen.getByText("Idle")).toBeTruthy();
    expect(container.querySelector(".settings-kv__dot--idle")).not.toBeNull();
    expect(screen.queryByTestId("settings-llm-gateway-sub")).toBeNull();
  });

  it("renders OK row without sub-caption when llmGateway is healthy", () => {
    render(
      <SettingsLlmGatewaySection
        llmGateway={{
          status: "ok",
          detail: { degraded: false, llmReady: true, blockedReason: null },
        }}
      />,
    );
    expect(screen.getByText("OK")).toBeTruthy();
    expect(screen.queryByTestId("settings-llm-gateway-sub")).toBeNull();
  });

  it("renders Degraded with mapped Korean copy when degraded=true && blockedReason=backend_unreachable", () => {
    render(
      <SettingsLlmGatewaySection
        llmGateway={{
          status: "degraded",
          detail: {
            degraded: true,
            llmReady: false,
            blockedReason: "backend_unreachable",
          },
        }}
      />,
    );
    expect(screen.getByText("Degraded")).toBeTruthy();
    const sub = screen.getByTestId("settings-llm-gateway-sub");
    expect(sub.textContent).toBe("LLM 백엔드 연결 불가");
  });

  it("renders mapped copy for circuit_open", () => {
    render(
      <SettingsLlmGatewaySection
        llmGateway={{
          status: "degraded",
          detail: { degraded: true, llmReady: true, blockedReason: "circuit_open" },
        }}
      />,
    );
    expect(screen.getByTestId("settings-llm-gateway-sub").textContent).toBe("LLM 회로 차단");
  });

  it("renders mapped copy for circuit_half_open", () => {
    render(
      <SettingsLlmGatewaySection
        llmGateway={{
          status: "degraded",
          detail: { degraded: false, llmReady: false, blockedReason: "circuit_half_open" },
        }}
      />,
    );
    expect(screen.getByTestId("settings-llm-gateway-sub").textContent).toBe("LLM 복구 탐침 중");
  });

  it("renders fallback sub-caption when degraded but blockedReason is null", () => {
    render(
      <SettingsLlmGatewaySection
        llmGateway={{
          status: "degraded",
          detail: { degraded: true, llmReady: false, blockedReason: null },
        }}
      />,
    );
    expect(screen.getByTestId("settings-llm-gateway-sub").textContent).toBe(
      "LLM 일부 준비 안 됨",
    );
  });

  it("renders Unreachable row when S2 cannot reach S7", () => {
    const { container } = render(
      <SettingsLlmGatewaySection llmGateway={{ status: "unreachable" }} />,
    );
    expect(screen.getByText("Unreachable")).toBeTruthy();
    expect(container.querySelector(".settings-kv__dot--error")).not.toBeNull();
    // No sub-caption when detail is missing
    expect(screen.queryByTestId("settings-llm-gateway-sub")).toBeNull();
  });

  it("treats llmReady=false alone as degraded sub-caption", () => {
    // detail.degraded omitted, only llmReady=false — readiness gate per WR
    render(
      <SettingsLlmGatewaySection
        llmGateway={{
          status: "ok",
          detail: { llmReady: false, blockedReason: "backend_unreachable" },
        }}
      />,
    );
    expect(screen.getByTestId("settings-llm-gateway-sub").textContent).toBe(
      "LLM 백엔드 연결 불가",
    );
  });
});
