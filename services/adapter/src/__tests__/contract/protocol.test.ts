import { describe, it, expect } from "vitest";
import type {
  CanFrame,
  EcuResponse,
  EcuToAdapterMessage,
  AdapterToEcuMessage,
  AdapterToBackendMessage,
  BackendToAdapterMessage,
} from "../../protocol";

/**
 * Protocol contract tests — verifies TypeScript type definitions
 * match the documented API contract in docs/contracts/adapter.md.
 *
 * Each test creates a well-typed sample object and checks runtime shape.
 * If a field is removed or renamed in protocol.ts, these tests will fail.
 */

const sampleFrame: CanFrame = {
  timestamp: "2026-03-18T14:23:45.123Z",
  id: "0x100",
  dlc: 8,
  data: "DE AD BE EF 01 02 03 04",
};

describe("Protocol Contract — adapter-api.md compliance", () => {
  describe("CanFrame", () => {
    it("has required fields: timestamp, id, dlc, data", () => {
      expect(sampleFrame).toHaveProperty("timestamp");
      expect(sampleFrame).toHaveProperty("id");
      expect(sampleFrame).toHaveProperty("dlc");
      expect(sampleFrame).toHaveProperty("data");
      expect(typeof sampleFrame.timestamp).toBe("string");
      expect(typeof sampleFrame.id).toBe("string");
      expect(typeof sampleFrame.dlc).toBe("number");
      expect(typeof sampleFrame.data).toBe("string");
    });
  });

  describe("EcuResponse", () => {
    it("has required field: success (boolean)", () => {
      const resp: EcuResponse = { success: true };
      expect(typeof resp.success).toBe("boolean");
    });

    it("accepts all documented error values", () => {
      const errors: EcuResponse["error"][] = [
        "no_response",
        "malformed",
        "reset",
        "delayed",
        undefined,
      ];
      errors.forEach((err) => {
        const resp: EcuResponse = { success: false, error: err };
        expect(resp).toBeDefined();
      });
    });

    it("accepts optional data and delayMs fields", () => {
      const resp: EcuResponse = {
        success: true,
        data: "DE AD BE EF 01 02 03 04",
        delayMs: 25,
      };
      expect(typeof resp.data).toBe("string");
      expect(typeof resp.delayMs).toBe("number");
    });
  });

  describe("EcuToAdapterMessage", () => {
    it("can-frame variant has type and frame", () => {
      const msg: EcuToAdapterMessage = { type: "can-frame", frame: sampleFrame };
      expect(msg.type).toBe("can-frame");
      expect(msg).toHaveProperty("frame");
    });

    it("inject-response variant has type, requestId, and response", () => {
      const msg: EcuToAdapterMessage = {
        type: "inject-response",
        requestId: "req-123",
        response: { success: true },
      };
      expect(msg.type).toBe("inject-response");
      expect(msg).toHaveProperty("requestId");
      expect(msg).toHaveProperty("response");
    });

    it("ecu-info variant has type and ecu with name and canIds", () => {
      const msg: EcuToAdapterMessage = {
        type: "ecu-info",
        ecu: { name: "ECU_SIM", canIds: ["0x100", "0x200"] },
      };
      expect(msg.type).toBe("ecu-info");
      expect(msg).toHaveProperty("ecu");
      expect(typeof (msg as any).ecu.name).toBe("string");
      expect(Array.isArray((msg as any).ecu.canIds)).toBe(true);
    });
  });

  describe("AdapterToEcuMessage", () => {
    it("inject-request variant has type, requestId, and frame", () => {
      const msg: AdapterToEcuMessage = {
        type: "inject-request",
        requestId: "req-123",
        frame: sampleFrame,
      };
      expect(msg.type).toBe("inject-request");
      expect(msg).toHaveProperty("requestId");
      expect(msg).toHaveProperty("frame");
    });
  });

  describe("AdapterToBackendMessage", () => {
    it("supports all 4 message types", () => {
      const messages: AdapterToBackendMessage[] = [
        { type: "can-frame", frame: sampleFrame },
        { type: "inject-response", requestId: "req-1", response: { success: true } },
        { type: "ecu-status", status: "connected" },
        { type: "ecu-info", ecu: { name: "ECU_SIM", canIds: ["0x100"] } },
      ];
      const types = messages.map((m) => m.type);
      expect(types).toContain("can-frame");
      expect(types).toContain("inject-response");
      expect(types).toContain("ecu-status");
      expect(types).toContain("ecu-info");
    });

    it("ecu-status accepts connected and disconnected", () => {
      const c: AdapterToBackendMessage = { type: "ecu-status", status: "connected" };
      const d: AdapterToBackendMessage = { type: "ecu-status", status: "disconnected" };
      expect((c as any).status).toBe("connected");
      expect((d as any).status).toBe("disconnected");
    });
  });

  describe("BackendToAdapterMessage", () => {
    it("inject-request has type, requestId, and frame", () => {
      const msg: BackendToAdapterMessage = {
        type: "inject-request",
        requestId: "req-abc123",
        frame: sampleFrame,
      };
      expect(msg.type).toBe("inject-request");
      expect(typeof (msg as any).requestId).toBe("string");
      expect(msg).toHaveProperty("frame");
    });
  });
});
