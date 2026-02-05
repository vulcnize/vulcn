import { describe, it, expect } from "vitest";
import {
  Recorder,
  Runner,
  parseSession,
  createSession,
  BUILTIN_PAYLOADS,
  type Payload,
} from "../src/index.js";

describe("Public API exports", () => {
  it("should export Recorder class", () => {
    expect(Recorder).toBeDefined();
    expect(typeof Recorder).toBe("function");
  });

  it("should export Runner class", () => {
    expect(Runner).toBeDefined();
    expect(typeof Runner).toBe("function");
  });

  it("should export parseSession function", () => {
    expect(parseSession).toBeDefined();
    expect(typeof parseSession).toBe("function");
  });

  it("should export BUILTIN_PAYLOADS", () => {
    expect(BUILTIN_PAYLOADS).toBeDefined();
    expect(typeof BUILTIN_PAYLOADS).toBe("object");
  });

  it("should export createSession function", () => {
    expect(createSession).toBeDefined();
    expect(typeof createSession).toBe("function");
  });
});

describe("Types", () => {
  it("should allow creating Session objects", () => {
    const session = createSession({
      name: "test-session",
      startUrl: "https://example.com",
    });
    expect(session.version).toBe("1");
    expect(session.name).toBe("test-session");
    expect(session.steps).toEqual([]);
  });

  it("should allow referencing Payload type", () => {
    // Verify the Payload type structure by accessing a known payload
    const payload: Payload = BUILTIN_PAYLOADS["xss-basic"];
    expect(payload.name).toBe("xss-basic");
    expect(payload.category).toBe("xss");
    expect(Array.isArray(payload.payloads)).toBe(true);
    expect(Array.isArray(payload.detectPatterns)).toBe(true);
  });
});
