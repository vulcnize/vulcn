import { describe, it, expect } from "vitest";
import { BUILTIN_PAYLOADS } from "../src/index.js";

describe("BUILTIN_PAYLOADS", () => {
  it("should have xss-basic payload set", () => {
    expect(BUILTIN_PAYLOADS["xss-basic"]).toBeDefined();
  });

  it("should have sqli-basic payload set", () => {
    expect(BUILTIN_PAYLOADS["sqli-basic"]).toBeDefined();
  });

  it("should have valid structure for all payload sets", () => {
    for (const [name, payload] of Object.entries(BUILTIN_PAYLOADS)) {
      expect(payload.name).toBe(name);
      expect(payload.category).toMatch(/^(xss|sqli|ssrf|xxe|custom)$/);
      expect(payload.description).toBeTruthy();
      expect(Array.isArray(payload.payloads)).toBe(true);
      expect(payload.payloads.length).toBeGreaterThan(0);
      expect(Array.isArray(payload.detectPatterns)).toBe(true);
    }
  });

  it("xss-basic should contain script tag payloads", () => {
    const xss = BUILTIN_PAYLOADS["xss-basic"];
    const hasScriptPayload = xss.payloads.some((p) =>
      p.toLowerCase().includes("<script"),
    );
    expect(hasScriptPayload).toBe(true);
  });

  it("sqli-basic should contain SQL syntax payloads", () => {
    const sqli = BUILTIN_PAYLOADS["sqli-basic"];
    const hasSqlPayload = sqli.payloads.some(
      (p) => p.includes("'") || p.includes("--") || p.includes("OR"),
    );
    expect(hasSqlPayload).toBe(true);
  });
});
