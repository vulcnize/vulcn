import { describe, it, expect } from "vitest";
import type {
  PayloadCategory,
  PayloadSource,
  RuntimePayload,
  CustomPayload,
  CustomPayloadFile,
} from "../src/payload-types";
import { getSeverity } from "../src/payload-types";

describe("Payload Types", () => {
  it("should define valid PayloadCategory values", () => {
    const categories: PayloadCategory[] = [
      "xss",
      "sqli",
      "ssrf",
      "xxe",
      "command-injection",
      "path-traversal",
      "open-redirect",
      "reflection",
      "security-misconfiguration",
      "information-disclosure",
      "custom",
    ];
    expect(categories).toHaveLength(11);
  });

  it("should define valid PayloadSource values", () => {
    const sources: PayloadSource[] = [
      "curated",
      "custom",
      "payloadbox",
      "plugin",
    ];
    expect(sources).toHaveLength(4);
  });

  it("should allow creating RuntimePayload objects", () => {
    const payload: RuntimePayload = {
      name: "test-xss",
      category: "xss",
      description: "Test XSS payloads",
      payloads: ["<script>alert(1)</script>"],
      detectPatterns: [/<script>/i],
      source: "payloadbox",
    };

    expect(payload.name).toBe("test-xss");
    expect(payload.category).toBe("xss");
    expect(payload.payloads).toHaveLength(1);
    expect(payload.detectPatterns).toHaveLength(1);
    expect(payload.source).toBe("payloadbox");
  });

  it("should allow creating CustomPayload objects", () => {
    const custom: CustomPayload = {
      name: "my-payload",
      category: "sqli",
      description: "Custom SQLi",
      payloads: ["' OR '1'='1"],
      detectPatterns: ["sql.*error"],
    };

    expect(custom.name).toBe("my-payload");
    expect(custom.detectPatterns).toHaveLength(1);
  });

  it("should allow creating CustomPayloadFile objects", () => {
    const file: CustomPayloadFile = {
      version: "1",
      payloads: [
        {
          name: "p1",
          category: "xss",
          payloads: ["test"],
        },
      ],
    };

    expect(file.version).toBe("1");
    expect(file.payloads).toHaveLength(1);
  });
});

describe("getSeverity", () => {
  it("should return critical for sqli, command-injection, xxe", () => {
    expect(getSeverity("sqli")).toBe("critical");
    expect(getSeverity("command-injection")).toBe("critical");
    expect(getSeverity("xxe")).toBe("critical");
  });

  it("should return high for xss, ssrf, path-traversal", () => {
    expect(getSeverity("xss")).toBe("high");
    expect(getSeverity("ssrf")).toBe("high");
    expect(getSeverity("path-traversal")).toBe("high");
  });

  it("should return medium for open-redirect", () => {
    expect(getSeverity("open-redirect")).toBe("medium");
  });

  it("should return low for security-misconfiguration", () => {
    expect(getSeverity("security-misconfiguration")).toBe("low");
  });

  it("should return info for information-disclosure", () => {
    expect(getSeverity("information-disclosure")).toBe("info");
  });

  it("should return medium for custom/unknown categories", () => {
    expect(getSeverity("custom")).toBe("medium");
    expect(getSeverity("reflection")).toBe("medium");
  });
});
