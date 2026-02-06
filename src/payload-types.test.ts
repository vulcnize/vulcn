import { describe, it, expect } from "vitest";
import type {
  PayloadCategory,
  PayloadSource,
  RuntimePayload,
  CustomPayload,
  CustomPayloadFile,
} from "../src/payload-types";

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
      "custom",
    ];
    expect(categories).toHaveLength(8);
  });

  it("should define valid PayloadSource values", () => {
    const sources: PayloadSource[] = [
      "builtin",
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
      source: "builtin",
    };

    expect(payload.name).toBe("test-xss");
    expect(payload.category).toBe("xss");
    expect(payload.payloads).toHaveLength(1);
    expect(payload.detectPatterns).toHaveLength(1);
    expect(payload.source).toBe("builtin");
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
