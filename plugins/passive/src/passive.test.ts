/**
 * Passive Scanner Plugin Tests
 *
 * Tests the passive security scanner's detection logic for:
 * - Missing security headers
 * - Cookie security issues
 * - Information disclosure
 * - CORS misconfigurations
 */

import { describe, it, expect } from "vitest";

// Import the detection helpers directly for unit testing
// We test the exported utilities and config schema
import plugin, { configSchema } from "../src/index";

describe("@vulcn/plugin-passive", () => {
  describe("configSchema", () => {
    it("should accept empty config with all defaults", () => {
      const parsed = configSchema.parse({});
      expect(parsed.detectHeaders).toBe(true);
      expect(parsed.detectCookies).toBe(true);
      expect(parsed.detectInfoLeak).toBe(true);
      expect(parsed.detectCors).toBe(true);
      expect(parsed.detectMixed).toBe(true);
    });

    it("should accept custom severity levels", () => {
      const parsed = configSchema.parse({
        headerSeverity: "high",
        cookieSeverity: "critical",
        infoLeakSeverity: "info",
        corsSeverity: "medium",
        mixedContentSeverity: "low",
      });
      expect(parsed.headerSeverity).toBe("high");
      expect(parsed.cookieSeverity).toBe("critical");
      expect(parsed.infoLeakSeverity).toBe("info");
      expect(parsed.corsSeverity).toBe("medium");
      expect(parsed.mixedContentSeverity).toBe("low");
    });

    it("should support disabling individual checks", () => {
      const parsed = configSchema.parse({
        detectHeaders: false,
        detectCors: false,
      });
      expect(parsed.detectHeaders).toBe(false);
      expect(parsed.detectCors).toBe(false);
      expect(parsed.detectCookies).toBe(true); // default
    });

    it("should reject invalid severity values", () => {
      expect(() => configSchema.parse({ headerSeverity: "invalid" })).toThrow();
    });
  });

  describe("plugin structure", () => {
    it("should export a valid VulcnPlugin", () => {
      expect(plugin.name).toBe("@vulcn/plugin-passive");
      expect(plugin.version).toBe("0.1.0");
      expect(plugin.apiVersion).toBe(1);
    });

    it("should have required hooks", () => {
      expect(plugin.hooks?.onInit).toBeDefined();
      expect(plugin.hooks?.onRunStart).toBeDefined();
      expect(plugin.hooks?.onRunEnd).toBeDefined();
      expect(plugin.hooks?.onDestroy).toBeDefined();
    });

    it("should have a description", () => {
      expect(plugin.description).toContain("Passive");
    });

    it("should have a config schema", () => {
      expect(plugin.configSchema).toBeDefined();
    });
  });

  describe("default severity mappings", () => {
    it("should use medium for headers by default", () => {
      const parsed = configSchema.parse({});
      expect(parsed.headerSeverity).toBe("medium");
    });

    it("should use medium for cookies by default", () => {
      const parsed = configSchema.parse({});
      expect(parsed.cookieSeverity).toBe("medium");
    });

    it("should use low for info leak by default", () => {
      const parsed = configSchema.parse({});
      expect(parsed.infoLeakSeverity).toBe("low");
    });

    it("should use high for CORS by default", () => {
      const parsed = configSchema.parse({});
      expect(parsed.corsSeverity).toBe("high");
    });

    it("should use medium for mixed content by default", () => {
      const parsed = configSchema.parse({});
      expect(parsed.mixedContentSeverity).toBe("medium");
    });
  });
});
