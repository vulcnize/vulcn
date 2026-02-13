import { describe, it, expect } from "vitest";
import {
  parseProjectConfig,
  VulcnProjectConfigSchema,
  DEFAULT_PROJECT_CONFIG,
} from "./config";

describe("VulcnProjectConfig", () => {
  describe("parseProjectConfig", () => {
    it("should parse an empty object with all defaults", () => {
      const config = parseProjectConfig({});

      expect(config.scan.browser).toBe("chromium");
      expect(config.scan.headless).toBe(true);
      expect(config.scan.timeout).toBe(30_000);

      expect(config.payloads.types).toEqual(["xss"]);
      expect(config.payloads.payloadbox).toBe(false);
      expect(config.payloads.limit).toBe(100);
      expect(config.payloads.custom).toBeNull();

      expect(config.detection.xss.dialogs).toBe(true);
      expect(config.detection.xss.console).toBe(true);
      expect(config.detection.xss.domMutation).toBe(false);
      expect(config.detection.xss.severity).toBe("high");
      expect(config.detection.reflection.enabled).toBe(true);
      expect(config.detection.passive).toBe(true);

      expect(config.crawl.depth).toBe(2);
      expect(config.crawl.maxPages).toBe(20);
      expect(config.crawl.sameOrigin).toBe(true);

      expect(config.report.format).toBeNull();
      expect(config.auth).toBeNull();
    });

    it("should parse a minimal config with just target", () => {
      const config = parseProjectConfig({
        target: "https://example.com",
      });

      expect(config.target).toBe("https://example.com");
      expect(config.scan.browser).toBe("chromium");
      expect(config.payloads.types).toEqual(["xss"]);
    });

    it("should parse a full config", () => {
      const config = parseProjectConfig({
        target: "https://dvwa.local",
        scan: {
          browser: "firefox",
          headless: false,
          timeout: 60000,
        },
        payloads: {
          types: ["xss", "sqli"],
          payloadbox: true,
          limit: 50,
          custom: "./my-payloads.yml",
        },
        detection: {
          xss: {
            dialogs: true,
            console: false,
            domMutation: true,
            severity: "critical",
            alertPatterns: ["XSS", "pwned"],
          },
          reflection: {
            enabled: false,
            minLength: 8,
          },
          passive: false,
        },
        crawl: {
          depth: 5,
          maxPages: 100,
          sameOrigin: false,
          timeout: 20000,
        },
        report: {
          format: "sarif",
        },
        auth: {
          strategy: "form",
          loginUrl: "https://dvwa.local/login",
          userSelector: "#user",
          passSelector: "#pass",
        },
      });

      expect(config.target).toBe("https://dvwa.local");
      expect(config.scan.browser).toBe("firefox");
      expect(config.scan.headless).toBe(false);
      expect(config.scan.timeout).toBe(60000);
      expect(config.payloads.types).toEqual(["xss", "sqli"]);
      expect(config.payloads.payloadbox).toBe(true);
      expect(config.payloads.limit).toBe(50);
      expect(config.payloads.custom).toBe("./my-payloads.yml");
      expect(config.detection.xss.console).toBe(false);
      expect(config.detection.xss.domMutation).toBe(true);
      expect(config.detection.xss.severity).toBe("critical");
      expect(config.detection.reflection.enabled).toBe(false);
      expect(config.detection.reflection.minLength).toBe(8);
      expect(config.detection.passive).toBe(false);
      expect(config.crawl.depth).toBe(5);
      expect(config.crawl.maxPages).toBe(100);
      expect(config.report.format).toBe("sarif");
      expect(config.auth).toEqual({
        strategy: "form",
        loginUrl: "https://dvwa.local/login",
        userSelector: "#user",
        passSelector: "#pass",
      });
    });

    it("should parse header auth config", () => {
      const config = parseProjectConfig({
        auth: {
          strategy: "header",
          headers: {
            Authorization: "Bearer abc123",
          },
        },
      });

      expect(config.auth).toEqual({
        strategy: "header",
        headers: { Authorization: "Bearer abc123" },
      });
    });

    it("should reject invalid browser value", () => {
      expect(() =>
        parseProjectConfig({
          scan: { browser: "opera" },
        }),
      ).toThrow();
    });

    it("should reject invalid payload type", () => {
      expect(() =>
        parseProjectConfig({
          payloads: { types: ["invalid"] },
        }),
      ).toThrow();
    });

    it("should reject invalid severity", () => {
      expect(() =>
        parseProjectConfig({
          detection: { xss: { severity: "extreme" } },
        }),
      ).toThrow();
    });

    it("should reject invalid report format", () => {
      expect(() =>
        parseProjectConfig({
          report: { format: "pdf" },
        }),
      ).toThrow();
    });

    it("should reject invalid target URL", () => {
      expect(() =>
        parseProjectConfig({
          target: "not-a-url",
        }),
      ).toThrow();
    });

    it("should allow target to be omitted", () => {
      const config = parseProjectConfig({});
      expect(config.target).toBeUndefined();
    });
  });

  describe("DEFAULT_PROJECT_CONFIG", () => {
    it("should be parseable", () => {
      const config = parseProjectConfig(DEFAULT_PROJECT_CONFIG);
      expect(config.target).toBe("https://example.com");
      expect(config.scan.browser).toBe("chromium");
      expect(config.payloads.types).toEqual(["xss"]);
    });
  });

  describe("partial configs", () => {
    it("should allow partial scan config", () => {
      const config = parseProjectConfig({
        scan: { browser: "webkit" },
      });
      expect(config.scan.browser).toBe("webkit");
      expect(config.scan.headless).toBe(true); // default
      expect(config.scan.timeout).toBe(30_000); // default
    });

    it("should allow partial detection config", () => {
      const config = parseProjectConfig({
        detection: {
          xss: { severity: "low" },
        },
      });
      expect(config.detection.xss.severity).toBe("low");
      expect(config.detection.xss.dialogs).toBe(true); // default
      expect(config.detection.passive).toBe(true); // default
    });

    it("should allow partial crawl config", () => {
      const config = parseProjectConfig({
        crawl: { depth: 10 },
      });
      expect(config.crawl.depth).toBe(10);
      expect(config.crawl.maxPages).toBe(20); // default
    });

    it("should allow partial reflection config", () => {
      const config = parseProjectConfig({
        detection: {
          reflection: {
            contexts: { script: false },
          },
        },
      });
      expect(config.detection.reflection.contexts.script).toBe(false);
      expect(config.detection.reflection.contexts.attribute).toBe(true); // default
      expect(config.detection.reflection.contexts.body).toBe(true); // default
    });

    it("should allow partial reflection severity", () => {
      const config = parseProjectConfig({
        detection: {
          reflection: {
            severity: { script: "high" },
          },
        },
      });
      expect(config.detection.reflection.severity.script).toBe("high");
      expect(config.detection.reflection.severity.attribute).toBe("medium"); // default
    });
  });
});
