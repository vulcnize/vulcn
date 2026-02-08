/**
 * SARIF Generator Tests
 *
 * Validates SARIF v2.1.0 output structure and correctness.
 */

import { describe, it, expect } from "vitest";
import { generateSarif } from "../src/sarif";
import type { Finding, RunResult, Session } from "@vulcn/engine";

const mockSession: Session = {
  name: "test-login-flow",
  driver: "browser",
  driverConfig: {
    startUrl: "https://example.com/login",
    browser: "chromium",
  },
  steps: [
    {
      id: "step_001",
      type: "browser.navigate",
      params: { url: "https://example.com/login" },
      timestamp: 1738972800000,
    },
    {
      id: "step_002",
      type: "browser.input",
      params: { selector: "#username", value: "admin" },
      timestamp: 1738972801000,
    },
  ],
};

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    type: "xss",
    severity: "high",
    title: "XSS: Script injection in search field",
    description: "The injected <script> payload was executed.",
    stepId: "step_002",
    payload: "<script>alert(1)</script>",
    url: "https://example.com/search",
    evidence: "Dialog triggered: alert(1)",
    ...overrides,
  };
}

function makeResult(findings: Finding[] = [makeFinding()]): RunResult {
  return {
    findings,
    stepsExecuted: 2,
    payloadsTested: 50,
    duration: 3200,
    errors: [],
  };
}

describe("generateSarif", () => {
  it("should produce valid SARIF v2.1.0 structure", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult(),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    // Top-level structure
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
  });

  it("should populate tool driver info", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult(),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe("Vulcn");
    expect(driver.version).toBe("0.4.0");
    expect(driver.semanticVersion).toBe("0.4.0");
    expect(driver.informationUri).toBe("https://vulcn.dev");
  });

  it("should create rules from unique finding types", () => {
    const findings = [
      makeFinding({ type: "xss", severity: "high" }),
      makeFinding({ type: "xss", severity: "high" }), // duplicate type
      makeFinding({ type: "sqli", severity: "critical" }),
    ];
    const sarif = generateSarif(
      mockSession,
      makeResult(findings),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const rules = sarif.runs[0].tool.driver.rules;
    expect(rules).toHaveLength(2); // xss + sqli, not 3
    expect(rules[0].id).toBe("VULCN-XSS");
    expect(rules[1].id).toBe("VULCN-SQLI");
  });

  it("should include CWE tags on rules", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult([makeFinding({ type: "xss" })]),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.properties.tags).toContain("security");
    expect(rule.properties.tags).toContain("CWE-79");
    expect(rule.properties.tags).toContain("external/cwe/cwe-79");
    expect(rule.helpUri).toContain("cwe.mitre.org/data/definitions/79");
  });

  it("should map severities to SARIF levels correctly", () => {
    const findings = [
      makeFinding({ severity: "critical", type: "sqli" }),
      makeFinding({ severity: "high", type: "xss" }),
      makeFinding({ severity: "medium", type: "open-redirect" }),
      makeFinding({ severity: "low", type: "reflection" }),
    ];

    const sarif = generateSarif(
      mockSession,
      makeResult(findings),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const results = sarif.runs[0].results;
    expect(results[0].level).toBe("error"); // critical
    expect(results[1].level).toBe("error"); // high
    expect(results[2].level).toBe("warning"); // medium
    expect(results[3].level).toBe("note"); // low
  });

  it("should map severities to security-severity scores", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult([makeFinding({ severity: "critical", type: "sqli" })]),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.properties["security-severity"]).toBe("9.0");
  });

  it("should create results with locations from finding URLs", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult([makeFinding({ url: "https://example.com/api/search" })]),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const result = sarif.runs[0].results[0];
    expect(result.locations).toHaveLength(1);
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe(
      "https://example.com/api/search",
    );
  });

  it("should include evidence and payload in result message", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult([
        makeFinding({
          evidence: "alert(1) dialog triggered",
          payload: "<img onerror=alert(1)>",
        }),
      ]),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const message = sarif.runs[0].results[0].message.text;
    expect(message).toContain("alert(1) dialog triggered");
    expect(message).toContain("<img onerror=alert(1)>");
  });

  it("should populate invocation metadata", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult(),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const invocation = sarif.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.startTimeUtc).toBe("2026-02-08T00:00:00.000Z");
    expect(invocation.properties?.sessionName).toBe("test-login-flow");
    expect(invocation.properties?.stepsExecuted).toBe(2);
    expect(invocation.properties?.payloadsTested).toBe(50);
  });

  it("should mark invocation as unsuccessful when errors exist", () => {
    const result = makeResult();
    result.errors = ["Step 1 timed out"];

    const sarif = generateSarif(
      mockSession,
      result,
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    const invocation = sarif.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.properties?.errors).toEqual(["Step 1 timed out"]);
  });

  it("should generate artifacts from unique finding URLs", () => {
    const findings = [
      makeFinding({ url: "https://example.com/search" }),
      makeFinding({ url: "https://example.com/search" }), // duplicate
      makeFinding({ url: "https://example.com/login" }),
    ];

    const sarif = generateSarif(
      mockSession,
      makeResult(findings),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    expect(sarif.runs[0].artifacts).toHaveLength(2);
    expect(sarif.runs[0].artifacts![0].location.uri).toBe(
      "https://example.com/search",
    );
    expect(sarif.runs[0].artifacts![1].location.uri).toBe(
      "https://example.com/login",
    );
  });

  it("should handle zero findings gracefully", () => {
    const sarif = generateSarif(
      mockSession,
      makeResult([]),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
    expect(sarif.runs[0].artifacts).toBeUndefined();
  });

  it("should produce deterministic fingerprints", () => {
    const finding = makeFinding({
      type: "xss",
      stepId: "step_002",
      payload: "<script>alert(1)</script>",
    });

    const sarif1 = generateSarif(
      mockSession,
      makeResult([finding]),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );
    const sarif2 = generateSarif(
      mockSession,
      makeResult([finding]),
      "2026-02-08T00:00:00.000Z",
      "0.4.0",
    );

    expect(sarif1.runs[0].results[0].fingerprints).toEqual(
      sarif2.runs[0].results[0].fingerprints,
    );
  });

  it("should map all known CWE types correctly", () => {
    const types = [
      "xss",
      "sqli",
      "xxe",
      "command-injection",
      "path-traversal",
      "open-redirect",
    ];

    for (const type of types) {
      const sarif = generateSarif(
        mockSession,
        makeResult([makeFinding({ type: type as Finding["type"] })]),
        "2026-02-08T00:00:00.000Z",
        "0.4.0",
      );

      const rule = sarif.runs[0].tool.driver.rules[0];
      expect(rule.properties.tags.some((t) => t.startsWith("CWE-"))).toBe(true);
      expect(rule.helpUri).toContain("cwe.mitre.org");
    }
  });
});
