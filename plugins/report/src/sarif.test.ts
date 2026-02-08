/**
 * SARIF Generator Tests
 *
 * Validates SARIF v2.1.0 output structure and correctness.
 * Tests go through the canonical model: buildReport() → generateSarif().
 */

import { describe, it, expect } from "vitest";
import { generateSarif } from "../src/sarif";
import { buildReport } from "../src/report-model";
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

/** Helper: build report then generate SARIF */
function toSarif(findings?: Finding[], overrides?: Partial<RunResult>) {
  const result = { ...makeResult(findings), ...overrides };
  const report = buildReport(
    mockSession,
    result,
    "2026-02-08T00:00:00.000Z",
    "0.4.0",
  );
  return generateSarif(report);
}

describe("generateSarif", () => {
  it("should produce valid SARIF v2.1.0 structure", () => {
    const sarif = toSarif();
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
  });

  it("should populate tool driver info", () => {
    const sarif = toSarif();
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
    const sarif = toSarif(findings);

    const rules = sarif.runs[0].tool.driver.rules;
    expect(rules).toHaveLength(2); // xss + sqli, not 3
    // Rules are ordered by severity: critical (SQLI) before high (XSS)
    expect(rules[0].id).toBe("VULCN-SQLI");
    expect(rules[1].id).toBe("VULCN-XSS");
  });

  it("should include CWE tags on rules", () => {
    const sarif = toSarif([makeFinding({ type: "xss" })]);

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

    const sarif = toSarif(findings);
    const results = sarif.runs[0].results;

    // Results are sorted by severity (critical first)
    expect(results[0].level).toBe("error"); // critical
    expect(results[1].level).toBe("error"); // high
    expect(results[2].level).toBe("warning"); // medium
    expect(results[3].level).toBe("note"); // low
  });

  it("should map severities to security-severity scores", () => {
    const sarif = toSarif([
      makeFinding({ severity: "critical", type: "sqli" }),
    ]);

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.properties["security-severity"]).toBe("9.0");
  });

  it("should create results with locations from finding URLs", () => {
    const sarif = toSarif([
      makeFinding({ url: "https://example.com/api/search" }),
    ]);

    const result = sarif.runs[0].results[0];
    expect(result.locations).toHaveLength(1);
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe(
      "https://example.com/api/search",
    );
  });

  it("should include evidence and payload in result message", () => {
    const sarif = toSarif([
      makeFinding({
        evidence: "alert(1) dialog triggered",
        payload: "<img onerror=alert(1)>",
      }),
    ]);

    const message = sarif.runs[0].results[0].message.text;
    expect(message).toContain("alert(1) dialog triggered");
    expect(message).toContain("<img onerror=alert(1)>");
  });

  it("should populate invocation metadata", () => {
    const sarif = toSarif();
    const invocation = sarif.runs[0].invocations[0];
    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.startTimeUtc).toBe("2026-02-08T00:00:00.000Z");
    expect(invocation.properties?.sessionName).toBe("test-login-flow");
    expect(invocation.properties?.stepsExecuted).toBe(2);
    expect(invocation.properties?.payloadsTested).toBe(50);
  });

  it("should mark invocation as unsuccessful when errors exist", () => {
    const sarif = toSarif(undefined, {
      errors: ["Step 1 timed out"],
    });

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

    const sarif = toSarif(findings);
    expect(sarif.runs[0].artifacts).toHaveLength(2);
    expect(sarif.runs[0].artifacts![0].location.uri).toBe(
      "https://example.com/search",
    );
    expect(sarif.runs[0].artifacts![1].location.uri).toBe(
      "https://example.com/login",
    );
  });

  it("should handle zero findings gracefully", () => {
    const sarif = toSarif([]);
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

    const sarif1 = toSarif([finding]);
    const sarif2 = toSarif([finding]);

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
      const sarif = toSarif([makeFinding({ type: type as Finding["type"] })]);

      const rule = sarif.runs[0].tool.driver.rules[0];
      expect(rule.properties.tags.some((t) => t.startsWith("CWE-"))).toBe(true);
      expect(rule.helpUri).toContain("cwe.mitre.org");
    }
  });
});
