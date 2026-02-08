/**
 * SARIF Report Generator for Vulcn
 *
 * Produces SARIF v2.1.0 (Static Analysis Results Interchange Format)
 * compatible with GitHub Code Scanning, Azure DevOps, and other
 * SARIF-consuming tools.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * @see https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
 */

import type { Finding, RunResult, Session } from "@vulcn/engine";

// ── SARIF Types ────────────────────────────────────────────────────────

/**
 * SARIF v2.1.0 Log — top-level structure
 */
export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  invocations: SarifInvocation[];
  artifacts?: SarifArtifact[];
}

interface SarifTool {
  driver: SarifToolComponent;
}

interface SarifToolComponent {
  name: string;
  version: string;
  informationUri: string;
  semanticVersion: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  help: { text: string; markdown: string };
  properties: {
    tags: string[];
    precision: "very-high" | "high" | "medium" | "low";
    "security-severity": string;
  };
  defaultConfiguration: {
    level: SarifLevel;
  };
}

type SarifLevel = "error" | "warning" | "note" | "none";

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: SarifLocation[];
  fingerprints: Record<string, string>;
  partialFingerprints: Record<string, string>;
  properties: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine: number;
      startColumn?: number;
    };
  };
  logicalLocations?: Array<{
    name: string;
    kind: string;
  }>;
}

interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
  properties?: Record<string, unknown>;
}

interface SarifArtifact {
  location: {
    uri: string;
  };
  length?: number;
}

// ── CWE Mappings ───────────────────────────────────────────────────────

/**
 * Map Vulcn vulnerability types to CWE IDs.
 * These are the most specific CWE entries for each category.
 */
const CWE_MAP: Record<string, { id: number; name: string }> = {
  xss: {
    id: 79,
    name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  },
  sqli: {
    id: 89,
    name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  },
  ssrf: { id: 918, name: "Server-Side Request Forgery (SSRF)" },
  xxe: {
    id: 611,
    name: "Improper Restriction of XML External Entity Reference",
  },
  "command-injection": {
    id: 78,
    name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  },
  "path-traversal": {
    id: 22,
    name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
  },
  "open-redirect": {
    id: 601,
    name: "URL Redirection to Untrusted Site ('Open Redirect')",
  },
  reflection: {
    id: 200,
    name: "Exposure of Sensitive Information to an Unauthorized Actor",
  },
  "security-misconfiguration": {
    id: 16,
    name: "Configuration",
  },
  "information-disclosure": {
    id: 200,
    name: "Exposure of Sensitive Information to an Unauthorized Actor",
  },
  custom: { id: 20, name: "Improper Input Validation" },
};

/**
 * Map Vulcn severities to SARIF levels.
 *
 * SARIF only has: error, warning, note, none
 *   - critical/high → error
 *   - medium → warning
 *   - low/info → note
 */
function toSarifLevel(severity: Finding["severity"]): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "warning";
  }
}

/**
 * Map Vulcn severities to CVSS-like security-severity scores.
 * GitHub uses this for sorting in the Security tab.
 *
 * Scale: 0.0–10.0
 *   critical: 9.0
 *   high: 7.0
 *   medium: 4.0
 *   low: 2.0
 *   info: 0.0
 */
function toSecuritySeverity(severity: Finding["severity"]): string {
  switch (severity) {
    case "critical":
      return "9.0";
    case "high":
      return "7.0";
    case "medium":
      return "4.0";
    case "low":
      return "2.0";
    case "info":
      return "0.0";
    default:
      return "4.0";
  }
}

/**
 * Map Vulcn severities to SARIF precision.
 */
function toPrecision(
  severity: Finding["severity"],
): SarifRule["properties"]["precision"] {
  switch (severity) {
    case "critical":
      return "very-high";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
    case "info":
      return "low";
    default:
      return "medium";
  }
}

// ── Rule Generation ────────────────────────────────────────────────────

/**
 * Generate a unique rule ID from a finding type.
 *
 * Format: VULCN-<TYPE>
 * Example: VULCN-XSS, VULCN-SQLI
 */
function toRuleId(type: string): string {
  return `VULCN-${type.toUpperCase().replace(/[^A-Z0-9]+/g, "-")}`;
}

/**
 * Build SARIF rules from unique finding types.
 * Each unique vulnerability type becomes one rule.
 */
function buildRules(findings: Finding[]): SarifRule[] {
  const seenTypes = new Map<string, Finding>();

  for (const f of findings) {
    if (!seenTypes.has(f.type)) {
      seenTypes.set(f.type, f);
    }
  }

  return Array.from(seenTypes.entries()).map(([type, sampleFinding]) => {
    const cwe = CWE_MAP[type] || CWE_MAP.custom;
    const ruleId = toRuleId(type);

    return {
      id: ruleId,
      name: type,
      shortDescription: {
        text: `${cwe.name} (CWE-${cwe.id})`,
      },
      fullDescription: {
        text: `Vulcn detected a potential ${type} vulnerability. ${cwe.name}. See CWE-${cwe.id} for details.`,
      },
      helpUri: `https://cwe.mitre.org/data/definitions/${cwe.id}.html`,
      help: {
        text: `## ${cwe.name}\n\nCWE-${cwe.id}: ${cwe.name}\n\nThis rule detects ${type} vulnerabilities by injecting security payloads into form inputs and analyzing the application's response for signs of exploitation.\n\n### Remediation\n\nSee https://cwe.mitre.org/data/definitions/${cwe.id}.html for detailed remediation guidance.`,
        markdown: `## ${cwe.name}\n\n**CWE-${cwe.id}**: ${cwe.name}\n\nThis rule detects \`${type}\` vulnerabilities by injecting security payloads into form inputs and analyzing the application's response for signs of exploitation.\n\n### Remediation\n\nSee [CWE-${cwe.id}](https://cwe.mitre.org/data/definitions/${cwe.id}.html) for detailed remediation guidance.`,
      },
      properties: {
        tags: ["security", `CWE-${cwe.id}`, `external/cwe/cwe-${cwe.id}`],
        precision: toPrecision(sampleFinding.severity),
        "security-severity": toSecuritySeverity(sampleFinding.severity),
      },
      defaultConfiguration: {
        level: toSarifLevel(sampleFinding.severity),
      },
    };
  });
}

// ── Result Generation ──────────────────────────────────────────────────

/**
 * Convert a Vulcn Finding to a SARIF Result.
 */
function toSarifResult(finding: Finding, rules: SarifRule[]): SarifResult {
  const ruleId = toRuleId(finding.type);
  const ruleIndex = rules.findIndex((r) => r.id === ruleId);

  // Build message with evidence if available
  let messageText = `${finding.title}\n\n${finding.description}`;
  if (finding.evidence) {
    messageText += `\n\nEvidence: ${finding.evidence}`;
  }
  messageText += `\n\nPayload: ${finding.payload}`;

  // Build location from URL
  const uri = finding.url || "unknown";

  // Generate fingerprint from finding properties
  const fingerprint = `${finding.type}:${finding.stepId}:${finding.payload.slice(0, 50)}`;

  return {
    ruleId,
    ruleIndex: Math.max(ruleIndex, 0),
    level: toSarifLevel(finding.severity),
    message: { text: messageText },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri,
          },
          region: {
            startLine: 1,
          },
        },
        logicalLocations: [
          {
            name: finding.stepId,
            kind: "test-step",
          },
        ],
      },
    ],
    fingerprints: {
      vulcnFindingV1: fingerprint,
    },
    partialFingerprints: {
      vulcnType: finding.type,
      vulcnStepId: finding.stepId,
    },
    properties: {
      severity: finding.severity,
      payload: finding.payload,
      stepId: finding.stepId,
      ...(finding.evidence ? { evidence: finding.evidence } : {}),
      ...(finding.metadata || {}),
    },
  };
}

// ── Public API ─────────────────────────────────────────────────────────

/**
 * Generate a SARIF v2.1.0 log from Vulcn scan results.
 *
 * Usage:
 *   const sarif = generateSarif(session, result, generatedAt, "0.4.0");
 *   await writeFile("vulcn-report.sarif", JSON.stringify(sarif, null, 2));
 *
 * The output can be uploaded to:
 *   - GitHub Code Scanning: `gh api /repos/{owner}/{repo}/code-scanning/sarifs`
 *   - GitHub Actions: `github/codeql-action/upload-sarif@v3`
 *   - Azure DevOps: SARIF SAST Scans Tab extension
 *
 * @param session  - The session that was executed
 * @param result   - The run result with findings
 * @param generatedAt - ISO timestamp
 * @param engineVersion - Vulcn engine version
 */
export function generateSarif(
  session: Session,
  result: RunResult,
  generatedAt: string,
  engineVersion: string,
): SarifLog {
  const rules = buildRules(result.findings);
  const results = result.findings.map((f) => toSarifResult(f, rules));

  // Build artifact list from unique URLs
  const uniqueUrls = [
    ...new Set(result.findings.map((f) => f.url).filter(Boolean)),
  ];
  const artifacts: SarifArtifact[] = uniqueUrls.map((url) => ({
    location: { uri: url },
  }));

  // Calculate end time from duration
  const startDate = new Date(generatedAt);
  const endDate = new Date(startDate.getTime() + result.duration);

  const sarifLog: SarifLog = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Vulcn",
            version: engineVersion,
            semanticVersion: engineVersion,
            informationUri: "https://vulcn.dev",
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: result.errors.length === 0,
            startTimeUtc: generatedAt,
            endTimeUtc: endDate.toISOString(),
            properties: {
              sessionName: session.name,
              stepsExecuted: result.stepsExecuted,
              payloadsTested: result.payloadsTested,
              durationMs: result.duration,
              ...(result.errors.length > 0 ? { errors: result.errors } : {}),
            },
          },
        ],
        ...(artifacts.length > 0 ? { artifacts } : {}),
      },
    ],
  };

  return sarifLog;
}
