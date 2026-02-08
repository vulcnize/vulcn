/**
 * SARIF Report Generator for Vulcn
 *
 * Projects the canonical VulcnReport into SARIF v2.1.0 (Static Analysis
 * Results Interchange Format) compatible with GitHub Code Scanning,
 * Azure DevOps, and other SARIF-consuming tools.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * @see https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
 */

import type {
  VulcnReport,
  EnrichedFinding,
  ReportRule,
  Severity,
} from "./report-model";

// ── SARIF Types ────────────────────────────────────────────────────────

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

// ── Mapping Helpers ────────────────────────────────────────────────────

function toSarifLevel(severity: Severity): SarifLevel {
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

function toPrecision(severity: Severity): SarifRule["properties"]["precision"] {
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

// ── Rule & Result Projection ───────────────────────────────────────────

function toSarifRule(rule: ReportRule): SarifRule {
  return {
    id: rule.id,
    name: rule.type,
    shortDescription: {
      text: `${rule.cwe.name} (CWE-${rule.cwe.id})`,
    },
    fullDescription: {
      text: rule.description,
    },
    helpUri: `https://cwe.mitre.org/data/definitions/${rule.cwe.id}.html`,
    help: {
      text: `## ${rule.cwe.name}\n\nCWE-${rule.cwe.id}: ${rule.cwe.name}\n\nThis rule detects ${rule.type} vulnerabilities by injecting security payloads into form inputs and analyzing the application's response for signs of exploitation.\n\n### Remediation\n\nSee https://cwe.mitre.org/data/definitions/${rule.cwe.id}.html for detailed remediation guidance.`,
      markdown: `## ${rule.cwe.name}\n\n**CWE-${rule.cwe.id}**: ${rule.cwe.name}\n\nThis rule detects \`${rule.type}\` vulnerabilities by injecting security payloads into form inputs and analyzing the application's response for signs of exploitation.\n\n### Remediation\n\nSee [CWE-${rule.cwe.id}](https://cwe.mitre.org/data/definitions/${rule.cwe.id}.html) for detailed remediation guidance.`,
    },
    properties: {
      tags: [
        "security",
        `CWE-${rule.cwe.id}`,
        `external/cwe/cwe-${rule.cwe.id}`,
      ],
      precision: toPrecision(rule.severity),
      "security-severity": rule.securitySeverity,
    },
    defaultConfiguration: {
      level: toSarifLevel(rule.severity),
    },
  };
}

function toSarifResult(
  finding: EnrichedFinding,
  sarifRules: SarifRule[],
): SarifResult {
  const ruleIndex = sarifRules.findIndex((r) => r.id === finding.ruleId);

  let messageText = `${finding.title}\n\n${finding.description}`;
  if (finding.evidence) {
    messageText += `\n\nEvidence: ${finding.evidence}`;
  }
  messageText += `\n\nPayload: ${finding.payload}`;

  return {
    ruleId: finding.ruleId,
    ruleIndex: Math.max(ruleIndex, 0),
    level: toSarifLevel(finding.severity),
    message: { text: messageText },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.url || "unknown",
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
      vulcnFindingV1: finding.fingerprint,
    },
    partialFingerprints: {
      vulcnType: finding.type,
      vulcnStepId: finding.stepId,
    },
    properties: {
      severity: finding.severity,
      payload: finding.payload,
      stepId: finding.stepId,
      detectionMethod: finding.detectionMethod,
      ...(finding.evidence ? { evidence: finding.evidence } : {}),
      ...(finding.passiveCategory
        ? { passiveCategory: finding.passiveCategory }
        : {}),
    },
  };
}

// ── Public API ─────────────────────────────────────────────────────────

/**
 * Generate a SARIF v2.1.0 log from a VulcnReport.
 *
 * Usage:
 *   const report = buildReport(session, result, generatedAt, "0.5.0");
 *   const sarif = generateSarif(report);
 *   await writeFile("vulcn-report.sarif", JSON.stringify(sarif, null, 2));
 */
export function generateSarif(report: VulcnReport): SarifLog {
  const sarifRules = report.rules.map(toSarifRule);
  const results = report.findings.map((f) => toSarifResult(f, sarifRules));

  // Build artifact list from unique URLs
  const artifacts: SarifArtifact[] = report.summary.affectedUrls.map((url) => ({
    location: { uri: url },
  }));

  // Calculate end time from duration
  const startDate = new Date(report.generatedAt);
  const endDate = new Date(startDate.getTime() + report.stats.durationMs);

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Vulcn",
            version: report.engineVersion,
            semanticVersion: report.engineVersion,
            informationUri: "https://vulcn.dev",
            rules: sarifRules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: report.stats.errors.length === 0,
            startTimeUtc: report.generatedAt,
            endTimeUtc: endDate.toISOString(),
            properties: {
              sessionName: report.session.name,
              stepsExecuted: report.stats.stepsExecuted,
              payloadsTested: report.stats.payloadsTested,
              durationMs: report.stats.durationMs,
              ...(report.stats.errors.length > 0
                ? { errors: report.stats.errors }
                : {}),
            },
          },
        ],
        ...(artifacts.length > 0 ? { artifacts } : {}),
      },
    ],
  };
}
