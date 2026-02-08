/**
 * Vulcn Report Model
 *
 * The canonical data model from which all output formats (HTML, JSON,
 * YAML, SARIF) are derived. This is the single source of truth for
 * CWE mappings, severity scores, fingerprinting, risk computation,
 * and passive analysis categorisation.
 *
 *   RunResult + Session
 *          ↓
 *     buildReport()
 *          ↓
 *     VulcnReport (canonical)
 *          ↓
 *   ┌──────┴──────────┬──────────┬──────────┐
 *   HTML            JSON       YAML       SARIF
 *
 * Every output format is a projection of this model.
 */

import type {
  Finding,
  RunResult,
  Session,
  PayloadCategory,
} from "@vulcn/engine";

// ── CWE Registry ───────────────────────────────────────────────────────

export interface CweEntry {
  id: number;
  name: string;
}

/**
 * Map Vulcn vulnerability types to CWE IDs.
 * Single source — used by every output format.
 */
export const CWE_MAP: Record<string, CweEntry> = {
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

// ── Severity Scoring ───────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

/**
 * CVSS-like security-severity scores (0.0–10.0).
 * Used by GitHub Security tab for sorting.
 */
export const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.0",
  high: "7.0",
  medium: "4.0",
  low: "2.0",
  info: "0.0",
};

// ── Passive Analysis Types ─────────────────────────────────────────────

export interface PassiveCheckDefinition {
  id: string;
  label: string;
  icon: string;
  color: string;
  remedy: string;
  checks: string[];
}

/**
 * All passive check categories with their check lists and remediation
 * guidance. Single source — used by HTML and JSON renderers alike.
 */
export const PASSIVE_CATEGORIES: PassiveCheckDefinition[] = [
  {
    id: "security-headers",
    label: "Security Headers",
    icon: "🔒",
    color: "#42a5f5",
    remedy:
      "Add the recommended security headers to your server configuration. Most web servers and frameworks support these via middleware.",
    checks: [
      "Strict-Transport-Security (HSTS)",
      "Content-Security-Policy (CSP)",
      "X-Content-Type-Options",
      "X-Frame-Options",
      "Referrer-Policy",
      "Permissions-Policy",
    ],
  },
  {
    id: "cookie-security",
    label: "Cookie Security",
    icon: "🍪",
    color: "#ffab40",
    remedy:
      "Set the Secure, HttpOnly, and SameSite attributes on all session cookies. Configure your framework's session middleware accordingly.",
    checks: ["Secure flag", "HttpOnly flag", "SameSite attribute"],
  },
  {
    id: "information-disclosure",
    label: "Information Disclosure",
    icon: "🔍",
    color: "#66bb6a",
    remedy:
      "Remove or obfuscate server version headers (Server, X-Powered-By). Disable debug mode in production environments.",
    checks: ["Server version", "X-Powered-By", "Debug tokens"],
  },
  {
    id: "cors",
    label: "CORS Configuration",
    icon: "🌐",
    color: "#ce93d8",
    remedy:
      "Replace wildcard origins with specific trusted domains. Never combine Access-Control-Allow-Credentials with wildcard origins.",
    checks: ["Wildcard origin", "Credentials with wildcard"],
  },
  {
    id: "mixed-content",
    label: "Mixed Content",
    icon: "⚠️",
    color: "#ff8a65",
    remedy:
      "Replace all HTTP resource URLs with HTTPS. Use Content-Security-Policy: upgrade-insecure-requests as a fallback.",
    checks: ["HTTP resources on HTTPS"],
  },
];

// ── Enriched Finding ───────────────────────────────────────────────────

export interface EnrichedFinding {
  /** Original raw finding fields */
  type: PayloadCategory;
  severity: Severity;
  title: string;
  description: string;
  stepId: string;
  payload: string;
  url: string;
  evidence?: string;
  metadata?: Record<string, unknown>;

  /** Enriched fields — computed by buildReport() */
  ruleId: string;
  cwe: CweEntry;
  securitySeverity: string;
  fingerprint: string;

  /** Detection classification */
  detectionMethod: "active" | "passive";
  /** Passive category (only set when detectionMethod === "passive") */
  passiveCategory?: string;
}

// ── Rule ────────────────────────────────────────────────────────────────

export interface ReportRule {
  /** e.g. "VULCN-XSS" */
  id: string;
  /** Raw type name e.g. "xss" */
  type: string;
  /** CWE info */
  cwe: CweEntry;
  /** Severity of the first finding with this rule */
  severity: Severity;
  securitySeverity: string;
  /** Description for help text */
  description: string;
}

// ── Passive Category Summary ───────────────────────────────────────────

export interface PassiveCategorySummary {
  definition: PassiveCheckDefinition;
  /** Findings in this category */
  findings: EnrichedFinding[];
  /** Issue count */
  issueCount: number;
  /** Number of checks that passed */
  passedChecks: number;
  /** Total checks for this category */
  totalChecks: number;
  /** PASS | WARN | FAIL */
  status: "pass" | "warn" | "fail";
}

export interface PassiveAnalysis {
  totalIssues: number;
  categories: PassiveCategorySummary[];
}

// ── Risk Assessment ────────────────────────────────────────────────────

export interface RiskAssessment {
  score: number;
  percent: number;
  label: "Critical" | "High" | "Medium" | "Low" | "Clear";
}

// ── Severity Counts ────────────────────────────────────────────────────

export type SeverityCounts = Record<Severity, number>;

// ── The Canonical Model ────────────────────────────────────────────────

export interface VulcnReport {
  /** Report format version */
  reportVersion: "2.0";

  /** Engine version that generated the scan */
  engineVersion: string;

  /** ISO timestamp when this report was generated */
  generatedAt: string;

  /** Session metadata */
  session: {
    name: string;
    driver: string;
    driverConfig: Record<string, unknown>;
    stepsCount: number;
    metadata?: Record<string, unknown>;
  };

  /** Execution statistics */
  stats: {
    stepsExecuted: number;
    payloadsTested: number;
    durationMs: number;
    errors: string[];
  };

  /** Summary / overview data */
  summary: {
    totalFindings: number;
    severityCounts: SeverityCounts;
    risk: RiskAssessment;
    vulnerabilityTypes: string[];
    affectedUrls: string[];
  };

  /** Rule registry — one rule per unique finding type */
  rules: ReportRule[];

  /** All findings — enriched with CWE, fingerprints, classification */
  findings: EnrichedFinding[];

  /** Active findings (subset) */
  activeFindings: EnrichedFinding[];

  /** Passive analysis summary */
  passiveAnalysis: PassiveAnalysis;
}

// ── Builder ────────────────────────────────────────────────────────────

/**
 * Generate a stable rule ID from a finding type.
 * Format: VULCN-<TYPE> e.g. VULCN-XSS, VULCN-SQLI
 */
export function toRuleId(type: string): string {
  return `VULCN-${type.toUpperCase().replace(/[^A-Z0-9]+/g, "-")}`;
}

/**
 * Generate a stable fingerprint for deduplication across runs.
 */
function fingerprint(f: Finding): string {
  return `${f.type}:${f.stepId}:${f.payload.slice(0, 50)}`;
}

/**
 * Determine detection method from finding metadata.
 */
function detectMethod(f: Finding): "active" | "passive" {
  return (f.metadata as Record<string, unknown>)?.detectionMethod === "passive"
    ? "passive"
    : "active";
}

/**
 * Get passive category from finding metadata.
 */
function passiveCat(f: Finding): string | undefined {
  const method = detectMethod(f);
  if (method !== "passive") return undefined;
  return (
    ((f.metadata as Record<string, unknown>)?.category as string) || "other"
  );
}

/**
 * Enrich a raw Finding with CWE, fingerprint, classification.
 */
function enrichFinding(f: Finding): EnrichedFinding {
  const cwe = CWE_MAP[f.type] || CWE_MAP.custom;
  const sev = f.severity as Severity;

  return {
    // Original fields
    type: f.type,
    severity: sev,
    title: f.title,
    description: f.description,
    stepId: f.stepId,
    payload: f.payload,
    url: f.url,
    evidence: f.evidence,
    metadata: f.metadata,

    // Enriched
    ruleId: toRuleId(f.type),
    cwe,
    securitySeverity: SECURITY_SEVERITY[sev] || "4.0",
    fingerprint: fingerprint(f),
    detectionMethod: detectMethod(f),
    passiveCategory: passiveCat(f),
  };
}

/**
 * Build rules from unique finding types.
 */
function buildRules(enriched: EnrichedFinding[]): ReportRule[] {
  const seen = new Map<string, EnrichedFinding>();
  for (const f of enriched) {
    if (!seen.has(f.type)) seen.set(f.type, f);
  }

  return Array.from(seen.entries()).map(([type, sample]) => ({
    id: toRuleId(type),
    type,
    cwe: sample.cwe,
    severity: sample.severity,
    securitySeverity: sample.securitySeverity,
    description: `Vulcn detected a potential ${type} vulnerability. ${sample.cwe.name}.`,
  }));
}

/**
 * Compute severity counts.
 */
function countSeverities(findings: EnrichedFinding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  return counts;
}

/**
 * Compute overall risk assessment.
 */
function assessRisk(counts: SeverityCounts, total: number): RiskAssessment {
  const score =
    counts.critical * SEVERITY_WEIGHTS.critical +
    counts.high * SEVERITY_WEIGHTS.high +
    counts.medium * SEVERITY_WEIGHTS.medium +
    counts.low * SEVERITY_WEIGHTS.low;

  const maxRisk = total * SEVERITY_WEIGHTS.critical || 1;
  const percent = Math.min(100, Math.round((score / maxRisk) * 100));

  const label: RiskAssessment["label"] =
    percent >= 80
      ? "Critical"
      : percent >= 50
        ? "High"
        : percent >= 25
          ? "Medium"
          : percent > 0
            ? "Low"
            : "Clear";

  return { score, percent, label };
}

/**
 * Build the passive analysis summary.
 */
function buildPassiveAnalysis(
  passiveFindings: EnrichedFinding[],
): PassiveAnalysis {
  // Group by category
  const grouped = new Map<string, EnrichedFinding[]>();
  for (const f of passiveFindings) {
    const cat = f.passiveCategory || "other";
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(f);
  }

  const categories: PassiveCategorySummary[] = PASSIVE_CATEGORIES.map((def) => {
    const findings = grouped.get(def.id) || [];
    const issueCount = findings.length;
    const totalChecks = def.checks.length;
    const passedChecks = Math.max(0, totalChecks - issueCount);
    const status: PassiveCategorySummary["status"] =
      issueCount === 0 ? "pass" : issueCount >= 3 ? "fail" : "warn";

    return {
      definition: def,
      findings,
      issueCount,
      passedChecks,
      totalChecks,
      status,
    };
  });

  return {
    totalIssues: passiveFindings.length,
    categories,
  };
}

// ── Public API ─────────────────────────────────────────────────────────

/**
 * Build a VulcnReport from raw scan output.
 *
 * This is the single transformation point. All output formats
 * (HTML, JSON, YAML, SARIF) operate on the returned model.
 */
export function buildReport(
  session: Session,
  result: RunResult,
  generatedAt: string,
  engineVersion: string,
): VulcnReport {
  // Sort by severity (critical first)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const sortedFindings = [...result.findings].sort(
    (a, b) =>
      (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5),
  );

  // Enrich all findings
  const findings = sortedFindings.map(enrichFinding);

  // Partition
  const activeFindings = findings.filter((f) => f.detectionMethod === "active");
  const passiveFindings = findings.filter(
    (f) => f.detectionMethod === "passive",
  );

  // Compute aggregates
  const counts = countSeverities(findings);
  const risk = assessRisk(counts, findings.length);
  const rules = buildRules(findings);

  return {
    reportVersion: "2.0",
    engineVersion,
    generatedAt,

    session: {
      name: session.name,
      driver: session.driver,
      driverConfig: session.driverConfig,
      stepsCount: session.steps.length,
      metadata: session.metadata,
    },

    stats: {
      stepsExecuted: result.stepsExecuted,
      payloadsTested: result.payloadsTested,
      durationMs: result.duration,
      errors: result.errors,
    },

    summary: {
      totalFindings: findings.length,
      severityCounts: counts,
      risk,
      vulnerabilityTypes: [...new Set(findings.map((f) => f.type))],
      affectedUrls: [...new Set(findings.map((f) => f.url))],
    },

    rules,
    findings,
    activeFindings,
    passiveAnalysis: buildPassiveAnalysis(passiveFindings),
  };
}

/**
 * Format milliseconds to human-readable duration.
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}
