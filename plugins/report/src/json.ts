/**
 * JSON Report Generator for Vulcn
 *
 * Produces a structured, machine-readable JSON report.
 */

import type { Finding, RunResult, Session } from "@vulcn/engine";

export interface JsonReport {
  vulcn: {
    version: string;
    reportVersion: string;
    generatedAt: string;
  };
  session: {
    name: string;
    driver: string;
    driverConfig: Record<string, unknown>;
    stepsCount: number;
    metadata?: Record<string, unknown>;
  };
  execution: {
    stepsExecuted: number;
    payloadsTested: number;
    durationMs: number;
    durationFormatted: string;
    errors: string[];
  };
  summary: {
    totalFindings: number;
    riskScore: number;
    severityCounts: Record<string, number>;
    vulnerabilityTypes: string[];
    affectedUrls: string[];
  };
  findings: Finding[];
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function generateJson(
  session: Session,
  result: RunResult,
  generatedAt: string,
  engineVersion: string,
): JsonReport {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of result.findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const riskScore =
    counts.critical * 10 + counts.high * 7 + counts.medium * 4 + counts.low * 1;

  return {
    vulcn: {
      version: engineVersion,
      reportVersion: "1.0",
      generatedAt,
    },
    session: {
      name: session.name,
      driver: session.driver,
      driverConfig: session.driverConfig,
      stepsCount: session.steps.length,
      metadata: session.metadata,
    },
    execution: {
      stepsExecuted: result.stepsExecuted,
      payloadsTested: result.payloadsTested,
      durationMs: result.duration,
      durationFormatted: formatDuration(result.duration),
      errors: result.errors,
    },
    summary: {
      totalFindings: result.findings.length,
      riskScore,
      severityCounts: counts,
      vulnerabilityTypes: [...new Set(result.findings.map((f) => f.type))],
      affectedUrls: [...new Set(result.findings.map((f) => f.url))],
    },
    findings: result.findings,
  };
}
