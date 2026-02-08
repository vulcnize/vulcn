/**
 * JSON Report Generator for Vulcn
 *
 * Projects the canonical VulcnReport into a clean JSON structure
 * suitable for CI/CD pipelines and programmatic consumption.
 */

import type { VulcnReport } from "./report-model";
import { formatDuration } from "./report-model";

/**
 * The JSON output shape — a clean projection of VulcnReport.
 */
export interface JsonReport {
  vulcn: {
    version: string;
    reportVersion: string;
    generatedAt: string;
  };
  session: VulcnReport["session"];
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
    riskLabel: string;
    severityCounts: VulcnReport["summary"]["severityCounts"];
    vulnerabilityTypes: string[];
    affectedUrls: string[];
  };
  findings: VulcnReport["findings"];
  passiveAnalysis: {
    totalIssues: number;
    categories: Array<{
      id: string;
      label: string;
      status: string;
      issueCount: number;
      passedChecks: number;
      totalChecks: number;
      remedy: string;
    }>;
  };
  rules: VulcnReport["rules"];
}

export function generateJson(report: VulcnReport): JsonReport {
  return {
    vulcn: {
      version: report.engineVersion,
      reportVersion: report.reportVersion,
      generatedAt: report.generatedAt,
    },
    session: report.session,
    execution: {
      stepsExecuted: report.stats.stepsExecuted,
      payloadsTested: report.stats.payloadsTested,
      durationMs: report.stats.durationMs,
      durationFormatted: formatDuration(report.stats.durationMs),
      errors: report.stats.errors,
    },
    summary: {
      totalFindings: report.summary.totalFindings,
      riskScore: report.summary.risk.score,
      riskLabel: report.summary.risk.label,
      severityCounts: report.summary.severityCounts,
      vulnerabilityTypes: report.summary.vulnerabilityTypes,
      affectedUrls: report.summary.affectedUrls,
    },
    findings: report.findings,
    passiveAnalysis: {
      totalIssues: report.passiveAnalysis.totalIssues,
      categories: report.passiveAnalysis.categories.map((c) => ({
        id: c.definition.id,
        label: c.definition.label,
        status: c.status,
        issueCount: c.issueCount,
        passedChecks: c.passedChecks,
        totalChecks: c.totalChecks,
        remedy: c.definition.remedy,
      })),
    },
    rules: report.rules,
  };
}
