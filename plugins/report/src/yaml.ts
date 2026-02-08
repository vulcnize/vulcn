/**
 * YAML Report Generator for Vulcn
 *
 * Produces a human-readable YAML report from the canonical VulcnReport.
 */

import { stringify } from "yaml";
import type { VulcnReport } from "./report-model";
import { generateJson } from "./json";

export function generateYaml(report: VulcnReport): string {
  const jsonReport = generateJson(report);

  const header = [
    "# ──────────────────────────────────────────────",
    "# Vulcn Security Report",
    `# Generated: ${report.generatedAt}`,
    `# Session: ${report.session.name}`,
    `# Findings: ${report.summary.totalFindings}`,
    "# ──────────────────────────────────────────────",
    "",
  ].join("\n");

  return header + stringify(jsonReport, { indent: 2 });
}
