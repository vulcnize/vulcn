/**
 * YAML Report Generator for Vulcn
 *
 * Produces a human-readable YAML report.
 */

import { stringify } from "yaml";
import type { RunResult, Session } from "@vulcn/engine";
import { generateJson } from "./json";

export function generateYaml(
  session: Session,
  result: RunResult,
  generatedAt: string,
  engineVersion: string,
): string {
  const report = generateJson(session, result, generatedAt, engineVersion);

  // YAML with header comment
  const header = [
    "# ──────────────────────────────────────────────",
    "# Vulcn Security Report",
    `# Generated: ${generatedAt}`,
    `# Session: ${session.name}`,
    `# Findings: ${result.findings.length}`,
    "# ──────────────────────────────────────────────",
    "",
  ].join("\n");

  return header + stringify(report, { indent: 2 });
}
