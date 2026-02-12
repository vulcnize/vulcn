import { z } from "zod";
import { writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import type {
  VulcnPlugin,
  PluginContext,
  PluginRunContext,
  RunResult,
  Session,
} from "@vulcn/engine";
import type { ScanContext } from "@vulcn/engine";

import { buildReport } from "./report-model";
import type { VulcnReport } from "./report-model";
import { generateHtml } from "./html";
import { generateJson } from "./json";
import { generateYaml } from "./yaml";
import { generateSarif } from "./sarif";

/**
 * Plugin configuration schema
 */
const configSchema = z.object({
  /**
   * Report format(s) to generate
   * - "html":  Beautiful dark-themed HTML report
   * - "json":  Machine-readable structured JSON
   * - "yaml":  Human-readable YAML
   * - "sarif": SARIF v2.1.0 for GitHub Code Scanning
   * - "all":   Generate all formats
   * @default "html"
   */
  format: z.enum(["html", "json", "yaml", "sarif", "all"]).default("html"),

  /**
   * Output directory for report files
   * @default "."
   */
  outputDir: z.string().default("."),

  /**
   * Base filename (without extension) for the report
   * @default "vulcn-report"
   */
  filename: z.string().default("vulcn-report"),

  /**
   * Auto-open HTML report in default browser after generation
   * @default false
   */
  open: z.boolean().default(false),
});

export type ReportConfig = z.infer<typeof configSchema>;

/**
 * Determine which formats to generate
 */
function getFormats(format: ReportConfig["format"]): string[] {
  if (format === "all") return ["html", "json", "yaml", "sarif"];
  return [format];
}

/**
 * Write report files in the requested formats.
 * Shared helper used by both onRunEnd and onScanEnd.
 */
async function writeReports(
  report: VulcnReport,
  config: ReportConfig,
  logger: PluginContext["logger"],
): Promise<string[]> {
  const formats = getFormats(config.format);
  const outDir = resolve(config.outputDir);
  await mkdir(outDir, { recursive: true });

  const basePath = resolve(outDir, config.filename);
  const writtenFiles: string[] = [];

  for (const fmt of formats) {
    try {
      switch (fmt) {
        case "html": {
          const html = generateHtml(report);
          const htmlPath = `${basePath}.html`;
          await writeFile(htmlPath, html, "utf-8");
          writtenFiles.push(htmlPath);
          logger.info(`📄 HTML report: ${htmlPath}`);
          break;
        }

        case "json": {
          const jsonReport = generateJson(report);
          const jsonPath = `${basePath}.json`;
          await writeFile(
            jsonPath,
            JSON.stringify(jsonReport, null, 2),
            "utf-8",
          );
          writtenFiles.push(jsonPath);
          logger.info(`📄 JSON report: ${jsonPath}`);
          break;
        }

        case "yaml": {
          const yamlContent = generateYaml(report);
          const yamlPath = `${basePath}.yml`;
          await writeFile(yamlPath, yamlContent, "utf-8");
          writtenFiles.push(yamlPath);
          logger.info(`📄 YAML report: ${yamlPath}`);
          break;
        }

        case "sarif": {
          const sarifReport = generateSarif(report);
          const sarifPath = `${basePath}.sarif`;
          await writeFile(
            sarifPath,
            JSON.stringify(sarifReport, null, 2),
            "utf-8",
          );
          writtenFiles.push(sarifPath);
          logger.info(`📄 SARIF report: ${sarifPath}`);
          break;
        }
      }
    } catch (err) {
      // Report write/generation failure is critical — don't swallow.
      // Let it propagate; the plugin-manager classifies onScanEnd as FATAL.
      throw new Error(
        `Failed to generate ${fmt} report: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return writtenFiles;
}

// Track whether we're in a multi-session scan
let isScanMode = false;

/**
 * Report Plugin
 */
const plugin: VulcnPlugin = {
  name: "@vulcn/plugin-report",
  version: "0.1.0",
  apiVersion: 1,
  description:
    "Report generation plugin — generates HTML, JSON, YAML, and SARIF security reports",

  configSchema,

  hooks: {
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      ctx.logger.info(
        `Report plugin initialized (format: ${config.format}, output: ${config.outputDir}/${config.filename})`,
      );
    },

    /**
     * Mark that we're in a multi-session scan.
     * onRunEnd will skip per-session reports — onScanEnd writes the aggregate.
     */
    onScanStart: async (_ctx: ScanContext) => {
      isScanMode = true;
    },

    /**
     * Generate report after a single-session run.
     * Skipped when inside a multi-session scan (onScanEnd handles that).
     */
    onRunEnd: async (
      result: RunResult,
      ctx: PluginRunContext,
    ): Promise<RunResult> => {
      if (isScanMode) {
        // In a multi-session scan, skip per-session reports.
        // onScanEnd will write the aggregate report.
        return result;
      }

      const config = configSchema.parse(ctx.config);
      const report = buildReport(
        ctx.session,
        result,
        new Date().toISOString(),
        ctx.engine.version,
      );

      const writtenFiles = await writeReports(report, config, ctx.logger);

      // Auto-open HTML report if configured
      if (config.open && writtenFiles.some((f) => f.endsWith(".html"))) {
        const htmlPath = writtenFiles.find((f) => f.endsWith(".html"))!;
        try {
          const { exec } = await import("node:child_process");
          const openCmd =
            process.platform === "darwin"
              ? "open"
              : process.platform === "win32"
                ? "start"
                : "xdg-open";
          exec(`${openCmd} "${htmlPath}"`);
        } catch {
          // Silently ignore if can't open browser
        }
      }

      return result;
    },

    /**
     * Generate aggregate report after all sessions in a scan complete.
     * This is the single report for vulcn run <session-dir>.
     */
    onScanEnd: async (
      result: RunResult,
      ctx: ScanContext,
    ): Promise<RunResult> => {
      isScanMode = false; // Reset for next run

      const config = configSchema.parse(ctx.config);

      // Build a synthetic session representing the full scan
      const syntheticSession: Session = {
        name: `Scan (${ctx.sessionCount} session${ctx.sessionCount !== 1 ? "s" : ""})`,
        driver: ctx.sessions[0]?.driver ?? "browser",
        driverConfig: ctx.sessions[0]?.driverConfig ?? {},
        steps: [],
        metadata: {
          sessionCount: ctx.sessionCount,
        },
      };

      const report = buildReport(
        syntheticSession,
        result,
        new Date().toISOString(),
        ctx.engine.version,
      );

      const writtenFiles = await writeReports(report, config, ctx.logger);

      // Auto-open HTML report if configured
      if (config.open && writtenFiles.some((f) => f.endsWith(".html"))) {
        const htmlPath = writtenFiles.find((f) => f.endsWith(".html"))!;
        try {
          const { exec } = await import("node:child_process");
          const openCmd =
            process.platform === "darwin"
              ? "open"
              : process.platform === "win32"
                ? "start"
                : "xdg-open";
          exec(`${openCmd} "${htmlPath}"`);
        } catch {
          // Silently ignore if can't open browser
        }
      }

      return result;
    },
  },
};

export default plugin;

// Named exports for programmatic usage
export {
  configSchema,
  generateHtml,
  generateJson,
  generateYaml,
  generateSarif,
  buildReport,
};

// Re-export the canonical model types
export type {
  VulcnReport,
  EnrichedFinding,
  ReportRule,
  PassiveAnalysis,
  PassiveCategorySummary,
  RiskAssessment,
  SeverityCounts,
  CweEntry,
  PassiveCheckDefinition,
} from "./report-model";

export type { JsonReport } from "./json";
export type { SarifLog } from "./sarif";
