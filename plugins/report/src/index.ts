/**
 * @vulcn/plugin-report
 * Report Generation Plugin for Vulcn
 *
 * Generates security reports in HTML, JSON, YAML, and SARIF formats
 * after a run completes. Features:
 * - Modern dark-themed HTML report with Vulcn branding
 * - Machine-readable JSON for CI/CD integration
 * - Human-readable YAML for documentation
 * - SARIF v2.1.0 for GitHub Code Scanning and IDE integration
 *
 * Configuration:
 *   format:     "html" | "json" | "yaml" | "sarif" | "all"  (default: "html")
 *   outputDir:  directory for reports               (default: ".")
 *   filename:   base filename (no extension)        (default: "vulcn-report")
 *   open:       auto-open HTML in browser           (default: false)
 */

import { z } from "zod";
import { writeFile, mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import type {
  VulcnPlugin,
  PluginContext,
  PluginRunContext,
  RunResult,
} from "@vulcn/engine";

import { generateHtml, type HtmlReportData } from "./html";
import { generateJson, type JsonReport } from "./json";
import { generateYaml } from "./yaml";
import { generateSarif, type SarifLog } from "./sarif";

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
     * Generate report(s) after run completes
     */
    onRunEnd: async (
      result: RunResult,
      ctx: PluginRunContext,
    ): Promise<RunResult> => {
      const config = configSchema.parse(ctx.config);
      const formats = getFormats(config.format);
      const generatedAt = new Date().toISOString();
      const engineVersion = ctx.engine.version;

      // Ensure output directory exists
      const outDir = resolve(config.outputDir);
      await mkdir(outDir, { recursive: true });

      const basePath = resolve(outDir, config.filename);
      const writtenFiles: string[] = [];

      for (const fmt of formats) {
        try {
          switch (fmt) {
            case "html": {
              const htmlData: HtmlReportData = {
                session: ctx.session,
                result,
                generatedAt,
                engineVersion,
              };
              const html = generateHtml(htmlData);
              const htmlPath = `${basePath}.html`;
              await writeFile(htmlPath, html, "utf-8");
              writtenFiles.push(htmlPath);
              ctx.logger.info(`📄 HTML report: ${htmlPath}`);
              break;
            }

            case "json": {
              const jsonReport = generateJson(
                ctx.session,
                result,
                generatedAt,
                engineVersion,
              );
              const jsonPath = `${basePath}.json`;
              await writeFile(
                jsonPath,
                JSON.stringify(jsonReport, null, 2),
                "utf-8",
              );
              writtenFiles.push(jsonPath);
              ctx.logger.info(`📄 JSON report: ${jsonPath}`);
              break;
            }

            case "yaml": {
              const yamlContent = generateYaml(
                ctx.session,
                result,
                generatedAt,
                engineVersion,
              );
              const yamlPath = `${basePath}.yml`;
              await writeFile(yamlPath, yamlContent, "utf-8");
              writtenFiles.push(yamlPath);
              ctx.logger.info(`📄 YAML report: ${yamlPath}`);
              break;
            }

            case "sarif": {
              const sarifReport = generateSarif(
                ctx.session,
                result,
                generatedAt,
                engineVersion,
              );
              const sarifPath = `${basePath}.sarif`;
              await writeFile(
                sarifPath,
                JSON.stringify(sarifReport, null, 2),
                "utf-8",
              );
              writtenFiles.push(sarifPath);
              ctx.logger.info(`📄 SARIF report: ${sarifPath}`);
              break;
            }
          }
        } catch (err) {
          ctx.logger.error(
            `Failed to generate ${fmt} report: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }

      // Auto-open HTML report if configured
      if (config.open && formats.includes("html")) {
        const htmlPath = `${basePath}.html`;
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
};
export type { HtmlReportData, JsonReport, SarifLog };
