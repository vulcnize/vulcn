/**
 * @vulcn/plugin-detect-xss
 * Execution-based XSS detection plugin for Vulcn
 *
 * Detects XSS vulnerabilities by monitoring actual JavaScript execution:
 * - Alert/confirm/prompt dialogs (classic XSS proof)
 * - Console markers (custom XSS detection)
 * - DOM mutations (advanced detection)
 *
 * This is more reliable than reflection-based detection because
 * it proves the payload actually executed, not just appeared in HTML.
 */

import { z } from "zod";
import type {
  VulcnPlugin,
  PluginContext,
  DetectContext,
  Finding,
} from "@vulcn/engine";
import type { Dialog, ConsoleMessage, Page } from "playwright";

/**
 * Plugin configuration schema
 */
const configSchema = z.object({
  /**
   * Enable dialog detection (alert, confirm, prompt)
   * @default true
   */
  detectDialogs: z.boolean().default(true),

  /**
   * Enable console marker detection
   * @default true
   */
  detectConsole: z.boolean().default(true),

  /**
   * Console marker prefix to look for
   * Payloads should log: console.log('VULCN_XSS:payload_id')
   * @default "VULCN_XSS:"
   */
  consoleMarker: z.string().default("VULCN_XSS:"),

  /**
   * Enable DOM-based XSS detection (advanced)
   * Looks for script elements created dynamically
   * @default false
   */
  detectDomMutation: z.boolean().default(false),

  /**
   * Custom alert text patterns to detect
   * Default detects common XSS proof patterns
   */
  alertPatterns: z
    .array(z.string())
    .default([
      "XSS",
      "1",
      "document.domain",
      "document.cookie",
      "vulcn",
      "pwned",
    ]),

  /**
   * Severity level for execution-based XSS findings
   * @default "high"
   */
  severity: z.enum(["critical", "high", "medium", "low"]).default("high"),
});

export type DetectXssConfig = z.infer<typeof configSchema>;

/**
 * XSS Detection Plugin
 *
 * Uses browser event hooks to detect actual XSS execution:
 * - onDialog: Triggered when alert/confirm/prompt fires
 * - onConsoleMessage: Triggered for console.log calls
 */
const plugin: VulcnPlugin = {
  name: "@vulcn/plugin-detect-xss",
  version: "0.2.0",
  apiVersion: 1,
  description:
    "Execution-based XSS detection - monitors alerts, console, and DOM for actual payload execution",

  configSchema,

  hooks: {
    /**
     * Initialize the plugin
     */
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      ctx.logger.info("XSS detection plugin initialized");
      ctx.logger.debug(
        `Detection modes: dialogs=${config.detectDialogs}, console=${config.detectConsole}, DOM=${config.detectDomMutation}`,
      );
    },

    /**
     * Detect XSS via alert/confirm/prompt dialogs
     * This is the classic XSS proof - if alert() fires, JS executed
     */
    onDialog: async (
      rawDialog: unknown,
      ctx: DetectContext,
    ): Promise<Finding | null> => {
      const dialog = rawDialog as Dialog;
      const page = ctx.page as Page;
      const config = configSchema.parse(ctx.config);

      if (!config.detectDialogs) {
        return null;
      }

      const dialogType = dialog.type(); // 'alert' | 'confirm' | 'prompt' | 'beforeunload'
      const message = dialog.message();

      // Only care about alert/confirm/prompt (not beforeunload)
      if (dialogType === "beforeunload") {
        return null;
      }

      ctx.logger.info(
        `🚨 XSS DETECTED: ${dialogType}() triggered with message: "${message}"`,
      );

      // Check if the message matches expected patterns
      const matchedPattern = config.alertPatterns.find(
        (pattern) =>
          message.toLowerCase().includes(pattern.toLowerCase()) ||
          pattern === "*",
      );

      return {
        type: "xss",
        severity: config.severity,
        title: `XSS Confirmed: ${dialogType}() executed`,
        description: `JavaScript ${dialogType}() dialog was triggered, proving XSS execution. Message: "${message}"`,
        stepId: ctx.stepId,
        payload: ctx.payloadValue,
        url: page.url(),
        evidence: `Dialog type: ${dialogType}, Message: ${message}`,
        metadata: {
          detectionMethod: "dialog",
          dialogType,
          dialogMessage: message,
          matchedPattern: matchedPattern || "none",
        },
      };
    },

    /**
     * Detect XSS via console markers
     * Payloads can use console.log('VULCN_XSS:identifier') for detection
     */
    onConsoleMessage: async (
      rawMsg: unknown,
      ctx: DetectContext,
    ): Promise<Finding | null> => {
      const msg = rawMsg as ConsoleMessage;
      const page = ctx.page as Page;
      const config = configSchema.parse(ctx.config);

      if (!config.detectConsole) {
        return null;
      }

      const text = msg.text();
      const marker = config.consoleMarker;

      // Check if this is a VULCN marker
      if (!text.startsWith(marker)) {
        return null;
      }

      const identifier = text.slice(marker.length);
      ctx.logger.info(`🚨 XSS DETECTED via console marker: ${identifier}`);

      return {
        type: "xss",
        severity: config.severity,
        title: "XSS Confirmed: Console marker detected",
        description: `JavaScript console.log() with XSS marker was executed, proving code injection. Marker: "${text}"`,
        stepId: ctx.stepId,
        payload: ctx.payloadValue,
        url: page.url(),
        evidence: `Console message: ${text}`,
        metadata: {
          detectionMethod: "console",
          marker: text,
          identifier,
        },
      };
    },

    /**
     * Additional detection after payload injection
     * Checks for DOM-based indicators of XSS
     */
    onAfterPayload: async (ctx: DetectContext): Promise<Finding[]> => {
      const config = configSchema.parse(ctx.config);
      const findings: Finding[] = [];

      // Only run DOM mutation detection if enabled
      if (!config.detectDomMutation) {
        return findings;
      }

      // Check for dynamically created script elements
      try {
        const page = ctx.page as Page;
        const scriptCount = await page.evaluate(() => {
          // Count script elements that were added after initial load
          const scripts = document.querySelectorAll("script");
          let dynamicScripts = 0;

          scripts.forEach((script) => {
            // Check if script has inline content (potential XSS)
            if (script.textContent && script.textContent.trim().length > 0) {
              // Look for common XSS patterns in script content
              const content = script.textContent.toLowerCase();
              if (
                content.includes("alert") ||
                content.includes("document.cookie") ||
                content.includes("vulcn") ||
                content.includes("xss")
              ) {
                dynamicScripts++;
              }
            }
          });

          return dynamicScripts;
        });

        if (scriptCount > 0) {
          ctx.logger.info(
            `🚨 XSS DETECTED: ${scriptCount} suspicious script element(s) found`,
          );
          findings.push({
            type: "xss",
            severity: "medium", // Lower confidence than dialog detection
            title: "Potential XSS: Suspicious script elements detected",
            description: `Found ${scriptCount} script element(s) with suspicious content that may indicate DOM-based XSS`,
            stepId: ctx.stepId,
            payload: ctx.payloadValue,
            url: page.url(),
            evidence: `${scriptCount} suspicious script elements`,
            metadata: {
              detectionMethod: "dom-mutation",
              scriptCount,
            },
          });
        }
      } catch {
        // Page may have navigated or closed, ignore
      }

      return findings;
    },
  },
};

export default plugin;

// Export config type for users
export { configSchema };
