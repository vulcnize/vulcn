/**
 * @vulcn/plugin-detect-reflection
 * Pattern-based reflection detection plugin for Vulcn
 *
 * Detects when payloads appear in the response body:
 * - Searches HTML content for injected payloads
 * - Tracks context (attribute, script, body, etc.)
 * - Lower confidence than execution-based detection (XSS dialog)
 *   but catches more reflection points
 *
 * Use this alongside detect-xss for comprehensive coverage:
 * - detect-reflection: "Payload appeared in HTML" (potential vulnerability)
 * - detect-xss: "JavaScript executed" (confirmed vulnerability)
 */

import { z } from "zod";
import type {
  VulcnPlugin,
  PluginContext,
  DetectContext,
  Finding,
} from "@vulcn/engine";
import type { Page } from "playwright";

/**
 * Plugin configuration schema
 */
const configSchema = z.object({
  /**
   * Enable reflection detection
   * @default true
   */
  enabled: z.boolean().default(true),

  /**
   * Minimum payload length to check for reflection
   * Short payloads may cause false positives
   * @default 4
   */
  minPayloadLength: z.number().default(4),

  /**
   * Detect reflection in HTML body
   * @default true
   */
  detectBody: z.boolean().default(true),

  /**
   * Detect reflection in script contexts
   * Higher severity as it's closer to XSS
   * @default true
   */
  detectScript: z.boolean().default(true),

  /**
   * Detect reflection in HTML attributes
   * @default true
   */
  detectAttribute: z.boolean().default(true),

  /**
   * Severity for general body reflection
   * @default "low"
   */
  bodySeverity: z.enum(["critical", "high", "medium", "low"]).default("low"),

  /**
   * Severity for script context reflection
   * @default "medium"
   */
  scriptSeverity: z
    .enum(["critical", "high", "medium", "low"])
    .default("medium"),

  /**
   * Severity for attribute reflection
   * @default "medium"
   */
  attributeSeverity: z
    .enum(["critical", "high", "medium", "low"])
    .default("medium"),

  /**
   * Patterns that indicate dangerous contexts
   * If payload is near these patterns, increase severity
   */
  dangerousPatterns: z
    .array(z.string())
    .default([
      "onerror",
      "onclick",
      "onload",
      "onmouseover",
      "onfocus",
      "javascript:",
      "eval(",
      "document.write",
      "innerHTML",
    ]),
});

export type DetectReflectionConfig = z.infer<typeof configSchema>;

/**
 * Reflection context types
 */
type ReflectionContext =
  | "body"
  | "script"
  | "attribute"
  | "comment"
  | "unknown";

/**
 * Analyze where in the HTML the reflection occurred
 */
function analyzeContext(
  html: string,
  payload: string,
  index: number,
): ReflectionContext {
  // Get surrounding context (500 chars before the match)
  const before = html.slice(Math.max(0, index - 500), index).toLowerCase();

  // Check if we're inside a script tag
  const lastScriptOpen = before.lastIndexOf("<script");
  const lastScriptClose = before.lastIndexOf("</script");
  if (lastScriptOpen > lastScriptClose) {
    return "script";
  }

  // Check if we're inside a comment
  const lastCommentOpen = before.lastIndexOf("<!--");
  const lastCommentClose = before.lastIndexOf("-->");
  if (lastCommentOpen > lastCommentClose) {
    return "comment";
  }

  // Check if we're inside an attribute
  // Look for patterns like: attribute="...PAYLOAD or attribute='...PAYLOAD
  const attrPattern = /\w+\s*=\s*["'][^"']*$/;
  if (attrPattern.test(before)) {
    return "attribute";
  }

  // Check for unquoted attribute
  const unquotedAttr = /\w+\s*=\s*[^\s>"']+$/;
  if (unquotedAttr.test(before)) {
    return "attribute";
  }

  return "body";
}

/**
 * Check for dangerous patterns near the reflection
 */
function checkDangerousPatterns(
  html: string,
  index: number,
  patterns: string[],
): string | null {
  // Check 200 chars around the reflection
  const start = Math.max(0, index - 100);
  const end = Math.min(html.length, index + 100);
  const surrounding = html.slice(start, end).toLowerCase();

  for (const pattern of patterns) {
    if (surrounding.includes(pattern.toLowerCase())) {
      return pattern;
    }
  }

  return null;
}

/**
 * Reflection Detection Plugin
 */
const plugin: VulcnPlugin = {
  name: "@vulcn/plugin-detect-reflection",
  version: "0.2.0",
  apiVersion: 1,
  description:
    "Pattern-based reflection detection - checks if payloads appear in response HTML",

  configSchema,

  hooks: {
    /**
     * Initialize the plugin
     */
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      ctx.logger.info("Reflection detection plugin initialized");
      ctx.logger.debug(
        `Detection modes: body=${config.detectBody}, script=${config.detectScript}, attribute=${config.detectAttribute}`,
      );
    },

    /**
     * Check for payload reflection after payload injection
     */
    onAfterPayload: async (ctx: DetectContext): Promise<Finding[]> => {
      const config = configSchema.parse(ctx.config);
      const findings: Finding[] = [];

      if (!config.enabled) {
        return findings;
      }

      const payload = ctx.payloadValue;

      // Skip very short payloads (too many false positives)
      if (payload.length < config.minPayloadLength) {
        return findings;
      }

      try {
        // Get page HTML content (cast from unknown to Playwright Page)
        const page = ctx.page as Page;
        const html = await page.content();

        // Search for all occurrences of the payload
        let searchIndex = 0;
        let matchIndex: number;

        while ((matchIndex = html.indexOf(payload, searchIndex)) !== -1) {
          const context = analyzeContext(html, payload, matchIndex);
          searchIndex = matchIndex + 1;

          // Skip if context detection is disabled
          if (context === "script" && !config.detectScript) continue;
          if (context === "attribute" && !config.detectAttribute) continue;
          if (context === "body" && !config.detectBody) continue;
          if (context === "comment") continue; // Comments are generally safe

          // Determine severity based on context
          let severity = config.bodySeverity;
          if (context === "script") {
            severity = config.scriptSeverity;
          } else if (context === "attribute") {
            severity = config.attributeSeverity;
          }

          // Check for dangerous patterns nearby
          const dangerousPattern = checkDangerousPatterns(
            html,
            matchIndex,
            config.dangerousPatterns,
          );

          if (dangerousPattern) {
            // Upgrade severity if dangerous pattern detected
            if (severity === "low") severity = "medium";
            if (severity === "medium") severity = "high";
          }

          // Get surrounding context for evidence
          const start = Math.max(0, matchIndex - 50);
          const end = Math.min(html.length, matchIndex + payload.length + 50);
          const surrounding = html.slice(start, end);

          const contextLabel = {
            body: "HTML body",
            script: "script context",
            attribute: "HTML attribute",
            comment: "HTML comment",
            unknown: "page content",
          }[context];

          ctx.logger.info(
            `📍 Reflection detected in ${contextLabel}: ${payload.slice(0, 30)}...`,
          );

          findings.push({
            type: "reflection",
            severity,
            title: `Payload Reflected in ${contextLabel}`,
            description: dangerousPattern
              ? `Input payload was reflected in ${contextLabel} near dangerous pattern "${dangerousPattern}". This may be exploitable for XSS.`
              : `Input payload was reflected back in the ${contextLabel}. While not proof of XSS, this indicates the input is not properly sanitized.`,
            stepId: ctx.stepId,
            payload,
            url: page.url(),
            evidence: surrounding.replace(/\s+/g, " ").trim(),
            metadata: {
              detectionMethod: "reflection",
              context,
              dangerousPattern,
              payloadLength: payload.length,
              matchPosition: matchIndex,
            },
          });

          // Only report first reflection per payload to avoid spam
          break;
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
