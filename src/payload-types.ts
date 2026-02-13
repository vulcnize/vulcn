/**
 * Payload Types for Vulcn
 * Core types used by the engine and plugins
 */

/**
 * Valid payload categories
 */
export type PayloadCategory =
  | "xss"
  | "sqli"
  | "ssrf"
  | "xxe"
  | "command-injection"
  | "path-traversal"
  | "open-redirect"
  | "reflection"
  | "security-misconfiguration"
  | "information-disclosure"
  | "custom";

/**
 * Payload source types
 */
export type PayloadSource = "curated" | "custom" | "payloadbox" | "plugin";

/**
 * Runtime payload structure - used by plugins and the runner
 */
export interface RuntimePayload {
  /** Unique payload name */
  name: string;

  /** Vulnerability category */
  category: PayloadCategory;

  /** Human-readable description */
  description: string;

  /** Array of payload strings to inject */
  payloads: string[];

  /** Patterns to detect vulnerability (as RegExp) */
  detectPatterns: RegExp[];

  /** Where this payload came from */
  source: PayloadSource;
}

/**
 * Custom payload schema for YAML/JSON files (used by loader plugins)
 */
export interface CustomPayload {
  name: string;
  category: PayloadCategory;
  description?: string;
  payloads: string[];
  detectPatterns?: string[];
}

/**
 * Custom payload file schema
 */
export interface CustomPayloadFile {
  version?: string;
  payloads: CustomPayload[];
}

/**
 * Determine finding severity based on vulnerability category.
 *
 * Central mapping used by all drivers and plugins — single source of truth
 * so severity ratings remain consistent across Tier 1 (HTTP) and Tier 2 (browser) scans.
 */
export function getSeverity(
  category: PayloadCategory,
): "critical" | "high" | "medium" | "low" | "info" {
  switch (category) {
    case "sqli":
    case "command-injection":
    case "xxe":
      return "critical";
    case "xss":
    case "ssrf":
    case "path-traversal":
      return "high";
    case "open-redirect":
      return "medium";
    case "security-misconfiguration":
      return "low";
    case "information-disclosure":
      return "info";
    default:
      return "medium";
  }
}
