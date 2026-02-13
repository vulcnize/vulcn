/**
 * Vulcn Project Configuration — `.vulcn.yml` schema
 *
 * Single source of truth for all Vulcn configuration.
 * The CLI is a thin layer that passes this config to the engine.
 * Plugin names never appear here — the engine maps flat keys to plugins internally.
 */

import { z } from "zod";

// ── Scan settings ─────────────────────────────────────────────────────

const ScanConfigSchema = z
  .object({
    /** Browser engine to use */
    browser: z.enum(["chromium", "firefox", "webkit"]).default("chromium"),
    /** Run in headless mode */
    headless: z.boolean().default(true),
    /** Per-step timeout in ms */
    timeout: z.number().positive().default(30_000),
  })
  .default({});

// ── Payload settings ──────────────────────────────────────────────────

const PayloadsConfigSchema = z
  .object({
    /** Payload types to use */
    types: z
      .array(z.enum(["xss", "sqli", "xxe", "cmd", "redirect", "traversal"]))
      .default(["xss"]),
    /** Opt-in to PayloadsAllTheThings community payloads */
    payloadbox: z.boolean().default(false),
    /** Max payloads per type from PayloadBox */
    limit: z.number().positive().default(100),
    /** Path to custom payload YAML file (relative to project root) */
    custom: z.string().nullable().default(null),
  })
  .default({});

// ── Detection settings ────────────────────────────────────────────────

const XssDetectionSchema = z
  .object({
    /** Monitor alert/confirm/prompt dialogs */
    dialogs: z.boolean().default(true),
    /** Monitor console.log markers */
    console: z.boolean().default(true),
    /** Console marker prefix */
    consoleMarker: z.string().default("VULCN_XSS:"),
    /** Check for injected <script> elements */
    domMutation: z.boolean().default(false),
    /** Finding severity level */
    severity: z.enum(["critical", "high", "medium", "low"]).default("high"),
    /** Text patterns to match in alert messages */
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
  })
  .default({});

const ReflectionSeveritySchema = z
  .object({
    script: z.enum(["critical", "high", "medium", "low"]).default("critical"),
    attribute: z.enum(["critical", "high", "medium", "low"]).default("medium"),
    body: z.enum(["critical", "high", "medium", "low"]).default("low"),
  })
  .default({});

const ReflectionContextsSchema = z
  .object({
    script: z.boolean().default(true),
    attribute: z.boolean().default(true),
    body: z.boolean().default(true),
  })
  .default({});

const ReflectionDetectionSchema = z
  .object({
    /** Enable reflection detection */
    enabled: z.boolean().default(true),
    /** Minimum payload length to check */
    minLength: z.number().positive().default(4),
    /** Which HTML contexts to check for reflections */
    contexts: ReflectionContextsSchema,
    /** Severity per context */
    severity: ReflectionSeveritySchema,
  })
  .default({});

const DetectionConfigSchema = z
  .object({
    /** XSS detection settings */
    xss: XssDetectionSchema,
    /** Reflection detection settings */
    reflection: ReflectionDetectionSchema,
    /** Enable passive security checks (headers, cookies, info-disclosure) */
    passive: z.boolean().default(true),
  })
  .default({});

// ── Crawl settings ────────────────────────────────────────────────────

const CrawlConfigSchema = z
  .object({
    /** Maximum crawl depth */
    depth: z.number().nonnegative().default(2),
    /** Maximum pages to visit */
    maxPages: z.number().positive().default(20),
    /** Stay on same origin */
    sameOrigin: z.boolean().default(true),
    /** Per-page timeout in ms */
    timeout: z.number().positive().default(10_000),
  })
  .default({});

// ── Report settings ───────────────────────────────────────────────────

const ReportConfigSchema = z
  .object({
    /** Report format to generate */
    format: z
      .enum(["html", "json", "yaml", "sarif", "all"])
      .nullable()
      .default(null),
  })
  .default({});

// ── Auth settings ─────────────────────────────────────────────────────

const FormAuthSchema = z.object({
  strategy: z.literal("form"),
  /** Login page URL */
  loginUrl: z.string().url().optional(),
  /** CSS selector for username field */
  userSelector: z.string().nullable().default(null),
  /** CSS selector for password field */
  passSelector: z.string().nullable().default(null),
});

const HeaderAuthSchema = z.object({
  strategy: z.literal("header"),
  /** Headers to include in requests */
  headers: z.record(z.string()),
});

const AuthConfigSchema = z
  .discriminatedUnion("strategy", [FormAuthSchema, HeaderAuthSchema])
  .nullable()
  .default(null);

// ── Root config ───────────────────────────────────────────────────────

export const VulcnProjectConfigSchema = z.object({
  /** Target URL to scan */
  target: z.string().url().optional(),

  /** Scan settings (browser, headless, timeout) */
  scan: ScanConfigSchema,

  /** Payload configuration */
  payloads: PayloadsConfigSchema,

  /** Detection configuration */
  detection: DetectionConfigSchema,

  /** Crawl configuration */
  crawl: CrawlConfigSchema,

  /** Report configuration */
  report: ReportConfigSchema,

  /** Authentication configuration */
  auth: AuthConfigSchema,
});

/** Parsed and validated project config */
export type VulcnProjectConfig = z.infer<typeof VulcnProjectConfigSchema>;

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Parse and validate a raw config object (from YAML.parse).
 * All fields have defaults, so an empty object is valid.
 */
export function parseProjectConfig(raw: unknown): VulcnProjectConfig {
  return VulcnProjectConfigSchema.parse(raw);
}

/**
 * Default config for `vulcn init`.
 * Only includes fields that users are likely to customize.
 */
export const DEFAULT_PROJECT_CONFIG = {
  target: "https://example.com",

  scan: {
    browser: "chromium",
    headless: true,
    timeout: 30000,
  },

  payloads: {
    types: ["xss"],
  },

  detection: {
    xss: {
      dialogs: true,
      console: true,
      domMutation: false,
      severity: "high",
    },
    reflection: {
      enabled: true,
    },
    passive: true,
  },

  crawl: {
    depth: 2,
    maxPages: 20,
    sameOrigin: true,
  },

  report: {
    format: "html",
  },
} as const;
