/**
 * @vulcn/plugin-passive
 * Passive Security Scanner for Vulcn
 *
 * Analyzes HTTP responses during session replay WITHOUT injecting
 * any payloads. Detects security misconfigurations by inspecting:
 *
 * 1. Security Headers — missing HSTS, CSP, X-Frame-Options, etc.
 * 2. Cookie Security — missing Secure, HttpOnly, SameSite flags
 * 3. Information Disclosure — server version, X-Powered-By, stack traces
 * 4. CORS Misconfiguration — wildcard origins, credential leaks
 * 5. Mixed Content — HTTP resources loaded on HTTPS pages
 *
 * This plugin is non-intrusive: it only observes network traffic
 * that occurs during normal session replay. No additional requests
 * are made, making it safe for production environments.
 *
 * Configuration:
 *   detectHeaders:   boolean  (default: true)
 *   detectCookies:   boolean  (default: true)
 *   detectInfoLeak:  boolean  (default: true)
 *   detectCors:      boolean  (default: true)
 *   detectMixed:     boolean  (default: true)
 *
 * Usage:
 *   vulcn run session.vulcn.yml --plugin @vulcn/plugin-passive
 */

import { z } from "zod";
import type {
  VulcnPlugin,
  PluginContext,
  DetectContext,
  PluginRunContext,
  Finding,
} from "@vulcn/engine";
import type { Response as PlaywrightResponse, Page } from "playwright";

// ── Configuration ──────────────────────────────────────────────────────

const configSchema = z.object({
  /**
   * Check for missing security response headers
   * @default true
   */
  detectHeaders: z.boolean().default(true),

  /**
   * Check for insecure cookie configurations
   * @default true
   */
  detectCookies: z.boolean().default(true),

  /**
   * Check for information disclosure in headers & responses
   * @default true
   */
  detectInfoLeak: z.boolean().default(true),

  /**
   * Check for CORS misconfigurations
   * @default true
   */
  detectCors: z.boolean().default(true),

  /**
   * Check for mixed content (HTTP on HTTPS pages)
   * @default true
   */
  detectMixed: z.boolean().default(true),

  /**
   * Severity for missing security headers
   * @default "medium"
   */
  headerSeverity: z
    .enum(["critical", "high", "medium", "low", "info"])
    .default("medium"),

  /**
   * Severity for insecure cookies
   * @default "medium"
   */
  cookieSeverity: z
    .enum(["critical", "high", "medium", "low", "info"])
    .default("medium"),

  /**
   * Severity for info disclosure
   * @default "low"
   */
  infoLeakSeverity: z
    .enum(["critical", "high", "medium", "low", "info"])
    .default("low"),

  /**
   * Severity for CORS issues
   * @default "high"
   */
  corsSeverity: z
    .enum(["critical", "high", "medium", "low", "info"])
    .default("high"),

  /**
   * Severity for mixed content
   * @default "medium"
   */
  mixedContentSeverity: z
    .enum(["critical", "high", "medium", "low", "info"])
    .default("medium"),
});

export type PassiveConfig = z.infer<typeof configSchema>;

// ── Security Header Checks ─────────────────────────────────────────────

/**
 * Security headers that should be present on HTML responses.
 * Each entry defines the header name, why it matters, and the CWE ID.
 */
interface HeaderCheck {
  /** HTTP header name (case-insensitive) */
  header: string;
  /** Human-readable title */
  title: string;
  /** What this header does */
  description: string;
  /** CWE reference */
  cwe: string;
  /** Optional: validate the value if present */
  validateValue?: (value: string) => string | null;
}

const SECURITY_HEADERS: HeaderCheck[] = [
  {
    header: "strict-transport-security",
    title: "Missing Strict-Transport-Security (HSTS)",
    description:
      "Without HSTS, the browser may connect over insecure HTTP on the first visit, allowing man-in-the-middle attacks. HSTS instructs browsers to always use HTTPS.",
    cwe: "CWE-319",
    validateValue: (value) => {
      if (!value.includes("max-age=")) {
        return "HSTS header is missing max-age directive";
      }
      const maxAge = parseInt(value.match(/max-age=(\d+)/)?.[1] ?? "0");
      if (maxAge < 31536000) {
        return `HSTS max-age is ${maxAge}s — recommend at least 31536000 (1 year)`;
      }
      return null;
    },
  },
  {
    header: "content-security-policy",
    title: "Missing Content-Security-Policy (CSP)",
    description:
      "Without CSP, the browser has no restrictions on script sources, style sources, or other resources. CSP is the most effective defense against XSS attacks.",
    cwe: "CWE-693",
    validateValue: (value) => {
      if (value.includes("'unsafe-inline'") && value.includes("script-src")) {
        return "CSP allows 'unsafe-inline' scripts — consider using nonces or hashes instead";
      }
      if (value.includes("'unsafe-eval'")) {
        return "CSP allows 'unsafe-eval' — this weakens XSS protections significantly";
      }
      return null;
    },
  },
  {
    header: "x-content-type-options",
    title: "Missing X-Content-Type-Options",
    description:
      "Without this header set to 'nosniff', browsers may MIME-sniff content types, potentially executing scripts from non-script MIME types.",
    cwe: "CWE-16",
    validateValue: (value) => {
      if (value.toLowerCase() !== "nosniff") {
        return `X-Content-Type-Options should be 'nosniff', got '${value}'`;
      }
      return null;
    },
  },
  {
    header: "x-frame-options",
    title: "Missing X-Frame-Options",
    description:
      "Without X-Frame-Options, the page can be embedded in iframes on other domains, enabling clickjacking attacks.",
    cwe: "CWE-1021",
    validateValue: (value) => {
      const upper = value.toUpperCase();
      if (upper !== "DENY" && upper !== "SAMEORIGIN") {
        return `X-Frame-Options should be 'DENY' or 'SAMEORIGIN', got '${value}'`;
      }
      return null;
    },
  },
  {
    header: "referrer-policy",
    title: "Missing Referrer-Policy",
    description:
      "Without Referrer-Policy, the browser may leak the full URL (including query parameters) to third-party sites through the Referer header.",
    cwe: "CWE-200",
  },
  {
    header: "permissions-policy",
    title: "Missing Permissions-Policy",
    description:
      "Without Permissions-Policy (formerly Feature-Policy), the page and embedded iframes can access browser features like camera, microphone, and geolocation.",
    cwe: "CWE-16",
  },
];

// ── Information Disclosure ─────────────────────────────────────────────

/**
 * Headers that may reveal server implementation details
 */
interface InfoLeakPattern {
  /** HTTP header to check (case-insensitive) */
  header: string;
  /** What this reveals */
  title: string;
  /** Why it matters */
  description: string;
  /** Optional: only flag if value matches this pattern */
  pattern?: RegExp;
}

const INFO_LEAK_HEADERS: InfoLeakPattern[] = [
  {
    header: "server",
    title: "Server Version Disclosed",
    description:
      "The Server header reveals the web server software and version, helping attackers identify known vulnerabilities for that specific version.",
    pattern: /\//, // Only flag if it contains a version (e.g., "nginx/1.21.4")
  },
  {
    header: "x-powered-by",
    title: "Technology Stack Disclosed (X-Powered-By)",
    description:
      "The X-Powered-By header reveals the application framework (e.g., Express, PHP, ASP.NET), helping attackers target framework-specific vulnerabilities.",
  },
  {
    header: "x-aspnet-version",
    title: "ASP.NET Version Disclosed",
    description:
      "The X-AspNet-Version header reveals the exact ASP.NET version, enabling targeted attacks against known vulnerabilities.",
  },
  {
    header: "x-aspnetmvc-version",
    title: "ASP.NET MVC Version Disclosed",
    description:
      "The X-AspNetMvc-Version header reveals the exact MVC framework version.",
  },
  {
    header: "x-debug-token",
    title: "Debug Token Exposed",
    description:
      "The X-Debug-Token header suggests debug mode is enabled in production, potentially exposing sensitive diagnostic information.",
  },
  {
    header: "x-debug-token-link",
    title: "Debug Profiler Link Exposed",
    description:
      "The X-Debug-Token-Link header provides a direct link to the debug profiler, which may expose internal application state and credentials.",
  },
];

// ── Cookie Security ────────────────────────────────────────────────────

/**
 * Checks for insecure cookie attributes.
 * Parses Set-Cookie headers and validates flags.
 */
interface CookieIssue {
  cookie: string;
  issue: string;
  description: string;
}

function checkCookieSecurity(
  setCookieHeaders: string[],
  isHttps: boolean,
): CookieIssue[] {
  const issues: CookieIssue[] = [];

  for (const header of setCookieHeaders) {
    const parts = header.split(";").map((p) => p.trim());
    const nameValue = parts[0];
    const name = nameValue?.split("=")?.[0]?.trim() ?? "unknown";
    const flags = parts.slice(1).map((f) => f.toLowerCase().trim());

    // Skip session-less cookies (very short-lived or tracking)
    if (name.startsWith("_ga") || name.startsWith("_gid")) continue;

    // Check for missing Secure flag on HTTPS sites
    if (isHttps && !flags.some((f) => f === "secure")) {
      issues.push({
        cookie: name,
        issue: "Missing Secure flag",
        description: `Cookie '${name}' is set without the Secure flag on an HTTPS site. It may be transmitted over unencrypted HTTP connections, exposing session data.`,
      });
    }

    // Check for missing HttpOnly (mostly relevant for session cookies)
    const isLikelySession = /session|sid|token|auth|jwt|csrf/i.test(name);
    if (isLikelySession && !flags.some((f) => f === "httponly")) {
      issues.push({
        cookie: name,
        issue: "Missing HttpOnly flag",
        description: `Session cookie '${name}' is set without the HttpOnly flag. JavaScript can access this cookie via document.cookie, enabling session theft through XSS.`,
      });
    }

    // Check for missing SameSite
    if (!flags.some((f) => f.startsWith("samesite"))) {
      issues.push({
        cookie: name,
        issue: "Missing SameSite attribute",
        description: `Cookie '${name}' is set without a SameSite attribute. Without SameSite, the cookie is sent with cross-site requests, enabling CSRF attacks.`,
      });
    }

    // Check for SameSite=None without Secure
    const sameSiteFlag = flags.find((f) => f.startsWith("samesite="));
    if (sameSiteFlag?.includes("none") && !flags.some((f) => f === "secure")) {
      issues.push({
        cookie: name,
        issue: "SameSite=None without Secure",
        description: `Cookie '${name}' uses SameSite=None but lacks the Secure flag. Browsers will reject this cookie, breaking cross-site functionality.`,
      });
    }
  }

  return issues;
}

// ── CORS Check ─────────────────────────────────────────────────────────

interface CorsIssue {
  title: string;
  description: string;
  evidence: string;
}

function checkCors(headers: Map<string, string>): CorsIssue[] {
  const issues: CorsIssue[] = [];
  const allowOrigin = headers.get("access-control-allow-origin");
  const allowCredentials = headers.get("access-control-allow-credentials");

  if (allowOrigin === "*") {
    issues.push({
      title: "CORS: Wildcard Access-Control-Allow-Origin",
      description:
        "The server responds with 'Access-Control-Allow-Origin: *', allowing any website to make cross-origin requests. While this is intentional for public APIs, it can be dangerous for authenticated endpoints.",
      evidence: "Access-Control-Allow-Origin: *",
    });

    if (allowCredentials?.toLowerCase() === "true") {
      issues.push({
        title: "CORS: Wildcard origin with credentials",
        description:
          "CRITICAL: The server allows credentials (cookies, authorization headers) with a wildcard origin. This effectively bypasses same-origin policy for all authenticated requests.",
        evidence:
          "Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
      });
    }
  }

  // Check for overly permissive reflected origin without validation
  if (
    allowOrigin &&
    allowOrigin !== "*" &&
    allowCredentials?.toLowerCase() === "true"
  ) {
    // If the origin is reflected back verbatim, it might be a misconfiguration
    // We can detect this by checking if Origin header was set in the request
    // For passive scanning, flag it as informational if credentials are allowed
    issues.push({
      title: "CORS: Credentials allowed with specific origin",
      description:
        "The server allows credentials with a specific origin. Verify this origin is trusted and the server properly validates the Origin header, not just reflecting it back.",
      evidence: `Access-Control-Allow-Origin: ${allowOrigin} + Access-Control-Allow-Credentials: true`,
    });
  }

  return issues;
}

// ── State tracking ─────────────────────────────────────────────────────

/**
 * Track which URLs/findings we've already reported to avoid duplicates.
 * Key: finding fingerprint (type + url + issue)
 */
const reportedFindings = new Set<string>();

/**
 * Track URLs we've analyzed to avoid re-scanning
 */
const analyzedUrls = new Set<string>();

// ── Utility ────────────────────────────────────────────────────────────

/**
 * Check if a URL is for a static asset
 */
function isStaticAsset(url: string): boolean {
  const STATIC_EXTENSIONS = [
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".webp",
    ".avif",
    ".mp4",
    ".webm",
    ".mp3",
  ];
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return STATIC_EXTENSIONS.some((ext) => pathname.endsWith(ext));
  } catch {
    return false;
  }
}

/**
 * Check if a response is an HTML document
 */
function isHtmlResponse(contentType: string | null): boolean {
  if (!contentType) return false;
  return contentType.includes("text/html");
}

/**
 * Create a deduplication key for a finding
 */
function findingKey(type: string, url: string, issue: string): string {
  return `${type}::${url}::${issue}`;
}

/**
 * Get the origin (scheme + host) from a URL
 */
function getOrigin(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return url;
  }
}

// ── Plugin ─────────────────────────────────────────────────────────────

const plugin: VulcnPlugin = {
  name: "@vulcn/plugin-passive",
  version: "0.1.0",
  apiVersion: 1,
  description:
    "Passive security scanner — detects missing security headers, insecure cookies, information disclosure, CORS issues, and mixed content",

  configSchema,

  hooks: {
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      const modes = [
        config.detectHeaders && "headers",
        config.detectCookies && "cookies",
        config.detectInfoLeak && "info-leak",
        config.detectCors && "cors",
        config.detectMixed && "mixed-content",
      ].filter(Boolean);

      ctx.logger.info(
        `Passive scanner initialized — checks: ${modes.join(", ")}`,
      );
    },

    /**
     * Hook into session replay — listen for network responses
     * and analyze them passively.
     */
    onRunStart: async (ctx: PluginRunContext) => {
      const config = configSchema.parse(ctx.config);
      const page = ctx.page as Page;

      // Clear state from previous runs
      reportedFindings.clear();
      analyzedUrls.clear();

      // Listen for all network responses
      page.on("response", async (response: PlaywrightResponse) => {
        try {
          const url = response.url();
          const status = response.status();

          // Skip already-analyzed URLs, redirects, and static assets
          if (analyzedUrls.has(url)) return;
          if (status >= 300 && status < 400) return;
          if (isStaticAsset(url)) return;

          analyzedUrls.add(url);

          // Collect headers (case-insensitive map)
          const allHeaders = await response.allHeaders();
          const headers = new Map<string, string>();
          for (const [key, value] of Object.entries(allHeaders)) {
            headers.set(key.toLowerCase(), value);
          }

          const contentType = headers.get("content-type") ?? null;
          const isHttps = url.startsWith("https://");
          const isHtml = isHtmlResponse(contentType);
          const origin = getOrigin(url);

          // ── 1. Security Headers (HTML responses only) ──────────────
          if (config.detectHeaders && isHtml) {
            for (const check of SECURITY_HEADERS) {
              const value = headers.get(check.header);

              if (!value) {
                // Header is missing entirely
                const key = findingKey("header-missing", origin, check.header);
                if (!reportedFindings.has(key)) {
                  reportedFindings.add(key);
                  ctx.findings.push({
                    type: "security-misconfiguration",
                    severity: config.headerSeverity,
                    title: check.title,
                    description: check.description,
                    stepId: "passive-scan",
                    payload: "",
                    url,
                    evidence: `Missing header: ${check.header}`,
                    metadata: {
                      detectionMethod: "passive",
                      category: "security-headers",
                      cwe: check.cwe,
                      header: check.header,
                    },
                  });
                }
              } else if (check.validateValue) {
                // Header is present but may have a weak value
                const issue = check.validateValue(value);
                if (issue) {
                  const key = findingKey("header-weak", origin, issue);
                  if (!reportedFindings.has(key)) {
                    reportedFindings.add(key);
                    ctx.findings.push({
                      type: "security-misconfiguration",
                      severity: config.headerSeverity,
                      title: `Weak ${check.header}`,
                      description: issue,
                      stepId: "passive-scan",
                      payload: "",
                      url,
                      evidence: `${check.header}: ${value}`,
                      metadata: {
                        detectionMethod: "passive",
                        category: "security-headers",
                        cwe: check.cwe,
                        header: check.header,
                        headerValue: value,
                      },
                    });
                  }
                }
              }
            }
          }

          // ── 2. Cookie Security ─────────────────────────────────────
          if (config.detectCookies) {
            const setCookie = headers.get("set-cookie");
            if (setCookie) {
              // Split multiple Set-Cookie headers (they may be joined)
              const cookies = setCookie.split(/,(?=\s*\w+=)/);
              const issues = checkCookieSecurity(cookies, isHttps);

              for (const issue of issues) {
                const key = findingKey(
                  "cookie",
                  origin,
                  `${issue.cookie}:${issue.issue}`,
                );
                if (!reportedFindings.has(key)) {
                  reportedFindings.add(key);
                  ctx.findings.push({
                    type: "security-misconfiguration",
                    severity: config.cookieSeverity,
                    title: `Cookie: ${issue.issue} — ${issue.cookie}`,
                    description: issue.description,
                    stepId: "passive-scan",
                    payload: "",
                    url,
                    evidence: `Set-Cookie: ${issue.cookie}=... (${issue.issue})`,
                    metadata: {
                      detectionMethod: "passive",
                      category: "cookie-security",
                      cwe: "CWE-614",
                      cookieName: issue.cookie,
                      issue: issue.issue,
                    },
                  });
                }
              }
            }
          }

          // ── 3. Information Disclosure ───────────────────────────────
          if (config.detectInfoLeak) {
            for (const leak of INFO_LEAK_HEADERS) {
              const value = headers.get(leak.header);
              if (!value) continue;

              // If there's a pattern, only flag if it matches
              if (leak.pattern && !leak.pattern.test(value)) continue;

              const key = findingKey("info-leak", origin, leak.header);
              if (!reportedFindings.has(key)) {
                reportedFindings.add(key);
                ctx.findings.push({
                  type: "information-disclosure",
                  severity: config.infoLeakSeverity,
                  title: leak.title,
                  description: leak.description,
                  stepId: "passive-scan",
                  payload: "",
                  url,
                  evidence: `${leak.header}: ${value}`,
                  metadata: {
                    detectionMethod: "passive",
                    category: "information-disclosure",
                    cwe: "CWE-200",
                    header: leak.header,
                    headerValue: value,
                  },
                });
              }
            }
          }

          // ── 4. CORS Misconfiguration ───────────────────────────────
          if (config.detectCors) {
            const corsIssues = checkCors(headers);
            for (const issue of corsIssues) {
              const key = findingKey("cors", origin, issue.title);
              if (!reportedFindings.has(key)) {
                reportedFindings.add(key);

                // Wildcard + credentials is critical
                const severity = issue.title.includes("credentials")
                  ? "critical"
                  : config.corsSeverity;

                ctx.findings.push({
                  type: "security-misconfiguration",
                  severity,
                  title: issue.title,
                  description: issue.description,
                  stepId: "passive-scan",
                  payload: "",
                  url,
                  evidence: issue.evidence,
                  metadata: {
                    detectionMethod: "passive",
                    category: "cors",
                    cwe: "CWE-942",
                  },
                });
              }
            }
          }

          // ── 5. Mixed Content ───────────────────────────────────────
          if (config.detectMixed && isHttps) {
            // Check if this HTTPS page loaded any HTTP resources
            // We detect this by checking if the response itself is HTTP on an HTTPS page
            // (the response listener sees all sub-resources too)
            if (
              url.startsWith("http://") &&
              !url.startsWith("http://localhost")
            ) {
              const key = findingKey("mixed-content", url, "http-resource");
              if (!reportedFindings.has(key)) {
                reportedFindings.add(key);
                ctx.findings.push({
                  type: "security-misconfiguration",
                  severity: config.mixedContentSeverity,
                  title: "Mixed Content: HTTP resource on HTTPS page",
                  description: `An HTTPS page loaded a resource over insecure HTTP. This allows attackers to intercept or modify the resource via man-in-the-middle attacks, potentially compromising the entire page.`,
                  stepId: "passive-scan",
                  payload: "",
                  url,
                  evidence: `HTTP resource: ${url}`,
                  metadata: {
                    detectionMethod: "passive",
                    category: "mixed-content",
                    cwe: "CWE-311",
                  },
                });
              }
            }
          }
        } catch {
          // Response analysis failed — skip silently
        }
      });

      ctx.logger.info("🔍 Passive scanner listening for network responses...");
    },

    onRunEnd: async (_result, ctx: PluginRunContext) => {
      const passiveFindings = ctx.findings.filter(
        (f) =>
          (f.metadata as Record<string, unknown>)?.detectionMethod ===
          "passive",
      );

      if (passiveFindings.length > 0) {
        ctx.logger.info(
          `🛡️  Passive scan complete — ${passiveFindings.length} issue${passiveFindings.length === 1 ? "" : "s"} found`,
        );
      } else {
        ctx.logger.info("🛡️  Passive scan complete — no issues found");
      }

      return _result;
    },

    onDestroy: async () => {
      reportedFindings.clear();
      analyzedUrls.clear();
    },
  },
};

export default plugin;
export { configSchema };
export type { HeaderCheck, CookieIssue, CorsIssue };
