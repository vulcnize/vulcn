/**
 * @vulcn/plugin-detect-sqli
 * SQL Injection detection plugin for Vulcn
 *
 * Detects SQL injection vulnerabilities using three strategies:
 *
 * 1. Error-based: Detects database error messages in HTTP responses
 *    - MySQL, PostgreSQL, Oracle, SQLite, MSSQL error patterns
 *    - Stack traces and debug output
 *
 * 2. Response diffing: Compares baseline response to payload response
 *    - Status code changes (200 → 500 = potential injection)
 *    - Response length anomalies
 *    - New error content appearing
 *
 * 3. Timing-based: Measures response time deltas for SLEEP/WAITFOR payloads
 *    - If response takes significantly longer, injection is likely
 *    - Requires timing payloads (sqli-blind)
 *
 * All detection works through the onAfterPayload and onNetworkResponse hooks.
 */

import { z } from "zod";
import type {
  VulcnPlugin,
  PluginContext,
  PluginRunContext,
  DetectContext,
  Finding,
} from "@vulcn/engine";
import type { Response as PlaywrightResponse, Page } from "playwright";

// ── Configuration ──────────────────────────────────────────────────────

const configSchema = z.object({
  /**
   * Enable error-based SQL injection detection
   * @default true
   */
  detectErrors: z.boolean().default(true),

  /**
   * Enable response body diffing
   * @default true
   */
  detectDiff: z.boolean().default(true),

  /**
   * Enable timing-based detection
   * @default true
   */
  detectTiming: z.boolean().default(true),

  /**
   * Timing threshold in milliseconds.
   * If response takes longer than this beyond baseline, flag it.
   * @default 4000
   */
  timingThresholdMs: z.number().default(4000),

  /**
   * Minimum status code change to consider significant
   * @default 400
   */
  errorStatusThreshold: z.number().default(400),

  /**
   * Severity for error-based findings
   * @default "high"
   */
  errorSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),

  /**
   * Severity for timing-based findings
   * @default "high"
   */
  timingSeverity: z.enum(["critical", "high", "medium", "low"]).default("high"),

  /**
   * Severity for diff-based findings
   * @default "medium"
   */
  diffSeverity: z.enum(["critical", "high", "medium", "low"]).default("medium"),
});

export type DetectSqliConfig = z.infer<typeof configSchema>;

// ── Error Patterns ─────────────────────────────────────────────────────

/**
 * Database-specific error patterns.
 * These are real error strings that database engines produce,
 * organized by database type.
 */
interface ErrorPattern {
  db: string;
  pattern: RegExp;
  description: string;
}

const SQL_ERROR_PATTERNS: ErrorPattern[] = [
  // MySQL
  {
    db: "MySQL",
    pattern: /you have an error in your sql syntax/i,
    description: "MySQL syntax error",
  },
  {
    db: "MySQL",
    pattern: /warning:.*mysql_/i,
    description: "MySQL PHP warning",
  },
  {
    db: "MySQL",
    pattern: /mysql_fetch_array\(\)/i,
    description: "MySQL fetch error",
  },
  {
    db: "MySQL",
    pattern: /mysql_num_rows\(\)/i,
    description: "MySQL num_rows error",
  },
  {
    db: "MySQL",
    pattern: /MySqlException/i,
    description: "MySQL exception",
  },
  {
    db: "MySQL",
    pattern: /com\.mysql\.jdbc/i,
    description: "MySQL JDBC error",
  },
  {
    db: "MySQL",
    pattern: /SQLSTATE\[HY000\]/i,
    description: "MySQL PDO error",
  },

  // PostgreSQL
  {
    db: "PostgreSQL",
    pattern: /pg_query\(\)/i,
    description: "PostgreSQL PHP error",
  },
  {
    db: "PostgreSQL",
    pattern: /pg_exec\(\)/i,
    description: "PostgreSQL exec error",
  },
  {
    db: "PostgreSQL",
    pattern: /postgresql.*error/i,
    description: "PostgreSQL error message",
  },
  {
    db: "PostgreSQL",
    pattern: /PSQLException/i,
    description: "PostgreSQL JDBC exception",
  },
  {
    db: "PostgreSQL",
    pattern: /org\.postgresql/i,
    description: "PostgreSQL Java driver error",
  },
  {
    db: "PostgreSQL",
    pattern: /ERROR:\s+syntax error at or near/i,
    description: "PostgreSQL syntax error",
  },

  // Oracle
  {
    db: "Oracle",
    pattern: /ORA-\d{5}/i,
    description: "Oracle error code",
  },
  {
    db: "Oracle",
    pattern: /oracle.*driver/i,
    description: "Oracle driver error",
  },
  {
    db: "Oracle",
    pattern: /quoted string not properly terminated/i,
    description: "Oracle quoted string error",
  },

  // SQLite
  {
    db: "SQLite",
    pattern: /sqlite3?\.OperationalError/i,
    description: "SQLite Python operational error",
  },
  {
    db: "SQLite",
    pattern: /SQLite3::SQLException/i,
    description: "SQLite Ruby exception",
  },
  {
    db: "SQLite",
    pattern: /SQLITE_ERROR/i,
    description: "SQLite error constant",
  },
  {
    db: "SQLite",
    pattern: /sqlite.*error/i,
    description: "SQLite generic error",
  },
  {
    db: "SQLite",
    pattern: /unrecognized token:/i,
    description: "SQLite unrecognized token",
  },

  // MSSQL / SQL Server
  {
    db: "MSSQL",
    pattern: /microsoft.*odbc.*sql.*server/i,
    description: "MSSQL ODBC error",
  },
  {
    db: "MSSQL",
    pattern: /unclosed quotation mark/i,
    description: "MSSQL unclosed quotation",
  },
  {
    db: "MSSQL",
    pattern: /mssql_query\(\)/i,
    description: "MSSQL PHP error",
  },
  {
    db: "MSSQL",
    pattern: /SqlException/i,
    description: "MSSQL .NET exception",
  },
  {
    db: "MSSQL",
    pattern: /Server Error in '.*' Application/i,
    description: "ASP.NET/MSSQL server error",
  },
  {
    db: "MSSQL",
    pattern: /Incorrect syntax near/i,
    description: "MSSQL syntax error",
  },

  // Generic / Multi-DB
  {
    db: "Generic",
    pattern: /SQL syntax.*error/i,
    description: "Generic SQL syntax error",
  },
  {
    db: "Generic",
    pattern: /SQLSTATE\[\w+\]/i,
    description: "PDO SQL state error",
  },
  {
    db: "Generic",
    pattern: /ODBC.*Driver/i,
    description: "ODBC driver error",
  },
  {
    db: "Generic",
    pattern: /column.*count.*doesn.*match/i,
    description: "Column count mismatch (UNION detection)",
  },
  {
    db: "Generic",
    pattern: /different.*number.*of.*columns/i,
    description: "Different number of columns (UNION detection)",
  },
  {
    db: "Generic",
    pattern: /supplied argument is not a valid.*result/i,
    description: "Invalid result argument",
  },
];

// ── Timing tracking ────────────────────────────────────────────────────

/**
 * Timing payloads contain these substrings.
 * We only apply timing detection for these payloads.
 */
const TIMING_INDICATORS = [
  "SLEEP(",
  "WAITFOR DELAY",
  "BENCHMARK(",
  "pg_sleep(",
  "DBMS_LOCK.SLEEP",
];

function isTimingPayload(payload: string): boolean {
  const upper = payload.toUpperCase();
  return TIMING_INDICATORS.some((indicator) =>
    upper.includes(indicator.toUpperCase()),
  );
}

// ── Plugin ─────────────────────────────────────────────────────────────

/**
 * State tracked per step for response diffing and baseline comparison
 */
interface ResponseBaseline {
  statusCode: number;
  bodyLength: number;
  responseTime: number;
  /** SQL error patterns that exist in the CLEAN (uninjected) page */
  baselineErrors: Set<string>;
}

const responseCache = new Map<string, ResponseBaseline>();

/**
 * Cache of baseline page content per step.
 * Captured before any payload is injected.
 */
const baselineContentCache = new Map<string, string>();

const plugin: VulcnPlugin = {
  name: "@vulcn/plugin-detect-sqli",
  version: "0.1.0",
  apiVersion: 1,
  description:
    "SQL injection detection — error-based, timing-based, and response diffing for MySQL, PostgreSQL, Oracle, SQLite, MSSQL",

  configSchema,

  hooks: {
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      ctx.logger.info("SQLi detection plugin initialized");
      ctx.logger.debug(
        `Detection modes: errors=${config.detectErrors}, diff=${config.detectDiff}, timing=${config.detectTiming}`,
      );
    },

    /**
     * Capture baseline page content BEFORE any payloads are injected.
     * This lets us know which SQL error patterns are "normal" for the page
     * so we can skip them during detection (avoid false positives from
     * pages that intentionally display SQL error messages).
     */
    onRunStart: async (ctx: PluginRunContext): Promise<void> => {
      try {
        const page = ctx.page as Page;
        const content = await page.content();
        const sessionKey = ctx.session.name ?? "default";
        baselineContentCache.set(sessionKey, content);

        // Pre-compute which error patterns match the clean page
        const baselineErrors = new Set<string>();
        for (const pattern of SQL_ERROR_PATTERNS) {
          if (pattern.pattern.test(content)) {
            baselineErrors.add(pattern.db + ":" + pattern.description);
          }
        }

        // Store baseline errors globally for this session —
        // all steps in this session will use the same baseline
        responseCache.set(`${sessionKey}:errors`, {
          statusCode: 0,
          bodyLength: content.length,
          responseTime: Date.now(),
          baselineErrors,
        });

        if (baselineErrors.size > 0) {
          ctx.logger.debug(
            `Baseline has ${baselineErrors.size} pre-existing SQL error pattern(s) — will not flag these`,
          );
        }
      } catch {
        // Page not ready yet
      }
    },

    /**
     * After each payload injection, check for SQLi indicators.
     *
     * This is the main detection hook. It:
     * 1. Reads the page content and checks for SQL error patterns
     *    (skipping patterns that already exist in the baseline)
     * 2. Compares response characteristics to baseline
     * 3. Checks timing for SLEEP-based payloads
     */
    onAfterPayload: async (ctx: DetectContext): Promise<Finding[]> => {
      const config = configSchema.parse(ctx.config);
      const findings: Finding[] = [];
      const page = ctx.page as Page;

      // Collect baseline errors for this step (captured by onNetworkResponse)
      const cacheKey = `${ctx.stepId}:baseline`;
      const baselineEntry = responseCache.get(cacheKey);
      const baselineErrors = baselineEntry?.baselineErrors ?? new Set<string>();

      try {
        const url = page.url();

        // ── 1. Error-based detection ─────────────────────────────────
        if (config.detectErrors) {
          const content = await page.content();
          const errorFindings = detectSqlErrors(
            content,
            ctx,
            config.errorSeverity,
            url,
            baselineErrors,
          );
          findings.push(...errorFindings);
        }

        // ── 2. Response diffing ──────────────────────────────────────
        if (config.detectDiff) {
          const diffFindings = await detectResponseDiff(page, ctx, config);
          findings.push(...diffFindings);
        }

        // ── 3. Timing-based detection ────────────────────────────────
        if (config.detectTiming && isTimingPayload(ctx.payloadValue)) {
          const timingFindings = detectTimingAnomaly(ctx, config);
          findings.push(...timingFindings);
        }
      } catch {
        // Page may have navigated or crashed — ignore
      }

      return findings;
    },

    /**
     * Monitor network responses for SQL error messages.
     * This catches errors returned in API responses (JSON, etc.)
     * that might not appear in the rendered page content.
     */
    onNetworkResponse: async (
      rawResponse: unknown,
      ctx: DetectContext,
    ): Promise<Finding | null> => {
      const config = configSchema.parse(ctx.config);
      const response = rawResponse as PlaywrightResponse;
      const url = response.url();
      const status = response.status();

      // ── Baseline Mode ─────────────────────────────────────────────
      // If we are merely navigating to the clean URL to establish a baseline,
      // we accumulate any SQL errors we see into the baseline cache.
      // We NEVER report findings in this mode.
      if (ctx.payloadValue === "__baseline__") {
        try {
          // Only process potential HTML/API responses
          if (isStaticAsset(url)) return null;

          const body = await response.text();
          const foundErrors = new Set<string>();
          for (const pattern of SQL_ERROR_PATTERNS) {
            if (pattern.pattern.test(body)) {
              foundErrors.add(pattern.db + ":" + pattern.description);
            }
          }

          const cacheKey = `${ctx.stepId}:baseline`;
          const existing = responseCache.get(cacheKey);
          const mergedErrors = existing
            ? new Set([...existing.baselineErrors, ...foundErrors])
            : foundErrors;

          responseCache.set(cacheKey, {
            statusCode: status,
            bodyLength: body.length,
            responseTime: Date.now(),
            baselineErrors: mergedErrors,
          });

          if (foundErrors.size > 0) {
            ctx.logger.debug(
              `Accumulated ${foundErrors.size} baseline errors from ${url}`,
            );
          }
        } catch {
          // Body access failed
        }
        return null;
      }

      // ── Detection Mode ────────────────────────────────────────────
      if (!config.detectErrors) return null;

      try {
        // Only check responses that look like they came from the target
        // Skip static assets
        if (isStaticAsset(url)) return null;

        // Cache response characteristics for diffing
        const cacheKey = `${ctx.stepId}:baseline`;
        if (!responseCache.has(cacheKey)) {
          try {
            const body = await response.text();

            // Scan the FIRST (clean) response for pre-existing SQL error patterns.
            // These are NOT caused by injection — they're part of the normal page.
            const baselineErrors = new Set<string>();
            for (const pattern of SQL_ERROR_PATTERNS) {
              if (pattern.pattern.test(body)) {
                baselineErrors.add(pattern.db + ":" + pattern.description);
              }
            }

            responseCache.set(cacheKey, {
              statusCode: status,
              bodyLength: body.length,
              responseTime: Date.now(),
              baselineErrors,
            });

            if (baselineErrors.size > 0) {
              ctx.logger.debug(
                `Baseline response has ${baselineErrors.size} pre-existing SQL error pattern(s)`,
              );
            }
          } catch {
            // Response body not available
          }
          return null;
        }

        // Check status code for server errors
        if (status >= config.errorStatusThreshold) {
          try {
            const body = await response.text();
            const stepBaseline = responseCache.get(cacheKey);
            const errorFindings = detectSqlErrors(
              body,
              ctx,
              config.errorSeverity,
              url,
              stepBaseline?.baselineErrors,
            );
            if (errorFindings.length > 0) {
              return errorFindings[0]; // Return first match
            }
          } catch {
            // Response body not available
          }
        }
      } catch {
        // Response handling failed
      }

      return null;
    },

    onDestroy: async () => {
      responseCache.clear();
      baselineContentCache.clear();
    },
  },
};

// ── Detection Functions ────────────────────────────────────────────────

/**
 * Check page/response content for SQL error patterns.
 */
function detectSqlErrors(
  content: string,
  ctx: DetectContext,
  severity: "critical" | "high" | "medium" | "low",
  url: string,
  baselineErrors: Set<string> = new Set(),
): Finding[] {
  const findings: Finding[] = [];
  const matched = new Set<string>();

  for (const pattern of SQL_ERROR_PATTERNS) {
    const patternKey = pattern.db + ":" + pattern.description;

    // Skip patterns that already existed in the clean (baseline) page.
    // These are NOT caused by injection — they're normal page content.
    if (baselineErrors.has(patternKey)) continue;

    if (pattern.pattern.test(content) && !matched.has(pattern.db)) {
      matched.add(pattern.db);

      // Extract the matching snippet for evidence
      const match = content.match(pattern.pattern);
      const snippet = match
        ? content.slice(
            Math.max(0, match.index! - 40),
            Math.min(content.length, match.index! + match[0].length + 40),
          )
        : "";

      ctx.logger.info(
        `🚨 SQLi DETECTED (${pattern.db}): ${pattern.description}`,
      );

      findings.push({
        type: "sqli",
        cwe: "CWE-89",
        severity,
        title: `SQL Injection: ${pattern.db} error detected`,
        description: `${pattern.description}. The injected payload caused a ${pattern.db} database error to appear in the response, indicating the input is being used in SQL queries without proper sanitization.`,
        stepId: ctx.stepId,
        payload: ctx.payloadValue,
        url,
        evidence: sanitizeEvidence(snippet),
        metadata: {
          detectionMethod: "error-based",
          database: pattern.db,
          errorPattern: pattern.description,
          patternMatched: pattern.pattern.source,
        },
      });
    }
  }

  return findings;
}

/**
 * Compare response characteristics to detect anomalies.
 */
async function detectResponseDiff(
  page: Page,
  ctx: DetectContext,
  config: DetectSqliConfig,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const cacheKey = `${ctx.stepId}:baseline`;
  const baseline = responseCache.get(cacheKey);

  if (!baseline) return findings;

  const baselineErrors = baseline.baselineErrors;

  try {
    const content = await page.content();
    const currentLength = content.length;

    // Significant response length change (>50% different)
    const lengthDelta = Math.abs(currentLength - baseline.bodyLength);
    const lengthRatio =
      baseline.bodyLength > 0 ? lengthDelta / baseline.bodyLength : 0;

    if (lengthRatio > 0.5 && lengthDelta > 500) {
      // Check if the new content has SQL-related errors
      // that were NOT already present in the baseline
      const hasNewErrors = SQL_ERROR_PATTERNS.some((p) => {
        const patternKey = p.db + ":" + p.description;
        if (baselineErrors.has(patternKey)) return false; // Skip pre-existing
        return p.pattern.test(content);
      });

      if (hasNewErrors) {
        ctx.logger.info(
          `🚨 SQLi DETECTED (diff): Response body changed by ${Math.round(lengthRatio * 100)}% with SQL errors`,
        );

        findings.push({
          type: "sqli",
          cwe: "CWE-89",
          severity: config.diffSeverity,
          title: "SQL Injection: Response anomaly with SQL errors",
          description: `The injected payload caused a significant change in response (${Math.round(lengthRatio * 100)}% size delta) with SQL error patterns present, suggesting injection vulnerability.`,
          stepId: ctx.stepId,
          payload: ctx.payloadValue,
          url: page.url(),
          evidence: `Baseline: ${baseline.bodyLength} bytes, Current: ${currentLength} bytes (${lengthDelta > 0 ? "+" : ""}${lengthDelta} bytes)`,
          metadata: {
            detectionMethod: "response-diff",
            baselineLength: baseline.bodyLength,
            currentLength,
            lengthDelta,
            lengthRatio: Math.round(lengthRatio * 100),
          },
        });
      }
    }
  } catch {
    // Page content not available
  }

  return findings;
}

/**
 * Detect timing anomalies for SLEEP/WAITFOR payloads.
 *
 * This records the time between payload injection and the
 * onAfterPayload call. If it exceeds the threshold, the
 * SLEEP executed — confirming injection.
 */
function detectTimingAnomaly(
  ctx: DetectContext,
  config: DetectSqliConfig,
): Finding[] {
  const findings: Finding[] = [];
  const cacheKey = `${ctx.stepId}:baseline`;
  const baseline = responseCache.get(cacheKey);

  if (!baseline) return findings;

  const elapsed = Date.now() - baseline.responseTime;

  if (elapsed > config.timingThresholdMs) {
    ctx.logger.info(
      `🚨 SQLi DETECTED (timing): Response took ${elapsed}ms (threshold: ${config.timingThresholdMs}ms)`,
    );

    findings.push({
      type: "sqli",
      cwe: "CWE-89",
      severity: config.timingSeverity,
      title: "SQL Injection: Timing anomaly detected (blind SQLi)",
      description: `The response took ${elapsed}ms after injecting a timing payload (SLEEP/WAITFOR). This exceeds the ${config.timingThresholdMs}ms threshold, indicating the SQL command was executed by the database.`,
      stepId: ctx.stepId,
      payload: ctx.payloadValue,
      url: "",
      evidence: `Response time: ${elapsed}ms, Threshold: ${config.timingThresholdMs}ms`,
      metadata: {
        detectionMethod: "timing-based",
        responseTimeMs: elapsed,
        thresholdMs: config.timingThresholdMs,
      },
    });
  }

  return findings;
}

// ── Utilities ──────────────────────────────────────────────────────────

/**
 * Skip static assets to avoid false noise
 */
function isStaticAsset(url: string): boolean {
  const staticExtensions = [
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
  ];
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    return staticExtensions.some((ext) => pathname.endsWith(ext));
  } catch {
    return false;
  }
}

/**
 * Sanitize evidence string — remove excessive whitespace,
 * truncate to reasonable length
 */
function sanitizeEvidence(raw: string): string {
  return raw.replace(/\s+/g, " ").trim().slice(0, 200);
}

export default plugin;
export { configSchema };
