/**
 * PayloadBox Loader
 *
 * Fetches payloads from PayloadsAllTheThings GitHub repository.
 * This is the primary payload source for Vulcn — community-curated,
 * battle-tested payloads from the largest security payload collection.
 *
 * Supports short aliases for convenience:
 *   xss, sqli, xxe, cmd, redirect, traversal
 */

import type { RuntimePayload, PayloadCategory } from "@vulcn/engine";

/**
 * Canonical PayloadBox type names (as they appear in PayloadsAllTheThings)
 */
export type PayloadBoxType =
  | "xss"
  | "sql-injection"
  | "xxe"
  | "command-injection"
  | "open-redirect"
  | "path-traversal";

/**
 * Short aliases → canonical PayloadBox types
 *
 * Users can use either:
 *   vulcn run session.yml -p xss sqli
 *   vulcn run session.yml -p sql-injection command-injection
 */
const ALIASES: Record<string, PayloadBoxType> = {
  // Short aliases
  xss: "xss",
  sqli: "sql-injection",
  sql: "sql-injection",
  xxe: "xxe",
  cmd: "command-injection",
  command: "command-injection",
  redirect: "open-redirect",
  traversal: "path-traversal",
  lfi: "path-traversal",

  // Full names (identity mapping)
  "sql-injection": "sql-injection",
  "command-injection": "command-injection",
  "open-redirect": "open-redirect",
  "path-traversal": "path-traversal",
};

/**
 * PayloadsAllTheThings URLs - raw GitHub content
 */
const PAYLOADBOX_URLS: Record<PayloadBoxType, string> = {
  xss: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/XSS%20Injection/Intruders/IntrudersXSS.txt",
  "sql-injection":
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
  xxe: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/XXE%20Injection/Intruders/xxe_payloads.txt",
  "command-injection":
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/Command%20Injection/Intruder/command_exec.txt",
  "open-redirect":
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/Open%20Redirect/Intruder/Open-Redirect-payloads.txt",
  "path-traversal":
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/Directory%20Traversal/Intruder/traversals-8-deep-exotic-encoding.txt",
};

/**
 * Map PayloadBox types to internal categories
 */
const CATEGORY_MAP: Record<PayloadBoxType, PayloadCategory> = {
  xss: "xss",
  "sql-injection": "sqli",
  xxe: "xxe",
  "command-injection": "command-injection",
  "open-redirect": "open-redirect",
  "path-traversal": "path-traversal",
};

/**
 * Human-readable descriptions
 */
const DESCRIPTIONS: Record<PayloadBoxType, string> = {
  xss: "Cross-Site Scripting — script injection, event handlers, SVG payloads",
  "sql-injection": "SQL Injection — auth bypass, UNION, error-based, blind",
  xxe: "XML External Entity — file read, SSRF via XML",
  "command-injection": "OS Command Injection — shell execution, pipe injection",
  "open-redirect": "Open Redirect — URL redirect to attacker domain",
  "path-traversal":
    "Path Traversal — directory traversal with exotic encodings",
};

/**
 * Cache for fetched payloads
 */
const cache: Map<PayloadBoxType, RuntimePayload> = new Map();

// ── Public API ─────────────────────────────────────────────────────────

/**
 * Get all available payload type names (canonical)
 */
export function getPayloadBoxTypes(): PayloadBoxType[] {
  return Object.keys(PAYLOADBOX_URLS) as PayloadBoxType[];
}

/**
 * Get all short aliases
 */
export function getAliases(): Record<string, PayloadBoxType> {
  return { ...ALIASES };
}

/**
 * Resolve a user-provided name to a canonical PayloadBox type.
 *
 * Accepts:
 *   "xss"              → "xss"
 *   "sqli"             → "sql-injection"
 *   "sql-injection"    → "sql-injection"
 *   "cmd"              → "command-injection"
 *
 * Returns null if the name doesn't match any known type.
 */
export function resolvePayloadType(name: string): PayloadBoxType | null {
  const resolved = ALIASES[name.toLowerCase()];
  return resolved ?? null;
}

/**
 * Check if a name resolves to a valid PayloadBox type
 */
export function isValidPayloadName(name: string): boolean {
  return resolvePayloadType(name) !== null;
}

/**
 * Get description for a payload type
 */
export function getDescription(type: PayloadBoxType): string {
  return DESCRIPTIONS[type] ?? type;
}

/**
 * Load payloads from PayloadBox.
 *
 * Accepts both canonical names and short aliases:
 *   loadPayloadBox("xss")     → fetches XSS payloads
 *   loadPayloadBox("sqli")    → fetches SQL injection payloads
 */
export async function loadPayloadBox(
  name: string,
  limit: number = 50,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<RuntimePayload> {
  const type = resolvePayloadType(name);

  if (!type) {
    const available = getPayloadBoxTypes().join(", ");
    const aliases = "xss, sqli, xxe, cmd, redirect, traversal";
    throw new Error(
      `Unknown payload type: "${name}". Available: ${available}\nShort aliases: ${aliases}`,
    );
  }

  // Check cache
  const cached = cache.get(type);
  if (cached) {
    return cached;
  }

  const url = PAYLOADBOX_URLS[type];

  try {
    const response = await fetchFn(url);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch: ${response.status} ${response.statusText}`,
      );
    }

    const text = await response.text();
    const payloads = text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"))
      .slice(0, limit);

    if (payloads.length === 0) {
      throw new Error(`No payloads found for ${type}`);
    }

    const payload: RuntimePayload = {
      name: type,
      category: CATEGORY_MAP[type],
      description: `${DESCRIPTIONS[type]} (${payloads.length} payloads from PayloadsAllTheThings)`,
      payloads,
      detectPatterns: getDefaultPatterns(type),
      source: "payloadbox",
    };

    // Cache it
    cache.set(type, payload);
    return payload;
  } catch (err) {
    throw new Error(
      `Failed to fetch payloads for "${type}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

// ── Internal ───────────────────────────────────────────────────────────

/**
 * Default detection patterns for PayloadBox types
 */
function getDefaultPatterns(type: PayloadBoxType): RegExp[] {
  switch (type) {
    case "xss":
      return [
        /<script[^>]*>alert\(/i,
        /onerror\s*=\s*alert\(/i,
        /onload\s*=\s*alert\(/i,
        /javascript:alert\(/i,
      ];
    case "sql-injection":
      return [
        /sql.*syntax/i,
        /mysql.*error/i,
        /ORA-\d{5}/i,
        /pg_query/i,
        /sqlite.*error/i,
      ];
    case "xxe":
      return [/root:.*:0:0/i, /\[fonts\]/i];
    case "command-injection":
      return [/uid=\d+\([\w]+\)/i, /root:.*:0:0/i];
    case "open-redirect":
      return []; // Detected by redirect behavior
    case "path-traversal":
      return [/root:.*:0:0/i, /\[fonts\]/i, /\[extensions\]/i];
    default:
      return [];
  }
}

/**
 * Clear PayloadBox cache
 */
export function clearPayloadBoxCache(): void {
  cache.clear();
}
