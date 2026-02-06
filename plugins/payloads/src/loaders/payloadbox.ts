/**
 * PayloadBox Loader
 * Fetches payloads from PayloadsAllTheThings GitHub repository
 */

import type { RuntimePayload, PayloadCategory } from "@vulcn/engine";

/**
 * Supported PayloadBox types
 */
export type PayloadBoxType =
  | "xss"
  | "sql-injection"
  | "xxe"
  | "command-injection"
  | "open-redirect"
  | "path-traversal";

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
 * Map PayloadBox types to our categories
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
 * Cache for fetched payloads
 */
const cache: Map<PayloadBoxType, RuntimePayload> = new Map();

/**
 * Get available PayloadBox types
 */
export function getPayloadBoxTypes(): PayloadBoxType[] {
  return Object.keys(PAYLOADBOX_URLS) as PayloadBoxType[];
}

/**
 * Check if a type is a valid PayloadBox type
 */
export function isPayloadBoxType(type: string): type is PayloadBoxType {
  return type in PAYLOADBOX_URLS;
}

/**
 * Load payloads from PayloadBox
 *
 * @param type - PayloadBox type (xss, sql-injection, etc.)
 * @param limit - Maximum number of payloads to include
 * @param fetchFn - Fetch function to use (for testing/DI)
 */
export async function loadPayloadBox(
  type: string,
  limit: number = 50,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<RuntimePayload> {
  // Validate type
  if (!isPayloadBoxType(type)) {
    throw new Error(
      `Unknown PayloadBox type: ${type}. Available: ${getPayloadBoxTypes().join(", ")}`,
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
      throw new Error(`No payloads found in ${type}`);
    }

    const payload: RuntimePayload = {
      name: `payloadbox:${type}`,
      category: CATEGORY_MAP[type],
      description: `PayloadsAllTheThings ${type} - ${payloads.length} payloads`,
      payloads,
      detectPatterns: getDefaultPatterns(type),
      source: "payloadbox",
    };

    // Cache it
    cache.set(type, payload);
    return payload;
  } catch (err) {
    throw new Error(
      `Failed to fetch PayloadBox ${type}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Get default detection patterns for PayloadBox types
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
