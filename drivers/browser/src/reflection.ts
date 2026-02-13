/**
 * Shared reflection detection utilities for the browser driver.
 *
 * Both runner.ts (browser-based) and http-scanner.ts (HTTP-based) need
 * to detect payload reflection in response content. This module provides
 * the shared core logic.
 */

import type { Finding, RuntimePayload } from "@vulcn/engine";
import { getSeverity } from "@vulcn/engine";

export interface ReflectionCheckOptions {
  /** Content to search for reflections (HTML body, HTTP response, etc.) */
  content: string;
  /** The payload set used */
  payloadSet: RuntimePayload;
  /** The specific payload value injected */
  payloadValue: string;
  /** Step identifier for findings */
  stepId: string;
  /** URL where the reflection was found */
  url: string;
  /** Additional metadata to attach to findings */
  metadata?: Record<string, unknown>;
  /**
   * Raw HTML source (before DOM parsing).
   * When provided, enables encoding-aware detection:
   * if the payload's dangerous chars are HTML-encoded in the raw source,
   * the reflection is considered safely sanitized and NOT reported.
   */
  rawContent?: string;
}

/** Characters that are dangerous in HTML contexts */
const DANGEROUS_HTML_CHARS = ["<", ">", '"', "'"];

/** HTML entity equivalents */
const HTML_ENTITY_MAP: Record<string, string[]> = {
  "<": ["&lt;", "&#60;", "&#x3c;", "&#x3C;"],
  ">": ["&gt;", "&#62;", "&#x3e;", "&#x3E;"],
  '"': ["&quot;", "&#34;", "&#x22;"],
  "'": ["&#39;", "&#x27;", "&apos;"],
};

/**
 * Check if a payload's dangerous characters are HTML-encoded in the raw source.
 * Returns true if the reflection is safely sanitized.
 */
export function isHtmlEncoded(payload: string, rawContent: string): boolean {
  // 1. If the raw string exists verbatim, it is definitely NOT encoded.
  if (rawContent.includes(payload)) return false;

  // 2. If the verbatim payload is NOT in the raw HTML, but we know it appeared
  // in the parsed DOM (caller ensures this), then it MUST have been encoded
  // (e.g., < became &lt;) or transformed by JS.
  return true;
}

/**
 * Check content for payload reflection using detect patterns and verbatim matching.
 *
 * This is the single source of truth for basic reflection detection.
 * The detect-reflection plugin provides deeper analysis (context awareness,
 * dangerous pattern proximity) and runs separately via hooks.
 *
 * @returns A finding if reflection is detected, undefined otherwise
 */
export function checkReflection(
  options: ReflectionCheckOptions,
): Finding | undefined {
  const {
    content,
    payloadSet,
    payloadValue,
    stepId,
    url,
    metadata,
    rawContent,
  } = options;

  // ─── Encoding-aware suppression ────────────────────────────
  // If the payload contains dangerous HTML chars and we have the raw source,
  // check if those chars were properly encoded. If so, the application
  // is correctly sanitizing input → NOT a vulnerability.
  const hasDangerousChars = DANGEROUS_HTML_CHARS.some((c) =>
    payloadValue.includes(c),
  );

  if (
    hasDangerousChars &&
    rawContent &&
    isHtmlEncoded(payloadValue, rawContent)
  ) {
    return undefined;
  }

  // Check if the payload appears verbatim in the rendered content first.
  // Without verbatim presence, detect pattern matches could be from
  // pre-existing page content or partially-encoded reflections.
  const payloadInContent = content.includes(payloadValue);

  // For payloads WITH dangerous chars that passed encoding checks above,
  // pattern matching provides high confidence (the chars are unencoded,
  // so the pattern likely triggers in an executable context).
  //
  // For payloads WITHOUT dangerous chars (e.g. `x onmouseover=alert(1)`),
  // pattern matching is unreliable — the text appears verbatim even inside
  // safely-quoted attributes where it can't execute. These payloads only
  // work in unquoted attribute contexts. Actual XSS from them will be
  // caught by the detect-xss plugin's onDialog hook when alert() fires.
  if (payloadInContent && hasDangerousChars) {
    for (const pattern of payloadSet.detectPatterns) {
      if (pattern.test(content)) {
        return {
          type: payloadSet.category,
          severity: getSeverity(payloadSet.category),
          title: `${payloadSet.category.toUpperCase()} vulnerability detected`,
          description: `Payload pattern was reflected in page content`,
          stepId,
          payload: payloadValue,
          url,
          evidence: content.match(pattern)?.[0]?.slice(0, 200),
          ...(metadata ? { metadata } : {}),
        };
      }
    }
  }

  // Verbatim match only — lower confidence.
  // Use type "reflection" since we can't confirm exploitation.
  if (payloadInContent) {
    return {
      type: "reflection",
      severity: "low",
      title: `Potential ${payloadSet.category.toUpperCase()} - payload reflection`,
      description: `Payload was reflected in page without encoding`,
      stepId,
      payload: payloadValue,
      url,
      ...(metadata ? { metadata } : {}),
    };
  }

  return undefined;
}
