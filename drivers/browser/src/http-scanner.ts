/**
 * HTTP Scanner — Tier 1 Fast Scan
 *
 * Replays captured HTTP requests via fetch() instead of Playwright.
 * Substitutes security payloads into injectable form fields and checks
 * the response body for payload reflection or error patterns.
 *
 * Speed: ~50ms per payload (vs 2-5s for browser replay)
 *
 * Catches:
 *   - Reflected XSS (payload appears in response body)
 *   - Error-based SQLi (SQL error patterns in response)
 *   - Server-side reflection of any payload
 *
 * Misses:
 *   - DOM-based XSS (requires JS execution)
 *   - Client-side state bugs
 *   - CSP-blocked attacks
 *
 * When reflection IS found, the finding is marked as `needsBrowserConfirmation`
 * so the caller can escalate to Tier 2 for execution-based proof.
 */

import type {
  Finding,
  RuntimePayload,
  PayloadCategory,
  CapturedRequest,
} from "@vulcn/engine";

// ── Types ──────────────────────────────────────────────────────────────

export interface HttpScanResult {
  /** Total HTTP requests sent */
  requestsSent: number;
  /** How long the scan took (ms) */
  duration: number;
  /** Findings from reflection detection */
  findings: Finding[];
  /** Requests where reflection was found — should be escalated to Tier 2 */
  reflectedRequests: ReflectedRequest[];
}

export interface ReflectedRequest {
  /** Original captured request */
  request: CapturedRequest;
  /** Payload that caused reflection */
  payload: string;
  /** Category of the payload */
  category: PayloadCategory;
}

export interface HttpScanOptions {
  /** Request timeout in ms (default: 10000) */
  timeout?: number;
  /** Max concurrent requests (default: 10) */
  concurrency?: number;
  /** Cookie header to send with requests (for auth) */
  cookies?: string;
  /** Extra headers to send */
  headers?: Record<string, string>;
  /** Callback for progress reporting */
  onProgress?: (completed: number, total: number) => void;
}

// ── Scanner ────────────────────────────────────────────────────────────

/**
 * Run Tier 1 HTTP-level scan on captured requests.
 *
 * For each CapturedRequest × each payload:
 *   1. Substitute the payload into the injectable field
 *   2. Send via fetch()
 *   3. Check response body for reflection patterns
 *   4. If reflected, add finding + mark for Tier 2 escalation
 */
export async function httpScan(
  requests: CapturedRequest[],
  payloads: RuntimePayload[],
  options: HttpScanOptions = {},
): Promise<HttpScanResult> {
  const timeout = options.timeout ?? 10_000;
  const concurrency = options.concurrency ?? 10;
  const start = Date.now();

  const findings: Finding[] = [];
  const reflectedRequests: ReflectedRequest[] = [];
  let requestsSent = 0;

  // Build the flat list of (request, payload, value) tuples
  const tasks: Array<{
    request: CapturedRequest;
    payloadSet: RuntimePayload;
    value: string;
  }> = [];

  for (const request of requests) {
    if (!request.injectableField) continue;

    for (const payloadSet of payloads) {
      for (const value of payloadSet.payloads) {
        tasks.push({ request, payloadSet, value });
      }
    }
  }

  const totalTasks = tasks.length;
  if (totalTasks === 0) {
    return { requestsSent: 0, duration: 0, findings, reflectedRequests };
  }

  // Process in batches for concurrency control
  for (let i = 0; i < tasks.length; i += concurrency) {
    const batch = tasks.slice(i, i + concurrency);

    const results = await Promise.allSettled(
      batch.map(async ({ request, payloadSet, value }) => {
        try {
          const body = await sendPayload(request, value, {
            timeout,
            cookies: options.cookies,
            headers: options.headers,
          });
          requestsSent++;

          const finding = checkHttpReflection(body, request, payloadSet, value);
          if (finding) {
            findings.push(finding);
            reflectedRequests.push({
              request,
              payload: value,
              category: payloadSet.category,
            });
          }
        } catch {
          // Network errors, timeouts — skip silently
          requestsSent++;
        }
      }),
    );

    // Report progress
    const completed = Math.min(i + batch.length, totalTasks);
    options.onProgress?.(completed, totalTasks);

    // Check for unhandled rejections (shouldn't happen with allSettled)
    for (const result of results) {
      if (result.status === "rejected") {
        // Already handled in catch above
      }
    }
  }

  return {
    requestsSent,
    duration: Date.now() - start,
    findings,
    reflectedRequests,
  };
}

// ── HTTP Request ───────────────────────────────────────────────────────

/**
 * Send a single HTTP request with a payload substituted in.
 * Returns the response body as a string.
 */
async function sendPayload(
  request: CapturedRequest,
  payload: string,
  options: {
    timeout: number;
    cookies?: string;
    headers?: Record<string, string>;
  },
): Promise<string> {
  const { method, url, headers, body, contentType, injectableField } = request;

  // Build request headers
  const reqHeaders: Record<string, string> = {
    ...headers,
    ...(options.headers ?? {}),
  };

  // Add cookies if provided
  if (options.cookies) {
    reqHeaders["Cookie"] = options.cookies;
  }

  // Remove headers that could interfere
  delete reqHeaders["content-length"];
  delete reqHeaders["Content-Length"];

  let requestUrl = url;
  let requestBody: string | undefined;

  if (method.toUpperCase() === "GET") {
    // For GET, inject into URL query parameters
    requestUrl = injectIntoUrl(url, injectableField!, payload);
  } else {
    // For POST/PUT, inject into the request body
    requestBody = injectIntoBody(body, contentType, injectableField!, payload);

    // Set content type if we have a body
    if (contentType) {
      reqHeaders["Content-Type"] = contentType;
    } else {
      reqHeaders["Content-Type"] = "application/x-www-form-urlencoded";
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout);

  try {
    const response = await fetch(requestUrl, {
      method: method.toUpperCase(),
      headers: reqHeaders,
      body: requestBody,
      signal: controller.signal,
      redirect: "follow",
    });

    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

// ── Injection Helpers ──────────────────────────────────────────────────

/**
 * Inject payload into a URL query parameter.
 */
function injectIntoUrl(url: string, field: string, payload: string): string {
  try {
    const parsed = new URL(url);
    parsed.searchParams.set(field, payload);
    return parsed.toString();
  } catch {
    // If URL parsing fails, append as query string
    const separator = url.includes("?") ? "&" : "?";
    return `${url}${separator}${encodeURIComponent(field)}=${encodeURIComponent(payload)}`;
  }
}

/**
 * Inject payload into a request body.
 *
 * Supports:
 *   - application/x-www-form-urlencoded
 *   - application/json
 *   - multipart/form-data (basic — replaces field value by regex)
 */
function injectIntoBody(
  body: string | undefined,
  contentType: string | undefined,
  field: string,
  payload: string,
): string {
  if (!body) {
    // No existing body — create a simple form body
    return `${encodeURIComponent(field)}=${encodeURIComponent(payload)}`;
  }

  const ct = (contentType ?? "").toLowerCase();

  if (ct.includes("application/json")) {
    return injectIntoJson(body, field, payload);
  }

  if (ct.includes("multipart/form-data")) {
    return injectIntoMultipart(body, field, payload);
  }

  // Default: form-urlencoded
  return injectIntoFormUrlEncoded(body, field, payload);
}

/**
 * Inject into application/x-www-form-urlencoded body.
 */
function injectIntoFormUrlEncoded(
  body: string,
  field: string,
  payload: string,
): string {
  const params = new URLSearchParams(body);
  params.set(field, payload);
  return params.toString();
}

/**
 * Inject into application/json body.
 */
function injectIntoJson(body: string, field: string, payload: string): string {
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed === "object" && parsed !== null) {
      parsed[field] = payload;
      return JSON.stringify(parsed);
    }
  } catch {
    // Fall through to regex-based injection
  }

  // Fallback: regex replacement for the field value
  const escaped = field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`("${escaped}"\\s*:\\s*)"[^"]*"`, "g");
  const replaced = body.replace(regex, `$1"${payload}"`);
  if (replaced !== body) return replaced;

  // Last resort: just return the body with the field appended
  return body;
}

/**
 * Inject into multipart/form-data body.
 * Basic regex-based replacement — works for simple text fields.
 */
function injectIntoMultipart(
  body: string,
  field: string,
  payload: string,
): string {
  // Match: Content-Disposition: form-data; name="fieldname"\r\n\r\nvalue
  const escaped = field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(
    `(Content-Disposition:\\s*form-data;\\s*name="${escaped}"\\r?\\n\\r?\\n)[^\\r\\n-]*`,
    "i",
  );
  return body.replace(regex, `$1${payload}`);
}

// ── Reflection Detection ───────────────────────────────────────────────

/**
 * Check HTTP response body for payload reflection.
 *
 * This mirrors the browser runner's `checkReflection` but works on raw
 * HTTP response text. Results are marked with `detectionMethod: "tier1-http"`
 * in metadata to distinguish from browser-confirmed findings.
 */
function checkHttpReflection(
  responseBody: string,
  request: CapturedRequest,
  payloadSet: RuntimePayload,
  payloadValue: string,
): Finding | undefined {
  // Check detect patterns from the payload set
  for (const pattern of payloadSet.detectPatterns) {
    if (pattern.test(responseBody)) {
      return {
        type: payloadSet.category,
        severity: getSeverity(payloadSet.category),
        title: `${payloadSet.category.toUpperCase()} reflection detected (HTTP)`,
        description: `Payload pattern was reflected in HTTP response body. Needs browser confirmation for execution proof.`,
        stepId: `http-${request.sessionName}`,
        payload: payloadValue,
        url: request.url,
        evidence: responseBody.match(pattern)?.[0]?.slice(0, 200),
        metadata: {
          detectionMethod: "tier1-http",
          needsBrowserConfirmation: true,
          requestMethod: request.method,
          injectableField: request.injectableField,
        },
      };
    }
  }

  // Check if payload appears verbatim in response
  if (responseBody.includes(payloadValue)) {
    return {
      type: payloadSet.category,
      severity: "medium",
      title: `Potential ${payloadSet.category.toUpperCase()} — payload reflected in HTTP response`,
      description: `Payload was reflected in HTTP response without encoding. Escalate to browser for execution proof.`,
      stepId: `http-${request.sessionName}`,
      payload: payloadValue,
      url: request.url,
      metadata: {
        detectionMethod: "tier1-http",
        needsBrowserConfirmation: true,
        requestMethod: request.method,
        injectableField: request.injectableField,
      },
    };
  }

  return undefined;
}

// ── Severity ───────────────────────────────────────────────────────────

/**
 * Determine severity based on vulnerability category.
 * Mirrors the browser runner's getSeverity().
 */
function getSeverity(
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
    default:
      return "medium";
  }
}

// ── Utility: Build CapturedRequests from Crawler Data ──────────────────

/**
 * Convert discovered forms into CapturedRequest metadata.
 *
 * Called by the crawler after form discovery. Each injectable form
 * produces one CapturedRequest per injectable input field.
 */
export function buildCapturedRequests(
  forms: Array<{
    pageUrl: string;
    action: string;
    method: string;
    inputs: Array<{ name: string; injectable: boolean; type: string }>;
    sessionName: string;
  }>,
): CapturedRequest[] {
  const requests: CapturedRequest[] = [];

  for (const form of forms) {
    const injectableInputs = form.inputs.filter((i) => i.injectable);
    if (injectableInputs.length === 0) continue;

    // Resolve the form action URL
    let actionUrl: string;
    try {
      actionUrl = new URL(form.action, form.pageUrl).toString();
    } catch {
      actionUrl = form.pageUrl;
    }

    const method = (form.method || "GET").toUpperCase();

    for (const input of injectableInputs) {
      // Build the default form body with placeholder values
      const formParams = new URLSearchParams();
      for (const inp of form.inputs) {
        formParams.set(inp.name || inp.type, inp.injectable ? "test" : "");
      }

      const request: CapturedRequest = {
        method,
        url: method === "GET" ? actionUrl : actionUrl,
        headers: {
          "User-Agent": "Vulcn/1.0 (Security Scanner)",
          Accept: "text/html,application/xhtml+xml,*/*",
        },
        ...(method !== "GET"
          ? {
              body: formParams.toString(),
              contentType: "application/x-www-form-urlencoded",
            }
          : {}),
        injectableField: input.name || input.type,
        sessionName: form.sessionName,
      };

      requests.push(request);
    }
  }

  return requests;
}
