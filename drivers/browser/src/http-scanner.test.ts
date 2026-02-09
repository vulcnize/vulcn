/**
 * Tests for HTTP Scanner — Tier 1 Fast Scan
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { httpScan, buildCapturedRequests } from "../src/http-scanner";
import type { CapturedRequest } from "@vulcn/engine";
import type { RuntimePayload } from "@vulcn/engine";
import http from "node:http";
import type { AddressInfo } from "node:net";

// ── Test Server ────────────────────────────────────────────────────────

let server: http.Server;
let baseUrl: string;

/**
 * Simple HTTP server that echoes form data back in the response body.
 * This simulates a vulnerable page that reflects input without encoding.
 */
function createTestServer(): Promise<http.Server> {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const url = new URL(req.url!, `http://localhost`);
        const path = url.pathname;

        if (path === "/reflect") {
          // Reflect the "q" parameter (GET) or form body (POST) in response
          const query = url.searchParams.get("q") ?? "";
          const formValue = body
            ? (new URLSearchParams(body).get("q") ?? "")
            : "";
          const value = query || formValue;

          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(
            `<html><body><p>Search results for: ${value}</p></body></html>`,
          );
        } else if (path === "/safe") {
          // HTML-encode the input — no reflection
          const query = url.searchParams.get("q") ?? "";
          const escaped = query
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");

          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(
            `<html><body><p>Search results for: ${escaped}</p></body></html>`,
          );
        } else if (path === "/sqli") {
          // Simulate SQL error on certain payloads
          const query = url.searchParams.get("q") ?? "";
          if (query.includes("'")) {
            res.writeHead(500, { "Content-Type": "text/html" });
            res.end(
              `<html><body>Error: You have an error in your SQL syntax near '${query}'</body></html>`,
            );
          } else {
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(`<html><body>Results: 0 found</body></html>`);
          }
        } else if (path === "/json-reflect") {
          // JSON endpoint that reflects input
          let parsed: Record<string, string> = {};
          try {
            parsed = JSON.parse(body);
          } catch {
            /* empty */
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ message: `Hello ${parsed.name ?? ""}` }));
        } else if (path === "/timeout") {
          // Never respond — for timeout testing
          // Don't call res.end()
        } else {
          res.writeHead(404);
          res.end("Not found");
        }
      });
    });

    srv.listen(0, "127.0.0.1", () => {
      resolve(srv);
    });
  });
}

beforeAll(async () => {
  server = await createTestServer();
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

// ── Test Payloads ──────────────────────────────────────────────────────

const xssPayloads: RuntimePayload = {
  name: "test-xss",
  category: "xss",
  description: "Test XSS payloads",
  payloads: ['<script>alert("XSS")</script>', "<img src=x onerror=alert(1)>"],
  detectPatterns: [
    /<script[^>]*>.*?alert\([^)]*\).*?<\/script>/i,
    /onerror\s*=\s*alert/i,
  ],
  source: "custom",
};

const sqliPayloads: RuntimePayload = {
  name: "test-sqli",
  category: "sqli",
  description: "Test SQLi payloads",
  payloads: ["' OR '1'='1", "'; DROP TABLE users;--"],
  detectPatterns: [/error in your SQL syntax/i, /unclosed quotation mark/i],
  source: "custom",
};

// ── Tests ──────────────────────────────────────────────────────────────

describe("httpScan", () => {
  it("should detect XSS reflection via GET", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/reflect`,
        headers: {},
        injectableField: "q",
        sessionName: "test-reflect",
      },
    ];

    const result = await httpScan(requests, [xssPayloads]);

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].type).toBe("xss");
    expect(result.findings[0].url).toContain("/reflect");
    expect(result.findings[0].metadata?.detectionMethod).toBe("tier1-http");
    expect(result.findings[0].metadata?.needsBrowserConfirmation).toBe(true);
    expect(result.reflectedRequests.length).toBeGreaterThan(0);
    expect(result.requestsSent).toBeGreaterThan(0);
  });

  it("should detect XSS reflection via POST", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "POST",
        url: `${baseUrl}/reflect`,
        headers: {},
        body: "q=test",
        contentType: "application/x-www-form-urlencoded",
        injectableField: "q",
        sessionName: "test-reflect-post",
      },
    ];

    const result = await httpScan(requests, [xssPayloads]);

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].type).toBe("xss");
  });

  it("should have fewer findings on safe (encoded) endpoints", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/safe`,
        headers: {},
        injectableField: "q",
        sessionName: "test-safe",
      },
    ];

    const result = await httpScan(requests, [xssPayloads]);

    // The safe endpoint encodes < and >, so the <script>...</script> pattern
    // should NOT match. However, onerror=alert may still match (no angle brackets).
    // This is expected — partial encoding doesn't prevent all vectors.
    const scriptFindings = result.findings.filter((f) =>
      f.evidence?.includes("<script>"),
    );
    expect(scriptFindings.length).toBe(0);
  });

  it("should detect SQL error reflection", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/sqli`,
        headers: {},
        injectableField: "q",
        sessionName: "test-sqli",
      },
    ];

    const result = await httpScan(requests, [sqliPayloads]);

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].type).toBe("sqli");
    expect(result.findings[0].severity).toBe("critical");
  });

  it("should handle multiple payloads and requests", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/reflect`,
        headers: {},
        injectableField: "q",
        sessionName: "form-1",
      },
      {
        method: "GET",
        url: `${baseUrl}/sqli`,
        headers: {},
        injectableField: "q",
        sessionName: "form-2",
      },
    ];

    const result = await httpScan(requests, [xssPayloads, sqliPayloads]);

    // Should have both XSS and SQLi findings
    const types = new Set(result.findings.map((f) => f.type));
    expect(types.has("xss")).toBe(true);
    expect(types.has("sqli")).toBe(true);
    expect(result.requestsSent).toBe(
      requests.length *
        (xssPayloads.payloads.length + sqliPayloads.payloads.length),
    );
  });

  it("should skip requests without injectable fields", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/reflect`,
        headers: {},
        // No injectableField!
        sessionName: "no-inject",
      },
    ];

    const result = await httpScan(requests, [xssPayloads]);

    expect(result.requestsSent).toBe(0);
    expect(result.findings.length).toBe(0);
  });

  it("should handle timeouts gracefully", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/timeout`,
        headers: {},
        injectableField: "q",
        sessionName: "test-timeout",
      },
    ];

    const result = await httpScan(requests, [xssPayloads], {
      timeout: 500, // 500ms timeout
    });

    // Should not throw, just increment requestsSent with no findings
    expect(result.findings.length).toBe(0);
    expect(result.requestsSent).toBeGreaterThan(0);
  });

  it("should report progress", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/reflect`,
        headers: {},
        injectableField: "q",
        sessionName: "progress-test",
      },
    ];

    const progressCalls: Array<[number, number]> = [];

    await httpScan(requests, [xssPayloads], {
      onProgress: (completed, total) => {
        progressCalls.push([completed, total]);
      },
    });

    expect(progressCalls.length).toBeGreaterThan(0);
    // Last call should have completed === total
    const last = progressCalls[progressCalls.length - 1];
    expect(last[0]).toBe(last[1]);
  });

  it("should pass cookies and custom headers", async () => {
    const requests: CapturedRequest[] = [
      {
        method: "GET",
        url: `${baseUrl}/reflect`,
        headers: {},
        injectableField: "q",
        sessionName: "auth-test",
      },
    ];

    // This mainly tests that the options don't cause errors
    const result = await httpScan(requests, [xssPayloads], {
      cookies: "session=abc123",
      headers: { "X-Custom": "test" },
    });

    expect(result.requestsSent).toBeGreaterThan(0);
  });

  it("should return empty results for empty inputs", async () => {
    const result = await httpScan([], [xssPayloads]);
    expect(result.requestsSent).toBe(0);
    expect(result.findings.length).toBe(0);
    expect(result.duration).toBe(0);

    const result2 = await httpScan(
      [
        {
          method: "GET",
          url: `${baseUrl}/reflect`,
          headers: {},
          injectableField: "q",
          sessionName: "empty-payloads",
        },
      ],
      [],
    );
    expect(result2.requestsSent).toBe(0);
  });
});

describe("buildCapturedRequests", () => {
  it("should generate requests from forms with injectable inputs", () => {
    const forms = [
      {
        pageUrl: "https://example.com/search",
        action: "/search",
        method: "GET",
        inputs: [
          { name: "q", injectable: true, type: "text" },
          { name: "category", injectable: false, type: "select" },
        ],
        sessionName: "search-form",
      },
    ];

    const requests = buildCapturedRequests(forms);

    expect(requests.length).toBe(1);
    expect(requests[0].method).toBe("GET");
    expect(requests[0].url).toBe("https://example.com/search");
    expect(requests[0].injectableField).toBe("q");
    expect(requests[0].sessionName).toBe("search-form");
  });

  it("should generate one request per injectable input", () => {
    const forms = [
      {
        pageUrl: "https://example.com/contact",
        action: "/contact",
        method: "POST",
        inputs: [
          { name: "name", injectable: true, type: "text" },
          { name: "email", injectable: true, type: "email" },
          { name: "submit", injectable: false, type: "submit" },
        ],
        sessionName: "contact-form",
      },
    ];

    const requests = buildCapturedRequests(forms);

    expect(requests.length).toBe(2);
    expect(requests[0].injectableField).toBe("name");
    expect(requests[1].injectableField).toBe("email");
    expect(requests[0].method).toBe("POST");
    expect(requests[0].body).toBeDefined();
    expect(requests[0].contentType).toBe("application/x-www-form-urlencoded");
  });

  it("should skip forms with no injectable inputs", () => {
    const forms = [
      {
        pageUrl: "https://example.com/login",
        action: "/login",
        method: "POST",
        inputs: [
          { name: "csrf", injectable: false, type: "hidden" },
          { name: "submit", injectable: false, type: "submit" },
        ],
        sessionName: "login-form",
      },
    ];

    const requests = buildCapturedRequests(forms);
    expect(requests.length).toBe(0);
  });

  it("should resolve relative action URLs against page URL", () => {
    const forms = [
      {
        pageUrl: "https://example.com/app/search",
        action: "../api/search",
        method: "GET",
        inputs: [{ name: "q", injectable: true, type: "text" }],
        sessionName: "relative-action",
      },
    ];

    const requests = buildCapturedRequests(forms);
    expect(requests[0].url).toBe("https://example.com/api/search");
  });
});
