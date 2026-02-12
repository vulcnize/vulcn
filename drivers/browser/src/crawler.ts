/**
 * Browser Crawler
 *
 * Automated session generator for the browser driver.
 * Crawls a web application using Playwright to discover:
 * - Forms with input fields and submit buttons
 * - Links to follow for deeper crawling
 *
 * Outputs Session[] that are directly compatible with BrowserRunner.
 * Also generates CapturedRequest[] metadata for Tier 1 HTTP fast scanning.
 *
 * This is the "auto-record" mode — instead of a human clicking around,
 * the crawler automatically discovers injection points.
 */

import type { Page, Browser, BrowserContext } from "playwright";
import type {
  Session,
  Step,
  CrawlOptions,
  CapturedRequest,
} from "@vulcn/engine";
import { launchBrowser, type BrowserType } from "./browser";
import { buildCapturedRequests } from "./http-scanner";

// ── Internal Types ─────────────────────────────────────────────────────

interface DiscoveredInput {
  selector: string;
  type: string;
  name: string;
  injectable: boolean;
  placeholder?: string;
}

interface DiscoveredForm {
  pageUrl: string;
  formSelector: string;
  action: string;
  method: string;
  inputs: DiscoveredInput[];
  submitSelector: string | null;
}

// Input types that accept text and can be injected with payloads
const INJECTABLE_INPUT_TYPES = new Set([
  "text",
  "search",
  "url",
  "email",
  "tel",
  "password",
  "textarea",
  "",
]);

const CRAWL_DEFAULTS = {
  maxDepth: 2,
  maxPages: 20,
  pageTimeout: 10000,
  sameOrigin: true,
};

// ── Public API ─────────────────────────────────────────────────────────

export interface BrowserCrawlConfig {
  /** Starting URL */
  startUrl: string;
  /** Browser type */
  browser?: BrowserType;
  /** Run headless */
  headless?: boolean;
  /** Viewport */
  viewport?: { width: number; height: number };
}

/** Result from crawling — sessions for browser replay + requests for HTTP scanning */
export interface CrawlResult {
  sessions: Session[];
  capturedRequests: CapturedRequest[];
}

/**
 * Crawl a URL and generate sessions.
 *
 * This is called by the browser driver's recorder.crawl() method.
 * Returns both Session[] for Tier 2 browser replay and
 * CapturedRequest[] for Tier 1 HTTP fast scanning.
 */
export async function crawlAndBuildSessions(
  config: BrowserCrawlConfig,
  options: CrawlOptions = {},
): Promise<CrawlResult> {
  const opts = { ...CRAWL_DEFAULTS, ...options } as typeof CRAWL_DEFAULTS &
    CrawlOptions;
  const startUrl = config.startUrl;

  let normalizedUrl: URL;
  try {
    normalizedUrl = new URL(startUrl);
  } catch {
    throw new Error(`Invalid URL: ${startUrl}`);
  }

  const origin = normalizedUrl.origin;
  const visited = new Set<string>();
  const allForms: DiscoveredForm[] = [];

  // BFS queue: [url, depth]
  const queue: [string, number][] = [[normalizedUrl.href, 0]];

  // Use the shared browser launcher
  const { browser } = await launchBrowser({
    browser: config.browser ?? "chromium",
    headless: config.headless ?? true,
  });

  const context: BrowserContext = await browser.newContext({
    viewport: config.viewport ?? { width: 1280, height: 720 },
    ...(options.storageState
      ? { storageState: JSON.parse(options.storageState) }
      : {}),
  });

  try {
    while (queue.length > 0 && visited.size < opts.maxPages) {
      const [url, depth] = queue.shift()!;
      const normalizedPageUrl = normalizeUrl(url);

      if (visited.has(normalizedPageUrl)) continue;
      visited.add(normalizedPageUrl);

      console.log(`[crawler] [depth=${depth}] Crawling: ${normalizedPageUrl}`);

      const page: Page = await context.newPage();

      try {
        await page.goto(normalizedPageUrl, {
          waitUntil: "domcontentloaded",
          timeout: opts.pageTimeout,
        });

        // Wait for JS-rendered content
        await page.waitForTimeout(1000);

        // Discover forms
        const forms = await discoverForms(page, normalizedPageUrl);
        allForms.push(...forms);

        const injectableCount = forms.reduce(
          (s, f) => s + f.inputs.filter((i) => i.injectable).length,
          0,
        );
        console.log(
          `[crawler]   Found ${forms.length} form(s), ${injectableCount} injectable input(s)`,
        );

        opts.onPageCrawled?.(normalizedPageUrl, forms.length);

        // Follow links
        if (depth < opts.maxDepth) {
          const links = await discoverLinks(page, origin, opts.sameOrigin);
          for (const link of links) {
            const normalizedLink = normalizeUrl(link);
            if (!visited.has(normalizedLink)) {
              queue.push([normalizedLink, depth + 1]);
            }
          }
          console.log(`[crawler]   Found ${links.length} link(s) to follow`);
        }
      } catch (err) {
        console.warn(
          `[crawler]   Failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      } finally {
        await page.close();
      }
    }
  } finally {
    await browser.close();
  }

  console.log(
    `[crawler] Complete: ${visited.size} page(s), ${allForms.length} form(s)`,
  );

  // Convert discovered forms to sessions
  const sessions = buildSessions(allForms);

  // Build HTTP request metadata for Tier 1 fast scanning
  const capturedRequests = buildCapturedRequests(
    allForms
      .filter((f) => f.inputs.some((i) => i.injectable))
      .map((form, idx) => ({
        pageUrl: form.pageUrl,
        action: form.action,
        method: form.method,
        inputs: form.inputs,
        sessionName: sessions[idx]?.name ?? `form-${idx + 1}`,
      })),
  );

  console.log(
    `[crawler] Generated ${sessions.length} session(s), ${capturedRequests.length} HTTP request(s) for Tier 1`,
  );

  return { sessions, capturedRequests };
}

// ── Form Discovery ─────────────────────────────────────────────────────

async function discoverForms(
  page: Page,
  pageUrl: string,
): Promise<DiscoveredForm[]> {
  const forms: DiscoveredForm[] = [];

  // 1. Explicit <form> elements
  const explicitForms = await page.evaluate(() => {
    const results: Array<{
      formIndex: number;
      action: string;
      method: string;
      inputs: Array<{
        selector: string;
        type: string;
        name: string;
        placeholder: string;
      }>;
      submitSelector: string | null;
    }> = [];

    const formElements = document.querySelectorAll("form");

    formElements.forEach((form, formIndex) => {
      const inputs: Array<{
        selector: string;
        type: string;
        name: string;
        placeholder: string;
      }> = [];

      const inputEls = form.querySelectorAll(
        'input, textarea, [contenteditable="true"]',
      );

      inputEls.forEach((input, inputIndex) => {
        const el = input as HTMLInputElement;
        const type =
          el.tagName.toLowerCase() === "textarea"
            ? "textarea"
            : el.getAttribute("type") || "text";
        const name = el.name || el.id || `input-${inputIndex}`;

        let selector = "";
        if (el.id) {
          selector = `#${CSS.escape(el.id)}`;
        } else if (el.name) {
          selector = `form:nth-of-type(${formIndex + 1}) [name="${CSS.escape(el.name)}"]`;
        } else if (el.tagName.toLowerCase() === "textarea") {
          selector = `form:nth-of-type(${formIndex + 1}) textarea`;
        } else {
          selector = `form:nth-of-type(${formIndex + 1}) input[type="${type}"]:nth-of-type(${inputIndex + 1})`;
        }

        inputs.push({
          selector,
          type,
          name,
          placeholder: el.placeholder || "",
        });
      });

      // Find submit trigger
      let submitSelector: string | null = null;
      const submitBtn =
        form.querySelector('button[type="submit"], input[type="submit"]') ||
        form.querySelector("button:not([type])") ||
        form.querySelector('button, input[type="button"]');

      if (submitBtn) {
        const btn = submitBtn as HTMLElement;
        if (btn.id) {
          submitSelector = `#${CSS.escape(btn.id)}`;
        } else {
          const tag = btn.tagName.toLowerCase();
          const type = btn.getAttribute("type");
          if (type) {
            submitSelector = `form:nth-of-type(${formIndex + 1}) ${tag}[type="${type}"]`;
          } else {
            submitSelector = `form:nth-of-type(${formIndex + 1}) ${tag}`;
          }
        }
      }

      results.push({
        formIndex,
        action: form.action || "",
        method: (form.method || "GET").toUpperCase(),
        inputs,
        submitSelector,
      });
    });

    return results;
  });

  for (const form of explicitForms) {
    if (form.inputs.length === 0) continue;

    forms.push({
      pageUrl,
      formSelector: `form:nth-of-type(${form.formIndex + 1})`,
      action: form.action,
      method: form.method,
      inputs: form.inputs.map((input) => ({
        selector: input.selector,
        type: input.type,
        name: input.name,
        injectable: INJECTABLE_INPUT_TYPES.has(input.type.toLowerCase()),
        placeholder: input.placeholder || undefined,
      })),
      submitSelector: form.submitSelector,
    });
  }

  // 2. Standalone inputs NOT inside a <form>
  const standaloneInputs = await page.evaluate(() => {
    const results: Array<{
      selector: string;
      type: string;
      name: string;
      placeholder: string;
      nearbyButtonSelector: string | null;
    }> = [];

    const allInputs = document.querySelectorAll(
      'input:not(form input), textarea:not(form textarea), [contenteditable="true"]:not(form [contenteditable])',
    );

    allInputs.forEach((input) => {
      const el = input as HTMLInputElement;
      const type =
        el.tagName.toLowerCase() === "textarea"
          ? "textarea"
          : el.getAttribute("type") || "text";
      const name = el.name || el.id || "";

      let selector = "";
      if (el.id) {
        selector = `#${CSS.escape(el.id)}`;
      } else if (el.name) {
        selector = `[name="${CSS.escape(el.name)}"]`;
      } else if (el.tagName.toLowerCase() === "textarea") {
        selector = `textarea`;
      } else {
        selector = `${el.tagName.toLowerCase()}[type="${type}"]`;
      }

      // Look for nearby button
      let nearbyButtonSelector: string | null = null;
      const parent = el.parentElement;
      if (parent) {
        const btn =
          parent.querySelector("button") ||
          parent.querySelector('input[type="submit"]') ||
          parent.querySelector('input[type="button"]');
        if (btn) {
          const btnEl = btn as HTMLElement;
          if (btnEl.id) {
            nearbyButtonSelector = `#${CSS.escape(btnEl.id)}`;
          }
        }
      }

      results.push({
        selector,
        type,
        name,
        placeholder: el.placeholder || "",
        nearbyButtonSelector,
      });
    });

    return results;
  });

  for (const input of standaloneInputs) {
    if (!INJECTABLE_INPUT_TYPES.has(input.type.toLowerCase())) continue;

    forms.push({
      pageUrl,
      formSelector: "(standalone)",
      action: pageUrl,
      method: "GET",
      inputs: [
        {
          selector: input.selector,
          type: input.type,
          name: input.name,
          injectable: true,
          placeholder: input.placeholder || undefined,
        },
      ],
      submitSelector: input.nearbyButtonSelector,
    });
  }

  return forms;
}

// ── Link Discovery ─────────────────────────────────────────────────────

/** Query parameter names commonly used for external redirects */
const REDIRECT_PARAMS = new Set([
  "to",
  "url",
  "redirect",
  "redirect_uri",
  "redirect_url",
  "return",
  "return_url",
  "returnto",
  "next",
  "goto",
  "dest",
  "destination",
  "continue",
  "target",
  "rurl",
  "out",
  "link",
  "forward",
]);

/**
 * Check if a link is a same-origin redirect that points to an external URL.
 * Example: /redirect?to=https://github.com/...
 */
function isExternalRedirectLink(link: string, origin: string): boolean {
  try {
    const parsed = new URL(link);
    // Only check links on our origin
    if (parsed.origin !== origin) return false;

    for (const [key, value] of parsed.searchParams) {
      if (REDIRECT_PARAMS.has(key.toLowerCase())) {
        // If the param value looks like an external URL, skip this link
        try {
          const targetUrl = new URL(value);
          if (targetUrl.origin !== origin) return true;
        } catch {
          // Not a URL — that's fine
        }
      }
    }
    return false;
  } catch {
    return false;
  }
}

async function discoverLinks(
  page: Page,
  origin: string,
  sameOrigin: boolean,
): Promise<string[]> {
  const links = await page.evaluate(() => {
    const found: string[] = [];

    // 1. Standard <a href> links
    for (const a of document.querySelectorAll("a[href]")) {
      const href = (a as HTMLAnchorElement).href;
      if (href.startsWith("http")) found.push(href);
    }

    // 2. URL-like text in the page body
    //    Many apps list navigable paths as plain text (e.g., WAVSEP's index page
    //    uses <b>active/index-xss.jsp</b> instead of proper links).
    //    We extract text content that looks like relative or absolute paths.
    const pathPattern =
      /(?:^|\s)((?:\/[\w\-.]+)+(?:\.[\w]+)?(?:\?[^\s<]*)?|[\w\-./]+\.(?:jsp|php|html?|aspx?|do|action|cgi|py|rb|pl)(?:\?[^\s<]*)?)/gi;
    const bodyText = document.body?.innerText ?? "";
    let match;
    while ((match = pathPattern.exec(bodyText)) !== null) {
      const candidate = match[1].trim();
      // Skip obvious non-URLs
      if (candidate.length < 3) continue;
      if (candidate.startsWith(".") && !candidate.startsWith("./")) continue;
      found.push(candidate);
    }

    // 3. href/src attributes on any element (not just <a>)
    //    Catches <frame src>, <area href>, etc.
    for (const el of document.querySelectorAll("[href], [src]")) {
      const val = el.getAttribute("href") || el.getAttribute("src") || "";
      if (
        val &&
        !val.startsWith("javascript:") &&
        !val.startsWith("#") &&
        !val.startsWith("data:")
      ) {
        found.push(val);
      }
    }

    return found;
  });

  // Resolve relative paths to full URLs using the page's current URL
  const pageUrl = page.url();
  const resolvedLinks: string[] = [];

  for (const link of links) {
    try {
      // Try resolving as relative to current page
      const resolved = new URL(link, pageUrl).href;
      resolvedLinks.push(resolved);
    } catch {
      // Not a valid URL — skip
    }
  }

  // Deduplicate
  const unique = [...new Set(resolvedLinks)];

  return unique.filter((link) => {
    try {
      const parsed = new URL(link);
      // Skip non-HTTP protocols
      if (!parsed.protocol.startsWith("http")) return false;
      // Filter out links to different origins
      if (sameOrigin && parsed.origin !== origin) return false;
      // Filter out redirect links that point to external URLs
      if (isExternalRedirectLink(link, origin)) return false;
      // Skip anchors, mailto, tel, etc.
      return true;
    } catch {
      return false;
    }
  });
}

// ── Session Builder ────────────────────────────────────────────────────

/**
 * Convert discovered forms into Vulcn sessions.
 *
 * Each form with injectable inputs becomes one session:
 *   navigate → fill input(s) → click submit / press Enter
 */
function buildSessions(forms: DiscoveredForm[]): Session[] {
  const targetForms = forms.filter((f) => f.inputs.some((i) => i.injectable));

  return targetForms.map((form, idx) => buildSessionForForm(form, idx));
}

function buildSessionForForm(form: DiscoveredForm, index: number): Session {
  const steps: Step[] = [];
  let stepNum = 1;

  // Step 1: Navigate
  steps.push({
    id: `step-${stepNum++}`,
    type: "browser.navigate",
    url: form.pageUrl,
    timestamp: Date.now(),
  } as Step);

  // Steps 2+: Fill each injectable input
  const injectableInputs = form.inputs.filter((i) => i.injectable);

  for (const input of injectableInputs) {
    steps.push({
      id: `step-${stepNum++}`,
      type: "browser.input",
      selector: input.selector,
      value: "test",
      injectable: true,
      timestamp: Date.now() + stepNum * 100,
    } as Step);
  }

  // Final step: Submit
  if (form.submitSelector) {
    steps.push({
      id: `step-${stepNum++}`,
      type: "browser.click",
      selector: form.submitSelector,
      timestamp: Date.now() + stepNum * 100,
    } as Step);
  } else {
    // No submit button — press Enter
    steps.push({
      id: `step-${stepNum++}`,
      type: "browser.keypress",
      key: "Enter",
      timestamp: Date.now() + stepNum * 100,
    } as Step);
  }

  const inputNames = injectableInputs.map((i) => i.name || i.type).join(", ");
  const pagePath = (() => {
    try {
      return new URL(form.pageUrl).pathname;
    } catch {
      return form.pageUrl;
    }
  })();

  return {
    name: `Crawl: ${pagePath} — form ${index + 1} (${inputNames})`,
    driver: "browser",
    driverConfig: {
      startUrl: form.pageUrl,
      browser: "chromium",
      headless: true,
      viewport: { width: 1280, height: 720 },
    },
    steps,
    metadata: {
      recordedAt: new Date().toISOString(),
      version: "0.3.0",
      source: "crawler",
      formAction: form.action,
      formMethod: form.method,
    },
  };
}

// ── Utilities ──────────────────────────────────────────────────────────

function normalizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    if (parsed.pathname !== "/" && parsed.pathname.endsWith("/")) {
      parsed.pathname = parsed.pathname.slice(0, -1);
    }
    return parsed.href;
  } catch {
    return url;
  }
}
