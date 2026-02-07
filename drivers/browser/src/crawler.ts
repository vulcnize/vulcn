/**
 * Browser Crawler
 *
 * Automated session generator for the browser driver.
 * Crawls a web application using Playwright to discover:
 * - Forms with input fields and submit buttons
 * - Links to follow for deeper crawling
 *
 * Outputs Session[] that are directly compatible with BrowserRunner.
 *
 * This is the "auto-record" mode — instead of a human clicking around,
 * the crawler automatically discovers injection points.
 */

import type { Page, Browser, BrowserContext } from "playwright";
import type { Session, Step, CrawlOptions } from "@vulcn/engine";
import { launchBrowser, type BrowserType } from "./browser";

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

/**
 * Crawl a URL and generate sessions.
 *
 * This is called by the browser driver's recorder.crawl() method.
 */
export async function crawlAndBuildSessions(
  config: BrowserCrawlConfig,
  options: CrawlOptions = {},
): Promise<Session[]> {
  const opts = { ...CRAWL_DEFAULTS, ...options };
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
  return buildSessions(allForms);
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
        } else {
          selector = `form:nth-of-type(${formIndex + 1}) ${el.tagName.toLowerCase()}:nth-of-type(${inputIndex + 1})`;
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

async function discoverLinks(
  page: Page,
  origin: string,
  sameOrigin: boolean,
): Promise<string[]> {
  const links = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("a[href]"))
      .map((a) => (a as HTMLAnchorElement).href)
      .filter((href) => href.startsWith("http"));
  });

  if (sameOrigin) {
    return links.filter((link) => {
      try {
        return new URL(link).origin === origin;
      } catch {
        return false;
      }
    });
  }

  return links;
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
