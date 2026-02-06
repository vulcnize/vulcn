/**
 * Browser utilities for @vulcn/driver-browser
 * Smart browser launching with system browser fallback
 */

import { chromium, firefox, webkit, type Browser } from "playwright";
import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);

export type BrowserType = "chromium" | "firefox" | "webkit";

export interface LaunchOptions {
  browser?: BrowserType;
  headless?: boolean;
}

export interface BrowserLaunchResult {
  browser: Browser;
  channel?: string;
}

export class BrowserNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowserNotFoundError";
  }
}

/**
 * Launch a browser with smart fallback:
 * 1. Try system Chrome/Edge first (zero-install experience)
 * 2. Fall back to Playwright's bundled browsers
 */
export async function launchBrowser(
  options: LaunchOptions = {},
): Promise<BrowserLaunchResult> {
  const browserType = options.browser ?? "chromium";
  const headless = options.headless ?? false;

  // For Chromium, try system browsers first
  if (browserType === "chromium") {
    // Try system Chrome
    try {
      const browser = await chromium.launch({
        channel: "chrome",
        headless,
      });
      return { browser, channel: "chrome" };
    } catch {
      // Chrome not available
    }

    // Try system Edge
    try {
      const browser = await chromium.launch({
        channel: "msedge",
        headless,
      });
      return { browser, channel: "msedge" };
    } catch {
      // Edge not available
    }

    // Fall back to Playwright's bundled Chromium
    try {
      const browser = await chromium.launch({ headless });
      return { browser, channel: "chromium" };
    } catch {
      throw new BrowserNotFoundError(
        "No Chromium browser found. Install Chrome or run: vulcn install chromium",
      );
    }
  }

  // Firefox
  if (browserType === "firefox") {
    try {
      const browser = await firefox.launch({ headless });
      return { browser, channel: "firefox" };
    } catch {
      throw new BrowserNotFoundError(
        "Firefox not found. Run: vulcn install firefox",
      );
    }
  }

  // WebKit
  if (browserType === "webkit") {
    try {
      const browser = await webkit.launch({ headless });
      return { browser, channel: "webkit" };
    } catch {
      throw new BrowserNotFoundError(
        "WebKit not found. Run: vulcn install webkit",
      );
    }
  }

  throw new BrowserNotFoundError(`Unknown browser type: ${browserType}`);
}

/**
 * Install Playwright browsers
 */
export async function installBrowsers(
  browsers: BrowserType[] = ["chromium"],
): Promise<void> {
  const browserArg = browsers.join(" ");
  await execAsync(`npx playwright install ${browserArg}`);
}

/**
 * Check which browsers are available
 */
export async function checkBrowsers(): Promise<{
  systemChrome: boolean;
  systemEdge: boolean;
  playwrightChromium: boolean;
  playwrightFirefox: boolean;
  playwrightWebkit: boolean;
}> {
  const results = {
    systemChrome: false,
    systemEdge: false,
    playwrightChromium: false,
    playwrightFirefox: false,
    playwrightWebkit: false,
  };

  // Check system Chrome
  try {
    const browser = await chromium.launch({
      channel: "chrome",
      headless: true,
    });
    await browser.close();
    results.systemChrome = true;
  } catch {
    // Not available
  }

  // Check system Edge
  try {
    const browser = await chromium.launch({
      channel: "msedge",
      headless: true,
    });
    await browser.close();
    results.systemEdge = true;
  } catch {
    // Not available
  }

  // Check Playwright Chromium
  try {
    const browser = await chromium.launch({ headless: true });
    await browser.close();
    results.playwrightChromium = true;
  } catch {
    // Not installed
  }

  // Check Playwright Firefox
  try {
    const browser = await firefox.launch({ headless: true });
    await browser.close();
    results.playwrightFirefox = true;
  } catch {
    // Not installed
  }

  // Check Playwright WebKit
  try {
    const browser = await webkit.launch({ headless: true });
    await browser.close();
    results.playwrightWebkit = true;
  } catch {
    // Not installed
  }

  return results;
}
