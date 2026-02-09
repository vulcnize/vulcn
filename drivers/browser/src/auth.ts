/**
 * Login Form Auto-Detection & Auth Replay
 *
 * Detects login forms on a page and fills them with credentials.
 * After login, captures the browser storage state (cookies + localStorage)
 * for re-use in subsequent scans.
 *
 * Detection strategy:
 * 1. Find forms with a password input (strongest signal)
 * 2. Find username field via heuristics (name, id, autocomplete, type)
 * 3. Find submit button
 * 4. Fall back to custom selectors from credentials
 */

import type { Page, BrowserContext } from "playwright";
import type { FormCredentials } from "@vulcn/engine";

// ── Types ──────────────────────────────────────────────────────────────

export interface LoginForm {
  /** Username input selector */
  usernameSelector: string;
  /** Password input selector */
  passwordSelector: string;
  /** Submit button selector (may be null if not found) */
  submitSelector: string | null;
  /** Whether the form was detected automatically */
  autoDetected: boolean;
}

export interface LoginResult {
  /** Whether login succeeded */
  success: boolean;
  /** Message for logging */
  message: string;
  /** Playwright storage state JSON (cookies + localStorage) */
  storageState?: string;
}

// ── Detection ──────────────────────────────────────────────────────────

/**
 * Auto-detect a login form on the current page.
 *
 * Strategy:
 * 1. Find `<form>` elements containing an `input[type="password"]`
 * 2. Within that form, find the username field using heuristics
 * 3. Find the submit button
 *
 * Falls back to page-wide search if no enclosing <form> is found.
 */
export async function detectLoginForm(page: Page): Promise<LoginForm | null> {
  return page.evaluate(() => {
    // Helper: find the best username input in a container
    function findUsernameInput(container: Element): HTMLInputElement | null {
      // Priority-ordered selectors for username fields
      const selectors = [
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
        'input[type="email"]',
        'input[name*="user" i]',
        'input[name*="login" i]',
        'input[name*="email" i]',
        'input[id*="user" i]',
        'input[id*="login" i]',
        'input[id*="email" i]',
        'input[name*="name" i]',
        'input[type="text"]',
      ];

      for (const sel of selectors) {
        const el = container.querySelector(sel) as HTMLInputElement | null;
        if (el && el.type !== "password" && el.type !== "hidden") {
          return el;
        }
      }

      return null;
    }

    // Helper: find submit button in a container
    function findSubmitButton(container: Element): HTMLElement | null {
      const selectors = [
        'button[type="submit"]',
        'input[type="submit"]',
        "button:not([type])",
        'button[type="button"]',
      ];

      for (const sel of selectors) {
        const el = container.querySelector(sel) as HTMLElement | null;
        if (el) return el;
      }

      return null;
    }

    // Helper: get a unique CSS selector for an element
    function getSelector(el: Element): string {
      if (el.id) return `#${CSS.escape(el.id)}`;
      if (el.getAttribute("name"))
        return `${el.tagName.toLowerCase()}[name="${CSS.escape(el.getAttribute("name")!)}"]`;
      if (el.getAttribute("type") && el.tagName === "INPUT")
        return `input[type="${el.getAttribute("type")}"]`;

      // Fall back to nth-child
      const parent = el.parentElement;
      if (!parent) return el.tagName.toLowerCase();
      const siblings = Array.from(parent.children);
      const index = siblings.indexOf(el) + 1;
      return `${parent.tagName.toLowerCase()} > ${el.tagName.toLowerCase()}:nth-child(${index})`;
    }

    // Strategy 1: Find <form> containing password input
    const forms = document.querySelectorAll("form");
    for (const form of forms) {
      const passwordInput = form.querySelector(
        'input[type="password"]',
      ) as HTMLInputElement | null;
      if (!passwordInput) continue;

      const usernameInput = findUsernameInput(form);
      const submitButton = findSubmitButton(form);

      return {
        usernameSelector: usernameInput
          ? getSelector(usernameInput)
          : 'input[type="text"]',
        passwordSelector: getSelector(passwordInput),
        submitSelector: submitButton ? getSelector(submitButton) : null,
        autoDetected: true,
      };
    }

    // Strategy 2: No <form> — look for password input anywhere on page
    const passwordInput = document.querySelector(
      'input[type="password"]',
    ) as HTMLInputElement | null;
    if (passwordInput) {
      const usernameInput = findUsernameInput(document.body);
      const submitButton = findSubmitButton(document.body);

      return {
        usernameSelector: usernameInput
          ? getSelector(usernameInput)
          : 'input[type="text"]',
        passwordSelector: getSelector(passwordInput),
        submitSelector: submitButton ? getSelector(submitButton) : null,
        autoDetected: true,
      };
    }

    return null;
  });
}

// ── Login ──────────────────────────────────────────────────────────────

/**
 * Perform login using detected form or custom selectors.
 *
 * Flow:
 * 1. Navigate to login URL (or target URL)
 * 2. Detect login form (or use custom selectors from credentials)
 * 3. Fill username + password
 * 4. Submit form
 * 5. Wait for navigation
 * 6. Check for logged-in indicator
 * 7. Capture storage state
 */
export async function performLogin(
  page: Page,
  context: BrowserContext,
  credentials: FormCredentials,
  options: {
    targetUrl: string;
    loggedInIndicator?: string;
    loggedOutIndicator?: string;
  },
): Promise<LoginResult> {
  const loginUrl = credentials.loginUrl ?? options.targetUrl;

  // Navigate to login page
  await page.goto(loginUrl, { waitUntil: "domcontentloaded", timeout: 15000 });

  // Determine selectors — custom overrides or auto-detect
  let usernameSelector: string;
  let passwordSelector: string;
  let submitSelector: string | null;

  if (credentials.userSelector && credentials.passSelector) {
    // Use custom selectors
    usernameSelector = credentials.userSelector;
    passwordSelector = credentials.passSelector;
    submitSelector = null; // Will try to find automatically
  } else {
    // Auto-detect
    const form = await detectLoginForm(page);

    if (!form) {
      return {
        success: false,
        message: `No login form detected on ${loginUrl}. Use --user-field and --pass-field to specify selectors.`,
      };
    }

    usernameSelector = form.usernameSelector;
    passwordSelector = form.passwordSelector;
    submitSelector = form.submitSelector;
  }

  // Fill credentials
  try {
    await page.fill(usernameSelector, credentials.username, { timeout: 5000 });
  } catch {
    return {
      success: false,
      message: `Could not find username field: ${usernameSelector}`,
    };
  }

  try {
    await page.fill(passwordSelector, credentials.password, { timeout: 5000 });
  } catch {
    return {
      success: false,
      message: `Could not find password field: ${passwordSelector}`,
    };
  }

  // Submit form
  try {
    if (submitSelector) {
      await Promise.all([
        page
          .waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 })
          .catch(() => {}),
        page.click(submitSelector, { timeout: 5000 }),
      ]);
    } else {
      // Try pressing Enter on the password field
      await Promise.all([
        page
          .waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 })
          .catch(() => {}),
        page.press(passwordSelector, "Enter"),
      ]);
    }
  } catch {
    return {
      success: false,
      message: "Failed to submit login form",
    };
  }

  // Wait for page to settle
  await page.waitForTimeout(1000);

  // Check if login succeeded
  const bodyText = await page.textContent("body").catch(() => "");

  if (
    options.loggedOutIndicator &&
    bodyText?.includes(options.loggedOutIndicator)
  ) {
    return {
      success: false,
      message: `Login failed — "${options.loggedOutIndicator}" still visible on page`,
    };
  }

  if (
    options.loggedInIndicator &&
    !bodyText?.includes(options.loggedInIndicator)
  ) {
    return {
      success: false,
      message: `Login uncertain — "${options.loggedInIndicator}" not found on page`,
    };
  }

  // Capture storage state (cookies + localStorage)
  const storageState = JSON.stringify(await context.storageState());

  return {
    success: true,
    message: "Login successful",
    storageState,
  };
}

// ── Session Expiry Detection ───────────────────────────────────────────

/**
 * Check if the current session is still alive.
 *
 * Used during long-running scans to detect session expiry
 * and trigger re-authentication.
 */
export async function checkSessionAlive(
  page: Page,
  config: {
    loggedInIndicator?: string;
    loggedOutIndicator?: string;
  },
): Promise<boolean> {
  try {
    const bodyText = await page.textContent("body");
    if (!bodyText) return true; // Can't determine, assume alive

    // Check for logged-out indicator (strongest signal of expiry)
    if (
      config.loggedOutIndicator &&
      bodyText.includes(config.loggedOutIndicator)
    ) {
      return false;
    }

    // Check for missing logged-in indicator
    if (
      config.loggedInIndicator &&
      !bodyText.includes(config.loggedInIndicator)
    ) {
      return false;
    }

    return true;
  } catch {
    // Page error — assume session is dead
    return false;
  }
}
