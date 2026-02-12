/**
 * Shared authentication helper for CLI commands.
 *
 * Both `vulcn run` and `vulcn crawl` perform the exact same auth dance:
 *   1. Check for creds file
 *   2. Decrypt credentials
 *   3. Form login or header injection
 *   4. Capture storage state
 *
 * This module centralizes that logic.
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { decryptCredentials, getPassphrase } from "@vulcn/engine";
import type { Credentials, AuthConfig } from "@vulcn/engine";
import chalk from "chalk";
import ora from "ora";

export interface AuthResult {
  /** Browser storage state JSON (for form auth) */
  storageState?: string;
  /** Decrypted credentials object */
  credentials?: Credentials;
  /** Auth config for session metadata */
  authConfig?: AuthConfig;
  /** Raw encrypted auth file content (for saving alongside sessions) */
  encryptedState?: string;
  /** Extra headers to inject (for header auth) */
  extraHeaders?: Record<string, string>;
}

export interface AuthOptions {
  /** Path to encrypted credentials file */
  credsFile?: string;
  /** Browser type for form login */
  browser: string;
  /** Run browser headless */
  headless: boolean;
  /** Target URL for form login (where to navigate after auth) */
  targetUrl?: string;
}

/**
 * Perform authentication using encrypted credentials.
 *
 * Returns an AuthResult with storage state, credentials, and/or extra headers.
 * Returns an empty object if no auth is needed or auth fails gracefully.
 */
export async function performAuth(options: AuthOptions): Promise<AuthResult> {
  const credsFile = options.credsFile ?? ".vulcn/auth.enc";

  if (!existsSync(credsFile)) {
    return {};
  }

  const authSpinner = ora("Authenticating...").start();

  try {
    const encrypted = await readFile(credsFile, "utf-8");

    let passphrase: string;
    try {
      passphrase = getPassphrase();
    } catch {
      authSpinner.fail(
        "Credentials found but no passphrase. Set VULCN_KEY or use --passphrase.",
      );
      return {};
    }

    const credentials = decryptCredentials(encrypted, passphrase);

    if (credentials.type === "form") {
      const { launchBrowser, performLogin } =
        await import("@vulcn/driver-browser");

      const { browser } = await launchBrowser({
        browser: options.browser as "chromium" | "firefox" | "webkit",
        headless: options.headless,
      });

      const context = await browser.newContext();
      const page = await context.newPage();

      const result = await performLogin(page, context, credentials, {
        targetUrl: options.targetUrl ?? "http://localhost",
      });

      await page.close();
      await context.close();
      await browser.close();

      if (result.success) {
        authSpinner.succeed(
          `Authenticated as ${chalk.cyan(credentials.username)}`,
        );
        return {
          storageState: result.storageState,
          credentials,
          authConfig: {
            strategy: "storage-state",
            loginUrl: credentials.loginUrl,
          },
          encryptedState: encrypted,
        };
      } else {
        authSpinner.warn(
          `Login failed: ${result.message} — continuing without auth`,
        );
        return {};
      }
    } else if (credentials.type === "header") {
      authSpinner.succeed("Loaded header credentials");
      return {
        credentials,
        authConfig: { strategy: "header" },
        extraHeaders: credentials.headers,
        encryptedState: encrypted,
      };
    }

    return {};
  } catch (err) {
    authSpinner.warn(`Auth failed: ${err} — continuing without auth`);
    return {};
  }
}
