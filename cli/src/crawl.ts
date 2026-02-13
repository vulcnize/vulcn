/**
 * vulcn crawl — Auto-discover forms and injection points
 *
 * Reads target from `.vulcn.yml`, crawls the site, saves sessions
 * to `sessions/` directory.
 *
 * Usage:
 *   vulcn crawl                        # reads target from .vulcn.yml
 *   vulcn crawl https://dvwa.local     # override target URL
 */

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DriverManager } from "@vulcn/engine";
import {
  loadProject,
  ensureProjectDirs,
  decryptStorageState,
  getPassphrase,
} from "@vulcn/engine";
import type { Session } from "@vulcn/engine";
import browserDriver from "@vulcn/driver-browser";
import chalk from "chalk";
import ora from "ora";
import { stringify } from "yaml";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";

interface CrawlOptions {
  depth?: number;
  maxPages?: number;
  browser?: string;
  headless?: boolean;
  timeout?: number;
  sameOrigin?: boolean;
  run?: boolean;
}

export async function crawlCommand(
  urlArg: string | undefined,
  options: CrawlOptions,
) {
  // ── Load project config ──────────────────────────────────────────────

  let project;
  try {
    project = await loadProject();
  } catch (err) {
    console.error(chalk.red(String(err)));
    process.exit(1);
  }

  const { config, paths } = project;

  // Target URL: CLI arg > config
  const targetUrl = urlArg ?? config.target;
  if (!targetUrl) {
    console.error(
      chalk.red(
        "No target URL. Set it in .vulcn.yml or pass as argument: vulcn crawl <url>",
      ),
    );
    process.exit(1);
  }

  // Validate URL
  try {
    new URL(targetUrl);
  } catch {
    console.error(chalk.red(`Invalid URL: ${targetUrl}`));
    process.exit(1);
  }

  // Merge config with CLI overrides
  const crawlConfig = {
    depth: options.depth ?? config.crawl.depth,
    maxPages: options.maxPages ?? config.crawl.maxPages,
    sameOrigin: options.sameOrigin ?? config.crawl.sameOrigin,
    timeout: options.timeout ?? config.crawl.timeout,
    browser: options.browser ?? config.scan.browser,
    headless: options.headless ?? config.scan.headless,
  };

  console.log();
  console.log(chalk.cyan("🕷️  Vulcn Crawler"));
  console.log(chalk.gray(`   Target: ${targetUrl}`));
  console.log(chalk.gray(`   Depth: ${crawlConfig.depth}`));
  console.log(chalk.gray(`   Max pages: ${crawlConfig.maxPages}`));
  console.log(chalk.gray(`   Browser: ${crawlConfig.browser}`));
  console.log(chalk.gray(`   Same origin: ${crawlConfig.sameOrigin}`));

  // ── Load auth state ──────────────────────────────────────────────────

  let storageState: string | undefined;
  const authStatePath = join(paths.auth, "state.enc");

  if (existsSync(authStatePath)) {
    try {
      const passphrase = getPassphrase();
      const encrypted = await readFile(authStatePath, "utf-8");
      storageState = decryptStorageState(encrypted, passphrase);
      console.log(chalk.green(`   Auth: authenticated`));
    } catch {
      console.log(
        chalk.yellow(
          "   ⚠️  Auth state found but VULCN_KEY not set — crawling without auth",
        ),
      );
    }
  }

  console.log();

  // ── Crawl ────────────────────────────────────────────────────────────

  const drivers = new DriverManager();
  drivers.register(browserDriver);

  await ensureProjectDirs(paths, ["sessions"]);

  const crawlSpinner = ora("Starting crawl...").start();
  let pagesCrawled = 0;
  let formsFound = 0;

  try {
    const sessions = await drivers.crawl(
      "browser",
      {
        startUrl: targetUrl,
        browser: crawlConfig.browser,
        headless: crawlConfig.headless,
      },
      {
        maxDepth: crawlConfig.depth,
        maxPages: crawlConfig.maxPages,
        pageTimeout: crawlConfig.timeout,
        sameOrigin: crawlConfig.sameOrigin,
        ...(storageState ? { storageState } : {}),
        onPageCrawled: (pageUrl: string, forms: number) => {
          pagesCrawled++;
          formsFound += forms;
          crawlSpinner.text = `Crawling... ${pagesCrawled} pages, ${formsFound} forms`;
        },
      },
    );

    crawlSpinner.succeed(
      `Crawl complete: ${chalk.cyan(pagesCrawled)} pages, ${chalk.cyan(formsFound)} forms found`,
    );

    if (sessions.length === 0) {
      console.log();
      console.log(
        chalk.yellow(
          "⚠️  No injectable forms found. Try increasing depth or checking the target.",
        ),
      );
      console.log(chalk.gray("   Tips:"));
      console.log(chalk.gray("   - Set crawl.depth: 3 in .vulcn.yml"));
      console.log(chalk.gray("   - Set crawl.maxPages: 50 in .vulcn.yml"));
      console.log(
        chalk.gray("   - Some SPAs need manual recording: vulcn record"),
      );
      return;
    }

    // ── Save sessions ─────────────────────────────────────────────────

    const saveSpinner = ora("Saving sessions...").start();

    for (const session of sessions) {
      const filename = slugify(session.name) + ".yml";
      const filepath = join(paths.sessions, filename);
      const yaml = stringify(session);
      await writeFile(filepath, yaml, "utf-8");
    }

    saveSpinner.succeed(
      `Saved ${chalk.cyan(sessions.length)} session(s) to ${chalk.green("sessions/")}`,
    );

    // Summary
    console.log();
    console.log(chalk.cyan("📋 Generated Sessions"));
    console.log();

    for (let i = 0; i < sessions.length; i++) {
      const session = sessions[i];
      const injectableCount = session.steps.filter(
        (s) =>
          s.type === "browser.input" &&
          (s as Record<string, unknown>).injectable,
      ).length;
      console.log(`  ${chalk.white(`${i + 1}.`)} ${chalk.gray(session.name)}`);
      console.log(
        chalk.gray(
          `     ${injectableCount} injectable input(s), ${session.steps.length} steps`,
        ),
      );
    }

    console.log();
    console.log(chalk.gray("Next steps:"));
    console.log(chalk.white("  vulcn run"));

    // ── Auto-chain into run ───────────────────────────────────────────

    if (options.run) {
      console.log();
      console.log(chalk.cyan("🔍 Auto-running scan..."));
      console.log();

      const { runCommand } = await import("./run");
      try {
        await runCommand({
          browser: crawlConfig.browser,
          headless: crawlConfig.headless,
        });
      } catch {
        // runCommand handles its own errors
      }
    }
  } catch (err) {
    crawlSpinner.fail("Crawl failed");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}

/**
 * Convert a string to a safe filename slug.
 */
function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}
