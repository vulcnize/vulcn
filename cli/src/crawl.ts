import { resolve } from "node:path";
import { DriverManager } from "@vulcn/engine";
import type { AuthConfig } from "@vulcn/engine";
import { saveSessionDir } from "@vulcn/engine";
import browserDriver from "@vulcn/driver-browser";
import chalk from "chalk";
import ora from "ora";
import { performAuth } from "./auth-helper";

interface CrawlOptions {
  output: string;
  depth: number;
  maxPages: number;
  browser: string;
  headless: boolean;
  timeout: number;
  sameOrigin: boolean;
  runAfter?: string[];
  creds?: string;
}

export async function crawlCommand(url: string, options: CrawlOptions) {
  console.log();
  console.log(chalk.cyan("🕷️  Vulcn Crawler"));
  console.log(chalk.gray(`   Target: ${url}`));
  console.log(chalk.gray(`   Depth: ${options.depth}`));
  console.log(chalk.gray(`   Max pages: ${options.maxPages}`));
  console.log(chalk.gray(`   Browser: ${options.browser}`));
  console.log(chalk.gray(`   Same origin: ${options.sameOrigin}`));

  // Validate URL
  try {
    new URL(url);
  } catch {
    console.error(chalk.red(`Invalid URL: ${url}`));
    process.exit(1);
  }

  // Handle authentication
  let storageState: string | undefined;
  let authConfig: AuthConfig | undefined;
  let encryptedState: string | undefined;

  const auth = await performAuth({
    credsFile: options.creds ?? ".vulcn/auth.enc",
    browser: options.browser,
    headless: options.headless,
    targetUrl: url,
  });

  if (auth.storageState) {
    storageState = auth.storageState;
  }
  if (auth.authConfig) {
    authConfig = auth.authConfig;
  }
  if (auth.encryptedState) {
    encryptedState = auth.encryptedState;
  }

  if (storageState) {
    console.log(chalk.green(`   Auth: authenticated (storage state captured)`));
  }
  console.log();

  // Set up driver manager
  const drivers = new DriverManager();
  drivers.register(browserDriver);

  const crawlSpinner = ora("Starting crawl...").start();

  let pagesCrawled = 0;
  let formsFound = 0;

  try {
    const sessions = await drivers.crawl(
      "browser",
      {
        startUrl: url,
        browser: options.browser,
        headless: options.headless,
      },
      {
        maxDepth: options.depth,
        maxPages: options.maxPages,
        pageTimeout: options.timeout,
        sameOrigin: options.sameOrigin,
        ...(storageState ? { storageState } : {}),
        onPageCrawled: (pageUrl, forms) => {
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
      console.log(chalk.gray("   - Use --depth 3 to crawl deeper"));
      console.log(chalk.gray("   - Use --max-pages 50 to visit more pages"));
      console.log(
        chalk.gray(
          "   - Some SPAs need manual recording instead: vulcn record <url>",
        ),
      );
      return;
    }

    // Save sessions using v2 session directory format
    const saveSpinner = ora("Saving sessions...").start();

    const outputDir = resolve(options.output);
    const parsedUrl = new URL(url);

    await saveSessionDir(outputDir, {
      name: `crawl-${parsedUrl.hostname}`,
      target: url,
      driver: "browser",
      driverConfig: {
        browser: options.browser,
        headless: options.headless,
      },
      sessions,
      authConfig,
      encryptedState: storageState ? encryptedState : undefined,
    });

    saveSpinner.succeed(
      `Saved ${chalk.cyan(sessions.length)} session(s) to ${chalk.green(outputDir)}`,
    );

    // Summary table
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
    console.log(chalk.white(`  vulcn run ${outputDir} -p xss sqli`));

    // If --run-after was specified, chain into run
    if (options.runAfter && options.runAfter.length > 0) {
      console.log();
      console.log(chalk.cyan("🔍 Auto-running scans..."));
      console.log();

      // Dynamic import to avoid circular deps
      const { runCommand } = await import("./run");

      console.log(chalk.gray(`── Running: ${outputDir} ──`));
      try {
        await runCommand(outputDir, {
          payload: options.runAfter,
          browser: options.browser,
          headless: options.headless,
        });
      } catch {
        // runCommand handles its own errors and exits
      }
      console.log();
    }
  } catch (err) {
    crawlSpinner.fail("Crawl failed");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}
