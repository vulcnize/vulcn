/**
 * vulcn init — Create `.vulcn.yml` project config
 *
 * Creates a `.vulcn.yml` file in the current directory, marking it
 * as a Vulcn project. Also creates the `sessions/` directory.
 *
 * Usage:
 *   vulcn init                        # defaults to target: https://example.com
 *   vulcn init https://dvwa.local     # pre-fill target URL
 */

import { existsSync } from "node:fs";
import { writeFile, mkdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import chalk from "chalk";
import ora from "ora";
import YAML from "yaml";
import { CONFIG_FILENAME, DIRS } from "@vulcn/engine";

interface InitOptions {
  force?: boolean;
}

/**
 * Generate the default `.vulcn.yml` content with helpful comments.
 */
function generateConfig(target: string): string {
  const config = {
    target,

    scan: {
      browser: "chromium",
      headless: true,
      timeout: 30000,
    },

    payloads: {
      types: ["xss"],
      payloadbox: false,
      limit: 100,
      custom: null,
    },

    detection: {
      xss: {
        dialogs: true,
        console: true,
        domMutation: false,
        severity: "high",
      },
      reflection: {
        enabled: true,
      },
      passive: true,
    },

    crawl: {
      depth: 2,
      maxPages: 20,
      sameOrigin: true,
      timeout: 10000,
    },

    report: {
      format: "html",
    },
  };

  const yamlContent = YAML.stringify(config, {
    indent: 2,
    lineWidth: 120,
  });

  return `# Vulcn Project Configuration
# Docs: https://docs.vulcn.dev/config
#
# This file is the single source of truth for your Vulcn project.
# All commands auto-discover this file from the current directory.
#
# Convention:
#   sessions/   ← recorded/crawled sessions
#   auth/       ← encrypted credentials
#   reports/    ← generated reports

${yamlContent}`;
}

export async function initCommand(
  target: string | undefined,
  options: InitOptions,
) {
  const root = process.cwd();
  const configPath = resolve(root, CONFIG_FILENAME);
  const sessionsDir = resolve(root, DIRS.sessions);

  // Check if config already exists
  if (existsSync(configPath) && !options.force) {
    console.log(
      chalk.yellow(
        `⚠️  ${CONFIG_FILENAME} already exists. Use --force to overwrite.`,
      ),
    );
    process.exit(1);
  }

  const spinner = ora(`Creating ${CONFIG_FILENAME}...`).start();

  try {
    const targetUrl = target ?? "https://example.com";
    const content = generateConfig(targetUrl);

    await writeFile(configPath, content, "utf-8");

    // Create sessions/ directory
    if (!existsSync(sessionsDir)) {
      await mkdir(sessionsDir, { recursive: true });
    }

    spinner.succeed(`Created ${chalk.cyan(CONFIG_FILENAME)}`);

    console.log();
    console.log(chalk.cyan("📁 Project initialized"));
    console.log(chalk.gray(`   ${CONFIG_FILENAME}`));
    console.log(chalk.gray(`   ${DIRS.sessions}/`));
    console.log();
    console.log(chalk.gray("Next steps:"));

    if (target) {
      console.log(chalk.gray("  1. Crawl or record:"));
      console.log(chalk.white("     vulcn crawl"));
      console.log(chalk.white("     vulcn record"));
    } else {
      console.log(chalk.gray("  1. Set your target URL in .vulcn.yml, then:"));
      console.log(chalk.white("     vulcn crawl"));
      console.log(chalk.white("     vulcn record"));
    }

    console.log();
    console.log(chalk.gray("  2. Run security tests:"));
    console.log(chalk.white("     vulcn run"));
    console.log();
  } catch (err) {
    spinner.fail("Failed to create config");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}
