/**
 * vulcn init - Create vulcn.config.yml
 */

import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import chalk from "chalk";
import ora from "ora";
import YAML from "yaml";

interface InitOptions {
  force?: boolean;
}

const DEFAULT_CONFIG = {
  version: "1",
  plugins: [
    {
      name: "@vulcn/plugin-payloads",
      config: {
        builtin: true,
      },
    },
    {
      name: "@vulcn/plugin-detect-xss",
      config: {
        detectDialogs: true,
        detectConsole: true,
        severity: "high",
      },
    },
  ],
  settings: {
    browser: "chromium",
    headless: true,
  },
};

export async function initCommand(options: InitOptions) {
  const configFile = resolve(process.cwd(), "vulcn.config.yml");

  // Check if config already exists
  if (existsSync(configFile) && !options.force) {
    console.log(
      chalk.yellow(
        "⚠️  vulcn.config.yml already exists. Use --force to overwrite.",
      ),
    );
    process.exit(1);
  }

  const spinner = ora("Creating vulcn.config.yml...").start();

  try {
    const yamlContent = YAML.stringify(DEFAULT_CONFIG, {
      indent: 2,
      lineWidth: 120,
    });

    // Add helpful comments
    const content = `# Vulcn Configuration
# Docs: https://rawlab.dev/vulcn/config

${yamlContent}`;

    await writeFile(configFile, content, "utf-8");
    spinner.succeed("Created vulcn.config.yml");

    console.log();
    console.log(chalk.cyan("📁 Configuration created"));
    console.log();
    console.log(chalk.gray("Next steps:"));
    console.log(chalk.gray("  1. Record a session:"));
    console.log(
      chalk.white("     vulcn record https://example.com -o session.vulcn.yml"),
    );
    console.log();
    console.log(chalk.gray("  2. Run security tests:"));
    console.log(chalk.white("     vulcn run session.vulcn.yml"));
    console.log();
    console.log(chalk.gray("  3. Customize payloads:"));
    console.log(
      chalk.white(
        "     vulcn run session.vulcn.yml --payload xss-basic sqli-basic",
      ),
    );
    console.log();
  } catch (err) {
    spinner.fail("Failed to create config");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}
