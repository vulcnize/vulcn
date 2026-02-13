import { Command } from "commander";
import chalk from "chalk";
import { recordCommand } from "./record";
import { runCommand } from "./run";
import { crawlCommand } from "./crawl";
import { storeCommand } from "./store";
import { payloadsCommand } from "./payloads";
import { installCommand, doctorCommand } from "./install";
import { initCommand } from "./init";

const program = new Command();

program
  .name("vulcn")
  .description("Security testing recorder & runner")
  .version("0.5.0")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Quick Start:")}
  ${chalk.gray("$")} vulcn init https://example.com             ${chalk.gray("Create project")}
  ${chalk.gray("$")} vulcn crawl                                ${chalk.gray("Auto-discover forms & inputs")}
  ${chalk.gray("$")} vulcn run                                  ${chalk.gray("Run security tests")}

${chalk.cyan.bold("Manual Recording:")}
  ${chalk.gray("$")} vulcn record                               ${chalk.gray("Record browser session")}
  ${chalk.gray("$")} vulcn run                                  ${chalk.gray("Run with recorded sessions")}

${chalk.cyan.bold("Authenticated Scans:")}
  ${chalk.gray("$")} vulcn store admin password123               ${chalk.gray("Store credentials (encrypted)")}
  ${chalk.gray("$")} vulcn crawl                                ${chalk.gray("Crawl with auth (auto-detected)")}
  ${chalk.gray("$")} vulcn run                                  ${chalk.gray("Run with auth (auto-detected)")}

${chalk.cyan.bold("Project Structure:")}
  ${chalk.gray(".vulcn.yml")}      ${chalk.gray("← config (single source of truth)")}
  ${chalk.gray("sessions/")}       ${chalk.gray("← recorded/crawled sessions")}
  ${chalk.gray("auth/")}           ${chalk.gray("← encrypted credentials")}
  ${chalk.gray("reports/")}        ${chalk.gray("← generated reports")}

${chalk.cyan.bold("Docs:")} https://docs.vulcn.dev
`,
  );

// vulcn init
program
  .command("init")
  .description("Create .vulcn.yml project config")
  .argument("[url]", "Target URL to scan")
  .option("-f, --force", "Overwrite existing config file")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn init                       ${chalk.gray("Create with defaults")}
  ${chalk.gray("$")} vulcn init https://dvwa.local     ${chalk.gray("Create with target pre-filled")}
  ${chalk.gray("$")} vulcn init --force                ${chalk.gray("Overwrite existing config")}
`,
  )
  .action(initCommand);

// vulcn record
program
  .command("record")
  .description("Record browser interactions")
  .argument("[url]", "Target URL (overrides .vulcn.yml)")
  .option("-o, --output <file>", "Output filename (saved to sessions/)")
  .option(
    "-b, --browser <browser>",
    "Browser to use (chromium, firefox, webkit)",
  )
  .option("--headless", "Run in headless mode")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("How it works:")}
  1. Reads target URL from ${chalk.white(".vulcn.yml")} (or CLI arg)
  2. Opens the browser and records every interaction
  3. Press ${chalk.white("Ctrl+C")} to stop and save to ${chalk.white("sessions/")}
  4. Run ${chalk.white("vulcn run")} to replay with security payloads

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn record                               ${chalk.gray("Target from .vulcn.yml")}
  ${chalk.gray("$")} vulcn record https://dvwa.local             ${chalk.gray("Override target")}
  ${chalk.gray("$")} vulcn record -b firefox                     ${chalk.gray("Use Firefox")}
`,
  )
  .action(recordCommand);

// vulcn crawl
program
  .command("crawl")
  .description("Auto-discover forms and injection points")
  .argument("[url]", "Target URL (overrides .vulcn.yml)")
  .option("-d, --depth <n>", "Maximum crawl depth")
  .option("-m, --max-pages <n>", "Maximum pages to visit")
  .option("-b, --browser <browser>", "Browser to use")
  .option("--headless", "Run in headless mode", true)
  .option("--no-headless", "Run with visible browser")
  .option("--no-same-origin", "Allow following cross-origin links")
  .option("-t, --timeout <ms>", "Page timeout in ms")
  .option("--run", "Auto-run scan after crawl")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("How it works:")}
  1. Reads target from ${chalk.white(".vulcn.yml")} and crawl settings
  2. Visits pages and discovers forms & injectable inputs
  3. Saves sessions to ${chalk.white("sessions/")}
  4. Optionally chains into ${chalk.white("vulcn run")} with ${chalk.white("--run")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn crawl                                ${chalk.gray("Target from .vulcn.yml")}
  ${chalk.gray("$")} vulcn crawl https://dvwa.local             ${chalk.gray("Override target")}
  ${chalk.gray("$")} vulcn crawl -d 3 -m 50                     ${chalk.gray("Deep crawl")}
  ${chalk.gray("$")} vulcn crawl --run                           ${chalk.gray("Crawl then scan")}
  ${chalk.gray("$")} vulcn crawl --no-headless                   ${chalk.gray("Visible browser")}
`,
  )
  .action((url: string | undefined, opts: Record<string, unknown>) => {
    crawlCommand(url, {
      depth: opts.depth ? parseInt(opts.depth as string, 10) : undefined,
      maxPages: opts.maxPages
        ? parseInt(opts.maxPages as string, 10)
        : undefined,
      browser: opts.browser as string | undefined,
      headless: opts.headless as boolean | undefined,
      timeout: opts.timeout ? parseInt(opts.timeout as string, 10) : undefined,
      sameOrigin: opts.sameOrigin as boolean | undefined,
      run: opts.run as boolean | undefined,
    });
  });

// vulcn run
program
  .command("run")
  .description("Run security tests")
  .option("-p, --payload <names...>", "Payload types (overrides .vulcn.yml)")
  .option(
    "-f, --payload-file <file>",
    "Load custom payloads from YAML/JSON file",
  )
  .option("-b, --browser <browser>", "Browser (overrides .vulcn.yml)")
  .option("--headless", "Run in headless mode")
  .option("--no-headless", "Run with visible browser")
  .option(
    "-r, --report <format>",
    "Report format (overrides .vulcn.yml): html, json, yaml, sarif, all",
  )
  .option("--report-output <dir>", "Output directory for reports")
  .option("--passive", "Enable passive scanner (overrides .vulcn.yml)")
  .option("--no-passive", "Disable passive scanner")
  .option("--payloadbox", "Also load PayloadsAllTheThings payloads", false)
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("How it works:")}
  1. Reads all config from ${chalk.white(".vulcn.yml")}
  2. Loads sessions from ${chalk.white("sessions/")}
  3. CLI flags override config values for this run only
  4. Auto-discovers auth from ${chalk.white("auth/state.enc")}
  5. Saves reports to ${chalk.white("reports/")}

${chalk.cyan.bold("Payload Types:")} ${chalk.gray("(curated context-aware payloads)")}
  ${chalk.red("xss")}                ${chalk.gray("Cross-Site Scripting")}
  ${chalk.magenta("sqli")}               ${chalk.gray("SQL Injection")}
  ${chalk.cyan("xxe")}                ${chalk.gray("XML External Entity")}
  ${chalk.yellow("cmd")}                ${chalk.gray("OS Command Injection")}
  ${chalk.white("redirect")}           ${chalk.gray("Open Redirect")}
  ${chalk.green("traversal")}          ${chalk.gray("Path Traversal")}

${chalk.cyan.bold("Report Formats:")}
  html               ${chalk.gray("Interactive HTML report")}
  json               ${chalk.gray("Machine-readable JSON")}
  yaml               ${chalk.gray("Human-readable YAML")}
  sarif              ${chalk.gray("SARIF v2.1.0 for CI/CD")}
  all                ${chalk.gray("All formats")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn run                                  ${chalk.gray("Uses .vulcn.yml config")}
  ${chalk.gray("$")} vulcn run -p xss sqli                      ${chalk.gray("Override payload types")}
  ${chalk.gray("$")} vulcn run --no-headless                     ${chalk.gray("Visible browser")}
  ${chalk.gray("$")} vulcn run -r sarif                          ${chalk.gray("SARIF report for CI")}
`,
  )
  .action(runCommand);

// vulcn store
program
  .command("store")
  .description("Store encrypted credentials for authenticated scans")
  .argument("[username]", "Username for form-based login")
  .argument("[password]", "Password for form-based login")
  .option(
    "--header <header>",
    'Header auth (e.g., "Authorization: Bearer xyz")',
  )
  .option(
    "--passphrase <passphrase>",
    "Encryption passphrase (or set VULCN_KEY)",
  )
  .option("--login-url <url>", "Custom login URL (overrides .vulcn.yml)")
  .option("--user-field <selector>", "CSS selector for username field")
  .option("--pass-field <selector>", "CSS selector for password field")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("How it works:")}
  1. Encrypts credentials with AES-256-GCM
  2. Saves to ${chalk.white("auth/state.enc")} next to ${chalk.white(".vulcn.yml")}
  3. ${chalk.white("vulcn crawl")} and ${chalk.white("vulcn run")} auto-discover auth

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn store admin password123               ${chalk.gray("Form auth")}
  ${chalk.gray("$")} vulcn store --header "Authorization: Bearer abc"
  ${chalk.gray("$")} VULCN_KEY=mykey vulcn store admin pass     ${chalk.gray("CI/CD (no prompt)")}
`,
  )
  .action(storeCommand);

// vulcn payloads
program
  .command("payloads")
  .description("List available payloads")
  .option("-c, --category <category>", "Filter by category")
  .option("-f, --file <file>", "Also show payloads from custom file")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn payloads                   ${chalk.gray("List all")}
  ${chalk.gray("$")} vulcn payloads -c xss            ${chalk.gray("XSS payloads only")}
  ${chalk.gray("$")} vulcn payloads -f custom.yml      ${chalk.gray("Include custom payloads")}
`,
  )
  .action(payloadsCommand);

// vulcn install
program
  .command("install")
  .description("Install Playwright browsers")
  .argument("[browsers...]", "Browsers to install (chromium, firefox, webkit)")
  .option("--all", "Install all browsers")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn install                    ${chalk.gray("Install Chromium")}
  ${chalk.gray("$")} vulcn install firefox webkit     ${chalk.gray("Specific browsers")}
  ${chalk.gray("$")} vulcn install --all              ${chalk.gray("All browsers")}
`,
  )
  .action(installCommand);

// vulcn doctor
program
  .command("doctor")
  .description("Check available browsers and system status")
  .action(doctorCommand);

program.parse();
