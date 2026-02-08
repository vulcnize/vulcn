import { Command } from "commander";
import chalk from "chalk";
import { recordCommand } from "./record";
import { runCommand } from "./run";
import { crawlCommand } from "./crawl";
import { payloadsCommand } from "./payloads";
import { installCommand, doctorCommand } from "./install";
import { initCommand } from "./init";
import {
  pluginListCommand,
  pluginAddCommand,
  pluginRemoveCommand,
  pluginEnableCommand,
  pluginDisableCommand,
} from "./plugin";

const program = new Command();

program
  .name("vulcn")
  .description("Security testing recorder & runner")
  .version("0.4.0")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Quick Start:")}
  ${chalk.gray("$")} vulcn init                                  ${chalk.gray("Create config file")}
  ${chalk.gray("$")} vulcn record https://example.com             ${chalk.gray("Record browser session")}
  ${chalk.gray("$")} vulcn crawl https://example.com              ${chalk.gray("Auto-discover forms & inputs")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml                  ${chalk.gray("Run with default payloads")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml -p xss sqli     ${chalk.gray("Run with specific payloads")}

${chalk.cyan.bold("Docs:")} https://docs.vulcn.dev
`,
  );

// vulcn record
program
  .command("record")
  .description("Record browser interactions")
  .argument("<url>", "Starting URL to record from")
  .option("-o, --output <file>", "Output file path", "session.vulcn.yml")
  .option(
    "-b, --browser <browser>",
    "Browser to use (chromium, firefox, webkit)",
    "chromium",
  )
  .option("--headless", "Run in headless mode", false)
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Browsers:")}
  chromium       ${chalk.gray("Google Chrome / Chromium (default)")}
  firefox        ${chalk.gray("Mozilla Firefox")}
  webkit         ${chalk.gray("Apple Safari / WebKit")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn record https://example.com
  ${chalk.gray("$")} vulcn record https://example.com -o login-flow.vulcn.yml
  ${chalk.gray("$")} vulcn record https://example.com -b firefox
  ${chalk.gray("$")} vulcn record https://example.com --headless

${chalk.cyan.bold("How it works:")}
  1. Opens the target URL in a browser
  2. Records every interaction (clicks, typing, navigation)
  3. Press ${chalk.white("Ctrl+C")} to stop and save the session file
  4. Use ${chalk.white("vulcn run")} to replay with security payloads
`,
  )
  .action(recordCommand);

// vulcn crawl
program
  .command("crawl")
  .description("Auto-discover forms and injection points")
  .argument("<url>", "Target URL to crawl")
  .option(
    "-o, --output <dir>",
    "Output directory for session files",
    "./sessions",
  )
  .option("-d, --depth <n>", "Maximum crawl depth", "2")
  .option("-m, --max-pages <n>", "Maximum pages to visit", "20")
  .option("-b, --browser <browser>", "Browser to use", "chromium")
  .option("--headless", "Run in headless mode", true)
  .option("--no-headless", "Run with visible browser")
  .option("-t, --timeout <ms>", "Page timeout in ms", "10000")
  .option("--no-same-origin", "Allow following cross-origin links")
  .option(
    "--run-after <payloads...>",
    "Auto-run scans after crawl with these payloads",
  )
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("How it works:")}
  1. Visits the target URL and discovers all links
  2. Follows links up to ${chalk.white("--depth")} levels deep
  3. Discovers forms and injectable inputs on each page
  4. Generates a ${chalk.white(".vulcn.yml")} session file per form
  5. Optionally chains into ${chalk.white("vulcn run")} with ${chalk.white("--run-after")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn crawl https://example.com
  ${chalk.gray("$")} vulcn crawl https://example.com -d 3 -m 50
  ${chalk.gray("$")} vulcn crawl https://example.com -o ./scans
  ${chalk.gray("$")} vulcn crawl https://example.com --no-headless
  ${chalk.gray("$")} vulcn crawl https://example.com --run-after xss sqli

${chalk.cyan.bold("Benchmarking:")}
  ${chalk.gray("$")} docker run -d -p 3000:3000 bkimminich/juice-shop
  ${chalk.gray("$")} vulcn crawl http://localhost:3000 -d 3 --run-after xss sqli -r html
`,
  )
  .action((url: string, opts: Record<string, unknown>) => {
    crawlCommand(url, {
      output: opts.output as string,
      depth: parseInt(opts.depth as string, 10),
      maxPages: parseInt(opts.maxPages as string, 10),
      browser: opts.browser as string,
      headless: opts.headless as boolean,
      timeout: parseInt(opts.timeout as string, 10),
      sameOrigin: opts.sameOrigin as boolean,
      runAfter: opts.runAfter as string[] | undefined,
    });
  });

// vulcn run
program
  .command("run")
  .description("Run a recorded session with payloads")
  .argument("<session>", "Session file to run (.vulcn.yml)")
  .option("-p, --payload <names...>", "Payloads to use (see list below)")
  .option(
    "-f, --payload-file <file>",
    "Load custom payloads from YAML/JSON file",
  )
  .option("-b, --browser <browser>", "Browser to use", "chromium")
  .option("--headless", "Run in headless mode", true)
  .option("--no-headless", "Run with visible browser")
  .option(
    "-r, --report <format>",
    "Generate report (html, json, yaml, sarif, all)",
  )
  .option("--report-output <dir>", "Output directory for reports", ".")
  .option(
    "--passive",
    "Enable passive security scanner (headers, cookies, info-disclosure)",
  )
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Payload Types:")} ${chalk.gray("(fetched from PayloadsAllTheThings)")}
  ${chalk.red("xss")}                ${chalk.gray("Cross-Site Scripting — script injection, event handlers")}
  ${chalk.magenta("sqli")}               ${chalk.gray("SQL Injection — auth bypass, UNION, error-based")}
  ${chalk.cyan("xxe")}                ${chalk.gray("XML External Entity — file read, SSRF via XML")}
  ${chalk.yellow("cmd")}                ${chalk.gray("OS Command Injection — shell execution")}
  ${chalk.white("redirect")}           ${chalk.gray("Open Redirect — URL redirect to attacker domain")}
  ${chalk.green("traversal")}          ${chalk.gray("Path Traversal — directory traversal, exotic encoding")}

${chalk.cyan.bold("Report Formats:")}
  html               ${chalk.gray("Interactive HTML report (opens in browser)")}
  json               ${chalk.gray("Machine-readable JSON output")}
  yaml               ${chalk.gray("Human-readable YAML output")}
  sarif              ${chalk.gray("SARIF v2.1.0 for GitHub Code Scanning / CI")}
  all                ${chalk.gray("Generate all formats")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml                    ${chalk.gray("Default: xss payloads")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml -p xss sqli        ${chalk.gray("XSS + SQL injection")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml -p xss sqli cmd    ${chalk.gray("Multiple types")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml -p xss -r html     ${chalk.gray("With HTML report")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml -r sarif            ${chalk.gray("SARIF for CI/CD")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml --passive            ${chalk.gray("+ passive security scan")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml --no-headless       ${chalk.gray("Visible browser")}
  ${chalk.gray("$")} vulcn run session.vulcn.yml -f custom.yml       ${chalk.gray("Custom payload file")}
`,
  )
  .action(runCommand);

// vulcn payloads
program
  .command("payloads")
  .description("List available payloads")
  .option("-c, --category <category>", "Filter by category")
  .option("-f, --file <file>", "Also show payloads from custom file")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Categories:")}
  xss                ${chalk.gray("Cross-Site Scripting")}
  sqli               ${chalk.gray("SQL Injection")}
  ssrf               ${chalk.gray("Server-Side Request Forgery")}
  xxe                ${chalk.gray("XML External Entity")}
  command-injection  ${chalk.gray("OS Command Injection")}
  path-traversal     ${chalk.gray("Directory Traversal")}
  open-redirect      ${chalk.gray("Open Redirect")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn payloads                   ${chalk.gray("List all payloads")}
  ${chalk.gray("$")} vulcn payloads -c xss            ${chalk.gray("List XSS payloads only")}
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
${chalk.cyan.bold("Browsers:")}
  chromium           ${chalk.gray("Chromium (default, recommended)")}
  firefox            ${chalk.gray("Mozilla Firefox")}
  webkit             ${chalk.gray("Apple Safari / WebKit")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn install                    ${chalk.gray("Install Chromium only")}
  ${chalk.gray("$")} vulcn install firefox webkit     ${chalk.gray("Install specific browsers")}
  ${chalk.gray("$")} vulcn install --all              ${chalk.gray("Install all browsers")}

${chalk.cyan.bold("Note:")} Most users only need Chromium. Use ${chalk.white("vulcn doctor")} to check status.
`,
  )
  .action(installCommand);

// vulcn doctor
program
  .command("doctor")
  .description("Check available browsers and system status")
  .action(doctorCommand);

// vulcn init
program
  .command("init")
  .description("Create vulcn.config.yml with default configuration")
  .option("-f, --force", "Overwrite existing config file")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Generated Config:")}
  Creates ${chalk.white("vulcn.config.yml")} with:
  - Default plugins (payloads, XSS detection)
  - Browser settings (chromium, headless)

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn init                       ${chalk.gray("Create config")}
  ${chalk.gray("$")} vulcn init --force               ${chalk.gray("Overwrite existing config")}
`,
  )
  .action(initCommand);

// vulcn plugin (subcommands)
const pluginCmd = program
  .command("plugin")
  .description("Manage plugins")
  .addHelpText(
    "after",
    `
${chalk.cyan.bold("Available Plugins:")}
  @vulcn/plugin-payloads          ${chalk.gray("Payload loading (built-in, PayloadBox, custom)")}
  @vulcn/plugin-detect-xss        ${chalk.gray("XSS detection via dialog/console monitoring")}
  @vulcn/plugin-detect-sqli       ${chalk.gray("SQL injection detection (error, timing, diff)")}
  @vulcn/plugin-detect-reflection ${chalk.gray("Reflection detection in responses")}
  @vulcn/plugin-report            ${chalk.gray("Report generation (HTML, JSON, YAML)")}

${chalk.cyan.bold("Examples:")}
  ${chalk.gray("$")} vulcn plugin list
  ${chalk.gray("$")} vulcn plugin add @vulcn/plugin-detect-xss
  ${chalk.gray("$")} vulcn plugin add @vulcn/plugin-report -c '{"format":"html"}'
  ${chalk.gray("$")} vulcn plugin disable @vulcn/plugin-detect-xss
  ${chalk.gray("$")} vulcn plugin remove @vulcn/plugin-report
`,
  );

pluginCmd
  .command("list")
  .description("List configured plugins")
  .action(pluginListCommand);

pluginCmd
  .command("add")
  .description("Add a plugin to configuration")
  .argument("<name>", "Plugin name (e.g., @vulcn/plugin-detect-sqli)")
  .option("-c, --config <json>", "Plugin configuration as JSON")
  .action(pluginAddCommand);

pluginCmd
  .command("remove")
  .description("Remove a plugin from configuration")
  .argument("<name>", "Plugin name to remove")
  .action(pluginRemoveCommand);

pluginCmd
  .command("enable")
  .description("Enable a disabled plugin")
  .argument("<name>", "Plugin name to enable")
  .action(pluginEnableCommand);

pluginCmd
  .command("disable")
  .description("Disable a plugin without removing it")
  .argument("<name>", "Plugin name to disable")
  .action(pluginDisableCommand);

program.parse();
