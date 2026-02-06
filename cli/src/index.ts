import { Command } from "commander";
import { recordCommand } from "./record";
import { runCommand } from "./run";
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
  .version("0.2.0");

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
  .action(recordCommand);

// vulcn run
program
  .command("run")
  .description("Run a recorded session with payloads")
  .argument("<session>", "Session file to run (.vulcn.yml)")
  .option(
    "-p, --payload <names...>",
    "Payloads to use (e.g., xss-basic, sqli-basic)",
  )
  .option(
    "-f, --payload-file <file>",
    "Load custom payloads from YAML/JSON file",
  )
  .option("-b, --browser <browser>", "Browser to use", "chromium")
  .option("--headless", "Run in headless mode", true)
  .option("--no-headless", "Run with visible browser")
  .option("-r, --report <format>", "Generate report (html, json, yaml, all)")
  .option("--report-output <dir>", "Output directory for reports", ".")
  .action(runCommand);

// vulcn payloads
program
  .command("payloads")
  .description("List available payloads")
  .option("-c, --category <category>", "Filter by category")
  .option("-f, --file <file>", "Also show payloads from custom file")
  .action(payloadsCommand);

// vulcn install
program
  .command("install")
  .description("Install Playwright browsers")
  .argument("[browsers...]", "Browsers to install (chromium, firefox, webkit)")
  .option("--all", "Install all browsers")
  .action(installCommand);

// vulcn doctor
program
  .command("doctor")
  .description("Check available browsers")
  .action(doctorCommand);

// vulcn init
program
  .command("init")
  .description("Create vulcn.config.yml with default configuration")
  .option("-f, --force", "Overwrite existing config file")
  .action(initCommand);

// vulcn plugin (subcommands)
const pluginCmd = program.command("plugin").description("Manage plugins");

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
