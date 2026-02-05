import { Command } from "commander";
import { recordCommand } from "./record";
import { runCommand } from "./run";
import { payloadsCommand } from "./payloads";
import { installCommand, doctorCommand } from "./install";

const program = new Command();

program
  .name("vulcn")
  .description("Security testing recorder & runner")
  .version("0.1.0");

// vulcn record
program
  .command("record")
  .description("Record browser interactions")
  .requiredOption("-u, --url <url>", "Starting URL to record from")
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
  .option("-b, --browser <browser>", "Browser to use", "chromium")
  .option("--headless", "Run in headless mode", true)
  .option("--no-headless", "Run with visible browser")
  .action(runCommand);

// vulcn payloads
program
  .command("payloads")
  .description("List available payloads")
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

program.parse();
