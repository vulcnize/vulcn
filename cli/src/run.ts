import { readFile } from "node:fs/promises";
import {
  Runner,
  parseSession,
  type BrowserType,
  type PayloadName,
} from "@vulcn/engine";
import chalk from "chalk";
import ora from "ora";

interface RunOptions {
  payload?: string[];
  browser: string;
  headless: boolean;
}

export async function runCommand(sessionFile: string, options: RunOptions) {
  // Load session
  const loadSpinner = ora("Loading session...").start();

  let sessionYaml: string;
  try {
    sessionYaml = await readFile(sessionFile, "utf-8");
  } catch {
    loadSpinner.fail(`Cannot read file: ${sessionFile}`);
    process.exit(1);
  }

  let session;
  try {
    session = parseSession(sessionYaml);
    loadSpinner.succeed(`Loaded session: ${chalk.cyan(session.name)}`);
  } catch (err) {
    loadSpinner.fail("Invalid session file");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }

  // Validate payloads
  const payloads = (options.payload ?? ["xss-basic"]) as PayloadName[];
  console.log();
  console.log(chalk.cyan("🔍 Running security tests"));
  console.log(chalk.gray(`   Session: ${session.name}`));
  console.log(chalk.gray(`   Payloads: ${payloads.join(", ")}`));
  console.log(chalk.gray(`   Browser: ${options.browser}`));
  console.log(chalk.gray(`   Headless: ${options.headless}`));
  console.log();

  const runSpinner = ora("Executing tests...").start();

  try {
    const result = await Runner.execute(session, payloads, {
      browser: options.browser as BrowserType,
      headless: options.headless,
      onFinding: (finding) => {
        runSpinner.stop();
        console.log(chalk.red(`⚠️  FINDING: ${finding.title}`));
        console.log(chalk.gray(`   Step: ${finding.stepId}`));
        console.log(
          chalk.gray(`   Payload: ${finding.payload.slice(0, 50)}...`),
        );
        console.log(chalk.gray(`   URL: ${finding.url}`));
        console.log();
        runSpinner.start("Continuing tests...");
      },
    });

    runSpinner.succeed("Tests completed");
    console.log();

    // Summary
    console.log(chalk.cyan("📊 Results"));
    console.log(chalk.gray(`   Steps executed: ${result.stepsExecuted}`));
    console.log(chalk.gray(`   Payloads tested: ${result.payloadsTested}`));
    console.log(
      chalk.gray(`   Duration: ${(result.duration / 1000).toFixed(1)}s`),
    );
    console.log();

    if (result.findings.length > 0) {
      console.log(chalk.red(`🚨 ${result.findings.length} findings detected!`));
      console.log();
      for (const finding of result.findings) {
        const severityColor =
          finding.severity === "critical" || finding.severity === "high"
            ? chalk.red
            : finding.severity === "medium"
              ? chalk.yellow
              : chalk.gray;

        console.log(
          severityColor(`[${finding.severity.toUpperCase()}] ${finding.title}`),
        );
        console.log(chalk.gray(`  Type: ${finding.type}`));
        console.log(chalk.gray(`  Step: ${finding.stepId}`));
        console.log(chalk.gray(`  URL: ${finding.url}`));
        console.log(chalk.gray(`  Payload: ${finding.payload}`));
        console.log();
      }
      process.exit(1); // Non-zero exit for CI/CD
    } else {
      console.log(chalk.green("✅ No vulnerabilities detected"));
    }

    if (result.errors.length > 0) {
      console.log();
      console.log(
        chalk.yellow(`⚠️  ${result.errors.length} errors during execution:`),
      );
      for (const err of result.errors.slice(0, 5)) {
        console.log(chalk.gray(`   - ${err}`));
      }
      if (result.errors.length > 5) {
        console.log(chalk.gray(`   ... and ${result.errors.length - 5} more`));
      }
    }
  } catch (err) {
    runSpinner.fail("Test execution failed");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}
