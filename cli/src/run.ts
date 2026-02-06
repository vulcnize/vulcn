import { readFile, access } from "node:fs/promises";
import { existsSync } from "node:fs";
import {
  Runner,
  parseSession,
  PluginManager,
  type BrowserType,
} from "@vulcn/engine";
import chalk from "chalk";
import ora from "ora";

interface RunOptions {
  payload?: string[];
  payloadFile?: string;
  browser: string;
  headless: boolean;
  config?: string;
}

export async function runCommand(sessionFile: string, options: RunOptions) {
  // Create plugin manager for this run
  const manager = new PluginManager();

  // Load config from file if present
  await manager.loadConfig(options.config);

  // Load plugins from config
  await manager.loadPlugins();

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

  // Add payloads from CLI options (legacy support)
  if (options.payloadFile) {
    const customSpinner = ora("Loading custom payloads...").start();
    try {
      // Dynamically import the payloads plugin file loader
      const { loadFromFile } = await import("@vulcn/plugin-payloads");
      const loaded = await loadFromFile(options.payloadFile);
      manager.addPayloads(loaded);
      customSpinner.succeed(
        `Loaded ${chalk.cyan(loaded.length)} custom payload(s) from ${options.payloadFile}`,
      );
    } catch (err) {
      customSpinner.fail(`Failed to load custom payloads: ${err}`);
      process.exit(1);
    }
  }

  // If specific payloads requested via CLI, add them
  if (options.payload && options.payload.length > 0) {
    const payloadSpinner = ora("Loading specified payloads...").start();
    try {
      const { BUILTIN_PAYLOADS, loadPayloadBox } =
        await import("@vulcn/plugin-payloads");

      for (const spec of options.payload) {
        if (spec.startsWith("payloadbox:")) {
          // PayloadBox spec
          const type = spec.slice("payloadbox:".length);
          const payload = await loadPayloadBox(type);
          manager.addPayloads([payload]);
          payloadSpinner.text = `Loaded payloadbox:${type}`;
        } else if (spec in BUILTIN_PAYLOADS) {
          // Built-in payload
          manager.addPayloads([BUILTIN_PAYLOADS[spec]]);
        } else {
          payloadSpinner.warn(`Unknown payload: ${spec}`);
        }
      }
      payloadSpinner.succeed(`Loaded ${options.payload.length} payload set(s)`);
    } catch (err) {
      payloadSpinner.fail(`Failed to load payloads: ${err}`);
      process.exit(1);
    }
  }

  // If no payloads loaded yet, load defaults
  if (manager.getPayloads().length === 0) {
    const defaultSpinner = ora("Loading default payloads...").start();
    try {
      const { BUILTIN_PAYLOADS } = await import("@vulcn/plugin-payloads");
      // Add xss-basic as default
      manager.addPayloads([BUILTIN_PAYLOADS["xss-basic"]]);
      defaultSpinner.succeed("Using default payload: xss-basic");
    } catch (err) {
      defaultSpinner.fail(`Failed to load default payloads: ${err}`);
      process.exit(1);
    }
  }

  // Auto-load default detection plugin if not already configured
  if (!manager.hasPlugin("@vulcn/plugin-detect-xss")) {
    const detectSpinner = ora("Loading XSS detection plugin...").start();
    try {
      const detectXssPlugin = await import("@vulcn/plugin-detect-xss");
      manager.addPlugin(detectXssPlugin.default);
      detectSpinner.succeed("Loaded XSS detection plugin");
    } catch (err) {
      detectSpinner.fail(`Failed to load detect-xss plugin: ${err}`);
      // Non-fatal: continue without detection
    }
  }

  const payloads = manager.getPayloads();

  console.log();
  console.log(chalk.cyan("🔍 Running security tests"));
  console.log(chalk.gray(`   Session: ${session.name}`));
  console.log(
    chalk.gray(`   Payloads: ${payloads.map((p) => p.name).join(", ")}`),
  );
  console.log(
    chalk.gray(
      `   Payload count: ${payloads.reduce((sum, p) => sum + p.payloads.length, 0)}`,
    ),
  );
  console.log(chalk.gray(`   Browser: ${options.browser}`));
  console.log(chalk.gray(`   Headless: ${options.headless}`));
  console.log();

  const runSpinner = ora("Executing tests...").start();

  try {
    const result = await Runner.execute(
      session,
      {
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
      },
      { pluginManager: manager },
    );

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
