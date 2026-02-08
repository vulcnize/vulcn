import { readFile } from "node:fs/promises";
import { DriverManager, PluginManager } from "@vulcn/engine";
import browserDriver from "@vulcn/driver-browser";
import chalk from "chalk";
import ora from "ora";

interface RunOptions {
  payload?: string[];
  payloadFile?: string;
  browser: string;
  headless: boolean;
  config?: string;
  report?: string;
  reportOutput?: string;
  passive?: boolean;
}

export async function runCommand(sessionFile: string, options: RunOptions) {
  // Create plugin manager for this run
  const manager = new PluginManager();

  // Load config from file if present
  await manager.loadConfig(options.config);

  // Load plugins from config
  await manager.loadPlugins();

  // Set up driver manager with browser driver
  const drivers = new DriverManager();
  drivers.register(browserDriver);

  // Load session
  const loadSpinner = ora("Loading session...").start();

  let sessionYaml: string;
  try {
    sessionYaml = await readFile(sessionFile, "utf-8");
  } catch {
    loadSpinner.fail(`Cannot read file: ${sessionFile}`);
    process.exit(1);
  }

  // Parse session — supports both legacy and driver-based formats
  let session;
  try {
    session = drivers.parseSession(sessionYaml, "browser");
    loadSpinner.succeed(`Loaded session: ${chalk.cyan(session.name)}`);
  } catch (err) {
    loadSpinner.fail("Invalid session file");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }

  // Add payloads from custom file
  if (options.payloadFile) {
    const customSpinner = ora("Loading custom payloads...").start();
    try {
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

  // Load payload types from --payload flag
  if (options.payload && options.payload.length > 0) {
    const payloadSpinner = ora("Fetching payloads...").start();
    try {
      const { loadPayloadBox } = await import("@vulcn/plugin-payloads");

      for (const name of options.payload) {
        payloadSpinner.text = `Fetching ${name}...`;
        const payload = await loadPayloadBox(name);
        manager.addPayloads([payload]);
      }
      payloadSpinner.succeed(
        `Loaded ${options.payload.length} payload type(s)`,
      );
    } catch (err) {
      payloadSpinner.fail(`Failed to load payloads: ${err}`);
      process.exit(1);
    }
  }

  // If no payloads loaded yet, default to XSS
  if (manager.getPayloads().length === 0) {
    const defaultSpinner = ora("Fetching default payloads (xss)...").start();
    try {
      const { loadPayloadBox } = await import("@vulcn/plugin-payloads");
      const payload = await loadPayloadBox("xss");
      manager.addPayloads([payload]);
      defaultSpinner.succeed("Using default payloads: xss");
    } catch (err) {
      defaultSpinner.fail(`Failed to load default payloads: ${err}`);
      process.exit(1);
    }
  }

  // Auto-load XSS detection plugin
  if (!manager.hasPlugin("@vulcn/plugin-detect-xss")) {
    const detectSpinner = ora("Loading XSS detection plugin...").start();
    try {
      const detectXssPlugin = await import("@vulcn/plugin-detect-xss");
      manager.addPlugin(detectXssPlugin.default);
      detectSpinner.succeed("Loaded XSS detection plugin");
    } catch (err) {
      detectSpinner.fail(`Failed to load detect-xss plugin: ${err}`);
    }
  }

  // Auto-load SQLi detection plugin when sqli payloads are used
  const hasSqliPayloads = (options.payload ?? []).some((p) => {
    const lower = p.toLowerCase();
    return (
      lower === "sqli" ||
      lower === "sql" ||
      lower === "sql-injection" ||
      lower.includes("sql")
    );
  });
  if (hasSqliPayloads && !manager.hasPlugin("@vulcn/plugin-detect-sqli")) {
    const sqliSpinner = ora("Loading SQLi detection plugin...").start();
    try {
      const detectSqliPlugin = await import("@vulcn/plugin-detect-sqli");
      manager.addPlugin(detectSqliPlugin.default);
      sqliSpinner.succeed("Loaded SQLi detection plugin");
    } catch (err) {
      sqliSpinner.fail(`Failed to load detect-sqli plugin: ${err}`);
    }
  }

  // Auto-load passive scanner plugin if --passive is specified
  if (options.passive && !manager.hasPlugin("@vulcn/plugin-passive")) {
    const passiveSpinner = ora("Loading passive scanner plugin...").start();
    try {
      const passivePlugin = await import("@vulcn/plugin-passive");
      manager.addPlugin(passivePlugin.default);
      passiveSpinner.succeed("Loaded passive security scanner");
    } catch (err) {
      passiveSpinner.fail(`Failed to load passive scanner plugin: ${err}`);
    }
  }

  // Load report plugin if --report is specified
  if (options.report) {
    const reportSpinner = ora("Loading report plugin...").start();
    try {
      const reportPlugin = await import("@vulcn/plugin-report");

      // Determine output path from --report-output or default
      const outputDir = options.reportOutput || ".";

      manager.addPlugin(reportPlugin.default, {
        format: options.report,
        outputDir,
        filename: "vulcn-report",
        open: options.report === "html" || options.report === "all",
      });
      reportSpinner.succeed(
        `Report plugin loaded (format: ${chalk.cyan(options.report)})`,
      );
    } catch (err) {
      reportSpinner.fail(`Failed to load report plugin: ${err}`);
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
    const result = await drivers.execute(session, manager, {
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
