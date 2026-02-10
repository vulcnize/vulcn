import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { DriverManager, PluginManager } from "@vulcn/engine";
import {
  loadSessionDir,
  isSessionDir,
  looksLikeSessionDir,
  readAuthState,
  decryptStorageState,
  getPassphrase,
} from "@vulcn/engine";
import type { Session } from "@vulcn/engine";
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
  creds?: string;
}

export async function runCommand(sessionInput: string, options: RunOptions) {
  // Create plugin manager for this run
  const manager = new PluginManager();

  // Load config from file if present
  await manager.loadConfig(options.config);

  // Load plugins from config
  await manager.loadPlugins();

  // Set up driver manager with browser driver
  const drivers = new DriverManager();
  drivers.register(browserDriver);

  // Load session(s) — v2 directory or legacy file
  const loadSpinner = ora("Loading session...").start();

  let sessions: Session[] = [];
  let storageState: string | undefined;

  try {
    if (isSessionDir(sessionInput) || looksLikeSessionDir(sessionInput)) {
      // v2 format: .vulcn/ directory
      const loaded = await loadSessionDir(sessionInput);
      sessions = loaded.sessions;

      // Load encrypted auth state if available
      const encState = await readAuthState(sessionInput);
      if (encState) {
        try {
          const passphrase = getPassphrase();
          storageState = decryptStorageState(encState, passphrase);
        } catch {
          loadSpinner.warn(
            "Auth state found but VULCN_KEY not set — scanning without auth",
          );
        }
      }

      loadSpinner.succeed(
        `Loaded ${chalk.cyan(sessions.length)} session(s) from ${chalk.cyan(sessionInput)}` +
          (storageState ? chalk.green(" (authenticated)") : ""),
      );
    } else {
      // Legacy: single .vulcn.yml file
      const sessionYaml = await readFile(sessionInput, "utf-8");
      const session = drivers.parseSession(sessionYaml, "browser");
      sessions = [session];
      loadSpinner.succeed(`Loaded session: ${chalk.cyan(session.name)}`);
    }
  } catch (err) {
    loadSpinner.fail(`Cannot load session: ${sessionInput}`);
    console.error(chalk.red(String(err)));
    process.exit(1);
  }

  if (sessions.length === 0) {
    console.error(chalk.yellow("No injectable sessions found."));
    process.exit(0);
  }

  // Handle --creds for authentication (works for both v2 and legacy sessions)
  if (!storageState && options.creds && existsSync(options.creds)) {
    const authSpinner = ora("Authenticating...").start();
    try {
      const encrypted = await readFile(options.creds, "utf-8");
      const passphrase = getPassphrase();
      const { decryptCredentials } = await import("@vulcn/engine");
      const credentials = decryptCredentials(encrypted, passphrase);

      if (credentials.type === "form") {
        const { launchBrowser, performLogin } =
          await import("@vulcn/driver-browser");

        const { browser } = await launchBrowser({
          browser: options.browser as "chromium" | "firefox" | "webkit",
          headless: options.headless,
        });

        const context = await browser.newContext();
        const page = await context.newPage();

        // Determine target URL from the first session's navigate step
        const firstNav = sessions[0].steps.find(
          (s) => s.type === "browser.navigate",
        );
        const targetUrl =
          (firstNav as { url?: string })?.url ?? "http://localhost";

        const result = await performLogin(page, context, credentials, {
          targetUrl,
        });

        if (result.success) {
          storageState = result.storageState;
          authSpinner.succeed(
            `Authenticated as ${chalk.cyan(credentials.username)}`,
          );
        } else {
          authSpinner.warn(
            `Login failed: ${result.message} — scanning without auth`,
          );
        }

        await page.close();
        await context.close();
        await browser.close();
      } else if (credentials.type === "header") {
        authSpinner.succeed("Loaded header credentials");
        // TODO: inject headers into runner options
      }
    } catch (err) {
      authSpinner.warn(`Auth failed: ${err} — scanning without auth`);
    }
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

  // Auto-load passive scanner plugin (enabled by default, disable with --no-passive)
  if (
    options.passive !== false &&
    !manager.hasPlugin("@vulcn/plugin-passive")
  ) {
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
  console.log(
    chalk.gray(
      `   Sessions: ${sessions.length} (${sessions.map((s) => s.name).join(", ")})`,
    ),
  );
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
  if (storageState) {
    console.log(chalk.green(`   Auth: authenticated (storage state loaded)`));
  }
  console.log();

  const runSpinner = ora("Executing tests...").start();

  try {
    const onFinding = (finding: {
      title: string;
      stepId: string;
      payload: string;
      url: string;
    }) => {
      runSpinner.stop();
      console.log(chalk.red(`⚠️  FINDING: ${finding.title}`));
      console.log(chalk.gray(`   Step: ${finding.stepId}`));
      console.log(chalk.gray(`   Payload: ${finding.payload.slice(0, 50)}...`));
      console.log(chalk.gray(`   URL: ${finding.url}`));
      console.log();
      runSpinner.start("Continuing tests...");
    };

    let result;

    if (sessions.length === 1) {
      // Single session — use execute() directly
      result = await drivers.execute(sessions[0], manager, {
        headless: options.headless,
        ...(storageState ? { storageState } : {}),
        onFinding,
      });
    } else {
      // Multiple sessions — use executeScan() for shared browser
      const scanResult = await drivers.executeScan(sessions, manager, {
        headless: options.headless,
        ...(storageState ? { storageState } : {}),
        onFinding,
      });
      result = scanResult.aggregate;
    }

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
