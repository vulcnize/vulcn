import { readFile } from "node:fs/promises";
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
import { performAuth } from "./auth-helper";

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
  let extraHeaders: Record<string, string> | undefined;

  if (!storageState && options.creds) {
    // Determine target URL from the first session's navigate step
    const firstNav = sessions[0].steps.find(
      (s) => s.type === "browser.navigate",
    );
    const targetUrl = (firstNav as { url?: string })?.url ?? "http://localhost";

    const auth = await performAuth({
      credsFile: options.creds,
      browser: options.browser,
      headless: options.headless,
      targetUrl,
    });

    if (auth.storageState) {
      storageState = auth.storageState;
    }
    if (auth.extraHeaders) {
      extraHeaders = auth.extraHeaders;
    }
  }

  // Load default payloads and detection plugins via core engine
  const defaultsSpinner = ora(
    "Loading payloads & detection plugins...",
  ).start();
  try {
    await manager.loadDefaults(options.payload ?? [], {
      passive: options.passive !== false,
      payloadFile: options.payloadFile,
    });
    const payloadNames = manager
      .getPayloads()
      .map((p) => p.name)
      .join(", ");
    defaultsSpinner.succeed(
      `Loaded payloads (${chalk.cyan(payloadNames)}) + detection plugins`,
    );
  } catch (err) {
    defaultsSpinner.fail(`Failed to load defaults: ${err}`);
    process.exit(1);
  }

  // Load report plugin if --report is specified (CLI-specific concern)
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
      process.exit(1);
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

    // Always use executeScan — works for 1 or many sessions,
    // ensures onSessionStart always fires for consistent UX
    const scanResult = await drivers.executeScan(sessions, manager, {
      headless: options.headless,
      ...(storageState ? { storageState } : {}),
      ...(extraHeaders ? { extraHeaders } : {}),
      onFinding,
      onSessionStart: (session: Session, index: number, total: number) => {
        runSpinner.text = `Session ${index + 1}/${total} — ${session.name}`;
      },
    });
    result = scanResult.aggregate;

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

    // Print error handler summary if there were issues
    const errorHandler = manager.getErrorHandler();
    if (errorHandler.hasErrors()) {
      console.log();
      console.log(chalk.yellow(errorHandler.getSummary()));
    }
  } catch (err) {
    runSpinner.fail("Test execution failed");
    console.error(chalk.red(String(err)));

    // Print error handler summary for context
    const errorHandler = manager.getErrorHandler();
    if (errorHandler.hasErrors()) {
      console.log();
      console.log(chalk.yellow(errorHandler.getSummary()));
    }

    process.exit(1);
  }
}
