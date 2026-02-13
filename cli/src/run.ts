/**
 * vulcn run — Execute security scans
 *
 * Reads `.vulcn.yml`, loads sessions from `sessions/`, runs payloads.
 * CLI flags override config values for this run only.
 *
 * Usage:
 *   vulcn run                          # reads everything from .vulcn.yml
 *   vulcn run -p xss sqli             # override payload types
 *   vulcn run --no-headless           # override headless mode
 */

import { readFile, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { DriverManager, PluginManager } from "@vulcn/engine";
import {
  loadProject,
  ensureProjectDirs,
  decryptStorageState,
  getPassphrase,
} from "@vulcn/engine";
import type { Session, VulcnProjectConfig } from "@vulcn/engine";
import browserDriver from "@vulcn/driver-browser";
import chalk from "chalk";
import ora from "ora";
import YAML from "yaml";

interface RunOptions {
  payload?: string[];
  payloadFile?: string;
  browser?: string;
  headless?: boolean;
  report?: string;
  reportOutput?: string;
  passive?: boolean;
  payloadbox?: boolean;
  config?: string;
}

export async function runCommand(options: RunOptions) {
  // ── Load project config ──────────────────────────────────────────────

  const loadSpinner = ora("Loading project...").start();

  let project;
  try {
    project = await loadProject();
  } catch (err) {
    loadSpinner.fail(String(err));
    process.exit(1);
  }

  const { config, paths } = project;

  // ── Apply CLI overrides ──────────────────────────────────────────────

  // CLI flags surgically override config values
  const effectiveConfig: VulcnProjectConfig = {
    ...config,
    scan: {
      ...config.scan,
      ...(options.browser
        ? { browser: options.browser as "chromium" | "firefox" | "webkit" }
        : {}),
      ...(options.headless !== undefined ? { headless: options.headless } : {}),
    },
    payloads: {
      ...config.payloads,
      ...(options.payload
        ? { types: options.payload as VulcnProjectConfig["payloads"]["types"] }
        : {}),
      ...(options.payloadbox !== undefined
        ? { payloadbox: options.payloadbox }
        : {}),
      ...(options.payloadFile ? { custom: options.payloadFile } : {}),
    },
    detection: {
      ...config.detection,
      ...(options.passive !== undefined ? { passive: options.passive } : {}),
    },
    report: {
      ...config.report,
      ...(options.report
        ? { format: options.report as VulcnProjectConfig["report"]["format"] }
        : {}),
    },
  };

  // ── Load sessions from sessions/ directory ───────────────────────────

  let sessions: Session[] = [];
  const drivers = new DriverManager();
  drivers.register(browserDriver);

  if (!existsSync(paths.sessions)) {
    loadSpinner.fail(
      `No sessions/ directory found. Run ${chalk.white("vulcn crawl")} or ${chalk.white("vulcn record")} first.`,
    );
    process.exit(1);
  }

  try {
    const files = await readdir(paths.sessions);
    const ymlFiles = files.filter(
      (f) => f.endsWith(".yml") || f.endsWith(".yaml"),
    );

    if (ymlFiles.length === 0) {
      loadSpinner.fail(
        `No session files in sessions/. Run ${chalk.white("vulcn crawl")} or ${chalk.white("vulcn record")} first.`,
      );
      process.exit(1);
    }

    for (const file of ymlFiles) {
      const content = await readFile(join(paths.sessions, file), "utf-8");
      const session = drivers.parseSession(content, "browser");
      sessions.push(session);
    }

    loadSpinner.succeed(
      `Loaded ${chalk.cyan(sessions.length)} session(s) from ${chalk.cyan("sessions/")}`,
    );
  } catch (err) {
    loadSpinner.fail(`Failed to load sessions: ${err}`);
    process.exit(1);
  }

  // ── Load auth state ──────────────────────────────────────────────────

  let storageState: string | undefined;
  const authStatePath = join(paths.auth, "state.enc");

  if (existsSync(authStatePath)) {
    try {
      const passphrase = getPassphrase();
      const encrypted = await readFile(authStatePath, "utf-8");
      storageState = decryptStorageState(encrypted, passphrase);
      console.log(chalk.green("   🔑 Auth state loaded"));
    } catch {
      console.log(
        chalk.yellow(
          "   ⚠️  Auth state found but VULCN_KEY not set — scanning without auth",
        ),
      );
    }
  }

  // ── Load payloads & detection plugins via engine ─────────────────────

  const manager = new PluginManager();
  const defaultsSpinner = ora(
    "Loading payloads & detection plugins...",
  ).start();

  try {
    // Resolve relative custom payload path against project root
    if (effectiveConfig.payloads.custom) {
      effectiveConfig.payloads.custom = resolve(
        paths.root,
        effectiveConfig.payloads.custom,
      );
    }

    await manager.loadFromConfig(effectiveConfig);

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

  // ── Load report plugin ───────────────────────────────────────────────

  const reportFormat = effectiveConfig.report.format;
  if (reportFormat) {
    const reportSpinner = ora("Loading report plugin...").start();
    try {
      const reportPlugin = await import("@vulcn/plugin-report");
      await ensureProjectDirs(paths, ["reports"]);

      manager.addPlugin(reportPlugin.default, {
        format: reportFormat,
        outputDir: options.reportOutput || paths.reports,
        filename: "vulcn-report",
        open: reportFormat === "html" || reportFormat === "all",
      });
      reportSpinner.succeed(
        `Report plugin loaded (format: ${chalk.cyan(reportFormat)})`,
      );
    } catch (err) {
      reportSpinner.fail(`Failed to load report plugin: ${err}`);
      process.exit(1);
    }
  }

  // ── Execute scan ─────────────────────────────────────────────────────

  const payloads = manager.getPayloads();

  console.log();
  console.log(chalk.cyan("🔍 Running security tests"));
  console.log(
    chalk.gray(`   Target: ${effectiveConfig.target ?? "from sessions"}`),
  );
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
  console.log(chalk.gray(`   Browser: ${effectiveConfig.scan.browser}`));
  console.log(chalk.gray(`   Headless: ${effectiveConfig.scan.headless}`));
  if (storageState) {
    console.log(chalk.green(`   Auth: authenticated`));
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

    const scanResult = await drivers.executeScan(sessions, manager, {
      headless: effectiveConfig.scan.headless,
      ...(storageState ? { storageState } : {}),
      onFinding,
      onSessionStart: (session: Session, index: number, total: number) => {
        runSpinner.text = `Session ${index + 1}/${total} — ${session.name}`;
      },
    });
    const result = scanResult.aggregate;

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

    const errorHandler = manager.getErrorHandler();
    if (errorHandler.hasErrors()) {
      console.log();
      console.log(chalk.yellow(errorHandler.getSummary()));
    }
  } catch (err) {
    runSpinner.fail("Test execution failed");
    console.error(chalk.red(String(err)));

    const errorHandler = manager.getErrorHandler();
    if (errorHandler.hasErrors()) {
      console.log();
      console.log(chalk.yellow(errorHandler.getSummary()));
    }

    process.exit(1);
  }
}
