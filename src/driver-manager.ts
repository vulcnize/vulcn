/**
 * Vulcn Driver Manager
 *
 * Handles driver loading, registration, and lifecycle.
 * Drivers are loaded from npm packages or local files.
 */

import { isAbsolute, resolve } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
export const { version: ENGINE_VERSION } = require("../package.json");
import { parse, stringify } from "yaml";
import type {
  VulcnDriver,
  LoadedDriver,
  DriverSource,
  Session,
  RunContext,
  RunResult,
  RunOptions,
  RecordOptions,
  CrawlOptions,
  RecordingHandle,
  DriverLogger,
  DRIVER_API_VERSION,
} from "./driver-types";
import type { PluginManager } from "./plugin-manager";
import type { Finding } from "./types";
import type { RuntimePayload } from "./payload-types";
import type { ScanContext } from "./plugin-types";
import { ErrorSeverity, VulcnError } from "./errors";

/**
 * Driver Manager - loads and manages recording/running drivers
 */
export class DriverManager {
  private drivers: Map<string, LoadedDriver> = new Map();
  private defaultDriver: string | null = null;

  /**
   * Register a driver
   */
  register(driver: VulcnDriver, source: DriverSource = "builtin"): void {
    this.validateDriver(driver);
    this.drivers.set(driver.name, { driver, source });

    // First registered driver becomes default
    if (this.drivers.size === 1) {
      this.defaultDriver = driver.name;
    }
  }

  /**
   * Load a driver from npm or local path
   */
  async load(nameOrPath: string): Promise<void> {
    let driver: VulcnDriver;
    let source: DriverSource;

    if (
      nameOrPath.startsWith("./") ||
      nameOrPath.startsWith("../") ||
      isAbsolute(nameOrPath)
    ) {
      // Local file
      const resolved = isAbsolute(nameOrPath)
        ? nameOrPath
        : resolve(process.cwd(), nameOrPath);
      const module = await import(resolved);
      driver = module.default || module;
      source = "local";
    } else {
      // npm package
      const module = await import(nameOrPath);
      driver = module.default || module;
      source = "npm";
    }

    this.register(driver, source);
  }

  /**
   * Get a loaded driver by name
   */
  get(name: string): VulcnDriver | undefined {
    return this.drivers.get(name)?.driver;
  }

  /**
   * Get the default driver
   */
  getDefault(): VulcnDriver | undefined {
    if (!this.defaultDriver) return undefined;
    return this.get(this.defaultDriver);
  }

  /**
   * Set the default driver
   */
  setDefault(name: string): void {
    if (!this.drivers.has(name)) {
      throw new Error(`Driver "${name}" is not registered`);
    }
    this.defaultDriver = name;
  }

  /**
   * Check if a driver is registered
   */
  has(name: string): boolean {
    return this.drivers.has(name);
  }

  /**
   * Get all registered drivers
   */
  list(): LoadedDriver[] {
    return Array.from(this.drivers.values());
  }

  /**
   * Get driver for a session
   */
  getForSession(session: Session): VulcnDriver {
    const driverName = session.driver;
    const driver = this.get(driverName);

    if (!driver) {
      throw new Error(
        `Driver "${driverName}" not found. Install @vulcn/driver-${driverName} or load it manually.`,
      );
    }

    return driver;
  }

  /**
   * Parse a YAML session string into a Session object.
   *
   * Sessions must use the driver format with a `driver` field.
   *
   * @param yaml - Raw YAML string
   */
  parseSession(yaml: string): Session {
    const data = parse(yaml) as Record<string, unknown>;

    if (!data.driver || typeof data.driver !== "string") {
      throw new Error(
        "Invalid session format: missing 'driver' field. Sessions must use the driver format.",
      );
    }

    return data as unknown as Session;
  }

  /**
   * Start recording with a driver
   */
  async startRecording(
    driverName: string,
    config: Record<string, unknown>,
    options: RecordOptions = {},
  ): Promise<RecordingHandle> {
    const driver = this.get(driverName);

    if (!driver) {
      throw new Error(`Driver "${driverName}" not found`);
    }

    return driver.recorder.start(config, options);
  }

  /**
   * Auto-crawl a URL using a driver.
   *
   * Uses the driver's optional crawl() method to automatically
   * discover forms and injection points, returning Session[] that
   * can be passed to execute().
   *
   * Not all drivers support this — only browser has crawl capability.
   * CLI and API drivers will throw.
   */
  async crawl(
    driverName: string,
    config: Record<string, unknown>,
    options: CrawlOptions = {},
  ): Promise<Session[]> {
    const driver = this.get(driverName);

    if (!driver) {
      throw new Error(`Driver "${driverName}" not found`);
    }

    if (!driver.recorder.crawl) {
      throw new Error(
        `Driver "${driverName}" does not support auto-crawl. Use manual recording instead.`,
      );
    }

    return driver.recorder.crawl(config, options);
  }

  /**
   * Execute a session
   * Invokes plugin hooks (onRunStart, onRunEnd) around the driver runner.
   * Plugin onRunStart is deferred until the driver signals the page is ready
   * via the onPageReady callback, ensuring plugins get a real page object.
   */
  async execute(
    session: Session,
    pluginManager: PluginManager,
    options: RunOptions = {},
  ): Promise<RunResult> {
    const driver = this.getForSession(session);
    const findings: Finding[] = [];
    const logger = this.createLogger(driver.name);

    // Shared addFinding function — used by both internal RunContext and
    // plugin context. Ensures all findings (active + passive) flow through
    // the onFinding callback so consumers get notified consistently.
    const addFinding = (finding: Finding) => {
      findings.push(finding);
      pluginManager.addFinding(finding);
      options.onFinding?.(finding);
    };

    // Build a plugin context template for hooks (page is set in onPageReady)
    const pluginCtx = {
      session,
      page: null as unknown,
      headless: !!(options as Record<string, unknown>).headless,
      config: {} as Record<string, unknown>,
      engine: { version: ENGINE_VERSION, pluginApiVersion: 1 },
      payloads: pluginManager.getPayloads(),
      findings,
      addFinding,
      logger,
      errors: pluginManager.getErrorHandler(),
      fetch: globalThis.fetch,
    };

    const ctx: RunContext = {
      session,
      pluginManager,
      payloads: pluginManager.getPayloads(),
      findings,
      addFinding,
      logger,
      errors: pluginManager.getErrorHandler(),
      options: {
        ...options,
        // Provide onPageReady callback — fires plugin onRunStart hooks
        // with the real page object once the driver has created it
        onPageReady: async (page: unknown) => {
          pluginCtx.page = page;

          for (const loaded of pluginManager.getPlugins()) {
            if (loaded.enabled && loaded.plugin.hooks?.onRunStart) {
              try {
                await loaded.plugin.hooks.onRunStart({
                  ...pluginCtx,
                  config: loaded.config,
                });
              } catch (err) {
                pluginManager.getErrorHandler().catch(err, {
                  severity: ErrorSeverity.ERROR,
                  source: `plugin:${loaded.plugin.name}`,
                  context: { hook: "onRunStart" },
                });
              }
            }
          }
        },
        // Fires before browser closes — lets plugins flush pending async work
        onBeforeClose: async (_page: unknown) => {
          for (const loaded of pluginManager.getPlugins()) {
            if (loaded.enabled && loaded.plugin.hooks?.onBeforeClose) {
              try {
                await loaded.plugin.hooks.onBeforeClose({
                  ...pluginCtx,
                  config: loaded.config,
                });
              } catch (err) {
                pluginManager.getErrorHandler().catch(err, {
                  severity: ErrorSeverity.WARN,
                  source: `plugin:${loaded.plugin.name}`,
                  context: { hook: "onBeforeClose" },
                });
              }
            }
          }
        },
      },
    };

    // Execute via driver runner
    // (runner calls ctx.options.onPageReady(page) after creating the page)
    let result = await driver.runner.execute(session, ctx);

    // Call onRunEnd hooks (e.g., report generation)
    for (const loaded of pluginManager.getPlugins()) {
      if (loaded.enabled && loaded.plugin.hooks?.onRunEnd) {
        try {
          result = await loaded.plugin.hooks.onRunEnd(result, {
            ...pluginCtx,
            config: loaded.config,
            findings: result.findings,
          });
        } catch (err) {
          // onRunEnd is FATAL — report generation lives here.
          pluginManager.getErrorHandler().catch(err, {
            severity: ErrorSeverity.FATAL,
            source: `plugin:${loaded.plugin.name}`,
            context: { hook: "onRunEnd" },
          });
        }
      }
    }

    return result;
  }

  /**
   * Execute multiple sessions with a shared browser (scan-level orchestration).
   *
   * This is the preferred entry point for running a full scan. It:
   * 1. Launches ONE browser for the entire scan
   * 2. Passes the browser to each session's runner via options.browser
   * 3. Each session creates its own context (lightweight, isolated cookies)
   * 4. Aggregates results across all sessions
   * 5. Closes the browser once at the end
   *
   * This is 5-10x faster than calling execute() per session because
   * launching a browser takes 2-3 seconds.
   */
  async executeScan(
    sessions: Session[],
    pluginManager: PluginManager,
    options: RunOptions = {},
  ): Promise<{
    results: RunResult[];
    aggregate: RunResult;
  }> {
    if (sessions.length === 0) {
      const empty: RunResult = {
        findings: [],
        stepsExecuted: 0,
        payloadsTested: 0,
        duration: 0,
        errors: ["No sessions to execute"],
      };
      return { results: [], aggregate: empty };
    }

    const startTime = Date.now();
    const results: RunResult[] = [];
    const allFindings: Finding[] = [];
    let totalSteps = 0;
    let totalPayloads = 0;
    const allErrors: string[] = [];

    // Launch shared browser via the first session's driver
    // (all sessions should use the same driver in a scan)
    const firstDriver = this.getForSession(sessions[0]);
    let sharedBrowser: unknown = null;

    // Only share browser/resource if the driver supports it
    if (typeof firstDriver.createSharedResource === "function") {
      try {
        // Use the first session's config as the baseline for the shared resource
        const driverConfig = sessions[0].driverConfig;
        sharedBrowser = await firstDriver.createSharedResource(
          driverConfig,
          options,
        );
      } catch (err) {
        // Can't share resource — warn and fall back to per-session launches
        pluginManager.getErrorHandler().catch(err, {
          severity: ErrorSeverity.WARN,
          source: `driver-manager:${firstDriver.name}`,
          context: { action: "create-shared-resource" },
        });
      }
    }

    try {
      // Auto-init plugins if not already initialized (idempotent)
      await pluginManager.initialize();

      // Fire onScanStart hooks
      await pluginManager.callHook("onScanStart", async (hook, ctx) => {
        const scanCtx: ScanContext = {
          ...ctx,
          sessions,
          headless: options.headless ?? true,
          sessionCount: sessions.length,
        };
        await (hook as (ctx: ScanContext) => Promise<void>)(scanCtx);
      });

      for (let i = 0; i < sessions.length; i++) {
        const session = sessions[i];

        // Clear per-session state so findings don't leak across sessions
        pluginManager.clearFindings();

        // Notify consumers before session starts
        options.onSessionStart?.(session, i, sessions.length);

        const sessionOptions: RunOptions = {
          ...options,
          ...(sharedBrowser ? { browser: sharedBrowser } : {}),
        };

        let result: RunResult;

        if (options.timeout && options.timeout > 0) {
          // Race execution against timeout
          const execPromise = this.execute(
            session,
            pluginManager,
            sessionOptions,
          );
          const timeoutPromise = new Promise<RunResult>((_, reject) =>
            setTimeout(
              () =>
                reject(
                  new Error(
                    `Session "${session.name}" timed out after ${options.timeout}ms`,
                  ),
                ),
              options.timeout,
            ),
          );

          try {
            result = await Promise.race([execPromise, timeoutPromise]);
          } catch (err) {
            // Timeout or execution error — record as failed session
            result = {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: options.timeout!,
              errors: [err instanceof Error ? err.message : String(err)],
            };
          }

          // Prevent unhandled rejection from the losing promise in the race.
          // When timeout wins, execute() is still running — its eventual
          // rejection must be absorbed or Node exits with code 1.
          execPromise.catch(() => {});
        } else {
          try {
            result = await this.execute(session, pluginManager, sessionOptions);
          } catch (err) {
            // Execution error — record as failed session, continue with next
            result = {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [err instanceof Error ? err.message : String(err)],
            };
          }
        }

        results.push(result);
        allFindings.push(...result.findings);
        totalSteps += result.stepsExecuted;
        totalPayloads += result.payloadsTested;
        allErrors.push(...result.errors);

        // Notify consumers after session ends
        options.onSessionEnd?.(session, result, i, sessions.length);
      }
    } finally {
      // Close the shared browser
      if (
        sharedBrowser &&
        typeof (sharedBrowser as { close: () => Promise<void> }).close ===
          "function"
      ) {
        await (sharedBrowser as { close: () => Promise<void> }).close();
      }
    }

    const aggregate: RunResult = {
      findings: allFindings,
      stepsExecuted: totalSteps,
      payloadsTested: totalPayloads,
      duration: Date.now() - startTime,
      errors: allErrors,
    };

    // Fire onScanEnd hooks — allows plugins to transform the aggregate result
    // This MUST run even if sessions failed — it's how the report gets written.
    let finalAggregate = aggregate;
    finalAggregate = await pluginManager.callHookPipe(
      "onScanEnd",
      finalAggregate,
      async (hook, value, ctx) => {
        const scanCtx: ScanContext = {
          ...ctx,
          sessions,
          headless: options.headless ?? true,
          sessionCount: sessions.length,
        };
        return await (
          hook as (result: RunResult, ctx: ScanContext) => Promise<RunResult>
        )(value, scanCtx);
      },
    );

    return { results, aggregate: finalAggregate };
  }

  /**
   * Validate driver structure
   */
  private validateDriver(driver: unknown): asserts driver is VulcnDriver {
    if (!driver || typeof driver !== "object") {
      throw new Error("Driver must be an object");
    }

    const d = driver as Record<string, unknown>;

    if (typeof d.name !== "string" || !d.name) {
      throw new Error("Driver must have a name");
    }

    if (typeof d.version !== "string" || !d.version) {
      throw new Error("Driver must have a version");
    }

    if (!Array.isArray(d.stepTypes) || d.stepTypes.length === 0) {
      throw new Error("Driver must define stepTypes");
    }

    if (!d.recorder || typeof d.recorder !== "object") {
      throw new Error("Driver must have a recorder");
    }

    if (!d.runner || typeof d.runner !== "object") {
      throw new Error("Driver must have a runner");
    }
  }

  /**
   * Create a scoped logger for a driver
   */
  private createLogger(name: string): DriverLogger {
    const prefix = `[driver:${name}]`;
    return {
      debug: (msg, ...args) => console.debug(prefix, msg, ...args),
      info: (msg, ...args) => console.info(prefix, msg, ...args),
      warn: (msg, ...args) => console.warn(prefix, msg, ...args),
      error: (msg, ...args) => console.error(prefix, msg, ...args),
    };
  }
}

/**
 * Default driver manager instance
 */
export const driverManager = new DriverManager();
