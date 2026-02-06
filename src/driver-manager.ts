/**
 * Vulcn Driver Manager
 *
 * Handles driver loading, registration, and lifecycle.
 * Drivers are loaded from npm packages or local files.
 */

import { isAbsolute, resolve } from "node:path";
import type {
  VulcnDriver,
  LoadedDriver,
  DriverSource,
  Session,
  RunContext,
  RunResult,
  RunOptions,
  RecordOptions,
  RecordingHandle,
  DriverLogger,
  DRIVER_API_VERSION,
} from "./driver-types";
import type { PluginManager } from "./plugin-manager";
import type { Finding } from "./types";
import type { RuntimePayload } from "./payload-types";

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
   * Execute a session
   */
  async execute(
    session: Session,
    pluginManager: PluginManager,
    options: RunOptions = {},
  ): Promise<RunResult> {
    const driver = this.getForSession(session);
    const findings: Finding[] = [];
    const logger = this.createLogger(driver.name);

    const ctx: RunContext = {
      session,
      pluginManager,
      payloads: pluginManager.getPayloads(),
      findings,
      addFinding: (finding) => {
        findings.push(finding);
        pluginManager.addFinding(finding);
        options.onFinding?.(finding);
      },
      logger,
      options,
    };

    return driver.runner.execute(session, ctx);
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
