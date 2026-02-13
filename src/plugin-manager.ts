/**
 * Vulcn Plugin Manager
 * Handles plugin loading, lifecycle, and hook execution.
 *
 * The primary entry point is `loadFromConfig(config)` which takes
 * a flat `VulcnProjectConfig` (from `.vulcn.yml`) and maps it to
 * internal plugin configs automatically.
 */

import { createRequire } from "node:module";
import type {
  VulcnPlugin,
  LoadedPlugin,
  PluginContext,
  PluginSource,
  PluginLogger,
  EngineInfo,
  PluginHooks,
} from "./plugin-types";
import { PLUGIN_API_VERSION } from "./plugin-types";
import type { Finding } from "./types";
import type { RuntimePayload } from "./payload-types";
import { ErrorHandler, ErrorSeverity, VulcnError } from "./errors";
import type { VulcnProjectConfig } from "./config";

const _require = createRequire(import.meta.url);
const { version: ENGINE_VERSION } = _require("../package.json");

/**
 * Plugin Manager - loads, configures, and orchestrates plugins
 */
export class PluginManager {
  private plugins: LoadedPlugin[] = [];
  private initialized = false;
  private errorHandler: ErrorHandler;

  /**
   * Shared context passed to all plugins
   */
  private sharedPayloads: RuntimePayload[] = [];
  private sharedFindings: Finding[] = [];

  constructor(errorHandler?: ErrorHandler) {
    this.errorHandler = errorHandler ?? new ErrorHandler();
  }

  /** Get the error handler for post-run inspection */
  getErrorHandler(): ErrorHandler {
    return this.errorHandler;
  }

  /**
   * Validate plugin structure
   */
  private validatePlugin(plugin: unknown): asserts plugin is VulcnPlugin {
    if (!plugin || typeof plugin !== "object") {
      throw new Error("Plugin must be an object");
    }

    const p = plugin as Record<string, unknown>;
    if (typeof p.name !== "string" || !p.name) {
      throw new Error("Plugin must have a name");
    }
    if (typeof p.version !== "string" || !p.version) {
      throw new Error("Plugin must have a version");
    }

    // Check API version compatibility
    const apiVersion = (p.apiVersion as number) || 1;
    if (apiVersion > PLUGIN_API_VERSION) {
      throw new Error(
        `Plugin requires API version ${apiVersion}, but engine supports ${PLUGIN_API_VERSION}`,
      );
    }
  }

  /**
   * Add a plugin programmatically (for testing or dynamic loading)
   */
  addPlugin(plugin: VulcnPlugin, config: Record<string, unknown> = {}): void {
    this.validatePlugin(plugin);
    this.plugins.push({
      plugin,
      config,
      source: "custom",
      enabled: true,
    });
  }

  /**
   * Initialize all plugins (call onInit hooks)
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Load payloads from plugins that provide them
    for (const loaded of this.plugins) {
      if (loaded.plugin.payloads) {
        const payloads =
          typeof loaded.plugin.payloads === "function"
            ? await loaded.plugin.payloads()
            : loaded.plugin.payloads;
        this.sharedPayloads.push(...payloads);
      }
    }

    // Call onInit hooks
    await this.callHook("onInit", (hook, ctx) => hook(ctx));

    this.initialized = true;
  }

  /**
   * Destroy all plugins (call onDestroy hooks)
   */
  async destroy(): Promise<void> {
    await this.callHook("onDestroy", (hook, ctx) => hook(ctx));
    this.plugins = [];
    this.sharedPayloads = [];
    this.sharedFindings = [];
    this.initialized = false;
  }

  /**
   * Load the engine from a flat VulcnProjectConfig (from `.vulcn.yml`).
   *
   * This is the primary entry point for the new config system.
   * Maps user-facing config keys to internal plugin configs automatically.
   *
   * @param config - Parsed and validated VulcnProjectConfig
   */
  async loadFromConfig(config: VulcnProjectConfig): Promise<void> {
    const { payloads, detection } = config;

    // ── Load payloads ──────────────────────────────────────────────────

    // Custom payload file (resolve relative paths externally before passing in)
    if (payloads.custom) {
      try {
        const payloadPkg = "@vulcn/plugin-payloads";
        const { loadFromFile } = await import(/* @vite-ignore */ payloadPkg);
        const loaded = await loadFromFile(payloads.custom);
        this.addPayloads(loaded);
      } catch (err) {
        throw new Error(
          `Failed to load custom payloads from ${payloads.custom}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // Load payload types — curated first, then PayloadBox if enabled
    try {
      const payloadPkg = "@vulcn/plugin-payloads";
      const { getCuratedPayloads, loadPayloadBox } = await import(
        /* @vite-ignore */ payloadPkg
      );

      for (const name of payloads.types) {
        // Curated payloads (always, if available)
        const curated = getCuratedPayloads(name);
        if (curated) {
          this.addPayloads(curated);
        }

        // PayloadBox if enabled, or as fallback if no curated set
        if (payloads.payloadbox || !curated) {
          try {
            const payload = await loadPayloadBox(name, payloads.limit);
            this.addPayloads([payload]);
          } catch (err) {
            if (!curated) {
              throw new Error(
                `No payloads for "${name}": no curated set and PayloadBox failed: ${err instanceof Error ? err.message : String(err)}`,
              );
            }
          }
        }
      }
    } catch (err) {
      throw new Error(
        `Failed to load payloads: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // ── Auto-load detection plugins ────────────────────────────────────

    // XSS detection: map flat config → plugin config
    if (
      payloads.types.includes("xss") &&
      !this.hasPlugin("@vulcn/plugin-detect-xss")
    ) {
      try {
        const pkg = "@vulcn/plugin-detect-xss";
        const mod = await import(/* @vite-ignore */ pkg);
        this.addPlugin(mod.default, {
          detectDialogs: detection.xss.dialogs,
          detectConsole: detection.xss.console,
          consoleMarker: detection.xss.consoleMarker,
          detectDomMutation: detection.xss.domMutation,
          severity: detection.xss.severity,
          alertPatterns: detection.xss.alertPatterns,
        });
      } catch (err) {
        this.errorHandler.catch(err, {
          severity: ErrorSeverity.WARN,
          source: "plugin-manager:loadFromConfig",
          context: { plugin: "@vulcn/plugin-detect-xss" },
        });
      }
    }

    // SQLi detection
    const hasSqli = payloads.types.some((t: string) => {
      const lower = t.toLowerCase();
      return lower === "sqli" || lower.includes("sql");
    });
    if (hasSqli && !this.hasPlugin("@vulcn/plugin-detect-sqli")) {
      try {
        const pkg = "@vulcn/plugin-detect-sqli";
        const mod = await import(/* @vite-ignore */ pkg);
        this.addPlugin(mod.default);
      } catch (err) {
        this.errorHandler.catch(err, {
          severity: ErrorSeverity.WARN,
          source: "plugin-manager:loadFromConfig",
          context: { plugin: "@vulcn/plugin-detect-sqli" },
        });
      }
    }

    // Passive scanner
    if (detection.passive && !this.hasPlugin("@vulcn/plugin-passive")) {
      try {
        const pkg = "@vulcn/plugin-passive";
        const mod = await import(/* @vite-ignore */ pkg);
        this.addPlugin(mod.default);
      } catch (err) {
        this.errorHandler.catch(err, {
          severity: ErrorSeverity.WARN,
          source: "plugin-manager:loadFromConfig",
          context: { plugin: "@vulcn/plugin-passive" },
        });
      }
    }
  }

  /**
   * Get all loaded payloads
   */
  getPayloads(): RuntimePayload[] {
    return this.sharedPayloads;
  }

  /**
   * Get all collected findings
   */
  getFindings(): Finding[] {
    return this.sharedFindings;
  }

  /**
   * Add a finding (used by detectors)
   */
  addFinding(finding: Finding): void {
    this.sharedFindings.push(finding);
  }

  /**
   * Add payloads (used by loaders)
   */
  addPayloads(payloads: RuntimePayload[]): void {
    this.sharedPayloads.push(...payloads);
  }

  /**
   * Clear findings (for new run)
   */
  clearFindings(): void {
    this.sharedFindings = [];
  }

  /**
   * Get loaded plugins
   */
  getPlugins(): LoadedPlugin[] {
    return this.plugins;
  }

  /**
   * Check if a plugin is loaded by name
   */
  hasPlugin(name: string): boolean {
    return this.plugins.some((p) => p.plugin.name === name);
  }

  /**
   * Create base context for plugins
   */
  createContext(
    pluginConfig: Record<string, unknown>,
    pluginName?: string,
  ): PluginContext {
    const engineInfo: EngineInfo = {
      version: ENGINE_VERSION,
      pluginApiVersion: PLUGIN_API_VERSION,
    };

    return {
      config: pluginConfig,
      engine: engineInfo,
      payloads: this.sharedPayloads,
      findings: this.sharedFindings,
      addFinding: (finding: Finding) => {
        console.log(
          `[DEBUG-PM] Plugin ${pluginName || "?"} adding finding: ${finding.type}`,
        );
        this.sharedFindings.push(finding);
      },
      logger: this.createLogger(pluginName || "plugin"),
      errors: this.errorHandler,
      fetch: globalThis.fetch,
    };
  }

  /**
   * Create scoped logger for a plugin
   */
  private createLogger(name: string): PluginLogger {
    const prefix = `[${name}]`;
    return {
      debug: (msg, ...args) => console.debug(prefix, msg, ...args),
      info: (msg, ...args) => console.info(prefix, msg, ...args),
      warn: (msg, ...args) => console.warn(prefix, msg, ...args),
      error: (msg, ...args) => console.error(prefix, msg, ...args),
    };
  }

  // ── Hook severity classification ────────────────────────────────────
  //
  // Hooks that produce OUTPUT (reports, results) are FATAL on failure.
  // Hooks that set up state are ERROR. Everything else is WARN.
  //
  private static readonly FATAL_HOOKS: Set<keyof PluginHooks> = new Set([
    "onRunEnd",
    "onScanEnd",
  ]);

  private static readonly ERROR_HOOKS: Set<keyof PluginHooks> = new Set([
    "onInit",
    "onRunStart",
    "onScanStart",
    "onAfterPayload",
  ]);

  private hookSeverity(hookName: keyof PluginHooks): ErrorSeverity {
    if (PluginManager.FATAL_HOOKS.has(hookName)) return ErrorSeverity.FATAL;
    if (PluginManager.ERROR_HOOKS.has(hookName)) return ErrorSeverity.ERROR;
    return ErrorSeverity.WARN;
  }

  /**
   * Call a hook on all plugins sequentially
   */
  async callHook<K extends keyof PluginHooks>(
    hookName: K,
    executor: (
      hook: NonNullable<PluginHooks[K]>,
      ctx: PluginContext,
    ) => Promise<unknown>,
  ): Promise<void> {
    for (const loaded of this.plugins) {
      const hook = loaded.plugin.hooks?.[hookName];
      if (hook) {
        const ctx = this.createContext(loaded.config, loaded.plugin.name);
        ctx.logger = this.createLogger(loaded.plugin.name);
        try {
          await executor(hook as NonNullable<PluginHooks[K]>, ctx);
        } catch (err) {
          this.errorHandler.catch(err, {
            severity: this.hookSeverity(hookName),
            source: `plugin:${loaded.plugin.name}`,
            context: { hook: hookName },
          });
        }
      }
    }
  }

  /**
   * Call a hook and collect results
   */
  async callHookCollect<K extends keyof PluginHooks, R>(
    hookName: K,
    executor: (
      hook: NonNullable<PluginHooks[K]>,
      ctx: PluginContext,
    ) => Promise<R | R[] | null>,
  ): Promise<R[]> {
    const results: R[] = [];

    for (const loaded of this.plugins) {
      const hook = loaded.plugin.hooks?.[hookName];
      if (hook) {
        const ctx = this.createContext(loaded.config, loaded.plugin.name);
        ctx.logger = this.createLogger(loaded.plugin.name);
        try {
          const result = await executor(
            hook as NonNullable<PluginHooks[K]>,
            ctx,
          );
          if (result !== null && result !== undefined) {
            if (Array.isArray(result)) {
              results.push(...result);
            } else {
              results.push(result);
            }
          }
        } catch (err) {
          this.errorHandler.catch(err, {
            severity: this.hookSeverity(hookName),
            source: `plugin:${loaded.plugin.name}`,
            context: { hook: hookName },
          });
        }
      }
    }

    return results;
  }

  /**
   * Call a hook that transforms a value through the pipeline
   */
  async callHookPipe<T>(
    hookName: keyof PluginHooks,
    initial: T,
    executor: (
      hook: NonNullable<PluginHooks[typeof hookName]>,
      value: T,
      ctx: PluginContext,
    ) => Promise<T>,
  ): Promise<T> {
    let value = initial;

    for (const loaded of this.plugins) {
      const hook = loaded.plugin.hooks?.[hookName];
      if (hook) {
        const ctx = this.createContext(loaded.config, loaded.plugin.name);
        ctx.logger = this.createLogger(loaded.plugin.name);
        try {
          value = await executor(
            hook as NonNullable<PluginHooks[typeof hookName]>,
            value,
            ctx,
          );
        } catch (err) {
          this.errorHandler.catch(err, {
            severity: this.hookSeverity(hookName),
            source: `plugin:${loaded.plugin.name}`,
            context: { hook: hookName },
          });
        }
      }
    }

    return value;
  }
}

/**
 * Default shared plugin manager instance
 */
export const pluginManager = new PluginManager();
