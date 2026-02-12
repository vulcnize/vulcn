/**
 * Vulcn Plugin Manager
 * Handles plugin loading, lifecycle, and hook execution
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve, isAbsolute } from "node:path";
import { createRequire } from "node:module";
import YAML from "yaml";
import { z } from "zod";
import type {
  VulcnPlugin,
  VulcnConfig,
  PluginConfig,
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

const _require = createRequire(import.meta.url);
const { version: ENGINE_VERSION } = _require("../package.json");

/**
 * Config file schema
 */
const VulcnConfigSchema = z.object({
  version: z.string().default("1"),
  plugins: z
    .array(
      z.object({
        name: z.string(),
        config: z.record(z.unknown()).optional(),
        enabled: z.boolean().default(true),
      }),
    )
    .optional(),
  settings: z
    .object({
      browser: z.enum(["chromium", "firefox", "webkit"]).optional(),
      headless: z.boolean().optional(),
      timeout: z.number().optional(),
    })
    .optional(),
});

/**
 * Plugin Manager - loads, configures, and orchestrates plugins
 */
export class PluginManager {
  private plugins: LoadedPlugin[] = [];
  private config: VulcnConfig | null = null;
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
   * Load configuration from vulcn.config.yml
   */
  async loadConfig(configPath?: string): Promise<VulcnConfig> {
    const paths = configPath
      ? [configPath]
      : [
          "vulcn.config.yml",
          "vulcn.config.yaml",
          "vulcn.config.json",
          ".vulcnrc.yml",
          ".vulcnrc.yaml",
          ".vulcnrc.json",
        ];

    for (const path of paths) {
      const resolved = isAbsolute(path) ? path : resolve(process.cwd(), path);
      if (existsSync(resolved)) {
        const content = await readFile(resolved, "utf-8");
        const parsed = path.endsWith(".json")
          ? JSON.parse(content)
          : YAML.parse(content);
        this.config = VulcnConfigSchema.parse(parsed);
        return this.config;
      }
    }

    // No config file - use defaults
    this.config = { version: "1", plugins: [], settings: {} };
    return this.config;
  }

  /**
   * Load all plugins from config
   */
  async loadPlugins(): Promise<void> {
    if (!this.config) {
      await this.loadConfig();
    }

    const pluginConfigs = this.config?.plugins || [];

    for (const pluginConfig of pluginConfigs) {
      if (pluginConfig.enabled === false) continue;

      try {
        const loaded = await this.loadPlugin(pluginConfig);
        this.plugins.push(loaded);
      } catch (err) {
        // Plugin from config failing to load is an ERROR — scan can
        // proceed but the user explicitly asked for this plugin.
        this.errorHandler.catch(err, {
          severity: ErrorSeverity.ERROR,
          source: `plugin-manager:load`,
          context: { plugin: pluginConfig.name },
        });
      }
    }
  }

  /**
   * Load a single plugin
   */
  private async loadPlugin(config: PluginConfig): Promise<LoadedPlugin> {
    const { name, config: pluginConfig = {} } = config;
    let plugin: VulcnPlugin;
    let source: PluginSource;

    // Determine plugin source and load
    if (name.startsWith("./") || name.startsWith("../") || isAbsolute(name)) {
      // Local file plugin
      const resolved = isAbsolute(name) ? name : resolve(process.cwd(), name);
      const module = await import(resolved);
      plugin = module.default || module;
      source = "local";
    } else if (name.startsWith("@vulcn/")) {
      // Official plugin (npm package)
      const module = await import(name);
      plugin = module.default || module;
      source = "npm";
    } else {
      // Community plugin (npm package)
      const module = await import(name);
      plugin = module.default || module;
      source = "npm";
    }

    // Validate plugin structure
    this.validatePlugin(plugin);

    // Validate plugin config if schema provided
    let resolvedConfig = pluginConfig;
    if (plugin.configSchema) {
      try {
        resolvedConfig = plugin.configSchema.parse(pluginConfig);
      } catch (err) {
        throw new Error(
          `Invalid config for plugin ${name}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    return {
      plugin,
      config: resolvedConfig,
      source,
      enabled: true,
    };
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
   * Load default payloads and detection plugins for common scanning.
   *
   * This encapsulates the orchestration logic that was previously duplicated
   * in the CLI `run` command and the Worker `scanner`. Both now collapse
   * to a single call:
   *
   *   await manager.loadDefaults(["xss", "sqli"], { passive: true });
   *
   * The method:
   * 1. Loads requested payload types via @vulcn/plugin-payloads
   * 2. Auto-loads matching detection plugins (xss → detect-xss, sqli → detect-sqli)
   * 3. Optionally loads the passive security scanner
   * 4. Falls back to ["xss"] if no payload types specified
   */
  async loadDefaults(
    payloadTypes: string[] = [],
    options: {
      /** Load passive scanner plugin (default: true) */
      passive?: boolean;
      /** Custom payload file to load */
      payloadFile?: string;
    } = {},
  ): Promise<void> {
    const { passive = true, payloadFile } = options;
    const types = payloadTypes.length > 0 ? payloadTypes : ["xss"];

    // Load custom payloads from file if provided
    if (payloadFile) {
      try {
        const payloadPkg = "@vulcn/plugin-payloads";
        const { loadFromFile } = await import(/* @vite-ignore */ payloadPkg);
        const loaded = await loadFromFile(payloadFile);
        this.addPayloads(loaded);
      } catch (err) {
        throw new Error(
          `Failed to load custom payloads from ${payloadFile}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // Load payload types
    try {
      const payloadPkg = "@vulcn/plugin-payloads";
      const { loadPayloadBox } = await import(/* @vite-ignore */ payloadPkg);
      for (const name of types) {
        const payload = await loadPayloadBox(name);
        this.addPayloads([payload]);
      }
    } catch (err) {
      throw new Error(
        `Failed to load payloads: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // Auto-load XSS detection plugin
    if (
      types.some((t) => t.toLowerCase() === "xss") &&
      !this.hasPlugin("@vulcn/plugin-detect-xss")
    ) {
      try {
        const pkg = "@vulcn/plugin-detect-xss";
        const mod = await import(/* @vite-ignore */ pkg);
        this.addPlugin(mod.default);
      } catch (err) {
        this.errorHandler.catch(err, {
          severity: ErrorSeverity.WARN,
          source: "plugin-manager:auto-load",
          context: { plugin: "@vulcn/plugin-detect-xss" },
        });
      }
    }

    // Auto-load SQLi detection plugin
    if (
      types.some((t) => {
        const lower = t.toLowerCase();
        return (
          lower === "sqli" ||
          lower === "sql" ||
          lower === "sql-injection" ||
          lower.includes("sql")
        );
      }) &&
      !this.hasPlugin("@vulcn/plugin-detect-sqli")
    ) {
      try {
        const pkg = "@vulcn/plugin-detect-sqli";
        const mod = await import(/* @vite-ignore */ pkg);
        this.addPlugin(mod.default);
      } catch (err) {
        this.errorHandler.catch(err, {
          severity: ErrorSeverity.WARN,
          source: "plugin-manager:auto-load",
          context: { plugin: "@vulcn/plugin-detect-sqli" },
        });
      }
    }

    // Auto-load passive scanner (opt-out)
    if (passive && !this.hasPlugin("@vulcn/plugin-passive")) {
      try {
        const pkg = "@vulcn/plugin-passive";
        const mod = await import(/* @vite-ignore */ pkg);
        this.addPlugin(mod.default);
      } catch (err) {
        this.errorHandler.catch(err, {
          severity: ErrorSeverity.WARN,
          source: "plugin-manager:auto-load",
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
