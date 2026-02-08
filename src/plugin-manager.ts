/**
 * Vulcn Plugin Manager
 * Handles plugin loading, lifecycle, and hook execution
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve, isAbsolute } from "node:path";
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

// Package version (injected at build time or read from package.json)
const ENGINE_VERSION = "0.2.0";

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

  /**
   * Shared context passed to all plugins
   */
  private sharedPayloads: RuntimePayload[] = [];
  private sharedFindings: Finding[] = [];

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
        console.error(
          `Failed to load plugin ${pluginConfig.name}:`,
          err instanceof Error ? err.message : String(err),
        );
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
  createContext(pluginConfig: Record<string, unknown>): PluginContext {
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
        this.sharedFindings.push(finding);
      },
      logger: this.createLogger("plugin"),
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
        const ctx = this.createContext(loaded.config);
        ctx.logger = this.createLogger(loaded.plugin.name);
        try {
          await executor(hook as NonNullable<PluginHooks[K]>, ctx);
        } catch (err) {
          console.error(
            `Error in plugin ${loaded.plugin.name}.${hookName}:`,
            err instanceof Error ? err.message : String(err),
          );
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
        const ctx = this.createContext(loaded.config);
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
          console.error(
            `Error in plugin ${loaded.plugin.name}.${hookName}:`,
            err instanceof Error ? err.message : String(err),
          );
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
        const ctx = this.createContext(loaded.config);
        ctx.logger = this.createLogger(loaded.plugin.name);
        try {
          value = await executor(
            hook as NonNullable<PluginHooks[typeof hookName]>,
            value,
            ctx,
          );
        } catch (err) {
          console.error(
            `Error in plugin ${loaded.plugin.name}.${hookName}:`,
            err instanceof Error ? err.message : String(err),
          );
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
