/**
 * Vulcn Plugin System Types
 * @module @vulcn/engine/plugin
 *
 * The plugin system is driver-agnostic. Detection plugins receive
 * a generic page interface rather than Playwright types directly.
 * This allows the same plugin to work across different driver types.
 */

import type { z } from "zod";
import type { Session, Step } from "./driver-types";
import type { Finding } from "./types";
import type { ErrorHandler } from "./errors";
import type { RunResult } from "./driver-types";
import type { RuntimePayload, PayloadCategory } from "./payload-types";

// Re-export for plugin authors
export type {
  Session,
  Step,
  Finding,
  RunResult,
  RuntimePayload,
  PayloadCategory,
};

/**
 * Plugin API version - plugins declare compatibility
 */
export const PLUGIN_API_VERSION = 1;

/**
 * Plugin source types for identification
 */
export type PluginSource = "builtin" | "npm" | "local" | "custom";

/**
 * Main plugin interface
 */
export interface VulcnPlugin {
  /** Unique plugin name (e.g., "@vulcn/plugin-payloads") */
  name: string;

  /** Plugin version (semver) */
  version: string;

  /** Plugin API version this plugin targets */
  apiVersion?: number;

  /** Human-readable description */
  description?: string;

  /** Lifecycle hooks */
  hooks?: PluginHooks;

  /**
   * Payloads provided by this plugin (Loaders)
   * Can be static array or async function for lazy loading
   */
  payloads?: RuntimePayload[] | (() => Promise<RuntimePayload[]>);

  /**
   * Zod schema for plugin configuration validation
   */
  configSchema?: z.ZodSchema;
}

/**
 * Plugin lifecycle hooks
 *
 * Detection hooks (onDialog, onConsoleMessage, etc.) receive
 * Playwright types from the driver. Plugins that use these
 * should declare playwright as a peer/dev dependency.
 */
export interface PluginHooks {
  // ─────────────────────────────────────────────────────────────────
  // Initialization
  // ─────────────────────────────────────────────────────────────────

  /**
   * Called when plugin is loaded, before any operation
   * Use for setup, loading payloads, etc.
   */
  onInit?: (ctx: PluginContext) => Promise<void>;

  /**
   * Called when plugin is unloaded/cleanup
   */
  onDestroy?: (ctx: PluginContext) => Promise<void>;

  // ─────────────────────────────────────────────────────────────────
  // Recording Phase
  // ─────────────────────────────────────────────────────────────────

  /** Called when recording starts */
  onRecordStart?: (ctx: RecordContext) => Promise<void>;

  /** Called for each recorded step, can transform */
  onRecordStep?: (step: Step, ctx: RecordContext) => Promise<Step>;

  /** Called when recording ends, can transform session */
  onRecordEnd?: (session: Session, ctx: RecordContext) => Promise<Session>;

  // ─────────────────────────────────────────────────────────────────
  // Scan Phase (wraps all sessions)
  // ─────────────────────────────────────────────────────────────────

  /** Called once when a scan starts (before any session is executed) */
  onScanStart?: (ctx: ScanContext) => Promise<void>;

  /** Called once when a scan ends (after all sessions have executed) */
  onScanEnd?: (result: RunResult, ctx: ScanContext) => Promise<RunResult>;

  // ─────────────────────────────────────────────────────────────────
  // Running Phase (per session)
  // ─────────────────────────────────────────────────────────────────

  /** Called when run starts */
  onRunStart?: (ctx: RunContext) => Promise<void>;

  /** Called before each payload is injected, can transform payload */
  onBeforePayload?: (
    payload: string,
    step: Step,
    ctx: RunContext,
  ) => Promise<string>;

  /** Called after payload injection, for detection */
  onAfterPayload?: (ctx: DetectContext) => Promise<Finding[]>;

  /**
   * Called before the browser/driver is closed.
   * Plugins should await any pending async work here (e.g., flush
   * in-flight response handlers that need browser access).
   */
  onBeforeClose?: (ctx: PluginContext) => Promise<void>;

  /** Called when run ends, can transform results */
  onRunEnd?: (result: RunResult, ctx: RunContext) => Promise<RunResult>;

  // ─────────────────────────────────────────────────────────────────
  // Browser Event Hooks (Detection)
  // These receive driver-specific types (e.g. Playwright's Dialog)
  // ─────────────────────────────────────────────────────────────────

  /** Called when JavaScript alert/confirm/prompt appears */
  onDialog?: (dialog: unknown, ctx: DetectContext) => Promise<Finding | null>;

  /** Called on console.log/warn/error */
  onConsoleMessage?: (
    msg: unknown,
    ctx: DetectContext,
  ) => Promise<Finding | null>;

  /** Called on page load/navigation */
  onPageLoad?: (page: unknown, ctx: DetectContext) => Promise<Finding[]>;

  /** Called on network request */
  onNetworkRequest?: (
    request: unknown,
    ctx: DetectContext,
  ) => Promise<Finding | null>;

  /** Called on network response */
  onNetworkResponse?: (
    response: unknown,
    ctx: DetectContext,
  ) => Promise<Finding | null>;
}

/**
 * Logger interface for plugins
 */
export interface PluginLogger {
  debug: (msg: string, ...args: unknown[]) => void;
  info: (msg: string, ...args: unknown[]) => void;
  warn: (msg: string, ...args: unknown[]) => void;
  error: (msg: string, ...args: unknown[]) => void;
}

/**
 * Engine information exposed to plugins
 */
export interface EngineInfo {
  version: string;
  pluginApiVersion: number;
}

/**
 * Base context available to all plugin hooks
 */
export interface PluginContext {
  /** Plugin-specific configuration */
  config: Record<string, unknown>;

  /** Engine information */
  engine: EngineInfo;

  /** Shared payload registry - loaders add payloads here */
  payloads: RuntimePayload[];

  /** Shared findings collection (read-only view, use addFinding to add) */
  findings: Finding[];

  /**
   * Add a finding through the proper callback chain.
   * Plugins should use this instead of pushing to findings[] directly,
   * so consumers (CLI, worker) get notified via onFinding callbacks.
   */
  addFinding: (finding: Finding) => void;

  /** Scoped logger */
  logger: PluginLogger;

  /**
   * Centralized error handler.
   * Plugins MUST use this to surface errors instead of swallowing them:
   *   ctx.errors.fatal("can't write report", "plugin:report", { cause: err })
   *   ctx.errors.warn("optional feature unavailable", "plugin:passive")
   */
  errors: ErrorHandler;

  /** Fetch API for network requests */
  fetch: typeof fetch;
}

/**
 * Context for recording phase hooks
 */
export interface RecordContext extends PluginContext {
  /** Page interface (driver-specific, e.g. Playwright Page) */
  page: unknown;
}

/**
 * Context for running phase hooks
 */
export interface RunContext extends PluginContext {
  /** Session being executed */
  session: Session;

  /** Page interface (driver-specific, e.g. Playwright Page) */
  page: unknown;

  /** Whether running headless */
  headless: boolean;
}

/**
 * Context for scan-level hooks (wraps all sessions)
 */
export interface ScanContext extends PluginContext {
  /** All sessions in this scan */
  sessions: Session[];

  /** Whether running headless */
  headless: boolean;

  /** Total sessions count */
  sessionCount: number;
}

/**
 * Context for detection hooks
 */
export interface DetectContext extends RunContext {
  /** Current step being tested */
  step: Step;

  /** Current payload set being tested */
  payloadSet: RuntimePayload;

  /** Actual payload value injected */
  payloadValue: string;

  /** Step ID for reporting */
  stepId: string;
}

/**
 * Loaded plugin instance with resolved config
 */
export interface LoadedPlugin {
  /** Plugin definition */
  plugin: VulcnPlugin;

  /** Resolved configuration */
  config: Record<string, unknown>;

  /** Source of the plugin */
  source: PluginSource;

  /** Whether plugin is enabled */
  enabled: boolean;
}
