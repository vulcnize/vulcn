/**
 * @vulcn/engine - Core security testing engine
 *
 * This is the minimal, low-level core that provides:
 * - Recording browser interactions
 * - Replaying sessions with payload injection
 * - Plugin system for extensibility
 *
 * Plugins handle:
 * - Payload loading (builtin, payloadbox, custom files)
 * - Vulnerability detection (reflection, execution, etc.)
 * - Reporting (JSON, SARIF, HTML)
 */

// Core classes
export { Recorder, type RecordingSession } from "./recorder";
export { Runner } from "./runner";

// Session handling
export {
  createSession,
  parseSession,
  serializeSession,
  SessionSchema,
  StepSchema,
  type Session,
  type Step,
} from "./session";

// Browser utilities
export {
  launchBrowser,
  installBrowsers,
  checkBrowsers,
  BrowserNotFoundError,
  type LaunchOptions,
  type BrowserLaunchResult,
} from "./browser";

// Core types
export type {
  BrowserType,
  RecorderOptions,
  RunnerOptions,
  Finding,
  RunResult,
} from "./types";

// Payload types (for plugins to use)
export type {
  PayloadCategory,
  PayloadSource,
  RuntimePayload,
  CustomPayload,
  CustomPayloadFile,
} from "./payload-types";

// Plugin System
export { PluginManager, pluginManager } from "./plugin-manager";
export { PLUGIN_API_VERSION } from "./plugin-types";
export type {
  VulcnPlugin,
  VulcnConfig,
  PluginConfig,
  PluginHooks,
  PluginContext,
  RecordContext,
  RunContext,
  DetectContext,
  LoadedPlugin,
  PluginLogger,
  EngineInfo,
  PluginSource,
} from "./plugin-types";
