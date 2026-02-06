/**
 * @vulcn/engine - Core security testing engine
 *
 * v0.3.0: Driver-based architecture
 *
 * The engine now provides:
 * - Driver system for different recording targets (browser, api, cli)
 * - Plugin system for payloads and detection
 * - Generic session format
 *
 * Drivers handle:
 * - Recording interactions (RecorderDriver)
 * - Replaying with payload injection (RunnerDriver)
 *
 * Plugins handle:
 * - Payload loading (builtin, payloadbox, custom files)
 * - Vulnerability detection (reflection, execution, etc.)
 * - Reporting (JSON, SARIF, HTML)
 */

// ============================================================================
// Driver System (NEW in v0.3.0)
// ============================================================================

export { DriverManager, driverManager } from "./driver-manager";
export { DRIVER_API_VERSION } from "./driver-types";
export type {
  VulcnDriver,
  RecorderDriver,
  RunnerDriver,
  RecordingHandle,
  RecordOptions,
  RunOptions,
  RunResult,
  RunContext,
  Session,
  Step,
  DriverLogger,
  LoadedDriver,
  DriverSource,
} from "./driver-types";

// ============================================================================
// Plugin System
// ============================================================================

export { PluginManager, pluginManager } from "./plugin-manager";
export { PLUGIN_API_VERSION } from "./plugin-types";
export type {
  VulcnPlugin,
  VulcnConfig,
  PluginConfig,
  PluginHooks,
  PluginContext,
  RecordContext,
  DetectContext,
  LoadedPlugin as LoadedPluginInfo,
  PluginLogger,
  EngineInfo,
  PluginSource,
} from "./plugin-types";

// ============================================================================
// Payload Types
// ============================================================================

export type {
  PayloadCategory,
  PayloadSource,
  RuntimePayload,
  CustomPayload,
  CustomPayloadFile,
} from "./payload-types";

// ============================================================================
// Core Types
// ============================================================================

export type {
  BrowserType,
  RecorderOptions,
  RunnerOptions,
  Finding,
} from "./types";

// ============================================================================
// Legacy Exports (Deprecated - will be removed in v1.0)
// These are browser-specific and should be imported from @vulcn/driver-browser
// ============================================================================

/** @deprecated Import from @vulcn/driver-browser instead */
export { Recorder, type RecordingSession } from "./recorder";

/** @deprecated Import from @vulcn/driver-browser instead */
export { Runner } from "./runner";

/** @deprecated Import from @vulcn/driver-browser instead */
export {
  createSession,
  parseSession,
  serializeSession,
  SessionSchema,
  StepSchema,
} from "./session";
export type { Session as LegacySession, Step as LegacyStep } from "./session";

/** @deprecated Import from @vulcn/driver-browser instead */
export {
  launchBrowser,
  installBrowsers,
  checkBrowsers,
  BrowserNotFoundError,
  type LaunchOptions,
  type BrowserLaunchResult,
} from "./browser";
