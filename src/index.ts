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
// Driver System
// ============================================================================

export { DriverManager, driverManager } from "./driver-manager";
export { DRIVER_API_VERSION } from "./driver-types";
export type {
  VulcnDriver,
  RecorderDriver,
  RunnerDriver,
  RecordingHandle,
  RecordOptions,
  CrawlOptions,
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
  RunContext as PluginRunContext,
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

export type { Finding } from "./types";
