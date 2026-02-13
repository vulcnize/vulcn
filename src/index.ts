/**
 * @vulcn/engine - Core security testing engine
 *
 * v0.9.0: Unified project config (.vulcn.yml)
 *
 * The engine provides:
 * - Project config system (.vulcn.yml — single source of truth)
 * - Driver system for different recording targets (browser, api, cli)
 * - Plugin system for payloads and detection
 * - Generic session format
 * - Credential encryption & auth state management
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
// Project Config (.vulcn.yml)
// ============================================================================

export {
  VulcnProjectConfigSchema,
  parseProjectConfig,
  DEFAULT_PROJECT_CONFIG,
} from "./config";
export type { VulcnProjectConfig } from "./config";

export {
  findProjectRoot,
  resolveProjectPaths,
  loadProject,
  loadProjectFromFile,
  ensureProjectDirs,
  CONFIG_FILENAME,
  DIRS,
} from "./project";
export type { ProjectPaths, VulcnProject } from "./project";

// ============================================================================
// Driver System
// ============================================================================

export { DriverManager, driverManager, ENGINE_VERSION } from "./driver-manager";
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
  PluginHooks,
  PluginContext,
  RecordContext,
  RunContext as PluginRunContext,
  ScanContext,
  DetectContext,
  LoadedPlugin as LoadedPluginInfo,
  PluginLogger,
  EngineInfo,
  PluginSource,
} from "./plugin-types";

// ============================================================================
// Auth System
// ============================================================================

export {
  encrypt,
  decrypt,
  encryptCredentials,
  decryptCredentials,
  encryptStorageState,
  decryptStorageState,
  getPassphrase,
} from "./auth";
export type {
  FormCredentials,
  HeaderCredentials,
  Credentials,
  AuthConfig,
} from "./auth";

// ============================================================================
// Session Types
// ============================================================================

export type { CapturedRequest } from "./session";

// ============================================================================
// Payload Types
// ============================================================================

export { getSeverity } from "./payload-types";
export type {
  PayloadCategory,
  PayloadSource,
  RuntimePayload,
  CustomPayload,
  CustomPayloadFile,
} from "./payload-types";

// ============================================================================
// Error System
// ============================================================================

export {
  VulcnError,
  ErrorHandler,
  ErrorSeverity,
  fatal,
  error,
  warn,
} from "./errors";
export type { ErrorListener } from "./errors";

// ============================================================================
// Core Types
// ============================================================================

export type { Finding } from "./types";
