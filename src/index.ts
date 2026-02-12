/**
 * @vulcn/engine - Core security testing engine
 *
 * v0.7.0: Driver-based architecture + Auth + Session v2
 *
 * The engine now provides:
 * - Driver system for different recording targets (browser, api, cli)
 * - Plugin system for payloads and detection
 * - Generic session format
 * - Credential encryption & auth state management
 * - Session format v2 (.vulcn/ directory)
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
  VulcnConfig,
  PluginConfig,
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
// Session Format v2
// ============================================================================

export {
  loadSessionDir,
  saveSessionDir,
  isSessionDir,
  looksLikeSessionDir,
  readAuthState,
  readCapturedRequests,
} from "./session";
export type { ScanManifest, SessionRef, CapturedRequest } from "./session";

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
