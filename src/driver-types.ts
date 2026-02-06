/**
 * Vulcn Driver System
 *
 * Drivers handle recording and running sessions for different targets:
 * - browser: Web applications (Playwright)
 * - api: REST/HTTP APIs
 * - cli: Command-line tools
 *
 * Each driver implements RecorderDriver and RunnerDriver interfaces.
 */

import type { z } from "zod";
import type { Finding } from "./types";
import type { RuntimePayload } from "./payload-types";
import type { PluginManager } from "./plugin-manager";

/**
 * Current driver API version
 */
export const DRIVER_API_VERSION = 1;

/**
 * Generic step - drivers define their own step types
 */
export interface Step {
  /** Unique step ID */
  id: string;

  /** Step type (namespaced, e.g., "browser.click", "api.request") */
  type: string;

  /** Timestamp when step was recorded */
  timestamp: number;

  /** Step-specific data */
  [key: string]: unknown;
}

/**
 * Generic session format
 */
export interface Session {
  /** Session name */
  name: string;

  /** Driver that recorded this session */
  driver: string;

  /** Driver-specific configuration */
  driverConfig: Record<string, unknown>;

  /** Recorded steps */
  steps: Step[];

  /** Session metadata */
  metadata?: {
    recordedAt?: string;
    version?: string;
    [key: string]: unknown;
  };
}

/**
 * Recording context passed to drivers
 */
export interface RecordContext {
  /** Session being built */
  session: Partial<Session>;

  /** Add a step to the session */
  addStep(step: Omit<Step, "id" | "timestamp">): void;

  /** Logger */
  logger: DriverLogger;
}

/**
 * Running context passed to drivers
 */
export interface RunContext {
  /** Session being executed */
  session: Session;

  /** Plugin manager for calling hooks */
  pluginManager: PluginManager;

  /** Available payloads */
  payloads: RuntimePayload[];

  /** Collected findings */
  findings: Finding[];

  /** Add a finding */
  addFinding(finding: Finding): void;

  /** Logger */
  logger: DriverLogger;

  /** Running options */
  options: RunOptions;
}

/**
 * Options for recording
 */
export interface RecordOptions {
  /** Driver-specific options */
  [key: string]: unknown;
}

/**
 * Options for running
 */
export interface RunOptions {
  /** Run headless (for visual drivers) */
  headless?: boolean;

  /** Callback for findings */
  onFinding?: (finding: Finding) => void;

  /** Callback for step completion */
  onStepComplete?: (stepId: string, payloadCount: number) => void;

  /** Driver-specific options */
  [key: string]: unknown;
}

/**
 * Run result
 */
export interface RunResult {
  /** All findings */
  findings: Finding[];

  /** Steps executed */
  stepsExecuted: number;

  /** Payloads tested */
  payloadsTested: number;

  /** Duration in milliseconds */
  duration: number;

  /** Errors encountered */
  errors: string[];
}

/**
 * Driver logger
 */
export interface DriverLogger {
  debug(msg: string, ...args: unknown[]): void;
  info(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
}

/**
 * Recorder Driver Interface
 *
 * Implement this to add recording support for a target type.
 */
export interface RecorderDriver {
  /** Start recording and return control handle */
  start(
    config: Record<string, unknown>,
    options: RecordOptions,
  ): Promise<RecordingHandle>;
}

/**
 * Handle returned by RecorderDriver.start()
 */
export interface RecordingHandle {
  /** Stop recording and return the session */
  stop(): Promise<Session>;

  /** Abort recording without saving */
  abort(): Promise<void>;

  /** Get current steps (during recording) */
  getSteps(): Step[];

  /** Manually add a step */
  addStep(step: Omit<Step, "id" | "timestamp">): void;
}

/**
 * Runner Driver Interface
 *
 * Implement this to add running/replay support for a target type.
 */
export interface RunnerDriver {
  /** Execute a session with payloads */
  execute(session: Session, ctx: RunContext): Promise<RunResult>;
}

/**
 * Complete driver definition
 */
export interface VulcnDriver {
  /** Unique driver name (e.g., "browser", "api", "cli") */
  name: string;

  /** Driver version */
  version: string;

  /** Driver API version */
  apiVersion?: number;

  /** Human-readable description */
  description?: string;

  /** Configuration schema (Zod) */
  configSchema?: z.ZodSchema;

  /** Step types this driver handles */
  stepTypes: string[];

  /** Recorder implementation */
  recorder: RecorderDriver;

  /** Runner implementation */
  runner: RunnerDriver;
}

/**
 * Driver source for loading
 */
export type DriverSource = "npm" | "local" | "builtin";

/**
 * Loaded driver with metadata
 */
export interface LoadedDriver {
  driver: VulcnDriver;
  source: DriverSource;
}
