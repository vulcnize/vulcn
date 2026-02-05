// Core exports
export { Recorder, type RecordingSession } from "./recorder";
export { Runner } from "./runner";
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

// Payloads
export {
  BUILTIN_PAYLOADS,
  getPayload,
  getPayloadNames,
  getPayloadsByCategory,
  type Payload,
  type PayloadCategory,
  type PayloadName,
} from "./payloads";

// Types
export type {
  BrowserType,
  RecorderOptions,
  RunnerOptions,
  Finding,
  RunResult,
} from "./types";
