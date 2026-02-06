/**
 * @vulcn/driver-browser
 *
 * Browser recording driver for Vulcn.
 * Uses Playwright to record and replay web application interactions.
 *
 * Step types:
 * - browser.navigate - Navigate to a URL
 * - browser.click - Click an element
 * - browser.input - Type into an input field
 * - browser.keypress - Press a key
 * - browser.scroll - Scroll the page
 * - browser.wait - Wait for a duration
 */

import { z } from "zod";
import type {
  VulcnDriver,
  RecorderDriver,
  RunnerDriver,
  RecordingHandle,
  RecordOptions,
  Session,
  Step,
  RunContext,
  RunResult,
} from "@vulcn/engine";

import { BrowserRecorder } from "./recorder";
import { BrowserRunner } from "./runner";

/**
 * Browser driver configuration schema
 */
export const configSchema = z.object({
  /** Starting URL for recording */
  startUrl: z.string().url().optional(),

  /** Browser type */
  browser: z.enum(["chromium", "firefox", "webkit"]).default("chromium"),

  /** Viewport size */
  viewport: z
    .object({
      width: z.number().default(1280),
      height: z.number().default(720),
    })
    .default({ width: 1280, height: 720 }),

  /** Run headless */
  headless: z.boolean().default(false),
});

export type BrowserConfig = z.infer<typeof configSchema>;

/**
 * Browser step types
 */
export const BROWSER_STEP_TYPES = [
  "browser.navigate",
  "browser.click",
  "browser.input",
  "browser.keypress",
  "browser.scroll",
  "browser.wait",
] as const;

export type BrowserStepType = (typeof BROWSER_STEP_TYPES)[number];

/**
 * Browser-specific step schemas
 */
export const BrowserStepSchema = z.discriminatedUnion("type", [
  z.object({
    id: z.string(),
    type: z.literal("browser.navigate"),
    url: z.string(),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("browser.click"),
    selector: z.string(),
    position: z.object({ x: z.number(), y: z.number() }).optional(),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("browser.input"),
    selector: z.string(),
    value: z.string(),
    injectable: z.boolean().default(true),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("browser.keypress"),
    key: z.string(),
    modifiers: z.array(z.string()).optional(),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("browser.scroll"),
    selector: z.string().optional(),
    position: z.object({ x: z.number(), y: z.number() }),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("browser.wait"),
    duration: z.number(),
    timestamp: z.number(),
  }),
]);

export type BrowserStep = z.infer<typeof BrowserStepSchema>;

/**
 * Browser recorder implementation
 */
const recorderDriver: RecorderDriver = {
  async start(
    config: Record<string, unknown>,
    options: RecordOptions,
  ): Promise<RecordingHandle> {
    const parsedConfig = configSchema.parse(config);
    return BrowserRecorder.start(parsedConfig, options);
  },
};

/**
 * Browser runner implementation
 */
const runnerDriver: RunnerDriver = {
  async execute(session: Session, ctx: RunContext): Promise<RunResult> {
    return BrowserRunner.execute(session, ctx);
  },
};

/**
 * Browser driver for Vulcn
 */
const browserDriver: VulcnDriver = {
  name: "browser",
  version: "0.1.0",
  apiVersion: 1,
  description: "Browser recording driver using Playwright",
  configSchema,
  stepTypes: [...BROWSER_STEP_TYPES],
  recorder: recorderDriver,
  runner: runnerDriver,
};

export default browserDriver;

// Re-export utilities
export { BrowserRecorder } from "./recorder";
export { BrowserRunner } from "./runner";
export { launchBrowser, checkBrowsers, installBrowsers } from "./browser";
