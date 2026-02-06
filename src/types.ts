import type { PayloadCategory } from "./payload-types";

export type BrowserType = "chromium" | "firefox" | "webkit";

export interface RecorderOptions {
  browser?: BrowserType;
  viewport?: { width: number; height: number };
  headless?: boolean;
}

export interface RunnerOptions {
  browser?: BrowserType;
  headless?: boolean;
  onFinding?: (finding: Finding) => void;
}

export interface Finding {
  type: PayloadCategory;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  stepId: string;
  payload: string;
  url: string;
  evidence?: string;
  /** Plugin-specific metadata */
  metadata?: Record<string, unknown>;
}

export interface RunResult {
  findings: Finding[];
  stepsExecuted: number;
  payloadsTested: number;
  duration: number;
  errors: string[];
}
