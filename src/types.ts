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
  type: "xss" | "sqli" | "ssrf" | "path-traversal" | "custom";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  stepId: string;
  payload: string;
  url: string;
  evidence?: string;
}

export interface RunResult {
  findings: Finding[];
  stepsExecuted: number;
  payloadsTested: number;
  duration: number;
  errors: string[];
}
