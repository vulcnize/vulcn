import type { PayloadCategory } from "./payload-types";

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
