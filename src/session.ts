import { z } from "zod";
import { parse, stringify } from "yaml";

// Step types
export const StepSchema = z.discriminatedUnion("type", [
  z.object({
    id: z.string(),
    type: z.literal("navigate"),
    url: z.string(),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("click"),
    selector: z.string(),
    position: z.object({ x: z.number(), y: z.number() }).optional(),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("input"),
    selector: z.string(),
    value: z.string(),
    injectable: z.boolean().optional().default(true),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("keypress"),
    key: z.string(),
    modifiers: z.array(z.string()).optional(),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("scroll"),
    selector: z.string().optional(),
    position: z.object({ x: z.number(), y: z.number() }),
    timestamp: z.number(),
  }),
  z.object({
    id: z.string(),
    type: z.literal("wait"),
    duration: z.number(),
    timestamp: z.number(),
  }),
]);

export type Step = z.infer<typeof StepSchema>;

// Session schema
export const SessionSchema = z.object({
  version: z.string().default("1"),
  name: z.string(),
  recordedAt: z.string(),
  browser: z.enum(["chromium", "firefox", "webkit"]).default("chromium"),
  viewport: z.object({
    width: z.number(),
    height: z.number(),
  }),
  startUrl: z.string(),
  steps: z.array(StepSchema),
});

export type Session = z.infer<typeof SessionSchema>;

/**
 * Create a new session object
 */
export function createSession(options: {
  name: string;
  startUrl: string;
  browser?: "chromium" | "firefox" | "webkit";
  viewport?: { width: number; height: number };
}): Session {
  return {
    version: "1",
    name: options.name,
    recordedAt: new Date().toISOString(),
    browser: options.browser ?? "chromium",
    viewport: options.viewport ?? { width: 1280, height: 720 },
    startUrl: options.startUrl,
    steps: [],
  };
}

/**
 * Parse a session from YAML string
 */
export function parseSession(yaml: string): Session {
  const data = parse(yaml);
  return SessionSchema.parse(data);
}

/**
 * Serialize a session to YAML string
 */
export function serializeSession(session: Session): string {
  return stringify(session, { lineWidth: 0 });
}
