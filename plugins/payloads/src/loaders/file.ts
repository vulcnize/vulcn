/**
 * File Loader
 * Loads custom payloads from YAML/JSON files
 */

import { readFile } from "node:fs/promises";
import { resolve, isAbsolute, extname } from "node:path";
import YAML from "yaml";
import { z } from "zod";
import type { RuntimePayload, PayloadCategory } from "@vulcn/engine";

/**
 * Valid payload categories
 */
const PAYLOAD_CATEGORIES: PayloadCategory[] = [
  "xss",
  "sqli",
  "ssrf",
  "xxe",
  "command-injection",
  "path-traversal",
  "open-redirect",
  "custom",
];

/**
 * Schema for a single custom payload
 */
const CustomPayloadSchema = z.object({
  name: z.string().min(1),
  category: z.enum(
    PAYLOAD_CATEGORIES as [PayloadCategory, ...PayloadCategory[]],
  ),
  description: z.string().optional(),
  payloads: z.array(z.string()).min(1),
  detectPatterns: z.array(z.string()).optional(),
});

/**
 * Schema for a payload file (can contain multiple payloads)
 */
const PayloadFileSchema = z.object({
  version: z.string().optional(),
  payloads: z.array(CustomPayloadSchema),
});

/**
 * Load multiple payload files
 */
export async function loadFromFiles(
  filePaths: string[],
): Promise<RuntimePayload[]> {
  const payloads: RuntimePayload[] = [];

  for (const filePath of filePaths) {
    const loaded = await loadFromFile(filePath);
    payloads.push(...loaded);
  }

  return payloads;
}

/**
 * Load payloads from a single file
 */
export async function loadFromFile(
  filePath: string,
): Promise<RuntimePayload[]> {
  const resolved = isAbsolute(filePath)
    ? filePath
    : resolve(process.cwd(), filePath);

  const content = await readFile(resolved, "utf-8");
  const ext = extname(resolved).toLowerCase();

  // Parse based on extension
  let data: unknown;
  if (ext === ".json") {
    data = JSON.parse(content);
  } else if (ext === ".yml" || ext === ".yaml") {
    data = YAML.parse(content);
  } else {
    throw new Error(
      `Unsupported file extension: ${ext}. Use .yml, .yaml, or .json`,
    );
  }

  // Parse and validate
  return parsePayloadData(data);
}

/**
 * Parse and validate payload data
 */
function parsePayloadData(data: unknown): RuntimePayload[] {
  const dataObj = data as Record<string, unknown>;

  let parsed;

  if (Array.isArray(data)) {
    // Array of payload objects
    parsed = { version: "1", payloads: data };
  } else if (dataObj?.name && dataObj?.category) {
    // Single payload object (has name and category)
    parsed = { version: "1", payloads: [CustomPayloadSchema.parse(data)] };
  } else if (dataObj?.payloads && Array.isArray(dataObj.payloads)) {
    // File schema with payloads array
    parsed = PayloadFileSchema.parse(data);
  } else {
    throw new Error(
      "Invalid payload file format. Expected: array of payloads, file schema, or single payload object",
    );
  }

  // Convert to RuntimePayload[]
  return parsed.payloads.map(
    (p): RuntimePayload => ({
      name: p.name,
      category: p.category,
      description: p.description || `Custom payload: ${p.name}`,
      payloads: p.payloads,
      detectPatterns: parseDetectPatterns(p.detectPatterns),
      source: "custom",
    }),
  );
}

/**
 * Parse detect patterns from strings to RegExp
 */
function parseDetectPatterns(patterns?: string[]): RegExp[] {
  if (!patterns || patterns.length === 0) {
    return [];
  }

  const regexps: RegExp[] = [];
  for (const pattern of patterns) {
    try {
      regexps.push(new RegExp(pattern, "i"));
    } catch {
      console.warn(`Invalid regex pattern: ${pattern}`);
    }
  }
  return regexps;
}
