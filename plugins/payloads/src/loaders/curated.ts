/**
 * Curated Payload Registry
 *
 * Maps payload type names to their curated payload sets.
 * These are hand-crafted, context-aware payloads that ship
 * with Vulcn and are loaded by default.
 *
 * To add a new curated payload type:
 *   1. Create `curated-<type>.ts` with exported RuntimePayload[]
 *   2. Register it in the CURATED_REGISTRY below
 */

import type { RuntimePayload } from "@vulcn/engine";
import { CURATED_XSS } from "./curated-xss";

/**
 * Registry of curated payload sets keyed by type name.
 * Keys are the same short aliases used by PayloadBox
 * (xss, sqli, cmd, etc.)
 */
const CURATED_REGISTRY: Record<string, RuntimePayload[]> = {
  xss: CURATED_XSS,
  // Future: sqli, cmd, path-traversal, etc.
};

/**
 * Get curated payloads for a given type.
 * Returns the payload sets, or undefined if no curated set exists.
 */
export function getCuratedPayloads(type: string): RuntimePayload[] | undefined {
  const key = type.toLowerCase();
  return CURATED_REGISTRY[key];
}

/**
 * Check if a curated payload set exists for a type.
 */
export function hasCuratedPayloads(type: string): boolean {
  return type.toLowerCase() in CURATED_REGISTRY;
}

/**
 * List all available curated payload types.
 */
export function getCuratedTypes(): string[] {
  return Object.keys(CURATED_REGISTRY);
}
