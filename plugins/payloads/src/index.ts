/**
 * @vulcn/plugin-payloads
 * Official payload loader plugin for Vulcn
 *
 * Payload sources (in order of priority):
 * 1. Curated — hand-crafted, context-aware payloads (DEFAULT)
 * 2. PayloadBox — community payloads from PayloadsAllTheThings (opt-in)
 * 3. Custom files — expert-provided YAML/JSON payload files
 *
 * Short aliases for payload types:
 *   xss, sqli, xxe, cmd, redirect, traversal
 */

import { z } from "zod";
import type { VulcnPlugin, PluginContext, RuntimePayload } from "@vulcn/engine";
import { loadPayloadBox, resolvePayloadType } from "./loaders/payloadbox";
import { getCuratedPayloads, hasCuratedPayloads } from "./loaders/curated";
import { loadFromFiles } from "./loaders/file";

/**
 * Plugin configuration schema
 */
const configSchema = z.object({
  /**
   * Payload types to load.
   * Accepts short aliases: xss, sqli, xxe, cmd, redirect, traversal
   * @example ["xss", "sqli"]
   */
  types: z.array(z.string()).optional(),

  /**
   * Enable PayloadBox (PayloadsAllTheThings) payloads.
   * When true, loads community payloads IN ADDITION to curated payloads.
   * @default false
   */
  usePayloadBox: z.boolean().default(false),

  /**
   * Maximum payloads per type when loading from PayloadBox (default 100)
   */
  limit: z.number().default(100),

  /**
   * Custom payload files to load (YAML/JSON)
   */
  files: z.array(z.string()).optional(),
});

export type PayloadsPluginConfig = z.infer<typeof configSchema>;

/**
 * Payloads Plugin
 */
const plugin: VulcnPlugin = {
  name: "@vulcn/plugin-payloads",
  version: "0.4.0",
  apiVersion: 1,
  description:
    "Payload loader — curated context-aware payloads + PayloadBox + custom files",

  configSchema,

  hooks: {
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      const loadedPayloads: RuntimePayload[] = [];

      if (config.types?.length) {
        for (const type of config.types) {
          // 1. Load curated payloads first (always, if available)
          const curated = getCuratedPayloads(type);
          if (curated) {
            loadedPayloads.push(...curated);
            ctx.logger.debug(
              `Loaded ${curated.length} curated payload sets for: ${type}`,
            );
          }

          // 2. Load from PayloadBox if enabled (supplements curated)
          if (config.usePayloadBox) {
            try {
              const payload = await loadPayloadBox(
                type,
                config.limit,
                ctx.fetch,
              );
              loadedPayloads.push(payload);
              ctx.logger.debug(
                `Loaded PayloadBox payload type: ${type} (${payload.payloads.length} payloads)`,
              );
            } catch (err) {
              // If no curated payloads either, this is critical
              if (!curated) {
                throw new Error(
                  `Failed to load payload type "${type}": ${err instanceof Error ? err.message : String(err)}`,
                );
              }
              // Curated payloads available — PayloadBox failure is a warning
              ctx.logger.warn(
                `PayloadBox fetch failed for "${type}" (using curated payloads): ${err instanceof Error ? err.message : String(err)}`,
              );
            }
          } else if (!curated) {
            // No curated, no PayloadBox — try PayloadBox as fallback
            try {
              const payload = await loadPayloadBox(
                type,
                config.limit,
                ctx.fetch,
              );
              loadedPayloads.push(payload);
              ctx.logger.debug(
                `No curated payloads for "${type}" — loaded from PayloadBox (${payload.payloads.length} payloads)`,
              );
            } catch (err) {
              throw new Error(
                `No payloads available for "${type}": no curated set exists and PayloadBox fetch failed: ${err instanceof Error ? err.message : String(err)}`,
              );
            }
          }
        }
      }

      // 3. Load from custom files
      if (config.files?.length) {
        try {
          const filePayloads = await loadFromFiles(config.files);
          loadedPayloads.push(...filePayloads);
          ctx.logger.debug(
            `Loaded ${filePayloads.length} payload sets from files`,
          );
        } catch (err) {
          throw new Error(
            `Failed to load custom payload files: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }

      // Add to shared context
      ctx.payloads.push(...loadedPayloads);

      const totalPayloads = loadedPayloads.reduce(
        (sum, p) => sum + p.payloads.length,
        0,
      );
      ctx.logger.info(
        `Payloads plugin loaded ${loadedPayloads.length} payload sets (${totalPayloads} total payloads)`,
      );
    },
  },
};

export default plugin;

// Re-export for direct access
export {
  loadPayloadBox,
  getPayloadBoxTypes,
  resolvePayloadType,
  isValidPayloadName,
  getDescription,
  getAliases,
  clearPayloadBoxCache,
} from "./loaders/payloadbox";
export { loadFromFiles, loadFromFile } from "./loaders/file";
export {
  getCuratedPayloads,
  hasCuratedPayloads,
  getCuratedTypes,
} from "./loaders/curated";
