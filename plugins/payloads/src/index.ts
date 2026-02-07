/**
 * @vulcn/plugin-payloads
 * Official payload loader plugin for Vulcn
 *
 * Payload sources (in order of priority):
 * 1. PayloadBox — community-curated payloads from PayloadsAllTheThings (default)
 * 2. Custom files — expert-provided YAML/JSON payload files
 *
 * Short aliases for payload types:
 *   xss, sqli, xxe, cmd, redirect, traversal
 */

import { z } from "zod";
import type { VulcnPlugin, PluginContext, RuntimePayload } from "@vulcn/engine";
import { loadPayloadBox, resolvePayloadType } from "./loaders/payloadbox";
import { loadFromFiles } from "./loaders/file";

/**
 * Plugin configuration schema
 */
const configSchema = z.object({
  /**
   * Payload types to load from PayloadsAllTheThings.
   * Accepts short aliases: xss, sqli, xxe, cmd, redirect, traversal
   * @example ["xss", "sqli"]
   */
  types: z.array(z.string()).optional(),

  /**
   * Maximum payloads per type (default 50)
   */
  limit: z.number().default(50),

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
  version: "0.3.0",
  apiVersion: 1,
  description: "Payload loader — PayloadsAllTheThings + custom files",

  configSchema,

  hooks: {
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      const loadedPayloads: RuntimePayload[] = [];

      // 1. Load from PayloadBox (primary source)
      if (config.types?.length) {
        for (const type of config.types) {
          try {
            const payload = await loadPayloadBox(type, config.limit, ctx.fetch);
            loadedPayloads.push(payload);
            ctx.logger.debug(`Loaded payload type: ${type}`);
          } catch (err) {
            ctx.logger.error(
              `Failed to load "${type}": ${err instanceof Error ? err.message : String(err)}`,
            );
          }
        }
      }

      // 2. Load from custom files
      if (config.files?.length) {
        try {
          const filePayloads = await loadFromFiles(config.files);
          loadedPayloads.push(...filePayloads);
          ctx.logger.debug(
            `Loaded ${filePayloads.length} payload sets from files`,
          );
        } catch (err) {
          ctx.logger.error(
            `Failed to load custom files: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }

      // Add to shared context
      ctx.payloads.push(...loadedPayloads);

      ctx.logger.info(
        `Payloads plugin loaded ${loadedPayloads.length} payload sets`,
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
