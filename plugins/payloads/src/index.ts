/**
 * @vulcn/plugin-payloads
 * Official payload loader plugin for Vulcn
 *
 * Provides:
 * - Built-in payloads (XSS, SQLi, SSRF, XXE, etc.)
 * - PayloadBox loader (PayloadsAllTheThings)
 * - Custom file loader (YAML/JSON)
 */

import { z } from "zod";
import type { VulcnPlugin, PluginContext, RuntimePayload } from "@vulcn/engine";
import { BUILTIN_PAYLOADS } from "./builtin";
import { loadPayloadBox } from "./loaders/payloadbox";
import { loadFromFiles } from "./loaders/file";

/**
 * Plugin configuration schema
 */
const configSchema = z.object({
  /**
   * Include built-in payloads (default: true)
   */
  builtin: z.boolean().default(true),

  /**
   * Specific built-in payload names to include (if not all)
   */
  include: z.array(z.string()).optional(),

  /**
   * Built-in payload names to exclude
   */
  exclude: z.array(z.string()).optional(),

  /**
   * PayloadBox types to fetch from PayloadsAllTheThings
   * e.g., ["xss", "sql-injection", "xxe"]
   */
  payloadbox: z.array(z.string()).optional(),

  /**
   * Limit per PayloadBox type
   */
  payloadboxLimit: z.number().default(50),

  /**
   * Custom payload files to load (YAML/JSON)
   */
  files: z.array(z.string()).optional(),
});

export type PayloadsPluginConfig = z.infer<typeof configSchema>;

/**
 * Payloads Plugin - loads payloads from various sources
 */
const plugin: VulcnPlugin = {
  name: "@vulcn/plugin-payloads",
  version: "0.2.0",
  apiVersion: 1,
  description:
    "Official payload loader plugin - built-in, PayloadBox, and custom files",

  configSchema,

  hooks: {
    onInit: async (ctx: PluginContext) => {
      const config = configSchema.parse(ctx.config);
      const loadedPayloads: RuntimePayload[] = [];

      // 1. Load built-in payloads
      if (config.builtin) {
        let builtinNames = Object.keys(BUILTIN_PAYLOADS);

        // Filter by include list if provided
        if (config.include?.length) {
          builtinNames = builtinNames.filter((name) =>
            config.include!.includes(name),
          );
        }

        // Remove excluded payloads
        if (config.exclude?.length) {
          builtinNames = builtinNames.filter(
            (name) => !config.exclude!.includes(name),
          );
        }

        for (const name of builtinNames) {
          const payload = BUILTIN_PAYLOADS[name];
          if (payload) {
            loadedPayloads.push(payload);
          }
        }

        ctx.logger.debug(`Loaded ${builtinNames.length} built-in payload sets`);
      }

      // 2. Load from PayloadBox
      if (config.payloadbox?.length) {
        for (const type of config.payloadbox) {
          try {
            const payload = await loadPayloadBox(
              type,
              config.payloadboxLimit,
              ctx.fetch,
            );
            loadedPayloads.push(payload);
            ctx.logger.debug(`Loaded PayloadBox: ${type}`);
          } catch (err) {
            ctx.logger.error(
              `Failed to load PayloadBox ${type}: ${err instanceof Error ? err.message : String(err)}`,
            );
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
export { BUILTIN_PAYLOADS } from "./builtin";
export { loadPayloadBox, getPayloadBoxTypes } from "./loaders/payloadbox";
export { loadFromFiles, loadFromFile } from "./loaders/file";
