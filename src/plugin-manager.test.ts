import { describe, it, expect, beforeEach, vi } from "vitest";
import { PluginManager } from "../src/plugin-manager";
import { PLUGIN_API_VERSION } from "../src/plugin-types";
import type { VulcnPlugin, RuntimePayload } from "../src/index";

describe("PluginManager", () => {
  let manager: PluginManager;

  beforeEach(() => {
    manager = new PluginManager();
  });

  describe("PLUGIN_API_VERSION", () => {
    it("should export the current API version", () => {
      expect(PLUGIN_API_VERSION).toBe(1);
    });
  });

  describe("addPlugin", () => {
    it("should add a valid plugin", () => {
      const plugin: VulcnPlugin = {
        name: "test-plugin",
        version: "1.0.0",
      };

      manager.addPlugin(plugin);
      expect(manager.getPlugins()).toHaveLength(1);
      expect(manager.getPlugins()[0].plugin.name).toBe("test-plugin");
    });

    it("should throw for plugin without name", () => {
      const plugin = { version: "1.0.0" } as VulcnPlugin;
      expect(() => manager.addPlugin(plugin)).toThrow("must have a name");
    });

    it("should throw for plugin without version", () => {
      const plugin = { name: "test" } as VulcnPlugin;
      expect(() => manager.addPlugin(plugin)).toThrow("must have a version");
    });

    it("should throw for incompatible API version", () => {
      const plugin: VulcnPlugin = {
        name: "test",
        version: "1.0.0",
        apiVersion: 999, // Future version
      };
      expect(() => manager.addPlugin(plugin)).toThrow("API version");
    });
  });

  describe("payload management", () => {
    it("should start with empty payloads", () => {
      expect(manager.getPayloads()).toEqual([]);
    });

    it("should allow adding payloads", () => {
      const payload: RuntimePayload = {
        name: "test-payload",
        category: "xss",
        description: "Test",
        payloads: ["<script>alert(1)</script>"],
        detectPatterns: [],
        source: "custom",
      };

      manager.addPayloads([payload]);
      expect(manager.getPayloads()).toHaveLength(1);
    });
  });

  describe("findings management", () => {
    it("should start with empty findings", () => {
      expect(manager.getFindings()).toEqual([]);
    });

    it("should allow adding findings", () => {
      manager.addFinding({
        type: "xss",
        severity: "high",
        title: "Test XSS",
        description: "Found XSS",
        stepId: "step-1",
        payload: "<script>alert(1)</script>",
        url: "http://example.com",
      });

      expect(manager.getFindings()).toHaveLength(1);
    });

    it("should clear findings", () => {
      manager.addFinding({
        type: "xss",
        severity: "high",
        title: "Test",
        description: "Test",
        stepId: "1",
        payload: "test",
        url: "http://test.com",
      });

      manager.clearFindings();
      expect(manager.getFindings()).toEqual([]);
    });
  });

  describe("initialize", () => {
    it("should load payloads from plugins during init", async () => {
      const payload: RuntimePayload = {
        name: "plugin-payload",
        category: "sqli",
        description: "From plugin",
        payloads: ["' OR '1'='1"],
        detectPatterns: [],
        source: "plugin",
      };

      const plugin: VulcnPlugin = {
        name: "payload-provider",
        version: "1.0.0",
        payloads: [payload],
      };

      manager.addPlugin(plugin);
      await manager.initialize();

      expect(manager.getPayloads()).toContainEqual(payload);
    });

    it("should call onInit hooks", async () => {
      const onInit = vi.fn();
      const plugin: VulcnPlugin = {
        name: "hook-test",
        version: "1.0.0",
        hooks: { onInit },
      };

      manager.addPlugin(plugin);
      await manager.initialize();

      expect(onInit).toHaveBeenCalledTimes(1);
    });

    it("should only initialize once", async () => {
      const onInit = vi.fn();
      const plugin: VulcnPlugin = {
        name: "once-test",
        version: "1.0.0",
        hooks: { onInit },
      };

      manager.addPlugin(plugin);
      await manager.initialize();
      await manager.initialize();

      expect(onInit).toHaveBeenCalledTimes(1);
    });
  });

  describe("destroy", () => {
    it("should call onDestroy hooks", async () => {
      const onDestroy = vi.fn();
      const plugin: VulcnPlugin = {
        name: "destroy-test",
        version: "1.0.0",
        hooks: { onDestroy },
      };

      manager.addPlugin(plugin);
      await manager.initialize();
      await manager.destroy();

      expect(onDestroy).toHaveBeenCalledTimes(1);
    });

    it("should clear plugins and state", async () => {
      manager.addPlugin({ name: "test", version: "1.0.0" });
      manager.addPayloads([
        {
          name: "p",
          category: "xss",
          description: "",
          payloads: ["x"],
          detectPatterns: [],
          source: "custom",
        },
      ]);

      await manager.destroy();

      expect(manager.getPlugins()).toEqual([]);
      expect(manager.getPayloads()).toEqual([]);
    });
  });

  describe("callHook", () => {
    it("should call hooks on all plugins sequentially", async () => {
      const order: string[] = [];

      manager.addPlugin({
        name: "plugin-1",
        version: "1.0.0",
        hooks: {
          onInit: async () => {
            order.push("p1");
          },
        },
      });

      manager.addPlugin({
        name: "plugin-2",
        version: "1.0.0",
        hooks: {
          onInit: async () => {
            order.push("p2");
          },
        },
      });

      await manager.initialize();

      expect(order).toEqual(["p1", "p2"]);
    });

    it("should continue on hook errors", async () => {
      const consoleSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});

      manager.addPlugin({
        name: "error-plugin",
        version: "1.0.0",
        hooks: {
          onInit: async () => {
            throw new Error("Hook failed");
          },
        },
      });

      manager.addPlugin({
        name: "ok-plugin",
        version: "1.0.0",
        hooks: {
          onInit: async (ctx) => {
            ctx.payloads.push({
              name: "ok",
              category: "xss",
              description: "",
              payloads: [],
              detectPatterns: [],
              source: "custom",
            });
          },
        },
      });

      await manager.initialize();

      // Second plugin should still run
      expect(manager.getPayloads()).toHaveLength(1);
      consoleSpy.mockRestore();
    });
  });

  describe("createContext", () => {
    it("should create context with all required fields", () => {
      const ctx = manager.createContext({ key: "value" });

      expect(ctx.config).toEqual({ key: "value" });
      expect(ctx.engine.version).toBeDefined();
      expect(ctx.engine.pluginApiVersion).toBe(PLUGIN_API_VERSION);
      expect(ctx.payloads).toEqual([]);
      expect(ctx.findings).toEqual([]);
      expect(ctx.logger).toBeDefined();
      expect(ctx.fetch).toBe(globalThis.fetch);
    });
  });
});
