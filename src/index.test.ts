import { describe, it, expect } from "vitest";
import {
  Recorder,
  Runner,
  parseSession,
  createSession,
  PluginManager,
  PLUGIN_API_VERSION,
} from "../src/index.js";

describe("Public API exports", () => {
  it("should export Recorder class", () => {
    expect(Recorder).toBeDefined();
    expect(typeof Recorder).toBe("function");
  });

  it("should export Runner class", () => {
    expect(Runner).toBeDefined();
    expect(typeof Runner).toBe("function");
  });

  it("should export parseSession function", () => {
    expect(parseSession).toBeDefined();
    expect(typeof parseSession).toBe("function");
  });

  it("should export createSession function", () => {
    expect(createSession).toBeDefined();
    expect(typeof createSession).toBe("function");
  });

  it("should export PluginManager class", () => {
    expect(PluginManager).toBeDefined();
    expect(typeof PluginManager).toBe("function");
  });

  it("should export PLUGIN_API_VERSION", () => {
    expect(PLUGIN_API_VERSION).toBe(1);
  });
});

describe("Session API", () => {
  it("should allow creating Session objects", () => {
    const session = createSession({
      name: "test-session",
      startUrl: "https://example.com",
    });
    expect(session.version).toBe("1");
    expect(session.name).toBe("test-session");
    expect(session.steps).toEqual([]);
  });
});

describe("Plugin API", () => {
  it("should allow creating and managing plugins", async () => {
    const manager = new PluginManager();

    manager.addPlugin({
      name: "test-plugin",
      version: "1.0.0",
    });

    expect(manager.getPlugins()).toHaveLength(1);
    await manager.destroy();
  });
});
