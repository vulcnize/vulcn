import { describe, it, expect } from "vitest";
import {
  DriverManager,
  driverManager,
  DRIVER_API_VERSION,
  PluginManager,
  pluginManager,
  PLUGIN_API_VERSION,
  VulcnProjectConfigSchema,
  parseProjectConfig,
  DEFAULT_PROJECT_CONFIG,
  findProjectRoot,
  resolveProjectPaths,
  CONFIG_FILENAME,
} from "../src/index.js";

describe("Public API exports", () => {
  it("should export DriverManager class", () => {
    expect(DriverManager).toBeDefined();
    expect(typeof DriverManager).toBe("function");
  });

  it("should export driverManager singleton", () => {
    expect(driverManager).toBeDefined();
    expect(driverManager).toBeInstanceOf(DriverManager);
  });

  it("should export DRIVER_API_VERSION", () => {
    expect(DRIVER_API_VERSION).toBe(1);
  });

  it("should export PluginManager class", () => {
    expect(PluginManager).toBeDefined();
    expect(typeof PluginManager).toBe("function");
  });

  it("should export pluginManager singleton", () => {
    expect(pluginManager).toBeDefined();
    expect(pluginManager).toBeInstanceOf(PluginManager);
  });

  it("should export PLUGIN_API_VERSION", () => {
    expect(PLUGIN_API_VERSION).toBe(1);
  });

  it("should export project config system", () => {
    expect(VulcnProjectConfigSchema).toBeDefined();
    expect(parseProjectConfig).toBeDefined();
    expect(DEFAULT_PROJECT_CONFIG).toBeDefined();
    expect(findProjectRoot).toBeDefined();
    expect(resolveProjectPaths).toBeDefined();
    expect(CONFIG_FILENAME).toBe(".vulcn.yml");
  });
});

describe("DriverManager", () => {
  it("should parse driver-format sessions", () => {
    const yaml = `
name: Driver Session
driver: browser
driverConfig:
  browser: chromium
  startUrl: https://example.com
steps:
  - id: step_001
    type: browser.navigate
    url: https://example.com
    timestamp: 0
`;
    const dm = new DriverManager();
    const session = dm.parseSession(yaml);

    expect(session.driver).toBe("browser");
    expect(session.steps[0].type).toBe("browser.navigate");
  });

  it("should reject sessions without a driver field", () => {
    const yaml = `
name: Legacy Session
steps:
  - id: step_001
    type: navigate
    url: https://example.com
`;
    const dm = new DriverManager();
    expect(() => dm.parseSession(yaml)).toThrow("missing 'driver' field");
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
