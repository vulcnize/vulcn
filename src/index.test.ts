import { describe, it, expect } from "vitest";
import {
  DriverManager,
  driverManager,
  DRIVER_API_VERSION,
  PluginManager,
  pluginManager,
  PLUGIN_API_VERSION,
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
});

describe("DriverManager", () => {
  it("should parse legacy sessions into driver format", () => {
    const yaml = `
version: "1"
name: Test Session
recordedAt: "2026-01-01T00:00:00Z"
browser: chromium
viewport:
  width: 1280
  height: 720
startUrl: https://example.com
steps:
  - id: step_001
    type: navigate
    url: https://example.com
    timestamp: 0
  - id: step_002
    type: input
    selector: "#search"
    value: test
    injectable: true
    timestamp: 1000
  - id: step_003
    type: click
    selector: button
    timestamp: 2000
`;
    const dm = new DriverManager();
    const session = dm.parseSession(yaml);

    expect(session.driver).toBe("browser");
    expect(session.driverConfig.startUrl).toBe("https://example.com");
    expect(session.driverConfig.browser).toBe("chromium");
    expect(session.steps).toHaveLength(3);
    expect(session.steps[0].type).toBe("browser.navigate");
    expect(session.steps[1].type).toBe("browser.input");
    expect(session.steps[2].type).toBe("browser.click");
  });

  it("should pass through driver-format sessions unchanged", () => {
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
