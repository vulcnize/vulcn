/**
 * Driver Manager Tests
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { DriverManager } from "./driver-manager";
import { PluginManager } from "./plugin-manager";
import type {
  VulcnDriver,
  RunContext,
  RunResult,
  RecordingHandle,
  Session,
} from "./driver-types";
import type { Finding } from "./types";

// Mock driver for testing
const createMockDriver = (name: string): VulcnDriver => ({
  name,
  version: "1.0.0",
  apiVersion: 1,
  description: `Mock ${name} driver`,
  stepTypes: [`${name}.action`],
  recorder: {
    async start() {
      const steps: unknown[] = [];
      return {
        async stop() {
          return {
            name: "Mock Session",
            driver: name,
            driverConfig: {},
            steps: [],
          };
        },
        async abort() {},
        getSteps() {
          return steps;
        },
        addStep(step) {
          steps.push(step);
        },
      } as RecordingHandle;
    },
  },
  runner: {
    async execute(session, ctx: RunContext): Promise<RunResult> {
      return {
        findings: ctx.findings,
        stepsExecuted: session.steps.length,
        payloadsTested: 0,
        duration: 100,
        errors: [],
      };
    },
  },
});

describe("DriverManager", () => {
  let manager: DriverManager;

  beforeEach(() => {
    manager = new DriverManager();
  });

  describe("register", () => {
    it("should register a driver", () => {
      const driver = createMockDriver("test");
      manager.register(driver);
      expect(manager.has("test")).toBe(true);
    });

    it("should set first registered driver as default", () => {
      const driver = createMockDriver("test");
      manager.register(driver);
      expect(manager.getDefault()?.name).toBe("test");
    });

    it("should not change default when registering second driver", () => {
      manager.register(createMockDriver("first"));
      manager.register(createMockDriver("second"));
      expect(manager.getDefault()?.name).toBe("first");
    });

    it("should register with source type", () => {
      const driver = createMockDriver("test");
      manager.register(driver, "npm");
      const list = manager.list();
      expect(list[0].source).toBe("npm");
    });

    it("should reject null driver", () => {
      expect(() => manager.register(null as unknown as VulcnDriver)).toThrow(
        "Driver must be an object",
      );
    });

    it("should reject driver without name", () => {
      expect(() => manager.register({} as VulcnDriver)).toThrow(
        "Driver must have a name",
      );
    });

    it("should reject driver with empty name", () => {
      expect(() => manager.register({ name: "" } as VulcnDriver)).toThrow(
        "Driver must have a name",
      );
    });

    it("should reject driver without version", () => {
      expect(() => manager.register({ name: "test" } as VulcnDriver)).toThrow(
        "Driver must have a version",
      );
    });

    it("should reject driver with empty version", () => {
      expect(() =>
        manager.register({ name: "test", version: "" } as VulcnDriver),
      ).toThrow("Driver must have a version");
    });

    it("should reject driver without stepTypes", () => {
      expect(() =>
        manager.register({ name: "test", version: "1.0" } as VulcnDriver),
      ).toThrow("Driver must define stepTypes");
    });

    it("should reject driver with empty stepTypes", () => {
      expect(() =>
        manager.register({
          name: "test",
          version: "1.0",
          stepTypes: [],
        } as unknown as VulcnDriver),
      ).toThrow("Driver must define stepTypes");
    });

    it("should reject driver without recorder", () => {
      expect(() =>
        manager.register({
          name: "test",
          version: "1.0",
          stepTypes: ["test.action"],
        } as VulcnDriver),
      ).toThrow("Driver must have a recorder");
    });

    it("should reject driver without runner", () => {
      expect(() =>
        manager.register({
          name: "test",
          version: "1.0",
          stepTypes: ["test.action"],
          recorder: {},
        } as unknown as VulcnDriver),
      ).toThrow("Driver must have a runner");
    });
  });

  describe("get", () => {
    it("should return registered driver", () => {
      const driver = createMockDriver("test");
      manager.register(driver);
      expect(manager.get("test")).toBe(driver);
    });

    it("should return undefined for unregistered driver", () => {
      expect(manager.get("nonexistent")).toBeUndefined();
    });
  });

  describe("getDefault", () => {
    it("should return undefined when no drivers registered", () => {
      expect(manager.getDefault()).toBeUndefined();
    });

    it("should return first registered driver", () => {
      manager.register(createMockDriver("first"));
      expect(manager.getDefault()?.name).toBe("first");
    });
  });

  describe("setDefault", () => {
    it("should change default driver", () => {
      manager.register(createMockDriver("first"));
      manager.register(createMockDriver("second"));
      manager.setDefault("second");
      expect(manager.getDefault()?.name).toBe("second");
    });

    it("should throw for unregistered driver", () => {
      expect(() => manager.setDefault("nonexistent")).toThrow(
        'Driver "nonexistent" is not registered',
      );
    });
  });

  describe("list", () => {
    it("should return empty array when no drivers", () => {
      expect(manager.list()).toEqual([]);
    });

    it("should return all registered drivers", () => {
      manager.register(createMockDriver("a"));
      manager.register(createMockDriver("b"));
      const list = manager.list();
      expect(list.length).toBe(2);
      expect(list.map((d) => d.driver.name)).toContain("a");
      expect(list.map((d) => d.driver.name)).toContain("b");
    });
  });

  describe("getForSession", () => {
    it("should return driver matching session", () => {
      const driver = createMockDriver("browser");
      manager.register(driver);
      const session: Session = {
        name: "test",
        driver: "browser",
        driverConfig: {},
        steps: [],
      };
      expect(manager.getForSession(session)).toBe(driver);
    });

    it("should throw for missing driver", () => {
      const session: Session = {
        name: "test",
        driver: "missing",
        driverConfig: {},
        steps: [],
      };
      expect(() => manager.getForSession(session)).toThrow(
        'Driver "missing" not found',
      );
    });
  });

  describe("startRecording", () => {
    it("should start recording with correct driver", async () => {
      manager.register(createMockDriver("test"));
      const handle = await manager.startRecording("test", {});
      expect(handle).toBeDefined();
      expect(typeof handle.stop).toBe("function");
      expect(typeof handle.abort).toBe("function");
    });

    it("should return session from recording handle", async () => {
      manager.register(createMockDriver("test"));
      const handle = await manager.startRecording("test", {});
      const session = await handle.stop();
      expect(session.driver).toBe("test");
    });

    it("should throw for missing driver", async () => {
      await expect(manager.startRecording("missing", {})).rejects.toThrow(
        'Driver "missing" not found',
      );
    });
  });

  describe("crawl", () => {
    it("should call driver's crawl method when supported", async () => {
      const mockSessions: Session[] = [
        {
          name: "Crawled Session",
          driver: "crawlable",
          driverConfig: { startUrl: "http://test.com" },
          steps: [
            { id: "step-1", type: "crawlable.navigate", timestamp: 0 },
            { id: "step-2", type: "crawlable.input", timestamp: 100 },
          ],
        },
      ];

      const driver: VulcnDriver = {
        name: "crawlable",
        version: "1.0.0",
        stepTypes: ["crawlable.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
          async crawl(_config, _options) {
            return mockSessions;
          },
        },
        runner: {
          async execute(_session, _ctx): Promise<RunResult> {
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const sessions = await manager.crawl("crawlable", {
        startUrl: "http://test.com",
      });
      expect(sessions).toEqual(mockSessions);
      expect(sessions.length).toBe(1);
      expect(sessions[0].name).toBe("Crawled Session");
    });

    it("should pass config and options to driver crawl", async () => {
      let receivedConfig: Record<string, unknown> = {};
      let receivedOptions = {};

      const driver: VulcnDriver = {
        name: "spy",
        version: "1.0.0",
        stepTypes: ["spy.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
          async crawl(config, options) {
            receivedConfig = config;
            receivedOptions = options;
            return [];
          },
        },
        runner: {
          async execute(): Promise<RunResult> {
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      await manager.crawl(
        "spy",
        { startUrl: "http://example.com", headless: true },
        { maxDepth: 3, maxPages: 10 },
      );

      expect(receivedConfig).toEqual({
        startUrl: "http://example.com",
        headless: true,
      });
      expect(receivedOptions).toEqual({ maxDepth: 3, maxPages: 10 });
    });

    it("should throw for missing driver", async () => {
      await expect(manager.crawl("missing", {})).rejects.toThrow(
        'Driver "missing" not found',
      );
    });

    it("should throw when driver does not support crawl", async () => {
      // Register a driver WITHOUT the crawl method
      const driver = createMockDriver("nocrawl");
      manager.register(driver);

      await expect(manager.crawl("nocrawl", {})).rejects.toThrow(
        'Driver "nocrawl" does not support auto-crawl',
      );
    });
  });

  describe("execute", () => {
    it("should execute session with driver", async () => {
      const driver = createMockDriver("test");
      manager.register(driver);

      const session: Session = {
        name: "test",
        driver: "test",
        driverConfig: {},
        steps: [{ id: "1", type: "test.action", timestamp: 0 }],
      };

      const pm = new PluginManager();

      const result = await manager.execute(session, pm);
      expect(result.stepsExecuted).toBe(1);
      expect(result.errors).toEqual([]);
    });

    it("should collect findings during execution", async () => {
      // Create driver that adds a finding
      const driver: VulcnDriver = {
        name: "finder",
        version: "1.0.0",
        stepTypes: ["finder.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            ctx.addFinding({
              type: "xss",
              severity: "high",
              title: "Test Finding",
              description: "Found during test",
              stepId: "1",
              url: "http://test.com",
              payload: "<script>alert(1)</script>",
            });
            return {
              findings: ctx.findings,
              stepsExecuted: 1,
              payloadsTested: 1,
              duration: 100,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const session: Session = {
        name: "test",
        driver: "finder",
        driverConfig: {},
        steps: [{ id: "1", type: "finder.action", timestamp: 0 }],
      };

      const pm = new PluginManager();
      const result = await manager.execute(session, pm);

      expect(result.findings.length).toBe(1);
      expect(result.findings[0].title).toBe("Test Finding");
    });

    it("should call onFinding callback", async () => {
      const driver: VulcnDriver = {
        name: "callback",
        version: "1.0.0",
        stepTypes: ["callback.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            ctx.addFinding({
              type: "xss",
              severity: "high",
              title: "Callback Finding",
              description: "Test",
              stepId: "1",
              url: "http://test.com",
              payload: "<script>alert(1)</script>",
            });
            return {
              findings: ctx.findings,
              stepsExecuted: 1,
              payloadsTested: 1,
              duration: 100,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const session: Session = {
        name: "test",
        driver: "callback",
        driverConfig: {},
        steps: [],
      };

      const onFinding = vi.fn();
      const pm = new PluginManager();
      await manager.execute(session, pm, { onFinding });

      expect(onFinding).toHaveBeenCalledTimes(1);
      expect(onFinding).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Callback Finding" }),
      );
    });

    it("should provide logger to runner", async () => {
      let receivedLogger: unknown;
      const driver: VulcnDriver = {
        name: "logger",
        version: "1.0.0",
        stepTypes: ["logger.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            receivedLogger = ctx.logger;
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const session: Session = {
        name: "test",
        driver: "logger",
        driverConfig: {},
        steps: [],
      };

      const pm = new PluginManager();
      await manager.execute(session, pm);

      expect(receivedLogger).toBeDefined();
      expect(typeof (receivedLogger as { debug: unknown }).debug).toBe(
        "function",
      );
      expect(typeof (receivedLogger as { info: unknown }).info).toBe(
        "function",
      );
      expect(typeof (receivedLogger as { warn: unknown }).warn).toBe(
        "function",
      );
      expect(typeof (receivedLogger as { error: unknown }).error).toBe(
        "function",
      );
    });

    it("should throw for missing driver in session", async () => {
      const session: Session = {
        name: "test",
        driver: "missing",
        driverConfig: {},
        steps: [],
      };

      const pm = new PluginManager();
      await expect(manager.execute(session, pm)).rejects.toThrow(
        'Driver "missing" not found',
      );
    });

    it("should call plugin onRunStart when onPageReady fires", async () => {
      const onRunStartSpy = vi.fn();
      const driver: VulcnDriver = {
        name: "page-ready",
        version: "1.0.0",
        stepTypes: ["page-ready.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            // Simulate driver calling onPageReady
            await ctx.options.onPageReady?.({} /* fake page */);
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const pm = new PluginManager();
      pm.addPlugin({
        name: "run-start-hook",
        version: "1.0.0",
        hooks: { onRunStart: onRunStartSpy },
      });

      const session: Session = {
        name: "test",
        driver: "page-ready",
        driverConfig: {},
        steps: [],
      };

      await manager.execute(session, pm);
      expect(onRunStartSpy).toHaveBeenCalledTimes(1);
    });

    it("should call plugin onBeforeClose when driver invokes it", async () => {
      const onBeforeCloseSpy = vi.fn();
      const driver: VulcnDriver = {
        name: "close-test",
        version: "1.0.0",
        stepTypes: ["close-test.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            await ctx.options.onBeforeClose?.({} /* fake page */);
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const pm = new PluginManager();
      pm.addPlugin({
        name: "before-close-hook",
        version: "1.0.0",
        hooks: { onBeforeClose: onBeforeCloseSpy },
      });

      const session: Session = {
        name: "test",
        driver: "close-test",
        driverConfig: {},
        steps: [],
      };

      await manager.execute(session, pm);
      expect(onBeforeCloseSpy).toHaveBeenCalledTimes(1);
    });

    it("should call plugin onRunEnd and allow result transformation", async () => {
      const driver: VulcnDriver = {
        name: "run-end",
        version: "1.0.0",
        stepTypes: ["run-end.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(): Promise<RunResult> {
            return {
              findings: [],
              stepsExecuted: 1,
              payloadsTested: 0,
              duration: 50,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const pm = new PluginManager();
      pm.addPlugin({
        name: "run-end-hook",
        version: "1.0.0",
        hooks: {
          onRunEnd: async (result, _ctx) => {
            return {
              ...result,
              errors: [...result.errors, "run-end-hook-ran"],
            };
          },
        },
      });

      const session: Session = {
        name: "test",
        driver: "run-end",
        driverConfig: {},
        steps: [{ id: "1", type: "run-end.action", timestamp: 0 }],
      };

      const result = await manager.execute(session, pm);
      expect(result.errors).toContain("run-end-hook-ran");
    });

    it("should handle onRunStart hook errors gracefully", async () => {
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

      const driver: VulcnDriver = {
        name: "hook-err",
        version: "1.0.0",
        stepTypes: ["hook-err.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            await ctx.options.onPageReady?.({});
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const pm = new PluginManager();
      pm.addPlugin({
        name: "error-hook",
        version: "1.0.0",
        hooks: {
          onRunStart: async () => {
            throw new Error("hook boom");
          },
        },
      });

      const session: Session = {
        name: "test",
        driver: "hook-err",
        driverConfig: {},
        steps: [],
      };

      // onRunStart is ERROR severity — logged but does not throw
      const result = await manager.execute(session, pm);
      expect(result).toBeDefined();
      expect(errorSpy).toHaveBeenCalled();

      // ErrorHandler should have captured it
      const errors = pm.getErrorHandler().getErrors();
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].message).toContain("hook boom");

      errorSpy.mockRestore();
    });

    it("should handle onBeforeClose hook errors gracefully", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      const driver: VulcnDriver = {
        name: "close-err",
        version: "1.0.0",
        stepTypes: ["close-err.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            await ctx.options.onBeforeClose?.({});
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const pm = new PluginManager();
      pm.addPlugin({
        name: "close-error-hook",
        version: "1.0.0",
        hooks: {
          onBeforeClose: async () => {
            throw new Error("close hook boom");
          },
        },
      });

      const session: Session = {
        name: "test",
        driver: "close-err",
        driverConfig: {},
        steps: [],
      };

      const result = await manager.execute(session, pm);
      expect(result).toBeDefined();
      expect(warnSpy).toHaveBeenCalled();
      warnSpy.mockRestore();
    });

    it("should throw on onRunEnd hook errors (FATAL severity)", async () => {
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

      const driver: VulcnDriver = {
        name: "end-err",
        version: "1.0.0",
        stepTypes: ["end-err.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(): Promise<RunResult> {
            return {
              findings: [],
              stepsExecuted: 0,
              payloadsTested: 0,
              duration: 0,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const pm = new PluginManager();
      pm.addPlugin({
        name: "run-end-error-hook",
        version: "1.0.0",
        hooks: {
          onRunEnd: async () => {
            throw new Error("run end boom");
          },
        },
      });

      const session: Session = {
        name: "test",
        driver: "end-err",
        driverConfig: {},
        steps: [],
      };

      // onRunEnd is FATAL severity — should throw and halt execution
      await expect(manager.execute(session, pm)).rejects.toThrow(
        "run end boom",
      );

      // ErrorHandler should have captured it
      const errors = pm.getErrorHandler().getErrors();
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].severity).toBe("fatal");

      errorSpy.mockRestore();
    });
  });

  describe("executeScan", () => {
    it("should return empty results for no sessions", async () => {
      const pm = new PluginManager();
      const { results, aggregate } = await manager.executeScan([], pm);

      expect(results).toEqual([]);
      expect(aggregate.stepsExecuted).toBe(0);
      expect(aggregate.errors).toContain("No sessions to execute");
    });

    it("should aggregate results from multiple sessions", async () => {
      manager.register(createMockDriver("mock"));
      const sessions: Session[] = [
        {
          name: "Session A",
          driver: "mock",
          driverConfig: {},
          steps: [{ id: "1", type: "mock.action", timestamp: 0 }],
        },
        {
          name: "Session B",
          driver: "mock",
          driverConfig: {},
          steps: [{ id: "2", type: "mock.action", timestamp: 0 }],
        },
      ];

      const pm = new PluginManager();
      const { results, aggregate } = await manager.executeScan(sessions, pm);

      expect(results.length).toBe(2);
      expect(aggregate.stepsExecuted).toBeGreaterThanOrEqual(0);
      expect(aggregate.duration).toBeGreaterThanOrEqual(0);
    });

    it("should fire onScanStart hook with all sessions", async () => {
      manager.register(createMockDriver("mock"));
      const receivedSessions: Session[][] = [];

      const pm = new PluginManager();
      pm.addPlugin({
        name: "test-scan-hook",
        version: "1.0.0",
        hooks: {
          onScanStart: async (ctx) => {
            receivedSessions.push(ctx.sessions);
          },
        },
      });

      const sessions: Session[] = [
        {
          name: "A",
          driver: "mock",
          driverConfig: {},
          steps: [],
        },
        {
          name: "B",
          driver: "mock",
          driverConfig: {},
          steps: [],
        },
      ];

      await manager.executeScan(sessions, pm);

      expect(receivedSessions.length).toBe(1);
      expect(receivedSessions[0].length).toBe(2);
      expect(receivedSessions[0][0].name).toBe("A");
      expect(receivedSessions[0][1].name).toBe("B");
    });

    it("should fire onScanEnd hook and allow result transformation", async () => {
      manager.register(createMockDriver("mock"));
      const pm = new PluginManager();
      pm.addPlugin({
        name: "test-scan-end",
        version: "1.0.0",
        hooks: {
          onScanEnd: async (result, _ctx) => {
            return {
              ...result,
              errors: [...result.errors, "scan-end-hook-ran"],
            };
          },
        },
      });

      const sessions: Session[] = [
        {
          name: "S1",
          driver: "mock",
          driverConfig: {},
          steps: [],
        },
      ];

      const { aggregate } = await manager.executeScan(sessions, pm);

      expect(aggregate.errors).toContain("scan-end-hook-ran");
    });

    it("should call onSessionStart and onSessionEnd callbacks", async () => {
      manager.register(createMockDriver("mock"));

      const sessionStartCalls: [string, number, number][] = [];
      const sessionEndCalls: [string, number, number][] = [];

      const sessions: Session[] = [
        { name: "A", driver: "mock", driverConfig: {}, steps: [] },
        { name: "B", driver: "mock", driverConfig: {}, steps: [] },
      ];

      const pm = new PluginManager();
      await manager.executeScan(sessions, pm, {
        onSessionStart: (session, index, total) => {
          sessionStartCalls.push([session.name, index, total]);
        },
        onSessionEnd: (session, _result, index, total) => {
          sessionEndCalls.push([session.name, index, total]);
        },
      });

      expect(sessionStartCalls).toEqual([
        ["A", 0, 2],
        ["B", 1, 2],
      ]);
      expect(sessionEndCalls).toEqual([
        ["A", 0, 2],
        ["B", 1, 2],
      ]);
    });

    it("should clear findings between sessions", async () => {
      // Create a driver that reports plugin manager findings
      const driver: VulcnDriver = {
        name: "leak-test",
        version: "1.0.0",
        stepTypes: ["leak-test.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(session, ctx): Promise<RunResult> {
            ctx.addFinding({
              type: "xss",
              severity: "high",
              title: `Finding from ${session.name}`,
              description: "test",
              stepId: "1",
              url: "http://test.com",
              payload: "test",
            });
            // Return ONLY this session's findings
            return {
              findings: ctx.findings,
              stepsExecuted: 1,
              payloadsTested: 1,
              duration: 50,
              errors: [],
            };
          },
        },
      };
      manager.register(driver);

      const sessions: Session[] = [
        {
          name: "S1",
          driver: "leak-test",
          driverConfig: {},
          steps: [{ id: "1", type: "leak-test.action", timestamp: 0 }],
        },
        {
          name: "S2",
          driver: "leak-test",
          driverConfig: {},
          steps: [{ id: "2", type: "leak-test.action", timestamp: 0 }],
        },
      ];

      const pm = new PluginManager();
      const { results } = await manager.executeScan(sessions, pm);

      // Each session should only have 1 finding (not accumulated from previous)
      expect(results[0].findings.length).toBe(1);
      expect(results[0].findings[0].title).toBe("Finding from S1");
      expect(results[1].findings.length).toBe(1);
      expect(results[1].findings[0].title).toBe("Finding from S2");
    });

    it("should auto-initialize plugins if not already initialized", async () => {
      manager.register(createMockDriver("mock"));
      const onInitSpy = vi.fn();

      const pm = new PluginManager();
      pm.addPlugin({
        name: "auto-init-test",
        version: "1.0.0",
        hooks: { onInit: onInitSpy },
      });

      const sessions: Session[] = [
        { name: "S1", driver: "mock", driverConfig: {}, steps: [] },
      ];

      // Calling executeScan without explicit initialize()
      await manager.executeScan(sessions, pm);

      // onInit should have been called automatically
      expect(onInitSpy).toHaveBeenCalledTimes(1);
    });

    it("should not double-initialize plugins on repeated executeScan calls", async () => {
      manager.register(createMockDriver("mock"));
      const onInitSpy = vi.fn();

      const pm = new PluginManager();
      pm.addPlugin({
        name: "idempotent-init",
        version: "1.0.0",
        hooks: { onInit: onInitSpy },
      });

      const sessions: Session[] = [
        { name: "S1", driver: "mock", driverConfig: {}, steps: [] },
      ];

      await manager.executeScan(sessions, pm);
      await manager.executeScan(sessions, pm);

      // onInit should only fire once (idempotent)
      expect(onInitSpy).toHaveBeenCalledTimes(1);
    });

    it("should timeout slow sessions when timeout option is set", async () => {
      // Create a slow driver that takes longer than the timeout
      const slowDriver: VulcnDriver = {
        name: "slow",
        version: "1.0.0",
        stepTypes: ["slow.action"],
        recorder: {
          async start() {
            return {} as RecordingHandle;
          },
        },
        runner: {
          async execute(): Promise<RunResult> {
            // Simulate a slow session (500ms)
            await new Promise((resolve) => setTimeout(resolve, 500));
            return {
              findings: [],
              stepsExecuted: 1,
              payloadsTested: 0,
              duration: 500,
              errors: [],
            };
          },
        },
      };
      manager.register(slowDriver);

      const sessions: Session[] = [
        { name: "Slow Session", driver: "slow", driverConfig: {}, steps: [] },
      ];

      const pm = new PluginManager();
      const { results, aggregate } = await manager.executeScan(sessions, pm, {
        timeout: 50, // 50ms timeout — way shorter than 500ms
      });

      // Should record timeout error
      expect(results.length).toBe(1);
      expect(results[0].errors.length).toBe(1);
      expect(results[0].errors[0]).toContain("timed out");
      expect(aggregate.errors.length).toBe(1);
    });

    it("should not timeout fast sessions", async () => {
      manager.register(createMockDriver("mock"));

      const sessions: Session[] = [
        { name: "Fast", driver: "mock", driverConfig: {}, steps: [] },
      ];

      const pm = new PluginManager();
      const { results } = await manager.executeScan(sessions, pm, {
        timeout: 5000, // Generous timeout
      });

      expect(results.length).toBe(1);
      expect(results[0].errors).toEqual([]);
    });
  });
});
