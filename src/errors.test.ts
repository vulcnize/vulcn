/**
 * Tests for the centralized error system
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  VulcnError,
  ErrorHandler,
  ErrorSeverity,
  fatal,
  error,
  warn,
} from "./errors";

describe("VulcnError", () => {
  it("should create a FATAL error", () => {
    const err = fatal("something broke", "driver:browser");
    expect(err).toBeInstanceOf(VulcnError);
    expect(err).toBeInstanceOf(Error);
    expect(err.severity).toBe(ErrorSeverity.FATAL);
    expect(err.source).toBe("driver:browser");
    expect(err.message).toBe("something broke");
    expect(err.timestamp).toBeDefined();
  });

  it("should create an ERROR", () => {
    const err = error("partial failure", "plugin:detect-xss");
    expect(err.severity).toBe(ErrorSeverity.ERROR);
    expect(err.source).toBe("plugin:detect-xss");
  });

  it("should create a WARN", () => {
    const err = warn("plugin not installed", "plugin-manager:auto-load");
    expect(err.severity).toBe(ErrorSeverity.WARN);
  });

  it("should preserve cause", () => {
    const cause = new Error("original");
    const err = fatal("wrapped", "engine", { cause });
    expect(err.cause).toBe(cause);
  });

  it("should include context", () => {
    const err = error("hook failed", "plugin:report", {
      context: { hook: "onScanEnd" },
    });
    expect(err.context).toEqual({ hook: "onScanEnd" });
  });

  describe("VulcnError.from", () => {
    it("should wrap a plain Error", () => {
      const original = new Error("boom");
      const wrapped = VulcnError.from(original, {
        severity: ErrorSeverity.ERROR,
        source: "test",
      });
      expect(wrapped).toBeInstanceOf(VulcnError);
      expect(wrapped.message).toBe("boom");
      expect(wrapped.cause).toBe(original);
    });

    it("should pass through existing VulcnError", () => {
      const original = fatal("already typed", "engine");
      const wrapped = VulcnError.from(original, {
        severity: ErrorSeverity.WARN,
        source: "different",
      });
      // Should return the original, not re-wrap
      expect(wrapped).toBe(original);
      expect(wrapped.severity).toBe(ErrorSeverity.FATAL); // keeps original severity
    });

    it("should wrap string errors", () => {
      const wrapped = VulcnError.from("string error", {
        severity: ErrorSeverity.WARN,
        source: "test",
      });
      expect(wrapped.message).toBe("string error");
    });
  });
});

describe("ErrorHandler", () => {
  let handler: ErrorHandler;

  beforeEach(() => {
    handler = new ErrorHandler();
  });

  it("should start empty", () => {
    expect(handler.getAll()).toEqual([]);
    expect(handler.hasErrors()).toBe(false);
    expect(handler.getSummary()).toBe("No errors.");
  });

  it("should record WARN errors", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    handler.handle(warn("minor issue", "test"));

    expect(handler.getAll()).toHaveLength(1);
    expect(handler.hasErrors()).toBe(false); // WARNs are not "errors"
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it("should record ERROR errors", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    handler.handle(error("something broke", "test"));

    expect(handler.getAll()).toHaveLength(1);
    expect(handler.hasErrors()).toBe(true);
    expect(handler.getErrors()).toHaveLength(1);

    errorSpy.mockRestore();
  });

  it("should THROW on FATAL errors", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const fatalErr = fatal("catastrophic", "engine");
    expect(() => handler.handle(fatalErr)).toThrow("catastrophic");

    // Should still be recorded despite throwing
    expect(handler.getAll()).toHaveLength(1);
    expect(handler.hasErrors()).toBe(true);
    expect(handler.getErrors()[0].severity).toBe(ErrorSeverity.FATAL);

    errorSpy.mockRestore();
  });

  it("should provide accurate counts", () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    handler.handle(warn("w1", "a"));
    handler.handle(warn("w2", "b"));
    handler.handle(error("e1", "c"));

    const counts = handler.counts();
    expect(counts.fatal).toBe(0);
    expect(counts.error).toBe(1);
    expect(counts.warn).toBe(2);

    consoleSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it("should provide human-readable summary", () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    handler.handle(warn("minor", "plugin:xss"));
    handler.handle(error("broke", "engine"));

    const summary = handler.getSummary();
    expect(summary).toContain("0 fatal");
    expect(summary).toContain("1 errors");
    expect(summary).toContain("1 warnings");
    expect(summary).toContain("plugin:xss");
    expect(summary).toContain("engine");

    consoleSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it("should notify listeners", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const listener = vi.fn();

    handler.onError(listener);
    handler.handle(warn("something", "test"));

    expect(listener).toHaveBeenCalledTimes(1);
    expect(listener).toHaveBeenCalledWith(
      expect.objectContaining({ message: "something" }),
    );

    warnSpy.mockRestore();
  });

  it("should allow unsubscribing listeners", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const listener = vi.fn();

    const unsub = handler.onError(listener);
    unsub();
    handler.handle(warn("something", "test"));

    expect(listener).not.toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it("should clear errors", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    handler.handle(warn("something", "test"));
    expect(handler.getAll()).toHaveLength(1);

    handler.clear();
    expect(handler.getAll()).toHaveLength(0);
    expect(handler.hasErrors()).toBe(false);

    warnSpy.mockRestore();
  });

  describe("catch helper", () => {
    it("should wrap and handle in one call", () => {
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

      handler.catch(new Error("boom"), {
        severity: ErrorSeverity.ERROR,
        source: "test",
      });

      expect(handler.getErrors()).toHaveLength(1);
      expect(handler.getErrors()[0].message).toBe("boom");
      expect(handler.getErrors()[0].source).toBe("test");

      errorSpy.mockRestore();
    });

    it("should throw on FATAL", () => {
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

      expect(() =>
        handler.catch(new Error("critical"), {
          severity: ErrorSeverity.FATAL,
          source: "test",
        }),
      ).toThrow("critical");

      errorSpy.mockRestore();
    });
  });
});
