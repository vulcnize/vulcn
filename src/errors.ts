/**
 * Vulcn Error System
 *
 * Centralized error handling with severity classification.
 * Components emit errors here instead of making local catch/swallow decisions.
 *
 * Severity levels:
 *   FATAL  — Stop execution immediately. The operation cannot continue.
 *            Examples: report plugin fails to write, payload loading fails,
 *            driver can't launch browser.
 *
 *   ERROR  — Something broke but execution can continue. Record it.
 *            Examples: a single session times out, a plugin hook fails
 *            on a non-critical lifecycle event.
 *
 *   WARN   — Expected or recoverable. Log and move on.
 *            Examples: optional plugin not installed, browser page navigation
 *            intermittently fails, auth state not found.
 */

// ── Error Severity ─────────────────────────────────────────────────────

export enum ErrorSeverity {
  /** Stop execution — unrecoverable */
  FATAL = "fatal",
  /** Record and continue — something broke but others can proceed */
  ERROR = "error",
  /** Log and move on — expected or minor */
  WARN = "warn",
}

// ── Typed Error ────────────────────────────────────────────────────────

export class VulcnError extends Error {
  readonly severity: ErrorSeverity;
  readonly source: string;
  readonly context?: Record<string, unknown>;
  readonly timestamp: string;

  constructor(
    message: string,
    options: {
      severity: ErrorSeverity;
      source: string;
      cause?: unknown;
      context?: Record<string, unknown>;
    },
  ) {
    super(message, { cause: options.cause });
    this.name = "VulcnError";
    this.severity = options.severity;
    this.source = options.source;
    this.context = options.context;
    this.timestamp = new Date().toISOString();
  }

  /**
   * Wrap any caught error into a VulcnError.
   * If it's already a VulcnError, returns it as-is.
   */
  static from(
    err: unknown,
    defaults: {
      severity: ErrorSeverity;
      source: string;
      context?: Record<string, unknown>;
    },
  ): VulcnError {
    if (err instanceof VulcnError) return err;

    const message = err instanceof Error ? err.message : String(err);

    return new VulcnError(message, {
      severity: defaults.severity,
      source: defaults.source,
      cause: err,
      context: defaults.context,
    });
  }
}

// ── Convenience constructors ───────────────────────────────────────────

export function fatal(
  message: string,
  source: string,
  options?: { cause?: unknown; context?: Record<string, unknown> },
): VulcnError {
  return new VulcnError(message, {
    severity: ErrorSeverity.FATAL,
    source,
    ...options,
  });
}

export function error(
  message: string,
  source: string,
  options?: { cause?: unknown; context?: Record<string, unknown> },
): VulcnError {
  return new VulcnError(message, {
    severity: ErrorSeverity.ERROR,
    source,
    ...options,
  });
}

export function warn(
  message: string,
  source: string,
  options?: { cause?: unknown; context?: Record<string, unknown> },
): VulcnError {
  return new VulcnError(message, {
    severity: ErrorSeverity.WARN,
    source,
    ...options,
  });
}

// ── Error Handler ──────────────────────────────────────────────────────

export type ErrorListener = (error: VulcnError) => void;

/**
 * Central error handler for the Vulcn engine.
 *
 * - FATAL errors throw immediately (halt execution)
 * - ERROR errors are recorded and logged
 * - WARN errors are logged only
 *
 * At the end of a run/scan, call `getSummary()` to see everything that went wrong.
 */
export class ErrorHandler {
  private errors: VulcnError[] = [];
  private listeners: ErrorListener[] = [];

  /**
   * Handle an error based on its severity.
   *
   * - FATAL: logs, records, then THROWS (caller must not catch silently)
   * - ERROR: logs and records
   * - WARN: logs only
   */
  handle(err: VulcnError): void {
    // Always record
    this.errors.push(err);

    // Notify listeners (e.g., for streaming results to UI)
    for (const listener of this.listeners) {
      try {
        listener(err);
      } catch {
        // Listener errors must not cascade
      }
    }

    // Log based on severity
    const ctx = err.context ? ` ${JSON.stringify(err.context)}` : "";

    switch (err.severity) {
      case ErrorSeverity.FATAL:
        console.error(`❌ FATAL [${err.source}] ${err.message}${ctx}`);
        if (err.cause instanceof Error) {
          console.error(`   Caused by: ${err.cause.message}`);
        }
        throw err; // ← This is the whole point. FATAL stops execution.

      case ErrorSeverity.ERROR:
        console.error(`⚠️  ERROR [${err.source}] ${err.message}${ctx}`);
        break;

      case ErrorSeverity.WARN:
        console.warn(`⚡ WARN  [${err.source}] ${err.message}${ctx}`);
        break;
    }
  }

  /**
   * Convenience: wrap a caught error and handle it.
   */
  catch(
    err: unknown,
    defaults: {
      severity: ErrorSeverity;
      source: string;
      context?: Record<string, unknown>;
    },
  ): void {
    this.handle(VulcnError.from(err, defaults));
  }

  // ── Query ──────────────────────────────────────────────────────────

  /** All recorded errors (FATAL + ERROR + WARN) */
  getAll(): VulcnError[] {
    return [...this.errors];
  }

  /** Only ERROR and FATAL */
  getErrors(): VulcnError[] {
    return this.errors.filter(
      (e) =>
        e.severity === ErrorSeverity.ERROR ||
        e.severity === ErrorSeverity.FATAL,
    );
  }

  /** Were there any errors (not just warnings)? */
  hasErrors(): boolean {
    return this.errors.some(
      (e) =>
        e.severity === ErrorSeverity.ERROR ||
        e.severity === ErrorSeverity.FATAL,
    );
  }

  /** Count by severity */
  counts(): Record<ErrorSeverity, number> {
    const counts = {
      [ErrorSeverity.FATAL]: 0,
      [ErrorSeverity.ERROR]: 0,
      [ErrorSeverity.WARN]: 0,
    };
    for (const e of this.errors) {
      counts[e.severity]++;
    }
    return counts;
  }

  /** Human-readable summary for end-of-run reporting */
  getSummary(): string {
    if (this.errors.length === 0) return "No errors.";

    const c = this.counts();
    const lines: string[] = [
      `Error Summary: ${c.fatal} fatal, ${c.error} errors, ${c.warn} warnings`,
    ];

    for (const e of this.errors) {
      const icon =
        e.severity === ErrorSeverity.FATAL
          ? "❌"
          : e.severity === ErrorSeverity.ERROR
            ? "⚠️ "
            : "⚡";
      lines.push(`  ${icon} [${e.source}] ${e.message}`);
    }

    return lines.join("\n");
  }

  // ── Lifecycle ──────────────────────────────────────────────────────

  /** Subscribe to errors as they happen */
  onError(listener: ErrorListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  /** Reset for a new run */
  clear(): void {
    this.errors = [];
  }
}
