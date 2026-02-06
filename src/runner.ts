/**
 * Runner - replays sessions with security payloads
 * v0.2.0: Plugin-based architecture for extensibility
 */

import type { Page, Dialog, ConsoleMessage } from "playwright";
import { launchBrowser } from "./browser";
import type { RuntimePayload, PayloadCategory } from "./payload-types";
import type { Session, Step } from "./session";
import type { Finding, RunResult, RunnerOptions } from "./types";
import { PluginManager, pluginManager } from "./plugin-manager";
import type { DetectContext, RunContext } from "./plugin-types";

export interface RunnerConfig {
  /** Plugin manager to use (defaults to shared instance) */
  pluginManager?: PluginManager;
}

/**
 * Runner - replays sessions with security payloads
 *
 * Uses plugin hooks for:
 * - Payload loading (onInit)
 * - Payload transformation (onBeforePayload)
 * - Vulnerability detection (onAfterPayload, onDialog, onConsoleMessage, etc.)
 * - Results processing (onRunEnd)
 */
export class Runner {
  /**
   * Execute a session with security payloads from plugins
   *
   * @param session - The recorded session to replay
   * @param options - Runner configuration
   * @param config - Plugin manager configuration
   */
  static async execute(
    session: Session,
    options: RunnerOptions = {},
    config: RunnerConfig = {},
  ): Promise<RunResult> {
    const manager = config.pluginManager ?? pluginManager;
    const browserType = options.browser ?? session.browser ?? "chromium";
    const headless = options.headless ?? true;
    const startTime = Date.now();

    const errors: string[] = [];
    let payloadsTested = 0;

    // Initialize plugins and load payloads
    await manager.initialize();
    manager.clearFindings();

    const payloads = manager.getPayloads();
    if (payloads.length === 0) {
      return {
        findings: [],
        stepsExecuted: session.steps.length,
        payloadsTested: 0,
        duration: Date.now() - startTime,
        errors: [
          "No payloads loaded. Add a payload plugin or configure payloads.",
        ],
      };
    }

    // Launch browser
    const { browser } = await launchBrowser({
      browser: browserType,
      headless,
    });
    const context = await browser.newContext({ viewport: session.viewport });
    const page = await context.newPage();

    // Create base run context
    const baseRunContext: Omit<RunContext, "config"> = {
      session,
      page,
      browser: browserType,
      headless,
      engine: { version: "0.2.0", pluginApiVersion: 1 },
      payloads: manager.getPayloads(),
      findings: manager.getFindings(),
      logger: {
        debug: console.debug.bind(console),
        info: console.info.bind(console),
        warn: console.warn.bind(console),
        error: console.error.bind(console),
      },
      fetch: globalThis.fetch,
    };

    // Call onRunStart hooks
    await manager.callHook("onRunStart", async (hook, ctx) => {
      const runCtx: RunContext = { ...baseRunContext, ...ctx };
      await hook(runCtx);
    });

    // Set up browser event listeners for detection
    const eventFindings: Finding[] = [];
    let currentDetectContext: DetectContext | null = null;

    // Dialog handler (for alert-based XSS detection)
    const dialogHandler = async (dialog: Dialog) => {
      if (currentDetectContext) {
        const findings = await manager.callHookCollect<"onDialog", Finding>(
          "onDialog",
          async (hook, ctx) => {
            const detectCtx: DetectContext = {
              ...currentDetectContext!,
              ...ctx,
            };
            return hook(dialog, detectCtx);
          },
        );
        eventFindings.push(...findings);
      }
      // Always dismiss dialogs to prevent blocking
      try {
        await dialog.dismiss();
      } catch {
        // Dialog may have already been handled
      }
    };

    // Console message handler (for console-based XSS detection)
    const consoleHandler = async (msg: ConsoleMessage) => {
      if (currentDetectContext) {
        const findings = await manager.callHookCollect<
          "onConsoleMessage",
          Finding
        >("onConsoleMessage", async (hook, ctx) => {
          const detectCtx: DetectContext = { ...currentDetectContext!, ...ctx };
          return hook(msg, detectCtx);
        });
        eventFindings.push(...findings);
      }
    };

    page.on("dialog", dialogHandler);
    page.on("console", consoleHandler);

    try {
      // Find injectable steps
      const injectableSteps = session.steps.filter(
        (step): step is Step & { type: "input" } =>
          step.type === "input" && step.injectable !== false,
      );

      // Build flat list of all individual payloads to test
      const allPayloads: { payloadSet: RuntimePayload; value: string }[] = [];
      for (const payloadSet of payloads) {
        for (const value of payloadSet.payloads) {
          allPayloads.push({ payloadSet, value });
        }
      }

      // For each injectable step, test with each payload
      for (const injectableStep of injectableSteps) {
        for (const { payloadSet, value: originalValue } of allPayloads) {
          try {
            // Transform payload through plugins
            let transformedPayload = originalValue;
            for (const loaded of manager.getPlugins()) {
              const hook = loaded.plugin.hooks?.onBeforePayload;
              if (hook) {
                const ctx = manager.createContext(loaded.config);
                const runCtx: RunContext = { ...baseRunContext, ...ctx };
                transformedPayload = await hook(
                  transformedPayload,
                  injectableStep,
                  runCtx,
                );
              }
            }

            // Create detect context for this payload
            currentDetectContext = {
              ...baseRunContext,
              config: {},
              step: injectableStep,
              payloadSet,
              payloadValue: transformedPayload,
              stepId: injectableStep.id,
            };

            // Replay session with payload
            await Runner.replayWithPayload(
              page,
              session,
              injectableStep,
              transformedPayload,
            );

            // Call onAfterPayload hooks for detection
            const afterFindings = await manager.callHookCollect<
              "onAfterPayload",
              Finding
            >("onAfterPayload", async (hook, ctx) => {
              const detectCtx: DetectContext = {
                ...currentDetectContext!,
                ...ctx,
              };
              return hook(detectCtx);
            });

            // Also do basic reflection check (built-in fallback)
            const reflectionFinding = await Runner.checkReflection(
              page,
              injectableStep,
              payloadSet,
              transformedPayload,
            );

            // Collect all findings
            const allFindings = [...afterFindings, ...eventFindings];
            if (reflectionFinding) {
              allFindings.push(reflectionFinding);
            }

            // Add unique findings
            for (const finding of allFindings) {
              manager.addFinding(finding);
              options.onFinding?.(finding);
            }

            // Clear event findings for next iteration
            eventFindings.length = 0;
            payloadsTested++;
          } catch (err) {
            errors.push(`${injectableStep.id}: ${String(err)}`);
          }
        }
      }
    } finally {
      // Remove listeners
      page.off("dialog", dialogHandler);
      page.off("console", consoleHandler);

      currentDetectContext = null;
      await browser.close();
    }

    // Create result
    let result: RunResult = {
      findings: manager.getFindings(),
      stepsExecuted: session.steps.length,
      payloadsTested,
      duration: Date.now() - startTime,
      errors,
    };

    // Transform result through plugins
    for (const loaded of manager.getPlugins()) {
      const hook = loaded.plugin.hooks?.onRunEnd;
      if (hook) {
        const ctx = manager.createContext(loaded.config);
        const runCtx: RunContext = { ...baseRunContext, ...ctx };
        result = await hook(result, runCtx);
      }
    }

    return result;
  }

  /**
   * Execute with explicit payloads (legacy API, for backwards compatibility)
   */
  static async executeWithPayloads(
    session: Session,
    payloads: RuntimePayload[],
    options: RunnerOptions = {},
  ): Promise<RunResult> {
    // Create a temporary plugin manager with the provided payloads
    const manager = new PluginManager();
    manager.addPayloads(payloads);

    return Runner.execute(session, options, { pluginManager: manager });
  }

  /**
   * Replay session steps with payload injected at target step
   */
  private static async replayWithPayload(
    page: Page,
    session: Session,
    targetStep: Step & { type: "input" },
    payloadValue: string,
  ): Promise<void> {
    // Navigate to start
    await page.goto(session.startUrl, { waitUntil: "domcontentloaded" });

    // Replay steps
    for (const step of session.steps) {
      try {
        if (step.type === "navigate") {
          await page.goto(step.url, { waitUntil: "domcontentloaded" });
        } else if (step.type === "click") {
          await page.click(step.selector, { timeout: 5000 });
        } else if (step.type === "input") {
          // Inject payload for target step
          const value = step.id === targetStep.id ? payloadValue : step.value;
          await page.fill(step.selector, value, { timeout: 5000 });
        } else if (step.type === "keypress") {
          const modifiers = step.modifiers ?? [];
          for (const mod of modifiers) {
            await page.keyboard.down(
              mod as "Control" | "Shift" | "Alt" | "Meta",
            );
          }
          await page.keyboard.press(step.key);
          for (const mod of modifiers.reverse()) {
            await page.keyboard.up(mod as "Control" | "Shift" | "Alt" | "Meta");
          }
        }
      } catch {
        // Step failed, continue to next
      }

      // Stop after target step is injected (we can check sooner)
      if (step.id === targetStep.id) {
        // Wait a bit for any scripts to execute
        await page.waitForTimeout(100);
        break;
      }
    }
  }

  /**
   * Basic reflection check - fallback when no detection plugin is loaded
   */
  private static async checkReflection(
    page: Page,
    step: Step & { type: "input" },
    payloadSet: RuntimePayload,
    payloadValue: string,
  ): Promise<Finding | undefined> {
    // Get page content
    const content = await page.content();

    // Check for reflection patterns
    for (const pattern of payloadSet.detectPatterns) {
      if (pattern.test(content)) {
        return {
          type: payloadSet.category,
          severity: Runner.getSeverity(payloadSet.category),
          title: `${payloadSet.category.toUpperCase()} vulnerability detected`,
          description: `Payload pattern was reflected in page content`,
          stepId: step.id,
          payload: payloadValue,
          url: page.url(),
          evidence: content.match(pattern)?.[0]?.slice(0, 200),
        };
      }
    }

    // Check if payload appears verbatim (potential XSS)
    if (content.includes(payloadValue)) {
      return {
        type: payloadSet.category,
        severity: "medium",
        title: `Potential ${payloadSet.category.toUpperCase()} - payload reflection`,
        description: `Payload was reflected in page without encoding`,
        stepId: step.id,
        payload: payloadValue,
        url: page.url(),
      };
    }

    return undefined;
  }

  /**
   * Determine severity based on vulnerability category
   */
  private static getSeverity(
    category: PayloadCategory,
  ): "critical" | "high" | "medium" | "low" | "info" {
    switch (category) {
      case "sqli":
      case "command-injection":
      case "xxe":
        return "critical";
      case "xss":
      case "ssrf":
      case "path-traversal":
        return "high";
      case "open-redirect":
        return "medium";
      default:
        return "medium";
    }
  }
}
