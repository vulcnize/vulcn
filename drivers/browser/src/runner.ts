/**
 * Browser Runner Implementation
 *
 * Replays browser sessions with security payloads.
 * Uses plugin hooks for detection.
 */

import type { Page, Dialog, ConsoleMessage } from "playwright";
import type {
  Session,
  Step,
  RunContext,
  RunResult,
  Finding,
  RuntimePayload,
  PayloadCategory,
} from "@vulcn/engine";

import { launchBrowser, type BrowserType } from "./browser";
import type { BrowserStep } from "./index";

/**
 * Browser Runner - replays sessions with payloads
 */
export class BrowserRunner {
  /**
   * Execute a session with security payloads
   */
  static async execute(session: Session, ctx: RunContext): Promise<RunResult> {
    const config = session.driverConfig;
    const browserType = (config.browser as BrowserType) ?? "chromium";
    const viewport = (config.viewport as { width: number; height: number }) ?? {
      width: 1280,
      height: 720,
    };
    const startUrl = config.startUrl as string;
    const headless = ctx.options.headless ?? true;

    const startTime = Date.now();
    const errors: string[] = [];
    let payloadsTested = 0;

    const payloads = ctx.payloads;
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
    const context = await browser.newContext({ viewport });
    const page = await context.newPage();

    // Event findings from dialog/console handlers
    const eventFindings: Finding[] = [];
    let currentPayloadInfo: {
      stepId: string;
      payloadSet: RuntimePayload;
      payloadValue: string;
    } | null = null;

    // Dialog handler (for alert-based XSS detection)
    const dialogHandler = async (dialog: Dialog) => {
      if (currentPayloadInfo) {
        // Check if dialog message matches payload
        const message = dialog.message();
        if (
          message.includes("vulcn") ||
          message === currentPayloadInfo.payloadValue
        ) {
          eventFindings.push({
            type: "xss",
            severity: "high",
            title: "XSS Confirmed - Dialog Triggered",
            description: `JavaScript dialog was triggered by payload injection`,
            stepId: currentPayloadInfo.stepId,
            payload: currentPayloadInfo.payloadValue,
            url: page.url(),
            evidence: `Dialog message: ${message}`,
            metadata: {
              dialogType: dialog.type(),
              detectionMethod: "dialog",
            },
          });
        }
      }
      // Always dismiss dialogs to prevent blocking
      try {
        await dialog.dismiss();
      } catch {
        // Dialog may have already been handled
      }
    };

    // Console message handler
    const consoleHandler = async (msg: ConsoleMessage) => {
      if (currentPayloadInfo && msg.type() === "log") {
        const text = msg.text();
        if (
          text.includes("vulcn") ||
          text.includes(currentPayloadInfo.payloadValue)
        ) {
          eventFindings.push({
            type: "xss",
            severity: "high",
            title: "XSS Confirmed - Console Output",
            description: `JavaScript console.log was triggered by payload injection`,
            stepId: currentPayloadInfo.stepId,
            payload: currentPayloadInfo.payloadValue,
            url: page.url(),
            evidence: `Console output: ${text}`,
            metadata: {
              consoleType: msg.type(),
              detectionMethod: "console",
            },
          });
        }
      }
    };

    page.on("dialog", dialogHandler);
    page.on("console", consoleHandler);

    try {
      // Find injectable steps (browser.input with injectable=true)
      const injectableSteps = session.steps.filter(
        (
          step,
        ): step is Step & { type: "browser.input"; injectable?: boolean } =>
          step.type === "browser.input" &&
          (step as BrowserStep & { type: "browser.input" }).injectable !==
            false,
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
        for (const { payloadSet, value } of allPayloads) {
          try {
            currentPayloadInfo = {
              stepId: injectableStep.id,
              payloadSet,
              payloadValue: value,
            };

            // Replay session with payload
            await BrowserRunner.replayWithPayload(
              page,
              session,
              injectableStep,
              value,
              startUrl,
            );

            // Check for reflection
            const reflectionFinding = await BrowserRunner.checkReflection(
              page,
              injectableStep,
              payloadSet,
              value,
            );

            // Collect all findings
            const allFindings = [...eventFindings];
            if (reflectionFinding) {
              allFindings.push(reflectionFinding);
            }

            // Add unique findings
            for (const finding of allFindings) {
              ctx.addFinding(finding);
            }

            // Clear event findings for next iteration
            eventFindings.length = 0;
            payloadsTested++;

            // Report progress
            ctx.options.onStepComplete?.(injectableStep.id, payloadsTested);
          } catch (err) {
            errors.push(`${injectableStep.id}: ${String(err)}`);
          }
        }
      }
    } finally {
      page.off("dialog", dialogHandler);
      page.off("console", consoleHandler);
      currentPayloadInfo = null;
      await browser.close();
    }

    return {
      findings: ctx.findings,
      stepsExecuted: session.steps.length,
      payloadsTested,
      duration: Date.now() - startTime,
      errors,
    };
  }

  /**
   * Replay session steps with payload injected at target step
   */
  private static async replayWithPayload(
    page: Page,
    session: Session,
    targetStep: Step & { type: "browser.input" },
    payloadValue: string,
    startUrl: string,
  ): Promise<void> {
    // Navigate to start
    await page.goto(startUrl, { waitUntil: "domcontentloaded" });

    // Replay steps
    for (const step of session.steps) {
      const browserStep = step as BrowserStep;

      try {
        switch (browserStep.type) {
          case "browser.navigate":
            await page.goto(browserStep.url, { waitUntil: "domcontentloaded" });
            break;

          case "browser.click":
            await page.click(browserStep.selector, { timeout: 5000 });
            break;

          case "browser.input": {
            // Inject payload for target step
            const value =
              step.id === targetStep.id ? payloadValue : browserStep.value;
            await page.fill(browserStep.selector, value, { timeout: 5000 });
            break;
          }

          case "browser.keypress": {
            const modifiers = browserStep.modifiers ?? [];
            for (const mod of modifiers) {
              await page.keyboard.down(
                mod as "Control" | "Shift" | "Alt" | "Meta",
              );
            }
            await page.keyboard.press(browserStep.key);
            for (const mod of modifiers.reverse()) {
              await page.keyboard.up(
                mod as "Control" | "Shift" | "Alt" | "Meta",
              );
            }
            break;
          }

          case "browser.scroll":
            if (browserStep.selector) {
              await page.locator(browserStep.selector).evaluate((el, pos) => {
                el.scrollTo(pos.x, pos.y);
              }, browserStep.position);
            } else {
              await page.evaluate((pos) => {
                window.scrollTo(pos.x, pos.y);
              }, browserStep.position);
            }
            break;

          case "browser.wait":
            await page.waitForTimeout(browserStep.duration);
            break;
        }
      } catch {
        // Step failed, continue to next
      }

      // Stop after target step is injected
      if (step.id === targetStep.id) {
        // Wait a bit for any scripts to execute
        await page.waitForTimeout(100);
        break;
      }
    }
  }

  /**
   * Check for payload reflection in page content
   */
  private static async checkReflection(
    page: Page,
    step: Step & { type: "browser.input" },
    payloadSet: RuntimePayload,
    payloadValue: string,
  ): Promise<Finding | undefined> {
    const content = await page.content();

    // Check for reflection patterns
    for (const pattern of payloadSet.detectPatterns) {
      if (pattern.test(content)) {
        return {
          type: payloadSet.category,
          severity: BrowserRunner.getSeverity(payloadSet.category),
          title: `${payloadSet.category.toUpperCase()} vulnerability detected`,
          description: `Payload pattern was reflected in page content`,
          stepId: step.id,
          payload: payloadValue,
          url: page.url(),
          evidence: content.match(pattern)?.[0]?.slice(0, 200),
        };
      }
    }

    // Check if payload appears verbatim
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
