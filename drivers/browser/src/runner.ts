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

    // Signal that the page is ready — plugins (e.g. passive scanner)
    // can now attach event listeners to the real page object
    await ctx.options.onPageReady?.(page);

    // Event findings from dialog/console handlers
    const eventFindings: Finding[] = [];
    let currentPayloadInfo: {
      stepId: string;
      payloadSet: RuntimePayload;
      payloadValue: string;
    } | null = null;

    // Dialog handler (for alert-based XSS detection)
    // ANY dialog triggered during payload testing is evidence of XSS execution
    const dialogHandler = async (dialog: Dialog) => {
      if (currentPayloadInfo) {
        const message = dialog.message();
        const dialogType = dialog.type();

        // Skip beforeunload dialogs (not XSS-related)
        if (dialogType !== "beforeunload") {
          eventFindings.push({
            type: "xss",
            severity: "high",
            title: `XSS Confirmed - ${dialogType}() triggered`,
            description: `JavaScript ${dialogType}() dialog was triggered by payload injection. Message: "${message}"`,
            stepId: currentPayloadInfo.stepId,
            payload: currentPayloadInfo.payloadValue,
            url: page.url(),
            evidence: `Dialog type: ${dialogType}, Message: ${message}`,
            metadata: {
              dialogType,
              dialogMessage: message,
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

      // Build flat list of payloads, interleaved by category (round-robin).
      // This ensures we test at least one payload from each category quickly,
      // so the dedup early-break fires sooner on slow SPAs like Angular apps.
      // Before: [sqli1, sqli2, ..., sqli50, xss1, xss2, ..., xss50]
      // After:  [sqli1, xss1, sqli2, xss2, ..., sqli50, xss50]
      const allPayloads: { payloadSet: RuntimePayload; value: string }[] = [];
      const payloadsByCategory = payloads.map((ps) =>
        ps.payloads.map((value) => ({ payloadSet: ps, value })),
      );
      const maxLen = Math.max(...payloadsByCategory.map((c) => c.length));
      for (let i = 0; i < maxLen; i++) {
        for (const category of payloadsByCategory) {
          if (i < category.length) {
            allPayloads.push(category[i]);
          }
        }
      }

      // Track confirmed vulnerability types per-step to avoid duplicate findings.
      // Once XSS is confirmed on an input (e.g., via dialog), skip remaining XSS payloads.
      const confirmedTypes = new Set<string>();

      // For each injectable step, test with each payload
      for (const injectableStep of injectableSteps) {
        for (const { payloadSet, value } of allPayloads) {
          // Skip if this vulnerability type is already confirmed for this step
          const stepTypeKey = `${injectableStep.id}::${payloadSet.category}`;
          if (confirmedTypes.has(stepTypeKey)) {
            continue;
          }

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

            // Collect all findings from this payload
            const allFindings = [...eventFindings];
            if (reflectionFinding) {
              allFindings.push(reflectionFinding);
            }

            // Deduplicate: only add findings we haven't already reported
            const seenKeys = new Set<string>();
            for (const finding of allFindings) {
              const dedupKey = `${finding.type}::${finding.stepId}::${finding.title}`;
              if (!seenKeys.has(dedupKey)) {
                seenKeys.add(dedupKey);
                ctx.addFinding(finding);
              }
            }

            // If we got any finding (dialog, console, or reflection), mark as confirmed
            // and skip remaining payloads of this category for this input.
            // One confirmed finding is enough evidence — no need to test more payloads.
            if (allFindings.length > 0) {
              confirmedTypes.add(stepTypeKey);
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

      // Let plugins flush pending async work before browser closes
      // (e.g., passive scanner's in-flight response header analysis)
      await ctx.options.onBeforeClose?.(page);

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
   *
   * IMPORTANT: We replay ALL steps, not just up to the injectable step.
   * The injection replaces the input value, but subsequent steps (like
   * clicking submit) must still execute so the payload reaches the server
   * and gets reflected back in the response.
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

    let injected = false;

    // Replay ALL steps — inject payload at the target input step,
    // but continue replaying remaining steps (clicks, navigations)
    // so forms get submitted and payloads reach the server
    for (const step of session.steps) {
      const browserStep = step as BrowserStep;

      try {
        switch (browserStep.type) {
          case "browser.navigate":
            // Skip post-submission navigates that have session-specific URLs
            // (they'll happen naturally from form submission)
            if (injected && browserStep.url.includes("sid=")) {
              continue;
            }
            await page.goto(browserStep.url, { waitUntil: "domcontentloaded" });
            break;

          case "browser.click":
            // If this click is after injection, wait for potential navigation
            if (injected) {
              await Promise.all([
                page
                  .waitForNavigation({
                    waitUntil: "domcontentloaded",
                    timeout: 5000,
                  })
                  .catch(() => {}),
                page.click(browserStep.selector, { timeout: 5000 }),
              ]);
            } else {
              await page.click(browserStep.selector, { timeout: 5000 });
            }
            break;

          case "browser.input": {
            // Inject payload for target step
            const value =
              step.id === targetStep.id ? payloadValue : browserStep.value;
            await page.fill(browserStep.selector, value, { timeout: 5000 });
            if (step.id === targetStep.id) {
              injected = true;
            }
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
    }

    // Wait for any scripts to execute after all steps complete
    await page.waitForTimeout(500);
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
