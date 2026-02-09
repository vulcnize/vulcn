/**
 * Browser Runner Implementation
 *
 * Replays browser sessions with security payloads.
 * Uses plugin hooks for detection.
 *
 * v2: Persistent browser with in-page payload cycling.
 *   - ONE browser for the entire scan (not per-session)
 *   - Uses page.goBack() between payloads instead of full page.goto()
 *   - Falls back to full navigation when goBack() fails
 *   - 5-10x faster on SPAs, same speed on simple sites
 */

import type {
  Browser,
  BrowserContext,
  Page,
  Dialog,
  ConsoleMessage,
} from "playwright";
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

// ── Types ──────────────────────────────────────────────────────────────

interface PayloadItem {
  payloadSet: RuntimePayload;
  value: string;
}

interface CurrentPayloadInfo {
  stepId: string;
  payloadSet: RuntimePayload;
  payloadValue: string;
}

// ── Browser Runner ─────────────────────────────────────────────────────

/**
 * Browser Runner - replays sessions with payloads
 *
 * Supports two modes:
 * 1. Self-managed browser: launches its own browser (backward compat)
 * 2. Shared browser: receives a browser instance via RunOptions
 *
 * In both modes, payload cycling uses goBack() for speed.
 */
export class BrowserRunner {
  /**
   * Execute a session with security payloads.
   *
   * If ctx.options.browser is provided, reuses that browser (persistent mode).
   * Otherwise, launches and closes its own browser (standalone mode).
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

    // ── Browser lifecycle ────────────────────────────────────────────
    // Use shared browser from options if available (persistent mode),
    // otherwise launch our own (standalone / backward compat).
    const sharedBrowser = ctx.options.browser as Browser | undefined;
    const ownBrowser = sharedBrowser
      ? null
      : (await launchBrowser({ browser: browserType, headless })).browser;
    const browser = sharedBrowser ?? ownBrowser!;

    // Inject storageState from options if available (for auth)
    const storageState = ctx.options.storageState as string | undefined;
    const contextOptions: Record<string, unknown> = { viewport };
    if (storageState) {
      contextOptions.storageState = JSON.parse(storageState);
    }

    const context = await browser.newContext(contextOptions);
    const page = await context.newPage();

    // Signal that the page is ready — plugins (e.g. passive scanner)
    // can now attach event listeners to the real page object
    await ctx.options.onPageReady?.(page);

    // ── Event tracking ───────────────────────────────────────────────
    const eventFindings: Finding[] = [];
    let currentPayloadInfo: CurrentPayloadInfo | null = null;

    const dialogHandler = createDialogHandler(
      page,
      eventFindings,
      () => currentPayloadInfo,
    );
    const consoleHandler = createConsoleHandler(
      eventFindings,
      () => currentPayloadInfo,
    );

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

      // Build interleaved payload list (round-robin across categories)
      const allPayloads = interleavePayloads(payloads);

      // Track confirmed vulnerability types per-step (dedup)
      const confirmedTypes = new Set<string>();

      // ── Per-step payload cycling ───────────────────────────────────
      for (const injectableStep of injectableSteps) {
        let isFirstPayload = true;
        // Track the URL we navigate back to for goBack fallback
        let formPageUrl: string | null = null;

        for (const { payloadSet, value } of allPayloads) {
          // Skip if this vuln type is already confirmed for this step
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

            if (isFirstPayload) {
              // First payload: full navigation + replay all steps
              await replayWithPayload(
                page,
                session,
                injectableStep,
                value,
                startUrl,
              );
              isFirstPayload = false;
              // Capture the form page URL for fallback navigation
              formPageUrl = startUrl;
            } else {
              // Subsequent payloads: try goBack() first (fast path)
              const cycled = await cyclePayload(
                page,
                session,
                injectableStep,
                value,
                formPageUrl ?? startUrl,
              );
              if (!cycled) {
                // goBack failed — fall back to full replay
                await replayWithPayload(
                  page,
                  session,
                  injectableStep,
                  value,
                  startUrl,
                );
              }
            }

            // Check for reflection
            const reflectionFinding = await checkReflection(
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

            // If we got any finding, mark as confirmed and skip remaining
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
            // If an error occurred, reset so next payload does full navigation
            isFirstPayload = true;
          }
        }
      }
    } finally {
      page.off("dialog", dialogHandler);
      page.off("console", consoleHandler);
      currentPayloadInfo = null;

      // Let plugins flush pending async work before browser closes
      await ctx.options.onBeforeClose?.(page);

      // Close context (lightweight — doesn't close the browser)
      await context.close();

      // Only close browser if we launched it ourselves
      if (ownBrowser) {
        await ownBrowser.close();
      }
    }

    return {
      findings: ctx.findings,
      stepsExecuted: session.steps.length,
      payloadsTested,
      duration: Date.now() - startTime,
      errors,
    };
  }
}

// ── Dialog / Console Handlers ──────────────────────────────────────────

function createDialogHandler(
  page: Page,
  eventFindings: Finding[],
  getPayloadInfo: () => CurrentPayloadInfo | null,
) {
  return async (dialog: Dialog) => {
    const info = getPayloadInfo();
    if (info) {
      const message = dialog.message();
      const dialogType = dialog.type();

      // Skip beforeunload dialogs (not XSS-related)
      if (dialogType !== "beforeunload") {
        eventFindings.push({
          type: "xss",
          severity: "high",
          title: `XSS Confirmed - ${dialogType}() triggered`,
          description: `JavaScript ${dialogType}() dialog was triggered by payload injection. Message: "${message}"`,
          stepId: info.stepId,
          payload: info.payloadValue,
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
}

function createConsoleHandler(
  eventFindings: Finding[],
  getPayloadInfo: () => CurrentPayloadInfo | null,
) {
  return async (msg: ConsoleMessage) => {
    const info = getPayloadInfo();
    if (info && msg.type() === "log") {
      const text = msg.text();
      if (text.includes("vulcn") || text.includes(info.payloadValue)) {
        eventFindings.push({
          type: "xss",
          severity: "high",
          title: "XSS Confirmed - Console Output",
          description: `JavaScript console.log was triggered by payload injection`,
          stepId: info.stepId,
          payload: info.payloadValue,
          url: "",
          evidence: `Console output: ${text}`,
          metadata: {
            consoleType: msg.type(),
            detectionMethod: "console",
          },
        });
      }
    }
  };
}

// ── Payload Cycling ────────────────────────────────────────────────────

/**
 * Fast-path payload cycling using goBack().
 *
 * After a form submission causes navigation, goBack() returns to the form
 * page much faster than a full page.goto() — especially for SPAs where
 * the client-side router handles the back navigation without a full reload.
 *
 * Falls back to full navigation if goBack doesn't land on a page with
 * the expected form.
 *
 * Returns true if cycling succeeded, false if caller should fall back
 * to full replay.
 */
async function cyclePayload(
  page: Page,
  session: Session,
  targetStep: Step & { type: "browser.input" },
  payloadValue: string,
  formPageUrl: string,
): Promise<boolean> {
  try {
    // Try goBack first — fast on SPAs, cheap on static sites
    await page.goBack({ waitUntil: "domcontentloaded", timeout: 5000 });

    // Verify the form element is still present
    const targetSelector = (
      targetStep as BrowserStep & { type: "browser.input" }
    ).selector;
    const formPresent = await page
      .waitForSelector(targetSelector, { timeout: 3000 })
      .then(() => true)
      .catch(() => false);

    if (!formPresent) {
      // goBack didn't land on the form page — try direct navigation
      await page.goto(formPageUrl, {
        waitUntil: "domcontentloaded",
        timeout: 5000,
      });

      // Wait for the form element after navigation
      const formPresentAfterNav = await page
        .waitForSelector(targetSelector, { timeout: 3000 })
        .then(() => true)
        .catch(() => false);

      if (!formPresentAfterNav) {
        // Even direct nav failed — fall back to full replay
        return false;
      }
    }

    // Fill the injectable step with the new payload
    await page.fill(targetSelector, payloadValue, { timeout: 5000 });

    // Execute remaining steps after the injectable step (click submit, etc.)
    await replayStepsAfter(page, session, targetStep);

    // Wait for scripts to execute
    await page.waitForTimeout(500);

    return true;
  } catch {
    return false;
  }
}

// ── Full Replay ────────────────────────────────────────────────────────

/**
 * Replay session steps with payload injected at target step.
 *
 * IMPORTANT: We replay ALL steps, not just up to the injectable step.
 * The injection replaces the input value, but subsequent steps (like
 * clicking submit) must still execute so the payload reaches the server
 * and gets reflected back in the response.
 */
async function replayWithPayload(
  page: Page,
  session: Session,
  targetStep: Step & { type: "browser.input" },
  payloadValue: string,
  startUrl: string,
): Promise<void> {
  // Navigate to start
  await page.goto(startUrl, { waitUntil: "domcontentloaded" });

  let injected = false;

  for (const step of session.steps) {
    const browserStep = step as BrowserStep;

    try {
      switch (browserStep.type) {
        case "browser.navigate":
          if (injected && browserStep.url.includes("sid=")) {
            continue;
          }
          await page.goto(browserStep.url, { waitUntil: "domcontentloaded" });
          break;

        case "browser.click":
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
            await page.keyboard.up(mod as "Control" | "Shift" | "Alt" | "Meta");
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
 * Replay only the steps AFTER the injectable step.
 *
 * Used by cyclePayload() — the injectable step has already been filled,
 * so we just need to execute the remaining steps (click submit, etc.)
 */
async function replayStepsAfter(
  page: Page,
  session: Session,
  targetStep: Step & { type: "browser.input" },
): Promise<void> {
  let pastTarget = false;

  for (const step of session.steps) {
    if (step.id === targetStep.id) {
      pastTarget = true;
      continue; // skip the injectable step itself (already filled)
    }

    if (!pastTarget) continue;

    const browserStep = step as BrowserStep;

    try {
      switch (browserStep.type) {
        case "browser.navigate":
          // Skip post-submission navigates
          break;

        case "browser.click":
          await Promise.all([
            page
              .waitForNavigation({
                waitUntil: "domcontentloaded",
                timeout: 5000,
              })
              .catch(() => {}),
            page.click(browserStep.selector, { timeout: 5000 }),
          ]);
          break;

        case "browser.input":
          await page.fill(browserStep.selector, browserStep.value, {
            timeout: 5000,
          });
          break;

        case "browser.keypress": {
          const modifiers = browserStep.modifiers ?? [];
          for (const mod of modifiers) {
            await page.keyboard.down(
              mod as "Control" | "Shift" | "Alt" | "Meta",
            );
          }
          await page.keyboard.press(browserStep.key);
          for (const mod of modifiers.reverse()) {
            await page.keyboard.up(mod as "Control" | "Shift" | "Alt" | "Meta");
          }
          break;
        }

        case "browser.scroll":
          break; // skip scrolls in fast path

        case "browser.wait":
          break; // skip waits in fast path
      }
    } catch {
      // Step failed, continue
    }
  }

  // Wait for scripts to execute
  await page.waitForTimeout(500);
}

// ── Detection Helpers ──────────────────────────────────────────────────

/**
 * Check for payload reflection in page content
 */
async function checkReflection(
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
        severity: getSeverity(payloadSet.category),
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
function getSeverity(
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

// ── Payload Interleaving ───────────────────────────────────────────────

/**
 * Build flat list of payloads, interleaved by category (round-robin).
 *
 * This ensures we test at least one payload from each category quickly,
 * so the dedup early-break fires sooner on slow SPAs.
 *
 * Before: [sqli1, sqli2, ..., sqli50, xss1, xss2, ..., xss50]
 * After:  [sqli1, xss1, sqli2, xss2, ..., sqli50, xss50]
 */
function interleavePayloads(payloads: RuntimePayload[]): PayloadItem[] {
  const result: PayloadItem[] = [];
  const payloadsByCategory = payloads.map((ps) =>
    ps.payloads.map((value) => ({ payloadSet: ps, value })),
  );
  const maxLen = Math.max(...payloadsByCategory.map((c) => c.length));
  for (let i = 0; i < maxLen; i++) {
    for (const category of payloadsByCategory) {
      if (i < category.length) {
        result.push(category[i]);
      }
    }
  }
  return result;
}
