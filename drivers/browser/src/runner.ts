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
 *
 * v3: URL parameter injection support.
 *   - browser.navigate steps can be marked injectable with a parameter name
 *   - URL parameter payloads are injected by rewriting the query string
 *   - No form fill/click needed — just navigate and check for reflection
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
  DetectContext,
} from "@vulcn/engine";
import type { Response } from "playwright";
import { getSeverity, ErrorSeverity, fatal } from "@vulcn/engine";

import { launchBrowser, type BrowserType } from "./browser";
import { checkReflection } from "./reflection";
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

/**
 * An injectable step can be either:
 *   - browser.input: fills a form field with the payload
 *   - browser.navigate: rewrites a URL query parameter with the payload
 */
type InjectableStep =
  | (Step & { type: "browser.input"; injectable?: boolean })
  | (Step & {
      type: "browser.navigate";
      injectable: true;
      parameter: string;
      url: string;
    });

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
    const startUrl = config.startUrl as string | undefined;
    const headless = ctx.options.headless ?? true;

    const startTime = Date.now();
    const errors: string[] = [];
    let payloadsTested = 0;

    // ── Validate session data ─────────────────────────────────────────
    // If startUrl is missing, every step will fail. Surface immediately.
    if (!startUrl) {
      throw fatal(
        `Session "${session.name}" has no startUrl in driverConfig. ` +
          `The session data is malformed — cannot replay without a start URL.`,
        "driver:browser",
        { context: { session: session.name, driverConfig: config } },
      );
    }

    const payloads = ctx.payloads;
    if (payloads.length === 0) {
      throw fatal(
        "No payloads loaded. Add a payload plugin or configure payloads.",
        "driver:browser",
        { context: { session: session.name } },
      );
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

    let context = await browser.newContext(contextOptions);
    let page = await context.newPage();

    // Signal that the page is ready — plugins (e.g. passive scanner)
    // can now attach event listeners to the real page object
    await ctx.options.onPageReady?.(page);

    // ── Event tracking ───────────────────────────────────────────────
    const eventFindings: Finding[] = [];
    let currentPayloadInfo: CurrentPayloadInfo | null = null;

    const dialogHandler = createDialogHandler(
      ctx,
      page,
      eventFindings,
      () => currentPayloadInfo,
    );
    const consoleHandler = createConsoleHandler(
      ctx,
      eventFindings,
      () => currentPayloadInfo,
    );

    // Wire onNetworkResponse hooks — dispatches to all plugins on each
    // HTTP response so they can inspect status codes, bodies, headers.
    const responseHandler = createNetworkResponseHandler(
      ctx,
      page,
      () => currentPayloadInfo,
    );

    page.on("dialog", dialogHandler);
    page.on("console", consoleHandler);
    page.on("response", responseHandler);

    try {
      // Find ALL injectable steps:
      //   - browser.input with injectable=true (form-based injection)
      //   - browser.navigate with injectable=true (URL parameter injection)
      const injectableSteps = session.steps.filter(
        (step): step is InjectableStep => {
          if (
            step.type === "browser.input" &&
            (step as BrowserStep & { type: "browser.input" }).injectable !==
              false
          ) {
            return true;
          }
          if (
            step.type === "browser.navigate" &&
            (step as any).injectable === true &&
            (step as any).parameter
          ) {
            return true;
          }
          return false;
        },
      );

      // Build interleaved payload list (round-robin across categories)
      const allPayloads = interleavePayloads(payloads);

      // Track confirmed vulnerability types per-step (dedup)
      const confirmedTypes = new Set<string>();

      // ── Per-step payload cycling ───────────────────────────────────
      for (const injectableStep of injectableSteps) {
        if (injectableStep.type === "browser.navigate") {
          // URL parameter injection — navigate directly with payload in URL
          payloadsTested += await cycleUrlPayloads(
            page,
            session,
            injectableStep as Step & {
              type: "browser.navigate";
              injectable: true;
              parameter: string;
              url: string;
            },
            allPayloads,
            confirmedTypes,
            eventFindings,
            ctx,
            errors,
            currentPayloadInfo,
            (info) => {
              currentPayloadInfo = info;
            },
          );
        } else {
          // ── Baseline Submission ──
          // Capture the "normal" response of the form submission (with safe data)
          // so plugins can learn what errors/content are normal.
          const inputStep = injectableStep as BrowserStep & {
            type: "browser.input";
          };
          // We need the original/safe value recorded in the session
          const safeValue = inputStep.value;

          try {
            // Set context so onNetworkResponse knows this is the baseline
            currentPayloadInfo = {
              stepId: injectableStep.id,
              payloadSet: allPayloads[0]?.payloadSet ?? ({} as RuntimePayload),
              payloadValue: "__baseline__",
            };

            // Use replayWithPayload to submit the form with safe data
            await replayWithPayload(
              page,
              session,
              inputStep,
              safeValue,
              startUrl,
            );
          } catch (err) {
            // Non-fatal: just means we might not have a perfect baseline
            ctx.logger.warn(
              `Baseline submission failed for step ${injectableStep.id}: ${err}`,
            );
          } finally {
            currentPayloadInfo = null;
          }

          // Form-based injection — fill input and click submit
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
                  injectableStep as Step & { type: "browser.input" },
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
                  injectableStep as Step & { type: "browser.input" },
                  value,
                  formPageUrl ?? startUrl,
                );
                if (!cycled) {
                  // goBack failed — fall back to full replay
                  await replayWithPayload(
                    page,
                    session,
                    injectableStep as Step & { type: "browser.input" },
                    value,
                    startUrl,
                  );
                }
              }

              // Check for reflection — only for XSS payloads.
              // Reflection-based detection is NOT valid for SQLi:
              // reflecting `' OR 1=1--` in the page doesn't prove a SQL
              // injection vulnerability — it just means the app echoes input.
              let reflectionFinding: Finding | undefined;
              if (payloadSet.category === "xss") {
                const pageContent = await page.content();
                let rawContent: string | undefined;
                try {
                  // Fetch the current page URL to get raw HTML (before DOM parsing)
                  const cookies = await context.cookies();
                  const cookieHeader = cookies
                    .map((c) => `${c.name}=${c.value}`)
                    .join("; ");
                  const res = await fetch(page.url(), {
                    headers: { Cookie: cookieHeader },
                  });
                  if (res.ok) rawContent = await res.text();
                } catch {
                  // Fetch failed — encoding check will be skipped
                }
                reflectionFinding = checkReflection({
                  content: pageContent,
                  payloadSet,
                  payloadValue: value,
                  stepId: injectableStep.id,
                  url: page.url(),
                  rawContent,
                });
              }

              // Dispatch onAfterPayload hooks to all plugins
              const pluginFindings = await dispatchAfterPayload(ctx, page, {
                step: injectableStep,
                payloadSet,
                payloadValue: value,
                stepId: injectableStep.id,
              });

              // Collect all findings from this payload
              const allFindings = [...eventFindings, ...pluginFindings];
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

              // Only skip remaining payloads if we have a high-confidence
              // finding whose type matches the payload category. Low-confidence
              // "reflection" findings should not prevent trying payloads that
              // might trigger actual execution (e.g. alert() → confirmed XSS).
              const hasConfirmedFinding = allFindings.some(
                (f) => f.type === payloadSet.category,
              );
              if (hasConfirmedFinding) {
                confirmedTypes.add(stepTypeKey);
              }

              // Clear event findings for next iteration
              eventFindings.length = 0;
              payloadsTested++;

              // Report progress
              ctx.options.onStepComplete?.(injectableStep.id, payloadsTested);
            } catch (err) {
              const errMsg = err instanceof Error ? err.message : String(err);

              // Check if page/context is dead — no point retrying on a dead page
              if (errMsg.includes("has been closed")) {
                ctx.errors.catch(err, {
                  severity: ErrorSeverity.ERROR,
                  source: "driver:browser",
                  context: {
                    step: injectableStep.id,
                    payload: value.slice(0, 40),
                    session: session.name,
                  },
                });
                errors.push(`${injectableStep.id}: ${String(err)}`);

                // Try to recover by creating a fresh context+page
                try {
                  context = await browser.newContext(contextOptions);
                  page = await context.newPage();
                  page.on("dialog", dialogHandler);
                  page.on("console", consoleHandler);
                  isFirstPayload = true; // Force full navigation on next payload
                  continue;
                } catch {
                  // Browser itself is dead — bail out of entire session
                  errors.push(
                    `${injectableStep.id}: Browser crashed — aborting session`,
                  );
                  break;
                }
              }

              // Surface per-payload errors through the error handler.
              // These are NOT fatal — one payload failing shouldn't kill the session.
              ctx.errors.catch(err, {
                severity: ErrorSeverity.ERROR,
                source: "driver:browser",
                context: {
                  step: injectableStep.id,
                  payload: value.slice(0, 40),
                  session: session.name,
                },
              });
              errors.push(`${injectableStep.id}: ${String(err)}`);
              // If an error occurred, reset so next payload does full navigation
              isFirstPayload = true;
            }
          }
        }
      }
    } finally {
      page.off("dialog", dialogHandler);
      page.off("console", consoleHandler);
      page.off("response", responseHandler);
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

// ── URL Parameter Injection ────────────────────────────────────────────

/**
 * Inject payloads by rewriting a URL query parameter and navigating directly.
 *
 * This is the fast path for GET-based injection points (WAVSEP GET tests,
 * OWASP Benchmark, and any real-world page that reflects a URL parameter).
 *
 * For each payload:
 *   1. Rewrite the URL: replace ?param=value with ?param=PAYLOAD
 *   2. Navigate to the modified URL
 *   3. Check for reflection + dialog events
 *
 * Returns the number of payloads tested.
 */
async function cycleUrlPayloads(
  page: Page,
  _session: Session,
  targetStep: Step & {
    type: "browser.navigate";
    injectable: true;
    parameter: string;
    url: string;
  },
  allPayloads: PayloadItem[],
  confirmedTypes: Set<string>,
  eventFindings: Finding[],
  ctx: RunContext,
  errors: string[],
  _currentPayloadInfo: CurrentPayloadInfo | null,
  setPayloadInfo: (info: CurrentPayloadInfo | null) => void,
): Promise<number> {
  let payloadsTested = 0;

  // ── Baseline capture ──────────────────────────────────────────────
  // Navigate to the clean URL so onNetworkResponse can capture the
  // baseline response (pre-existing SQL errors, etc.) before we
  // start injecting payloads. The response handler only fires when
  // payloadInfo is set, so we set a synthetic "baseline" payload.
  try {
    setPayloadInfo({
      stepId: targetStep.id,
      payloadSet: allPayloads[0]?.payloadSet ?? ({} as RuntimePayload),
      payloadValue: "__baseline__",
    });
    await page.goto(targetStep.url, {
      waitUntil: "domcontentloaded",
      timeout: 10000,
    });
    // Brief pause for onNetworkResponse to process
    await page.waitForTimeout(100);
  } catch {
    // Baseline failed — continue without it
  } finally {
    setPayloadInfo(null);
  }

  for (const { payloadSet, value } of allPayloads) {
    const stepTypeKey = `${targetStep.id}::${payloadSet.category}`;
    if (confirmedTypes.has(stepTypeKey)) continue;

    try {
      setPayloadInfo({
        stepId: targetStep.id,
        payloadSet,
        payloadValue: value,
      });

      // Build the URL with the payload in the query parameter
      const injectedUrl = buildInjectedUrl(
        targetStep.url,
        targetStep.parameter,
        value,
      );

      // Navigate directly — this is all that's needed for GET-based injection
      // Capture the raw HTTP response for encoding-aware reflection detection
      const response = await page.goto(injectedUrl, {
        waitUntil: "domcontentloaded",
        timeout: 10000,
      });

      // Get raw HTTP body (before DOM parsing) for encoding checks
      let rawContent: string | undefined;
      try {
        rawContent = await response?.text();
      } catch {
        // Response body not available (redirected, etc.)
      }

      // Wait for scripts/dialogs - 'domcontentloaded' is usually enough,
      // but we add a small buffer for heavy frameworks if needed.
      try {
        await page.waitForLoadState("domcontentloaded", { timeout: 1000 });
      } catch {
        // Ignore timeout
      }

      // Check reflection — only for XSS payloads.
      // SQL payload reflection does NOT indicate SQL injection.
      let reflectionFinding: Finding | undefined;
      if (payloadSet.category === "xss") {
        const pageContent = await page.content();
        reflectionFinding = checkReflection({
          content: pageContent,
          payloadSet,
          payloadValue: value,
          stepId: targetStep.id,
          url: page.url(),
          rawContent,
        });
      }

      // Dispatch onAfterPayload hooks to all plugins
      const pluginFindings = await dispatchAfterPayload(ctx, page, {
        step: targetStep,
        payloadSet,
        payloadValue: value,
        stepId: targetStep.id,
      });

      // Collect findings
      const allFindings = [...eventFindings, ...pluginFindings];
      if (reflectionFinding) {
        allFindings.push(reflectionFinding);
      }

      // Deduplicate and add
      const seenKeys = new Set<string>();
      for (const finding of allFindings) {
        const dedupKey = `${finding.type}::${finding.stepId}::${finding.title}`;
        if (!seenKeys.has(dedupKey)) {
          seenKeys.add(dedupKey);
          ctx.addFinding(finding);
        }
      }

      // Only skip remaining payloads on high-confidence (category-matching) findings
      const hasConfirmedFinding = allFindings.some(
        (f) => f.type === payloadSet.category,
      );
      if (hasConfirmedFinding) {
        confirmedTypes.add(stepTypeKey);
      }

      eventFindings.length = 0;
      payloadsTested++;

      ctx.options.onStepComplete?.(targetStep.id, payloadsTested);
    } catch (err) {
      ctx.errors.catch(err, {
        severity: ErrorSeverity.ERROR,
        source: "driver:browser",
        context: {
          step: targetStep.id,
          payload: value.slice(0, 40),
        },
      });
      errors.push(`${targetStep.id}: ${String(err)}`);
    }
  }

  setPayloadInfo(null);
  return payloadsTested;
}

/**
 * Build a URL with a payload injected into a specific query parameter.
 *
 * Example:
 *   buildInjectedUrl(
 *     "http://host/page.jsp?userinput=test&other=1",
 *     "userinput",
 *     "<script>alert(1)</script>"
 *   )
 *   → "http://host/page.jsp?userinput=%3Cscript%3Ealert(1)%3C%2Fscript%3E&other=1"
 *
 * If the parameter doesn't exist in the URL, it's appended.
 */
function buildInjectedUrl(
  originalUrl: string,
  parameter: string,
  payload: string,
): string {
  const url = new URL(originalUrl);
  url.searchParams.set(parameter, payload);
  return url.toString();
}

// ── Dialog / Console Handlers ──────────────────────────────────────────

function createDialogHandler(
  ctx: RunContext,
  page: Page,
  eventFindings: Finding[],
  getPayloadInfo: () => CurrentPayloadInfo | null,
) {
  return async (dialog: Dialog) => {
    const info = getPayloadInfo();
    const pm = ctx.pluginManager;

    // Dispatch to plugins
    for (const loaded of pm.getPlugins()) {
      if (loaded.enabled && loaded.plugin.hooks?.onDialog) {
        try {
          const baseCtx = pm.createContext(loaded.config, loaded.plugin.name);
          // Look up step safely
          const currentStep = info?.stepId
            ? ctx.session.steps.find((s) => s.id === info.stepId)
            : undefined;

          const detectCtx: DetectContext = {
            ...baseCtx,
            session: ctx.session, // Required by DetectContext
            page,
            headless: ctx.options.headless ?? true,
            stepId: info?.stepId ?? "unknown",
            payloadValue: info?.payloadValue ?? "",
            step:
              currentStep ??
              ({
                id: "unknown",
                type: "browser.wait",
                duration: 0,
                timestamp: Date.now(),
              } as unknown as Step),
            payloadSet: info?.payloadSet ?? ({} as unknown as RuntimePayload),
            // Override addFinding to capture locally + globally
            addFinding: (finding: Finding) => {
              eventFindings.push(finding);
              pm.addFinding(finding);
            },
            // Override logger to use specific name
            logger: baseCtx.logger,
          };

          const finding = await loaded.plugin.hooks.onDialog(dialog, detectCtx);
          if (finding) {
            eventFindings.push(finding);
          }
        } catch (err) {
          pm.getErrorHandler().catch(err, {
            severity: ErrorSeverity.WARN,
            source: `plugin:${loaded.plugin.name}`,
            context: { hook: "onDialog" },
          });
        }
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
  ctx: RunContext,
  eventFindings: Finding[],
  getPayloadInfo: () => CurrentPayloadInfo | null,
) {
  return async (msg: ConsoleMessage) => {
    const info = getPayloadInfo();
    const pm = ctx.pluginManager;

    // Dispatch to plugins
    for (const loaded of pm.getPlugins()) {
      if (loaded.enabled && loaded.plugin.hooks?.onConsoleMessage) {
        try {
          const baseCtx = pm.createContext(loaded.config, loaded.plugin.name);
          // Look up step safely
          const currentStep = info?.stepId
            ? ctx.session.steps.find((s) => s.id === info.stepId)
            : undefined;

          const detectCtx: DetectContext = {
            ...baseCtx,
            session: ctx.session, // Required by DetectContext
            page: msg.page(),
            headless: ctx.options.headless ?? true,
            stepId: info?.stepId ?? "unknown",
            payloadValue: info?.payloadValue ?? "",
            step:
              currentStep ??
              ({
                id: "unknown",
                type: "browser.wait",
                duration: 0,
                timestamp: Date.now(),
              } as unknown as Step),
            payloadSet: info?.payloadSet ?? ({} as unknown as RuntimePayload),
            addFinding: (finding: Finding) => {
              eventFindings.push(finding);
              pm.addFinding(finding);
            },
            logger: baseCtx.logger,
          };

          const finding = await loaded.plugin.hooks.onConsoleMessage(
            msg,
            detectCtx,
          );
          if (finding) {
            eventFindings.push(finding);
          }
        } catch (err) {
          pm.getErrorHandler().catch(err, {
            severity: ErrorSeverity.WARN,
            source: `plugin:${loaded.plugin.name}`,
            context: { hook: "onConsoleMessage" },
          });
        }
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
    } catch (err) {
      // Step-level failures during replay — WARN, not fatal.
      // A CSS selector may not exist, a page may not respond, etc.
      // But we still log it so it's visible.
      console.warn(
        `[driver:browser] Step replay failed: ${err instanceof Error ? err.message : String(err)}`,
      );
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

// ── Plugin Hook Dispatchers ────────────────────────────────────────────

/**
 * Dispatch onAfterPayload hooks to all loaded plugins and collect findings.
 *
 * This is the bridge between the browser runner (which handles navigation
 * and payload injection) and detection plugins (which analyze page state
 * for vulnerabilities).
 */
async function dispatchAfterPayload(
  ctx: RunContext,
  page: Page,
  payload: {
    step: Step;
    payloadSet: RuntimePayload;
    payloadValue: string;
    stepId: string;
  },
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const pm = ctx.pluginManager;

  for (const loaded of pm.getPlugins()) {
    if (!loaded.enabled || !loaded.plugin.hooks?.onAfterPayload) continue;

    try {
      const detectCtx: DetectContext = {
        session: ctx.session,
        page,
        headless: !!(ctx.options as Record<string, unknown>).headless,
        config: loaded.config,
        engine: { version: "0.9.2", pluginApiVersion: 1 },
        payloads: ctx.payloads,
        findings: ctx.findings,
        addFinding: ctx.addFinding,
        logger: {
          debug: (msg: string, ...args: unknown[]) =>
            console.debug(`[${loaded.plugin.name}]`, msg, ...args),
          info: (msg: string, ...args: unknown[]) =>
            console.info(`[${loaded.plugin.name}]`, msg, ...args),
          warn: (msg: string, ...args: unknown[]) =>
            console.warn(`[${loaded.plugin.name}]`, msg, ...args),
          error: (msg: string, ...args: unknown[]) =>
            console.error(`[${loaded.plugin.name}]`, msg, ...args),
        },
        errors: pm.getErrorHandler(),
        fetch: globalThis.fetch,
        step: payload.step,
        payloadSet: payload.payloadSet,
        payloadValue: payload.payloadValue,
        stepId: payload.stepId,
      };

      const result = await loaded.plugin.hooks.onAfterPayload(detectCtx);
      if (result && result.length > 0) {
        findings.push(...result);
      }
    } catch (err) {
      pm.getErrorHandler().catch(err, {
        severity: ErrorSeverity.WARN,
        source: `plugin:${loaded.plugin.name}`,
        context: { hook: "onAfterPayload" },
      });
    }
  }

  return findings;
}

/**
 * Create a response handler that dispatches onNetworkResponse to all plugins.
 *
 * Returns a function suitable for page.on('response', handler).
 * The handler fires asynchronously — findings are added directly via ctx.addFinding.
 */
function createNetworkResponseHandler(
  ctx: RunContext,
  _page: Page,
  getPayloadInfo: () => CurrentPayloadInfo | null,
): (response: Response) => void {
  return (response: Response) => {
    const payloadInfo = getPayloadInfo();
    if (!payloadInfo) return; // No payload active — skip (e.g. baseline page load)

    // Fire-and-forget — response handlers run async alongside the main loop
    void (async () => {
      const pm = ctx.pluginManager;
      for (const loaded of pm.getPlugins()) {
        if (!loaded.enabled || !loaded.plugin.hooks?.onNetworkResponse)
          continue;

        try {
          const detectCtx: DetectContext = {
            session: ctx.session,
            page: _page,
            headless: !!(ctx.options as Record<string, unknown>).headless,
            config: loaded.config,
            engine: { version: "0.9.2", pluginApiVersion: 1 },
            payloads: ctx.payloads,
            findings: ctx.findings,
            addFinding: ctx.addFinding,
            logger: {
              debug: (msg: string, ...args: unknown[]) =>
                console.debug(`[${loaded.plugin.name}]`, msg, ...args),
              info: (msg: string, ...args: unknown[]) =>
                console.info(`[${loaded.plugin.name}]`, msg, ...args),
              warn: (msg: string, ...args: unknown[]) =>
                console.warn(`[${loaded.plugin.name}]`, msg, ...args),
              error: (msg: string, ...args: unknown[]) =>
                console.error(`[${loaded.plugin.name}]`, msg, ...args),
            },
            errors: pm.getErrorHandler(),
            fetch: globalThis.fetch,
            step: {
              id: payloadInfo.stepId,
              type: "browser.navigate",
              timestamp: Date.now(),
            },
            payloadSet: payloadInfo.payloadSet,
            payloadValue: payloadInfo.payloadValue,
            stepId: payloadInfo.stepId,
          };

          const finding = await loaded.plugin.hooks.onNetworkResponse(
            response,
            detectCtx,
          );
          if (finding) {
            ctx.addFinding(finding);
          }
        } catch (err) {
          pm.getErrorHandler().catch(err, {
            severity: ErrorSeverity.WARN,
            source: `plugin:${loaded.plugin.name}`,
            context: { hook: "onNetworkResponse" },
          });
        }
      }
    })();
  };
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
