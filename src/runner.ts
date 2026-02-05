import type { Page } from "playwright";
import { launchBrowser } from "./browser";
import { BUILTIN_PAYLOADS, type PayloadName } from "./payloads";
import type { Session, Step } from "./session";
import type { Finding, RunResult, RunnerOptions } from "./types";

/**
 * Runner - replays sessions with security payloads
 */
export class Runner {
  /**
   * Execute a session with security payloads
   */
  static async execute(
    session: Session,
    payloadNames: PayloadName[],
    options: RunnerOptions = {},
  ): Promise<RunResult> {
    const browserType = options.browser ?? session.browser ?? "chromium";
    const headless = options.headless ?? true;
    const startTime = Date.now();

    const findings: Finding[] = [];
    const errors: string[] = [];
    let payloadsTested = 0;

    // Launch browser
    const { browser } = await launchBrowser({
      browser: browserType,
      headless,
    });
    const context = await browser.newContext({ viewport: session.viewport });
    const page = await context.newPage();

    try {
      // Find injectable steps
      const injectableSteps = session.steps.filter(
        (step): step is Step & { type: "input" } =>
          step.type === "input" && step.injectable !== false,
      );

      // Get all payloads
      const allPayloads: { name: PayloadName; value: string }[] = [];
      for (const name of payloadNames) {
        const payload = BUILTIN_PAYLOADS[name];
        if (payload) {
          for (const value of payload.payloads) {
            allPayloads.push({ name, value });
          }
        }
      }

      // For each injectable step, test with each payload
      for (const injectableStep of injectableSteps) {
        for (const payload of allPayloads) {
          try {
            // Replay session up to this step with payload injected
            const finding = await Runner.replayWithPayload(
              page,
              session,
              injectableStep,
              payload.name,
              payload.value,
            );

            if (finding) {
              findings.push(finding);
              options.onFinding?.(finding);
            }

            payloadsTested++;
          } catch (err) {
            errors.push(`${injectableStep.id}: ${String(err)}`);
          }
        }
      }
    } finally {
      await browser.close();
    }

    return {
      findings,
      stepsExecuted: session.steps.length,
      payloadsTested,
      duration: Date.now() - startTime,
      errors,
    };
  }

  private static async replayWithPayload(
    page: Page,
    session: Session,
    targetStep: Step & { type: "input" },
    payloadName: PayloadName,
    payloadValue: string,
  ): Promise<Finding | undefined> {
    // Navigate to start
    await page.goto(session.startUrl);

    // Replay steps
    for (const step of session.steps) {
      if (step.type === "navigate") {
        await page.goto(step.url);
      } else if (step.type === "click") {
        await page.click(step.selector, { timeout: 5000 });
      } else if (step.type === "input") {
        // Inject payload for target step
        const value = step.id === targetStep.id ? payloadValue : step.value;
        await page.fill(step.selector, value, { timeout: 5000 });
      } else if (step.type === "keypress") {
        const modifiers = step.modifiers ?? [];
        for (const mod of modifiers) {
          await page.keyboard.down(mod as "Control" | "Shift" | "Alt" | "Meta");
        }
        await page.keyboard.press(step.key);
        for (const mod of modifiers.reverse()) {
          await page.keyboard.up(mod as "Control" | "Shift" | "Alt" | "Meta");
        }
      }

      // If we just filled the target step, check for reflection
      if (step.id === targetStep.id) {
        const finding = await Runner.checkForVulnerability(
          page,
          targetStep,
          payloadName,
          payloadValue,
        );
        if (finding) {
          return finding;
        }
      }
    }

    return undefined;
  }

  private static async checkForVulnerability(
    page: Page,
    step: Step & { type: "input" },
    payloadName: PayloadName,
    payloadValue: string,
  ): Promise<Finding | undefined> {
    const payload = BUILTIN_PAYLOADS[payloadName];
    if (!payload) return undefined;

    // Get page content
    const content = await page.content();

    // Check for reflection patterns
    for (const pattern of payload.detectPatterns) {
      if (pattern.test(content)) {
        return {
          type: payload.category,
          severity: payload.category === "xss" ? "high" : "critical",
          title: `${payload.category.toUpperCase()} vulnerability detected`,
          description: `Payload was reflected in page content`,
          stepId: step.id,
          payload: payloadValue,
          url: page.url(),
          evidence: content.match(pattern)?.[0],
        };
      }
    }

    // Check if payload appears verbatim (potential XSS)
    if (content.includes(payloadValue)) {
      return {
        type: payload.category,
        severity: "medium",
        title: `Potential ${payload.category.toUpperCase()} - payload reflection`,
        description: `Payload was reflected in page without encoding`,
        stepId: step.id,
        payload: payloadValue,
        url: page.url(),
      };
    }

    return undefined;
  }
}
