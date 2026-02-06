/**
 * Browser Recorder Implementation
 *
 * Records browser interactions as replayable sessions.
 * Uses Playwright for browser automation.
 */

import type { Page } from "playwright";
import type {
  RecordingHandle,
  RecordOptions,
  Session,
  Step,
} from "@vulcn/engine";

import { launchBrowser } from "./browser";
import type { BrowserConfig, BrowserStep } from "./index";

/**
 * Browser Recorder - captures browser interactions
 */
export class BrowserRecorder {
  /**
   * Start a new recording session
   */
  static async start(
    config: BrowserConfig,
    _options: RecordOptions = {},
  ): Promise<RecordingHandle> {
    const { startUrl, browser: browserType, viewport, headless } = config;

    if (!startUrl) {
      throw new Error("startUrl is required for browser recording");
    }

    // Launch browser with smart fallback
    const { browser } = await launchBrowser({
      browser: browserType,
      headless,
    });

    const context = await browser.newContext({ viewport });
    const page = await context.newPage();

    // Navigate to start URL
    await page.goto(startUrl);

    // Track recording
    const startTime = Date.now();
    const steps: Step[] = [];
    let stepCounter = 0;

    const generateStepId = () => {
      stepCounter++;
      return `step_${String(stepCounter).padStart(3, "0")}`;
    };

    // Add initial navigation step
    steps.push({
      id: generateStepId(),
      type: "browser.navigate",
      url: startUrl,
      timestamp: 0,
    });

    // Attach event listeners
    BrowserRecorder.attachListeners(page, steps, startTime, generateStepId);

    return {
      async stop(): Promise<Session> {
        const session: Session = {
          name: `Recording ${new Date().toISOString()}`,
          driver: "browser",
          driverConfig: {
            browser: browserType,
            viewport,
            startUrl,
          },
          steps,
          metadata: {
            recordedAt: new Date().toISOString(),
            version: "1",
          },
        };

        await browser.close();
        return session;
      },

      async abort(): Promise<void> {
        await browser.close();
      },

      getSteps(): Step[] {
        return [...steps];
      },

      addStep(step: Omit<Step, "id" | "timestamp">): void {
        steps.push({
          ...step,
          id: generateStepId(),
          timestamp: Date.now() - startTime,
        } as Step);
      },
    };
  }

  /**
   * Attach event listeners to the page
   */
  private static attachListeners(
    page: Page,
    steps: Step[],
    startTime: number,
    generateStepId: () => string,
  ) {
    const getTimestamp = () => Date.now() - startTime;

    const addStep = (
      step: Omit<Step, "id" | "timestamp"> & { type: string },
    ) => {
      steps.push({
        ...step,
        id: generateStepId(),
        timestamp: getTimestamp(),
      } as Step);
    };

    // Track navigation
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) {
        const url = frame.url();
        // Avoid duplicate nav steps for initial load
        const lastStep = steps[steps.length - 1];
        if (
          steps.length > 0 &&
          lastStep?.type === "browser.navigate" &&
          (lastStep as BrowserStep & { type: "browser.navigate" }).url === url
        ) {
          return;
        }
        addStep({
          type: "browser.navigate",
          url,
        });
      }
    });

    // Expose recording function to browser
    page.exposeFunction(
      "__vulcn_record",
      async (event: { type: string; data: Record<string, unknown> }) => {
        switch (event.type) {
          case "click": {
            const data = event.data as {
              selector: string;
              x: number;
              y: number;
            };
            addStep({
              type: "browser.click",
              selector: data.selector,
              position: { x: data.x, y: data.y },
            });
            break;
          }
          case "input": {
            const data = event.data as {
              selector: string;
              value: string;
              inputType: string | null;
              injectable: boolean;
            };
            addStep({
              type: "browser.input",
              selector: data.selector,
              value: data.value,
              injectable: data.injectable,
            });
            break;
          }
          case "keypress": {
            const data = event.data as { key: string; modifiers?: string[] };
            addStep({
              type: "browser.keypress",
              key: data.key,
              modifiers: data.modifiers,
            });
            break;
          }
        }
      },
    );

    // Inject recording script into every frame
    page.on("load", async () => {
      await BrowserRecorder.injectRecordingScript(page);
    });

    // Inject into initial page
    BrowserRecorder.injectRecordingScript(page);
  }

  /**
   * Inject the recording script into the page
   */
  private static async injectRecordingScript(page: Page) {
    await page.evaluate(`
      (function() {
        if (window.__vulcn_injected) return;
        window.__vulcn_injected = true;

        var textInputTypes = ['text', 'password', 'email', 'search', 'url', 'tel', 'number'];

        function getSelector(el) {
          if (el.id) {
            return '#' + CSS.escape(el.id);
          }
          if (el.name) {
            var tag = el.tagName.toLowerCase();
            var nameSelector = tag + '[name="' + el.name + '"]';
            if (document.querySelectorAll(nameSelector).length === 1) {
              return nameSelector;
            }
          }
          if (el.dataset && el.dataset.testid) {
            return '[data-testid="' + el.dataset.testid + '"]';
          }
          if (el.tagName === 'INPUT' && el.type && el.name) {
            var inputSelector = 'input[type="' + el.type + '"][name="' + el.name + '"]';
            if (document.querySelectorAll(inputSelector).length === 1) {
              return inputSelector;
            }
          }
          if (el.className && typeof el.className === 'string') {
            var classes = el.className.trim().split(/\\s+/).filter(function(c) { return c.length > 0; });
            if (classes.length > 0) {
              var classSelector = el.tagName.toLowerCase() + '.' + classes.map(function(c) { return CSS.escape(c); }).join('.');
              if (document.querySelectorAll(classSelector).length === 1) {
                return classSelector;
              }
            }
          }
          var path = [];
          var current = el;
          while (current && current !== document.body) {
            var tag = current.tagName.toLowerCase();
            var parent = current.parentElement;
            if (parent) {
              var siblings = Array.from(parent.children).filter(function(c) { return c.tagName === current.tagName; });
              if (siblings.length > 1) {
                var index = siblings.indexOf(current) + 1;
                tag = tag + ':nth-of-type(' + index + ')';
              }
            }
            path.unshift(tag);
            current = parent;
          }
          return path.join(' > ');
        }

        function getInputType(el) {
          if (el.tagName === 'INPUT') return el.type || 'text';
          if (el.tagName === 'TEXTAREA') return 'textarea';
          if (el.tagName === 'SELECT') return 'select';
          return null;
        }

        function isTextInjectable(el) {
          var inputType = getInputType(el);
          if (!inputType) return false;
          if (inputType === 'textarea') return true;
          if (inputType === 'select') return false;
          return textInputTypes.indexOf(inputType) !== -1;
        }

        document.addEventListener('click', function(e) {
          var target = e.target;
          window.__vulcn_record({
            type: 'click',
            data: {
              selector: getSelector(target),
              x: e.clientX,
              y: e.clientY
            }
          });
        }, true);

        document.addEventListener('change', function(e) {
          var target = e.target;
          if ('value' in target) {
            var inputType = getInputType(target);
            window.__vulcn_record({
              type: 'input',
              data: {
                selector: getSelector(target),
                value: target.value,
                inputType: inputType,
                injectable: isTextInjectable(target)
              }
            });
          }
        }, true);

        document.addEventListener('keydown', function(e) {
          if (e.ctrlKey || e.metaKey || e.altKey) {
            var modifiers = [];
            if (e.ctrlKey) modifiers.push('ctrl');
            if (e.metaKey) modifiers.push('meta');
            if (e.altKey) modifiers.push('alt');
            if (e.shiftKey) modifiers.push('shift');

            window.__vulcn_record({
              type: 'keypress',
              data: {
                key: e.key,
                modifiers: modifiers
              }
            });
          }
        }, true);
      })();
    `);
  }
}
