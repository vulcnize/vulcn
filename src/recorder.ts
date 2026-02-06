/**
 * Recorder - captures browser interactions as a replayable session
 * v0.2.0: Plugin hooks for recording customization
 */

import { Page } from "playwright";
import { createSession, type Session, type Step } from "./session";
import { launchBrowser } from "./browser";
import type { RecorderOptions } from "./types";
import { PluginManager, pluginManager } from "./plugin-manager";
import type { RecordContext } from "./plugin-types";

/**
 * Configuration for the recorder
 */
export interface RecorderConfig {
  /** Plugin manager to use (defaults to shared instance) */
  pluginManager?: PluginManager;
}

/**
 * Active recording session handle
 */
export interface RecordingSession {
  /** Stop recording and return the session */
  stop(): Promise<Session>;
  /** Get current recorded steps */
  getSteps(): Step[];
  /** Get the Playwright page (for advanced use) */
  getPage(): Page;
}

/**
 * Recorder - captures browser interactions as a replayable session
 *
 * Uses plugin hooks for:
 * - onRecordStart: Called when recording starts
 * - onRecordStep: Called for each step, can transform
 * - onRecordEnd: Called when recording ends, can transform session
 */
export class Recorder {
  /**
   * Start a new recording session
   * Opens a browser window for the user to interact with
   */
  static async start(
    startUrl: string,
    options: RecorderOptions = {},
    config: RecorderConfig = {},
  ): Promise<RecordingSession> {
    const manager = config.pluginManager ?? pluginManager;
    const browserType = options.browser ?? "chromium";
    const viewport = options.viewport ?? { width: 1280, height: 720 };
    const headless = options.headless ?? false;

    // Initialize plugins if not already done
    await manager.initialize();

    // Launch browser with smart fallback (system Chrome first)
    const { browser } = await launchBrowser({
      browser: browserType,
      headless,
    });
    const context = await browser.newContext({ viewport });
    const page = await context.newPage();

    // Navigate to start URL
    await page.goto(startUrl);

    // Create session
    const session = createSession({
      name: `Recording ${new Date().toISOString()}`,
      startUrl,
      browser: browserType,
      viewport,
    });

    // Track recording start time
    const startTime = Date.now();
    const steps: Step[] = [];
    let stepCounter = 0;

    const generateStepId = () => {
      stepCounter++;
      return `step_${String(stepCounter).padStart(3, "0")}`;
    };

    // Create base record context
    const baseRecordContext: Omit<RecordContext, "config"> = {
      startUrl,
      browser: browserType,
      page,
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

    // Call onRecordStart hooks
    await manager.callHook("onRecordStart", async (hook, ctx) => {
      const recordCtx: RecordContext = { ...baseRecordContext, ...ctx };
      await hook(recordCtx);
    });

    // Add initial navigation step
    const initialStep: Step = {
      id: generateStepId(),
      type: "navigate",
      url: startUrl,
      timestamp: 0,
    };

    // Transform through plugins
    const transformedInitialStep = await Recorder.transformStep(
      initialStep,
      manager,
      baseRecordContext,
    );
    if (transformedInitialStep) {
      steps.push(transformedInitialStep);
    }

    // Attach event listeners with step transformation
    Recorder.attachListeners(
      page,
      steps,
      startTime,
      generateStepId,
      manager,
      baseRecordContext,
    );

    return {
      async stop() {
        // Call onRecordEnd hooks to transform session
        session.steps = steps;
        let finalSession = session;

        for (const loaded of manager.getPlugins()) {
          const hook = loaded.plugin.hooks?.onRecordEnd;
          if (hook) {
            const ctx = manager.createContext(loaded.config);
            const recordCtx: RecordContext = { ...baseRecordContext, ...ctx };
            finalSession = await hook(finalSession, recordCtx);
          }
        }

        await browser.close();
        return finalSession;
      },
      getSteps() {
        return [...steps];
      },
      getPage() {
        return page;
      },
    };
  }

  /**
   * Transform a step through plugin hooks
   * Returns null if the step should be filtered out
   */
  private static async transformStep(
    step: Step,
    manager: PluginManager,
    baseContext: Omit<RecordContext, "config">,
  ): Promise<Step | null> {
    let transformedStep = step;

    for (const loaded of manager.getPlugins()) {
      const hook = loaded.plugin.hooks?.onRecordStep;
      if (hook) {
        const ctx = manager.createContext(loaded.config);
        const recordCtx: RecordContext = { ...baseContext, ...ctx };
        transformedStep = await hook(transformedStep, recordCtx);
      }
    }

    return transformedStep;
  }

  private static attachListeners(
    page: Page,
    steps: Step[],
    startTime: number,
    generateStepId: () => string,
    manager: PluginManager,
    baseContext: Omit<RecordContext, "config">,
  ) {
    const getTimestamp = () => Date.now() - startTime;

    // Helper to add step with plugin transformation
    const addStep = async (step: Step) => {
      const transformed = await Recorder.transformStep(
        step,
        manager,
        baseContext,
      );
      if (transformed) {
        steps.push(transformed);
      }
    };

    // Track navigation
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) {
        const url = frame.url();
        // Avoid duplicate nav steps for initial load
        const lastStep = steps[steps.length - 1];
        if (
          steps.length > 0 &&
          lastStep.type === "navigate" &&
          lastStep.url === url
        ) {
          return;
        }
        addStep({
          id: generateStepId(),
          type: "navigate",
          url,
          timestamp: getTimestamp(),
        });
      }
    });

    // Expose recording function to browser
    page.exposeFunction(
      "__vulcn_record",
      async (event: { type: string; data: Record<string, unknown> }) => {
        const timestamp = getTimestamp();

        switch (event.type) {
          case "click": {
            const data = event.data as {
              selector: string;
              x: number;
              y: number;
            };
            await addStep({
              id: generateStepId(),
              type: "click",
              selector: data.selector,
              position: { x: data.x, y: data.y },
              timestamp,
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
            await addStep({
              id: generateStepId(),
              type: "input",
              selector: data.selector,
              value: data.value,
              injectable: data.injectable,
              timestamp,
            });
            break;
          }
          case "keypress": {
            const data = event.data as { key: string; modifiers?: string[] };
            await addStep({
              id: generateStepId(),
              type: "keypress",
              key: data.key,
              modifiers: data.modifiers,
              timestamp,
            });
            break;
          }
        }
      },
    );

    // Inject recording script into every frame
    page.on("load", async () => {
      await Recorder.injectRecordingScript(page);
    });

    // Inject into initial page
    Recorder.injectRecordingScript(page);
  }

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
