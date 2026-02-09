/**
 * Session Format v2 Tests
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadSessionDir,
  saveSessionDir,
  isSessionDir,
  looksLikeSessionDir,
  readAuthState,
  readCapturedRequests,
} from "./session";
import type { Session } from "./driver-types";
import type { AuthConfig } from "./auth";

describe("Session Format v2", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "vulcn-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("saveSessionDir + loadSessionDir round-trip", () => {
    it("should save and load a basic session directory", async () => {
      const sessions: Session[] = [
        {
          name: "XSS Reflected",
          driver: "browser",
          driverConfig: { startUrl: "https://target.com/xss" },
          steps: [
            {
              id: "step-1",
              type: "browser.navigate",
              url: "https://target.com/xss",
              timestamp: 0,
            },
            {
              id: "step-2",
              type: "browser.input",
              selector: "input[name='q']",
              value: "test",
              injectable: true,
              timestamp: 100,
            },
            {
              id: "step-3",
              type: "browser.click",
              selector: "button[type='submit']",
              timestamp: 200,
            },
          ],
        },
      ];

      const dirPath = join(tempDir, "test.vulcn");

      await saveSessionDir(dirPath, {
        name: "Test Scan",
        target: "https://target.com",
        driver: "browser",
        driverConfig: {
          browser: "chromium",
          viewport: { width: 1280, height: 720 },
        },
        sessions,
      });

      // Verify files exist
      expect(existsSync(join(dirPath, "manifest.yml"))).toBe(true);
      expect(existsSync(join(dirPath, "sessions"))).toBe(true);

      // Load it back
      const loaded = await loadSessionDir(dirPath);

      expect(loaded.manifest.version).toBe("2");
      expect(loaded.manifest.name).toBe("Test Scan");
      expect(loaded.manifest.target).toBe("https://target.com");
      expect(loaded.manifest.driver).toBe("browser");
      expect(loaded.sessions.length).toBe(1);
      expect(loaded.sessions[0].name).toBe("XSS Reflected");
      expect(loaded.sessions[0].steps.length).toBe(3);
    });

    it("should save multiple sessions", async () => {
      const sessions: Session[] = [
        {
          name: "Form A",
          driver: "browser",
          driverConfig: { startUrl: "https://target.com/a" },
          steps: [
            {
              id: "s1",
              type: "browser.input",
              selector: "#a",
              value: "x",
              injectable: true,
              timestamp: 0,
            },
          ],
        },
        {
          name: "Form B",
          driver: "browser",
          driverConfig: { startUrl: "https://target.com/b" },
          steps: [
            {
              id: "s2",
              type: "browser.input",
              selector: "#b",
              value: "y",
              injectable: true,
              timestamp: 0,
            },
          ],
        },
      ];

      const dirPath = join(tempDir, "multi.vulcn");
      await saveSessionDir(dirPath, {
        name: "Multi Scan",
        target: "https://target.com",
        driver: "browser",
        driverConfig: { browser: "chromium" },
        sessions,
      });

      const loaded = await loadSessionDir(dirPath);
      expect(loaded.sessions.length).toBe(2);
    });

    it("should handle auth config", async () => {
      const authConfig: AuthConfig = {
        strategy: "storage-state",
        loginUrl: "https://target.com/login",
        loggedInIndicator: "Logout",
        loggedOutIndicator: "Sign In",
        sessionExpiry: {
          statusCodes: [401, 403],
          redirectPattern: "/login",
        },
      };

      const dirPath = join(tempDir, "auth.vulcn");
      await saveSessionDir(dirPath, {
        name: "Auth Scan",
        target: "https://target.com",
        driver: "browser",
        driverConfig: { browser: "chromium" },
        sessions: [
          {
            name: "Form",
            driver: "browser",
            driverConfig: { startUrl: "https://target.com/form" },
            steps: [
              {
                id: "s1",
                type: "browser.input",
                selector: "#x",
                value: "v",
                injectable: true,
                timestamp: 0,
              },
            ],
          },
        ],
        authConfig,
      });

      // Verify auth config file exists
      expect(existsSync(join(dirPath, "auth", "config.yml"))).toBe(true);

      const loaded = await loadSessionDir(dirPath);
      expect(loaded.authConfig).toBeDefined();
      expect(loaded.authConfig?.strategy).toBe("storage-state");
      expect(loaded.authConfig?.loggedInIndicator).toBe("Logout");
      expect(loaded.manifest.auth?.strategy).toBe("storage-state");
    });

    it("should handle encrypted auth state", async () => {
      const dirPath = join(tempDir, "state.vulcn");
      await saveSessionDir(dirPath, {
        name: "State Scan",
        target: "https://target.com",
        driver: "browser",
        driverConfig: {},
        sessions: [
          {
            name: "test",
            driver: "browser",
            driverConfig: { startUrl: "https://target.com" },
            steps: [],
          },
        ],
        encryptedState: '{"encrypted":"data"}',
      });

      expect(existsSync(join(dirPath, "auth", "state.enc"))).toBe(true);

      const state = await readAuthState(dirPath);
      expect(state).toBe('{"encrypted":"data"}');
    });

    it("should handle captured HTTP requests", async () => {
      const dirPath = join(tempDir, "requests.vulcn");
      await saveSessionDir(dirPath, {
        name: "HTTP Scan",
        target: "https://target.com",
        driver: "browser",
        driverConfig: {},
        sessions: [
          {
            name: "form",
            driver: "browser",
            driverConfig: { startUrl: "https://target.com" },
            steps: [],
          },
        ],
        requests: [
          {
            method: "POST",
            url: "https://target.com/search",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "q=test",
            injectableField: "q",
            sessionName: "search-form",
          },
        ],
      });

      const requests = await readCapturedRequests(dirPath);
      expect(requests.length).toBe(1);
      expect(requests[0].method).toBe("POST");
      expect(requests[0].injectableField).toBe("q");
    });

    it("should skip non-injectable sessions when loading", async () => {
      const dirPath = join(tempDir, "skip.vulcn");

      // Create a session with no injectable inputs
      await saveSessionDir(dirPath, {
        name: "Skip Test",
        target: "https://target.com",
        driver: "browser",
        driverConfig: {},
        sessions: [
          {
            name: "login-only",
            driver: "browser",
            driverConfig: { startUrl: "https://target.com/login" },
            steps: [
              {
                id: "s1",
                type: "browser.click",
                selector: "#btn",
                timestamp: 0,
              },
            ],
          },
        ],
      });

      // Manually mark the session as non-injectable in manifest
      const manifestPath = join(dirPath, "manifest.yml");
      let manifest = await readFile(manifestPath, "utf-8");
      manifest = manifest.replace("injectable: false", "injectable: false");

      const loaded = await loadSessionDir(dirPath);
      // The session has no browser.input steps, so injectable=false
      // loadSessionDir filters by injectable !== false
      expect(loaded.sessions.length).toBe(0);
    });
  });

  describe("isSessionDir", () => {
    it("should return true for a v2 session directory", async () => {
      const dirPath = join(tempDir, "valid.vulcn");
      await saveSessionDir(dirPath, {
        name: "Test",
        target: "https://test.com",
        driver: "browser",
        driverConfig: {},
        sessions: [],
      });

      expect(isSessionDir(dirPath)).toBe(true);
    });

    it("should return false for non-session directory", () => {
      expect(isSessionDir(tempDir)).toBe(false);
    });

    it("should return false for non-existent directory", () => {
      expect(isSessionDir("/nonexistent/path")).toBe(false);
    });
  });

  describe("looksLikeSessionDir", () => {
    it("should match .vulcn extension", () => {
      expect(looksLikeSessionDir("test.vulcn")).toBe(true);
      expect(looksLikeSessionDir("test.vulcn/")).toBe(true);
      expect(looksLikeSessionDir("/path/to/dvwa.vulcn")).toBe(true);
    });

    it("should not match other extensions", () => {
      expect(looksLikeSessionDir("test.yml")).toBe(false);
      expect(looksLikeSessionDir("test.json")).toBe(false);
      expect(looksLikeSessionDir("vulcn.config.yml")).toBe(false);
    });
  });

  describe("readAuthState", () => {
    it("should return null if no auth state exists", async () => {
      const state = await readAuthState(tempDir);
      expect(state).toBeNull();
    });
  });

  describe("readCapturedRequests", () => {
    it("should return empty array if no requests directory", async () => {
      const requests = await readCapturedRequests(tempDir);
      expect(requests).toEqual([]);
    });
  });

  describe("loadSessionDir errors", () => {
    it("should throw if no manifest.yml", async () => {
      await expect(loadSessionDir(tempDir)).rejects.toThrow(
        "No manifest.yml found",
      );
    });

    it("should throw if wrong version", async () => {
      const { writeFile } = await import("node:fs/promises");
      await writeFile(
        join(tempDir, "manifest.yml"),
        'version: "3"\nname: test\ntarget: http://test\nrecordedAt: now\ndriver: browser\ndriverConfig: {}\nsessions: []\n',
      );

      await expect(loadSessionDir(tempDir)).rejects.toThrow(
        "Unsupported session format version",
      );
    });
  });
});
