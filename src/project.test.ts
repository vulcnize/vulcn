import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, writeFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import YAML from "yaml";
import {
  findProjectRoot,
  resolveProjectPaths,
  loadProject,
  loadProjectFromFile,
  ensureProjectDirs,
  CONFIG_FILENAME,
} from "./project";

describe("Project", () => {
  let testDir: string;

  beforeEach(async () => {
    testDir = join(
      tmpdir(),
      `vulcn-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(testDir, { recursive: true });
  });

  afterEach(async () => {
    if (existsSync(testDir)) {
      await rm(testDir, { recursive: true, force: true });
    }
  });

  describe("findProjectRoot", () => {
    it("should find .vulcn.yml in the same directory", async () => {
      await writeFile(
        join(testDir, CONFIG_FILENAME),
        "target: https://example.com\n",
      );

      const root = findProjectRoot(testDir);
      expect(root).toBe(testDir);
    });

    it("should find .vulcn.yml in parent directory", async () => {
      const subDir = join(testDir, "subdir");
      await mkdir(subDir, { recursive: true });
      await writeFile(
        join(testDir, CONFIG_FILENAME),
        "target: https://example.com\n",
      );

      const root = findProjectRoot(subDir);
      expect(root).toBe(testDir);
    });

    it("should find .vulcn.yml in grandparent directory", async () => {
      const deepDir = join(testDir, "a", "b", "c");
      await mkdir(deepDir, { recursive: true });
      await writeFile(
        join(testDir, CONFIG_FILENAME),
        "target: https://example.com\n",
      );

      const root = findProjectRoot(deepDir);
      expect(root).toBe(testDir);
    });

    it("should return null if not found", () => {
      const root = findProjectRoot(testDir);
      expect(root).toBeNull();
    });
  });

  describe("resolveProjectPaths", () => {
    it("should resolve convention-based paths", () => {
      const paths = resolveProjectPaths(testDir);

      expect(paths.root).toBe(testDir);
      expect(paths.config).toBe(join(testDir, ".vulcn.yml"));
      expect(paths.sessions).toBe(join(testDir, "sessions"));
      expect(paths.auth).toBe(join(testDir, "auth"));
      expect(paths.reports).toBe(join(testDir, "reports"));
    });
  });

  describe("loadProject", () => {
    it("should load a minimal config", async () => {
      await writeFile(
        join(testDir, CONFIG_FILENAME),
        YAML.stringify({ target: "https://example.com" }),
      );

      const project = await loadProject(testDir);

      expect(project.config.target).toBe("https://example.com");
      expect(project.config.scan.browser).toBe("chromium");
      expect(project.config.payloads.types).toEqual(["xss"]);
      expect(project.paths.root).toBe(testDir);
    });

    it("should load an empty config with all defaults", async () => {
      await writeFile(join(testDir, CONFIG_FILENAME), "");

      const project = await loadProject(testDir);

      expect(project.config.target).toBeUndefined();
      expect(project.config.scan.browser).toBe("chromium");
      expect(project.config.payloads.types).toEqual(["xss"]);
    });

    it("should throw if no config found", async () => {
      await expect(loadProject(testDir)).rejects.toThrow("No .vulcn.yml found");
    });

    it("should throw on invalid YAML", async () => {
      await writeFile(join(testDir, CONFIG_FILENAME), "{ invalid yaml ::::");

      await expect(loadProject(testDir)).rejects.toThrow("Invalid YAML");
    });
  });

  describe("loadProjectFromFile", () => {
    it("should load from a specific file path", async () => {
      const configPath = join(testDir, CONFIG_FILENAME);
      await writeFile(
        configPath,
        YAML.stringify({ target: "https://test.local" }),
      );

      const project = await loadProjectFromFile(configPath);

      expect(project.config.target).toBe("https://test.local");
      expect(project.paths.root).toBe(testDir);
    });
  });

  describe("ensureProjectDirs", () => {
    it("should create sessions directory", async () => {
      const paths = resolveProjectPaths(testDir);
      await ensureProjectDirs(paths, ["sessions"]);

      expect(existsSync(paths.sessions)).toBe(true);
    });

    it("should create multiple directories", async () => {
      const paths = resolveProjectPaths(testDir);
      await ensureProjectDirs(paths, ["sessions", "auth", "reports"]);

      expect(existsSync(paths.sessions)).toBe(true);
      expect(existsSync(paths.auth)).toBe(true);
      expect(existsSync(paths.reports)).toBe(true);
    });

    it("should not fail if directory already exists", async () => {
      const paths = resolveProjectPaths(testDir);
      await mkdir(paths.sessions, { recursive: true });

      await expect(
        ensureProjectDirs(paths, ["sessions"]),
      ).resolves.not.toThrow();
    });
  });
});
