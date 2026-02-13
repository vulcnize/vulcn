/**
 * Vulcn Project Discovery & Resolution
 *
 * Finds `.vulcn.yml` by walking up from `cwd`, parses the config,
 * and resolves convention-based paths (sessions/, auth/, reports/).
 */

import { readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import YAML from "yaml";
import { parseProjectConfig, type VulcnProjectConfig } from "./config";

// ── Constants ─────────────────────────────────────────────────────────

/** Config filename — presence marks a directory as a Vulcn project */
export const CONFIG_FILENAME = ".vulcn.yml";

/** Convention-based subdirectory names */
export const DIRS = {
  sessions: "sessions",
  auth: "auth",
  reports: "reports",
} as const;

// ── Types ─────────────────────────────────────────────────────────────

/** Resolved project paths */
export interface ProjectPaths {
  /** Absolute path to the project root (directory containing .vulcn.yml) */
  root: string;
  /** Absolute path to .vulcn.yml */
  config: string;
  /** Absolute path to sessions/ directory */
  sessions: string;
  /** Absolute path to auth/ directory */
  auth: string;
  /** Absolute path to reports/ directory */
  reports: string;
}

/** Loaded project — config + paths */
export interface VulcnProject {
  /** Parsed and validated config */
  config: VulcnProjectConfig;
  /** Resolved absolute paths */
  paths: ProjectPaths;
}

// ── Discovery ─────────────────────────────────────────────────────────

/**
 * Find the project root by walking up from `startDir` looking for `.vulcn.yml`.
 *
 * @param startDir - Directory to start searching from (default: `cwd()`)
 * @returns Absolute path to the project root, or `null` if not found
 */
export function findProjectRoot(startDir?: string): string | null {
  let dir = resolve(startDir ?? process.cwd());

  // Walk up the directory tree
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const configPath = join(dir, CONFIG_FILENAME);
    if (existsSync(configPath)) {
      return dir;
    }

    const parent = dirname(dir);
    if (parent === dir) {
      // Reached filesystem root
      return null;
    }
    dir = parent;
  }
}

/**
 * Resolve convention-based paths from a project root.
 */
export function resolveProjectPaths(root: string): ProjectPaths {
  return {
    root,
    config: join(root, CONFIG_FILENAME),
    sessions: join(root, DIRS.sessions),
    auth: join(root, DIRS.auth),
    reports: join(root, DIRS.reports),
  };
}

// ── Loading ───────────────────────────────────────────────────────────

/**
 * Load a Vulcn project from a directory.
 *
 * Finds `.vulcn.yml`, parses it, validates with Zod, and resolves paths.
 *
 * @param startDir - Directory to start searching from (default: `cwd()`)
 * @throws If `.vulcn.yml` is not found or invalid
 */
export async function loadProject(startDir?: string): Promise<VulcnProject> {
  const root = findProjectRoot(startDir);

  if (!root) {
    throw new Error(
      `No ${CONFIG_FILENAME} found. Run \`vulcn init\` to create one.`,
    );
  }

  const paths = resolveProjectPaths(root);
  const raw = await readFile(paths.config, "utf-8");

  let parsed: unknown;
  try {
    parsed = YAML.parse(raw);
  } catch (err) {
    throw new Error(
      `Invalid YAML in ${paths.config}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Empty file → empty object (all defaults)
  if (parsed === null || parsed === undefined) {
    parsed = {};
  }

  const config = parseProjectConfig(parsed);

  return { config, paths };
}

/**
 * Load project config from a specific file path (no discovery).
 * Useful for testing or when the path is already known.
 */
export async function loadProjectFromFile(
  configPath: string,
): Promise<VulcnProject> {
  const absPath = resolve(configPath);
  const root = dirname(absPath);
  const paths = resolveProjectPaths(root);

  const raw = await readFile(absPath, "utf-8");

  let parsed: unknown;
  try {
    parsed = YAML.parse(raw);
  } catch (err) {
    throw new Error(
      `Invalid YAML in ${absPath}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (parsed === null || parsed === undefined) {
    parsed = {};
  }

  const config = parseProjectConfig(parsed);

  return { config, paths };
}

// ── Initialization ────────────────────────────────────────────────────

/**
 * Ensure convention directories exist (sessions/, auth/, reports/).
 * Called during init and before operations that write to these dirs.
 */
export async function ensureProjectDirs(
  paths: ProjectPaths,
  dirs: Array<keyof typeof DIRS> = ["sessions"],
): Promise<void> {
  for (const dir of dirs) {
    const dirPath = paths[dir];
    if (!existsSync(dirPath)) {
      await mkdir(dirPath, { recursive: true });
    }
  }
}
