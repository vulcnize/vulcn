/**
 * Vulcn Session Format v2
 *
 * Directory-based session format: `.vulcn/` or `<name>.vulcn/`
 *
 * Structure:
 *   manifest.yml          - scan config, session list, auth config
 *   auth/config.yml       - login strategy, indicators
 *   auth/state.enc        - encrypted storageState (cookies/localStorage)
 *   sessions/*.yml        - individual session files (one per form)
 *   requests/*.json       - captured HTTP metadata (for Tier 1 fast scan)
 */

import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, basename, extname } from "node:path";
import { createHash } from "node:crypto";
import { parse, stringify } from "yaml";
import type { Session } from "./driver-types";
import type { AuthConfig } from "./auth";

// ── Types ──────────────────────────────────────────────────────────────

/** Manifest file schema (manifest.yml) */
export interface ScanManifest {
  /** Format version */
  version: "2";
  /** Human-readable scan name */
  name: string;
  /** Target URL */
  target: string;
  /** When the scan was recorded */
  recordedAt: string;
  /** Driver name */
  driver: string;
  /** Driver configuration */
  driverConfig: Record<string, unknown>;
  /** Auth configuration (optional) */
  auth?: {
    strategy: string;
    configFile?: string;
    stateFile?: string;
    loggedInIndicator?: string;
    loggedOutIndicator?: string;
    reAuthOn?: Array<Record<string, unknown>>;
  };
  /** Session file references */
  sessions: SessionRef[];
  /** Scan configuration */
  scan?: {
    tier?: "auto" | "http-only" | "browser-only";
    parallel?: number;
    timeout?: number;
  };
}

/** Reference to a session file within the manifest */
export interface SessionRef {
  /** Relative path to session file */
  file: string;
  /** Whether this session has injectable inputs */
  injectable?: boolean;
}

/** HTTP request metadata for Tier 1 fast scanning */
export interface CapturedRequest {
  /** Request method */
  method: string;
  /** Full URL */
  url: string;
  /** Request headers */
  headers: Record<string, string>;
  /** Form data (for POST) */
  body?: string;
  /** Content type */
  contentType?: string;
  /** Which form field is injectable */
  injectableField?: string;
  /** Session name this request belongs to */
  sessionName: string;
}

// ── Read ──────────────────────────────────────────────────────────────

/**
 * Load a v2 session directory into Session[] ready for execution.
 *
 * @param dirPath - Path to the .vulcn/ directory
 * @returns Array of sessions with manifest metadata attached
 */
export async function loadSessionDir(dirPath: string): Promise<{
  manifest: ScanManifest;
  sessions: Session[];
  authConfig?: AuthConfig;
}> {
  // Read manifest
  const manifestPath = join(dirPath, "manifest.yml");
  if (!existsSync(manifestPath)) {
    throw new Error(
      `No manifest.yml found in ${dirPath}. Is this a v2 session directory?`,
    );
  }

  const manifestYaml = await readFile(manifestPath, "utf-8");
  const manifest = parse(manifestYaml) as ScanManifest;

  if (manifest.version !== "2") {
    throw new Error(
      `Unsupported session format version: ${manifest.version}. Expected "2".`,
    );
  }

  // Read auth config if present
  let authConfig: AuthConfig | undefined;
  if (manifest.auth?.configFile) {
    const authPath = join(dirPath, manifest.auth.configFile);
    if (existsSync(authPath)) {
      const authYaml = await readFile(authPath, "utf-8");
      authConfig = parse(authYaml) as AuthConfig;
    }
  }

  // Read session files
  const sessions: Session[] = [];

  for (const ref of manifest.sessions) {
    // Skip non-injectable sessions (e.g., login-only sessions)
    if (ref.injectable === false) continue;

    const sessionPath = join(dirPath, ref.file);
    if (!existsSync(sessionPath)) {
      console.warn(`Session file not found: ${sessionPath}, skipping`);
      continue;
    }

    const sessionYaml = await readFile(sessionPath, "utf-8");
    const sessionData = parse(sessionYaml) as Record<string, unknown>;

    // Build full session with manifest-level driver config
    const session: Session = {
      name: (sessionData.name as string) ?? basename(ref.file, ".yml"),
      driver: manifest.driver,
      driverConfig: {
        ...manifest.driverConfig,
        startUrl: resolveUrl(
          manifest.target,
          sessionData.page as string | undefined,
        ),
      },
      steps: (sessionData.steps as Session["steps"]) ?? [],
      metadata: {
        recordedAt: manifest.recordedAt,
        version: "2",
        manifestDir: dirPath,
      },
    };

    sessions.push(session);
  }

  return { manifest, sessions, authConfig };
}

/**
 * Check if a path is a v2 session directory.
 */
export function isSessionDir(path: string): boolean {
  return existsSync(join(path, "manifest.yml"));
}

/**
 * Check if a path looks like a v2 session directory (by extension).
 */
export function looksLikeSessionDir(path: string): boolean {
  return path.endsWith(".vulcn") || path.endsWith(".vulcn/");
}

// ── Write ─────────────────────────────────────────────────────────────

/**
 * Save sessions to a v2 session directory.
 *
 * Creates the directory structure:
 *   <dirPath>/
 *   ├── manifest.yml
 *   ├── sessions/
 *   │   ├── <session-name>.yml
 *   │   └── ...
 *   └── requests/   (if HTTP metadata provided)
 *       └── ...
 */
export async function saveSessionDir(
  dirPath: string,
  options: {
    name: string;
    target: string;
    driver: string;
    driverConfig: Record<string, unknown>;
    sessions: Session[];
    authConfig?: AuthConfig;
    encryptedState?: string;
    requests?: CapturedRequest[];
  },
): Promise<void> {
  // Create directory structure
  await mkdir(join(dirPath, "sessions"), { recursive: true });

  const sessionRefs: SessionRef[] = [];

  // Write individual session files
  for (const session of options.sessions) {
    const safeName = slugify(session.name);
    const fileName = `sessions/${safeName}.yml`;
    const sessionPath = join(dirPath, fileName);

    // Extract the page-relative URL if it starts with the target
    const startUrl = session.driverConfig.startUrl as string | undefined;
    const page = startUrl
      ? startUrl.replace(options.target, "").replace(/^\//, "/")
      : undefined;

    const sessionData: Record<string, unknown> = {
      name: session.name,
      ...(page ? { page } : {}),
      steps: session.steps,
    };

    await writeFile(sessionPath, stringify(sessionData), "utf-8");

    // Check if session has injectable inputs
    const hasInjectable = session.steps.some(
      (s) =>
        s.type === "browser.input" &&
        (s as Record<string, unknown>).injectable !== false,
    );

    sessionRefs.push({
      file: fileName,
      injectable: hasInjectable,
    });
  }

  // Write auth config if provided
  if (options.authConfig) {
    await mkdir(join(dirPath, "auth"), { recursive: true });
    await writeFile(
      join(dirPath, "auth", "config.yml"),
      stringify(options.authConfig),
      "utf-8",
    );
  }

  // Write encrypted auth state if provided
  if (options.encryptedState) {
    await mkdir(join(dirPath, "auth"), { recursive: true });
    await writeFile(
      join(dirPath, "auth", "state.enc"),
      options.encryptedState,
      "utf-8",
    );
  }

  // Write HTTP request metadata if provided
  if (options.requests && options.requests.length > 0) {
    await mkdir(join(dirPath, "requests"), { recursive: true });
    for (const req of options.requests) {
      const safeName = slugify(req.sessionName);
      await writeFile(
        join(dirPath, "requests", `${safeName}.json`),
        JSON.stringify(req, null, 2),
        "utf-8",
      );
    }
  }

  // Write manifest
  const manifest: ScanManifest = {
    version: "2",
    name: options.name,
    target: options.target,
    recordedAt: new Date().toISOString(),
    driver: options.driver,
    driverConfig: options.driverConfig,
    ...(options.authConfig
      ? {
          auth: {
            strategy: options.authConfig.strategy,
            configFile: "auth/config.yml",
            stateFile: options.encryptedState ? "auth/state.enc" : undefined,
            loggedInIndicator: options.authConfig.loggedInIndicator,
            loggedOutIndicator: options.authConfig.loggedOutIndicator,
          },
        }
      : {}),
    sessions: sessionRefs,
    scan: {
      tier: "auto",
      parallel: 1,
      timeout: 120000,
    },
  };

  await writeFile(join(dirPath, "manifest.yml"), stringify(manifest), "utf-8");
}

/**
 * Read encrypted auth state from a session directory.
 */
export async function readAuthState(dirPath: string): Promise<string | null> {
  const statePath = join(dirPath, "auth", "state.enc");
  if (!existsSync(statePath)) return null;
  return readFile(statePath, "utf-8");
}

/**
 * Read captured HTTP requests from a session directory.
 */
export async function readCapturedRequests(
  dirPath: string,
): Promise<CapturedRequest[]> {
  const requestsDir = join(dirPath, "requests");
  if (!existsSync(requestsDir)) return [];

  const files = await readdir(requestsDir);
  const requests: CapturedRequest[] = [];

  for (const file of files) {
    if (!file.endsWith(".json")) continue;
    const content = await readFile(join(requestsDir, file), "utf-8");
    requests.push(JSON.parse(content) as CapturedRequest);
  }

  return requests;
}

// ── Helpers ────────────────────────────────────────────────────────────

/**
 * Resolve a page path against a target URL.
 */
function resolveUrl(target: string, page?: string): string {
  if (!page) return target;
  if (page.startsWith("http")) return page;

  // Ensure target doesn't end with / and page starts with /
  const base = target.replace(/\/$/, "");
  const path = page.startsWith("/") ? page : `/${page}`;
  return `${base}${path}`;
}

/**
 * Convert a string to a safe filename slug.
 *
 * Appends a short hash of the full text to guarantee uniqueness,
 * even when names share long common prefixes (e.g., WAVSEP test cases).
 * The readable portion is truncated to fit within maxLen.
 */
function slugify(text: string, maxLen = 80): string {
  const slug = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  // Short hash for uniqueness (8 hex chars = 4 bytes, ~4B combinations)
  const hash = createHash("sha256").update(text).digest("hex").slice(0, 8);

  // If slug + hash fits, use it as-is
  const withHash = `${slug}-${hash}`;
  if (withHash.length <= maxLen) return withHash;

  // Truncate the slug (keep tail — most unique part) and append hash
  const maxSlugLen = maxLen - hash.length - 1; // -1 for the separator
  const truncated = slug.slice(-maxSlugLen).replace(/^-+/, "");
  return `${truncated}-${hash}`;
}
