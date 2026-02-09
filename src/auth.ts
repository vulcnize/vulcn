/**
 * Vulcn Auth Module
 *
 * Handles credential encryption/decryption and auth state management.
 *
 * Security:
 * - AES-256-GCM encryption for credentials at rest
 * - PBKDF2 key derivation from passphrase
 * - Reads passphrase from VULCN_KEY env var (CI/CD) or interactive prompt
 * - Auth state (cookies, localStorage) encrypted separately
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
} from "node:crypto";

// ── Types ──────────────────────────────────────────────────────────────

/** Form-based login credentials */
export interface FormCredentials {
  type: "form";
  username: string;
  password: string;
  /** Custom login URL (if different from target) */
  loginUrl?: string;
  /** Custom CSS selector for username field */
  userSelector?: string;
  /** Custom CSS selector for password field */
  passSelector?: string;
}

/** Header-based authentication (API keys, Bearer tokens) */
export interface HeaderCredentials {
  type: "header";
  headers: Record<string, string>;
}

/** All credential types */
export type Credentials = FormCredentials | HeaderCredentials;

/** Auth configuration for a scan */
export interface AuthConfig {
  /** Auth strategy */
  strategy: "storage-state" | "header";
  /** Login page URL */
  loginUrl?: string;
  /** Text that appears when logged in (e.g., "Logout") */
  loggedInIndicator?: string;
  /** Text that appears when logged out (e.g., "Sign In") */
  loggedOutIndicator?: string;
  /** Session expiry detection rules */
  sessionExpiry?: {
    /** HTTP status codes that indicate session expired */
    statusCodes?: number[];
    /** URL pattern that indicates redirect to login */
    redirectPattern?: string;
    /** Page content that indicates session expired */
    pageContent?: string;
  };
}

/** Encrypted payload structure (stored as JSON) */
interface EncryptedData {
  /** Format version */
  version: 1;
  /** PBKDF2 salt (hex) */
  salt: string;
  /** AES-256-GCM IV (hex) */
  iv: string;
  /** AES-256-GCM auth tag (hex) */
  tag: string;
  /** Encrypted data (hex) */
  data: string;
  /** PBKDF2 iterations */
  iterations: number;
}

// ── Constants ──────────────────────────────────────────────────────────

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32; // 256 bits
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_DIGEST = "sha512";

// ── Key Derivation ─────────────────────────────────────────────────────

/**
 * Derive AES-256 key from passphrase using PBKDF2.
 */
function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return pbkdf2Sync(
    passphrase,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST,
  );
}

// ── Encryption ─────────────────────────────────────────────────────────

/**
 * Encrypt data with AES-256-GCM.
 *
 * @param data - Plaintext data to encrypt
 * @param passphrase - Passphrase for key derivation
 * @returns JSON string of EncryptedData
 */
export function encrypt(data: string, passphrase: string): string {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(passphrase, salt);

  const cipher = createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag();

  const payload: EncryptedData = {
    version: 1,
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
    data: encrypted,
    iterations: PBKDF2_ITERATIONS,
  };

  return JSON.stringify(payload);
}

/**
 * Decrypt data encrypted with encrypt().
 *
 * @param encrypted - JSON string from encrypt()
 * @param passphrase - Passphrase used during encryption
 * @returns Decrypted plaintext
 * @throws Error if passphrase is wrong or data is tampered
 */
export function decrypt(encrypted: string, passphrase: string): string {
  const payload: EncryptedData = JSON.parse(encrypted);

  if (payload.version !== 1) {
    throw new Error(`Unsupported encryption version: ${payload.version}`);
  }

  const salt = Buffer.from(payload.salt, "hex");
  const iv = Buffer.from(payload.iv, "hex");
  const tag = Buffer.from(payload.tag, "hex");
  const key = deriveKey(passphrase, salt);

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(payload.data, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

// ── Credential Helpers ─────────────────────────────────────────────────

/**
 * Encrypt credentials to a storable string.
 */
export function encryptCredentials(
  credentials: Credentials,
  passphrase: string,
): string {
  return encrypt(JSON.stringify(credentials), passphrase);
}

/**
 * Decrypt credentials from a stored string.
 */
export function decryptCredentials(
  encrypted: string,
  passphrase: string,
): Credentials {
  const json = decrypt(encrypted, passphrase);
  return JSON.parse(json) as Credentials;
}

/**
 * Encrypt browser storage state (cookies, localStorage, etc.).
 * The state is the JSON output from Playwright's context.storageState().
 */
export function encryptStorageState(
  storageState: string,
  passphrase: string,
): string {
  return encrypt(storageState, passphrase);
}

/**
 * Decrypt browser storage state.
 */
export function decryptStorageState(
  encrypted: string,
  passphrase: string,
): string {
  return decrypt(encrypted, passphrase);
}

// ── Passphrase Resolution ──────────────────────────────────────────────

/**
 * Get passphrase from environment or throw.
 *
 * In CI/CD, set VULCN_KEY env var.
 * In interactive mode, the CLI should prompt and pass the value here.
 */
export function getPassphrase(interactive?: string): string {
  // Interactive passphrase takes priority
  if (interactive) return interactive;

  // Fall back to env var
  const envKey = process.env.VULCN_KEY;
  if (envKey) return envKey;

  throw new Error(
    "No passphrase provided. Set VULCN_KEY environment variable or pass --passphrase.",
  );
}
