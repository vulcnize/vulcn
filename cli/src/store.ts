/**
 * vulcn store — Credential management
 *
 * Securely stores authentication credentials for scanning.
 * Saves to `auth/state.enc` next to `.vulcn.yml`.
 *
 * Usage:
 *   vulcn store <username> <password>              # Store form credentials
 *   vulcn store --header "Authorization: Bearer x"  # Store header auth
 *
 * Credentials are encrypted with AES-256-GCM using a passphrase
 * from --passphrase flag, interactive prompt, or VULCN_KEY env var.
 */

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import chalk from "chalk";
import {
  encryptCredentials,
  getPassphrase,
  loadProject,
  ensureProjectDirs,
} from "@vulcn/engine";
import type {
  FormCredentials,
  HeaderCredentials,
  Credentials,
} from "@vulcn/engine";

interface StoreOptions {
  header?: string;
  passphrase?: string;
  loginUrl?: string;
  userSelector?: string;
  passSelector?: string;
}

/**
 * Prompt for a passphrase (hidden input)
 */
async function promptPassphrase(prompt: string): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      process.stdout.write(prompt);
      const stdin = process.stdin;
      stdin.setRawMode?.(true);
      stdin.resume();

      let password = "";
      const onData = (ch: Buffer) => {
        const c = ch.toString("utf8");
        if (c === "\n" || c === "\r" || c === "\u0004") {
          stdin.setRawMode?.(false);
          stdin.removeListener("data", onData);
          stdin.pause();
          rl.close();
          process.stdout.write("\n");
          resolve(password);
        } else if (c === "\u007f" || c === "\b") {
          if (password.length > 0) {
            password = password.slice(0, -1);
            process.stdout.write("\b \b");
          }
        } else if (c === "\u0003") {
          process.exit(1);
        } else {
          password += c;
          process.stdout.write("*");
        }
      };
      stdin.on("data", onData);
    } else {
      rl.question(prompt, (answer) => {
        rl.close();
        resolve(answer);
      });
    }
  });
}

export async function storeCommand(
  username: string | undefined,
  password: string | undefined,
  options: StoreOptions,
) {
  // ── Load project ─────────────────────────────────────────────────────

  let project;
  try {
    project = await loadProject();
  } catch (err) {
    console.error(chalk.red(String(err)));
    process.exit(1);
  }

  const { config, paths } = project;

  // ── Parse credentials ────────────────────────────────────────────────

  let credentials: Credentials;

  if (options.header) {
    const colonIdx = options.header.indexOf(":");
    if (colonIdx === -1) {
      console.error(
        chalk.red('Invalid header format. Use: --header "Name: Value"'),
      );
      process.exit(1);
    }

    const headerName = options.header.slice(0, colonIdx).trim();
    const headerValue = options.header.slice(colonIdx + 1).trim();

    credentials = {
      type: "header",
      headers: { [headerName]: headerValue },
    } satisfies HeaderCredentials;

    console.log(chalk.gray(`   Auth type: header (${headerName})`));
  } else {
    if (!username || !password) {
      console.error(
        chalk.red(
          "Usage: vulcn store <username> <password>\n" +
            '       vulcn store --header "Authorization: Bearer xyz"',
        ),
      );
      process.exit(1);
    }

    // Use auth config from .vulcn.yml if available
    const authConfig =
      config.auth && config.auth.strategy === "form" ? config.auth : null;

    credentials = {
      type: "form",
      username,
      password,
      ...(options.loginUrl || authConfig?.loginUrl
        ? { loginUrl: options.loginUrl ?? authConfig?.loginUrl }
        : {}),
      ...(options.userSelector || authConfig?.userSelector
        ? {
            userSelector:
              options.userSelector ?? authConfig?.userSelector ?? undefined,
          }
        : {}),
      ...(options.passSelector || authConfig?.passSelector
        ? {
            passSelector:
              options.passSelector ?? authConfig?.passSelector ?? undefined,
          }
        : {}),
    } satisfies FormCredentials;

    console.log(chalk.gray(`   Auth type: form`));
    console.log(chalk.gray(`   Username: ${username}`));
    console.log(chalk.gray(`   Password: ${"*".repeat(password.length)}`));
  }

  // ── Get passphrase ───────────────────────────────────────────────────

  let passphrase: string;
  try {
    passphrase = getPassphrase(options.passphrase);
  } catch {
    if (!process.stdin.isTTY) {
      console.error(
        chalk.red(
          "No passphrase provided. Set VULCN_KEY env var or use --passphrase.",
        ),
      );
      process.exit(1);
    }

    passphrase = await promptPassphrase("   Enter passphrase to encrypt: ");

    if (!passphrase || passphrase.length < 4) {
      console.error(chalk.red("Passphrase must be at least 4 characters."));
      process.exit(1);
    }

    const confirm = await promptPassphrase("   Confirm passphrase: ");
    if (passphrase !== confirm) {
      console.error(chalk.red("Passphrases do not match."));
      process.exit(1);
    }
  }

  // ── Encrypt and save ─────────────────────────────────────────────────

  const encrypted = encryptCredentials(credentials, passphrase);

  await ensureProjectDirs(paths, ["auth"]);
  const outputPath = join(paths.auth, "state.enc");
  await writeFile(outputPath, encrypted, "utf-8");

  console.log();
  console.log(
    chalk.green(`✅ Credentials saved to ${chalk.cyan("auth/state.enc")}`),
  );
  console.log(chalk.yellow(`⚠️  Add ${chalk.cyan("auth/")} to .gitignore`));
}
