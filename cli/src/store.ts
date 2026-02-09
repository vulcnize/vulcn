/**
 * vulcn store — Credential management
 *
 * Securely stores authentication credentials for scanning.
 *
 * Usage:
 *   vulcn store <username> <password>              # Store form credentials
 *   vulcn store --header "Authorization: Bearer x"  # Store header auth
 *
 * Credentials are encrypted with AES-256-GCM using a passphrase
 * from --passphrase flag, interactive prompt, or VULCN_KEY env var.
 */

import { writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createInterface } from "node:readline";
import chalk from "chalk";
import { encryptCredentials, getPassphrase } from "@vulcn/engine";
import type {
  FormCredentials,
  HeaderCredentials,
  Credentials,
} from "@vulcn/engine";

interface StoreOptions {
  header?: string;
  output?: string;
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
    // Disable echo for password input
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
          // Backspace
          if (password.length > 0) {
            password = password.slice(0, -1);
            process.stdout.write("\b \b");
          }
        } else if (c === "\u0003") {
          // Ctrl+C
          process.exit(1);
        } else {
          password += c;
          process.stdout.write("*");
        }
      };
      stdin.on("data", onData);
    } else {
      // Non-interactive: read from pipe
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
  const outputPath = resolve(options.output ?? ".vulcn/auth.enc");

  let credentials: Credentials;

  if (options.header) {
    // Header-based auth: --header "Authorization: Bearer xyz"
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
    // Form-based auth
    if (!username || !password) {
      console.error(
        chalk.red(
          "Usage: vulcn store <username> <password>\n" +
            '       vulcn store --header "Authorization: Bearer xyz"',
        ),
      );
      process.exit(1);
    }

    credentials = {
      type: "form",
      username,
      password,
      ...(options.loginUrl ? { loginUrl: options.loginUrl } : {}),
      ...(options.userSelector ? { userSelector: options.userSelector } : {}),
      ...(options.passSelector ? { passSelector: options.passSelector } : {}),
    } satisfies FormCredentials;

    console.log(chalk.gray(`   Auth type: form`));
    console.log(chalk.gray(`   Username: ${username}`));
    console.log(chalk.gray(`   Password: ${"*".repeat(password.length)}`));
  }

  // Get passphrase
  let passphrase: string;
  try {
    passphrase = getPassphrase(options.passphrase);
  } catch {
    // No env var or flag — prompt interactively
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

    // Confirm
    const confirm = await promptPassphrase("   Confirm passphrase: ");
    if (passphrase !== confirm) {
      console.error(chalk.red("Passphrases do not match."));
      process.exit(1);
    }
  }

  // Encrypt
  const encrypted = encryptCredentials(credentials, passphrase);

  // Write to file
  const dir = dirname(outputPath);
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true });
  }

  await writeFile(outputPath, encrypted, "utf-8");

  console.log();
  console.log(chalk.green(`✅ Credentials saved to ${chalk.cyan(outputPath)}`));
  console.log(chalk.yellow(`⚠️  Add ${chalk.cyan(outputPath)} to .gitignore`));
}
