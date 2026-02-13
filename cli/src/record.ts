/**
 * vulcn record — Record browser interactions
 *
 * Opens a browser at the target URL, records all interactions,
 * and saves the session to `sessions/` on Ctrl+C.
 *
 * Usage:
 *   vulcn record                        # reads target from .vulcn.yml
 *   vulcn record https://dvwa.local     # override target URL
 */

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DriverManager } from "@vulcn/engine";
import { loadProject, ensureProjectDirs } from "@vulcn/engine";
import browserDriver from "@vulcn/driver-browser";
import chalk from "chalk";
import ora from "ora";
import { stringify } from "yaml";

interface RecordOptions {
  output?: string;
  browser?: string;
  headless?: boolean;
}

export async function recordCommand(
  urlArg: string | undefined,
  options: RecordOptions,
) {
  // ── Load project config ──────────────────────────────────────────────

  let project;
  try {
    project = await loadProject();
  } catch (err) {
    console.error(chalk.red(String(err)));
    process.exit(1);
  }

  const { config, paths } = project;

  // Target URL: CLI arg > config
  const targetUrl = urlArg ?? config.target;
  if (!targetUrl) {
    console.error(
      chalk.red(
        "No target URL. Set it in .vulcn.yml or pass as argument: vulcn record <url>",
      ),
    );
    process.exit(1);
  }

  const browser = options.browser ?? config.scan.browser;
  // Recording should never be headless (you need to see the browser)
  const headless = options.headless ?? false;

  await ensureProjectDirs(paths, ["sessions"]);

  const spinner = ora("Starting browser...").start();

  const drivers = new DriverManager();
  drivers.register(browserDriver);

  try {
    const handle = await drivers.startRecording("browser", {
      startUrl: targetUrl,
      browser,
      headless,
    });

    spinner.succeed("Browser started");
    console.log();
    console.log(chalk.cyan("🎬 Recording started"));
    console.log(chalk.gray(`   URL: ${targetUrl}`));
    console.log(chalk.gray(`   Browser: ${browser}`));
    console.log();
    console.log(
      chalk.yellow("   Interact with the browser to record actions."),
    );
    console.log(chalk.yellow("   Press Ctrl+C to stop recording."));
    console.log();

    // Enable raw mode to intercept Ctrl+C
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }
    process.stdin.resume();
    process.stdin.setEncoding("utf8");

    let stopped = false;
    const stopRecording = async (): Promise<void> => {
      if (stopped) return;
      stopped = true;

      console.log();
      const saveSpinner = ora("Stopping recording...").start();

      try {
        const session = await handle.stop();
        const yaml = stringify(session);

        // Save to sessions/ directory
        const outputFile =
          options.output ??
          `recording-${new Date().toISOString().slice(0, 19).replace(/[:.]/g, "-")}.yml`;
        const outputPath = join(paths.sessions, outputFile);
        await writeFile(outputPath, yaml, "utf-8");

        saveSpinner.succeed(
          `Session saved to ${chalk.green(`sessions/${outputFile}`)}`,
        );
        console.log();
        console.log(chalk.cyan(`📝 Recorded ${session.steps.length} steps`));
        console.log();
        console.log(chalk.gray("To run security tests:"));
        console.log(chalk.white("   vulcn run"));
      } catch (err) {
        saveSpinner.fail("Failed to save session");
        console.error(chalk.red(String(err)));
        process.exit(1);
      }
    };

    await new Promise<void>((resolve) => {
      const handleStop = () => {
        process.stdin.removeAllListeners("data");
        process.off("SIGINT", handleStop);
        process.off("SIGTERM", handleStop);

        stopRecording()
          .then(() => {
            resolve();
          })
          .catch((err) => {
            console.error(chalk.red(String(err)));
            process.exit(1);
          });
      };

      process.stdin.on("data", (key: string) => {
        if (key === "\u0003") {
          handleStop();
        }
      });

      process.on("SIGINT", handleStop);
      process.on("SIGTERM", handleStop);
    });
  } catch (err) {
    spinner.fail("Failed to start recording");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}
