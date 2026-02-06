import { writeFile } from "node:fs/promises";
import { Recorder, serializeSession, type BrowserType } from "@vulcn/engine";
import chalk from "chalk";
import ora from "ora";

interface RecordOptions {
  output: string;
  browser: string;
  headless: boolean;
}

export async function recordCommand(url: string, options: RecordOptions) {
  const spinner = ora("Starting browser...").start();

  try {
    const session = await Recorder.start(url, {
      browser: options.browser as BrowserType,
      headless: options.headless,
    });

    spinner.succeed("Browser started");
    console.log();
    console.log(chalk.cyan("🎬 Recording started"));
    console.log(chalk.gray(`   URL: ${url}`));
    console.log(chalk.gray(`   Browser: ${options.browser}`));
    console.log();
    console.log(
      chalk.yellow("   Interact with the browser to record actions."),
    );
    console.log(chalk.yellow("   Press Ctrl+C to stop recording."));
    console.log();

    // Enable raw mode to intercept Ctrl+C before it becomes SIGINT
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
    }
    process.stdin.resume();
    process.stdin.setEncoding("utf8");

    // Handle Ctrl+C gracefully
    let stopped = false;
    const stopRecording = async (): Promise<void> => {
      if (stopped) return;
      stopped = true;

      console.log();
      const saveSpinner = ora("Stopping recording...").start();

      try {
        const result = await session.stop();
        const yaml = serializeSession(result);
        await writeFile(options.output, yaml, "utf-8");

        saveSpinner.succeed(`Session saved to ${chalk.green(options.output)}`);
        console.log();
        console.log(chalk.cyan(`📝 Recorded ${result.steps.length} steps`));
        console.log();
        console.log(chalk.gray("To run with payloads:"));
        console.log(
          chalk.white(`   vulcn run ${options.output} --payload xss-basic`),
        );
      } catch (err) {
        saveSpinner.fail("Failed to save session");
        console.error(chalk.red(String(err)));
        process.exit(1);
      }
    };

    // Use a promise-based approach to handle signals properly
    await new Promise<void>((resolve) => {
      const handleStop = () => {
        // Remove all handlers to prevent double-handling
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

      // Listen for Ctrl+C keypress (char code 0x03) in raw mode
      process.stdin.on("data", (key: string) => {
        if (key === "\u0003") {
          handleStop();
        }
      });

      // Also handle SIGINT/SIGTERM for non-TTY or external signals
      process.on("SIGINT", handleStop);
      process.on("SIGTERM", handleStop);
    });
  } catch (err) {
    spinner.fail("Failed to start recording");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}
