import { installBrowsers, checkBrowsers, type BrowserType } from "@vulcn/engine";
import chalk from "chalk";
import ora from "ora";

export async function installCommand(
  browsers?: string[],
  options?: { all?: boolean },
) {
  // Determine which browsers to install
  let browsersToInstall: BrowserType[];

  if (options?.all) {
    browsersToInstall = ["chromium", "firefox", "webkit"];
  } else if (browsers && browsers.length > 0) {
    browsersToInstall = browsers as BrowserType[];
  } else {
    browsersToInstall = ["chromium"];
  }

  console.log();
  console.log(chalk.cyan("🔧 Installing browsers for Vulcn"));
  console.log();

  try {
    await installBrowsers(browsersToInstall);
    console.log();
    console.log(chalk.green("✅ Browsers installed successfully"));
  } catch (err) {
    console.error(chalk.red("Failed to install browsers:"), err);
    process.exit(1);
  }
}

export async function doctorCommand() {
  console.log();
  console.log(chalk.cyan("🩺 Vulcn Browser Check"));
  console.log();

  const spinner = ora("Checking available browsers...").start();

  try {
    const status = await checkBrowsers();
    spinner.stop();

    console.log(chalk.white("System Browsers:"));
    console.log(
      `  Chrome:    ${status.systemChrome ? chalk.green("✓ Available") : chalk.gray("✗ Not found")}`,
    );
    console.log(
      `  Edge:      ${status.systemEdge ? chalk.green("✓ Available") : chalk.gray("✗ Not found")}`,
    );
    console.log();

    console.log(chalk.white("Playwright Browsers:"));
    console.log(
      `  Chromium:  ${status.playwrightChromium ? chalk.green("✓ Installed") : chalk.gray("✗ Not installed")}`,
    );
    console.log(
      `  Firefox:   ${status.playwrightFirefox ? chalk.green("✓ Installed") : chalk.gray("✗ Not installed")}`,
    );
    console.log(
      `  WebKit:    ${status.playwrightWebkit ? chalk.green("✓ Installed") : chalk.gray("✗ Not installed")}`,
    );
    console.log();

    // Recommendation
    if (status.systemChrome || status.systemEdge) {
      console.log(
        chalk.green("✅ Ready to use! Vulcn will use your system browser."),
      );
    } else if (status.playwrightChromium) {
      console.log(
        chalk.green("✅ Ready to use! Vulcn will use Playwright Chromium."),
      );
    } else {
      console.log(chalk.yellow("⚠️  No browsers found."));
      console.log();
      console.log(chalk.white("Options:"));
      console.log(chalk.gray("  1. Install Google Chrome (recommended)"));
      console.log(chalk.gray("  2. Run: vulcn install"));
    }
  } catch (err) {
    spinner.fail("Failed to check browsers");
    console.error(chalk.red(String(err)));
    process.exit(1);
  }
}
