import { BUILTIN_PAYLOADS } from "@vulcn/engine";
import chalk from "chalk";

export async function payloadsCommand() {
  console.log();
  console.log(chalk.cyan("📦 Available Payloads"));
  console.log();

  const payloads = Object.values(BUILTIN_PAYLOADS);

  for (const payload of payloads) {
    console.log(chalk.white(`  ${payload.name}`));
    console.log(chalk.gray(`    Category: ${payload.category}`));
    console.log(chalk.gray(`    ${payload.description}`));
    console.log(chalk.gray(`    Payloads: ${payload.payloads.length}`));
    console.log();
  }

  console.log(chalk.gray("Usage:"));
  console.log(chalk.white("  vulcn run session.vulcn.yml --payload xss-basic"));
}
