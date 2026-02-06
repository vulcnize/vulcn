import type { PayloadCategory } from "@vulcn/engine";
import chalk from "chalk";

interface PayloadsOptions {
  category?: string;
  file?: string;
}

export async function payloadsCommand(options: PayloadsOptions) {
  // Dynamically import the payloads plugin
  const { BUILTIN_PAYLOADS, loadFromFile, getPayloadBoxTypes } =
    await import("@vulcn/plugin-payloads");

  // All payloads to display
  const allPayloads = { ...BUILTIN_PAYLOADS };

  // Load custom payloads if specified
  if (options.file) {
    try {
      const customPayloads = await loadFromFile(options.file);
      for (const p of customPayloads) {
        allPayloads[p.name] = p;
      }
      console.log(
        chalk.green(`✓ Loaded ${customPayloads.length} custom payload(s)\n`),
      );
    } catch (err) {
      console.error(chalk.red(`Failed to load custom payloads: ${err}\n`));
    }
  }

  console.log(chalk.cyan.bold("📦 Available Payloads\n"));

  // Get unique categories
  const categories = new Set<PayloadCategory>();
  for (const p of Object.values(allPayloads)) {
    categories.add(p.category);
  }

  // Filter by category if specified
  const filteredCategories = options.category
    ? [...categories].filter((c) => c === options.category)
    : [...categories];

  if (options.category && filteredCategories.length === 0) {
    console.log(chalk.yellow(`No payloads in category: ${options.category}`));
    console.log(
      chalk.gray(`Available categories: ${[...categories].join(", ")}`),
    );
    return;
  }

  // Category colors
  const categoryColors: Record<string, (text: string) => string> = {
    xss: chalk.red,
    sqli: chalk.magenta,
    ssrf: chalk.blue,
    xxe: chalk.cyan,
    "command-injection": chalk.yellow,
    "path-traversal": chalk.green,
    "open-redirect": chalk.white,
    custom: chalk.gray,
  };

  for (const category of filteredCategories) {
    const payloads = Object.values(allPayloads).filter(
      (p) => p.category === category,
    );
    const color = categoryColors[category] || chalk.white;

    console.log(chalk.bold(color(`[${category.toUpperCase()}]`)));

    for (const payload of payloads) {
      const sourceTag =
        payload.source === "custom"
          ? chalk.gray(" (custom)")
          : payload.source === "payloadbox"
            ? chalk.blue(" (payloadbox)")
            : "";

      console.log(`  ${chalk.white(payload.name)}${sourceTag}`);
      console.log(chalk.gray(`    ${payload.description}`));
      console.log(chalk.gray(`    ${payload.payloads.length} payloads`));
    }
    console.log();
  }

  // Show summary
  const totalBuiltin = Object.keys(BUILTIN_PAYLOADS).length;
  const totalPayloadStrings = Object.values(BUILTIN_PAYLOADS).reduce(
    (sum, p) => sum + p.payloads.length,
    0,
  );

  console.log(chalk.cyan("─".repeat(40)));
  console.log(
    chalk.gray(
      `${totalBuiltin} payload sets | ${totalPayloadStrings} individual payloads`,
    ),
  );

  // Show PayloadBox
  console.log();
  console.log(chalk.blue.bold("🌐 PayloadBox (Remote)"));
  console.log(chalk.gray("  Fetch curated payloads from PayloadsAllTheThings"));
  const pbTypes = getPayloadBoxTypes();
  for (const type of pbTypes) {
    console.log(chalk.blue(`  payloadbox:${type}`));
  }

  console.log();
  console.log(chalk.gray("Usage:"));
  console.log(
    chalk.gray("  vulcn run session.yml --payload xss-basic sqli-basic"),
  );
  console.log(chalk.gray("  vulcn run session.yml --payload-file custom.yml"));
  console.log(
    chalk.blue(
      "  vulcn run session.yml --payload payloadbox:xss payloadbox:sql-injection",
    ),
  );
}
