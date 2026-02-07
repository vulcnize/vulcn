import chalk from "chalk";

interface PayloadsOptions {
  category?: string;
  file?: string;
}

export async function payloadsCommand(options: PayloadsOptions) {
  const { getPayloadBoxTypes, getDescription, getAliases, loadFromFile } =
    await import("@vulcn/plugin-payloads");

  console.log();
  console.log(chalk.cyan.bold("📦 Available Payload Types"));
  console.log(
    chalk.gray("  Payloads are fetched from PayloadsAllTheThings on demand.\n"),
  );

  // Category colors
  const typeColors: Record<string, (text: string) => string> = {
    xss: chalk.red,
    "sql-injection": chalk.magenta,
    xxe: chalk.cyan,
    "command-injection": chalk.yellow,
    "open-redirect": chalk.white,
    "path-traversal": chalk.green,
  };

  // Build alias reverse map: canonical → aliases
  const aliases = getAliases();
  const reverseAliases: Record<string, string[]> = {};
  for (const [alias, canonical] of Object.entries(aliases)) {
    if (alias !== canonical) {
      if (!reverseAliases[canonical]) reverseAliases[canonical] = [];
      reverseAliases[canonical].push(alias);
    }
  }

  const types = getPayloadBoxTypes();

  // Filter if category specified
  const filtered = options.category
    ? types.filter((t) => {
        const lower = options.category!.toLowerCase();
        return (
          t === lower ||
          t.startsWith(lower) ||
          reverseAliases[t]?.includes(lower)
        );
      })
    : types;

  if (options.category && filtered.length === 0) {
    console.log(chalk.yellow(`  No payload type matches: ${options.category}`));
    console.log(chalk.gray(`  Available: ${types.join(", ")}`));
    return;
  }

  for (const type of filtered) {
    const color = typeColors[type] || chalk.white;
    const desc = getDescription(type);
    const shorts = reverseAliases[type] || [];
    const aliasStr =
      shorts.length > 0 ? chalk.gray(` (${shorts.join(", ")})`) : "";

    console.log(`  ${color(type)}${aliasStr}`);
    console.log(chalk.gray(`    ${desc}`));
  }

  // Show custom payloads from file if specified
  if (options.file) {
    console.log();
    try {
      const customPayloads = await loadFromFile(options.file);
      console.log(chalk.blue.bold("📄 Custom Payloads"));
      console.log(
        chalk.green(`  ✓ Loaded ${customPayloads.length} payload set(s)\n`),
      );
      for (const p of customPayloads) {
        console.log(
          `  ${chalk.white(p.name)} ${chalk.gray(`(${p.category})`)}`,
        );
        console.log(chalk.gray(`    ${p.description}`));
        console.log(chalk.gray(`    ${p.payloads.length} payloads`));
      }
    } catch (err) {
      console.error(chalk.red(`  Failed to load custom payloads: ${err}`));
    }
  }

  console.log();
  console.log(chalk.cyan("─".repeat(50)));
  console.log(
    chalk.gray(`${types.length} payload types | Source: PayloadsAllTheThings`),
  );
  console.log();
  console.log(chalk.gray("Usage:"));
  console.log(chalk.white("  vulcn run session.yml -p xss sqli"));
  console.log(chalk.white("  vulcn run session.yml -p xss sqli cmd xxe"));
  console.log(chalk.white("  vulcn run session.yml -f custom-payloads.yml"));
}
