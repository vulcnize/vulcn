/**
 * vulcn plugin - Plugin management commands
 */

import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import chalk from "chalk";
import ora from "ora";
import YAML from "yaml";

interface PluginConfig {
  name: string;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

interface VulcnConfig {
  version: string;
  plugins?: PluginConfig[];
  settings?: Record<string, unknown>;
}

const CONFIG_FILES = [
  "vulcn.config.yml",
  "vulcn.config.yaml",
  "vulcn.config.json",
  ".vulcnrc.yml",
  ".vulcnrc.yaml",
  ".vulcnrc.json",
];

/**
 * Find and load the config file
 */
async function loadConfigFile(): Promise<{
  path: string;
  config: VulcnConfig;
} | null> {
  for (const file of CONFIG_FILES) {
    const configPath = resolve(process.cwd(), file);
    if (existsSync(configPath)) {
      const content = await readFile(configPath, "utf-8");
      const config = file.endsWith(".json")
        ? JSON.parse(content)
        : YAML.parse(content);
      return { path: configPath, config };
    }
  }
  return null;
}

/**
 * Save config back to file
 */
async function saveConfigFile(
  path: string,
  config: VulcnConfig,
): Promise<void> {
  const isJson = path.endsWith(".json");
  const content = isJson
    ? JSON.stringify(config, null, 2)
    : `# Vulcn Configuration\n# Docs: https://docs.vulcn.dev/config\n\n${YAML.stringify(config, { indent: 2 })}`;
  await writeFile(path, content, "utf-8");
}

/**
 * vulcn plugin list - Show loaded plugins
 */
export async function pluginListCommand() {
  const result = await loadConfigFile();

  if (!result) {
    console.log(chalk.yellow("No vulcn.config.yml found."));
    console.log(chalk.gray("Run 'vulcn init' to create one."));
    return;
  }

  const { config } = result;
  const plugins = config.plugins || [];

  if (plugins.length === 0) {
    console.log(chalk.yellow("No plugins configured."));
    console.log(chalk.gray("Run 'vulcn plugin add <name>' to add a plugin."));
    return;
  }

  console.log(chalk.cyan("📦 Configured Plugins\n"));

  for (const plugin of plugins) {
    const status =
      plugin.enabled === false ? chalk.gray("(disabled)") : chalk.green("✓");
    const name =
      plugin.enabled === false
        ? chalk.gray(plugin.name)
        : chalk.white(plugin.name);
    console.log(`  ${status} ${name}`);

    if (plugin.config && Object.keys(plugin.config).length > 0) {
      for (const [key, value] of Object.entries(plugin.config)) {
        console.log(chalk.gray(`      ${key}: ${JSON.stringify(value)}`));
      }
    }
  }

  console.log();
}

interface AddOptions {
  config?: string;
}

/**
 * vulcn plugin add <name> - Add a plugin to config
 */
export async function pluginAddCommand(name: string, options: AddOptions) {
  const spinner = ora(`Adding plugin ${name}...`).start();

  // Load existing config
  let result = await loadConfigFile();

  if (!result) {
    spinner.fail("No vulcn.config.yml found. Run 'vulcn init' first.");
    process.exit(1);
  }

  const { path: configPath, config } = result;

  // Check if plugin already exists
  const plugins = config.plugins || [];
  const existing = plugins.find((p) => p.name === name);

  if (existing) {
    if (existing.enabled === false) {
      // Re-enable the plugin
      existing.enabled = true;
      await saveConfigFile(configPath, config);
      spinner.succeed(`Re-enabled plugin: ${chalk.cyan(name)}`);
    } else {
      spinner.warn(`Plugin ${chalk.cyan(name)} is already configured.`);
    }
    return;
  }

  // Add the new plugin
  const newPlugin: PluginConfig = { name };

  // Parse config option if provided
  if (options.config) {
    try {
      newPlugin.config = JSON.parse(options.config);
    } catch {
      spinner.fail(`Invalid config JSON: ${options.config}`);
      process.exit(1);
    }
  }

  config.plugins = [...plugins, newPlugin];
  await saveConfigFile(configPath, config);

  spinner.succeed(`Added plugin: ${chalk.cyan(name)}`);
  console.log(
    chalk.gray(
      `\nPlugin will be loaded on next 'vulcn run' or 'vulcn record'.`,
    ),
  );
}

/**
 * vulcn plugin remove <name> - Remove a plugin from config
 */
export async function pluginRemoveCommand(name: string) {
  const spinner = ora(`Removing plugin ${name}...`).start();

  const result = await loadConfigFile();

  if (!result) {
    spinner.fail("No vulcn.config.yml found.");
    process.exit(1);
  }

  const { path: configPath, config } = result;
  const plugins = config.plugins || [];

  const index = plugins.findIndex((p) => p.name === name);

  if (index === -1) {
    spinner.warn(`Plugin ${chalk.cyan(name)} is not configured.`);
    return;
  }

  // Remove the plugin
  plugins.splice(index, 1);
  config.plugins = plugins;
  await saveConfigFile(configPath, config);

  spinner.succeed(`Removed plugin: ${chalk.cyan(name)}`);
}

interface EnableDisableOptions {
  // Future: could add options here
}

/**
 * vulcn plugin enable <name> - Enable a disabled plugin
 */
export async function pluginEnableCommand(
  name: string,
  _options: EnableDisableOptions,
) {
  const spinner = ora(`Enabling plugin ${name}...`).start();

  const result = await loadConfigFile();

  if (!result) {
    spinner.fail("No vulcn.config.yml found.");
    process.exit(1);
  }

  const { path: configPath, config } = result;
  const plugins = config.plugins || [];

  const plugin = plugins.find((p) => p.name === name);

  if (!plugin) {
    spinner.fail(
      `Plugin ${chalk.cyan(name)} is not configured. Use 'vulcn plugin add ${name}' first.`,
    );
    process.exit(1);
  }

  if (plugin.enabled !== false) {
    spinner.info(`Plugin ${chalk.cyan(name)} is already enabled.`);
    return;
  }

  plugin.enabled = true;
  await saveConfigFile(configPath, config);

  spinner.succeed(`Enabled plugin: ${chalk.cyan(name)}`);
}

/**
 * vulcn plugin disable <name> - Disable a plugin without removing it
 */
export async function pluginDisableCommand(
  name: string,
  _options: EnableDisableOptions,
) {
  const spinner = ora(`Disabling plugin ${name}...`).start();

  const result = await loadConfigFile();

  if (!result) {
    spinner.fail("No vulcn.config.yml found.");
    process.exit(1);
  }

  const { path: configPath, config } = result;
  const plugins = config.plugins || [];

  const plugin = plugins.find((p) => p.name === name);

  if (!plugin) {
    spinner.fail(`Plugin ${chalk.cyan(name)} is not configured.`);
    process.exit(1);
  }

  if (plugin.enabled === false) {
    spinner.info(`Plugin ${chalk.cyan(name)} is already disabled.`);
    return;
  }

  plugin.enabled = false;
  await saveConfigFile(configPath, config);

  spinner.succeed(`Disabled plugin: ${chalk.cyan(name)}`);
}
