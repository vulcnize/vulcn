# @vulcn/plugin-detect-reflection

## 0.2.2

### Patch Changes

- 90b60ed: Docs: align all documentation with v0.9 refactored architecture
  - Replace all `vulcn.config.yml` references with `.vulcn.yml` flat config
  - Remove `vulcn plugin` command (deleted `cli/plugin.mdx`, removed from nav)
  - Update `vulcn run` examples to argless format (auto-discovers sessions from `sessions/`)
  - Update auth path from `.vulcn/auth.enc` to `auth/state.enc`
  - Replace `driverManager`/`pluginManager` singletons with `new DriverManager()`/`new PluginManager()` + `loadFromConfig()`
  - Replace `Runner.execute()` with `DriverManager.executeScan()`
  - Remove legacy exports section from API overview, add Project Config exports
  - Rewrite plugins overview to document auto-loading from flat config keys
  - Update drivers/browser config, auth workflow, and programmatic examples
  - Update drivers/creating-drivers to remove config-based driver registration
  - Rewrite plugin-api.mdx Session/Step types and PluginManager methods
  - Fix plugin-report, plugin-passive, plugin-payloads, plugin-detect-sqli examples

- 90b60ed: Improve reflection detection accuracy — eliminate XSS false positives

  **@vulcn/driver-browser**
  - `checkReflection`: verbatim-only matches now use type `"reflection"` instead of the payload category, distinguishing low-confidence reflection from confirmed exploitation
  - `checkReflection`: detect patterns only run when the payload appears verbatim in rendered content, preventing false matches on partially-encoded reflections
  - `checkReflection`: encoding suppression now explicitly checks for dangerous HTML chars before calling `isHtmlEncoded`
  - `confirmedTypes` early-exit now only triggers on high-confidence findings (type matches payload category), allowing the scanner to continue trying payloads that may trigger actual execution (e.g. `alert()`)

  **@vulcn/plugin-detect-reflection**
  - Skip payloads without dangerous HTML characters — reflecting plain text like `alert(1)` is not a vulnerability
  - Include authentication cookies when fetching raw content for encoding checks
  - Simplified encoding check flow

  **benchmarks**
  - Exclude `"reflection"` findings from XSS benchmark evaluation (reflection ≠ confirmed XSS)
  - Add Youden's J score with qualitative label to per-case summary output

  **WAVSEP XSS benchmark (before → after)**
  - False Positives: 6 → 0
  - True Negatives: 1 → 7
  - Precision: 88.5% → 100%
  - Youden's J: 0.051 → 0.479

## 0.2.1

### Patch Changes

- c62a3dc: ### `@vulcn/plugin-report` — New Package

  Introducing the **Report Generation Plugin** — generate professional security reports at the end of every `vulcn run`.
  - **HTML**: Modern dark-themed dashboard with risk gauge, severity breakdown bars, expandable finding cards, Vulcn branding, Inter + JetBrains Mono typography, and print-friendly CSS
  - **JSON**: Machine-readable structured output for CI/CD pipelines — includes severity counts, risk score, vuln types, affected URLs
  - **YAML**: Human-readable YAML with descriptive header comment — same data model as JSON
  - Uses the `onRunEnd` plugin hook to intercept results after execution completes
  - Exports `generateHtml`, `generateJson`, `generateYaml` for programmatic use

  ### `@vulcn/engine`
  - **Plugin lifecycle hooks**: `DriverManager.execute()` now invokes `onRunStart` and `onRunEnd` plugin hooks around the driver runner, enabling plugins like the report generator to intercept and process results
  - Removed legacy `Runner` and `Recorder` exports — all execution now goes through `DriverManager`
  - Updated package description and SEO keywords for npm discoverability

  ### `vulcn` (CLI)
  - Added `--report <format>` flag (`html`, `json`, `yaml`, `all`) to generate security reports after test runs
  - Added `--report-output <dir>` flag to specify output directory for generated reports
  - Report plugin is auto-loaded when `--report` flag is used
  - Updated package description and SEO keywords — positioned as a modern, fast alternative to legacy security scanners

  ### `@vulcn/driver-browser`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability

  ### `@vulcn/plugin-payloads`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability

  ### `@vulcn/plugin-detect-xss`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability

  ### `@vulcn/plugin-detect-reflection`
  - Updated package description, keywords, homepage, and bugs URL for npm discoverability

## 0.2.0

### Patch Changes

- Updated dependencies [621502c]
  - @vulcn/engine@0.3.0

## 0.1.0

### Minor Changes

- 7e1133c: ## v0.2.0 - Plugin System & CLI Enhancements

  ### @vulcn/engine
  - **Plugin System**: Complete hook-based plugin architecture with lifecycle management
  - **PluginManager**: New class for loading, configuring, and orchestrating plugins
  - Added `hasPlugin()` method to check if a plugin is already loaded
  - Added `reflection` as a valid `PayloadCategory` type
  - Full TypeScript types for plugin development (`VulcnPlugin`, `PluginContext`, `DetectContext`, etc.)

  ### vulcn (CLI)
  - **`vulcn init`**: Create `vulcn.config.yml` with default plugins pre-configured
  - **`vulcn plugin` commands**:
    - `vulcn plugin list` - List configured plugins
    - `vulcn plugin add <name>` - Add a plugin to configuration
    - `vulcn plugin remove <name>` - Remove a plugin from configuration
    - `vulcn plugin enable <name>` - Re-enable a disabled plugin
    - `vulcn plugin disable <name>` - Disable a plugin without removing it
  - **Auto-loading**: CLI automatically loads `@vulcn/plugin-detect-xss` if not already configured

  ### @vulcn/plugin-payloads
  - Official payload loader plugin
  - Built-in payloads (13 sets, 91 payloads): XSS, SQLi, SSRF, XXE, command injection, path traversal, open redirect
  - PayloadsAllTheThings integration for fetching community payloads
  - Custom payload file loading (YAML/JSON)

  ### @vulcn/plugin-detect-xss
  - Execution-based XSS detection plugin
  - Monitors `alert()`, `confirm()`, `prompt()` dialogs
  - Console marker detection (`console.log('VULCN_XSS:...')`)
  - Configurable alert patterns and severity levels

  ### @vulcn/plugin-detect-reflection (NEW)
  - Pattern-based reflection detection plugin
  - Detects when payloads appear in response HTML
  - Context-aware detection (body, script, attribute)
  - Dangerous pattern proximity detection (onerror, onclick, javascript:, etc.)
  - Configurable severity per context type

### Patch Changes

- Updated dependencies [7e1133c]
  - @vulcn/engine@0.2.0
