# @vulcn/plugin-payloads

## 0.4.1

### Patch Changes

- Updated dependencies [15d8504]
  - @vulcn/engine@0.8.0

## 0.4.0

### Patch Changes

- Updated dependencies [458572e]
  - @vulcn/engine@0.7.0

## 0.3.1

### Patch Changes

- Updated dependencies [56eb043]
  - @vulcn/engine@0.5.0

## 0.3.0

### Minor Changes

- d4fd4df: ### Breaking: Remove built-in payloads, PayloadBox is now the default

  All hardcoded built-in payloads have been removed. Payloads are now fetched on demand from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), the largest community-curated security payload collection.

  **`@vulcn/engine`**
  - Removed `"builtin"` from `PayloadSource` type — valid sources are now `"custom" | "payloadbox" | "plugin"`

  **`@vulcn/plugin-payloads`**
  - Removed all built-in payload sets and the `builtin`, `include`, `exclude`, `payloadbox` config options
  - New config: `types` (short aliases), `limit`, `files`
  - Short aliases for payload types: `xss`, `sqli`, `xxe`, `cmd`, `redirect`, `traversal`
  - Removed legacy `payloadbox:` prefix — use short aliases directly

  **`vulcn` (CLI)**
  - Default payload changed from `xss-basic` to `xss` (PayloadBox)
  - `vulcn payloads` now lists PayloadBox types with short aliases
  - `vulcn run` help updated with payload type reference
  - Auto-loads `@vulcn/plugin-detect-sqli` when `sqli` payloads are used

  **`@vulcn/plugin-detect-sqli`**
  - SQL injection detection plugin with error-based, response diffing, and timing-based strategies
  - Auto-loaded by CLI when SQLi payloads are selected

### Patch Changes

- Updated dependencies [d4fd4df]
  - @vulcn/engine@0.4.0

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

### Minor Changes

- 621502c: ## Driver-Based Architecture

  Introduces a modular driver system that makes Vulcn extensible to different recording targets beyond web browsers.

  ### New Package: `@vulcn/driver-browser`

  A new package that encapsulates all Playwright-based browser recording and replay functionality:
  - **BrowserRecorder** - Records browser interactions (clicks, inputs, navigation)
  - **BrowserRunner** - Replays sessions with payload injection and detection
  - **Browser utilities** - Smart browser launching with system Chrome/Edge fallback

  Step types: `browser.navigate`, `browser.click`, `browser.input`, `browser.keypress`, `browser.scroll`, `browser.wait`

  ### New in `@vulcn/engine`

  #### DriverManager

  New `DriverManager` class for loading and orchestrating drivers:
  - `register(driver)` - Register a driver
  - `load(nameOrPath)` - Load driver from npm or local file
  - `startRecording(driverName, config)` - Start recording with a driver
  - `execute(session, pluginManager)` - Execute session with payloads
  - `getForSession(session)` - Get driver for a session

  #### Driver Interfaces

  New TypeScript interfaces for building custom drivers:
  - `VulcnDriver` - Main driver definition
  - `RecorderDriver` - Recording interface
  - `RunnerDriver` - Replay/execution interface
  - `RecordingHandle` - Handle for controlling active recordings
  - `Session` - Generic session format with `driver` field
  - `Step` - Generic step format with namespaced types

  ### Session Format Changes

  Sessions now include a `driver` field to specify which driver handles them:

  ```yaml
  name: My Session
  driver: browser
  driverConfig:
    browser: chromium
    startUrl: https://example.com
  steps:
    - type: browser.navigate
    - type: browser.input
  ```

  ### Documentation
  - New "Drivers" tab in docs with overview, browser driver reference, and custom driver guide
  - Updated API reference with DriverManager documentation
  - Simplified README pointing to docs.vulcn.dev

  ### Breaking Changes

  None - existing code continues to work. Legacy `Recorder` and `Runner` exports are preserved but deprecated.

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
