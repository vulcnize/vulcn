# Changelog

## 0.4.0

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

## 0.3.2

### Patch Changes

- 51d69b7: ### Auto-Crawl: Automated Form Discovery & Session Generation

  Adds a new **auto-crawl** capability to the browser driver — automatically discovers injectable forms, inputs, and submit buttons on a target URL, then generates ready-to-run `Session[]` objects. This replaces the need to manually record sessions for basic form testing.

  #### `@vulcn/engine`
  - **`CrawlOptions` type** — new interface for crawl configuration (`maxDepth`, `maxPages`, `pageTimeout`, `sameOrigin`, `onPageCrawled` callback)
  - **`RecorderDriver.crawl()`** — optional method on the recorder interface, so only drivers that support auto-discovery need to implement it
  - **`DriverManager.crawl()`** — new top-level method that dispatches to the driver's crawl implementation, with clear errors when a driver doesn't support it
  - **Test coverage** — 4 new tests for the crawl flow (success, arg passthrough, missing driver, unsupported driver), coverage at 62.88%

  #### `@vulcn/driver-browser`
  - **`BrowserCrawler`** — new module (`crawler.ts`) that performs BFS-based crawling using Playwright:
    - Discovers explicit `<form>` elements with their inputs and submit buttons
    - Discovers standalone inputs not inside a `<form>` (common in SPAs)
    - Identifies injectable text-like input types (text, search, url, email, tel, password, textarea)
    - Finds submit triggers (submit buttons, untyped buttons, or falls back to Enter keypress)
    - Follows same-origin links with configurable depth control
    - Generates proper `navigate → input → submit` step sequences per form
  - **`recorder.crawl()`** — wired into the browser driver's recorder interface
  - **Exported** — `crawlAndBuildSessions` available for direct programmatic use

  #### Architecture
  - Removed standalone `@vulcn/crawler` package — crawler is now a core part of `@vulcn/driver-browser`, consistent with the driver-based architecture
  - Cleaned up `pnpm-workspace.yaml` to remove the deleted crawler entry

## 0.3.1

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

## 0.3.0

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

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-05

### Added

- Initial release of Vulcn - Security testing recorder & runner
- **Session Recording** - Record browser interactions (clicks, form fills, navigation)
- **Session Replay** - Replay sessions with security payloads injected
- **Smart Browser Detection** - Uses system Chrome/Edge first, Playwright fallback
- **Built-in Payloads** - XSS and SQL injection payload sets
- **YAML Sessions** - Human-readable session format with Zod validation
- **Cross-Platform** - macOS, Linux, and Windows support

### CLI Commands

- `vulcn record` - Record browser interactions
- `vulcn run` - Replay session with payloads
- `vulcn payloads` - List available payloads
- `vulcn doctor` - Check browser availability
- `vulcn install` - Install Playwright browsers

[0.1.0]: https://github.com/vulcnize/vulcn/releases/tag/v0.1.0
