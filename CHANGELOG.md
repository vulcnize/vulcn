# Changelog

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
