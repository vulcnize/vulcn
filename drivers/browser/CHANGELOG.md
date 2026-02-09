# @vulcn/driver-browser

## 0.4.0

### Minor Changes

- 5011ca5: Add Tier 1 HTTP fast scanner for high-speed payload testing
  - **`httpScan()`** — replay captured HTTP requests via `fetch()` at ~50ms/payload, detecting reflected XSS, error-based SQLi, and server-side reflection without launching a browser
  - **`buildCapturedRequests()`** — convert crawler-discovered forms into `CapturedRequest` metadata for Tier 1 scanning
  - **`CrawlResult`** — `crawlAndBuildSessions()` now returns both `Session[]` (Tier 2 browser replay) and `CapturedRequest[]` (Tier 1 HTTP scan)
  - Tier 1 findings are tagged with `metadata.detectionMethod: "tier1-http"` and `metadata.needsBrowserConfirmation: true` for escalation to Tier 2
  - Supports payload injection into URL params (GET), form-urlencoded bodies, JSON bodies, and multipart form data
  - Configurable concurrency, timeout, cookies, and custom headers via `HttpScanOptions`
  - Progress callbacks for real-time scan monitoring
  - 14 new tests covering XSS/SQLi detection, safe encoding, timeouts, and `buildCapturedRequests` form conversion

## 0.3.0

### Minor Changes

- 15d8504: ### Authenticated Scanning

  End-to-end support for scanning applications behind login pages.

  #### `@vulcn/engine`
  - **Credential encryption module** (`src/auth.ts`): AES-256-GCM encryption/decryption for credentials and Playwright storage state, with PBKDF2 key derivation (600k iterations)
  - **Auth types**: `FormCredentials`, `HeaderCredentials`, `AuthConfig` with session expiry detection config
  - **Scan-level hooks**: `onScanStart` / `onScanEnd` — fire once per scan wrapping all sessions, with `ScanContext` providing full session list and scan metadata
  - **`onScanEnd` result transformation**: uses `callHookPipe` so plugins can transform the aggregate `RunResult` (e.g. deduplication, risk scoring)
  - **v2 session format**: `.vulcn/` directory structure with manifest, encrypted auth state, and config alongside session files
  - **`CrawlOptions.storageState`**: pass authenticated browser state (cookies + localStorage) to the crawler
  - **New exports**: `ScanContext`, `encryptCredentials`, `decryptCredentials`, `encryptStorageState`, `decryptStorageState`, `getPassphrase`

  #### `@vulcn/driver-browser`
  - **Authenticated crawling**: `crawlAndBuildSessions` accepts `storageState` via `CrawlOptions` and injects it into the Playwright browser context
  - **Authenticated scanning**: `BrowserRunner` reads `storageState` from `RunOptions` and applies it to the scanner's browser context
  - **Login form auto-detection**: `performLogin` navigates to the login URL, auto-detects username/password fields, fills credentials, and submits
  - **Storage state capture**: after successful login, captures full browser storage state (cookies, localStorage, sessionStorage)

  #### `vulcn` (CLI)
  - **`vulcn store`**: new command to encrypt and save credentials (form-based or header-based) to `.vulcn/auth.enc`
  - **`vulcn crawl --creds`**: decrypt credentials → perform login → capture storage state → crawl all authenticated pages
  - **`vulcn run --creds`**: decrypt credentials → perform login → inject storage state into scanner browser context → run all payloads authenticated
  - **Auth state persistence**: crawl saves encrypted auth state + config alongside sessions in the output directory

## 0.2.0

### Minor Changes

- 458572e: ### @vulcn/engine
  - **`addFinding` on PluginContext**: Plugins now have `ctx.addFinding()` to report findings through the proper callback chain. This ensures consumers are notified via `onFinding` and findings survive timeouts. Plugins should use this instead of `ctx.findings.push()`.
  - **`onPageReady` callback**: New `RunOptions.onPageReady` callback fires after the driver creates the browser page. The engine uses this to defer `onRunStart` plugin hooks until the page is ready, so plugins receive a real page object (not `null`).
  - **`onBeforeClose` hook**: New plugin lifecycle hook called before the browser is closed. Plugins can flush in-flight async work here (e.g., pending response handlers that need browser access).
  - **`onBeforeClose` callback**: New `RunOptions.onBeforeClose` callback fires before browser teardown, triggering plugin `onBeforeClose` hooks.

  ### @vulcn/driver-browser
  - **`onPageReady` signal**: Runner now calls `ctx.options.onPageReady(page)` after creating the browser page, enabling plugins to attach event listeners before any navigation occurs.
  - **`onBeforeClose` signal**: Runner now calls `ctx.options.onBeforeClose(page)` before `browser.close()`, giving plugins time to drain pending async work.
  - **Payload interleaving**: Payloads are now ordered round-robin across categories (e.g., `[sqli1, xss1, sqli2, xss2, ...]`) instead of sequentially. This ensures faster category coverage and earlier dedup early-breaks on slow SPAs.
  - **Extended dedup early-break**: The per-step category dedup now treats any finding (dialog, console, or reflection) as confirmation, not just dialog-based detections. One confirmed finding per category per step is sufficient.

  ### @vulcn/plugin-passive
  - **Uses `ctx.addFinding()`**: All findings are now reported through the proper callback chain instead of pushing to `ctx.findings` directly. This fixes passive findings being invisible to `onFinding` consumers.
  - **Cross-session dedup**: `reportedFindings` is no longer cleared between sessions, so the same passive finding (e.g., "Missing CSP" on the same origin) is reported once per scan, not once per crawled form.
  - **Async handler drain**: Response handlers are tracked as promises and drained in the new `onBeforeClose` hook, preventing findings from being lost when the browser closes before async `response.allHeaders()` calls complete.

## 0.1.2

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

## 0.1.1

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

## 0.1.0

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
