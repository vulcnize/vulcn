---
"@vulcn/driver-browser": patch
"@vulcn/engine": patch
---

### Auto-Crawl: Automated Form Discovery & Session Generation

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
