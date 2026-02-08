# @vulcn/plugin-passive

## 0.3.0

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

## 0.2.0

### Minor Changes

- 56eb043: ### @vulcn/plugin-report
  - **SARIF v2.1.0 output** — new `generateSarif()` generator produces reports compatible with GitHub Code Scanning, Azure DevOps, and other SARIF-consuming tools
  - Added `"sarif"` to the `format` config option (`html | json | yaml | sarif | all`)
  - CWE mappings for all vulnerability types including passive scan categories
  - CVSS-like security-severity scores for GitHub Security tab sorting
  - Fingerprinting and deduplication for stable result tracking across runs

  ### @vulcn/plugin-passive
  - **New plugin** — passive security scanner that analyzes HTTP responses during session replay without injecting payloads
  - Detects missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) with value validation
  - Detects insecure cookie configurations (missing Secure, HttpOnly, SameSite flags)
  - Detects information disclosure (Server version, X-Powered-By, debug tokens)
  - Detects CORS misconfigurations (wildcard origins, credentials with wildcards)
  - Detects mixed content (HTTP resources on HTTPS pages)
  - Automatic deduplication — each unique issue reported once per origin
  - Configurable severity levels and per-check enable/disable toggles

  ### @vulcn/engine
  - Added `"security-misconfiguration"` and `"information-disclosure"` to `PayloadCategory` type
  - These new categories support passive scanner findings in reports and SARIF output

  ### vulcn (CLI)
  - Added `--passive` flag to `vulcn run` to enable the passive security scanner
  - Added `"sarif"` to the `--report` format option
  - Auto-loads `@vulcn/plugin-passive` when `--passive` is specified
  - Updated help text with passive scanning and SARIF examples
