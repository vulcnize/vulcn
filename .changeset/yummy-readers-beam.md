---
"@vulcn/driver-browser": minor
"@vulcn/engine": minor
---

Add Tier 1 HTTP fast scanner for high-speed payload testing

- **`httpScan()`** — replay captured HTTP requests via `fetch()` at ~50ms/payload, detecting reflected XSS, error-based SQLi, and server-side reflection without launching a browser
- **`buildCapturedRequests()`** — convert crawler-discovered forms into `CapturedRequest` metadata for Tier 1 scanning
- **`CrawlResult`** — `crawlAndBuildSessions()` now returns both `Session[]` (Tier 2 browser replay) and `CapturedRequest[]` (Tier 1 HTTP scan)
- Tier 1 findings are tagged with `metadata.detectionMethod: "tier1-http"` and `metadata.needsBrowserConfirmation: true` for escalation to Tier 2
- Supports payload injection into URL params (GET), form-urlencoded bodies, JSON bodies, and multipart form data
- Configurable concurrency, timeout, cookies, and custom headers via `HttpScanOptions`
- Progress callbacks for real-time scan monitoring
- 14 new tests covering XSS/SQLi detection, safe encoding, timeouts, and `buildCapturedRequests` form conversion
